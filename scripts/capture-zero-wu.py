#!/usr/bin/env python3
"""Framing-level capture of wu_zero_stream against loopback targets.

Records exact bytes we send and the server's HTTP/2 frames (post-TLS).
Saves hex transcripts under evidence/zero-wu/. Loopback-only.
NOT a vulnerability claim — RFC-conformance observation aid.
"""
from __future__ import annotations

import binascii
import ssl
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ours import framing as F
from ours.battery import _assert_loopback, _open
from ours.driver import DriverConfig, H2Session
from ours.oracle import goaway_error
from ours.targets import TARGETS, get_target

OUT = ROOT / "evidence" / "zero-wu"


def hexdump(label: str, data: bytes) -> str:
    lines = [f"## {label} ({len(data)} bytes)"]
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<48s}  {asci}")
    lines.append(f"hex={binascii.hexlify(data).decode()}")
    return "\n".join(lines)


def frame_summary(frames) -> str:
    names = {
        F.DATA: "DATA",
        F.HEADERS: "HEADERS",
        F.RST_STREAM: "RST_STREAM",
        F.SETTINGS: "SETTINGS",
        F.PING: "PING",
        F.GOAWAY: "GOAWAY",
        F.WINDOW_UPDATE: "WINDOW_UPDATE",
    }
    lines = []
    for kind, flags, sid, payload in frames:
        name = names.get(kind, f"TYPE_{kind}")
        extra = ""
        if kind == F.GOAWAY and len(payload) >= 8:
            extra = f" last_stream={int.from_bytes(payload[0:4],'big')} error={int.from_bytes(payload[4:8],'big')}"
        elif kind == F.RST_STREAM and len(payload) == 4:
            extra = f" error={int.from_bytes(payload,'big')}"
        elif kind == F.WINDOW_UPDATE and len(payload) == 4:
            extra = f" incr={int.from_bytes(payload,'big')}"
        elif kind == F.PING:
            extra = f" ack={bool(flags & F.ACK)} payload={payload!r}"
        lines.append(f"  {name} flags=0x{flags:02x} stream={sid} len={len(payload)}{extra}")
    return "\n".join(lines) if lines else "  (no frames)"


def capture_one(target_id: str) -> Path:
    target = get_target(target_id)
    host, port, path = _assert_loopback(target.url)
    if target.path:
        path = target.path

    wu_bytes = F.window_update_raw(1, 0)
    assert wu_bytes == bytes.fromhex("00000408000000000100000000"), (
        f"unexpected WU encoding: {wu_bytes.hex()}"
    )

    session = None
    lines = [
        f"# wu_zero_stream framing capture — {target_id}",
        f"url: {target.url}",
        f"rfc: RFC 9113 §6.9.1 — WINDOW_UPDATE increment 0 MUST be connection PROTOCOL_ERROR",
        f"probe_frame_hex: {wu_bytes.hex()}",
        f"probe_frame_layout: len=4 type=WINDOW_UPDATE(0x08) flags=0 stream=1 payload=00000000",
        "",
    ]
    try:
        session = _open(target.url, path, print)
        # Open stream 1 WITHOUT END_STREAM (h2spec-aligned), then WU(0).
        req = F.headers_frame(
            1, F.request_headers(session.authority, path), end_stream=False
        )
        before = len(session.frames)
        session.send(req + wu_bytes)
        _pt, alive = session.drain(2.0)
        after_frames = session.frames[before:]
        err = goaway_error(session.frames)
        rst = any(k == F.RST_STREAM and s == 1 for k, _f, s, _p in after_frames)
        # Liveness ping
        ping_ok = False
        if alive:
            token = b"ZWUCAPT1"
            pb = len(session.frames)
            session.send(F.ping(token))
            _pt2, alive2 = session.drain(2.0)
            ping_ok = any(
                kind == F.PING and (flags & F.ACK) and payload == token
                for kind, flags, sid, payload in session.frames[pb:]
            )
            alive = alive2

        lines.append("## sent")
        lines.append(hexdump("HEADERS GET stream=1 (NO END_STREAM, h2spec-aligned)", req))
        lines.append("")
        lines.append(hexdump("WINDOW_UPDATE stream=1 increment=0 (RFC-illegal)", wu_bytes))
        lines.append("")
        lines.append("## received after WU(0)")
        lines.append(f"alive={alive}")
        lines.append(f"goaway_error={err}")
        lines.append(f"rst_stream_1={rst}")
        lines.append(f"ping_acked_after={ping_ok}")
        lines.append("frames_after_wu:")
        lines.append(frame_summary(after_frames))
        lines.append("")
        # Classification matching battery probe (RST before ACCEPTED)
        if err == F.PROTOCOL_ERROR:
            verdict = "REJECTED_STRICT (GOAWAY PROTOCOL_ERROR) — PASS vs RFC"
        elif not alive and err is None:
            verdict = "CONNECTION_CLOSED without GOAWAY PROTOCOL_ERROR — ANOMALY"
        elif rst and alive:
            verdict = "RST_STREAM only (connection kept) — ANOMALY vs RFC (h2spec still passes)"
        elif ping_ok and alive:
            verdict = "ACCEPTED (connection still usable, PING ACK) — FAIL vs RFC §6.9.1"
        elif not alive:
            verdict = "CONNECTION_CLOSED without GOAWAY PROTOCOL_ERROR — ANOMALY"
        else:
            verdict = f"UNCLEAR goaway={err} alive={alive} ping={ping_ok} rst={rst}"
        lines.append(f"## classification: {verdict}")
        lines.append(
            "Honesty: this is an RFC-conformance observation, NOT a CVE claim."
        )
    except Exception as exc:
        lines.append(f"## ERROR: {type(exc).__name__}: {exc}")
    finally:
        if session:
            session.close()

    OUT.mkdir(parents=True, exist_ok=True)
    path_out = OUT / f"{target_id}-wu-zero-stream.txt"
    path_out.write_text("\n".join(lines) + "\n")
    print(f"wrote {path_out}")
    return path_out


def main(argv: list[str]) -> int:
    ids = argv[1:] or [
        "nginx-1.31.8",
        "httpd-2.4.71",
        "nginx-1.31.9",
        "caddy-2.10",
        "envoy-1.32",
        "go-nethttp",
        "nghttpd",
    ]
    for tid in ids:
        if tid not in TARGETS:
            print(f"skip unknown {tid}", file=sys.stderr)
            continue
        if not TARGETS[tid].supports_h2:
            continue
        # Restart envoy if needed
        t = TARGETS[tid]
        if t.restart_container:
            import subprocess
            subprocess.run(["docker", "restart", t.restart_container], check=False)
            time.sleep(2)
        capture_one(tid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
