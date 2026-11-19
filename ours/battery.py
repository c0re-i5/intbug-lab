"""HTTP/2 flow-control / counter / length integer-bug test battery.

Each probe exercises one RFC-grounded invariant. Results use Status:
  PASS / FAIL / ANOMALY / SKIP / ERROR

Citations are RFC 9113 (HTTP/2, formerly RFC 7540) unless noted.
We do not invent CVE IDs for ANOMALY results.
"""

from __future__ import annotations

import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from . import framing as F
from .driver import DriverConfig, H2Session, run_accounting_probe
from .oracle import (
    Status,
    evaluate_connection_window_invariant,
    goaway_error,
)
from .targets import Target


LogFn = Callable[[str], None]


@dataclass
class ProbeResult:
    probe_id: str
    title: str
    rfc: str
    status: Status
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class TargetBatteryReport:
    target_id: str
    target_name: str
    url: str
    results: list[ProbeResult] = field(default_factory=list)
    error: str | None = None


def _assert_loopback(url: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("only https:// targets supported")
    host = parts.hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"refusing non-loopback host {host!r}")
    port = parts.port or 443
    path = parts.path or "/index.html"
    if not path.startswith("/"):
        path = "/" + path
    return host, port, path


def _open(url: str, path: str, log: LogFn) -> H2Session:
    host, port, _ = _assert_loopback(url)
    cfg = DriverConfig(url=url, path=path, key_updates=0, carrier_app_bytes=1024, log=log)
    session = H2Session(host, port, cfg)
    session.handshake()
    session.send(F.client_preface_settings())
    session.drain(1.0)
    session.send(F.settings_ack())
    return session


def _ping_alive(session: H2Session, token: bytes = b"BATTERY1") -> bool:
    before = len(session.frames)
    session.send(F.ping(token))
    _pt, alive = session.drain(2.0)
    acked = any(
        kind == F.PING and (flags & F.ACK) and sid == 0 and payload == token
        for kind, flags, sid, payload in session.frames[before:]
    )
    return bool(alive and acked)


# ----- individual probes -----

def probe_h2_alpn(target: Target, log: LogFn) -> ProbeResult:
    title = "ALPN negotiates h2"
    rfc = "RFC 9113 §3.3 / RFC 7301"
    try:
        host, port, path = _assert_loopback(target.url)
        if target.path:
            path = target.path
        cfg = DriverConfig(url=target.url, path=path, key_updates=0, log=log)
        session = H2Session(host, port, cfg)
        try:
            session.handshake()
            ok = session.negotiated_h2
        finally:
            session.close()
        if target.supports_h2:
            return ProbeResult(
                "h2_alpn", title, rfc,
                Status.PASS if ok else Status.FAIL,
                "ALPN h2 negotiated" if ok else "ALPN h2 missing on h2-capable target",
            )
        # negative control: must NOT negotiate h2
        return ProbeResult(
            "h2_alpn", title, rfc,
            Status.PASS if not ok else Status.FAIL,
            "ALPN h2 correctly absent" if not ok else "unexpected ALPN h2 on http2-off target",
        )
    except (ssl.SSLError, OSError, RuntimeError) as exc:
        msg = str(exc)
        no_h2 = "NO_APPLICATION_PROTOCOL" in msg or "no application protocol" in msg.lower()
        if not target.supports_h2 and no_h2:
            return ProbeResult(
                "h2_alpn", title, rfc, Status.PASS,
                f"TLS alert without h2 (expected): {msg}",
            )
        if target.supports_h2 and no_h2:
            return ProbeResult(
                "h2_alpn", title, rfc, Status.FAIL, f"h2 expected but ALPN failed: {msg}"
            )
        return ProbeResult("h2_alpn", title, rfc, Status.ERROR, msg)


def probe_wu_zero_conn(target: Target, log: LogFn) -> ProbeResult:
    """WINDOW_UPDATE with increment 0 on the connection — MUST PROTOCOL_ERROR.

    RFC 9113 §6.9.1: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame
    with an flow-control window increment of 0 as a connection error of type
    PROTOCOL_ERROR."
    """
    title = "WINDOW_UPDATE increment 0 (connection) rejected"
    rfc = "RFC 9113 §6.9.1"
    if not target.supports_h2:
        return ProbeResult("wu_zero_conn", title, rfc, Status.SKIP, "target does not speak h2")
    session = None
    try:
        session = _open(target.url, target.path, log)
        before = len(session.frames)
        session.send(F.window_update_raw(0, 0))
        _pt, alive = session.drain(2.0)
        frames = session.frames[before:]
        err = goaway_error(session.frames)
        evidence = [
            f"alive={alive}",
            f"goaway_error={err}",
            f"new_frames={len(frames)}",
        ]
        # Strict PASS: GOAWAY PROTOCOL_ERROR (1) or connection dead after GOAWAY.
        if err == F.PROTOCOL_ERROR:
            return ProbeResult("wu_zero_conn", title, rfc, Status.PASS,
                               "GOAWAY PROTOCOL_ERROR", evidence)
        if not alive and err is None:
            return ProbeResult(
                "wu_zero_conn", title, rfc, Status.ANOMALY,
                "connection closed without GOAWAY PROTOCOL_ERROR — needs manual review",
                evidence,
            )
        if alive and _ping_alive(session):
            return ProbeResult(
                "wu_zero_conn", title, rfc, Status.FAIL,
                "connection stayed up and answered PING after WU(0)=0 (RFC violation)",
                evidence,
            )
        return ProbeResult(
            "wu_zero_conn", title, rfc, Status.ANOMALY,
            f"unclear rejection pattern (goaway={err}, alive={alive})",
            evidence,
        )
    except Exception as exc:
        return ProbeResult("wu_zero_conn", title, rfc, Status.ERROR, str(exc))
    finally:
        if session:
            session.close()


def probe_wu_zero_stream(target: Target, log: LogFn) -> ProbeResult:
    """Zero increment on a stream WINDOW_UPDATE — also PROTOCOL_ERROR (connection).

    Stream is opened with HEADERS *without* END_STREAM so it stays in open
    state (matches h2spec http2/6.9/2). Sending WU(0) after END_STREAM can
    hit a closed/half-closed stream that some stacks silently ignore — that
    is a probe artifact, not an RFC deviation.
    """
    title = "WINDOW_UPDATE increment 0 (stream) rejected"
    rfc = "RFC 9113 §6.9.1"
    if not target.supports_h2:
        return ProbeResult("wu_zero_stream", title, rfc, Status.SKIP, "target does not speak h2")
    session = None
    try:
        session = _open(target.url, target.path, log)
        # Open stream 1 without END_STREAM (h2spec-aligned); WU immediately.
        open_hdrs = F.headers_frame(
            1, F.request_headers(session.authority, target.path), end_stream=False
        )
        wu0 = F.window_update_raw(1, 0)
        before = len(session.frames)
        session.send(open_hdrs + wu0)
        _pt, alive = session.drain(2.0)
        err = goaway_error(session.frames)
        new_frames = session.frames[before:]
        rst = [
            (sid, int.from_bytes(payload, "big") if len(payload) == 4 else -1)
            for kind, _f, sid, payload in new_frames
            if kind == F.RST_STREAM
        ]
        evidence = [
            f"alive={alive}",
            f"goaway_error={err}",
            f"rst={rst}",
            "opened_without_end_stream=1",
            f"wu_frame_hex={wu0.hex()}",
        ]
        if err == F.PROTOCOL_ERROR:
            return ProbeResult("wu_zero_stream", title, rfc, Status.PASS,
                               "GOAWAY PROTOCOL_ERROR", evidence)
        # Hard close without GOAWAY (Envoy-style) after the illegal WU.
        if not alive and err is None:
            return ProbeResult(
                "wu_zero_stream", title, rfc, Status.ANOMALY,
                "connection closed without GOAWAY PROTOCOL_ERROR — needs manual review",
                evidence,
            )
        # Some stacks RST the stream instead — rejection, but not the
        # connection error the RFC requires → ANOMALY (h2spec still passes).
        if rst and alive:
            return ProbeResult(
                "wu_zero_stream", title, rfc, Status.ANOMALY,
                "RST_STREAM on stream only; RFC wants connection PROTOCOL_ERROR "
                "(h2spec treats this as pass)",
                evidence,
            )
        if alive and _ping_alive(session):
            return ProbeResult(
                "wu_zero_stream", title, rfc, Status.FAIL,
                "accepted zero stream WINDOW_UPDATE on an open stream "
                "(connection still usable) — confirmed with open-stream probe",
                evidence,
            )
        return ProbeResult(
            "wu_zero_stream", title, rfc, Status.ANOMALY,
            f"unclear (goaway={err}, alive={alive}, rst={rst})", evidence,
        )
    except Exception as exc:
        return ProbeResult("wu_zero_stream", title, rfc, Status.ERROR, str(exc))
    finally:
        if session:
            session.close()


def probe_wu_conn_overflow(target: Target, log: LogFn) -> ProbeResult:
    """Increment that would push connection window above MAX → FLOW_CONTROL_ERROR.

    Initial connection window is 65,535. WINDOW_UPDATE(0, MAX) yields
    65535+MAX > MAX. RFC 9113 §6.9.1: MUST treat as connection error
    FLOW_CONTROL_ERROR.
    """
    title = "connection WINDOW_UPDATE that exceeds MAX rejected"
    rfc = "RFC 9113 §6.9.1"
    if not target.supports_h2:
        return ProbeResult("wu_conn_overflow", title, rfc, Status.SKIP, "target does not speak h2")
    session = None
    try:
        session = _open(target.url, target.path, log)
        session.send(F.window_update(0, F.MAX_WINDOW))
        _pt, alive = session.drain(2.0)
        err = goaway_error(session.frames)
        evidence = [f"alive={alive}", f"goaway_error={err}"]
        if err == F.FLOW_CONTROL_ERROR:
            return ProbeResult("wu_conn_overflow", title, rfc, Status.PASS,
                               "GOAWAY FLOW_CONTROL_ERROR", evidence)
        if alive and _ping_alive(session):
            return ProbeResult(
                "wu_conn_overflow", title, rfc, Status.FAIL,
                "accepted connection WU that overflows MAX (RFC violation)",
                evidence,
            )
        return ProbeResult(
            "wu_conn_overflow", title, rfc, Status.ANOMALY,
            f"rejected-ish but not GOAWAY FLOW_CONTROL_ERROR (goaway={err}, alive={alive})",
            evidence,
        )
    except Exception as exc:
        return ProbeResult("wu_conn_overflow", title, rfc, Status.ERROR, str(exc))
    finally:
        if session:
            session.close()


def probe_wu_stream_overflow(target: Target, log: LogFn) -> ProbeResult:
    """Stream WINDOW_UPDATE that would exceed MAX → FLOW_CONTROL_ERROR.

    Keep the stream open with zero credit, raise to MAX, then +1 in one flight
    so we do not accidentally WU a already-closed stream after a full response.
    """
    title = "stream WINDOW_UPDATE that exceeds MAX rejected"
    rfc = "RFC 9113 §6.9.1"
    if not target.supports_h2:
        return ProbeResult("wu_stream_overflow", title, rfc, Status.SKIP, "target does not speak h2")
    session = None
    try:
        session = _open(target.url, target.path, log)
        # Zero stream credit so DATA cannot complete/close the stream first.
        session.send(F.settings_initial_window(0))
        time.sleep(0.05)
        flight = (
            F.get_request(1, session.authority, target.path)
            + F.window_update(1, F.MAX_WINDOW)  # 0 → MAX (legal)
            + F.window_update(1, 1)             # MAX → MAX+1 (illegal)
        )
        session.send(flight)
        _pt, alive = session.drain(2.0)
        err = goaway_error(session.frames)
        evidence = [f"alive={alive}", f"goaway_error={err}"]
        if err == F.FLOW_CONTROL_ERROR:
            return ProbeResult("wu_stream_overflow", title, rfc, Status.PASS,
                               "GOAWAY FLOW_CONTROL_ERROR", evidence)
        rst_fc = any(
            kind == F.RST_STREAM and sid == 1 and len(payload) == 4
            and int.from_bytes(payload, "big") == F.FLOW_CONTROL_ERROR
            for kind, _f, sid, payload in session.frames
        )
        if rst_fc and alive:
            return ProbeResult(
                "wu_stream_overflow", title, rfc, Status.ANOMALY,
                "RST_STREAM FLOW_CONTROL_ERROR on stream; RFC wants connection error — "
                "needs manual review, not claimed as a CVE",
                evidence + ["rst_stream_fc=1"],
            )
        if alive and _ping_alive(session):
            return ProbeResult(
                "wu_stream_overflow", title, rfc, Status.FAIL,
                "accepted stream WU that overflows MAX while stream was open",
                evidence,
            )
        return ProbeResult(
            "wu_stream_overflow", title, rfc, Status.ANOMALY,
            f"unclear (goaway={err}, alive={alive})", evidence,
        )
    except Exception as exc:
        return ProbeResult("wu_stream_overflow", title, rfc, Status.ERROR, str(exc))
    finally:
        if session:
            session.close()


def probe_settings_iw_overflow(target: Target, log: LogFn) -> ProbeResult:
    """SETTINGS_INITIAL_WINDOW_SIZE delta that would push a stream past MAX.

    RFC 9113 §6.9.2: resulting window > MAX MUST be a connection error
    FLOW_CONTROL_ERROR. Some servers RST the stream and keep the connection —
    recorded as ANOMALY, not a CVE claim.
    """
    title = "SETTINGS_INITIAL_WINDOW_SIZE overflow handling"
    rfc = "RFC 9113 §6.9.2"
    if not target.supports_h2:
        return ProbeResult("settings_iw_overflow", title, rfc, Status.SKIP, "target does not speak h2")
    session = None
    try:
        session = _open(target.url, target.path, log)
        session.send(F.settings_initial_window(0))
        time.sleep(0.05)
        # One flight: open stream at 0 credit, raise to MAX-1, then SETTINGS 2
        # (delta +2) before any DATA can complete the stream.
        before = len(session.frames)
        session.send(
            F.get_request(1, session.authority, target.path)
            + F.window_update(1, F.MAX_WINDOW - 1)
            + F.settings_initial_window(2)
        )
        _pt, alive = session.drain(2.0)
        err = goaway_error(session.frames)
        rst = {
            sid: int.from_bytes(payload, "big")
            for kind, _f, sid, payload in session.frames[before:]
            if kind == F.RST_STREAM and len(payload) == 4
        }
        evidence = [f"alive={alive}", f"goaway_error={err}", f"rst={rst}"]
        if err == F.FLOW_CONTROL_ERROR:
            return ProbeResult(
                "settings_iw_overflow", title, rfc, Status.PASS,
                "GOAWAY FLOW_CONTROL_ERROR (strict RFC)", evidence,
            )
        if rst.get(1) == F.FLOW_CONTROL_ERROR and alive:
            return ProbeResult(
                "settings_iw_overflow", title, rfc, Status.ANOMALY,
                "stream RST FLOW_CONTROL_ERROR, connection kept — RFC wants connection error; "
                "NOT claimed as a vulnerability by itself",
                evidence,
            )
        if alive and _ping_alive(session) and 1 not in rst:
            return ProbeResult(
                "settings_iw_overflow", title, rfc, Status.FAIL,
                "SETTINGS overflow appeared to be accepted with no RST/GOAWAY",
                evidence,
            )
        return ProbeResult(
            "settings_iw_overflow", title, rfc, Status.ANOMALY,
            f"mixed/unclear reaction (goaway={err}, rst={rst}, alive={alive})",
            evidence,
        )
    except Exception as exc:
        return ProbeResult("settings_iw_overflow", title, rfc, Status.ERROR, str(exc))
    finally:
        if session:
            session.close()


def _soft_transport_failure(exc: BaseException) -> bool:
    """True when the peer/transport died before we could evaluate accounting."""
    msg = str(exc)
    return (
        "ALPN" in msg
        or "NO_APPLICATION_PROTOCOL" in msg
        or "body size" in msg
        or "empty bodies" in msg
        or "Broken pipe" in msg
        or "Connection reset" in msg
        or "Connection refused" in msg
        or isinstance(exc, BrokenPipeError)
        or isinstance(exc, ConnectionResetError)
        or isinstance(exc, ConnectionRefusedError)
    )


def _cleanup_driver_config(target: Target, log: LogFn, *, key_updates, carrier_app_bytes) -> DriverConfig:
    kw: dict = {"url": target.url, "path": target.path, "log": log}
    if key_updates is not None:
        kw["key_updates"] = key_updates
    if carrier_app_bytes is not None:
        kw["carrier_app_bytes"] = carrier_app_bytes
    return DriverConfig(**kw)


def probe_cleanup_overcredit(target: Target, log: LogFn) -> ProbeResult:
    """Queued-DATA cleanup over-credit + underflowed WINDOW_UPDATE guard.

    This is the CVE-2026-123007 *accounting* signal (not RCE). FAIL means the
    invariant was violated (vulnerable class). PASS means a complete probe ran
    and the accounting signal was NOT observed. INCONCLUSIVE means the probe
    could not complete (transport died) — never reported as PASS.
    """
    title = "queued-DATA cleanup must not push connection window above MAX"
    rfc = "RFC 9113 §6.9 / CWE-191 class (nginx CVE-2026-123007 accounting)"
    if not target.supports_h2:
        return ProbeResult("cleanup_overcredit", title, rfc, Status.SKIP, "target does not speak h2")

    # Primary profile from target tuning (None → DriverConfig defaults).
    attempts: list[tuple[str, int | None, int | None]] = [
        ("primary", target.key_updates, target.carrier_app_bytes),
    ]
    # Soft-failure fallback (disabled when fallback_key_updates is None).
    if target.fallback_key_updates is not None:
        fb_ku = target.fallback_key_updates
        fb_car = target.fallback_carrier_app_bytes
        # Avoid a duplicate attempt when fallback == primary.
        primary_ku = target.key_updates
        primary_car = target.carrier_app_bytes
        if (fb_ku, fb_car) != (primary_ku, primary_car):
            attempts.append(("fallback", fb_ku, fb_car))

    soft_failures: list[str] = []
    for label, ku, car in attempts:
        # Resolve display values (None → defaults known to DriverConfig).
        from .driver import DEFAULT_CARRIER_APP_BYTES, DEFAULT_KEY_UPDATES
        ku_disp = DEFAULT_KEY_UPDATES if ku is None else ku
        car_disp = DEFAULT_CARRIER_APP_BYTES if car is None else car
        log(f"    cleanup profile={label} key_updates={ku_disp} carrier={car_disp}")
        try:
            cfg = _cleanup_driver_config(target, log, key_updates=ku, carrier_app_bytes=car)
            obs = run_accounting_probe(cfg)
            report = evaluate_connection_window_invariant(obs)
            evidence = [
                f"profile={label} key_updates={ku_disp} carrier={car_disp}",
                *[f"{c.name}={'PASS' if c.passed else 'FAIL'}: {c.detail}" for c in report.checks],
            ]
            if soft_failures:
                evidence.append("prior_soft_failures=" + " | ".join(soft_failures))
            if report.verdict.value == "VULNERABLE":
                return ProbeResult(
                    "cleanup_overcredit", title, rfc, Status.FAIL,
                    "INVARIANT BROKEN: cleanup over-credit + underflowed WU guard (accounting bug class)",
                    evidence,
                )
            return ProbeResult(
                "cleanup_overcredit", title, rfc, Status.PASS,
                f"accounting over-credit signal NOT proven (completed under {label} "
                f"key_updates={ku_disp}, carrier={car_disp})",
                evidence,
            )
        except (ssl.SSLError, OSError, RuntimeError, ValueError) as exc:
            msg = f"{type(exc).__name__}: {exc}"
            if _soft_transport_failure(exc):
                soft_failures.append(f"{label}(ku={ku_disp},carrier={car_disp}): {msg}")
                log(f"    soft failure on {label}: {msg}")
                continue
            return ProbeResult("cleanup_overcredit", title, rfc, Status.ERROR, msg)

    # Every attempt soft-failed — honest INCONCLUSIVE, never a fabricated PASS.
    detail = (
        "probe could not complete on any profile; accounting signal unevaluable. "
        + " ; ".join(soft_failures)
    )
    return ProbeResult(
        "cleanup_overcredit", title, rfc, Status.INCONCLUSIVE, detail,
        soft_failures,
    )


PROBES: dict[str, Callable[[Target, LogFn], ProbeResult]] = {
    "h2_alpn": probe_h2_alpn,
    "wu_zero_conn": probe_wu_zero_conn,
    "wu_zero_stream": probe_wu_zero_stream,
    "wu_conn_overflow": probe_wu_conn_overflow,
    "wu_stream_overflow": probe_wu_stream_overflow,
    "settings_iw_overflow": probe_settings_iw_overflow,
    "cleanup_overcredit": probe_cleanup_overcredit,
}


DEFAULT_PROBE_ORDER = (
    "h2_alpn",
    "wu_zero_conn",
    "wu_zero_stream",
    "wu_conn_overflow",
    "wu_stream_overflow",
    "settings_iw_overflow",
    "cleanup_overcredit",
)


def _maybe_restart_target(target: Target, log: LogFn, reason: str) -> None:
    name = getattr(target, "restart_container", "") or ""
    if not name:
        return
    log(f"    [restart:{reason}] docker restart {name}")
    try:
        subprocess.run(
            ["docker", "restart", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        time.sleep(2.0)
    except Exception as exc:
        log(f"    [restart:{reason}] failed: {exc}")


def run_battery_on_target(
    target: Target,
    probe_ids: list[str] | None = None,
    log: LogFn = print,
) -> TargetBatteryReport:
    report = TargetBatteryReport(
        target_id=target.id, target_name=target.name, url=target.url
    )
    selected = list(probe_ids or target.probes or DEFAULT_PROBE_ORDER)
    for pid in selected:
        fn = PROBES.get(pid)
        if fn is None:
            report.results.append(
                ProbeResult(pid, pid, "", Status.ERROR, f"unknown probe id {pid!r}")
            )
            continue
        # Envoy (and similar) may exit under earlier adversarial WU probes;
        # bring them back before the heavy discriminator so it can actually run.
        if pid == "cleanup_overcredit":
            _maybe_restart_target(target, log, "pre-cleanup_overcredit")
        log(f"--- {target.id} :: {pid} ---")
        result = fn(target, log)
        report.results.append(result)
        log(f"    => {result.status.value}: {result.detail}")
    return report


def format_matrix(reports: list[TargetBatteryReport]) -> str:
    """ASCII matrix: rows=probes, cols=targets."""
    if not reports:
        return "(no reports)"
    probes = []
    for r in reports:
        for pr in r.results:
            if pr.probe_id not in probes:
                probes.append(pr.probe_id)
    cols = [r.target_id for r in reports]
    # header
    width_p = max(len("probe"), max(len(p) for p in probes))
    width_c = max(8, max(len(c) for c in cols))
    lines = []
    header = "probe".ljust(width_p) + " | " + " | ".join(c.ljust(width_c) for c in cols)
    lines.append(header)
    lines.append("-" * len(header))
    lookup = {
        (r.target_id, pr.probe_id): pr.status.value
        for r in reports
        for pr in r.results
    }
    for p in probes:
        row = p.ljust(width_p) + " | " + " | ".join(
            lookup.get((c, p), "-").ljust(width_c) for c in cols
        )
        lines.append(row)
    lines.append("")
    lines.append(
        "Legend: PASS=invariant held / RFC reaction; "
        "FAIL=invariant broken (bug-class signal); "
        "ANOMALY=needs manual review (NOT a confirmed vulnerability); "
        "INCONCLUSIVE=probe could not complete (NOT a PASS); "
        "SKIP=not applicable; ERROR=harness failure"
    )
    return "\n".join(lines)


def format_report_detailed(report: TargetBatteryReport) -> str:
    lines = [f"# {report.target_id} — {report.target_name}", f"url: {report.url}", ""]
    for pr in report.results:
        lines.append(f"## {pr.probe_id} — {pr.status.value}")
        lines.append(f"title: {pr.title}")
        lines.append(f"rfc:   {pr.rfc}")
        lines.append(f"detail: {pr.detail}")
        for ev in pr.evidence:
            lines.append(f"  evidence: {ev}")
        lines.append("")
    return "\n".join(lines)
