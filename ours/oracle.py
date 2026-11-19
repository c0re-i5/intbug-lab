"""HTTP/2 flow-control invariant oracle (target-agnostic).

Status vocabulary used by the slice-3 battery:
  PASS    — invariant held / RFC-required reaction observed
  FAIL    — invariant clearly violated (bug-class signal)
  ANOMALY — unexpected deviation; needs manual review (NOT a confirmed CVE)
  SKIP    — probe not applicable
  ERROR   — harness/transport failure

Legacy `evaluate_connection_window_invariant` remains for the cleanup-overcredit
signal used by slice 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence


MAX_WINDOW = 0x7FFFFFFF
FLOW_CONTROL_ERROR = 3
PROTOCOL_ERROR = 1


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ANOMALY = "ANOMALY"
    INCONCLUSIVE = "INCONCLUSIVE"  # probe could not complete; NOT a PASS
    SKIP = "SKIP"
    ERROR = "ERROR"


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    NOT_PROVEN = "NOT_PROVEN"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


@dataclass
class OracleReport:
    verdict: Verdict
    checks: list[CheckResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)


@dataclass
class FlowControlObservation:
    expected_fc_reset_streams: Sequence[int]
    rst_errors: dict[int, int]
    canary_body: bytes
    expected_canary_body: bytes
    post_refund_ping_acked: bool
    negotiated_h2: bool = True
    extras: dict = field(default_factory=dict)


def evaluate_connection_window_invariant(obs: FlowControlObservation) -> OracleReport:
    """Slice-2 cleanup-overcredit signal (CVE-2026-123007 accounting class)."""
    notes: list[str] = []
    checks: list[CheckResult] = []

    if not obs.negotiated_h2:
        return OracleReport(
            verdict=Verdict.NOT_PROVEN,
            checks=[CheckResult("alpn_h2", False, "peer did not negotiate HTTP/2 (ALPN h2)")],
            notes=["No HTTP/2 session — invariant not applicable."],
        )

    expected = list(obs.expected_fc_reset_streams)
    got = {sid: obs.rst_errors.get(sid) for sid in expected}
    fc_ok = all(got.get(sid) == FLOW_CONTROL_ERROR for sid in expected) and len(expected) >= 1
    checks.append(
        CheckResult(
            "queued_data_refund_resets",
            fc_ok,
            f"expected RST FLOW_CONTROL_ERROR on {expected}; got {got}",
        )
    )

    release_ok = len(obs.expected_canary_body) > 0 and obs.canary_body == obs.expected_canary_body
    checks.append(
        CheckResult(
            "public_byte_release",
            release_ok,
            f"canary {len(obs.canary_body)} bytes vs expected {len(obs.expected_canary_body)}",
        )
    )

    checks.append(
        CheckResult(
            "underflowed_wu_guard",
            bool(obs.post_refund_ping_acked),
            "post-refund PING ACK"
            if obs.post_refund_ping_acked
            else "no matching PING ACK after suspected over-credit WINDOW_UPDATE",
        )
    )

    usable = release_ok and bool(obs.post_refund_ping_acked)
    checks.append(
        CheckResult(
            "connection_still_usable",
            usable,
            "canary DATA + PING ACK on same connection"
            if usable
            else "connection did not remain cleanly usable",
        )
    )

    notes.append(
        "Invariant: connection send_window must remain in [0, MAX=2^31-1]. "
        "Accepting a MAX WINDOW_UPDATE after a queued-DATA refund that drove the "
        "counter above MAX is the underflowed-guard failure (CWE-191)."
    )
    notes.append(
        "This oracle proves the *accounting* bug only. It does not walk the "
        "counter to 2^64 and does not prove memory corruption or RCE."
    )

    verdict = Verdict.VULNERABLE if all(c.passed for c in checks) else Verdict.NOT_PROVEN
    return OracleReport(verdict=verdict, checks=checks, notes=notes)


def format_report(report: OracleReport, target: str = "") -> str:
    lines = []
    tag = {
        Verdict.VULNERABLE: "[+] INVARIANT VIOLATION: VULNERABLE",
        Verdict.NOT_PROVEN: "[-] NOT PROVEN",
        Verdict.ERROR: "[!] ERROR",
    }[report.verdict]
    lines.append(tag + (f"  target={target}" if target else ""))
    for i, check in enumerate(report.checks, 1):
        mark = "PASS" if check.passed else "FAIL"
        lines.append(f"    [{i}] {check.name:28s}: {mark} ({check.detail})")
    for note in report.notes:
        lines.append(f"    note: {note}")
    return "\n".join(lines)


# --- helpers shared by the battery ---

def goaway_error(frames) -> int | None:
    """Return GOAWAY error code if present (payload bytes 4..8)."""
    from . import framing as F

    for kind, _flags, _sid, payload in frames:
        if kind == F.GOAWAY and len(payload) >= 8:
            return int.from_bytes(payload[4:8], "big")
    return None


def connection_error_seen(frames, alive: bool, codes: set[int]) -> bool:
    err = goaway_error(frames)
    if err is not None and err in codes:
        return True
    # Hard close without GOAWAY after we sent an illegal frame is acceptable
    # evidence of rejection for some stacks.
    if not alive and err is None:
        return False
    return False
