#!/usr/bin/env python3
"""Run the HTTP/2 flow-control invariant battery across configured lab targets."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "ours"

from ours.battery import (
    DEFAULT_PROBE_ORDER,
    format_matrix,
    format_report_detailed,
    run_battery_on_target,
)
from ours.targets import TARGETS, get_target, list_targets

def _restart_container(name: str, log) -> None:
    """Best-effort docker restart for flaky targets (e.g. Envoy after adversarial WU)."""
    if not name:
        return
    log(f"[*] restarting container {name}")
    try:
        subprocess.run(
            ["docker", "restart", name],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        log(f"[!] docker restart {name} failed: {exc}")
        return
    # Wait until the published port accepts TCP again (up to ~10s).
    time.sleep(2.0)



def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="HTTP/2 flow-control invariant battery (lab-local)")
    p.add_argument(
        "--targets",
        nargs="*",
        default=None,
        help="target ids (default: all). Known: " + ", ".join(TARGETS),
    )
    p.add_argument(
        "--probes",
        nargs="*",
        default=None,
        help="probe ids (default: per-target or full suite)",
    )
    p.add_argument(
        "--skip-heavy",
        action="store_true",
        help="skip cleanup_overcredit (~14 MiB / ~45s each)",
    )
    p.add_argument(
        "--evidence-dir",
        default=str(Path(__file__).resolve().parents[1] / "evidence"),
    )
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, flush=True)

    ids = args.targets or list(TARGETS.keys())
    targets = [get_target(i) for i in ids]
    probes = list(args.probes) if args.probes else None
    if args.skip_heavy and probes is None:
        probes = [x for x in DEFAULT_PROBE_ORDER if x != "cleanup_overcredit"]
    elif args.skip_heavy and probes is not None:
        probes = [x for x in probes if x != "cleanup_overcredit"]

    reports = []
    for t in targets:
        # Respect target.probes when caller did not override.
        use = probes
        if use is None and t.probes:
            use = list(t.probes)
        if t.restart_container:
            _restart_container(t.restart_container, log)
        reports.append(run_battery_on_target(t, probe_ids=use, log=log))
        # Envoy (and similar) may exit during adversarial WU probes; restart
        # after the target so the next target / subsequent runs see a live peer.
        if t.restart_container:
            _restart_container(t.restart_container, log)

    matrix = format_matrix(reports)
    print()
    print(matrix)

    evidence = Path(args.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(ZoneInfo("America/Toronto")).strftime("%Y%m%d-%H%M%S")
    matrix_path = evidence / f"BATTERY-MATRIX-{stamp}.txt"
    latest = evidence / "BATTERY-MATRIX-latest.txt"
    matrix_path.write_text(matrix + "\n")
    latest.write_text(matrix + "\n")

    for r in reports:
        detail = format_report_detailed(r)
        path = evidence / f"BATTERY-{r.target_id}-{stamp}.txt"
        path.write_text(detail)
        log(f"wrote {path}")

    # Honest summary of FAIL / ANOMALY / INCONCLUSIVE
    print()
    print("=== Summary flags ===")
    any_flag = False
    for r in reports:
        for pr in r.results:
            if pr.status.value == "FAIL":
                any_flag = True
                print(f"FAIL          {r.target_id:20s} {pr.probe_id}: {pr.detail}")
            elif pr.status.value == "ANOMALY":
                any_flag = True
                print(
                    f"ANOMALY       {r.target_id:20s} {pr.probe_id}: {pr.detail} "
                    f"[NOT a confirmed vulnerability — manual review]"
                )
            elif pr.status.value == "INCONCLUSIVE":
                any_flag = True
                print(
                    f"INCONCLUSIVE  {r.target_id:20s} {pr.probe_id}: {pr.detail} "
                    f"[probe incomplete — NOT a PASS]"
                )
    if not any_flag:
        print("(no FAIL, ANOMALY, or INCONCLUSIVE)")
    print(f"matrix: {matrix_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
