#!/usr/bin/env python3
"""CLI: run our counter-driver + oracle against a loopback lab target."""

from __future__ import annotations

import argparse
import ssl
import sys
from pathlib import Path

# Allow `python ours/run_proof.py` from repo root or `python -m ours.run_proof`.
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "ours"

from ours.driver import DriverConfig, run_accounting_probe
from ours.oracle import Verdict, evaluate_connection_window_invariant, format_report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lab-local HTTP/2 flow-control accounting proof")
    p.add_argument(
        "--url",
        default="https://127.0.0.1:19443/",
        help="loopback HTTPS origin (default lab port 19443)",
    )
    p.add_argument("--path", default="/index.html")
    p.add_argument(
        "--key-updates",
        type=int,
        default=DriverConfig.key_updates,
        help="TLS 1.3 KeyUpdate count after the cleanup flight (0 to skip)",
    )
    p.add_argument(
        "--carrier-bytes",
        type=int,
        default=DriverConfig.carrier_app_bytes,
        help="application bytes in the prepared carrier+event flight",
    )
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv)

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, flush=True)

    cfg = DriverConfig(
        url=args.url,
        path=args.path,
        key_updates=args.key_updates,
        carrier_app_bytes=args.carrier_bytes,
        log=log,
    )

    try:
        obs = run_accounting_probe(cfg)
    except ValueError as exc:
        # Non-loopback refusal, bad URL, etc.
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        return 2
    except (RuntimeError, ssl.SSLError, OSError) as exc:
        msg = str(exc)
        print(f"[*] driver stopped: {msg}", flush=True)
        no_h2 = (
            "ALPN" in msg
            or "h2" in msg.lower()
            or "NO_APPLICATION_PROTOCOL" in msg
            or "no application protocol" in msg.lower()
        )
        if no_h2:
            from ours.oracle import FlowControlObservation
            report = evaluate_connection_window_invariant(
                FlowControlObservation(
                    expected_fc_reset_streams=(),
                    rst_errors={},
                    canary_body=b"",
                    expected_canary_body=b"",
                    post_refund_ping_acked=False,
                    negotiated_h2=False,
                )
            )
            print(format_report(report, target=args.url))
            return 4
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        return 2

    report = evaluate_connection_window_invariant(obs)
    print(format_report(report, target=args.url))
    extras = obs.extras or {}
    if extras:
        print(
            f"    meta: body={extras.get('body_size')} "
            f"carrier={extras.get('carrier_app_bytes')} "
            f"key_updates={extras.get('key_updates')}"
        )

    if report.verdict == Verdict.VULNERABLE:
        return 0
    if report.verdict == Verdict.NOT_PROVEN:
        return 4
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
