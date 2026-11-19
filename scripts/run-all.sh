#!/usr/bin/env bash
# Bring targets up (idempotent), run offline unit tests, run the full battery,
# print the matrix. Loopback-only. Exit 0 always after a successful harness run
# (FAIL/ANOMALY in the matrix are observations, not harness failures).
# Exit non-zero only if: docker unreachable, unit tests fail, or battery crashes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_HEAVY=0
TARGETS_ARG=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-heavy) SKIP_HEAVY=1; shift ;;
    --targets)
      shift
      while [[ $# -gt 0 && "$1" != --* ]]; do TARGETS_ARG+=("$1"); shift; done
      ;;
    -h|--help)
      cat <<USAGE
Usage: ./scripts/run-all.sh [--skip-heavy] [--targets id ...]
  1) ensure dockerd  2) lab-up-targets  3) offline unit tests  4) full battery
USAGE
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "==> [1/4] docker"
./scripts/box-dockerd.sh

echo "==> [2/4] lab-up-targets"
./scripts/lab-up-targets.sh

echo "==> [3/4] offline unit tests"
.venv/bin/python -m unittest discover -s ours/tests -v

echo "==> [4/4] battery"
BATTERY_ARGS=()
if [[ $SKIP_HEAVY -eq 1 ]]; then BATTERY_ARGS+=(--skip-heavy); fi
if [[ ${#TARGETS_ARG[@]} -gt 0 ]]; then BATTERY_ARGS+=(--targets "${TARGETS_ARG[@]}"); fi
.venv/bin/python -m ours.run_battery "${BATTERY_ARGS[@]}"
echo
echo "done. matrix: evidence/BATTERY-MATRIX-latest.txt"
echo "manual review: evidence/MANUAL-REVIEW-NOTES.txt"
