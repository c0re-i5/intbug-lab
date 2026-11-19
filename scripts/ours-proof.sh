#!/usr/bin/env bash
# Run our counter-driver + oracle against the local lab.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${LAB_PORT:-19443}"
URL="${1:-https://127.0.0.1:${PORT}/}"
mkdir -p "${ROOT}/evidence"
OUT="${ROOT}/evidence/OURS-run-$(date +%Y%m%d-%H%M%S).txt"
cd "$ROOT"
set +e
"${ROOT}/.venv/bin/python" -m ours.run_proof --url "$URL" 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
set -e
echo "Saved: $OUT (exit $rc)"
exit "$rc"
