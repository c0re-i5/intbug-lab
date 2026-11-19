#!/usr/bin/env bash
# Run arkrwn --safe against the local lab. Exit 0 = VULNERABLE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${LAB_PORT:-19443}"
POC="${ROOT}/bin/poc-safe"
if [[ ! -x "$POC" ]]; then
  POC="${ROOT}/detectors/arkrwn-nginx2root/target/release/poc"
fi
if [[ ! -x "$POC" ]]; then
  echo "Missing PoC binary. Build: (cd detectors/arkrwn-nginx2root && cargo build --release)" >&2
  exit 1
fi
mkdir -p "${ROOT}/evidence"
OUT="${ROOT}/evidence/arkrwn-safe-proof-$(date +%Y%m%d-%H%M%S).txt"
set +e
"$POC" --host "https://127.0.0.1:${PORT}/" --safe 2>&1 | tee "$OUT"
rc=${PIPESTATUS[0]}
set -e
echo "Saved: $OUT (exit $rc)"
exit "$rc"
