#!/usr/bin/env bash
# Cross-check RFC 9113 §6.9 zero WINDOW_UPDATE cases with h2spec against
# loopback lab targets. Saves raw output under evidence/zero-wu/.
# Loopback-only. NOT a CVE claim.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
H2SPEC="${ROOT}/bin/h2spec"
OUT="${ROOT}/evidence/zero-wu"
mkdir -p "$OUT"

if [[ ! -x "$H2SPEC" ]]; then
  echo "missing $H2SPEC — place h2spec binary there" >&2
  exit 1
fi

# Ensure envoy is up
docker restart integer-lab-envoy >/dev/null 2>&1 || true
sleep 2

SUMMARY="$OUT/h2spec-summary.txt"
: > "$SUMMARY"
echo "# h2spec §6.9 zero-WU cross-check" >> "$SUMMARY"
echo "# $(date)" >> "$SUMMARY"
echo "# cases: http2/6.9/1 (conn WU incr 0), http2/6.9/2 (stream WU incr 0)" >> "$SUMMARY"
echo >> "$SUMMARY"

run_one() {
  local id="$1" port="$2"
  local raw="$OUT/h2spec-${id}.txt"
  echo "==> h2spec $id :$port"
  # -t TLS -k insecure -p port -h 127.0.0.1
  # Restrict to 6.9.1 and 6.9.2 zero-increment cases.
  set +e
  "$H2SPEC" http2/6.9/1 http2/6.9/2 -t -k -h 127.0.0.1 -p "$port" -o 5 -v \
    >"$raw" 2>&1
  local rc=$?
  set -e
  echo "--- $id (exit $rc) ---" >> "$SUMMARY"
  # Pull the 6.9 results
  rg -n "6\.9|WINDOW_UPDATE|✓|×|failed|passed|Error" "$raw" | head -40 >> "$SUMMARY" || true
  echo >> "$SUMMARY"
  # Restart envoy after h2spec too (it may die)
  if [[ "$id" == "envoy-1.32" ]]; then
    docker restart integer-lab-envoy >/dev/null 2>&1 || true
    sleep 2
  fi
}

run_one nginx-1.31.8 19443
run_one httpd-2.4.71 19445
run_one nginx-1.31.9 19446
run_one caddy-2.10 19447
run_one envoy-1.32 19448
run_one go-nethttp 19449
run_one nghttpd 19450

echo "summary: $SUMMARY"
