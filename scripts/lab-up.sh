#!/usr/bin/env bash
# Start vulnerable nginx 1.31.8 (CVE-2026-123007) on 127.0.0.1:19443 only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${LAB_NAME:-integer-lab-nginx-1318}"
PORT="${LAB_PORT:-19443}"
IMAGE='nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da'

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon not reachable. Start dockerd first." >&2
  exit 1
fi

docker pull --platform linux/amd64 "$IMAGE"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --platform linux/amd64 \
  -p "127.0.0.1:${PORT}:443" \
  --mount type=bind,src="${ROOT}/conf/nginx.conf",dst=/etc/nginx/nginx.conf,readonly \
  --entrypoint sh "$IMAGE" -c '
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout /tmp/nginx-h2.key -out /tmp/nginx-h2.crt \
      -subj /CN=localhost \
      -addext subjectAltName=DNS:localhost,IP:127.0.0.1 &&
    exec nginx -g "daemon off;"'

echo "Waiting for HTTPS..."
for i in $(seq 1 30); do
  if curl -skS --http2 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PORT}/index.html" 2>/dev/null | grep -q 200; then
    break
  fi
  sleep 0.5
done

echo "=== nginx -v ==="
docker exec "$NAME" nginx -v
echo "=== HTTP/2 smoke ==="
curl -skS --http2 -D - -o /dev/null "https://127.0.0.1:${PORT}/index.html"
echo "Lab up: https://127.0.0.1:${PORT}/  (loopback only)"
