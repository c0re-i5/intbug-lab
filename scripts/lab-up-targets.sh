#!/usr/bin/env bash
# Start all configured loopback HTTP/2 lab targets (digest-pinned).
# Idempotent: removes any prior containers of the same name first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! docker info >/dev/null 2>&1; then
  echo "Docker not reachable; try ./scripts/box-dockerd.sh" >&2
  exit 1
fi

# --- pinned digests (must match ours/targets.py) ---
NGINX_VULN='nginx@sha256:5ab5b0b01097420873a3f3330f44248e34a3c2a3e8d5ee30658aeae8cb7435da'
NGINX_FIX='nginx@sha256:08f354a3b44c422021a5c0f5efb3e27f8f90236b5447d3bac4053f5f50ab6760'
HTTPD='httpd@sha256:32e9403360ab2f1047523e72f256527fb9aee68b342abf6ad03f0d629157f3d9'
CADDY='caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb'
ENVOY='envoyproxy/envoy@sha256:6bf0d37dd5e8eac4b37effe89a1aec4760f7f2ce860d1fd6af22147eb87a5058'
GOLANG='golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac'
DEBIAN='debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc'
# openresty/1.31.8.1 alpine — still the nginx 1.31.8 line.
OPENRESTY='openresty/openresty@sha256:2cb90d64192934c26b3749cf744f47edd59277787fe761bd109eeebdc3e2214a'
# node:22-alpine → v22.23.5. Lab app (conf/node) is not separately hashed.
NODE='node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a'

ensure_certs() {
  if [[ ! -f certs/lab.crt || ! -f certs/lab.key ]]; then
    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout certs/lab.key -out certs/lab.crt \
      -subj /CN=localhost \
      -addext subjectAltName=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1
    chmod 644 certs/lab.crt certs/lab.key
    echo "generated certs/lab.{crt,key}"
  fi
}

start_nginx() {
  local name="$1" image="$2" port="$3" conf="$4"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --platform linux/amd64 \
    -p "127.0.0.1:${port}:443" \
    --mount type=bind,src="${ROOT}/conf/${conf}",dst=/etc/nginx/nginx.conf,readonly \
    --entrypoint sh "$image" -c '
      openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -keyout /tmp/nginx-h2.key -out /tmp/nginx-h2.crt \
        -subj /CN=localhost \
        -addext subjectAltName=DNS:localhost,IP:127.0.0.1 &&
      exec nginx -g "daemon off;"'
  echo "started $name on 127.0.0.1:${port}"
}

ensure_certs

# --- nginx family ---
start_nginx integer-lab-nginx-1318 "$NGINX_VULN" 19443 nginx.conf
start_nginx integer-lab-nginx-neg   "$NGINX_VULN" 19444 nginx-http2-off.conf
docker pull --platform linux/amd64 "$NGINX_FIX" >/dev/null
start_nginx integer-lab-nginx-1319 "$NGINX_FIX" 19446 nginx.conf

# --- Apache httpd ---
docker pull --platform linux/amd64 "$HTTPD" >/dev/null
docker rm -f integer-lab-httpd >/dev/null 2>&1 || true
docker run -d --name integer-lab-httpd --platform linux/amd64 \
  -p 127.0.0.1:19445:443 \
  --mount type=bind,src="${ROOT}/conf/apache/htdocs",dst=/usr/local/apache2/htdocs-lab,readonly \
  --mount type=bind,src="${ROOT}/conf/apache/entrypoint.sh",dst=/entrypoint-lab.sh,readonly \
  --entrypoint sh "$HTTPD" /entrypoint-lab.sh
echo "started integer-lab-httpd on 127.0.0.1:19445"

# --- Caddy ---
docker pull --platform linux/amd64 "$CADDY" >/dev/null
docker rm -f integer-lab-caddy >/dev/null 2>&1 || true
docker run -d --name integer-lab-caddy --platform linux/amd64 \
  -p 127.0.0.1:19447:443 \
  --mount type=bind,src="${ROOT}/conf/caddy/Caddyfile",dst=/etc/caddy/Caddyfile,readonly \
  --mount type=bind,src="${ROOT}/conf/shared/index.html",dst=/srv/index.html,readonly \
  --mount type=bind,src="${ROOT}/certs/lab.crt",dst=/certs/lab.crt,readonly \
  --mount type=bind,src="${ROOT}/certs/lab.key",dst=/certs/lab.key,readonly \
  "$CADDY"
echo "started integer-lab-caddy on 127.0.0.1:19447"

# --- Envoy ---
docker pull --platform linux/amd64 "$ENVOY" >/dev/null
docker rm -f integer-lab-envoy >/dev/null 2>&1 || true
docker run -d --name integer-lab-envoy --platform linux/amd64 \
  -p 127.0.0.1:19448:10000 \
  --mount type=bind,src="${ROOT}/conf/envoy/envoy.yaml",dst=/etc/envoy/envoy.yaml,readonly \
  --mount type=bind,src="${ROOT}/conf/shared/index.html",dst=/srv/index.html,readonly \
  --mount type=bind,src="${ROOT}/certs/lab.crt",dst=/certs/lab.crt,readonly \
  --mount type=bind,src="${ROOT}/certs/lab.key",dst=/certs/lab.key,readonly \
  "$ENVOY" -c /etc/envoy/envoy.yaml
echo "started integer-lab-envoy on 127.0.0.1:19448"

# --- Go net/http (built locally from pinned golang digest) ---
docker pull --platform linux/amd64 "$GOLANG" >/dev/null
docker build --platform linux/amd64 --build-arg GO_IMAGE="$GOLANG" \
  -t integer-lab-go:pinned "${ROOT}/conf/go" >/dev/null
docker rm -f integer-lab-go >/dev/null 2>&1 || true
docker run -d --name integer-lab-go --platform linux/amd64 \
  -p 127.0.0.1:19449:443 integer-lab-go:pinned
echo "started integer-lab-go on 127.0.0.1:19449"

# --- nghttpd (built locally from pinned debian; apt package not digest-pinned) ---
docker pull --platform linux/amd64 "$DEBIAN" >/dev/null
docker build --platform linux/amd64 --build-arg DEBIAN_IMAGE="$DEBIAN" \
  -t integer-lab-nghttpd:pinned "${ROOT}/conf/nghttpd" >/dev/null
docker rm -f integer-lab-nghttpd >/dev/null 2>&1 || true
docker run -d --name integer-lab-nghttpd --platform linux/amd64 \
  -p 127.0.0.1:19450:443 integer-lab-nghttpd:pinned
echo "started integer-lab-nghttpd on 127.0.0.1:19450"

# --- OpenResty (nginx 1.31.8 line; openssl self-signed, like nginx-1318) ---
docker pull --platform linux/amd64 "$OPENRESTY" >/dev/null
docker rm -f integer-lab-openresty >/dev/null 2>&1 || true
docker run -d --name integer-lab-openresty --platform linux/amd64 \
  -p 127.0.0.1:19452:443 \
  --mount type=bind,src="${ROOT}/conf/openresty/nginx.conf",dst=/usr/local/openresty/nginx/conf/nginx.conf,readonly \
  --mount type=bind,src="${ROOT}/conf/shared/index.html",dst=/usr/local/openresty/nginx/html/index.html,readonly \
  --entrypoint sh "$OPENRESTY" -c '
    # openresty alpine has no openssl CLI; cert only, server stays pinned.
    apk add --no-cache openssl >/dev/null &&
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout /tmp/lab-h2.key -out /tmp/lab-h2.crt \
      -subj /CN=localhost \
      -addext subjectAltName=DNS:localhost,IP:127.0.0.1 &&
    exec openresty -g "daemon off;"'
echo "started integer-lab-openresty on 127.0.0.1:19452"

# --- Node.js http2 (built locally from pinned node:22-alpine, like go-nethttp) ---
docker pull --platform linux/amd64 "$NODE" >/dev/null
docker build --platform linux/amd64 --build-arg NODE_IMAGE="$NODE" \
  -t integer-lab-node:pinned "${ROOT}/conf/node" >/dev/null
docker rm -f integer-lab-node >/dev/null 2>&1 || true
docker run -d --name integer-lab-node --platform linux/amd64 \
  -p 127.0.0.1:19454:443 \
  --mount type=bind,src="${ROOT}/certs/lab.crt",dst=/certs/lab.crt,readonly \
  --mount type=bind,src="${ROOT}/certs/lab.key",dst=/certs/lab.key,readonly \
  integer-lab-node:pinned
echo "started integer-lab-node on 127.0.0.1:19454"

sleep 3
echo
echo "=== smoke ==="
for url in \
  https://127.0.0.1:19443/index.html \
  https://127.0.0.1:19444/index.html \
  https://127.0.0.1:19445/index.html \
  https://127.0.0.1:19446/index.html \
  https://127.0.0.1:19447/index.html \
  https://127.0.0.1:19448/index.html \
  https://127.0.0.1:19449/index.html \
  https://127.0.0.1:19450/index.html \
  https://127.0.0.1:19452/index.html \
  https://127.0.0.1:19454/index.html
do
  code=$(curl -skS --http2 -o /dev/null -w '%{http_code}/%{http_version}/%{size_download}' "$url" 2>/dev/null || echo fail)
  echo "smoke $url -> $code"
done
docker ps --filter name=integer-lab --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
