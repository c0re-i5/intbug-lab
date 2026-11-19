#!/usr/bin/env bash
set -euo pipefail
for name in \
  integer-lab-nginx-1318 integer-lab-nginx-neg integer-lab-nginx-1319 \
  integer-lab-httpd integer-lab-caddy integer-lab-envoy \
  integer-lab-go integer-lab-nghttpd integer-lab-openresty
do
  docker rm -f "$name" >/dev/null 2>&1 || true
  echo "removed $name"
done
