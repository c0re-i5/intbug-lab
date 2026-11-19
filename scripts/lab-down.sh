#!/usr/bin/env bash
set -euo pipefail
NAME="${LAB_NAME:-integer-lab-nginx-1318}"
docker stop "$NAME" >/dev/null 2>&1 || true
docker rm "$NAME" >/dev/null 2>&1 || true
echo "Lab down: removed container $NAME"
