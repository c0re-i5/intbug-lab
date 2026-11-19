#!/usr/bin/env bash
# Box-specific helper: start static dockerd when apt docker is unavailable.
# Requires docker/dockerd already installed under /usr/local/bin (static 27.5.1).
set -euo pipefail
if docker info >/dev/null 2>&1; then
  echo "dockerd already reachable"
  exit 0
fi
sudo mkdir -p /var/lib/docker /var/run
sudo dockerd --host=unix:///var/run/docker.sock \
  --data-root=/var/lib/docker \
  --iptables=false --ip6tables=false \
  >/tmp/dockerd.log 2>&1 &
for i in $(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then
    sudo chmod 666 /var/run/docker.sock || true
    echo "dockerd ready"
    exit 0
  fi
  sleep 0.5
done
echo "dockerd failed; see /tmp/dockerd.log" >&2
tail -40 /tmp/dockerd.log >&2
exit 1
