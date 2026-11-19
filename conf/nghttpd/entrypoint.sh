#!/bin/sh
set -eu
# Self-signed cert generated at container start (loopback lab only).
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout /tmp/lab.key -out /tmp/lab.crt \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1
# nghttpd <PORT> <KEY> <CERT>; -d serves a document root over HTTP/2 + TLS.
exec nghttpd -d /srv 443 /tmp/lab.key /tmp/lab.crt
