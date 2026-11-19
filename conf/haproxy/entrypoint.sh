#!/bin/sh
# Build the combined PEM HAProxy loads, then exec haproxy in the foreground.
# HAProxy's `crt` keyword wants certificate then private key in one file.
set -eu
mkdir -p /etc/haproxy/certs
cat /certs/lab.crt /certs/lab.key > /etc/haproxy/certs/lab.pem
chmod 600 /etc/haproxy/certs/lab.pem
exec haproxy -f /usr/local/etc/haproxy/haproxy.cfg -db
