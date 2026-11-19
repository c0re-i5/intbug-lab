#!/bin/sh
# Lab entrypoint for OpenLiteSpeed (open source). This is not LiteSpeed
# Enterprise (LSWS). Patch the stock SSL listener and the docker vhost
# template so :443 serves the shared index over TLS + HTTP/2, then start OLS.
#
# WebAdmin stays off (disableWebAdmin 1). Do not publish 7080.
# Inside the container the HTTPS listener is *:443 so Docker can reach it.
# The host publish is 127.0.0.1 only.
set -eu

LAB_CRT_SRC=/certs/lab.crt
LAB_KEY_SRC=/certs/lab.key
LAB_DIR=/usr/local/lsws/conf/lab
CONF=/usr/local/lsws/conf/httpd_config.conf
DOCKER_TMPL=/usr/local/lsws/conf/templates/docker.conf

if [ ! -f "$LAB_CRT_SRC" ] || [ ! -f "$LAB_KEY_SRC" ]; then
  echo "openlitespeed lab: missing /certs/lab.crt or /certs/lab.key" >&2
  exit 1
fi
if [ ! -f /var/www/vhosts/localhost/html/index.html ]; then
  echo "openlitespeed lab: missing /var/www/vhosts/localhost/html/index.html" >&2
  exit 1
fi

mkdir -p "$LAB_DIR"
cp "$LAB_CRT_SRC" "$LAB_DIR/lab.crt"
cp "$LAB_KEY_SRC" "$LAB_DIR/lab.key"
# Lab cert only. 644 so lshttpd can read the key after it drops privileges.
chmod 644 "$LAB_DIR/lab.crt" "$LAB_DIR/lab.key"
chown lsadm:lsadm "$LAB_DIR/lab.crt" "$LAB_DIR/lab.key" || true

# Do not start WebAdmin. The compose file also does not publish 7080.
sed -i 's/^disableWebAdmin[[:space:]]*.*/disableWebAdmin                  1/' "$CONF"
# This slice is HTTP/2 on TCP. Leave QUIC/HTTP3 off.
sed -i 's/^[[:space:]]*quicEnable[[:space:]]*.*/    quicEnable                   0/' "$CONF"

# Replace the stock HTTPS listener (admin cert, no HTTP/2) with the lab pair.
awk '
  /^listener HTTPS[[:space:]]*\{/ {
    print "listener HTTPS {"
    print "  address                 *:443"
    print "  secure                  1"
    print "  keyFile                 /usr/local/lsws/conf/lab/lab.key"
    print "  certFile                /usr/local/lsws/conf/lab/lab.crt"
    print "  certChain               0"
    print "  sslProtocol             24"
    print "  enableSpdy              8"
    print "  enableQuic              0"
    print "}"
    skip = 1
    next
  }
  skip && /^\}/ { skip = 0; next }
  skip { next }
  { print }
' "$CONF" > "${CONF}.lab"
mv "${CONF}.lab" "$CONF"

# The docker vhost template otherwise points vhssl at an acme.sh path that
# does not exist, and that override wins over the listener certificate.
awk '
  /^[[:space:]]*vhssl[[:space:]]*\{/ {
    print "  vhssl  {"
    print "    keyFile               /usr/local/lsws/conf/lab/lab.key"
    print "    certFile              /usr/local/lsws/conf/lab/lab.crt"
    print "    certChain             0"
    print "  }"
    skip = 1
    next
  }
  skip && /^[[:space:]]*\}/ { skip = 0; next }
  skip { next }
  { print }
' "$DOCKER_TMPL" > "${DOCKER_TMPL}.lab"
mv "${DOCKER_TMPL}.lab" "$DOCKER_TMPL"

# Stock image entrypoint chowns conf to lsadm and runs lswsctrl in the
# foreground-wait loop. Config patches above must be done first.
exec /entrypoint.sh
