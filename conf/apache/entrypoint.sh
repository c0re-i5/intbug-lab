#!/bin/sh
set -eu
CONF=/usr/local/apache2/conf/httpd.conf
SSL=/usr/local/apache2/conf/extra/httpd-ssl.conf

sed -i \
  -e 's/^#LoadModule socache_shmcb_module/LoadModule socache_shmcb_module/' \
  -e 's/^#LoadModule ssl_module/LoadModule ssl_module/' \
  -e 's/^#LoadModule http2_module/LoadModule http2_module/' \
  -e 's|^#Include conf/extra/httpd-ssl.conf|Include conf/extra/httpd-ssl.conf|' \
  "$CONF"

if ! grep -q '^Protocols ' "$CONF"; then
  printf '\nProtocols h2 http/1.1\n' >> "$CONF"
fi
if ! grep -q '^ServerName ' "$CONF"; then
  printf '\nServerName localhost\n' >> "$CONF"
fi

# Allow the lab document root (bind-mounted).
if ! grep -q 'htdocs-lab' "$CONF"; then
  cat >> "$CONF" <<'APACHE'
<Directory "/usr/local/apache2/htdocs-lab">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
APACHE
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout /usr/local/apache2/conf/server.key \
  -out /usr/local/apache2/conf/server.crt \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1

sed -i \
  -e 's|DocumentRoot "/usr/local/apache2/htdocs"|DocumentRoot "/usr/local/apache2/htdocs-lab"|' \
  -e 's|<Directory "/usr/local/apache2/htdocs">|<Directory "/usr/local/apache2/htdocs-lab">|' \
  -e 's|ServerName www.example.com:443|ServerName localhost:443|' \
  "$SSL"

exec httpd-foreground
