#!/bin/sh
# shadowsocks-libev + qeli-ss-plugin: CLIENT side example.
#
# ss-local is pointed at the server's PLUGIN port (8443) with the plugin
# attached; the plugin muxes every ss-local connection over one long-lived
# qeli fake-tls tunnel.
#
# plugin_opts — ALL plugin options (client side):
#   password=<secret>  the plugin's own auth secret — REQUIRED; ONE password
#                      serves any number of clients from any hosts (must match
#                      the server; NOT the shadowsocks password)
#   serverkey=<hex64>  the server's static PUBLIC key from
#                      `qeli-ss-plugin --genkey` (pinning protects against
#                      MITM; omit for trust-on-first-use)
#   sni=<host>         the hostname the fake-TLS ClientHello carries — what a
#                      passive observer (DPI) sees as the destination of an
#                      ordinary HTTPS connection; default www.cloudflare.com;
#                      empty ("sni=") omits the SNI extension entirely
#   ping=<secs>        keepalive interval (0 = off); dead-peer detection is
#                      bounded by ping + 2s
#   timeout=<secs>     connect/handshake timeout
#
# Addresses: SERVER accepts IPv4 and IPv6 (libev passes the host to the
# plugin via SS_REMOTE_HOST; the plugin handles both forms).

set -eu

SERVER="203.0.113.10"          # IPv6 example: SERVER="2001:db8::10"
SERVERKEY="0000000000000000000000000000000000000000000000000000000000000000"
PLUGIN_PASSWORD="change-me"
SS_PASSWORD="ss-change-me"
SNI="www.cloudflare.com"
PING=2
TIMEOUT=10

exec ss-local \
  -s "$SERVER" -p 8443 \
  -b 127.0.0.1 -l 1080 \
  -k "$SS_PASSWORD" -m chacha20-ietf-poly1305 \
  --plugin qeli-ss-plugin \
  --plugin-opts "password=$PLUGIN_PASSWORD;serverkey=$SERVERKEY;sni=$SNI;ping=$PING;timeout=$TIMEOUT"
