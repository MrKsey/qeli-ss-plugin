#!/bin/sh
# shadowsocks-libev + qeli-ss-plugin: SERVER side example.
#
# ss-server listens on loopback; the plugin listens on the public interface
# (SS_REMOTE_*) and forwards demuxed streams to ss-server (SS_LOCAL_*).
#
# 1. Generate the server identity once:
#        qeli-ss-plugin --genkey
#    and put the private key into KEY below (keep it secret).
# 2. Adjust PLUGIN_PASSWORD (the plugin's own auth secret — NOT the
#    shadowsocks password) and the ports.
#
# plugin_opts — ALL plugin options (server side):
#   s=1                server role
#   key=<hex64>        the server identity PRIVATE key from
#                      `qeli-ss-plugin --genkey` (keep it secret; clients pin
#                      the matching public key via serverkey=)
#   password=<secret>  the plugin's own auth secret — REQUIRED; ONE password
#                      serves any number of clients from any hosts (must match
#                      the clients; NOT the shadowsocks password)
#   ping=<secs>        keepalive interval (0 = off); dead-peer detection is
#                      bounded by ping + 2s
#   timeout=<secs>     connect/handshake timeout
#
# Note: sni/serverkey are CLIENT-side options (the SNI lives in the
# ClientHello the client sends); the server side does not need them.
#
# Addresses: SS_REMOTE_HOST accepts IPv4 ("0.0.0.0" = all IPv4 interfaces)
# and IPv6 ("::" = all interfaces, dual-stack on Linux; the plugin brackets
# bare IPv6 hosts automatically).

set -eu

KEY="0000000000000000000000000000000000000000000000000000000000000000"  # --genkey output
PLUGIN_PASSWORD="change-me"
SS_PASSWORD="ss-change-me"
PING=2
TIMEOUT=10

# ss-server itself: loopback only
ss-server -s 127.0.0.1 -p 1310 -k "$SS_PASSWORD" -m chacha20-ietf-poly1305 &

# The SIP003 plugin server: public listener.
# IPv4:  SS_REMOTE_HOST=0.0.0.0   IPv6/dual-stack: SS_REMOTE_HOST=::
SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=1310 \
SS_REMOTE_HOST=0.0.0.0 SS_REMOTE_PORT=8443 \
exec qeli-ss-plugin "s=1;key=$KEY;password=$PLUGIN_PASSWORD;ping=$PING;timeout=$TIMEOUT"
