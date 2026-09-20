# qeli-ss-plugin

A [SIP003](https://shadowsocks.org/en/wiki/Plugin.html) plugin for
[shadowsocks](https://shadowsocks.org) that carries all `ss-local` ↔
`ss-server` TCP traffic over **one long-lived connection** — a
[qeli](https://github.com/litvinovtd/qeli) fake-TLS tunnel with stream
multiplexing:

```text
apps → ss-local → [plugin client] ══ qeli fake-TLS tunnel ══ [plugin server] → ss-server → internet
                       one stream per connection                    demux
```

To a passive observer (DPI) the tunnel looks like ordinary TLS 1.3 traffic
to a CDN host. Underneath: a hybrid post-quantum key exchange and
authenticated encryption.

**Русская версия: [README.ru.md](README.ru.md).**

## Highlights

* **Looks like ordinary HTTPS** — the wire is genuine TLS 1.3 record
  choreography with a configurable SNI; after the handshake everything is
  indistinguishable from TLS `application_data`.
* **Post-quantum handshake** — X25519 + ML-KEM-768 (FIPS 203) combined, so
  the tunnel is confidential even against a future quantum adversary that
  breaks ECDH ("harvest now, decrypt later").
* **One connection, many streams** — every shadowsocks connection rides its
  own stream over a single shared tunnel; no per-connection handshakes.
* **Survives bad networks** — corrupted and replayed records are dropped
  without killing the tunnel; dead peers are detected within seconds
  (`ping` + 2 s, default ≈ 4 s) and the client redials automatically.
* **Single shared password** — one password serves any number of clients
  from any hosts; optional server-key pinning protects against MITM.
* **Runs anywhere** — static musl Linux binaries (amd64, arm64) work on any
  distro or embedded system (OpenWrt, Entware on Keenetic, routers, Alpine);
  a Windows amd64 build is included.

## How it works

The plugin encrypts everything on the wire itself. Only the two loopback
legs are ever plaintext (by SIP003 definition they are local):

```text
app ─(plaintext, loopback)─ ss-local ─(plaintext, loopback)─ plugin client
                                                                ║
          everything past this point is the qeli fake-TLS tunnel ║
          ║  handshake: X25519 + ML-KEM-768                       ║
          ║  records:   ChaCha20-Poly1305 AEAD + anti-replay      ║
          ║  payload:   multiplexer frames inside the records     ║
                                                                ║
                                                     plugin server ─(plaintext, loopback)─ ss-server → internet
```

* **Handshake** (`src/handshake.rs`) — a real-looking TLS 1.3 flight
  (ClientHello → ServerHello → … → Finished) performs the hybrid key
  exchange; the password is then verified *inside* the already-encrypted
  channel (constant-time compare), so it is never visible on the wire.
* **Data** (`src/carrier.rs`) — every mux frame is sealed into an AEAD
  record (ChaCha20-Poly1305, TLS-dressed, sliding-window anti-replay,
  window ≈ 2048 packets) before it touches the socket. Shadowsocks' own
  AEAD keeps running on top, so the transit leg is double-encrypted.
* **Multiplexing** (`src/mux.rs`) — `OPEN/DATA/CLOSE/PING/PONG` frames
  (`type(1) ‖ stream(4) ‖ len(2) ‖ payload`, up to 16 KiB per DATA), one
  frame per AEAD record. A FIN from `ss-local` travels as a `CLOSE` frame
  and becomes a FIN upstream — real half-close, not a connection kill.

### SNI

Set with the `sni=` option (client side — the SNI lives in the ClientHello
the client sends):

```sh
--plugin-opts "password=...;serverkey=...;sni=cdn.example.com"
```

Default: `www.cloudflare.com`. An empty value omits the SNI extension
entirely (also valid TLS). Must be an ASCII hostname of at most 253 bytes.

### Resilience (every item is covered by tests)

| What goes wrong | What happens |
|---|---|
| A few corrupted or replayed records | Dropped; the tunnel dies only after 8 *consecutive* bad records |
| Peer silently hangs (no FIN) | Keepalive detects it within `ping` + 2 s (default ≈ 4 s); the client redials |
| Peer connects and stalls mid-handshake | Both sides time out (`timeout=`, default 10 s) |
| One stream's consumer stops reading | That stream is dropped after 5 s — the rest of the tunnel keeps flowing |
| A write stalls | Wire write kills the tunnel after 10 s; a local write abandons only its stream after 30 s |

## Install

Download a binary from the
[Releases](https://github.com/MrKsey/qeli-ss-plugin/releases) page:

| file | platform |
|---|---|
| `qeli-ss-plugin-linux-amd64` | Linux x86-64 (static musl) |
| `qeli-ss-plugin-linux-arm64` | Linux arm64 (static musl) |
| `qeli-ss-plugin-windows-amd64.exe` | Windows x86-64 |

Or build from source:

```sh
cargo build --release
cargo test                      # 67 tests: unit + end-to-end over real TCP

# static Linux binaries from any host (via cargo-zigbuild):
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

The `qeli` core is pulled as a pinned git dependency; `Cargo.toml` has a
`[patch]` snippet for developing against a local checkout.

## Usage

### 1. Generate the server identity (once)

```sh
qeli-ss-plugin -genkey
# private key (key=...):        9f2c...   ← server side, keep secret
# public  key (serverkey=...):  a41b...   ← client side, pin it
```

### 2. Server side

`ss-server` listens on loopback; the plugin listens on the public interface
and forwards demuxed streams to it:

```sh
ss-server -s 127.0.0.1 -p 1310 -k mypassword -m chacha20-ietf-poly1305 &

SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=1310 \
SS_REMOTE_HOST=0.0.0.0 SS_REMOTE_PORT=8443 \
qeli-ss-plugin -s "key=<private-key-hex>;password=<plugin-password>"
```

### 3. Client side

```sh
ss-local -s <server> -p 8443 -b 127.0.0.1 -l 1080 \
  -k mypassword -m chacha20-ietf-poly1305 \
  --plugin qeli-ss-plugin \
  --plugin-opts "password=<plugin-password>;serverkey=<public-key-hex>"
```

`ss-local` passes the addresses to the plugin via the `SS_*` environment;
the plugin options come from `plugin_opts`. Ready-made configs for
shadowsocks-libev (CLI) and shadowsocks-rust (JSON) are in
[`examples/`](examples/).

### `plugin_opts` reference

| option | side | meaning | default |
|---|---|---|---|
| `s=1` / `server=1` | both | server role (`0` = client) | client |
| `password=<secret>` | both | **required**; one password serves any number of clients | — |
| `sni=<host>` | client | fake-TLS SNI (empty = omit) | `www.cloudflare.com` |
| `serverkey=<hex64>` | client | pin the server's static public key (anti-MITM) | TOFU |
| `key=<hex64>` | server | static identity private key (`-genkey`) | ephemeral (logged) |
| `ping=<secs>` | both | keepalive interval; dead-peer detection ≤ `ping`+2 s | `2` (`0` = off) |
| `timeout=<secs>` | both | connect/handshake timeout | `10` |

SIP003 escaping applies: `\;`, `\=`, `\\` inside values.

## Standalone mode (no shadowsocks)

The plugin can also run directly from its own **JSON** config — no
`ss-local`/`ss-server`, no `SS_*` environment. The standalone client is a
plain TCP forwarder (every accepted connection = one stream over the shared
tunnel); the standalone server forwards demuxed streams to **any** TCP
service (an HTTP server, sshd, a database — or ss-server, if you still want
it in the middle):

```sh
qeli-ss-plugin -c standalone-server.json   # on the server host
qeli-ss-plugin -c standalone-client.json   # on the client host
```

Config keys: `role` (`"client"`/`"server"`), `listen` and `remote`
(required; `forward` is an alias for `remote`), plus every `plugin_opts`
option from the table above (`password`, `sni`, `serverkey`, `key`, `ping`,
`timeout`). `"_comment"` is allowed and ignored; unknown keys are a config
**error** — a typo must not be silently ignored.

Full annotated examples:
[`examples/standalone-client.json`](examples/standalone-client.json),
[`examples/standalone-server.json`](examples/standalone-server.json).

## IPv4 and IPv6

Every address in every config accepts both families:

* **standalone JSON** — IPv4 `"203.0.113.10:8443"` or bracketed IPv6
  `"[2001:db8::10]:8443"`; `listen` may be `"[::]:8443"` (all interfaces).
  A *bare* unbracketed IPv6 literal is rejected with a hint (ambiguous with
  the port separator).
* **SIP003 environment** — `SS_LOCAL_HOST`/`SS_REMOTE_HOST` accept IPv4,
  bracketed and bare IPv6 hosts.
* Hostnames resolve via the system resolver (A + AAAA).

## Version

```sh
qeli-ss-plugin -v        # prints the version, e.g. v1.0.2
```

Release builds take the version from the release tag
(`QELI_SS_PLUGIN_VERSION` at build time); local builds default to `0.1`.

## Command-line flags

```
-c <file>   path to a JSON config file (standalone mode)
-client      run as client (default)
-s           run as server
-genkey      generate a server identity key pair and exit
-v           print version and exit
-h           print help and exit
```

## Tests

```sh
cargo test
```

The integration suite runs the full stack (mux + handshake + carrier +
client/server) over real TCP sockets with an echo stand-in for `ss-server`,
including hostile-middlebox scenarios: record corruption, replayed records,
killed dials, a hung server, stalled consumers, IPv6 loopback.

> Note: on machines with an intercepting web filter (e.g. a local AV proxy),
> loopback test dials can be transparently answered with an HTTP error. The
> tests retry such interceptions; for fully clean runs add the test binaries
> to your AV exclusions.

## Layout

```text
src/mux.rs        stream multiplexer framing (OPEN/DATA/CLOSE/PING/PONG)
src/handshake.rs  fake-TLS + password handshake (client & server, time-bounded)
src/carrier.rs    the long-lived tunnel: reader/writer, demux registry,
                  keepalive, per-stream pump, half-close
src/client.rs     client side: listen for ss-local, mux, automatic redial
src/server.rs     server side: accept tunnels, demux to the destination
src/opts.rs       SIP003 environment, plugin_opts and JSON config parsing
src/main.rs       CLI
tests/            unit and end-to-end integration tests
```

## License

AGPL-3.0-only (same as the qeli core) — see [LICENSE](LICENSE).
