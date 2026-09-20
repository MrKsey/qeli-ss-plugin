# qeli-ss-plugin

A [SIP003](https://shadowsocks.org/en/wiki/Plugin.html) plugin for
[shadowsocks](https://shadowsocks.org) that carries **all** `ss-local` ↔
`ss-server` TCP traffic over **one long-lived connection** — a
[qeli](https://github.com/litvinovtd/qeli) fake-TLS tunnel with per-connection
stream multiplexing:

```text
apps → ss-local → [plugin client] ══ qeli fake-tls tunnel ══ [plugin server] → ss-server → internet
                      mux (stream-id frames)                  demux
```

To a passive observer (DPI) the tunnel looks like ordinary TLS 1.3 traffic to
a CDN host; underneath it is a hybrid post-quantum handshake and
authenticated-encryption records.

**Русская версия: [README.ru.md](README.ru.md).**

## Encryption model

The plugin itself encrypts everything on the wire. Only the two loopback
legs (by SIP003 definition local) are ever plaintext:

```text
app ──(plaintext, loopback)── ss-local ──(plaintext, loopback)── plugin client
                                                                    ║
              ══ encrypted from here on: qeli fake-tls tunnel ══   ║
              ║  • fake-TLS handshake: X25519 + ML-KEM-768          ║
              ║  • AEAD records: ChaCha20-Poly1305 + anti-replay    ║
              ║  • mux frames ride INSIDE the AEAD records          ║
                                                                    ║
                                                          plugin server ──(plaintext, loopback)── ss-server ──> internet
```

* **Handshake** (`src/handshake.rs`): a real-looking TLS 1.3 record flight
  (ClientHello → ServerHello → … → Finished) performs a hybrid
  **X25519 + ML-KEM-768** key exchange; the password auth then
  happens *inside* the already-encrypted channel.
* **Data** (`src/carrier.rs`): every mux frame is sealed into an AEAD record
  (ChaCha20-Poly1305, TLS-dressed, sliding-window anti-replay) before it
  touches the socket.
* Shadowsocks' own AEAD keeps running on top, so the transit leg is
  double-encrypted — the price of indistinguishability from TLS.

### Where SNI is set

In `plugin_opts`, the `sni=` option (client side — the SNI lives in the
ClientHello the client sends):

```sh
--plugin-opts "password=...;serverkey=...;sni=cdn.example.com"
```

* Default: `www.cloudflare.com`.
* `sni=` (empty) omits the SNI extension entirely (also valid TLS).
* Must be an ASCII hostname ≤ 253 bytes; anything else is a config error.

### The fake-tls "mode"

There is no mode switch — fake-TLS **is** the wire profile of this plugin,
hard-wired into the handshake (the qeli `FakeTlsHandshake`). On the wire it
is always the genuine TLS 1.3 record choreography, and after "Finished" the
AEAD records look like ordinary TLS `application_data`. An alternative
profile (e.g. `obfs=http`-style) does not exist, hence no option for it.

---

## What it is built on

The plugin reuses the [qeli](https://github.com/litvinovtd/qeli) core as a
library (`qeli` crate / `qeli_core`):

* **Fake-TLS wire profile** — the exact ClientHello/ServerHello/…/Finished
  record choreography of TLS 1.3, with a configurable SNI
  (`www.cloudflare.com` by default), so the flow is indistinguishable from
  ordinary HTTPS to a CDN.
* **Hybrid post-quantum key exchange** — X25519 + ML-KEM-768 (FIPS 203)
  combined, so the tunnel is confidential even against a future quantum
  adversary that breaks ECDH ("harvest now, decrypt later").
* **AEAD records** — ChaCha20-Poly1305 in TLS-dressed records with a
  sliding-window anti-replay filter (window ≈ 2048 packets, WireGuard-sized).
* **Transcript-bound server identity** — the server proves its long-lived
  static key bound to the handshake transcript; clients can pin it
  (anti-MITM) or trust-on-first-use.

## What the plugin adds

* **SIP003 plumbing** — the `SS_LOCAL_*`/`SS_REMOTE_*` environment, the
  `plugin_opts` string, client and server roles.
* **Stream multiplexer** (`src/mux.rs`) — `OPEN/DATA/CLOSE/PING/PONG` frames
  (`type(1) ‖ stream(4) ‖ len(2) ‖ payload`, ≤ 16 KiB per DATA) carried one
  per AEAD record. One shadowsocks connection = one stream id.
* **The long-lived carrier** (`src/carrier.rs`) — writer/reader loops, the
  demux registry, keepalive, and a per-stream pump bridging each local
  socket onto its stream.
* **Half-close propagation** — a FIN from `ss-local` travels as a `CLOSE`
  frame, FINs the upstream, and the reply path keeps draining (real
  half-duplex shutdown, not a full connection kill).
* **Auth** — a single shared password (constant-time compare) inside the
  encrypted channel, plus optional server-key pinning. One password serves
  any number of clients from any hosts.

### Resilience (each behavior is covered by tests)

* **A couple of corrupted or replayed records do not kill the tunnel.** A
  bad record (failed AEAD tag / replay window / malformed frame) is dropped;
  the tunnel dies only after 8 *consecutive* bad records.
* **Dead peers are detected within seconds, not minutes.** Keepalive PINGs
  every `ping` seconds (default 2) with a fixed 2 s PONG grace → worst-case
  detection ≈ 4 s. A silently hung server is killed, the client lazily
  redials, and traffic continues on the fresh tunnel.
* **Handshakes are time-bounded on both sides** — a peer that connects and
  stalls cannot hang the dialer or the server (`timeout=`, default 10 s).
* **One stalled consumer cannot freeze the tunnel.** A stream whose local
  reader stays stuck for 5 s is dropped (with a `CLOSE` to the peer) instead
  of head-of-line-blocking the shared reader.
* **Writes are time-bounded** — a stalled wire write kills the tunnel
  (10 s); a stalled per-stream local write abandons that stream (30 s).

### Performance notes

* Records are read in large chunks and parsed from a cursor-based buffer —
  no per-record allocations on the read path, no quadratic buffer drains.
* `TCP_NODELAY` on every socket (tunnel + local) — small interactive frames
  are not delayed by Nagle.
* One frame per AEAD record keeps the wire format identical to qeli's (DPI
  sees only TLS-shaped records of ordinary sizes); throughput traffic rides
  16 KiB DATA frames.

## Usage

### 1. Generate the server identity (once)

```sh
qeli-ss-plugin --genkey
# private key (key=...):        9f2c...   ← server side, keep secret
# public  key (serverkey=...):  a41b...   ← client side, pin it
```

### 2. Server side (with `ss-server`)

`ss-server` listens on loopback; the plugin listens on the public interface
and forwards demuxed streams to it:

```sh
ss-server -s 127.0.0.1 -p 1310 -k mypassword -m chacha20-ietf-poly1305 &
SS_LOCAL_HOST=127.0.0. SS_LOCAL_PORT=1310 \
SS_REMOTE_HOST=0.0.0.0 SS_REMOTE_PORT=8443 \
qeli-ss-plugin "s=1;key=<private-key-hex>;password=<plugin-password>"
```

### 3. Client side (with `ss-local`)

```sh
SS_LOCAL_HOST=127.0.0.1 SS_LOCAL_PORT=1080 \
SS_REMOTE_HOST=<server> SS_REMOTE_PORT=8443 \
qeli-ss-plugin "password=<plugin-password>;serverkey=<public-key-hex>"
```

```sh
ss-local -s <server> -p 8443 -b 127.0.0.1 -l 1080 \
  -k mypassword -m chacha20-ietf-poly1305 \
  --plugin qeli-ss-plugin \
  --plugin-opts "password=<plugin-password>;serverkey=<public-key-hex>"
```

### `plugin_opts` reference

| option | side | meaning | default |
|---|---|---|---|
| `s=1` / `server=1` | both | server role (`0` = client) | client |
| `password=<secret>` | both | **required** auth secret; one password serves any number of clients from any hosts | — |
| `sni=<host>` | client | fake-TLS SNI (empty = omit) | `www.cloudflare.com` |
| `serverkey=<hex64>` | client | pin the server's static public key | TOFU |
| `key=<hex64>` | server | static identity private key (`--genkey`) | ephemeral (logged) |
| `ping=<secs>` | both | keepalive interval; detection ≤ `ping`+2 s | `2` (`0` = off) |
| `timeout=<secs>` | both | connect/handshake timeout | `10` |

SIP003 escaping applies: `\;`, `\=`, `\\` inside values.

Ready-made configs: [`examples/`](examples/) (shadowsocks-libev CLI and
shadowsocks-rust JSON, client + server).

## Standalone mode (no shadowsocks)

The plugin can also run **directly**, from its own **JSON** config file — no
`ss-local`/`ss-server`, no `SS_*` environment. The standalone client is a
plain TCP forwarder (every accepted connection = one stream over the shared
tunnel); the standalone server forwards demuxed streams to **any** TCP
service (an HTTP server, sshd, a database — or ss-server, if you still want
it in the middle):

```sh
qeli-ss-plugin --config standalone-server.json   # on the server host
qeli-ss-plugin --config standalone-client.json   # on the client host
```

The config is JSON; `"_comment"` (string or array of strings) is allowed and
ignored (JSON has no comments), unknown keys are a config **error** (a typo
must not be silently ignored). Standalone-only keys:

| key | meaning |
|---|---|
| `role` | `"client"` or `"server"` (default client) |
| `listen` | **required** — this process's listener, `"host:port"` |
| `remote` | **required** — client: the plugin server; server: the forward target (`"forward"` alias) |

Every other key is the same `plugin_opts` option with the same validation:

| key | type | meaning | default |
|---|---|---|---|
| `password` | string | **required** auth secret; one password, any number of clients | — |
| `sni` | string | fake-TLS SNI (empty string omits it) | `www.cloudflare.com` |
| `serverkey` | string | client: pin the server's static public key (64 hex) | TOFU |
| `key` | string | server: static identity private key (64 hex) | ephemeral (logged) |
| `ping` | number | keepalive interval, seconds (0 = off) | `2` |
| `timeout` | number | connect/handshake timeout, seconds | `10` |

Full annotated examples covering every option (including SNI):
[`examples/standalone-client.json`](examples/standalone-client.json),
[`examples/standalone-server.json`](examples/standalone-server.json).

## IPv4 and IPv6

Every address in every config accepts both families:

* **standalone JSON** — IPv4 `"203.0.113.10:8443"` or **bracketed** IPv6
  `"[2001:db8::10]:8443"` (`listen` may be `"[::]:8443"` for all interfaces;
  a *bare* unbracketed IPv6 literal is rejected with a hint — it is ambiguous
  with the port separator);
* **SIP003 environment** — `SS_LOCAL_HOST`/`SS_REMOTE_HOST` accept IPv4,
  bracketed IPv6 (`[2001:db8::10]`) and bare IPv6 (`2001:db8::10`) hosts;
* hostnames resolve via the system resolver (A + AAAA).

The tunnel itself is family-agnostic end to end (tested over IPv6 loopback).

## Version

`qeli-ss-plugin --version` prints the plugin version. Default: `0.1`.
Release builds override it to the release tag by setting
`QELI_SS_PLUGIN_VERSION` at build time:

```sh
QELI_SS_PLUGIN_VERSION=v1.2.3 cargo build --release
```

## Building

```sh
cargo build --release          # native
cargo test                     # 67 tests: unit + end-to-end over real TCP

# Linux binaries from any host (via cargo-zigbuild): STATIC musl builds —
# no libc interpreter, run on any distro/embedded system (OpenWrt, Entware,
# routers, Alpine) regardless of the host libc:
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

The `qeli` core is pulled as a pinned git dependency; see `Cargo.toml` for a
`[patch]` snippet to develop against a local checkout.

## Testing notes

The integration suite runs the full stack (mux + handshake + carrier +
client/server) over real TCP sockets with an echo stand-in for `ss-server`,
including hostile-middlebox scenarios (record corruption, replayed records,
killed dials, a hung server, stalled consumers).

> Note: on machines with an intercepting web filter (e.g. Kaspersky's local
> proxy) loopback test dials can be transparently answered with an HTTP error.
> The tests retry such interceptions; for fully clean runs add the test
> binaries to your AV exclusions.

## Layout

```text
src/mux.rs        stream multiplexer framing (OPEN/DATA/CLOSE/PING/PONG)
src/handshake.rs  fake-tls + auth handshake (client & server, time-bounded)
src/carrier.rs    the long-lived tunnel: writer/reader, registry, keepalive,
                  per-stream pump, half-close (WriteFin)
src/client.rs     SIP003 client: listen for ss-local, mux, lazy redial
src/server.rs     SIP003 server: accept tunnels, demux to ss-server
src/opts.rs       SIP003 env + plugin_opts parsing
src/main.rs       CLI (--genkey, --server, --client)
tests/            unit-level and end-to-end integration tests
```

## License

AGPL-3.0-only (same as the qeli core) — see [LICENSE](LICENSE).

> Binaries for every release: see the [Releases](https://github.com/MrKsey/qeli-ss-plugin/releases) page.
