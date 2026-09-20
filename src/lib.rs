//! qeli-ss-plugin — SIP003 plugin for shadowsocks.
//!
//! Tunnels `ss-local` ↔ `ss-server` TCP traffic through ONE long-lived qeli
//! connection (fake-tls wire profile) with per-connection stream multiplexing:
//!
//! ```text
//! apps → ss-local → [plugin client] == qeli fake-tls tunnel == [plugin server] → ss-server → internet
//!                      mux (stream-id frames)                    demux
//! ```
//!
//! Layers reused from the qeli core (`qeli` crate, `qeli_core` lib):
//! * fake-TLS ClientHello/ServerHello choreography incl. the X25519+ML-KEM-768
//!   hybrid post-quantum key exchange (`qeli_core::protocol::FakeTlsHandshake`);
//! * AEAD records (ChaCha20-Poly1305, TLS-dressed framing, anti-replay)
//!   via `qeli_core::protocol::PacketCodec`;
//! * the transcript-bound server identity proof + user/password auth
//!   (`qeli_core::crypto`).
//!
//! The plugin adds:
//! * [`mux`] — stream multiplexer framing (OPEN/DATA/CLOSE/PING/PONG);
//! * [`handshake`] — the plugin's own fake-tls + auth handshake (a slimmed-down
//!   mirror of qeli's, without the VPN NetworkPlan machinery);
//! * [`carrier`] — the long-lived tunnel: writer/reader loops, stream registry,
//!   keepalive;
//! * [`client`]/[`server`] — the SIP003 sides;
//! * [`opts`] — SIP003 environment + `plugin_opts` parsing.

/// The plugin version, shown by `--version` and in the auth response.
///
/// Default: `0.1`. Release builds override it by setting the
/// `QELI_SS_PLUGIN_VERSION` environment variable at build time (e.g. to the
/// GitHub release tag):
///
/// ```sh
/// QELI_SS_PLUGIN_VERSION=v1.2.3 cargo build --release
/// ```
pub const VERSION: &str = match option_env!("QELI_SS_PLUGIN_VERSION") {
    Some(version) => version,
    None => "0.1",
};

pub mod carrier;
pub mod client;
pub mod handshake;
pub mod mux;
pub mod opts;
pub mod server;
