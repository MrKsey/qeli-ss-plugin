//! SIP003 client side: listen for `ss-local`, mux every accepted connection
//! as one stream over a single shared, lazily-redialed qeli tunnel.

use crate::carrier::{self, Tunnel};
use crate::handshake;
use crate::opts::{PluginOpts, Role, Sip003};
use anyhow::{anyhow, Result};
use qeli_core::protocol::DEVICE_ID_LEN;
use rand::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

/// Everything needed to dial the plugin server.
#[derive(Clone, Debug)]
pub struct ClientTunnelConfig {
    pub remote: SocketAddr,
    pub password: String,
    pub sni: String,
    /// Pinned server static public key (hex-parsed), if configured.
    pub server_public_key: Option<[u8; 32]>,
    /// Keepalive interval, seconds (0 = off).
    pub ping_secs: u32,
    pub dial_timeout: Duration,
}

impl ClientTunnelConfig {
    pub fn from_opts(opts: &PluginOpts, sip: &Sip003) -> Self {
        Self {
            remote: sip.remote,
            password: opts.password.clone(),
            sni: opts.sni.clone(),
            server_public_key: opts.server_public_key,
            ping_secs: opts.ping_secs,
            dial_timeout: Duration::from_secs(opts.dial_timeout_secs),
        }
    }
}

/// Owns the one shared tunnel; dials a replacement whenever the current one
/// is dead (lazy reconnect — the next accepted connection pays the dial).
pub struct TunnelManager {
    config: ClientTunnelConfig,
    device_id: [u8; DEVICE_ID_LEN],
    current: Mutex<Option<Arc<Tunnel>>>,
}

impl TunnelManager {
    pub fn new(config: ClientTunnelConfig) -> Self {
        let mut device_id = [0u8; DEVICE_ID_LEN];
        rand::rng().fill_bytes(&mut device_id);
        Self {
            config,
            device_id,
            current: Mutex::new(None),
        }
    }

    /// The live tunnel, dialing a fresh one when the cached tunnel is dead.
    /// Concurrent callers serialize on the mutex: only one dial at a time.
    pub async fn tunnel(&self) -> Result<Arc<Tunnel>> {
        let mut current = self.current.lock().await;
        if let Some(tunnel) = current.as_ref() {
            if !tunnel.is_dead() {
                return Ok(tunnel.clone());
            }
        }
        let tunnel = self.dial().await?;
        *current = Some(tunnel.clone());
        Ok(tunnel)
    }

    /// The cached tunnel, if any (diagnostics / tests).
    pub async fn current(&self) -> Option<Arc<Tunnel>> {
        self.current.lock().await.clone()
    }

    async fn dial(&self) -> Result<Arc<Tunnel>> {
        let cfg = &self.config;
        let connect = async {
            let mut io = TcpStream::connect(cfg.remote).await?;
            // Interactive traffic rides small records; Nagle would add
            // RTT-scale latency on top of every request-response turn.
            io.set_nodelay(true)?;
            let auth = handshake::client_handshake(
                &mut io,
                &cfg.sni,
                &cfg.password,
                &self.device_id,
                cfg.server_public_key,
                cfg.dial_timeout,
            )
            .await?;
            Ok::<_, anyhow::Error>((io, auth))
        };
        let (io, auth) = tokio::time::timeout(cfg.dial_timeout, connect)
            .await
            .map_err(|_| anyhow!("tunnel dial to {} timed out", cfg.remote))??;

        // The server never opens streams; a received OPEN is a violation.
        let on_open = |tunnel: Arc<Tunnel>, id: u32, _inbound: mpsc::Receiver<Vec<u8>>| async move {
            log::warn!("client received unexpected OPEN for stream {id} — ignoring");
            tunnel.handle().close(id).await;
        };

        log::info!(
            "tunnel up: {} (server key {})",
            cfg.remote,
            crate::opts::to_hex(&auth.server_static)
        );
        let peer = cfg.remote.to_string();
        Ok(carrier::spawn_tunnel(
            io,
            auth.rx,
            auth.tx,
            cfg.ping_secs,
            &peer,
            on_open,
        )
        .await)
    }

    /// Serve one accepted `ss-local` connection as one mux stream.
    ///
    /// Retries once on a dead tunnel (the cached tunnel can die between the
    /// liveness check and the OPEN enqueue; the retry dials fresh).
    pub async fn accept_connection(&self, local: TcpStream) -> Result<()> {
        let mut last_error: Option<anyhow::Error> = None;
        for _attempt in 0..2 {
            let tunnel = match self.tunnel().await {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let id = tunnel.handle().alloc_id();
            let (inbound_tx, inbound_rx) =
                tokio::sync::mpsc::channel::<Vec<u8>>(carrier::INBOUND_CAPACITY);
            // Register BEFORE the OPEN leaves: the peer cannot answer before it
            // sees the OPEN, so the entry is always in place for the first DATA.
            tunnel.registry().register(id, inbound_tx).await;
            match tunnel.handle().open(id).await {
                Ok(()) => {
                    if tunnel.is_dead() {
                        // The tunnel died while the OPEN was in flight.
                        last_error = Some(anyhow!("tunnel died while opening stream {id}"));
                        continue;
                    }
                    log::debug!("stream {id} opened");
                    tokio::spawn(carrier::pump_stream(local, tunnel, id, inbound_rx));
                    return Ok(());
                }
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        Err(anyhow!(
            "no usable tunnel: {}",
            last_error
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "unknown".to_string())
        ))
    }
}

/// Run the SIP003 client plugin until the process is killed.
pub async fn run(opts: PluginOpts, sip: Sip003) -> Result<()> {
    debug_assert_eq!(opts.role, Role::Client, "client::run requires the client role");
    let listener = TcpListener::bind(sip.local).await?;
    log::info!(
        "qeli-ss-plugin (client) listening on {} → {} [sni={}]",
        sip.local,
        sip.remote,
        opts.sni
    );
    let manager = Arc::new(TunnelManager::new(ClientTunnelConfig::from_opts(&opts, &sip)));
    loop {
        match listener.accept().await {
            Ok((local, peer)) => {
                let _ = local.set_nodelay(true);
                let manager = manager.clone();
                tokio::spawn(async move {
                    if let Err(error) = manager.accept_connection(local).await {
                        log::warn!("connection from {peer} failed: {error:#}");
                    }
                });
            }
            Err(error) => log::warn!("accept failed: {error}"),
        }
    }
}
