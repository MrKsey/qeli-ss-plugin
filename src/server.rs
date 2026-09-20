//! SIP003 server side: accept qeli tunnel connections, authenticate, and demux
//! every OPEN frame to a TCP connection to `ss-server` (SS_LOCAL_HOST:PORT).

use crate::carrier::{self, Tunnel};
use crate::handshake;
use crate::opts::{PluginOpts, Role, Sip003};
use anyhow::Result;
use qeli_core::crypto::StaticKeypair;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

/// Server-side configuration (one per plugin process).
pub struct ServerConfig {
    /// Long-lived identity key — the key clients pin (`serverkey=`).
    pub static_kp: StaticKeypair,
    pub password: String,
    /// Where ss-server listens (SS_LOCAL_HOST:SS_LOCAL_PORT).
    pub destination: SocketAddr,
    /// Keepalive interval, seconds (0 = off).
    pub ping_secs: u32,
    /// Upstream (ss-server) connect timeout.
    pub dial_timeout: Duration,
}

/// Serve tunnel connections on `listener` until `shutdown` fires.
///
/// On shutdown every live tunnel is killed (its socket closes → the client
/// side redials on next use) and every connection task is aborted.
pub async fn serve(listener: TcpListener, cfg: ServerConfig, mut shutdown: watch::Receiver<bool>) {
    let cfg = Arc::new(cfg);
    // Live tunnels of accepted connections; killed wholesale on shutdown so
    // their sockets actually close (a dropped listener alone does not).
    let tunnels: Arc<std::sync::Mutex<Vec<Arc<Tunnel>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((io, peer)) => {
                    log::info!("tunnel connection from {peer}");
                    let tunnels = tunnels.clone();
                    conns.spawn(handle_conn(io, cfg.clone(), tunnels));
                }
                Err(error) => log::warn!("accept failed: {error}"),
            },
            Some(_finished) = conns.join_next() => {}
        }
    }
    // Kill every live tunnel: writer/reader drop both socket halves → the
    // peer sees EOF immediately instead of hanging on a half-open socket.
    // (Collect first: a MutexGuard must not live across the kill().await.)
    let live: Vec<_> = tunnels.lock().unwrap().drain(..).collect();
    for tunnel in live {
        tunnel.kill().await;
    }
    conns.abort_all();
    log::info!("server stopped");
}

async fn handle_conn(
    mut io: TcpStream,
    cfg: Arc<ServerConfig>,
    tunnels: Arc<std::sync::Mutex<Vec<Arc<Tunnel>>>>,
) {
    // Interactive traffic rides small records; Nagle would add RTT-scale
    // latency on every request-response turn.
    let _ = io.set_nodelay(true);
    let auth = match handshake::server_handshake(
        &mut io,
        &cfg.static_kp,
        &cfg.password,
        cfg.dial_timeout,
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => {
            log::warn!("tunnel auth failed: {error:#}");
            return;
        }
    };
    log::info!("tunnel authenticated");

    let destination = cfg.destination;
    let dial_timeout = cfg.dial_timeout;
    // The inbound receiver is registered by the tunnel reader before this
    // closure runs (see carrier::reader_loop) — DATA already in flight is
    // buffered in the channel, so dialing first loses nothing.
    let on_open =
        move |tunnel: Arc<Tunnel>, id: u32, inbound_rx: mpsc::Receiver<Vec<u8>>| async move {
            match tokio::time::timeout(dial_timeout, TcpStream::connect(destination)).await {
                Ok(Ok(upstream)) => {
                    let _ = upstream.set_nodelay(true);
                    tokio::spawn(carrier::pump_stream(upstream, tunnel, id, inbound_rx));
                }
                _ => {
                    log::warn!("upstream connect to {destination} failed for stream {id}");
                    // Unregister, then tell the client instead of letting it
                    // time out.
                    tunnel.registry().remove(id).await;
                    tunnel.handle().close(id).await;
                }
            }
        };

    let peer = io.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let tunnel =
        carrier::spawn_tunnel(io, auth.rx, auth.tx, cfg.ping_secs, &peer, on_open).await;
    let mut live = tunnels.lock().unwrap();
    live.retain(|t| !t.is_dead());
    live.push(tunnel);
}

/// Run the SIP003 server plugin until the process is killed.
pub async fn run(opts: PluginOpts, sip: Sip003) -> Result<()> {
    debug_assert_eq!(opts.role, Role::Server, "server::run requires the server role");
    let static_kp = match opts.server_private_key {
        Some(bytes) => StaticKeypair::from_private_bytes(bytes),
        None => {
            let kp = StaticKeypair::generate();
            log::warn!(
                "generated ephemeral server identity {} — set key={} in plugin_opts to keep it \
                 stable (clients pin it with serverkey={})",
                crate::opts::to_hex(kp.private_bytes().as_ref()),
                crate::opts::to_hex(kp.private_bytes().as_ref()),
                crate::opts::to_hex(kp.public.as_bytes()),
            );
            kp
        }
    };
    let listener = TcpListener::bind(sip.remote).await?;
    log::info!(
        "qeli-ss-plugin (server) listening on {} → {}",
        sip.remote,
        sip.local
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    serve(
        listener,
        ServerConfig {
            static_kp,
                password: opts.password,
            destination: sip.local,
            ping_secs: opts.ping_secs,
            dial_timeout: Duration::from_secs(opts.dial_timeout_secs),
        },
        shutdown_rx,
    )
    .await;
    Ok(())
}
