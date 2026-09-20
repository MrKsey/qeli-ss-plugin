//! End-to-end integration tests: full stack (mux + handshake + carrier +
//! client/server) over real TCP sockets, with a stand-in "ss-server" echo.

use qeli_core::crypto::StaticKeypair;
use qeli_ss_plugin::client::{ClientTunnelConfig, TunnelManager};
use qeli_ss_plugin::server::{serve, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const PASSWORD: &str = "s3cret-p4ss";
const SNI: &str = "www.example.com";

/// Hard per-test deadline: every potentially-blocking read is wrapped, so a
/// regression cannot hang a test beyond this bound.
const TEST_DEADLINE: Duration = Duration::from_secs(20);

async fn read_exact_deadlined<S: tokio::io::AsyncReadExt + Unpin>(
    sock: &mut S,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    tokio::time::timeout(TEST_DEADLINE, sock.read_exact(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "test deadline exceeded"))?
}

async fn read_deadlined<S: tokio::io::AsyncReadExt + Unpin>(
    sock: &mut S,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    tokio::time::timeout(TEST_DEADLINE, sock.read(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "test deadline exceeded"))?
}

/// A stand-in ss-server: echoes every connection byte-for-byte.
async fn spawn_echo_ss_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut io, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    match io.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if io.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn server_key() -> [u8; 32] {
    [0x5A; 32]
}

/// The server's PUBLIC key derived from the private one — X25519(private) ≠
/// private, so tests must pin this, not the private bytes.
fn server_public(key: [u8; 32]) -> [u8; 32] {
    *StaticKeypair::from_private_bytes(key).public.as_bytes()
}

/// Start the plugin server; returns (listen addr, shutdown sender, task).
/// `bind: None` picks an ephemeral port; `Some(addr)` listens on a fixed one
/// (used to restart the server on the SAME address after a death).
async fn spawn_plugin_server(
    destination: SocketAddr,
    key: [u8; 32],
    ping_secs: u32,
    bind: Option<SocketAddr>,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(bind.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cfg = ServerConfig {
        static_kp: StaticKeypair::from_private_bytes(key),
        password: PASSWORD.to_string(),
        destination,
        ping_secs,
        dial_timeout: Duration::from_secs(3),
    };
    let task = tokio::spawn(serve(listener, cfg, shutdown_rx));
    (addr, shutdown_tx, task)
}

fn manager(remote: SocketAddr, server_key: Option<[u8; 32]>, ping_secs: u32) -> Arc<TunnelManager> {
    Arc::new(TunnelManager::new(ClientTunnelConfig {
        remote,
        password: PASSWORD.to_string(),
        sni: SNI.to_string(),
        server_public_key: server_key,
        ping_secs,
        dial_timeout: Duration::from_secs(3),
    }))
}

/// One "ss-local connection": a real TCP pair whose server side is pumped
/// through the manager; returns the client-facing socket.
///
/// Tolerant of local AV-proxy interception: a web filter (e.g. Kaspersky's
/// avp) can transparently redirect an outbound loopback connect to its own
/// HTTP proxy, which answers with an HTTP error instead of our ServerHello
/// ("failed to parse hybrid ServerHello"). That is an environment artifact,
/// not a plugin bug — the dial is retried instead of failing the test.
async fn ss_local_side(manager: &TunnelManager) -> TcpStream {
    dial_ss_local(manager)
        .await
        .expect("accept_connection must succeed")
}

/// Same as [`ss_local_side`], but returns the error (for negative tests)
/// after retrying AV-proxy interceptions.
async fn dial_ss_local(manager: &TunnelManager) -> Result<TcpStream, anyhow::Error> {
    const ATTEMPTS: usize = 4;
    for attempt in 0..ATTEMPTS {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_side, _) = listener.accept().await.unwrap();
        match manager.accept_connection(server_side).await {
            Ok(()) => return Ok(client),
            Err(error) => {
                drop(client);
                let intercepted = error.to_string().contains("parse hybrid ServerHello");
                if intercepted && attempt + 1 < ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    continue;
                }
                return Err(error);
            }
        }
    }
    unreachable!("the loop always returns")
}

/// Read one raw TLS-dressed record (5-byte header + payload) from `io`.
async fn read_record_raw<S: tokio::io::AsyncRead + Unpin>(
    io: &mut S,
) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await.ok()?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await.ok()?;
    record.extend_from_slice(&payload);
    Some(record)
}

/// A hostile middlebox between the client and the real server. After the
/// (deterministic, 7-record) server handshake flight it CORRUPTS one
/// server→client record (flips an AEAD tag byte), and it DUPLICATES the
/// first client→server record after the (2-record) client handshake flight.
/// Both must be tolerated: records dropped, tunnel alive.
async fn spawn_mangling_proxy(real: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(upstream) = TcpStream::connect(real).await else {
                continue;
            };
            tokio::spawn(splice_mangling(client, upstream));
        }
    });
    addr
}

async fn splice_mangling(client: TcpStream, upstream: TcpStream) {
    use tokio::io::AsyncWriteExt as _;
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    // client→server: records 1-2 are the handshake (ClientHello, auth);
    // duplicate record 3 (the first mux frame, the OPEN), then pass through.
    let c2s = async move {
        let mut n = 0u32;
        while let Some(record) = read_record_raw(&mut cr).await {
            let _ = uw.write_all(&record).await;
            if n == 2 {
                // the duplicate — a replayed segment
                let _ = uw.write_all(&record).await;
            }
            n += 1;
        }
    };
    // server→client: records 1-7 are the handshake flight (SH, CCS, Cert,
    // Finished, NST, identity proof, OK); corrupt record 8 (the first mux
    // record, the first echo reply), then pass through.
    let s2c = async move {
        let mut n = 0u32;
        while let Some(mut record) = read_record_raw(&mut ur).await {
            if n == 7 {
                let last = record.len() - 1;
                record[last] ^= 0xFF; // corrupt the AEAD tag
            }
            let _ = cw.write_all(&record).await;
            n += 1;
        }
    };
    tokio::join!(c2s, s2c);
}

/// A flaky front end: the first `fail_first` connections are accepted and
/// immediately dropped (a load balancer killing a connection mid-handshake);
/// everything after is a plain byte pipe to the real server.
async fn spawn_flaky_proxy(real: SocketAddr, fail_first: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut failed = 0usize;
        while let Ok((client, _)) = listener.accept().await {
            if failed < fail_first {
                failed += 1;
                drop(client); // killed mid-handshake
                continue;
            }
            let Ok(upstream) = TcpStream::connect(real).await else {
                continue;
            };
            tokio::spawn(async move {
                let mut client = client;
                let mut upstream = upstream;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn single_connection_echo_roundtrip() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    sock.write_all(b"hello qeli mux").await.unwrap();
    let mut buf = [0u8; 14];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"hello qeli mux");
}

#[tokio::test]
async fn concurrent_streams_share_one_tunnel() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let mut sockets = Vec::new();
    for i in 0..3 {
        let mut sock = ss_local_side(&manager).await;
        let msg = format!("stream-{i}-payload");
        sock.write_all(msg.as_bytes()).await.unwrap();
        sockets.push((sock, msg));
    }

    // All three streams must have ridden the SAME tunnel (path B: one
    // long-lived connection, one stream per ss-local connection).
    let tunnel = manager.current().await.expect("a tunnel exists");
    assert!(
        !tunnel.is_dead(),
        "the shared tunnel must be alive after three streams"
    );

    for (mut sock, msg) in sockets {
        let mut buf = vec![0u8; msg.len()];
        read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
        assert_eq!(buf, msg.into_bytes());
    }
}

#[tokio::test]
async fn large_transfer_roundtrip_chunked() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    // 1 MiB pseudo-random pattern: exercises DATA chunking (16384-byte frames)
    // and both directions of the pump.
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i * 31 % 251) as u8).collect();

    let (mut reader, mut writer) = tokio::io::split(sock);
    let send_payload = payload.clone();
    let send = tokio::spawn(async move {
        for chunk in send_payload.chunks(60_000) {
            writer.write_all(chunk).await.unwrap();
        }
        // NOTE: no shutdown() — tokio's TcpStream shutdown closes BOTH
        // directions, which would kill the reader half. The echo reply is
        // exactly payload.len() bytes, so read exactly that many instead.
    });

    let mut received = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < received.len() {
        let n = read_deadlined(&mut reader, &mut received[filled..])
            .await
            .unwrap();
        assert!(n > 0, "echo closed early after {filled} of {} bytes", payload.len());
        filled += n;
    }
    let send_result =
        tokio::time::timeout(TEST_DEADLINE, send)
            .await
            .expect("send task must finish within the deadline");
    assert!(send_result.is_ok(), "send task must not panic");
    assert_eq!(filled, payload.len());
    assert_eq!(received, payload, "1 MiB echo must roundtrip intact");
}

#[tokio::test]
async fn half_close_reaches_the_echo_server() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    sock.write_all(b"fin-test").await.unwrap();
    // Read the echo reply BEFORE half-closing: on Windows a shutdown(SD_SEND)
    // on a socket with a parked reader spurious-EOFs that reader (tokio IOCP
    // readiness emulation), so the reply-after-FIN ordering is only
    // observable on Linux (SHUT_WR leaves the read side intact).
    let mut buf = [0u8; 64];
    let n = read_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fin-test", "the echo reply must come back");

    // Now ss-local half-closes its write side (a direct SHUT_WR via the
    // plugin's WriteFin — tokio's shutdown() would close BOTH directions).
    qeli_ss_plugin::carrier::WriteFin::capture(&sock)
        .fin()
        .unwrap();
    // The FIN must travel: pump EOF → CLOSE frame → server removes the
    // stream → FIN to the echo → echo closes → CLOSE back → the client
    // pump FINs our socket → EOF here.
    let n = read_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(n, 0, "EOF must propagate back after the half-close");
}

#[tokio::test]
async fn wrong_password_is_rejected_end_to_end() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = Arc::new(TunnelManager::new(ClientTunnelConfig {
        remote: server_addr,
        password: "not-the-password".to_string(),
        sni: SNI.to_string(),
        server_public_key: Some(server_public(server_key())),
        ping_secs: 0,
        dial_timeout: Duration::from_secs(3),
    }));

    let error = dial_ss_local(&manager)
        .await
        .expect_err("wrong password must fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("auth"),
        "the failure must be an auth failure, got: {message}"
    );
}

#[tokio::test]
async fn pinned_server_key_rejects_an_impostor() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) =
        spawn_plugin_server(echo, [0x77; 32], 0, None).await; // different identity
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let error = dial_ss_local(&manager)
        .await
        .expect_err("identity mismatch must fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("identity"),
        "the failure must name the identity mismatch, got: {message}"
    );
}

#[tokio::test]
async fn server_death_forces_lazy_redial_on_same_manager() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, shutdown, task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    // Stream 1 works.
    let mut sock1 = ss_local_side(&manager).await;
    sock1.write_all(b"before death").await.unwrap();
    let mut buf = [0u8; 12];
    sock1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before death");
    let first_tunnel = manager.current().await.unwrap();

    // The server dies (listener + every tunnel aborted).
    shutdown.send(true).unwrap();
    task.await.unwrap();
    // Let the client's reader notice the dropped TCP (EOF → dead tunnel).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The old ss-local socket sees EOF through the death fan-out.
    let mut eof = [0u8; 8];
    let n = read_deadlined(&mut sock1, &mut eof).await.unwrap();
    assert_eq!(n, 0, "the old stream must see EOF after tunnel death");
    assert!(first_tunnel.is_dead());

    // Restart the server on the SAME address; the SAME manager redials lazily.
    let (_server_addr2, _shutdown2, _task2) =
        spawn_plugin_server(echo, server_key(), 0, Some(server_addr)).await;
    let mut sock2 = ss_local_side(&manager).await;
    sock2.write_all(b"after rebirth").await.unwrap();
    let mut buf = [0u8; 13];
    sock2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"after rebirth");

    let second_tunnel = manager.current().await.unwrap();
    assert!(
        !Arc::ptr_eq(&first_tunnel, &second_tunnel),
        "a fresh tunnel must have been dialed"
    );
}

#[tokio::test]
async fn keepalive_ping_pong_keeps_tunnel_alive() {
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 1, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 1);

    let mut sock = ss_local_side(&manager).await;
    sock.write_all(b"ka").await.unwrap();
    let mut buf = [0u8; 2];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"ka");

    // Both sides ping every 1s; PONGs must accumulate on the client tunnel.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let tunnel = manager.current().await.unwrap();
        if tunnel.pongs() >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no PONG observed within 6s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn corrupted_and_replayed_records_do_not_kill_the_tunnel() {
    // Real traffic through a hostile middlebox: one server→client record is
    // corrupted (its echo reply is lost) and one client→server record is
    // duplicated (a replayed OPEN). The tunnel must survive both and keep
    // carrying traffic.
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let proxy_addr = spawn_mangling_proxy(server_addr).await;
    let manager = manager(proxy_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    // "first" rides the record the proxy corrupts: its echo reply is
    // dropped, never delivered. Give the roundtrip time to complete so the
    // next write is a separate mux frame.
    sock.write_all(b"first").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // "second" must come back intact — the tunnel survived the corruption
    // and the replayed OPEN.
    sock.write_all(b"second").await.unwrap();
    let mut buf = [0u8; 6];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"second");
    // And the tunnel is still healthy: more traffic flows.
    sock.write_all(b"third").await.unwrap();
    let mut buf = [0u8; 5];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"third");
    let tunnel = manager.current().await.unwrap();
    assert!(!tunnel.is_dead(), "the tunnel must survive mangling");
}

#[tokio::test]
async fn flaky_front_end_first_dial_killed_retry_succeeds() {
    // The first tunnel dial is killed mid-handshake (a connection dropped
    // during auth); accept_connection must retry transparently and the
    // stream must flow over the second dial.
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let flaky_addr = spawn_flaky_proxy(server_addr, 1).await;
    let manager = manager(flaky_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    sock.write_all(b"after-flake").await.unwrap();
    let mut buf = [0u8; 11];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"after-flake");
}

#[tokio::test]
async fn hung_server_peer_detected_within_five_seconds_and_redialed() {
    // Phase 1: a "hung" server — completes the handshake, then goes silent
    // forever (socket open, nothing answered: a frozen process). The client
    // must detect the dead tunnel within 5s (ping=1 + grace=2 ≈ 3s) and the
    // stalled ss-local socket must see EOF.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hung_addr = listener.local_addr().unwrap();

    let static_kp = StaticKeypair::from_private_bytes(server_key());
    tokio::spawn(async move {
        // Accept the (single) tunnel dial, complete the handshake, then hold
        // the socket open and silent forever: a frozen process.
        let (mut hung_io, _client_of_hung) = listener.accept().await.unwrap();
        drop(listener); // free the port for the real server in phase 2
        let _ = qeli_ss_plugin::handshake::server_handshake(
            &mut hung_io,
            &static_kp,
            PASSWORD,
            Duration::from_secs(3),
        )
        .await;
        let mut buf = vec![0u8; 4096];
        loop {
            match hung_io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let manager = manager(hung_addr, Some(server_public(server_key())), 1);
    let mut sock = ss_local_side(&manager).await; // dial + handshake OK
    sock.write_all(b"hello?").await.unwrap(); // never answered
    let tunnel = manager.current().await.unwrap();
    let start = tokio::time::Instant::now();
    loop {
        if tunnel.is_dead() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a dead tunnel must be detected within 5s (took {:?})",
            start.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The stalled stream sees EOF through the death fan-out.
    let mut buf = [0u8; 8];
    let n = read_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(n, 0, "the stalled ss-local socket must see EOF");

    // Phase 2: a real server takes over the SAME port; the SAME manager
    // redials lazily and traffic flows again.
    let echo = spawn_echo_ss_server().await;
    let (_addr2, _shutdown2, _task2) =
        spawn_plugin_server(echo, server_key(), 0, Some(hung_addr)).await;
    let mut sock2 = ss_local_side(&manager).await;
    sock2.write_all(b"reborn").await.unwrap();
    let mut buf = [0u8; 6];
    read_exact_deadlined(&mut sock2, &mut buf).await.unwrap();
    assert_eq!(&buf, b"reborn");
    let second = manager.current().await.unwrap();
    assert!(
        !Arc::ptr_eq(&tunnel, &second),
        "a fresh tunnel must have been dialed after the hang"
    );
}

#[tokio::test]
async fn eight_streams_of_mixed_sizes_share_one_tunnel() {
    // Realistic mix: 8 concurrent ss-local connections, payloads from 1 byte
    // to 200 KiB (spanning many 16 KiB mux frames), all riding ONE tunnel.
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let sizes: [usize; 8] = [1, 64, 1024, 16 * 1024, 20_001, 65_536, 131_072, 200_003];
    let mut sockets = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        let mut sock = ss_local_side(&manager).await;
        // Per-stream pseudo-random payload (deterministic).
        let payload: Vec<u8> = (0..size).map(|j| ((i + 1) * j * 31 % 251) as u8).collect();
        sock.write_all(&payload).await.unwrap();
        sockets.push((sock, payload));
    }

    for (mut sock, payload) in sockets {
        let mut received = vec![0u8; payload.len()];
        let mut filled = 0;
        while filled < received.len() {
            let n = read_deadlined(&mut sock, &mut received[filled..])
                .await
                .unwrap();
            assert!(
                n > 0,
                "echo closed early after {filled} of {} bytes",
                payload.len()
            );
            filled += n;
        }
        assert_eq!(received, payload, "every stream must roundtrip intact");
    }

    let tunnel = manager.current().await.unwrap();
    assert!(!tunnel.is_dead(), "one tunnel carried all 8 streams");
}

#[tokio::test]
async fn ipv6_loopback_tunnel_roundtrip() {
    // The whole stack over IPv6 loopback: the plugin server listens on [::1],
    // the client dials [::1] — same code path as IPv4, family-agnostic.
    // (Skipped when the host has no IPv6 loopback.)
    if TcpListener::bind("[::1]:0").await.is_err() {
        eprintln!("no IPv6 loopback on this host — skipping");
        return;
    }
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) =
        spawn_plugin_server(echo, server_key(), 0, Some("[::1]:0".parse().unwrap())).await;
    assert!(server_addr.is_ipv6(), "the server must have bound IPv6");
    let manager = manager(server_addr, Some(server_public(server_key())), 0);

    let mut sock = ss_local_side(&manager).await;
    sock.write_all(b"v6 hello").await.unwrap();
    let mut buf = [0u8; 8];
    read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
    assert_eq!(&buf, b"v6 hello");

    let tunnel = manager.current().await.unwrap();
    assert!(!tunnel.is_dead(), "the IPv6 tunnel must be alive");
}

#[tokio::test]
async fn many_clients_same_password_share_one_server() {
    // One password, three independent clients (each its own manager = own
    // device id and dial), one server: all three authenticate and carry
    // traffic concurrently.
    let echo = spawn_echo_ss_server().await;
    let (server_addr, _shutdown, _task) = spawn_plugin_server(echo, server_key(), 0, None).await;

    let mut sockets = Vec::new();
    for i in 0..3 {
        let manager = manager(server_addr, Some(server_public(server_key())), 0);
        let mut sock = ss_local_side(&manager).await;
        let msg = format!("client-{i}");
        sock.write_all(msg.as_bytes()).await.unwrap();
        sockets.push((sock, msg));
    }

    for (mut sock, msg) in sockets {
        let mut buf = vec![0u8; msg.len()];
        read_exact_deadlined(&mut sock, &mut buf).await.unwrap();
        assert_eq!(buf, msg.into_bytes(), "every client must roundtrip");
    }
}
