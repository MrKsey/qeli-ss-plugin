//! The plugin's own fake-tls + auth handshake — a slimmed-down mirror of the
//! qeli client/server handshake, without the VPN NetworkPlan machinery.
//!
//! Wire choreography (identical record sequence to qeli's fake-tls profile):
//!
//! ```text
//! client                                            server
//!   ClientHello (X25519 + ML-KEM-768 key share)  →
//!                                                  parse, encapsulate ML-KEM
//!                                                ←  ServerHello (hybrid key share)
//!                                                ←  ChangeCipherSpec
//!                                                ←  Certificate (opaque)
//!                                                ←  Finished (opaque)
//!                                                ←  NewSessionTicket (opaque)
//!                                                ←  [AEAD] server identity proof
//!      verify proof (transcript-bound, TOFU/pin)
//!   [AEAD] password auth                        →
//!                                                  verify the shared password
//!                                                ←  [AEAD] "OK:qeli-ss-plugin/<version>"
//! ```
//!
//! After the handshake both sides hold matched `PacketCodec` pairs (TLS-dressed
//! AEAD records) and the mux frames flow inside them.

use anyhow::{anyhow, bail};
use qeli_core::crypto::auth::ct_eq;
use qeli_core::crypto::{
    build_server_auth_message, compute_client_key_proof, derive_keys_hybrid,
    handshake_transcript_hash, verify_server_auth_message, Keypair, PublicKey, StaticKeypair,
};
use qeli_core::protocol::{FakeTlsHandshake, PacketCodec, DEVICE_ID_LEN};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Chunk size for buffered handshake reads.
const READ_CHUNK: usize = 16384;

/// Buffered TLS-record reader for the handshake.
///
/// The handshake reads a burst of records (ServerHello/CCS/Cert/Finished/NST
/// or the auth flights) that the peer writes back-to-back. Exact-N
/// `read_exact`-style reads can park with further records already buffered in
/// the socket — on Windows IOCP the wake for that buffered data can be lost
/// (see [`crate::carrier::RecordBuf`]). Chunked reads + parsing from a buffer
/// sidestep the hazard.
struct RecordReader {
    buf: Vec<u8>,
}

impl RecordReader {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    /// Read until one complete TLS-dressed record is buffered, return it.
    async fn read_record<S>(&mut self, io: &mut S) -> Result<Vec<u8>, io::Error>
    where
        S: AsyncRead + Unpin,
    {
        const HEADER: usize = 5;
        loop {
            if self.buf.len() >= HEADER {
                let payload_len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
                let total = HEADER + payload_len;
                if self.buf.len() >= total {
                    return Ok(self.buf.drain(..total).collect());
                }
            }
            let mut chunk = [0u8; READ_CHUNK];
            let n = io.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-handshake",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Marker byte after the 32-byte client key proof, introducing the device id
/// (same backward-compatible layout qeli uses: `[proof:32][0x00][device_id:16][password]`).
const DEVICE_MARKER: u8 = 0;

/// Server response prefix on success.
pub const AUTH_OK_PREFIX: &str = "OK:";

/// Authenticated client-side handshake result: matched record codecs plus the
/// server's static identity key (for TOFU logging / pin verification).
pub struct ClientHandshake {
    /// Decrypts server→client records.
    pub rx: PacketCodec,
    /// Encrypts client→server records.
    pub tx: PacketCodec,
    /// The server's static public key observed in the identity proof.
    pub server_static: [u8; 32],
}

/// Run the client side of the handshake over an established connection.
///
/// `pinned_server_key`: when set, the server identity proof must match this
/// static key or the handshake fails (anti-MITM pinning). When absent the key
/// is accepted on first use (TOFU) and returned in
/// [`ClientHandshake::server_static`].
///
/// `timeout`: hard deadline for the WHOLE handshake — a peer that accepts
/// the TCP connection but stalls mid-handshake must not hang the dialer.
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake<S>(
    io: &mut S,
    sni: &str,
    password: &str,
    device_id: &[u8; DEVICE_ID_LEN],
    pinned_server_key: Option<[u8; 32]>,
    timeout: Duration,
) -> anyhow::Result<ClientHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(
        timeout,
        client_handshake_inner(io, sni, password, device_id, pinned_server_key),
    )
    .await
    .map_err(|_| anyhow!("client handshake timed out after {timeout:?}"))?
}

async fn client_handshake_inner<S>(
    io: &mut S,
    sni: &str,
    password: &str,
    device_id: &[u8; DEVICE_ID_LEN],
    pinned_server_key: Option<[u8; 32]>,
) -> anyhow::Result<ClientHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_kp = Keypair::generate();
    let mut reader = RecordReader::new();
    let (client_hello, mlkem_dk) =
        FakeTlsHandshake::build_client_hello_pq(client_kp.public(), sni, 0, None);
    io.write_all(&client_hello).await?;

    let server_hello = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read ServerHello: {e}"))?;
    let (mlkem_ct, server_x25519) = FakeTlsHandshake::parse_server_hello_pq(&server_hello)
        .ok_or_else(|| anyhow!("failed to parse hybrid ServerHello"))?;
    let change_cipher_spec = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read ChangeCipherSpec: {e}"))?;
    if change_cipher_spec.first() != Some(&0x14) {
        bail!("expected ChangeCipherSpec before the encrypted handshake flight");
    }
    let certificate = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read Certificate: {e}"))?;
    let finished = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read Finished: {e}"))?;
    let _new_session_ticket = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read NewSessionTicket: {e}"))?;

    let server_pub = PublicKey::from_bytes(&server_x25519);
    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow!("rejected low-order server public key"))?;
    let mlkem_shared = qeli_core::crypto::mlkem::mlkem768_decapsulate(&mlkem_dk, &mlkem_ct)
        .ok_or_else(|| anyhow!("ML-KEM decapsulation failed"))?;
    let mlkem_shared: [u8; 32] = mlkem_shared
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ML-KEM shared secret not 32 bytes"))?;
    let (server_to_client, client_to_server) = derive_keys_hybrid(&shared.0, &mlkem_shared);
    let mut rx = PacketCodec::new(server_to_client);
    let mut tx = PacketCodec::new(client_to_server);

    let transcript_hash =
        handshake_transcript_hash(&[&client_hello, &server_hello, &certificate, &finished]);

    // Server identity proof: static key + transcript binding.
    let proof_record = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read server identity proof: {e}"))?;
    let proof = rx
        .decrypt_packet(&proof_record)
        .map_err(|e| anyhow!("failed to decrypt server identity proof: {e}"))?;
    let server_static =
        verify_server_auth_message(&proof, &client_kp, &shared.0, &transcript_hash)
            .map_err(|e| anyhow!("server identity verification failed: {e}"))?;
    if let Some(pinned) = pinned_server_key {
        if !ct_eq(&server_static, &pinned) {
            bail!("server identity mismatch: the pinned key does not match this server");
        }
    }

    // Client auth: [key proof (zeros when unpinned)][0x00][device_id][password].
    let client_proof = pinned_server_key
        .map(|pinned| {
            let static_shared = client_kp.derive_shared(&PublicKey::from_bytes(&pinned));
            compute_client_key_proof(&static_shared.0, &shared.0, &transcript_hash)
        })
        .unwrap_or([0u8; 32]);
    let mut plaintext =
        Vec::with_capacity(32 + 1 + DEVICE_ID_LEN + password.len());
    plaintext.extend_from_slice(&client_proof);
    plaintext.push(DEVICE_MARKER);
    plaintext.extend_from_slice(device_id);
    plaintext.extend_from_slice(password.as_bytes());
    let auth_packet = tx
        .encrypt_packet(&plaintext, &[])
        .map_err(|e| anyhow!("failed to encrypt auth message: {e}"))?;
    io.write_all(&auth_packet).await?;

    let response_record = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read auth response: {e}"))?;
    let response = rx
        .decrypt_packet(&response_record)
        .map_err(|e| anyhow!("failed to decrypt auth response: {e}"))?;
    let response = String::from_utf8_lossy(&response);
    if !response.starts_with(AUTH_OK_PREFIX) {
        let shown: String = response.chars().take(64).collect();
        bail!("auth rejected by server: {shown}");
    }

    Ok(ClientHandshake {
        rx,
        tx,
        server_static,
    })
}

/// Authenticated server-side handshake result: matched record codecs.
pub struct ServerHandshake {
    /// Decrypts client→server records.
    pub rx: PacketCodec,
    /// Encrypts server→client records.
    pub tx: PacketCodec,
}

/// Run the server side of the handshake over an established connection.
///
/// `static_kp` is the server's long-lived identity key (the key clients pin).
/// The shared password is compared in constant time; failure aborts the
/// connection. One password serves any number of clients (each from any host
/// — the password IS the credential).
///
/// `timeout`: hard deadline for the WHOLE handshake — a client that connects
/// and stalls must not hang the server's connection task forever.
pub async fn server_handshake<S>(
    io: &mut S,
    static_kp: &StaticKeypair,
    password: &str,
    timeout: Duration,
) -> anyhow::Result<ServerHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(
        timeout,
        server_handshake_inner(io, static_kp, password),
    )
    .await
    .map_err(|_| anyhow!("server handshake timed out after {timeout:?}"))?
}

async fn server_handshake_inner<S>(
    io: &mut S,
    static_kp: &StaticKeypair,
    password: &str,
) -> anyhow::Result<ServerHandshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = RecordReader::new();
    let client_hello = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read ClientHello: {e}"))?;
    let client_pub_bytes = FakeTlsHandshake::parse_client_hello(&client_hello)
        .ok_or_else(|| anyhow!("failed to parse ClientHello"))?;
    if client_pub_bytes.len() != 32 {
        bail!("invalid client public key length");
    }
    let client_pub = PublicKey::from_bytes(&client_pub_bytes[..].try_into().expect("len checked"));
    let client_ek = FakeTlsHandshake::extract_client_mlkem_ek(&client_hello)
        .ok_or_else(|| anyhow!("ClientHello missing the X25519MLKEM768 key share"))?;
    let (mlkem_ct, mlkem_shared) = qeli_core::crypto::mlkem::mlkem768_encapsulate(&client_ek)
        .ok_or_else(|| anyhow!("ML-KEM encapsulation failed (malformed ek)"))?;
    let mlkem_shared: [u8; 32] = mlkem_shared
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ML-KEM shared secret not 32 bytes"))?;

    let server_kp = Keypair::generate();
    let server_hello = FakeTlsHandshake::build_server_hello_pq(server_kp.public(), &mlkem_ct);
    let certificate = FakeTlsHandshake::build_certificate();
    let finished = FakeTlsHandshake::build_finished();
    let new_session_ticket = FakeTlsHandshake::build_new_session_ticket();
    let transcript_hash =
        handshake_transcript_hash(&[&client_hello, &server_hello, &certificate, &finished]);

    io.write_all(&server_hello).await?;
    io.write_all(&FakeTlsHandshake::build_change_cipher_spec())
        .await?;
    io.write_all(&certificate).await?;
    io.write_all(&finished).await?;
    io.write_all(&new_session_ticket).await?;

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow!("rejected low-order client public key"))?;
    let (server_to_client, client_to_server) = derive_keys_hybrid(&shared.0, &mlkem_shared);
    let mut rx = PacketCodec::new(client_to_server);
    let mut tx = PacketCodec::new(server_to_client);

    // Server identity proof: static_pub(32) || proof(32), transcript-bound.
    let auth_msg = build_server_auth_message(static_kp, &client_pub, &shared.0, &transcript_hash);
    let proof_packet = tx
        .encrypt_packet(&auth_msg, &[])
        .map_err(|e| anyhow!("failed to encrypt identity proof: {e}"))?;
    io.write_all(&proof_packet).await?;

    // Client auth: [proof:32][0x00][device_id:16][password].
    let auth_record = reader.read_record(io).await
        .map_err(|e| anyhow!("failed to read client auth: {e}"))?;
    let auth = rx
        .decrypt_packet(&auth_record)
        .map_err(|e| anyhow!("failed to decrypt client auth: {e}"))?;
    let presented = parse_client_auth(&auth)?;
    if !ct_eq(presented.as_bytes(), password.as_bytes()) {
        bail!("auth failed: wrong password");
    }

    let ok_packet = tx
        .encrypt_packet(
            format!("{AUTH_OK_PREFIX}qeli-ss-plugin/{}", crate::VERSION).as_bytes(),
            &[],
        )
        .map_err(|e| anyhow!("failed to encrypt auth response: {e}"))?;
    io.write_all(&ok_packet).await?;

    Ok(ServerHandshake { rx, tx })
}

/// Split `[proof:32][0x00][device_id:16][password]` and return the password
/// slice. The proof field is not verified by the plugin (the shared password is
/// the auth); it only has to be present.
fn parse_client_auth(auth: &[u8]) -> anyhow::Result<&str> {
    if auth.len() < 33 {
        bail!("client auth message too short");
    }
    let password = if auth.len() >= 33 + DEVICE_ID_LEN && auth[32] == DEVICE_MARKER {
        &auth[33 + DEVICE_ID_LEN..]
    } else {
        &auth[32..]
    };
    std::str::from_utf8(password).map_err(|_| anyhow!("password is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qeli_core::crypto::StaticKeypair;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

        const PASSWORD: &str = "s3cret-p4ss";
    const SNI: &str = "www.example.com";
    const DEVICE: [u8; DEVICE_ID_LEN] = [0x42; DEVICE_ID_LEN];

    /// Hard deadline for the whole handshake pair: a regression must fail
    /// fast instead of hanging on a record read.
    const TEST_DEADLINE: Duration = Duration::from_secs(10);

    async fn handshake_pair() -> anyhow::Result<(ClientHandshake, ServerHandshake)> {
        tokio::time::timeout(TEST_DEADLINE, async {
            let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let static_kp = StaticKeypair::generate();
            let server = tokio::spawn(async move {
                server_handshake(&mut server_io, &static_kp, PASSWORD, TEST_DEADLINE)
                    .await
            });
            let client = client_handshake(
                &mut client_io,
                SNI,
                PASSWORD,
                &DEVICE,
                None,
                TEST_DEADLINE,
            )
            .await?;
            let server = server
                .await
                .map_err(|e| anyhow!("server task panicked: {e}"))??;
            Ok((client, server))
        })
        .await
        .map_err(|_| anyhow!("handshake pair exceeded the {TEST_DEADLINE:?} test deadline"))?
    }

    #[tokio::test]
    async fn handshake_roundtrip_then_records_flow_both_ways() {
        let (mut client, mut server) = handshake_pair().await.expect("handshake");

        // client → server
        let up = client
            .tx
            .encrypt_packet(b"ping from client", &[])
            .expect("encrypt");
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(&up).await.expect("write");
        let mut reader = RecordReader::new();
        let record = tokio::time::timeout(TEST_DEADLINE, reader.read_record(&mut b))
            .await
            .expect("deadline")
            .expect("read record");
        let plain = server.rx.decrypt_packet(&record).expect("decrypt");
        assert_eq!(plain, b"ping from client");

        // server → client
        let down = server
            .tx
            .encrypt_packet(b"pong from server", &[])
            .expect("encrypt");
        b.write_all(&down).await.expect("write");
        let mut reader = RecordReader::new();
        let record = tokio::time::timeout(TEST_DEADLINE, reader.read_record(&mut a))
            .await
            .expect("deadline")
            .expect("read record");
        let plain = client.rx.decrypt_packet(&record).expect("decrypt");
        assert_eq!(plain, b"pong from server");
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let static_kp = StaticKeypair::generate();
        let server = tokio::spawn(async move {
            server_handshake(&mut server_io, &static_kp, PASSWORD, TEST_DEADLINE).await
        });
        let client = tokio::time::timeout(
            Duration::from_secs(10),
            client_handshake(
                &mut client_io,
                SNI,
                "wrong-password",
                &DEVICE,
                None,
                TEST_DEADLINE,
            ),
        )
        .await
        .expect("timeout");
        assert!(client.is_err(), "client must not authenticate with a wrong password");
        let server = tokio::time::timeout(TEST_DEADLINE, server)
            .await
            .expect("server task must finish within the deadline")
            .expect("server task panicked");
        assert!(server.is_err(), "server must reject the wrong password");
    }

    #[tokio::test]
    async fn pinned_key_mismatch_is_rejected() {
        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let static_kp = StaticKeypair::generate();
        let other_key = StaticKeypair::generate();
        let server = tokio::spawn(async move {
            server_handshake(&mut server_io, &static_kp, PASSWORD, TEST_DEADLINE).await
        });
        let client = client_handshake(
            &mut client_io,
            SNI,
            PASSWORD,
            &DEVICE,
            Some(*other_key.public.as_bytes()),
            TEST_DEADLINE,
        )
        .await;
        let error = match client {
            Err(error) => error,
            Ok(_) => panic!("pin mismatch must fail"),
        };
        assert!(
            error.to_string().contains("identity mismatch"),
            "the error must name the identity mismatch, got: {error:#}"
        );
        // The server blocks reading the auth record that never comes; drop
        // the client's io so it sees EOF and finishes.
        drop(client_io);
        let server = tokio::time::timeout(TEST_DEADLINE, server)
            .await
            .expect("server task must finish within the deadline")
            .expect("server task panicked");
        assert!(server.is_err(), "server sees the client disconnect");
    }

    #[tokio::test]
    async fn tofu_returns_the_servers_static_key() {
        let (client, _server) = handshake_pair().await.expect("handshake");
        assert_eq!(client.server_static.len(), 32);
        assert!(client.server_static.iter().any(|b| *b != 0));
    }

    #[tokio::test]
    async fn stalled_peer_times_out_on_the_client_side() {
        // The peer accepts the TCP connection (duplex stays open) but never
        // answers the handshake — the dialer must give up, not hang.
        let (mut client_io, _silent_server_io) = tokio::io::duplex(64 * 1024);
        let start = std::time::Instant::now();
        let error = match client_handshake(
            &mut client_io,
            SNI,
            PASSWORD,
            &DEVICE,
            None,
            Duration::from_secs(1),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("a silent peer must time out"),
        };
        assert!(
            error.to_string().contains("timed out"),
            "the error must name the timeout, got: {error:#}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the 1s deadline must be honored (took {:?})",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn stalled_peer_times_out_on_the_server_side() {
        // A client that connects and sends nothing must not hang the
        // server's connection task forever.
        let (mut _silent_client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let static_kp = StaticKeypair::generate();
        let start = std::time::Instant::now();
        let error = match server_handshake(
            &mut server_io,
            &static_kp,
            PASSWORD,
            Duration::from_secs(1),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("a silent peer must time out"),
        };
        assert!(
            error.to_string().contains("timed out"),
            "the error must name the timeout, got: {error:#}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the 1s deadline must be honored (took {:?})",
            start.elapsed()
        );
    }

    #[test]
    fn parse_client_auth_layout() {
        let mut msg = vec![0u8; 32];
        msg.push(DEVICE_MARKER);
        msg.extend_from_slice(&[0u8; DEVICE_ID_LEN]);
        msg.extend_from_slice(b"s3cret");
        assert_eq!(parse_client_auth(&msg).unwrap(), "s3cret");
    }

    #[test]
    fn parse_client_auth_rejects_short_messages() {
        assert!(parse_client_auth(&[0u8; 32]).is_err());
        assert!(parse_client_auth(&[]).is_err());
    }

    #[tokio::test]
    async fn many_clients_same_password_each_own_tunnel() {
        // One password, three independent clients (fresh keys/device ids),
        // one server: every handshake must succeed concurrently.
        let (mut a_io, mut a_peer) = tokio::io::duplex(64 * 1024);
        let (mut b_io, mut b_peer) = tokio::io::duplex(64 * 1024);
        let (mut c_io, mut c_peer) = tokio::io::duplex(64 * 1024);
        let static_kp = StaticKeypair::generate();
        let server = tokio::spawn(async move {
            for io in [&mut a_peer, &mut b_peer, &mut c_peer] {
                let _ = server_handshake(io, &static_kp, PASSWORD, TEST_DEADLINE).await;
            }
        });
        let devices: Vec<[u8; DEVICE_ID_LEN]> =
            vec![[1; DEVICE_ID_LEN], [2; DEVICE_ID_LEN], [3; DEVICE_ID_LEN]];
        let mut clients = Vec::new();
        for (io, device) in [(a_io, devices[0]), (b_io, devices[1]), (c_io, devices[2])] {
            let mut io = io;
            clients.push(tokio::spawn(async move {
                client_handshake(
                    &mut io,
                    SNI,
                    PASSWORD,
                    &device,
                    None,
                    TEST_DEADLINE,
                )
                .await
                .is_ok()
            }));
        }
        tokio::time::timeout(TEST_DEADLINE, server)
            .await
            .expect("server must finish")
            .expect("server task panicked");
        for client in clients {
            assert!(
                tokio::time::timeout(TEST_DEADLINE, client)
                    .await
                    .expect("client deadline")
                    .expect("client task panicked"),
                "every client with the same password must authenticate"
            );
        }
    }
}
