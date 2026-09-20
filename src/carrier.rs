//! The shared long-lived qeli tunnel: wire writer/reader loops, the stream
//! registry (demux), keepalive and the per-stream pump.
//!
//! One [`Tunnel`] rides one TCP connection whose records are qeli AEAD
//! (fake-tls dressed) and whose payloads are [`mux::Frame`]s. Stream pumps
//! ([`pump_stream`]) bridge a local socket (ss-local connection on the client
//! side, ss-server connection on the server side) onto one mux stream id.
//!
//! Death semantics: when the wire reader or writer fails, the tunnel is marked
//! dead (`watch`), every registered inbound channel is closed (each pump sees
//! EOF on its local socket) and further [`CarrierHandle`] sends fail. The
//! client side dials a fresh tunnel lazily on the next accepted connection.

use crate::mux::{self, Frame};
use anyhow::anyhow;
use qeli_core::protocol::PacketCodec;
use rand::prelude::*;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};

/// Frames queued from stream pumps towards the wire writer.
pub const FRAME_CHANNEL_CAPACITY: usize = 256;

/// Per-stream inbound chunks buffered before the tunnel reader backpressures.
///
/// Backpressure here is deliberate: a stalled local consumer slows its own
/// stream's delivery, and — like any single-carrier mux without per-stream
/// windows — eventually the whole tunnel. Bounded, documented, v1.
pub const INBOUND_CAPACITY: usize = 64;

/// A stalled wire write is treated as a dead tunnel after this long.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// PONG grace: a PING unanswered for this long means the peer is silently
/// dead (frozen process, black-holed TCP). Fixed, NOT scaled by the ping
/// interval, so the worst-case detection stays bounded:
/// `ping interval + KEEPALIVE_GRACE` (defaults: 2s + 2s = 4s ≤ 5s).
const KEEPALIVE_GRACE: Duration = Duration::from_secs(2);

/// Consecutive undecryptable or malformed records tolerated before the
/// tunnel is declared dead. A couple of corrupted or replayed records in
/// flight (middlebox mangling, duplicated segments) must NOT kill a healthy
/// tunnel — each bad record is simply dropped. Persistent corruption beyond
/// this streak is still fatal (the stream is broken or under active attack).
const MAX_CONSECUTIVE_BAD_RECORDS: u32 = 8;

/// How long a FULL per-stream inbound channel may stay full (a stalled local
/// consumer) before the stream is dropped. Without this bound a single
/// stalled consumer would backpressure the shared reader and freeze the
/// WHOLE tunnel (head-of-line block) — including keepalive PONGs, which the
/// peer would read as our death.
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(5);

/// A stalled per-stream local write is abandoned after this long (more
/// lenient than the wire [`WRITE_TIMEOUT`]: a slow-but-alive consumer is not
/// a dead tunnel).
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Local socket read size; also the largest single mux DATA chunk.
pub const READ_BUF: usize = mux::MAX_DATA;

// ── stream registry ─────────────────────────────────────────────────────────

/// Demux table: stream id → inbound chunk sender for that stream's pump.
pub struct StreamRegistry {
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Register the inbound channel for `id`. Returns the previous sender if
    /// the id was already registered (the caller drops it — the old pump ends).
    pub async fn register(
        &self,
        id: u32,
        tx: mpsc::Sender<Vec<u8>>,
    ) -> Option<mpsc::Sender<Vec<u8>>> {
        self.streams.lock().await.insert(id, tx)
    }

    /// Deliver one DATA chunk. `false` = unknown/closed/stalled stream
    /// (dropped). A consumer whose channel stays FULL for
    /// [`STREAM_STALL_TIMEOUT`] is considered stalled: its stream is removed
    /// (the pump's inbound channel closes) so one stuck consumer can never
    /// freeze the shared reader — the rest of the tunnel keeps flowing.
    pub async fn deliver(&self, id: u32, payload: Vec<u8>) -> bool {
        let tx = { self.streams.lock().await.get(&id).cloned() };
        match tx {
            Some(tx) => match timeout(STREAM_STALL_TIMEOUT, tx.send(payload)).await {
                Ok(result) => result.is_ok(),
                Err(_) => {
                    log::warn!(
                        "stream {id}: consumer stalled for {STREAM_STALL_TIMEOUT:?} — \
                         dropping the stream to keep the tunnel alive"
                    );
                    self.streams.lock().await.remove(&id);
                    false
                }
            },
            None => false,
        }
    }

    /// Remove a stream (peer CLOSE or local teardown). Dropping the sender
    /// closes the pump's inbound channel → the pump finishes its local socket.
    pub async fn remove(&self, id: u32) -> Option<mpsc::Sender<Vec<u8>>> {
        self.streams.lock().await.remove(&id)
    }

    /// Close every stream: the death fan-out.
    pub async fn close_all(&self) {
        self.streams.lock().await.clear();
    }

    /// Number of live streams (diagnostics / tests).
    pub async fn len(&self) -> usize {
        self.streams.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

// ── carrier handle ──────────────────────────────────────────────────────────

/// Cloneable handle for enqueueing mux frames onto the tunnel.
#[derive(Clone)]
pub struct CarrierHandle {
    frames: mpsc::Sender<Frame>,
    dead: watch::Receiver<bool>,
    next_id: Arc<AtomicU32>,
}

impl CarrierHandle {
    /// Allocate a fresh stream id (per-tunnel, starts at 1).
    pub fn alloc_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Whether the tunnel is known-dead. A dead tunnel rejects sends; the
    /// client side dials a replacement on next use.
    pub fn is_dead(&self) -> bool {
        *self.dead.borrow()
    }

    async fn send_frame(&self, frame: Frame) -> anyhow::Result<()> {
        self.frames
            .send(frame)
            .await
            .map_err(|_| anyhow!("tunnel is down"))
    }

    /// Announce a new stream (OPEN frame).
    pub async fn open(&self, id: u32) -> anyhow::Result<()> {
        self.send_frame(Frame::Open { stream: id }).await
    }

    /// Send data on a stream, chunked into ≤ [`mux::MAX_DATA`] DATA frames.
    pub async fn send(&self, id: u32, data: &[u8]) -> anyhow::Result<()> {
        for chunk in data.chunks(mux::MAX_DATA) {
            self.send_frame(Frame::Data {
                stream: id,
                payload: chunk.to_vec(),
            })
            .await?;
        }
        Ok(())
    }

    /// Best-effort FIN (CLOSE frame); errors on a dead tunnel are ignored.
    pub async fn close(&self, id: u32) {
        let _ = self.send_frame(Frame::Close { stream: id }).await;
    }

    /// Send one keepalive PING.
    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut nonce = [0u8; mux::KEEPALIVE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        self.send_frame(Frame::Ping { nonce }).await
    }
}

// ── tunnel ──────────────────────────────────────────────────────────────────

/// One live tunnel: the handle, the demux registry and the death flag.
pub struct Tunnel {
    handle: CarrierHandle,
    registry: Arc<StreamRegistry>,
    dead_tx: watch::Sender<bool>,
    /// PONG frames received (keepalive diagnostics / tests).
    pongs: AtomicU64,
}

impl Tunnel {
    pub fn handle(&self) -> &CarrierHandle {
        &self.handle
    }

    pub fn registry(&self) -> &Arc<StreamRegistry> {
        &self.registry
    }

    pub fn pongs(&self) -> u64 {
        self.pongs.load(Ordering::Relaxed)
    }

    pub fn is_dead(&self) -> bool {
        self.handle.is_dead()
    }

    /// Force death: mark dead and close every stream. Idempotent.
    pub async fn kill(&self) {
        let _ = self.dead_tx.send(true);
        self.registry.close_all().await;
    }
}

/// Spawn a full tunnel over an authenticated connection.
///
/// * `rx` / `tx` — the matched `PacketCodec` pair from the handshake
///   (`rx` decrypts peer→us records, `tx` encrypts ours).
/// * `ping_secs` — keepalive interval in seconds; `0` disables keepalive.
/// * `on_open` — invoked (spawned) for every OPEN frame the peer sends with
///   the stream's registered inbound receiver. The server side connects its
///   upstream and pumps; the client side just logs the protocol violation.
pub async fn spawn_tunnel<S, F, Fut>(
    io: S,
    rx: PacketCodec,
    tx: PacketCodec,
    ping_secs: u32,
    on_open: F,
) -> Arc<Tunnel>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Arc<Tunnel>, u32, mpsc::Receiver<Vec<u8>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (frames_tx, frames_rx) = mpsc::channel::<Frame>(FRAME_CHANNEL_CAPACITY);
    let (dead_tx, dead_rx) = watch::channel(false);
    let tunnel = Arc::new(Tunnel {
        handle: CarrierHandle {
            frames: frames_tx,
            dead: dead_rx.clone(),
            next_id: Arc::new(AtomicU32::new(1)),
        },
        registry: Arc::new(StreamRegistry::new()),
        dead_tx,
        pongs: AtomicU64::new(0),
    });

    let (read_half, write_half) = tokio::io::split(io);
    tokio::spawn(writer_loop(write_half, tx, frames_rx, tunnel.clone()));
    tokio::spawn(reader_loop(read_half, rx, tunnel.clone(), on_open));
    if ping_secs > 0 {
        tokio::spawn(keepalive_loop(tunnel.clone(), ping_secs));
    }
    tunnel
}

/// Encrypt and write every queued frame; a write error/timeout kills the tunnel.
async fn writer_loop<W>(
    mut io: W,
    mut codec: PacketCodec,
    mut frames: mpsc::Receiver<Frame>,
    tunnel: Arc<Tunnel>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut dead = tunnel.dead_tx.subscribe();
    let mut plain = Vec::with_capacity(256);
    let mut record = Vec::with_capacity(4096);
    loop {
        // Check the CURRENT flag every iteration: a kill() that completed
        // before this task was first polled is invisible to changed() —
        // subscribe() marks the current value as already seen.
        if *dead.borrow() {
            break;
        }
        let frame = tokio::select! {
            f = frames.recv() => match f {
                Some(f) => f,
                None => break,
            },
            _ = dead.changed() => {
                if *dead.borrow() {
                    break;
                }
                continue;
            }
        };
        frame.encode_into(&mut plain);
        if codec.encrypt_packet_into(&plain, &[], &mut record).is_err() { break; }
        let write = async {
            io.write_all(&record).await?;
            io.flush().await
        };
        if matches!(timeout(WRITE_TIMEOUT, write).await, Err(_) | Ok(Err(_))) { break; }
    }
    tunnel.kill().await;
}

/// Buffered TLS-record extraction: push socket chunks, take complete records.
///
/// Rationale: an exact-N `read_exact`-style record read can park the reader
/// while MORE complete records are already buffered in the socket. On
/// Windows IOCP the wake for that buffered data can then be lost (tokio's
/// level-triggered emulation is a sticky readiness bit cleared on
/// WouldBlock — a successful exact read that leaves bytes behind relies on
/// it, and empirically the wake does not arrive). Reading big chunks and
/// parsing records from memory sidesteps the hazard structurally: the socket
/// is only re-armed after a WouldBlock (an empty socket), so a parked reader
/// never has complete records waiting in the kernel.
#[derive(Default)]
pub struct RecordBuf {
    buf: Vec<u8>,
    /// Read cursor: records are consumed from `buf[pos..]`. Advancing a
    /// cursor instead of draining keeps record extraction O(1) amortized
    /// (a `drain(..n).collect()` per record is O(buffer) — quadratic over a
    /// chunk holding many records).
    pos: usize,
}

impl RecordBuf {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            pos: 0,
        }
    }

    /// Append bytes read from the socket.
    pub fn push(&mut self, chunk: &[u8]) {
        // The buffer was fully consumed: reuse it without growing.
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        self.buf.extend_from_slice(chunk);
    }

    /// Take one complete TLS-dressed record (5-byte header + payload), if a
    /// whole record is buffered. Oversized declared lengths are returned as
    /// records and rejected later by the AEAD record bounds check.
    pub fn take_record(&mut self) -> Option<&[u8]> {
        const HEADER: usize = 5;
        let avail = self.buf.len() - self.pos;
        if avail < HEADER {
            self.compact();
            return None;
        }
        let payload_len =
            u16::from_be_bytes([self.buf[self.pos + 3], self.buf[self.pos + 4]]) as usize;
        let total = HEADER + payload_len;
        if avail < total {
            self.compact();
            return None;
        }
        let start = self.pos;
        self.pos += total;
        Some(&self.buf[start..start + total])
    }

    /// Drop consumed bytes once (per refill cycle) so the buffer does not
    /// grow unboundedly.
    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// Read, decrypt and dispatch frames; a read/decrypt error kills the tunnel.
///
/// Reads are chunked and records are parsed from a [`RecordBuf`] — see its
/// docs for why the socket is never re-armed while complete records remain
/// buffered.
async fn reader_loop<R, F, Fut>(
    mut io: R,
    mut codec: PacketCodec,
    tunnel: Arc<Tunnel>,
    on_open: F,
) where
    R: AsyncRead + Unpin + Send + 'static,
    F: Fn(Arc<Tunnel>, u32, mpsc::Receiver<Vec<u8>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    // A killed tunnel must drop its read half too: dropping only the write
    // half (writer_loop) does NOT signal EOF to the peer — EOF arrives when
    // BOTH halves of tokio::io::split are dropped. Without this, a dead
    // tunnel keeps its socket open and the peer never notices.
    let mut dead = tunnel.dead_tx.subscribe();
    let mut records = RecordBuf::new();
    let mut chunk = vec![0u8; READ_BUF];
    // Consecutive bad records (AEAD failure or malformed mux frame). A short
    // streak (corrupted/duplicated records in flight) is tolerated — the
    // records are dropped, the tunnel lives; see MAX_CONSECUTIVE_BAD_RECORDS.
    let mut bad_streak = 0u32;
    'tunnel: loop {
        // See writer_loop: a kill before the first poll is invisible to
        // changed(), so check the current flag on every iteration.
        if *dead.borrow() {
            break;
        }
        // Dispatch every complete record already buffered.
        while let Some(record) = records.take_record() {
            let plain = match codec.decrypt_packet(record) {
                Ok(plain) => plain,
                Err(error) => {
                    bad_streak += 1;
                    log::debug!("dropping bad record ({error}); streak {bad_streak}");
                    if bad_streak >= MAX_CONSECUTIVE_BAD_RECORDS {
                        log::warn!(
                            "{bad_streak} consecutive bad records — killing the tunnel"
                        );
                        break 'tunnel;
                    }
                    continue;
                }
            };
            let frame = match Frame::decode(&plain) {
                Ok(frame) => frame,
                Err(error) => {
                    bad_streak += 1;
                    log::debug!("dropping malformed mux frame ({error}); streak {bad_streak}");
                    if bad_streak >= MAX_CONSECUTIVE_BAD_RECORDS {
                        log::warn!(
                            "{bad_streak} consecutive malformed frames — killing the tunnel"
                        );
                        break 'tunnel;
                    }
                    continue;
                }
            };
            bad_streak = 0;
            match frame {
                Frame::Open { stream } => {
                    // Register the inbound channel synchronously, BEFORE the
                    // next buffered record is dispatched: OPEN and the first
                    // DATA can arrive in the same read chunk, and the spawned
                    // on_open task will not have been polled yet — an
                    // unregistered stream would drop that DATA.
                    let (inbound_tx, inbound_rx) =
                        mpsc::channel::<Vec<u8>>(INBOUND_CAPACITY);
                    tunnel.registry.register(stream, inbound_tx).await;
                    tokio::spawn(on_open(tunnel.clone(), stream, inbound_rx));
                }
                Frame::Data { stream, payload } => {
                    if !tunnel.registry.deliver(stream, payload).await {
                        // Unknown, closed or stalled stream. Echo a CLOSE so
                        // a well-behaved peer stops sending (and its pump can
                        // finish); harmless for ids the peer also considers
                        // closed.
                        log::debug!("DATA for stream {stream} dropped — echoing CLOSE");
                        tunnel.handle().close(stream).await;
                    }
                }
                Frame::Close { stream } => {
                    tunnel.registry.remove(stream).await;
                }
                Frame::Ping { nonce } => {
                    let _ = tunnel
                        .handle
                        .frames
                        .send(Frame::Pong { nonce })
                        .await;
                }
                Frame::Pong { .. } => {
                    tunnel.pongs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Refill: one read drains whatever is available (never an exact-N
        // read that could park with records still buffered).
        let read = tokio::select! {
            r = io.read(&mut chunk) => r,
            _ = dead.changed() => {
                if *dead.borrow() {
                    break 'tunnel;
                }
                continue;
            }
        };
        match read {
            Ok(0) | Err(_) => break 'tunnel,
            Ok(n) => records.push(&chunk[..n]),
        }
    }
    tunnel.kill().await;
}

/// Periodic liveness probe: send PING, expect a PONG within
/// [`KEEPALIVE_GRACE`], otherwise the peer is silently dead — kill the
/// tunnel so the client redials. Worst-case detection:
/// `ping interval + KEEPALIVE_GRACE` (defaults 2s + 2s = 4s).
async fn keepalive_loop(tunnel: Arc<Tunnel>, ping_secs: u32) {
    let period = Duration::from_secs(ping_secs.max(1) as u64);
    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut dead = tunnel.dead_tx.subscribe();
    loop {
        // See writer_loop: a kill before the first poll is invisible to
        // changed(), so check the current flag on every iteration.
        if *dead.borrow() {
            break;
        }
        tokio::select! {
            _ = ticker.tick() => {
                let before = tunnel.pongs();
                if tunnel.handle.ping().await.is_err() {
                    break;
                }
                tokio::select! {
                    _ = sleep(KEEPALIVE_GRACE) => {
                        if tunnel.pongs() <= before {
                            log::warn!(
                                "keepalive: no PONG within {KEEPALIVE_GRACE:?} — killing tunnel"
                            );
                            tunnel.kill().await;
                            break;
                        }
                    }
                    _ = dead.changed() => {
                        if *dead.borrow() {
                            break;
                        }
                    }
                }
            }
            _ = dead.changed() => {
                if *dead.borrow() {
                    break;
                }
            }
        }
    }
}

// ── per-stream pump ─────────────────────────────────────────────────────────

/// A captured write-only FIN (half-close) handle for a tokio `TcpStream`.
///
/// tokio's `AsyncWriteExt::shutdown` on a `TcpStream` shuts down BOTH
/// directions, which would kill the read half and lose peer replies still in
/// flight; and an `into_std`/`from_std` round-trip on a live socket
/// deregisters it from the reactor, which can lose in-flight IOCP/epoll
/// events. Instead the raw socket handle is captured here (before the split —
/// the halves don't expose it) and the FIN is a direct `shutdown(SHUT_WR)`
/// syscall via socket2, bypassing the reactor entirely.
///
/// # Safety of the captured handle
/// The handle is valid while the pump owns the stream: `fin()` is called
/// before the split halves drop, so the socket is still open. The socket2
/// `Socket` is wrapped in `ManuallyDrop`, so it never closes the handle.
pub struct WriteFin {
    #[cfg(unix)]
    fd: std::os::fd::RawFd,
    #[cfg(windows)]
    handle: std::os::windows::io::RawSocket,
}

impl WriteFin {
    /// Capture the FIN handle of a still-unsplit tokio `TcpStream`.
    pub fn capture(stream: &tokio::net::TcpStream) -> Self {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Self {
                fd: stream.as_raw_fd(),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            Self {
                handle: stream.as_raw_socket(),
            }
        }
    }

    /// FIN the write direction only; the read direction keeps draining.
    ///
    /// A non-owning `std::net::TcpStream` is rebuilt from the captured raw
    /// handle (`ManuallyDrop` = the handle is never closed by it) and
    /// `shutdown(Shutdown::Write)` is a direct syscall — no reactor
    /// involvement, so no registration is touched and no in-flight event is
    /// lost.
    pub fn fin(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        unsafe {
            use std::os::fd::FromRawFd;
            let socket =
                std::mem::ManuallyDrop::new(std::net::TcpStream::from_raw_fd(self.fd));
            socket.shutdown(std::net::Shutdown::Write)
        }
        #[cfg(windows)]
        unsafe {
            use std::os::windows::io::FromRawSocket;
            let socket =
                std::mem::ManuallyDrop::new(std::net::TcpStream::from_raw_socket(self.handle));
            socket.shutdown(std::net::Shutdown::Write)
        }
    }
}

/// Bridge one local TCP socket onto one mux stream.
///
/// * uplink: local reads → DATA frames; local EOF/error → CLOSE (FIN);
/// * downlink: inbound chunks → local writes; peer CLOSE (inbound channel
///   closed) → FIN the local write side ONLY ([`WriteFin`]), preserving
///   half-close: the uplink keeps running so replies already in flight still
///   drain.
///
/// The pump ends when both directions are finished; the tunnel or the peer
/// closing the stream also terminates it.
pub async fn pump_stream(
    local: tokio::net::TcpStream,
    tunnel: Arc<Tunnel>,
    id: u32,
    mut inbound: mpsc::Receiver<Vec<u8>>,
) {
    // Write-only FIN handle, captured before the split (the halves don't
    // expose the socket). See [`WriteFin`] for why this is not tokio's
    // shutdown() or an into_std/from_std round-trip.
    let fin = WriteFin::capture(&local);
    let (mut local_read, mut local_write) = tokio::io::split(local);

    let up_tunnel = tunnel.clone();
    let up = async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up_tunnel.handle().send(id, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        up_tunnel.handle().close(id).await;
    };

    let down = async move {
        while let Some(chunk) = inbound.recv().await {
            // A local write stalled beyond STREAM_WRITE_TIMEOUT means the
            // consumer is dead (not merely slow): abandon the stream instead
            // of parking this pump forever.
            if matches!(
                timeout(STREAM_WRITE_TIMEOUT, local_write.write_all(&chunk)).await,
                Err(_) | Ok(Err(_))
            ) {
                log::debug!("stream {id}: local write stalled/failed — dropping stream");
                break;
            }
        }
        // Peer CLOSE: FIN our writes only; keep draining the read side.
        let _ = fin.fin();
    };

    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Two matched codec pairs over a duplex: side A tx ↔ side B rx and back.
    fn codec_pair() -> (PacketCodec, PacketCodec, PacketCodec, PacketCodec) {
        let a_to_b = [0x11u8; 32];
        let b_to_a = [0x22u8; 32];
        (
            PacketCodec::new(b_to_a), // A rx
            PacketCodec::new(a_to_b), // A tx
            PacketCodec::new(a_to_b), // B rx
            PacketCodec::new(b_to_a), // B tx
        )
    }

    async fn tunnel_pair(
        ping_secs: u32,
    ) -> (
        Arc<Tunnel>,
        Arc<Tunnel>,
        mpsc::Receiver<(u32, mpsc::Receiver<Vec<u8>>)>,
    ) {
        let (a_io, b_io) = tokio::io::duplex(64 * 1024);
        let (a_rx, a_tx, b_rx, b_tx) = codec_pair();
        // The "server" side (B) reports the reader-registered inbound channel.
        let (opened_tx, opened_rx) = mpsc::channel(16);
        let on_open = move |_tunnel: Arc<Tunnel>, id: u32, inbound: mpsc::Receiver<Vec<u8>>| {
            let opened_tx = opened_tx.clone();
            async move {
                let _ = opened_tx.send((id, inbound)).await;
            }
        };
        let a = spawn_tunnel(a_io, a_rx, a_tx, ping_secs, |_, id, _| async move {
            panic!("client side must never receive OPEN (got {id})");
        })
        .await;
        let b = spawn_tunnel(b_io, b_rx, b_tx, ping_secs, on_open).await;
        (a, b, opened_rx)
    }

    /// A server-like tunnel (B) over one duplex end whose far end (A) is
    /// RAW — the test writes A's records by hand (to corrupt / replay them).
    /// Returns (tunnel, opened-report channel, raw A stream, A→B codec).
    async fn server_tunnel_vs_raw(
        ping_secs: u32,
    ) -> (
        Arc<Tunnel>,
        mpsc::Receiver<(u32, mpsc::Receiver<Vec<u8>>)>,
        tokio::io::DuplexStream,
        PacketCodec,
    ) {
        let (raw, b_io) = tokio::io::duplex(256 * 1024);
        let (_a_rx_unused, a_tx, b_rx, b_tx) = codec_pair();
        let (opened_tx, opened_rx) = mpsc::channel(16);
        let on_open = move |_tunnel: Arc<Tunnel>, id: u32, inbound: mpsc::Receiver<Vec<u8>>| {
            let opened_tx = opened_tx.clone();
            async move {
                let _ = opened_tx.send((id, inbound)).await;
            }
        };
        let b = spawn_tunnel(b_io, b_rx, b_tx, ping_secs, on_open).await;
        (b, opened_rx, raw, a_tx)
    }

    /// Write one mux frame from the raw A side as an encrypted record.
    async fn write_frame(
        io: &mut tokio::io::DuplexStream,
        codec: &mut PacketCodec,
        frame: Frame,
    ) {
        let record = codec
            .encrypt_packet(&frame.encode(), &[])
            .expect("encrypt");
        io.write_all(&record).await.expect("write");
    }

    /// One encrypted record from the raw A side, returned for mangling.
    fn encrypt_frame(codec: &mut PacketCodec, frame: Frame) -> Vec<u8> {
        codec
            .encrypt_packet(&frame.encode(), &[])
            .expect("encrypt")
    }

    async fn wait_until<F, Fut>(limit: Duration, mut cond: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + limit;
        while tokio::time::Instant::now() < deadline {
            if cond().await {
                return true;
            }
            sleep(Duration::from_millis(10)).await;
        }
        cond().await
    }

    /// Bounded mpsc recv: a regression must fail fast, never hang the suite.
    async fn recv_deadlined<T>(rx: &mut mpsc::Receiver<T>) -> Option<T> {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(value) => value,
            Err(_) => panic!("test deadline exceeded waiting for a mux chunk"),
        }
    }

    #[tokio::test]
    async fn open_data_close_roundtrip_through_tunnel() {
        let (a, b, mut opened) = tunnel_pair(0).await;
        let id = a.handle().alloc_id();
        a.handle().open(id).await.expect("open");

        let (opened_id, mut inbound) =
            recv_deadlined(&mut opened).await.expect("OPEN delivered");
        assert_eq!(opened_id, id);
        assert_eq!(b.registry().len().await, 1);

        a.handle().send(id, b"hello over mux").await.expect("send");
        let chunk = recv_deadlined(&mut inbound).await.expect("DATA delivered");
        assert_eq!(chunk, b"hello over mux");

        // Large payload is chunked but delivered in order and complete.
        let big: Vec<u8> = (0..mux::MAX_DATA * 3 + 7).map(|i| (i % 251) as u8).collect();
        a.handle().send(id, &big).await.expect("send big");
        let mut got = Vec::new();
        while got.len() < big.len() {
            got.extend_from_slice(&recv_deadlined(&mut inbound).await.expect("more DATA"));
        }
        assert_eq!(got, big);

        a.handle().close(id).await;
        let b_for_poll = b.clone();
        assert!(
            wait_until(Duration::from_secs(3), || {
                let b = b_for_poll.clone();
                async move { b.registry().len().await == 0 }
            })
            .await,
            "registry must be empty after CLOSE"
        );
        // The pump's inbound channel is closed → recv returns None.
        assert!(recv_deadlined(&mut inbound).await.is_none());
    }

    #[tokio::test]
    async fn ping_pong_crosses_the_tunnel() {
        let (a, _b, _opened) = tunnel_pair(0).await;
        a.handle().ping().await.expect("ping");
        assert!(
            wait_until(Duration::from_secs(5), || async { a.pongs() >= 1 }).await,
            "a PONG must come back for the PING"
        );
    }

    #[tokio::test]
    async fn wire_death_closes_streams_and_marks_dead() {
        let (a, b, mut opened) = tunnel_pair(0).await;
        let id = a.handle().alloc_id();
        a.handle().open(id).await.expect("open");
        let (_opened_id, _inbound) =
            recv_deadlined(&mut opened).await.expect("OPEN delivered");

        // Kill the far side: both its socket halves drop → A's reader sees EOF
        // → A dies. Must happen promptly, not after the keepalive grace.
        b.kill().await;
        let a_for_poll = a.clone();
        assert!(
            wait_until(Duration::from_secs(3), || {
                let a = a_for_poll.clone();
                async move { a.is_dead() }
            })
            .await,
            "A must notice the peer's death"
        );
        assert!(a.registry().is_empty().await);
        assert!(
            a.handle().send(id, b"after death").await.is_err(),
            "sends on a dead tunnel must fail"
        );
    }

    #[tokio::test]
    async fn registry_deliver_unknown_stream_returns_false() {
        let registry = StreamRegistry::new();
        assert!(!registry.deliver(99, b"orphan".to_vec()).await);
        let (tx, mut rx) = mpsc::channel(4);
        assert!(registry.register(1, tx).await.is_none());
        assert!(registry.deliver(1, b"x".to_vec()).await);
        assert_eq!(rx.recv().await, Some(b"x".to_vec()));
        assert!(registry.remove(1).await.is_some());
        assert!(!registry.deliver(1, b"gone".to_vec()).await);
    }

    #[tokio::test]
    async fn keepalive_kills_silent_tunnel() {
        // B is killed: A must notice through the wire EOF (reader), not by
        // waiting for the keepalive grace period.
        let (a, b, _opened) = tunnel_pair(1).await;
        b.kill().await;
        assert!(
            wait_until(Duration::from_secs(3), || async { a.is_dead() }).await,
            "A must notice B's death"
        );
    }

    #[test]
    fn record_buf_takes_records_in_order_and_keeps_leftovers() {
        let mut rb = RecordBuf::new();
        // One complete record (payload len 3) + a partial next header.
        rb.push(&[0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3, 0x17, 0x03, 0x03, 0x00]);
        assert_eq!(
            rb.take_record().unwrap(),
            &[0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3]
        );
        assert_eq!(rb.take_record(), None, "header incomplete");
        rb.push(&[0x02]); // completes the header: payload len 2
        assert_eq!(rb.take_record(), None, "payload incomplete");
        rb.push(&[9, 9]);
        assert_eq!(
            rb.take_record().unwrap(),
            &[0x17, 0x03, 0x03, 0x00, 0x02, 9, 9]
        );
        assert_eq!(rb.take_record(), None);
        // And the buffer keeps working across refill cycles.
        rb.push(&[0x17, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(rb.take_record().unwrap(), &[0x17, 0x00, 0x00, 0x00, 0x00]);
    }

    #[tokio::test]
    async fn corrupted_record_is_tolerated_and_traffic_continues() {
        // One corrupted record in flight (a flipped AEAD tag byte — a
        // middlebox mangling one segment) must be DROPPED, not fatal: the
        // tunnel survives and subsequent data flows.
        let (b, mut opened, mut raw, mut a_tx) = server_tunnel_vs_raw(0).await;
        write_frame(&mut raw, &mut a_tx, Frame::Open { stream: 1 }).await;
        let (id, mut inbound) = recv_deadlined(&mut opened).await.expect("OPEN delivered");
        assert_eq!(id, 1);

        let mut bad = encrypt_frame(
            &mut a_tx,
            Frame::Data {
                stream: 1,
                payload: b"lost-in-transit".to_vec(),
            },
        );
        let last = bad.len() - 1;
        bad[last] ^= 0xFF; // corrupt the AEAD tag
        raw.write_all(&bad).await.expect("write corrupted");

        write_frame(
            &mut raw,
            &mut a_tx,
            Frame::Data {
                stream: 1,
                payload: b"survives".to_vec(),
            },
        )
        .await;
        let chunk = recv_deadlined(&mut inbound).await.expect("DATA after corruption");
        assert_eq!(chunk, b"survives");
        assert!(!b.is_dead(), "one corrupted record must not kill the tunnel");
    }

    #[tokio::test]
    async fn replayed_record_is_dropped_but_tunnel_survives() {
        // A duplicated record (the same bytes twice — a replayed segment)
        // is rejected by the AEAD replay window and DROPPED, not fatal.
        let (b, mut opened, mut raw, mut a_tx) = server_tunnel_vs_raw(0).await;
        write_frame(&mut raw, &mut a_tx, Frame::Open { stream: 1 }).await;
        let (_id, mut inbound) = recv_deadlined(&mut opened).await.expect("OPEN delivered");

        let once = encrypt_frame(
            &mut a_tx,
            Frame::Data {
                stream: 1,
                payload: b"once".to_vec(),
            },
        );
        raw.write_all(&once).await.expect("write");
        raw.write_all(&once).await.expect("write replay"); // the duplicate
        write_frame(
            &mut raw,
            &mut a_tx,
            Frame::Data {
                stream: 1,
                payload: b"twice".to_vec(),
            },
        )
        .await;

        assert_eq!(
            recv_deadlined(&mut inbound).await.expect("first DATA"),
            b"once"
        );
        assert_eq!(
            recv_deadlined(&mut inbound).await.expect("DATA after replay"),
            b"twice"
        );
        assert!(!b.is_dead(), "a replayed record must not kill the tunnel");
    }

    #[tokio::test]
    async fn persistent_corruption_kills_the_tunnel() {
        // Tolerance is bounded: a sustained run of bad records means the
        // stream is broken (or under active attack) — the tunnel must die.
        let (b, _opened, mut raw, mut a_tx) = server_tunnel_vs_raw(0).await;
        write_frame(&mut raw, &mut a_tx, Frame::Open { stream: 1 }).await;
        for _ in 0..(MAX_CONSECUTIVE_BAD_RECORDS + 2) {
            let mut bad = encrypt_frame(
                &mut a_tx,
                Frame::Data {
                    stream: 1,
                    payload: vec![0x41; 16],
                },
            );
            let last = bad.len() - 1;
            bad[last] ^= 0xFF;
            raw.write_all(&bad).await.expect("write corrupted");
        }
        assert!(
            wait_until(Duration::from_secs(3), || async { b.is_dead() }).await,
            "persistent corruption must kill the tunnel"
        );
    }

    #[tokio::test]
    async fn stalled_stream_consumer_is_dropped_without_freezing_the_tunnel() {
        // One stream's consumer never reads: its inbound channel fills and
        // the shared reader must NOT block on it forever (head-of-line
        // block). After STREAM_STALL_TIMEOUT the stream is dropped and the
        // tunnel keeps serving PINGs.
        let (a, b, mut opened) = tunnel_pair(0).await;
        let id = a.handle().alloc_id();
        a.handle().open(id).await.expect("open");
        let (_opened_id, _inbound_never_read) =
            recv_deadlined(&mut opened).await.expect("OPEN delivered");

        // Fill the per-stream channel (INBOUND_CAPACITY chunks) and keep
        // sending past it.
        for _ in 0..(INBOUND_CAPACITY as u32 + 8) {
            a.handle().send(id, b"stall").await.expect("send");
        }
        assert!(
            wait_until(STREAM_STALL_TIMEOUT + Duration::from_secs(3), || {
                let b = b.clone();
                async move { b.registry().len().await == 0 }
            })
            .await,
            "the stalled stream must be dropped from the registry"
        );
        assert!(!b.is_dead(), "the tunnel itself must survive");

        // No head-of-line freeze: the tunnel still answers PINGs.
        a.handle().ping().await.expect("ping");
        assert!(
            wait_until(Duration::from_secs(3), || async { a.pongs() >= 1 }).await,
            "a PONG must come back after the stalled stream was dropped"
        );
    }

    #[tokio::test]
    async fn keepalive_kills_a_silent_peer_within_the_bound() {
        // The far end accepts the connection and keeps the socket open but
        // never answers (a frozen process). Detection must happen within
        // ping (1s) + KEEPALIVE_GRACE (2s) ≈ 3s — hard bound 5s.
        let (raw, a_io) = tokio::io::duplex(64 * 1024);
        let (a_rx, a_tx, _b_rx, _b_tx) = codec_pair();
        let a = spawn_tunnel(a_io, a_rx, a_tx, 1, |_, id, _| async move {
            panic!("no OPEN expected in this test (got {id})");
        })
        .await;
        // Drain the wire but never answer — a silent-but-connected peer.
        tokio::spawn(async move {
            let mut raw = raw;
            let mut buf = [0u8; 4096];
            loop {
                match raw.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let start = tokio::time::Instant::now();
        assert!(
            wait_until(Duration::from_secs(5), || async { a.is_dead() }).await,
            "a silent peer must be detected by keepalive"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "dead-tunnel detection took {:?} — must be ≤5s",
            start.elapsed()
        );
    }
}
