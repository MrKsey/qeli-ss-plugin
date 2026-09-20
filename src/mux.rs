//! Stream multiplexer framing carried inside qeli AEAD records.
//!
//! One frame per AEAD record. Frame layout (plaintext, before encryption):
//!
//! ```text
//! type(1) || stream_id(4, BE) || payload_len(2, BE) || payload
//! ```
//!
//! Frame types:
//! * `OPEN`  — the sender opened stream `id` (payload must be empty);
//! * `DATA`  — a payload chunk for stream `id`;
//! * `CLOSE` — the sender finished sending on stream `id` (FIN, payload empty);
//! * `PING`/`PONG` — tunnel keepalive (8 random bytes echoed back).
//!
//! The server never opens streams, so an `OPEN` received by the client side is
//! a protocol violation (logged and ignored by the carrier).

use thiserror::Error;

/// Frame header size: type(1) + stream_id(4) + payload_len(2).
pub const FRAME_HEADER: usize = 7;

/// Maximum DATA payload per frame.
///
/// One AEAD record is `[5-byte TLS header][12-byte nonce][counter(8) + frame
/// plaintext + padding_len(2)][16-byte tag]` and qeli caps the whole record at
/// 16672 bytes, so a 16384-byte DATA payload leaves ample headroom.
pub const MAX_DATA: usize = 16384;

pub const TYPE_OPEN: u8 = 1;
pub const TYPE_DATA: u8 = 2;
pub const TYPE_CLOSE: u8 = 3;
pub const TYPE_PING: u8 = 4;
pub const TYPE_PONG: u8 = 5;

/// PING/PONG carry exactly 8 random bytes.
pub const KEEPALIVE_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Open { stream: u32 },
    Data { stream: u32, payload: Vec<u8> },
    Close { stream: u32 },
    Ping { nonce: [u8; KEEPALIVE_LEN] },
    Pong { nonce: [u8; KEEPALIVE_LEN] },
}

impl Frame {
    /// The wire type byte of this frame.
    pub fn frame_type(&self) -> u8 {
        match self {
            Frame::Open { .. } => TYPE_OPEN,
            Frame::Data { .. } => TYPE_DATA,
            Frame::Close { .. } => TYPE_CLOSE,
            Frame::Ping { .. } => TYPE_PING,
            Frame::Pong { .. } => TYPE_PONG,
        }
    }

    /// The stream id this frame addresses (0 for PING/PONG).
    pub fn stream(&self) -> u32 {
        match self {
            Frame::Open { stream } | Frame::Data { stream, .. } | Frame::Close { stream } => {
                *stream
            }
            Frame::Ping { .. } | Frame::Pong { .. } => 0,
        }
    }

    /// Encode into caller-owned storage (cleared first; capacity retained).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        let payload = match self {
            Frame::Open { .. } | Frame::Close { .. } => &[][..],
            Frame::Data { payload, .. } => payload.as_slice(),
            Frame::Ping { nonce } | Frame::Pong { nonce } => nonce.as_slice(),
        };
        out.reserve(FRAME_HEADER + payload.len());
        out.push(self.frame_type());
        out.extend_from_slice(&self.stream().to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }

    /// Allocating convenience wrapper.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Decode one complete frame. Errors on any malformed input — a decode
    /// failure inside the carrier kills the tunnel (the AEAD already passed,
    /// so this is a peer bug, not an attack).
    pub fn decode(buf: &[u8]) -> Result<Frame, MuxError> {
        if buf.len() < FRAME_HEADER {
            return Err(MuxError::TooShort(buf.len()));
        }
        let frame_type = buf[0];
        let stream = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let payload_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        let payload = &buf[FRAME_HEADER..];
        if payload.len() != payload_len {
            return Err(MuxError::Truncated(payload_len, payload.len()));
        }
        match frame_type {
            TYPE_OPEN | TYPE_CLOSE => {
                if payload_len != 0 {
                    return Err(MuxError::EmptyPayloadRequired(frame_type));
                }
                if frame_type == TYPE_OPEN {
                    Ok(Frame::Open { stream })
                } else {
                    Ok(Frame::Close { stream })
                }
            }
            TYPE_DATA => {
                if payload_len > MAX_DATA {
                    return Err(MuxError::PayloadTooLarge(payload_len, MAX_DATA));
                }
                Ok(Frame::Data {
                    stream,
                    payload: payload.to_vec(),
                })
            }
            TYPE_PING | TYPE_PONG => {
                let nonce: [u8; KEEPALIVE_LEN] =
                    payload.try_into().map_err(|_| MuxError::BadKeepalive(payload_len))?;
                if frame_type == TYPE_PING {
                    Ok(Frame::Ping { nonce })
                } else {
                    Ok(Frame::Pong { nonce })
                }
            }
            other => Err(MuxError::UnknownType(other)),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuxError {
    #[error("frame too short: {0} bytes")]
    TooShort(usize),
    #[error("unknown frame type {0:#04x}")]
    UnknownType(u8),
    #[error("declared payload length {0} exceeds the {1}-byte cap")]
    PayloadTooLarge(usize, usize),
    #[error("truncated frame: header declares {0} payload bytes, got {1}")]
    Truncated(usize, usize),
    #[error("frame type {0:#04x} must carry an empty payload")]
    EmptyPayloadRequired(u8),
    #[error("PING/PONG payload must be exactly {KEEPALIVE_LEN} bytes, got {0}")]
    BadKeepalive(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_frame_types() {
        let frames = vec![
            Frame::Open { stream: 1 },
            Frame::Data {
                stream: 1,
                payload: b"hello shadowsocks".to_vec(),
            },
            Frame::Data {
                stream: 0xdead_beef,
                payload: Vec::new(),
            },
            Frame::Close { stream: 1 },
            Frame::Ping {
                nonce: [7; KEEPALIVE_LEN],
            },
            Frame::Pong {
                nonce: [9; KEEPALIVE_LEN],
            },
        ];
        for frame in frames {
            let decoded = Frame::decode(&frame.encode()).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn roundtrip_max_size_data() {
        let frame = Frame::Data {
            stream: 42,
            payload: vec![0xAB; MAX_DATA],
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), FRAME_HEADER + MAX_DATA);
        assert_eq!(Frame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn encode_into_reuses_capacity() {
        let mut buf = Vec::new();
        Frame::Data {
            stream: 1,
            payload: vec![1; 1024],
        }
        .encode_into(&mut buf);
        let cap = buf.capacity();
        Frame::Close { stream: 2 }.encode_into(&mut buf);
        assert_eq!(buf, Frame::Close { stream: 2 }.encode());
        assert_eq!(buf.capacity(), cap, "capacity must be retained, not regrown");
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(
            Frame::decode(&[TYPE_OPEN, 0, 0, 0, 1, 0]),
            Err(MuxError::TooShort(6))
        );
        assert_eq!(Frame::decode(&[]), Err(MuxError::TooShort(0)));
    }

    #[test]
    fn rejects_unknown_type() {
        let mut buf = Frame::Open { stream: 1 }.encode();
        buf[0] = 0xFF;
        assert_eq!(Frame::decode(&buf), Err(MuxError::UnknownType(0xFF)));
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut buf = Frame::Data {
            stream: 1,
            payload: b"abc".to_vec(),
        }
        .encode();
        buf.truncate(buf.len() - 1);
        assert_eq!(Frame::decode(&buf), Err(MuxError::Truncated(3, 2)));
    }

    #[test]
    fn rejects_oversized_declared_payload() {
        // Hand-craft a header declaring MAX_DATA + 1 payload bytes.
        let mut buf = vec![TYPE_DATA, 0, 0, 0, 1];
        buf.extend_from_slice(&((MAX_DATA + 1) as u16).to_be_bytes());
        buf.extend_from_slice(&[0u8; MAX_DATA + 1]);
        assert_eq!(
            Frame::decode(&buf),
            Err(MuxError::PayloadTooLarge(MAX_DATA + 1, MAX_DATA))
        );
    }

    #[test]
    fn rejects_open_with_payload() {
        let mut buf = vec![TYPE_OPEN, 0, 0, 0, 1, 0, 2, 0xAA, 0xBB];
        buf[0] = TYPE_OPEN;
        assert_eq!(
            Frame::decode(&buf),
            Err(MuxError::EmptyPayloadRequired(TYPE_OPEN))
        );
    }

    #[test]
    fn rejects_close_with_payload() {
        let buf = vec![TYPE_CLOSE, 0, 0, 0, 1, 0, 1, 0xAA];
        assert_eq!(
            Frame::decode(&buf),
            Err(MuxError::EmptyPayloadRequired(TYPE_CLOSE))
        );
    }

    #[test]
    fn rejects_ping_with_wrong_payload_len() {
        let buf = vec![TYPE_PING, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4];
        assert_eq!(Frame::decode(&buf), Err(MuxError::BadKeepalive(4)));
    }

    #[test]
    fn header_layout_is_stable() {
        // type || stream(BE32) || len(BE16): pin the wire format explicitly.
        let buf = Frame::Data {
            stream: 0x0102_0304,
            payload: b"xy".to_vec(),
        }
        .encode();
        assert_eq!(
            buf,
            vec![TYPE_DATA, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02, b'x', b'y']
        );
    }
}
