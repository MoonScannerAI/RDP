//! Video datagram path: hand-rolled fragment header + reassembly contract.
//!
//! Layout (14 bytes, little-endian, fixed — NOT postcard, hot path):
//! ```text
//! offset size field
//! 0      4    frame_id     (u32, wraps)
//! 4      2    frag_index   (u16)
//! 6      2    frag_count   (u16, >= 1)
//! 8      1    flags        (bit0 = keyframe)
//! 9      1    reserved     (must be 0)
//! 10     4    timestamp_ms (u32, sender monotonic, wraps)
//! ```
//! Payload follows immediately. Max datagram payload is negotiated from the
//! QUIC max_datagram_size; fragments must never exceed it.

use crate::error::{Error, Result};

pub const FRAG_HEADER_LEN: usize = 14;
pub const FLAG_KEYFRAME: u8 = 0b0000_0001;
/// Sanity cap: no encoded frame may exceed this many fragments.
pub const MAX_FRAGS_PER_FRAME: u16 = 512;
/// Sanity cap on a single reassembled frame (2 MiB is generous for 1080p H.264).
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragHeader {
    pub frame_id: u32,
    pub frag_index: u16,
    pub frag_count: u16,
    pub keyframe: bool,
    pub timestamp_ms: u32,
}

impl FragHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.frame_id.to_le_bytes());
        out.extend_from_slice(&self.frag_index.to_le_bytes());
        out.extend_from_slice(&self.frag_count.to_le_bytes());
        out.push(if self.keyframe { FLAG_KEYFRAME } else { 0 });
        out.push(0);
        out.extend_from_slice(&self.timestamp_ms.to_le_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<(FragHeader, &[u8])> {
        if buf.len() < FRAG_HEADER_LEN {
            return Err(Error::Invalid("fragment shorter than header".into()));
        }
        let frame_id = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let frag_index = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        let frag_count = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        let flags = buf[8];
        let reserved = buf[9];
        let timestamp_ms = u32::from_le_bytes(buf[10..14].try_into().unwrap());

        if frag_count == 0 || frag_count > MAX_FRAGS_PER_FRAME {
            return Err(Error::Invalid(format!("bad frag_count {frag_count}")));
        }
        if frag_index >= frag_count {
            return Err(Error::Invalid(format!(
                "frag_index {frag_index} >= frag_count {frag_count}"
            )));
        }
        if reserved != 0 {
            return Err(Error::Invalid("reserved byte not zero".into()));
        }
        if flags & !FLAG_KEYFRAME != 0 {
            return Err(Error::Invalid(format!("unknown flags {flags:#x}")));
        }
        let payload = &buf[FRAG_HEADER_LEN..];
        if payload.is_empty() {
            return Err(Error::Invalid("empty fragment payload".into()));
        }
        Ok((
            FragHeader {
                frame_id,
                frag_index,
                frag_count,
                keyframe: flags & FLAG_KEYFRAME != 0,
                timestamp_ms,
            },
            payload,
        ))
    }
}

/// A fully reassembled encoded frame ready for the decoder.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub timestamp_ms: u32,
    pub data: Vec<u8>,
}

/// Split one encoded frame into datagram-sized fragments.
/// `max_datagram` is the transport's current max datagram size.
pub fn fragment_frame(frame: &EncodedFrame, max_datagram: usize) -> Result<Vec<Vec<u8>>> {
    if frame.data.is_empty() {
        return Err(Error::Invalid("empty frame".into()));
    }
    if frame.data.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized {
            got: frame.data.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    let chunk = max_datagram
        .checked_sub(FRAG_HEADER_LEN)
        .ok_or_else(|| Error::Invalid("max_datagram smaller than header".into()))?;
    if chunk == 0 {
        return Err(Error::Invalid("max_datagram too small".into()));
    }
    let count = frame.data.len().div_ceil(chunk);
    if count > MAX_FRAGS_PER_FRAME as usize {
        return Err(Error::Oversized {
            got: count,
            limit: MAX_FRAGS_PER_FRAME as usize,
        });
    }
    let mut out = Vec::with_capacity(count);
    for (i, piece) in frame.data.chunks(chunk).enumerate() {
        let mut dgram = Vec::with_capacity(FRAG_HEADER_LEN + piece.len());
        FragHeader {
            frame_id: frame.frame_id,
            frag_index: i as u16,
            frag_count: count as u16,
            keyframe: frame.keyframe,
            timestamp_ms: frame.timestamp_ms,
        }
        .encode(&mut dgram);
        dgram.extend_from_slice(piece);
        out.push(dgram);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(len: usize) -> EncodedFrame {
        EncodedFrame {
            frame_id: 7,
            keyframe: true,
            timestamp_ms: 1234,
            data: vec![0xAB; len],
        }
    }

    #[test]
    fn header_roundtrip() {
        let mut buf = Vec::new();
        let h = FragHeader {
            frame_id: 1,
            frag_index: 2,
            frag_count: 5,
            keyframe: true,
            timestamp_ms: 99,
        };
        h.encode(&mut buf);
        buf.push(0xFF); // one payload byte
        let (back, payload) = FragHeader::decode(&buf).unwrap();
        assert_eq!(h, back);
        assert_eq!(payload, &[0xFF]);
    }

    #[test]
    fn fragment_then_sizes_ok() {
        let frame = mk(3000);
        let frags = fragment_frame(&frame, 1200).unwrap();
        assert!(frags.iter().all(|f| f.len() <= 1200));
        let total: usize = frags.iter().map(|f| f.len() - FRAG_HEADER_LEN).sum();
        assert_eq!(total, 3000);
    }

    #[test]
    fn rejects_bad_headers() {
        // frag_index >= frag_count
        let mut buf = Vec::new();
        FragHeader {
            frame_id: 1,
            frag_index: 5,
            frag_count: 5,
            keyframe: false,
            timestamp_ms: 0,
        }
        .encode(&mut buf);
        buf.push(0);
        assert!(FragHeader::decode(&buf).is_err());
        // short buffer
        assert!(FragHeader::decode(&[0u8; 5]).is_err());
    }
}
