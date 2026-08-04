//! Video datagram path: hand-rolled fragment header + reassembly contract.
//!
//! Layout (14 bytes, little-endian, fixed — NOT postcard, hot path):
//! ```text
//! offset size field
//! 0      4    frame_id     (u32, wraps)
//! 4      2    frag_index   (u16)      DATA: fragment index; PARITY: block index
//! 6      2    frag_count   (u16, >= 1) number of DATA fragments (N)
//! 8      1    flags        (bit0 = keyframe, bit1 = parity)
//! 9      1    block_size   (K, FEC block size; 0 = no FEC)
//! 10     4    DATA: timestamp_ms (u32); PARITY: last_frag_len (u16) then 0 (u16)
//! ```
//! Payload follows immediately. Max datagram payload is negotiated from the
//! QUIC max_datagram_size; fragments must never exceed it.
//!
//! # Forward error correction
//!
//! Video frames are fragmented into unreliable QUIC datagrams; losing a single
//! fragment otherwise discards the whole frame and forces a keyframe stall. With
//! FEC the sender groups the `N` data fragments into blocks of `K` and appends
//! one XOR-parity fragment per block, letting the receiver reconstruct a single
//! lost data fragment per block with no stall. Parity fragments repurpose the
//! timestamp field to carry `last_frag_len` — the byte length of the frame's
//! final (short) data fragment — which recovery needs to trim a reconstructed
//! last fragment back to its true size.

use crate::error::{Error, Result};

pub const FRAG_HEADER_LEN: usize = 14;
pub const FLAG_KEYFRAME: u8 = 0b0000_0001;
/// Set on parity fragments; clear on data fragments.
pub const FLAG_PARITY: u8 = 0b0000_0010;
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
    /// True on parity fragments: `frag_index` is a block index and the
    /// timestamp field carries `last_frag_len` instead of a capture time.
    pub parity: bool,
    /// FEC block size K (0 = no FEC). Present on both data and parity headers.
    pub block_size: u8,
    /// Parity only: byte length of the frame's final (short) data fragment.
    /// Zero on data fragments.
    pub last_frag_len: u16,
    pub timestamp_ms: u32,
}

impl FragHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.frame_id.to_le_bytes());
        out.extend_from_slice(&self.frag_index.to_le_bytes());
        out.extend_from_slice(&self.frag_count.to_le_bytes());
        let mut flags = 0u8;
        if self.keyframe {
            flags |= FLAG_KEYFRAME;
        }
        if self.parity {
            flags |= FLAG_PARITY;
        }
        out.push(flags);
        out.push(self.block_size);
        if self.parity {
            // Repurposed timestamp field: last_frag_len then a zero pad.
            out.extend_from_slice(&self.last_frag_len.to_le_bytes());
            out.extend_from_slice(&[0, 0]);
        } else {
            out.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        }
    }

    pub fn decode(buf: &[u8]) -> Result<(FragHeader, &[u8])> {
        if buf.len() < FRAG_HEADER_LEN {
            return Err(Error::Invalid("fragment shorter than header".into()));
        }
        let frame_id = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let frag_index = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        let frag_count = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        let flags = buf[8];
        let block_size = buf[9];

        if flags & !(FLAG_KEYFRAME | FLAG_PARITY) != 0 {
            return Err(Error::Invalid(format!("unknown flags {flags:#x}")));
        }
        if frag_count == 0 || frag_count > MAX_FRAGS_PER_FRAME {
            return Err(Error::Invalid(format!("bad frag_count {frag_count}")));
        }
        let keyframe = flags & FLAG_KEYFRAME != 0;
        let parity = flags & FLAG_PARITY != 0;

        let (timestamp_ms, last_frag_len) = if parity {
            // Parity fragment: `frag_index` is a block index in
            // `0..num_blocks`, and the timestamp field is repurposed to carry
            // `last_frag_len`. A parity fragment without a block size is
            // meaningless.
            if block_size < 1 {
                return Err(Error::Invalid("parity fragment with zero block_size".into()));
            }
            let last_frag_len = u16::from_le_bytes(buf[10..12].try_into().unwrap());
            let num_blocks = frag_count.div_ceil(block_size as u16);
            if frag_index >= num_blocks {
                return Err(Error::Invalid(format!(
                    "parity block {frag_index} >= num_blocks {num_blocks}"
                )));
            }
            (0, last_frag_len)
        } else {
            // Data fragment: `frag_index` addresses one of `frag_count` pieces
            // and the timestamp field is the real capture time.
            if frag_index >= frag_count {
                return Err(Error::Invalid(format!(
                    "frag_index {frag_index} >= frag_count {frag_count}"
                )));
            }
            (u32::from_le_bytes(buf[10..14].try_into().unwrap()), 0)
        };

        let payload = &buf[FRAG_HEADER_LEN..];
        if payload.is_empty() {
            return Err(Error::Invalid("empty fragment payload".into()));
        }
        Ok((
            FragHeader {
                frame_id,
                frag_index,
                frag_count,
                keyframe,
                parity,
                block_size,
                last_frag_len,
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
            parity: false,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: frame.timestamp_ms,
        }
        .encode(&mut dgram);
        dgram.extend_from_slice(piece);
        out.push(dgram);
    }
    Ok(out)
}

/// Split one encoded frame into datagram-sized fragments **with XOR parity**.
///
/// The data fragments are identical to [`fragment_frame`]'s (same chunking,
/// same caps) except each carries `block_size` in its header so the receiver
/// knows K without a side channel. The `N` data fragments are then grouped into
/// blocks of `K`, and one parity fragment per block is appended after all the
/// data fragments: its payload is the byte-wise XOR of the block's data
/// payloads (each padded to the full chunk width), letting the receiver rebuild
/// a single lost data fragment per block.
///
/// With `block_size == 0` or a single data fragment there is nothing a parity
/// block could recover, so only the data fragments are returned.
pub fn fragment_frame_fec(
    frame: &EncodedFrame,
    max_datagram: usize,
    block_size: u8,
) -> Result<Vec<Vec<u8>>> {
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
    // The last data fragment is the only short one; its length is what recovery
    // needs to trim a reconstructed final fragment back to size.
    let last_frag_len = (frame.data.len() - (count - 1) * chunk) as u16;

    let mut out = Vec::with_capacity(count);
    for (i, piece) in frame.data.chunks(chunk).enumerate() {
        let mut dgram = Vec::with_capacity(FRAG_HEADER_LEN + piece.len());
        FragHeader {
            frame_id: frame.frame_id,
            frag_index: i as u16,
            frag_count: count as u16,
            keyframe: frame.keyframe,
            parity: false,
            block_size,
            last_frag_len: 0,
            timestamp_ms: frame.timestamp_ms,
        }
        .encode(&mut dgram);
        dgram.extend_from_slice(piece);
        out.push(dgram);
    }

    // No FEC requested, or a lone data fragment: parity would be pure overhead.
    if block_size == 0 || count <= 1 {
        return Ok(out);
    }

    let k = block_size as usize;
    let num_blocks = count.div_ceil(k);
    for b in 0..num_blocks {
        let lo = b * k;
        let hi = ((b + 1) * k).min(count);
        // XOR every data payload in the block into a chunk-wide buffer. A short
        // (final) fragment contributes only its own bytes; the remaining bytes
        // stay as the XOR of the full-width pieces.
        let mut parity_payload = vec![0u8; chunk];
        for i in lo..hi {
            let piece = &frame.data[i * chunk..((i + 1) * chunk).min(frame.data.len())];
            for (j, &byte) in piece.iter().enumerate() {
                parity_payload[j] ^= byte;
            }
        }
        let mut dgram = Vec::with_capacity(FRAG_HEADER_LEN + chunk);
        FragHeader {
            frame_id: frame.frame_id,
            frag_index: b as u16,
            frag_count: count as u16,
            keyframe: frame.keyframe,
            parity: true,
            block_size,
            last_frag_len,
            timestamp_ms: 0,
        }
        .encode(&mut dgram);
        dgram.extend_from_slice(&parity_payload);
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
            parity: false,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 99,
        };
        h.encode(&mut buf);
        buf.push(0xFF); // one payload byte
        let (back, payload) = FragHeader::decode(&buf).unwrap();
        assert_eq!(h, back);
        assert_eq!(payload, &[0xFF]);
    }

    #[test]
    fn parity_header_roundtrip() {
        let mut buf = Vec::new();
        // Block index 1 of a 5-fragment frame with K=4 → num_blocks 2, so
        // block index 1 is in range. The timestamp field carries last_frag_len.
        let h = FragHeader {
            frame_id: 7,
            frag_index: 1,
            frag_count: 5,
            keyframe: false,
            parity: true,
            block_size: 4,
            last_frag_len: 321,
            timestamp_ms: 0,
        };
        h.encode(&mut buf);
        buf.push(0xFF);
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
            parity: false,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 0,
        }
        .encode(&mut buf);
        buf.push(0);
        assert!(FragHeader::decode(&buf).is_err());
        // short buffer
        assert!(FragHeader::decode(&[0u8; 5]).is_err());
        // parity block index out of range: K=4, N=5 → 2 blocks, block 2 invalid.
        let mut bad_parity = Vec::new();
        FragHeader {
            frame_id: 1,
            frag_index: 2,
            frag_count: 5,
            keyframe: false,
            parity: true,
            block_size: 4,
            last_frag_len: 1,
            timestamp_ms: 0,
        }
        .encode(&mut bad_parity);
        bad_parity.push(0);
        assert!(FragHeader::decode(&bad_parity).is_err());
    }

    #[test]
    fn fragment_frame_fec_round_trips_and_parity_is_consistent() {
        // A frame large enough for several fragments and, with K=4, >= 2 blocks.
        let frame = mk(10_000);
        let mtu = 1200;
        let k = 4u8;
        let frags = fragment_frame_fec(&frame, mtu, k).unwrap();

        let chunk = mtu - FRAG_HEADER_LEN;
        let n = frame.data.len().div_ceil(chunk);
        let num_blocks = n.div_ceil(k as usize);
        assert!(num_blocks >= 2, "want a multi-block frame");
        // N data fragments then num_blocks parity fragments.
        assert_eq!(frags.len(), n + num_blocks);
        assert!(frags.iter().all(|f| f.len() <= mtu));

        // Data payloads, in index order, reconstruct the frame exactly.
        let mut data_payloads: Vec<Vec<u8>> = vec![Vec::new(); n];
        let mut parity: Vec<(usize, Vec<u8>)> = Vec::new();
        for f in &frags {
            let (h, payload) = FragHeader::decode(f).unwrap();
            assert_eq!(h.frame_id, frame.frame_id);
            assert_eq!(h.frag_count as usize, n);
            assert_eq!(h.block_size, k);
            if h.parity {
                assert_eq!(h.last_frag_len as usize, frame.data.len() - (n - 1) * chunk);
                parity.push((h.frag_index as usize, payload.to_vec()));
            } else {
                data_payloads[h.frag_index as usize] = payload.to_vec();
            }
        }
        let rebuilt: Vec<u8> = data_payloads.concat();
        assert_eq!(rebuilt, frame.data);

        // Each block's parity XORed with its data (padded to chunk) is zeros.
        for (b, par) in parity {
            let lo = b * k as usize;
            let hi = ((b + 1) * k as usize).min(n);
            let mut acc = par.clone();
            for i in lo..hi {
                for (j, &byte) in data_payloads[i].iter().enumerate() {
                    acc[j] ^= byte;
                }
            }
            assert!(acc.iter().all(|&x| x == 0), "block {b} parity mismatch");
        }
    }

    #[test]
    fn fragment_frame_fec_without_fec_returns_data_only() {
        let frame = mk(10_000);
        // K=0 and single-fragment frames both skip parity entirely.
        let no_k = fragment_frame_fec(&frame, 1200, 0).unwrap();
        assert!(no_k.iter().all(|f| !FragHeader::decode(f).unwrap().0.parity));
        let tiny = fragment_frame_fec(&mk(50), 1200, 10).unwrap();
        assert_eq!(tiny.len(), 1);
        assert!(!FragHeader::decode(&tiny[0]).unwrap().0.parity);
    }
}
