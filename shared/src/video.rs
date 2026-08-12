//! Video datagram path: hand-rolled fragment header + reassembly contract.
//!
//! Layout (14 bytes, little-endian, fixed — NOT postcard, hot path):
//! ```text
//! offset size field
//! 0      4    frame_id     (u32, wraps)
//! 4      2    frag_index   (u16)      DATA: fragment index; PARITY: block index
//! 6      2    frag_count   (u16, >= 1) number of DATA fragments (N)
//! 8      1    flags        (bit0 = keyframe, bit1 = parity, bit2 = AUDIO —
//!                          never set by this module, and rejected on decode;
//!                          see [`FLAG_AUDIO`] and [`crate::audio`] —
//!                          bit3 = stream 1, see [`FLAG_STREAM1`])
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
/// Byte offset of the flags field in a fragment header.
///
/// Named rather than spelled `8` inline because [`crate::audio`] pins its own
/// flags byte to the same offset, with a `const` assertion that the two agree.
/// That shared offset is what lets the datagram demux be a single byte compare
/// against a slice of unknown provenance, before any header is parsed.
pub const FRAG_FLAGS_OFFSET: usize = 8;
pub const FLAG_KEYFRAME: u8 = 0b0000_0001;
/// Set on parity fragments; clear on data fragments.
pub const FLAG_PARITY: u8 = 0b0000_0010;
/// Marks a datagram as AUDIO, not a video fragment.
///
/// It lives in the *video* flag space, at the video flags offset, because that
/// is the only way one byte can separate the two kinds of media datagram: see
/// [`crate::audio`] for the demux itself. Nothing in this module ever sets it —
/// [`FragHeader::encode`] writes only [`FLAG_KEYFRAME`], [`FLAG_PARITY`] and
/// [`FLAG_STREAM1`] — and, more importantly:
///
/// **[`FragHeader::decode`]'s allowed mask is
/// `!(FLAG_KEYFRAME | FLAG_PARITY | FLAG_STREAM1)`, and this bit must stay
/// OUTSIDE it: decode must go on REJECTING `FLAG_AUDIO`.**
/// Widening the mask to tolerate `FLAG_AUDIO` looks like harmless forward
/// compatibility and is not. That rejection is the backstop that keeps an audio
/// datagram from ever reaching the reassembler's `accept_frame_id`: an audio
/// packet's bytes 0..4 are a *sequence number*, which is a completely unrelated
/// number line from the video `frame_id`, so eight consecutive audio datagrams
/// leaking into the video path would look like eight consecutive out-of-window
/// frame ids that agree with each other — precisely the signature of a
/// legitimate encoder renumbering. The reassembler would then call
/// `adopt_numbering`, which clears every live slot and every ready frame and
/// demands a keyframe. The visible symptom is a video stall with no error, on a
/// session whose only fault was that audio and video share a datagram path.
///
/// The mask *has* been widened once since this was written — for
/// [`FLAG_STREAM1`], the second monitor's tag — so "it grew before" will be
/// available as an argument and is not one. That bit is a value this module
/// itself writes and reads, on datagrams that are already video. This bit
/// announces a different format with a different meaning for every byte after
/// it, and tolerating it is how those bytes get read as video.
///
/// `is_audio_datagram` is the routing decision; this rejection is the safety
/// net for the day some future caller forgets to consult it. Keep both.
/// `video_decode_still_rejects_the_audio_flag` in the tests below pins it.
pub const FLAG_AUDIO: u8 = 0b0000_0100;
/// Marks a video fragment as belonging to **stream 1** — the second monitor.
///
/// Absence of the bit means stream 0, which is what every fragment a
/// single-monitor session has ever sent looks like: this is the whole reason
/// the second stream is a flag rather than a new header field. Widening
/// [`FRAG_HEADER_LEN`] would change where the payload starts for every peer,
/// deployed or not; spending a spare flag bit costs nothing and leaves stream
/// 0's bytes untouched.
///
/// Like [`FLAG_AUDIO`], it is peeked at [`FRAG_FLAGS_OFFSET`] by the session's
/// datagram demux *before* anything is parsed — see [`datagram_stream_id`] —
/// because the receiver has to pick which reassembler a datagram belongs to
/// before it has a header to consult. Sharing that one byte with the audio
/// demux is what keeps routing a single compare against a slice of unknown
/// provenance.
///
/// A new host sets it only once [`crate::protocol::features::MULTI_MONITOR`]
/// came back mutual, which is the same one-sided safety `FLAG_AUDIO` relies on
/// and is worth being precise about. An old peer handed a stream-1 fragment
/// rejects it in [`FragHeader::decode`] as an unknown flag: warn and drop,
/// non-fatal, one dropped datagram. That is *survivable* — but survivable is
/// not the guarantee. "Never sent unless negotiated" is, because a steady
/// stream of warn-and-drop fragments is an invisible second monitor plus a
/// flooded log, not a clean degradation.
///
/// One deliberate overlap to know about: this is bit 3, the same bit
/// [`crate::audio::FLAG_DISCONTINUITY`] uses in the same byte at the same
/// offset. They cannot be confused because [`FLAG_AUDIO`] is what discriminates
/// the two formats first — an audio packet always sets bit 2 and so never
/// reaches this module's decode, and a video fragment never sets bit 2 and so
/// never reaches the audio parser. The flag *space* is shared; the flag
/// *meanings* are per-format, and reading bit 3 without having settled which
/// format you hold is the mistake to avoid.
pub const FLAG_STREAM1: u8 = 0b0000_1000;
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
    /// Which video stream this fragment belongs to: `0` (the primary output,
    /// and everything a single-monitor session sends) or `1` (the second
    /// monitor). Carried as [`FLAG_STREAM1`] in the flags byte, so `0` encodes
    /// byte-identically to a pre-multi-monitor header. Every fragment of a
    /// frame — data *and* parity — carries the same value.
    pub stream: u8,
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
        if self.stream == 1 {
            flags |= FLAG_STREAM1;
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
        let flags = buf[FRAG_FLAGS_OFFSET];
        let block_size = buf[9];

        // Deliberately narrow: `FLAG_AUDIO` is NOT in this mask and must not be
        // added to it. See `FLAG_AUDIO`'s docs for what widening it costs.
        // `FLAG_STREAM1` is in it because this module now *emits* it; the audio
        // bit is the one that stays out.
        if flags & !(FLAG_KEYFRAME | FLAG_PARITY | FLAG_STREAM1) != 0 {
            return Err(Error::Invalid(format!("unknown flags {flags:#x}")));
        }
        if frag_count == 0 || frag_count > MAX_FRAGS_PER_FRAME {
            return Err(Error::Invalid(format!("bad frag_count {frag_count}")));
        }
        let keyframe = flags & FLAG_KEYFRAME != 0;
        let parity = flags & FLAG_PARITY != 0;
        let stream = u8::from(flags & FLAG_STREAM1 != 0);

        let (timestamp_ms, last_frag_len) = if parity {
            // Parity fragment: `frag_index` is a block index in
            // `0..num_blocks`, and the timestamp field is repurposed to carry
            // `last_frag_len`. A parity fragment without a block size is
            // meaningless.
            if block_size < 1 {
                return Err(Error::Invalid(
                    "parity fragment with zero block_size".into(),
                ));
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
                stream,
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
///
/// This is precisely [`fragment_frame_fec`] with `block_size = 0`, which is how
/// "no FEC" is spelled on the wire: identical chunking, identical caps,
/// identical errors in the same order, and `block_size: 0, last_frag_len: 0` in
/// every header. Delegating rather than keeping a second copy is what stops the
/// two from drifting — the FEC path's *data* fragments are required to be
/// byte-identical to these, so a header or cap change made in one place only
/// would be a wire-format split with no compiler error.
pub fn fragment_frame(frame: &EncodedFrame, max_datagram: usize) -> Result<Vec<Vec<u8>>> {
    fragment_frame_fec(frame, max_datagram, 0)
}

/// Split one encoded frame into datagram-sized fragments **with XOR parity**,
/// on video stream 0.
///
/// This is precisely [`fragment_frame_fec_on`] with `stream = 0`, which is how
/// "the primary output" is spelled on the wire: no [`FLAG_STREAM1`] bit, hence
/// bytes identical to every fragment this function emitted before multi-monitor
/// existed. It delegates rather than keeping its own loop for the same
/// anti-drift reason [`fragment_frame`] does — stream 0's fragments are
/// *required* to stay byte-identical to the tagged path's minus one flag bit,
/// and two copies of the chunking would let that requirement rot without a
/// compiler error.
pub fn fragment_frame_fec(
    frame: &EncodedFrame,
    max_datagram: usize,
    block_size: u8,
) -> Result<Vec<Vec<u8>>> {
    fragment_frame_fec_on(frame, max_datagram, block_size, 0)
}

/// Split one encoded frame into datagram-sized fragments **with XOR parity**,
/// tagged for video `stream` (0 = primary, 1 = second monitor).
///
/// `stream` is written as [`FLAG_STREAM1`] into every fragment of the frame —
/// data *and* parity alike, without exception. A parity fragment that lost its
/// stream tag would be XORed into the wrong stream's recovery buffer by a
/// receiver that demuxes on the bit, silently corrupting a frame that was never
/// even damaged; that is why the tag is a property of the frame here rather
/// than an argument the parity loop could forget to pass on.
///
/// The data fragments are identical to [`fragment_frame`]'s (same chunking,
/// same caps) except each carries `block_size` in its header so the receiver
/// knows K without a side channel. The `N` data fragments are then grouped into
/// blocks of `K`, and each block's parity fragment is emitted immediately after
/// its `K` data fragments (not appended after every block's data, at the tail):
/// its payload is the byte-wise XOR of the block's data payloads (each padded
/// to the full chunk width), letting the receiver rebuild a single lost data
/// fragment per block. Interleaving parity this way means a burst of tail loss
/// on a lossy link costs at most one block's fragments instead of every parity
/// fragment in the frame. Every datagram is self-describing (frame_id,
/// frag_index/block index, parity flag) and the reassembler indexes fragments
/// by those header fields rather than arrival order or position, so this is
/// wire-compatible in both directions: an old client reassembles a new host's
/// interleaved stream fine, and a new client reassembles an old host's
/// tail-appended stream fine. (Block *membership* — which data fragments a
/// given parity fragment covers — is unchanged: consecutive index ranges of
/// size `K`, same as before.)
///
/// With `block_size == 0` or a single data fragment there is nothing a parity
/// block could recover, so only the data fragments are returned.
pub fn fragment_frame_fec_on(
    frame: &EncodedFrame,
    max_datagram: usize,
    block_size: u8,
    stream: u8,
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

    let mut data_frags = Vec::with_capacity(count);
    for (i, piece) in frame.data.chunks(chunk).enumerate() {
        let mut dgram = Vec::with_capacity(FRAG_HEADER_LEN + piece.len());
        FragHeader {
            frame_id: frame.frame_id,
            frag_index: i as u16,
            frag_count: count as u16,
            keyframe: frame.keyframe,
            parity: false,
            stream,
            block_size,
            last_frag_len: 0,
            timestamp_ms: frame.timestamp_ms,
        }
        .encode(&mut dgram);
        dgram.extend_from_slice(piece);
        data_frags.push(dgram);
    }

    // No FEC requested, or a lone data fragment: parity would be pure overhead.
    if block_size == 0 || count <= 1 {
        return Ok(data_frags);
    }

    let k = block_size as usize;
    let num_blocks = count.div_ceil(k);
    let mut out = Vec::with_capacity(count + num_blocks);
    // Blocks are consecutive index ranges [lo, hi) in ascending order, so
    // draining `data_frags` in order and pulling one block's worth per
    // iteration reunites each block's data with its own parity — no clone,
    // no re-deriving indices.
    let mut data_iter = data_frags.into_iter();
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
        // Emit this block's K data fragments, then its parity fragment
        // immediately after (interleaved) instead of at the frame's tail.
        for _ in lo..hi {
            out.push(
                data_iter
                    .next()
                    .expect("data_frags has exactly `count` fragments, one per block index"),
            );
        }
        let mut dgram = Vec::with_capacity(FRAG_HEADER_LEN + chunk);
        FragHeader {
            frame_id: frame.frame_id,
            frag_index: b as u16,
            frag_count: count as u16,
            keyframe: frame.keyframe,
            parity: true,
            // Same tag as this block's data fragments, by construction: the
            // parity payload is only meaningful against them.
            stream,
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

/// Which video stream a datagram belongs to, from one byte and no parsing.
///
/// Returns `1` iff [`FLAG_STREAM1`] is set at [`FRAG_FLAGS_OFFSET`], else `0`.
/// The counterpart to [`crate::audio::is_audio_datagram`], and used the same
/// way and in the same place: the session demux needs to hand a datagram to the
/// right reassembler *before* it has a header, because deciding that is what
/// tells it which reassembler to parse the header with.
///
/// **Call it only on something already established to be video** — audio
/// datagrams spend bit 3 on [`crate::audio::FLAG_DISCONTINUITY`], so route with
/// `is_audio_datagram` first and ask this second. Doing it in the other order
/// reads a discontinuity marker as a stream tag.
///
/// Total by construction: a short or empty slice answers `0` rather than
/// panicking. That is not defensive habit — QUIC permits a zero-length
/// datagram, and this function's whole point is to run on a slice of unknown
/// provenance before anything has validated its length. Hence `.get`, never
/// indexing. A malformed datagram answering "stream 0" is harmless: the
/// stream-0 reassembler rejects it in [`FragHeader::decode`] a moment later,
/// which is where malformed input is supposed to die.
pub fn datagram_stream_id(d: &[u8]) -> u8 {
    match d.get(FRAG_FLAGS_OFFSET) {
        Some(flags) if flags & FLAG_STREAM1 != 0 => 1,
        _ => 0,
    }
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
            stream: 0,
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
            stream: 0,
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
    fn fragment_frame_is_fec_with_no_parity() {
        // `fragment_frame` delegates to `fragment_frame_fec(.., 0)`. Pin that
        // the two are byte-identical over the shapes that could diverge: a
        // single fragment, an exact multiple of the chunk size, a one-byte
        // overflow into a second fragment, and a long short-tailed frame.
        for len in [1usize, 500, 1186, 1187, 2372, 10_000] {
            for mtu in [64usize, 300, 1200, 1500] {
                let frame = mk(len);
                assert_eq!(
                    fragment_frame(&frame, mtu).unwrap(),
                    fragment_frame_fec(&frame, mtu, 0).unwrap(),
                    "len {len}, mtu {mtu}"
                );
                // Second link in the same chain: `fragment_frame_fec` is now
                // itself a wrapper over `fragment_frame_fec_on(.., 0)`. Pinning
                // it here keeps the stream-0 path provably one implementation
                // deep rather than three that agree today.
                assert_eq!(
                    fragment_frame_fec(&frame, mtu, 4).unwrap(),
                    fragment_frame_fec_on(&frame, mtu, 4, 0).unwrap(),
                    "len {len}, mtu {mtu} (with parity)"
                );
            }
        }
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
            stream: 0,
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
            stream: 0,
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
        // N data fragments plus num_blocks parity fragments, interleaved:
        // each block's parity immediately follows its K data fragments.
        assert_eq!(frags.len(), n + num_blocks);
        assert!(frags.iter().all(|f| f.len() <= mtu));

        // Output order: decode every fragment in emission order and check each
        // block's parity lands directly after its own data fragments, not
        // appended after all data at the tail.
        let mut pos = 0usize;
        for b in 0..num_blocks {
            let lo = b * k as usize;
            let hi = ((b + 1) * k as usize).min(n);
            for i in lo..hi {
                let (h, _) = FragHeader::decode(&frags[pos]).unwrap();
                assert!(!h.parity, "expected data fragment {i} at position {pos}");
                assert_eq!(h.frag_index as usize, i);
                pos += 1;
            }
            let (h, _) = FragHeader::decode(&frags[pos]).unwrap();
            assert!(
                h.parity,
                "expected block {b}'s parity fragment at position {pos}"
            );
            assert_eq!(h.frag_index as usize, b);
            pos += 1;
        }
        assert_eq!(pos, frags.len());

        // Data payloads, in index order, reconstruct the frame exactly.
        // (Order-agnostic: the reassembler indexes by header fields, not
        // position, so this also validates the wire contract those old/new
        // peers rely on.)
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
            for payload in &data_payloads[lo..hi] {
                for (j, &byte) in payload.iter().enumerate() {
                    acc[j] ^= byte;
                }
            }
            assert!(acc.iter().all(|&x| x == 0), "block {b} parity mismatch");
        }
    }

    /// The audio bit must stay OUTSIDE `decode`'s allowed mask.
    ///
    /// This is not a test of a behaviour anyone wants; it is a tripwire on a
    /// tempting "cleanup". A maintainer adding audio support may reasonably
    /// think the video decoder should tolerate the audio flag it now knows
    /// about, and widen the mask to `!(FLAG_KEYFRAME | FLAG_PARITY |
    /// FLAG_AUDIO)`. Doing that makes an audio datagram decode as a *video
    /// fragment*, whose `frame_id` is really an audio sequence number from an
    /// unrelated number line. Eight of those in a row read to the reassembler
    /// as eight consecutive, mutually-agreeing out-of-window ids — its exact
    /// signature for a legitimate encoder renumbering — so it calls
    /// `adopt_numbering`, drops every live slot and every ready frame, and
    /// demands a keyframe. Video stalls, and nothing logs an error.
    ///
    /// The assertion below therefore checks not just "an error" but that it is
    /// specifically the unknown-flags rejection, so that a mask widened by hand
    /// cannot be papered over by some other check happening to fail instead.
    #[test]
    fn video_decode_still_rejects_the_audio_flag() {
        // A header that is valid in every other respect, so the only thing the
        // decoder can object to is the flag itself.
        let mut buf = Vec::new();
        FragHeader {
            frame_id: 42,
            frag_index: 0,
            frag_count: 1,
            keyframe: true,
            parity: false,
            stream: 0,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 1234,
        }
        .encode(&mut buf);
        buf.push(0xFF); // one payload byte

        // Sanity: it decodes cleanly before the audio bit is set, so the
        // rejection below is attributable to that bit and nothing else.
        assert!(
            FragHeader::decode(&buf).is_ok(),
            "the fixture must be a valid fragment before FLAG_AUDIO is set"
        );

        buf[FRAG_FLAGS_OFFSET] |= FLAG_AUDIO;
        let err = FragHeader::decode(&buf).expect_err(
            "FragHeader::decode must REJECT the audio flag. If you just widened \
             decode's allowed mask to accept FLAG_AUDIO: undo it. That mask is \
             the backstop that keeps an audio datagram out of the reassembler, \
             where its sequence number would be read as a video frame_id and, \
             after 8 in a row, trigger adopt_numbering — wiping every live \
             video slot. Route audio with audio::is_audio_datagram instead.",
        );
        match err {
            Error::Invalid(msg) => assert!(
                msg.contains("unknown flags"),
                "expected the unknown-flags rejection, got: {msg}"
            ),
            other => panic!("expected Error::Invalid(unknown flags), got: {other}"),
        }
    }

    #[test]
    fn fragment_frame_fec_without_fec_returns_data_only() {
        let frame = mk(10_000);
        // K=0 and single-fragment frames both skip parity entirely.
        let no_k = fragment_frame_fec(&frame, 1200, 0).unwrap();
        assert!(no_k
            .iter()
            .all(|f| !FragHeader::decode(f).unwrap().0.parity));
        let tiny = fragment_frame_fec(&mk(50), 1200, 10).unwrap();
        assert_eq!(tiny.len(), 1);
        assert!(!FragHeader::decode(&tiny[0]).unwrap().0.parity);
    }

    /// The stream tag must be its own bit in the shared flag space.
    ///
    /// Cheap, and it catches the one mistake that would be invisible in every
    /// other test here: reusing a bit that already means something. Colliding
    /// with `FLAG_KEYFRAME` or `FLAG_PARITY` would corrupt this module's own
    /// decode; colliding with `FLAG_AUDIO` would make every stream-1 fragment
    /// classify as audio in the datagram demux.
    #[test]
    fn stream1_flag_is_distinct() {
        for other in [FLAG_KEYFRAME, FLAG_PARITY, FLAG_AUDIO] {
            assert_eq!(
                FLAG_STREAM1 & other,
                0,
                "FLAG_STREAM1 collides with an existing flag bit"
            );
        }
        assert_eq!(FLAG_STREAM1.count_ones(), 1, "the tag must be a single bit");
    }

    #[test]
    fn stream1_header_roundtrip() {
        // Data fragment on stream 1.
        let mut buf = Vec::new();
        let h = FragHeader {
            frame_id: 11,
            frag_index: 2,
            frag_count: 5,
            keyframe: true,
            parity: false,
            stream: 1,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 99,
        };
        h.encode(&mut buf);
        buf.push(0xFF);
        let (back, payload) = FragHeader::decode(&buf).unwrap();
        assert_eq!(h, back);
        assert_eq!(back.stream, 1);
        assert_eq!(payload, &[0xFF]);

        // Parity fragment on stream 1: the tag rides parity headers too, or a
        // receiver demuxing on the bit would XOR it into the wrong stream.
        let mut pbuf = Vec::new();
        let p = FragHeader {
            frame_id: 11,
            frag_index: 1,
            frag_count: 5,
            keyframe: false,
            parity: true,
            stream: 1,
            block_size: 4,
            last_frag_len: 321,
            timestamp_ms: 0,
        };
        p.encode(&mut pbuf);
        pbuf.push(0xFF);
        let (pback, ppayload) = FragHeader::decode(&pbuf).unwrap();
        assert_eq!(p, pback);
        assert_eq!(pback.stream, 1);
        assert!(pback.parity);
        assert_eq!(ppayload, &[0xFF]);
    }

    /// A `stream: 0` header must encode to exactly the bytes it encoded to
    /// before the stream tag existed.
    ///
    /// This is the anti-brick assertion for the whole multi-monitor datagram
    /// change. The 14-byte header is fixed-width and positional, with no
    /// version and nothing for a receiver to negotiate — an already-deployed
    /// client parses byte 8 as flags and bytes 10..14 as a timestamp no matter
    /// what this commit believes. Expected bytes are written out by hand rather
    /// than round-tripped through `encode` on purpose: a test that asks the new
    /// code what it produces cannot notice the new code producing something
    /// different from the old.
    #[test]
    fn stream0_headers_are_byte_identical_to_before_multi_monitor() {
        let mut data = Vec::new();
        FragHeader {
            frame_id: 1,
            frag_index: 2,
            frag_count: 5,
            keyframe: true,
            parity: false,
            stream: 0,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 99,
        }
        .encode(&mut data);
        assert_eq!(
            data,
            vec![
                0x01, 0x00, 0x00, 0x00, // frame_id     u32 LE 1
                0x02, 0x00, // frag_index           u16 LE 2
                0x05, 0x00, // frag_count           u16 LE 5
                0x01, // flags: FLAG_KEYFRAME only — NO stream bit
                0x00, // block_size 0 (no FEC)
                0x63, 0x00, 0x00, 0x00, // timestamp_ms u32 LE 99
            ],
            "a stream-0 data header changed shape — every deployed peer parses \
             this layout positionally, with no version field to save it"
        );

        let mut parity = Vec::new();
        FragHeader {
            frame_id: 7,
            frag_index: 1,
            frag_count: 5,
            keyframe: false,
            parity: true,
            stream: 0,
            block_size: 4,
            last_frag_len: 321,
            timestamp_ms: 0,
        }
        .encode(&mut parity);
        assert_eq!(
            parity,
            vec![
                0x07, 0x00, 0x00, 0x00, // frame_id  u32 LE 7
                0x01, 0x00, // frag_index (block index) u16 LE 1
                0x05, 0x00, // frag_count               u16 LE 5
                0x02, // flags: FLAG_PARITY only — NO stream bit
                0x04, // block_size K=4
                0x41, 0x01, // last_frag_len u16 LE 321 (repurposed timestamp)
                0x00, 0x00, // zero pad
            ],
            "a stream-0 parity header changed shape"
        );

        // And the tag is exactly one bit of difference, in the flags byte and
        // nowhere else — proof that stream 1 is a flag, not a layout change.
        let mut tagged = Vec::new();
        FragHeader {
            frame_id: 1,
            frag_index: 2,
            frag_count: 5,
            keyframe: true,
            parity: false,
            stream: 1,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 99,
        }
        .encode(&mut tagged);
        let mut expected = data.clone();
        expected[FRAG_FLAGS_OFFSET] |= FLAG_STREAM1;
        assert_eq!(tagged, expected);
        assert_eq!(tagged.len(), FRAG_HEADER_LEN);
    }

    /// `decode` accepts the stream bit, and the widened mask stops there.
    ///
    /// The mask grew from `!(KEYFRAME | PARITY)` to
    /// `!(KEYFRAME | PARITY | STREAM1)` for this feature, so this test pins
    /// both halves of that: the new bit gets through, and the bits either side
    /// of it — `FLAG_AUDIO` below, the first reserved bit above — still do not.
    /// `video_decode_still_rejects_the_audio_flag` is the standalone tripwire
    /// for the audio bit and is deliberately left untouched; the case here is
    /// the *combination* it cannot cover, a datagram carrying both bits.
    #[test]
    fn decode_accepts_stream1_and_still_rejects_the_rest() {
        let mut buf = Vec::new();
        FragHeader {
            frame_id: 3,
            frag_index: 0,
            frag_count: 1,
            keyframe: true,
            parity: false,
            stream: 1,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: 5,
        }
        .encode(&mut buf);
        buf.push(0xFF);
        let (h, _) = FragHeader::decode(&buf).expect("the stream tag must decode");
        assert_eq!(h.stream, 1);
        assert!(h.keyframe);

        // Audio bit *on top of* the stream bit: still rejected. A mask widened
        // one bit too far would let this through as a stream-1 video fragment.
        let mut with_audio = buf.clone();
        with_audio[FRAG_FLAGS_OFFSET] |= FLAG_AUDIO;
        let err = FragHeader::decode(&with_audio)
            .expect_err("FLAG_AUDIO must stay rejected, stream tag or not");
        match err {
            Error::Invalid(msg) => assert!(
                msg.contains("unknown flags"),
                "expected the unknown-flags rejection, got: {msg}"
            ),
            other => panic!("expected Error::Invalid(unknown flags), got: {other}"),
        }

        // The first bit above the stream tag is still reserved.
        let mut reserved = buf.clone();
        reserved[FRAG_FLAGS_OFFSET] |= 0b1_0000;
        assert!(
            FragHeader::decode(&reserved).is_err(),
            "reserved flag bits must stay rejected"
        );
    }

    /// The one-byte demux is total: it runs before anything has checked a
    /// length, and QUIC permits a zero-length datagram.
    #[test]
    fn datagram_stream_id_never_panics() {
        assert_eq!(datagram_stream_id(&[]), 0, "empty datagram");
        assert_eq!(
            datagram_stream_id(&[0u8; FRAG_FLAGS_OFFSET]),
            0,
            "one byte short of the flags byte"
        );

        let frame = mk(3000);
        for f in fragment_frame_fec_on(&frame, 1200, 4, 1).unwrap() {
            assert_eq!(datagram_stream_id(&f), 1);
        }
        for f in fragment_frame_fec_on(&frame, 1200, 4, 0).unwrap() {
            assert_eq!(datagram_stream_id(&f), 0);
        }
    }

    /// Every datagram of a stream-1 frame carries the tag — parity included.
    #[test]
    fn fragment_frame_fec_on_tags_every_fragment() {
        let frame = mk(10_000);
        let mtu = 1200;
        let k = 4u8;
        let frags = fragment_frame_fec_on(&frame, mtu, k, 1).unwrap();

        let n = frame.data.len().div_ceil(mtu - FRAG_HEADER_LEN);
        let num_blocks = n.div_ceil(k as usize);
        assert_eq!(
            frags.len(),
            n + num_blocks,
            "want data and parity fragments"
        );

        let mut saw_parity = false;
        for f in &frags {
            assert_eq!(f[FRAG_FLAGS_OFFSET] & FLAG_STREAM1, FLAG_STREAM1);
            let (h, _) = FragHeader::decode(f).expect("a tagged fragment must decode");
            assert_eq!(h.stream, 1);
            saw_parity |= h.parity;
        }
        assert!(saw_parity, "fixture must include parity fragments");

        // Stream 0 stays untagged over the same fixture — the two paths differ
        // by exactly the flag bit and nothing else.
        let plain = fragment_frame_fec_on(&frame, mtu, k, 0).unwrap();
        assert_eq!(plain.len(), frags.len());
        for (untagged, tagged) in plain.iter().zip(&frags) {
            let mut want = untagged.clone();
            want[FRAG_FLAGS_OFFSET] |= FLAG_STREAM1;
            assert_eq!(&want, tagged);
        }
    }
}
