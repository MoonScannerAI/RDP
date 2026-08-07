//! System audio datagram path: hand-rolled packet header, host → client.
//!
//! Layout (10 bytes, little-endian, fixed — NOT postcard, hot path):
//! ```text
//! offset size field
//! 0      4    seq         (u32, wraps)
//! 4      4    capture_ms  (u32, wraps)
//! 8      1    flags       (bit2 = AUDIO, always set; bit3 = discontinuity)
//! 9      1    format      (0 = 48k stereo, 1 = 44.1k stereo,
//!                          2 = 48k mono,   3 = 44.1k mono)
//! ```
//! Payload follows immediately: exactly one raw AAC-LC access unit, 1..=1024
//! bytes. One access unit per datagram, never a partial one and never two —
//! there is no fragmentation and therefore no reassembly, because an AAC-LC
//! frame at any bitrate we send fits inside a QUIC datagram with room to spare
//! and a lost audio frame is worth a click, not a recovery mechanism.
//!
//! # Why byte 8 is the flags byte
//!
//! Audio and video share the unreliable media datagram path, so something has
//! to tell them apart on arrival. Byte 8 is the flags byte in
//! [`crate::video`]'s fragment header too — [`AUDIO_FLAGS_OFFSET`] is asserted
//! equal to [`crate::video::FRAG_FLAGS_OFFSET`] at compile time, a few lines
//! below — and [`crate::video::FLAG_AUDIO`] is a bit that no video fragment
//! ever carries. So the demux is [`is_audio_datagram`]: one bounds-checked byte
//! load and one mask, decided before either header is parsed and before a
//! single byte is allocated.
//!
//! The alternative designs were a separate QUIC stream (reliable, so a lost
//! audio frame would head-of-line-block the next one — wrong trade for audio)
//! and a leading discriminant byte (which would push every video field one byte
//! over, changing a wire format that already-deployed peers parse positionally).
//! Sharing the flags offset costs one reserved bit and no layout change at all.
//!
//! The demux is a *routing* decision, not a security boundary. The security
//! boundary is that the video decoder keeps rejecting `FLAG_AUDIO` outright —
//! see that constant's docs for why an audio datagram reaching the video
//! reassembler would silently wipe its live state. Route with
//! [`is_audio_datagram`]; rely on the rejection when someone forgets to.
//!
//! # Why `format` is per-packet
//!
//! Sample rate and channel count ride in every single packet rather than being
//! announced once at stream start. That costs one byte per ~20 ms of audio,
//! which is nothing, and buys three things:
//!
//! * Every datagram is self-describing. There is no "first packet" whose loss
//!   leaves the receiver unable to interpret the rest — and this path is
//!   unreliable, so any packet designated special is a packet that will
//!   eventually go missing.
//! * A mid-session format change is the ordinary path, not an exception. The
//!   operator moving the host's default output from speakers to a Bluetooth
//!   headset changes the capture endpoint's mix format underneath us; the
//!   sender just starts stamping a different code, and the receiver
//!   reconfigures when it sees one, without a control-plane round trip that
//!   would have to be ordered against the datagrams it describes.
//! * There is no cross-packet state to get out of sync, so a receiver that
//!   joins late, or after a gap, is immediately correct.
//!
//! [`FLAG_DISCONTINUITY`] is the companion to that: it marks the first packet
//! after a capture gap (glitch, endpoint switch, silence suppression), telling
//! the receiver to reset its jitter buffer rather than try to bridge the hole.

use crate::error::{Error, Result};

/// Re-exported, not redefined. The bit's meaning is a property of the *shared*
/// datagram flag space, and one definition is what keeps the video decoder's
/// rejection and this module's demux talking about the same bit.
pub use crate::video::FLAG_AUDIO;

/// Fixed header length; payload begins here.
pub const AUDIO_HEADER_LEN: usize = 10;
/// Byte offset of the flags field. Deliberately identical to
/// [`crate::video::FRAG_FLAGS_OFFSET`] — see the module docs.
pub const AUDIO_FLAGS_OFFSET: usize = 8;
/// Byte offset of the format code.
pub const AUDIO_FORMAT_OFFSET: usize = 9;

/// Set on the first packet after a capture gap: reset the jitter buffer rather
/// than attempt to conceal a hole of unknown length.
pub const FLAG_DISCONTINUITY: u8 = 0b0000_1000;

/// The only flag bits an audio packet may carry. Every other bit is reserved
/// and MUST be zero on the wire; [`decode_packet`] rejects a packet that sets
/// one. Reserved-means-rejected is the cheap version of forward compatibility:
/// it keeps the option of spending a bit later without any deployed receiver
/// having already decided what it means.
pub const AUDIO_FLAGS_MASK: u8 = FLAG_AUDIO | FLAG_DISCONTINUITY;

/// Largest AAC-LC access unit we will send or accept. A 1024-sample AAC-LC
/// frame at 256 kbit/s is well under 1 KiB; this is a generous cap that still
/// keeps header + payload inside any plausible QUIC datagram limit.
pub const MAX_AUDIO_PAYLOAD: usize = 1024;

/// The audio flags byte must sit exactly where the video flags byte sits, or
/// the one-byte demux in [`is_audio_datagram`] silently starts reading an
/// unrelated field of whichever format it was not given. Moving either offset
/// fails the build here rather than at 3 a.m. on a live session.
const _: () = assert!(AUDIO_FLAGS_OFFSET == crate::video::FRAG_FLAGS_OFFSET);
/// The audio marker must not collide with a video flag, or every video fragment
/// would classify as audio (or vice versa).
const _: () = assert!(FLAG_AUDIO & (crate::video::FLAG_KEYFRAME | crate::video::FLAG_PARITY) == 0);
/// The header must be long enough to contain the fields it claims.
const _: () = assert!(AUDIO_HEADER_LEN > AUDIO_FORMAT_OFFSET);

/// Capture format of one audio packet.
///
/// Deliberately a closed set of four rather than free-form (rate, channels):
/// these are the mixes a Windows shared-mode render endpoint actually hands us,
/// the receiver has to be able to configure its output device for whatever
/// arrives, and a one-byte enumerated code is both smaller on the wire and
/// impossible to fill with a nonsense sample rate. An endpoint whose native mix
/// is something else (96 kHz, 5.1) is resampled/downmixed at the host before it
/// reaches this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// 48 kHz, 2 channels — the overwhelmingly common Windows default.
    Stereo48k,
    /// 44.1 kHz, 2 channels.
    Stereo44k1,
    /// 48 kHz, 1 channel.
    Mono48k,
    /// 44.1 kHz, 1 channel.
    Mono44k1,
}

impl AudioFormat {
    /// Every format, in wire-code order. Used by the tests to prove the code
    /// mapping round-trips without a hand-maintained second list.
    pub const ALL: [AudioFormat; 4] = [
        AudioFormat::Stereo48k,
        AudioFormat::Stereo44k1,
        AudioFormat::Mono48k,
        AudioFormat::Mono44k1,
    ];

    /// Samples per second per channel.
    pub const fn sample_rate(self) -> u32 {
        match self {
            AudioFormat::Stereo48k | AudioFormat::Mono48k => 48_000,
            AudioFormat::Stereo44k1 | AudioFormat::Mono44k1 => 44_100,
        }
    }

    /// Interleaved channel count.
    pub const fn channels(self) -> u8 {
        match self {
            AudioFormat::Stereo48k | AudioFormat::Stereo44k1 => 2,
            AudioFormat::Mono48k | AudioFormat::Mono44k1 => 1,
        }
    }

    /// The byte written at [`AUDIO_FORMAT_OFFSET`].
    ///
    /// These numbers are wire values. They may be appended to, never
    /// reassigned: a receiver that predates a renumbering would play the new
    /// code's audio at the old code's rate — audible, but as a pitch shift
    /// rather than an error anyone would trace back to here.
    pub const fn code(self) -> u8 {
        match self {
            AudioFormat::Stereo48k => 0,
            AudioFormat::Stereo44k1 => 1,
            AudioFormat::Mono48k => 2,
            AudioFormat::Mono44k1 => 3,
        }
    }

    /// Parse a wire code. `None` for anything unassigned — the caller must
    /// reject the packet rather than guess, because guessing means playing
    /// noise at the wrong rate instead of dropping one 20 ms frame.
    pub const fn from_code(code: u8) -> Option<AudioFormat> {
        match code {
            0 => Some(AudioFormat::Stereo48k),
            1 => Some(AudioFormat::Stereo44k1),
            2 => Some(AudioFormat::Mono48k),
            3 => Some(AudioFormat::Mono44k1),
            _ => None,
        }
    }
}

/// One audio datagram: the header fields plus a borrowed payload.
///
/// The payload borrows rather than owns for the same reason
/// [`crate::video::FragHeader::decode`] returns a slice — this is a per-20 ms,
/// per-session hot path and a decode should not allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioPacket<'a> {
    /// Wraps. Gaps mean loss; the receiver uses it for concealment decisions,
    /// never as an index into anything.
    pub seq: u32,
    /// Host capture timestamp, milliseconds, wraps. Same clock as the video
    /// fragment header's `timestamp_ms`, which is what makes A/V sync possible.
    pub capture_ms: u32,
    /// First packet after a capture gap — see [`FLAG_DISCONTINUITY`].
    pub discontinuity: bool,
    /// Format of *this* packet; may differ from the previous one. See the
    /// module docs for why this is per-packet.
    pub format: AudioFormat,
    /// Exactly one raw AAC-LC access unit, 1..=[`MAX_AUDIO_PAYLOAD`] bytes.
    pub payload: &'a [u8],
}

/// Serialize one audio packet into a datagram.
///
/// Rejects a payload that is empty or over [`MAX_AUDIO_PAYLOAD`], so that this
/// function cannot put on the wire anything [`decode_packet`] would refuse.
/// [`FLAG_AUDIO`] is set unconditionally: it is what makes the datagram
/// routable at all, so it is not the caller's to forget.
pub fn encode_packet(packet: &AudioPacket<'_>) -> Result<Vec<u8>> {
    if packet.payload.is_empty() {
        return Err(Error::Invalid("empty audio payload".into()));
    }
    if packet.payload.len() > MAX_AUDIO_PAYLOAD {
        return Err(Error::Oversized {
            got: packet.payload.len(),
            limit: MAX_AUDIO_PAYLOAD,
        });
    }
    let mut out = Vec::with_capacity(AUDIO_HEADER_LEN + packet.payload.len());
    out.extend_from_slice(&packet.seq.to_le_bytes());
    out.extend_from_slice(&packet.capture_ms.to_le_bytes());
    let mut flags = FLAG_AUDIO;
    if packet.discontinuity {
        flags |= FLAG_DISCONTINUITY;
    }
    out.push(flags);
    out.push(packet.format.code());
    out.extend_from_slice(packet.payload);
    Ok(out)
}

/// Parse one audio datagram.
///
/// Rejects, in this order:
/// * a datagram shorter than the fixed header,
/// * any reserved flag bit set (see [`AUDIO_FLAGS_MASK`]),
/// * [`FLAG_AUDIO`] *not* set — a datagram that reached this function without
///   the marker was misrouted, and parsing it anyway would turn a routing bug
///   into silently wrong audio,
/// * an unassigned format code,
/// * an empty payload,
/// * a payload over [`MAX_AUDIO_PAYLOAD`].
///
/// Every one of these is a drop, not a session error: this is the unreliable
/// path, and a caller that tore the session down over one malformed datagram
/// would hand any on-path attacker a one-packet disconnect.
pub fn decode_packet(buf: &[u8]) -> Result<AudioPacket<'_>> {
    if buf.len() < AUDIO_HEADER_LEN {
        return Err(Error::Invalid(format!(
            "audio packet shorter than header: {} bytes",
            buf.len()
        )));
    }
    let seq = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let capture_ms = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let flags = buf[AUDIO_FLAGS_OFFSET];
    let format_code = buf[AUDIO_FORMAT_OFFSET];

    if flags & !AUDIO_FLAGS_MASK != 0 {
        return Err(Error::Invalid(format!("unknown audio flags {flags:#x}")));
    }
    if flags & FLAG_AUDIO == 0 {
        return Err(Error::Invalid(format!(
            "audio packet without FLAG_AUDIO: flags {flags:#x}"
        )));
    }
    let Some(format) = AudioFormat::from_code(format_code) else {
        return Err(Error::Invalid(format!(
            "unknown audio format code {format_code}"
        )));
    };

    let payload = &buf[AUDIO_HEADER_LEN..];
    if payload.is_empty() {
        return Err(Error::Invalid("empty audio payload".into()));
    }
    if payload.len() > MAX_AUDIO_PAYLOAD {
        return Err(Error::Oversized {
            got: payload.len(),
            limit: MAX_AUDIO_PAYLOAD,
        });
    }
    Ok(AudioPacket {
        seq,
        capture_ms,
        discontinuity: flags & FLAG_DISCONTINUITY != 0,
        format,
        payload,
    })
}

/// True if this datagram is audio. Uses `.get()`, never indexing: QUIC
/// datagrams may legitimately be zero-length and anyone on the path can
/// inject one.
///
/// This is the media demux, and it is deliberately the cheapest possible test —
/// one bounds-checked byte load and a mask — so it can be applied to a slice of
/// entirely unknown provenance before any parsing or allocation happens.
///
/// It answers "which parser should see this", NOT "is this valid". A 9-byte
/// datagram with the bit set is audio *and* malformed: this returns `true` and
/// [`decode_packet`] then rejects it. Keeping classification separate from
/// validation is what stops a malformed audio packet from being retried as a
/// video fragment, which is exactly the misrouting
/// [`crate::video::FLAG_AUDIO`] exists to make impossible.
pub fn is_audio_datagram(datagram: &[u8]) -> bool {
    match datagram.get(AUDIO_FLAGS_OFFSET) {
        Some(flags) => flags & FLAG_AUDIO != 0,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::{fragment_frame_fec, EncodedFrame, FragHeader};
    use proptest::prelude::*;

    fn mk(payload: &[u8]) -> AudioPacket<'_> {
        AudioPacket {
            seq: 1,
            capture_ms: 2,
            discontinuity: false,
            format: AudioFormat::Stereo48k,
            payload,
        }
    }

    /// The audio header's bytes, pinned one at a time.
    ///
    /// Same job as `protocol::tests::hello_encoding_is_stable`: this layout is
    /// positional and has no field names, so widening a field, reordering two,
    /// or moving the flags byte changes how a peer built from another commit
    /// reads every byte after it — with no error, because there is nothing in a
    /// fixed binary header for a decoder to notice. If this test fails, the
    /// change in front of it is a wire break; do not update the expected bytes.
    ///
    /// The values are distinctive on purpose. An all-zero packet would encode
    /// identically whether `seq` were a u32 or a u16 followed by padding; these
    /// make each field's width and byte order visible.
    #[test]
    fn audio_header_layout_is_pinned() {
        let packet = AudioPacket {
            seq: 0x1122_3344,
            capture_ms: 0x5566_7788,
            discontinuity: true,
            format: AudioFormat::Mono44k1,
            payload: &[0xAA, 0xBB],
        };
        assert_eq!(
            encode_packet(&packet).unwrap(),
            vec![
                0x44, 0x33, 0x22, 0x11, // seq        u32 LE 0x11223344
                0x88, 0x77, 0x66, 0x55, // capture_ms u32 LE 0x55667788
                0x0C, // flags: FLAG_AUDIO (bit2) | FLAG_DISCONTINUITY (bit3)
                0x03, // format: Mono44k1
                0xAA, 0xBB, // payload (one AAC-LC access unit)
            ],
            "the audio header layout moved — it is positional and fixed-width, \
             so a peer built from another commit will misparse every byte after \
             the change without raising a single error"
        );

        // Without the discontinuity bit the flags byte is FLAG_AUDIO alone.
        // Pinned separately so that a change to either bit's value is caught
        // even if the other's happens to compensate in the combined byte.
        let plain = AudioPacket {
            discontinuity: false,
            format: AudioFormat::Stereo48k,
            ..packet
        };
        let bytes = encode_packet(&plain).unwrap();
        assert_eq!(bytes[AUDIO_FLAGS_OFFSET], 0x04, "FLAG_AUDIO alone");
        assert_eq!(bytes[AUDIO_FORMAT_OFFSET], 0x00, "Stereo48k code");
        assert_eq!(bytes.len(), AUDIO_HEADER_LEN + 2);
    }

    #[test]
    fn packet_roundtrips() {
        for format in AudioFormat::ALL {
            for discontinuity in [false, true] {
                let payload: Vec<u8> = (0..64u8).collect();
                let packet = AudioPacket {
                    seq: u32::MAX, // wraps next; nothing may treat it as an index
                    capture_ms: 0xDEAD_BEEF,
                    discontinuity,
                    format,
                    payload: &payload,
                };
                let bytes = encode_packet(&packet).unwrap();
                assert_eq!(decode_packet(&bytes).unwrap(), packet);
            }
        }
    }

    #[test]
    fn payload_size_bounds_roundtrip() {
        // Both ends of the legal range, since the caps are `>` / `is_empty`
        // and an off-by-one either way is invisible in ordinary traffic.
        for len in [1usize, MAX_AUDIO_PAYLOAD] {
            let payload = vec![0x5A; len];
            let bytes = encode_packet(&mk(&payload)).unwrap();
            assert_eq!(decode_packet(&bytes).unwrap().payload.len(), len);
        }
    }

    #[test]
    fn audio_format_codes_roundtrip() {
        for format in AudioFormat::ALL {
            assert_eq!(AudioFormat::from_code(format.code()), Some(format));
        }
        // Codes are distinct and contiguous from zero.
        let codes: Vec<u8> = AudioFormat::ALL.iter().map(|f| f.code()).collect();
        assert_eq!(codes, vec![0, 1, 2, 3]);
        // Everything unassigned stays unassigned.
        for code in 4u8..=255 {
            assert_eq!(
                AudioFormat::from_code(code),
                None,
                "code {code} must stay unassigned until it is given a meaning"
            );
        }
        // Rates and channel counts are the ones the codes claim.
        assert_eq!(AudioFormat::Stereo48k.sample_rate(), 48_000);
        assert_eq!(AudioFormat::Stereo48k.channels(), 2);
        assert_eq!(AudioFormat::Stereo44k1.sample_rate(), 44_100);
        assert_eq!(AudioFormat::Stereo44k1.channels(), 2);
        assert_eq!(AudioFormat::Mono48k.sample_rate(), 48_000);
        assert_eq!(AudioFormat::Mono48k.channels(), 1);
        assert_eq!(AudioFormat::Mono44k1.sample_rate(), 44_100);
        assert_eq!(AudioFormat::Mono44k1.channels(), 1);
    }

    #[test]
    fn encode_rejects_payloads_it_could_not_decode() {
        // The encoder must not be able to emit a datagram the decoder refuses;
        // otherwise a host bug becomes a silent one-way audio outage.
        assert!(encode_packet(&mk(&[])).is_err());
        let too_big = vec![0u8; MAX_AUDIO_PAYLOAD + 1];
        assert!(encode_packet(&mk(&too_big)).is_err());
    }

    #[test]
    fn decode_rejects_short_datagrams() {
        for len in 0..AUDIO_HEADER_LEN {
            let mut buf = vec![0u8; len];
            if len > AUDIO_FLAGS_OFFSET {
                buf[AUDIO_FLAGS_OFFSET] = FLAG_AUDIO;
            }
            assert!(
                decode_packet(&buf).is_err(),
                "{len}-byte datagram must not decode"
            );
        }
        // Header with no payload at all: long enough to parse, still invalid.
        let mut header_only = encode_packet(&mk(&[0xFF])).unwrap();
        header_only.truncate(AUDIO_HEADER_LEN);
        assert!(decode_packet(&header_only).is_err(), "empty payload");
    }

    #[test]
    fn decode_rejects_reserved_flag_bits() {
        // Every bit outside AUDIO_FLAGS_MASK, one at a time. Reserved bits are
        // rejected so they stay spendable later: a receiver that ignored them
        // would already have decided they mean "nothing".
        for bit in 0..8u8 {
            let reserved = 1u8 << bit;
            if reserved & AUDIO_FLAGS_MASK != 0 {
                continue;
            }
            let mut bytes = encode_packet(&mk(&[0x01, 0x02])).unwrap();
            bytes[AUDIO_FLAGS_OFFSET] |= reserved;
            let err = decode_packet(&bytes)
                .expect_err("a reserved flag bit must be rejected, so it stays spendable");
            assert!(
                err.to_string().contains("unknown audio flags"),
                "expected the unknown-flags rejection for {reserved:#x}, got: {err}"
            );
        }
    }

    #[test]
    fn decode_rejects_a_packet_without_the_audio_flag() {
        let mut bytes = encode_packet(&mk(&[0x01, 0x02])).unwrap();
        bytes[AUDIO_FLAGS_OFFSET] &= !FLAG_AUDIO;
        let err = decode_packet(&bytes).expect_err(
            "a datagram lacking FLAG_AUDIO reached the audio parser, which means \
             it was misrouted; parsing it anyway would turn a routing bug into \
             silently wrong audio",
        );
        assert!(err.to_string().contains("without FLAG_AUDIO"), "got: {err}");
    }

    #[test]
    fn decode_rejects_unknown_format_codes() {
        for code in 4u8..=255 {
            let mut bytes = encode_packet(&mk(&[0x01, 0x02])).unwrap();
            bytes[AUDIO_FORMAT_OFFSET] = code;
            let err = decode_packet(&bytes)
                .expect_err("an unassigned format code must be dropped, not guessed at");
            assert!(
                err.to_string().contains("unknown audio format code"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn decode_rejects_oversized_payloads() {
        // Built by hand, since `encode_packet` refuses to produce one.
        let mut bytes = encode_packet(&mk(&[0x01])).unwrap();
        bytes.resize(AUDIO_HEADER_LEN + MAX_AUDIO_PAYLOAD + 1, 0);
        assert!(decode_packet(&bytes).is_err());
        // One byte less is the largest legal packet.
        bytes.truncate(AUDIO_HEADER_LEN + MAX_AUDIO_PAYLOAD);
        assert!(decode_packet(&bytes).is_ok());
    }

    /// The demux must survive a slice of any length from anywhere, because on
    /// this path it gets exactly that.
    #[test]
    fn is_audio_datagram_classifies_by_one_byte() {
        // Zero-length: QUIC permits it and anyone on the path can inject one.
        // The point of `.get()` over `[8]` is that this is a `false`, not a
        // panic that would take the receive loop down.
        assert!(!is_audio_datagram(&[]));
        // Too short to contain the flags byte at all.
        assert!(!is_audio_datagram(&[0xFF; 8]));

        // Exactly 9 bytes: the flags byte exists, so this classifies as audio
        // even though it is far too short to BE a packet. Classification and
        // validation are separate on purpose — see `is_audio_datagram`'s docs.
        let mut nine = [0u8; 9];
        nine[AUDIO_FLAGS_OFFSET] = FLAG_AUDIO;
        assert!(
            is_audio_datagram(&nine),
            "9 bytes is enough to classify, never enough to decode"
        );
        assert!(
            decode_packet(&nine).is_err(),
            "classification must not imply validity"
        );

        // A real audio packet.
        let audio = encode_packet(&mk(&[0x01, 0x02, 0x03])).unwrap();
        assert!(is_audio_datagram(&audio));

        // A real video fragment. Both a data fragment and a parity fragment,
        // since they set different flag bits.
        let frame = EncodedFrame {
            frame_id: 7,
            keyframe: true,
            timestamp_ms: 1234,
            data: vec![0xAB; 10_000],
        };
        let frags = fragment_frame_fec(&frame, 1200, 4).unwrap();
        let mut saw_parity = false;
        for f in &frags {
            assert!(
                !is_audio_datagram(f),
                "a video fragment classified as audio"
            );
            saw_parity |= FragHeader::decode(f).unwrap().0.parity;
        }
        assert!(saw_parity, "fixture must include parity fragments");
    }

    /// A real audio packet must never survive the video decoder either.
    ///
    /// The mirror image of `video::tests::video_decode_still_rejects_the_audio_flag`:
    /// that one proves the flag is rejected, this one proves a genuine,
    /// well-formed audio datagram is what gets rejected by it.
    ///
    /// The fixture is chosen so the flag is the *only* thing wrong with it,
    /// which takes some care: read as a video header, an audio packet's
    /// `capture_ms` overlaps `frag_index` (bytes 4..6) and `frag_count`
    /// (bytes 6..8), and most timestamps make `frag_count` zero — which the
    /// video decoder would reject anyway, for an unrelated reason, hiding
    /// whether the flag check did anything at all. `capture_ms = 0x0001_0000`
    /// instead lands `frag_index = 0, frag_count = 1`, and the 64-byte payload
    /// puts the datagram well past `FRAG_HEADER_LEN`. So this packet satisfies
    /// every other rule the video decoder has: widen the allowed mask and it
    /// does not merely fail differently, it DECODES — a video fragment whose
    /// `frame_id` is really an audio sequence number, delivered straight to the
    /// reassembler. That is the failure this test exists to keep impossible.
    #[test]
    fn a_real_audio_packet_is_rejected_by_the_video_decoder() {
        let payload = [0x5A; 64];
        let audio = encode_packet(&AudioPacket {
            seq: 42,
            capture_ms: 0x0001_0000,
            discontinuity: false,
            format: AudioFormat::Stereo48k,
            payload: &payload,
        })
        .unwrap();
        assert!(audio.len() > crate::video::FRAG_HEADER_LEN);

        let err = FragHeader::decode(&audio)
            .expect_err("an audio datagram must never decode as a video fragment");
        assert!(
            err.to_string().contains("unknown flags"),
            "expected the video decoder's unknown-flags rejection, got: {err}"
        );

        // Prove the premise above rather than asserting it in prose: with the
        // audio bit cleared, this exact datagram IS a valid video fragment. The
        // flag is therefore carrying the whole rejection on its own.
        let mut disguised = audio.clone();
        disguised[AUDIO_FLAGS_OFFSET] &= !FLAG_AUDIO;
        let (header, _) = FragHeader::decode(&disguised).expect(
            "fixture must be a valid video fragment once the audio bit is cleared — \
             otherwise this test proves nothing about the flag",
        );
        assert_eq!(
            header.frame_id, 42,
            "the audio seq read as a video frame_id"
        );
    }

    proptest! {
        /// The demux has no false positives against real video traffic.
        ///
        /// `is_audio_datagram` reads one byte at a fixed offset, so the whole
        /// design rests on no video fragment ever setting that bit. Rather than
        /// assert that about `FragHeader::encode` by inspection, generate real
        /// fragments across frame sizes, MTUs and FEC block sizes — data and
        /// parity, full and short tails, single-fragment and many-fragment
        /// frames — and check every datagram the encoder can actually produce.
        #[test]
        fn is_audio_datagram_never_claims_a_real_video_fragment(
            len in 1usize..=20_000,
            mtu in 64usize..=1500,
            block_size in 0u8..=16,
            keyframe in any::<bool>(),
            frame_id in any::<u32>(),
            timestamp_ms in any::<u32>(),
        ) {
            let frame = EncodedFrame {
                frame_id,
                keyframe,
                timestamp_ms,
                data: vec![0xAB; len],
            };
            // The bounds above always fragment successfully (mtu >= 64 → chunk
            // >= 50, so 20_000 bytes is at most 400 fragments, under
            // MAX_FRAGS_PER_FRAME). Matched rather than unwrapped so that
            // widening the generator later cannot turn an out-of-range case
            // into a spurious failure of a test about something else.
            if let Ok(frags) = fragment_frame_fec(&frame, mtu, block_size) {
                prop_assert!(!frags.is_empty());
                for f in &frags {
                    prop_assert!(
                        !is_audio_datagram(f),
                        "video fragment classified as audio: flags {:#x}",
                        f[AUDIO_FLAGS_OFFSET]
                    );
                    // And it still decodes as video, i.e. the bit is absent
                    // rather than the datagram being malformed in some other
                    // way that happens to clear it.
                    prop_assert!(FragHeader::decode(f).is_ok());
                }
            }
        }
    }
}
