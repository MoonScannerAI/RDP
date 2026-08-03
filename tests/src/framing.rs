//! Byte-stream framing helpers for the simulated reliable channels.
//!
//! The netsim's streams are byte streams, exactly like a QUIC stream or a TCP
//! socket: bytes arrive in order but a `recv_stream` call may return a partial
//! message or several messages glued together. Everything that rides a stream
//! therefore needs a reader that buffers and re-splits.
//!
//! Three codecs live here:
//!
//! * [`FramedReader`] — the control-plane framing shared crate already defines
//!   on the wire (`u32-le length || postcard body`, see
//!   [`directdesk_shared::protocol::encode_framed`]).
//! * [`MuxRecord`] — the multiplexed record used by the TCP-fallback path, so
//!   video and control can share one ordered byte stream.
//! * [`encode_frame_record`] / [`decode_frame_record`] — an
//!   [`EncodedFrame`] flattened for that multiplexed stream, standing in for
//!   the length-prefixed video framing M4 will need once there is a real TCP
//!   fallback.

use directdesk_shared::error::{Error, Result};
use directdesk_shared::protocol::{parse_frame_len, MAX_CONTROL_MSG};
use directdesk_shared::video::{EncodedFrame, MAX_FRAME_BYTES};

/// Header size of a [`MuxRecord`]: class tag, payload length, enqueue instant,
/// sequence number.
pub const MUX_HEADER_LEN: usize = 1 + 4 + 8 + 8;

/// Largest payload accepted inside a [`MuxRecord`]. Generous enough for any
/// frame the harness produces, tight enough that a desynchronised stream fails
/// loudly instead of trying to allocate gigabytes.
pub const MUX_MAX_PAYLOAD: usize = MAX_FRAME_BYTES + 64;

/// Buffers stream bytes and re-splits them into whole length-prefixed messages.
#[derive(Debug, Clone)]
pub struct FramedReader {
    buf: Vec<u8>,
    limit: usize,
}

impl FramedReader {
    /// A reader accepting message bodies up to `limit` bytes.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
        }
    }

    /// A reader with the control-plane cap ([`MAX_CONTROL_MSG`]).
    #[must_use]
    pub fn control() -> Self {
        Self::new(MAX_CONTROL_MSG)
    }

    /// Append freshly received stream bytes.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet forming a complete message.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take every complete message currently buffered, oldest first.
    ///
    /// # Errors
    ///
    /// Returns the error from [`parse_frame_len`] if a length prefix is zero or
    /// exceeds the configured limit. The reader is left holding the offending
    /// bytes; a stream that has desynchronised cannot be resynchronised, so the
    /// caller should treat this as fatal for that channel.
    pub fn drain(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                return Ok(out);
            }
            let prefix: [u8; 4] = self.buf[0..4].try_into().expect("checked length");
            let len = parse_frame_len(prefix, self.limit)?;
            if self.buf.len() < 4 + len {
                return Ok(out);
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(0..4 + len);
        }
    }
}

/// Strip the control-plane length prefix, validating it first.
///
/// A [`MuxRecord`] already carries its own length, so a control message riding
/// the mux must not repeat one. The receiver hands the payload straight to
/// [`directdesk_shared::protocol::decode_strict`], which rejects trailing
/// bytes — a doubly framed message decodes as garbage or not at all.
///
/// # Errors
///
/// Returns [`Error::Invalid`] if the buffer is shorter than a prefix or if the
/// declared length does not match what follows, and whatever
/// [`parse_frame_len`] rejects.
pub fn strip_length_prefix(framed: &[u8], limit: usize) -> Result<Vec<u8>> {
    if framed.len() < 4 {
        return Err(Error::Invalid(
            "framed message shorter than its length prefix".into(),
        ));
    }
    let prefix: [u8; 4] = framed[0..4].try_into().expect("checked length");
    let len = parse_frame_len(prefix, limit)?;
    if framed.len() != 4 + len {
        return Err(Error::Invalid(format!(
            "framed message carries {} bytes but declares {len}",
            framed.len() - 4
        )));
    }
    Ok(framed[4..].to_vec())
}

/// Priority class of a record on the multiplexed fallback stream.
///
/// One ordered byte stream carries all three, exactly as a single TCP
/// connection would, so the sender's ordering policy is the only thing keeping
/// a small control message from queuing behind a backlog of video.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MuxClass {
    /// Session control: highest priority, never delayed behind bulk.
    Control,
    /// Input events: above video, below control.
    Input,
    /// Video frames: bulk, and the only class that may be dropped when stale.
    Video,
}

impl MuxClass {
    /// Scheduling rank; lower goes first.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            MuxClass::Control => 0,
            MuxClass::Input => 1,
            MuxClass::Video => 2,
        }
    }

    /// One-byte wire tag.
    #[must_use]
    pub fn tag(self) -> u8 {
        self.rank()
    }

    /// Inverse of [`MuxClass::tag`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for an unknown tag byte.
    pub fn from_tag(tag: u8) -> Result<MuxClass> {
        match tag {
            0 => Ok(MuxClass::Control),
            1 => Ok(MuxClass::Input),
            2 => Ok(MuxClass::Video),
            other => Err(Error::Invalid(format!("unknown mux class tag {other}"))),
        }
    }
}

/// One record carried on the multiplexed fallback stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxRecord {
    /// Priority class it was sent under.
    pub class: MuxClass,
    /// Sender-side enqueue order; strictly increasing across all classes.
    pub seq: u64,
    /// Virtual millisecond the sender enqueued it, carried so the receiver can
    /// measure queueing delay without a side channel.
    pub enqueued_ms: u64,
    /// Application bytes.
    pub payload: Vec<u8>,
}

/// Serialize a record for the multiplexed stream.
#[must_use]
pub fn encode_mux_record(class: MuxClass, seq: u64, enqueued_ms: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MUX_HEADER_LEN + payload.len());
    out.push(class.tag());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&enqueued_ms.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Buffers stream bytes and re-splits them into whole [`MuxRecord`]s.
#[derive(Debug, Clone, Default)]
pub struct MuxReader {
    buf: Vec<u8>,
}

impl MuxReader {
    /// An empty reader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append freshly received stream bytes.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet forming a complete record.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take every complete record currently buffered, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] on an unknown class tag and
    /// [`Error::Oversized`] on a payload length beyond [`MUX_MAX_PAYLOAD`].
    pub fn drain(&mut self) -> Result<Vec<MuxRecord>> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < MUX_HEADER_LEN {
                return Ok(out);
            }
            let class = MuxClass::from_tag(self.buf[0])?;
            let len = u32::from_le_bytes(self.buf[1..5].try_into().expect("checked")) as usize;
            if len > MUX_MAX_PAYLOAD {
                return Err(Error::Oversized {
                    got: len,
                    limit: MUX_MAX_PAYLOAD,
                });
            }
            if self.buf.len() < MUX_HEADER_LEN + len {
                return Ok(out);
            }
            let enqueued_ms = u64::from_le_bytes(self.buf[5..13].try_into().expect("checked"));
            let seq = u64::from_le_bytes(self.buf[13..21].try_into().expect("checked"));
            let payload = self.buf[MUX_HEADER_LEN..MUX_HEADER_LEN + len].to_vec();
            self.buf.drain(0..MUX_HEADER_LEN + len);
            out.push(MuxRecord {
                class,
                seq,
                enqueued_ms,
                payload,
            });
        }
    }
}

/// Header size of a flattened [`EncodedFrame`]: id, flags, timestamp.
pub const FRAME_RECORD_HEADER_LEN: usize = 4 + 1 + 4;

/// Flatten an [`EncodedFrame`] for the reliable video path.
#[must_use]
pub fn encode_frame_record(frame: &EncodedFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_RECORD_HEADER_LEN + frame.data.len());
    out.extend_from_slice(&frame.frame_id.to_le_bytes());
    out.push(u8::from(frame.keyframe));
    out.extend_from_slice(&frame.timestamp_ms.to_le_bytes());
    out.extend_from_slice(&frame.data);
    out
}

/// Inverse of [`encode_frame_record`].
///
/// # Errors
///
/// Returns [`Error::Invalid`] if the record is truncated, carries no payload,
/// or sets an unknown flag bit.
pub fn decode_frame_record(bytes: &[u8]) -> Result<EncodedFrame> {
    if bytes.len() <= FRAME_RECORD_HEADER_LEN {
        return Err(Error::Invalid("frame record truncated or empty".into()));
    }
    let frame_id = u32::from_le_bytes(bytes[0..4].try_into().expect("checked"));
    let flags = bytes[4];
    if flags & !1 != 0 {
        return Err(Error::Invalid(format!("unknown frame record flags {flags:#x}")));
    }
    let timestamp_ms = u32::from_le_bytes(bytes[5..9].try_into().expect("checked"));
    Ok(EncodedFrame {
        frame_id,
        keyframe: flags & 1 != 0,
        timestamp_ms,
        data: bytes[FRAME_RECORD_HEADER_LEN..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::protocol::{encode_framed, ControlMsg};

    #[test]
    fn framed_reader_splits_and_rejoins_arbitrary_chunking() {
        let a = encode_framed(&ControlMsg::RequestKeyframe).expect("encode");
        let b = encode_framed(&ControlMsg::Ping { token: 7 }).expect("encode");
        let mut wire = a.clone();
        wire.extend_from_slice(&b);

        // Feed one byte at a time: nothing may surface until it is whole.
        let mut r = FramedReader::control();
        let mut got = Vec::new();
        for byte in &wire {
            r.push_bytes(&[*byte]);
            got.extend(r.drain().expect("drain"));
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], a[4..].to_vec());
        assert_eq!(got[1], b[4..].to_vec());
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn strip_length_prefix_round_trips_and_validates() {
        let framed = encode_framed(&ControlMsg::Ping { token: 42 }).expect("encode");
        let body = strip_length_prefix(&framed, MAX_CONTROL_MSG).expect("strip");
        assert_eq!(body, framed[4..].to_vec());
        let back: ControlMsg =
            directdesk_shared::protocol::decode_strict(&body).expect("decode bare body");
        assert!(matches!(back, ControlMsg::Ping { token: 42 }));

        // Doubly framed input is exactly what this exists to prevent.
        assert!(directdesk_shared::protocol::decode_strict::<ControlMsg>(&framed).is_err());

        assert!(strip_length_prefix(&[0, 0], MAX_CONTROL_MSG).is_err());
        let mut truncated = framed.clone();
        truncated.pop();
        assert!(strip_length_prefix(&truncated, MAX_CONTROL_MSG).is_err());
    }

    #[test]
    fn framed_reader_rejects_a_bad_prefix() {
        let mut r = FramedReader::new(16);
        r.push_bytes(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert!(r.drain().is_err());
    }

    #[test]
    fn mux_records_round_trip_across_split_writes() {
        let one = encode_mux_record(MuxClass::Control, 1, 10, b"ctrl");
        let two = encode_mux_record(MuxClass::Video, 2, 11, &[7u8; 300]);
        let mut wire = one;
        wire.extend_from_slice(&two);

        let mut r = MuxReader::new();
        let mut got = Vec::new();
        for chunk in wire.chunks(7) {
            r.push_bytes(chunk);
            got.extend(r.drain().expect("drain"));
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].class, MuxClass::Control);
        assert_eq!(got[0].payload, b"ctrl".to_vec());
        assert_eq!(got[1].class, MuxClass::Video);
        assert_eq!(got[1].seq, 2);
        assert_eq!(got[1].enqueued_ms, 11);
        assert_eq!(got[1].payload.len(), 300);
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn mux_reader_rejects_garbage() {
        let mut r = MuxReader::new();
        r.push_bytes(&[9u8; MUX_HEADER_LEN]);
        assert!(r.drain().is_err(), "unknown class tag");

        let mut r = MuxReader::new();
        let mut bad = vec![MuxClass::Video.tag()];
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        bad.extend_from_slice(&[0u8; 16]);
        r.push_bytes(&bad);
        assert!(r.drain().is_err(), "absurd payload length");
    }

    #[test]
    fn frame_records_round_trip() {
        let frame = EncodedFrame {
            frame_id: 4_000_000_000,
            keyframe: true,
            timestamp_ms: 123_456,
            data: vec![1, 2, 3, 4, 5],
        };
        let back = decode_frame_record(&encode_frame_record(&frame)).expect("decode");
        assert_eq!(back.frame_id, frame.frame_id);
        assert!(back.keyframe);
        assert_eq!(back.timestamp_ms, frame.timestamp_ms);
        assert_eq!(back.data, frame.data);

        assert!(decode_frame_record(&[0u8; FRAME_RECORD_HEADER_LEN]).is_err());
    }
}
