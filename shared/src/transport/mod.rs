//! Transport: QUIC endpoints, framed control I/O, datagram reassembly, and the
//! session driver that turns a connection into typed channels.
//!
//! # Channel layout
//!
//! Three logical channels ride one QUIC connection, each mapped to the QUIC
//! primitive that matches its delivery requirement:
//!
//! | Channel | QUIC primitive | Why |
//! |---------|----------------|-----|
//! | [`Channel::Control`] | bidirectional stream, priority [`PRIORITY_CONTROL`] | Auth, session control. Must never be dropped or reordered. |
//! | [`Channel::Input`] | bidirectional stream, priority [`PRIORITY_INPUT`] | A dropped key-up leaves a key stuck down, so input is reliable — but it must overtake video, hence the priority. |
//! | [`Channel::Media`] | unreliable datagrams | A late video frame is worthless; retransmitting it costs latency for nothing. Loss is handled by asking for a keyframe. |
//!
//! Both streams are opened by the *client*, in that order, and each begins with
//! a one-byte tag (the postcard encoding of [`Channel`]) so the host can label
//! them without depending on accept ordering.
//!
//! # The TCP/TLS fallback
//!
//! [`tcp`] presents the same [`session::Session`] interface over a single
//! TLS-over-TCP stream, for networks that blackhole UDP. All three channels
//! share that one stream, so the priority policy that QUIC gets from stream
//! priorities has to be implemented explicitly — see the module docs there.
//! [`race`] is the staggered "happy eyeballs" racer that decides which of the
//! two (or of a longer ladder) actually gets used.
//!
//! # Layout
//!
//! - [`quic`] — endpoint construction, TLS wiring, framed stream I/O.
//! - [`tcp`] — the TCP/TLS fallback: handshake, multiplexing, priority sender.
//! - [`race`] — staggered route racing and the honest route report.
//! - [`reassembly`] — datagram fragments back into [`crate::video::EncodedFrame`]s.
//! - [`session`] — the async driver and the transport-agnostic [`session::Session`] trait.

pub mod quic;
pub mod race;
pub mod reassembly;
pub mod session;
pub mod tcp;

use crate::error::{Error, Result};
use crate::protocol::Channel;

/// Stream priority for the control channel. Highest: a `Bye` or a keyframe
/// request must not queue behind anything.
pub const PRIORITY_CONTROL: i32 = 32;

/// Stream priority for the input channel. Above the default (0) so input
/// overtakes any bulk stream traffic.
pub const PRIORITY_INPUT: i32 = 16;

/// Stream priority for bulk background traffic: lossless refinement tiles.
///
/// Below the default (0) so tiles yield to every other stream. Note this orders
/// tiles only against *streams* — it does **not** order them against the video
/// datagrams, which share the same congestion window. That coupling has to be
/// throttled in the application; priority alone will not do it.
pub const PRIORITY_BULK: i32 = -16;

// Bulk must never be able to overtake input or control. If someone "tidies"
// these numbers, this is the tripwire.
const _: () = assert!(PRIORITY_BULK < PRIORITY_INPUT);
const _: () = assert!(PRIORITY_INPUT < PRIORITY_CONTROL);

/// Encode the one-byte channel tag written at the head of each stream.
pub fn channel_tag(channel: Channel) -> Result<u8> {
    let bytes = postcard::to_stdvec(&channel)?;
    match bytes.as_slice() {
        [b] => Ok(*b),
        other => Err(Error::Protocol(format!(
            "channel tag is {} bytes",
            other.len()
        ))),
    }
}

/// Decode a one-byte channel tag.
pub fn parse_channel_tag(tag: u8) -> Result<Channel> {
    crate::protocol::decode_strict::<Channel>(&[tag])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_tags_roundtrip() {
        for ch in [Channel::Control, Channel::Input, Channel::Media] {
            let tag = channel_tag(ch).unwrap();
            assert_eq!(parse_channel_tag(tag).unwrap(), ch);
        }
    }

    #[test]
    fn channel_tags_are_distinct() {
        let c = channel_tag(Channel::Control).unwrap();
        let i = channel_tag(Channel::Input).unwrap();
        let m = channel_tag(Channel::Media).unwrap();
        assert_ne!(c, i);
        assert_ne!(i, m);
        assert_ne!(c, m);
    }

    #[test]
    fn unknown_channel_tag_rejected() {
        assert!(parse_channel_tag(0xFE).is_err());
    }

    #[test]
    fn input_outranks_default_but_not_control() {
        const { assert!(PRIORITY_INPUT > 0) };
        const { assert!(PRIORITY_CONTROL > PRIORITY_INPUT) };
    }
}
