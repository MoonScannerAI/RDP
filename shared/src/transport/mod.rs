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
//! # The TCP/TLS fallback and the racer are parked
//!
//! `tcp` presents the same [`session::Session`] interface over a single
//! TLS-over-TCP stream, for networks that blackhole UDP. All three channels
//! share that one stream, so the priority policy that QUIC gets for free from
//! stream priorities is implemented explicitly there — see the module docs.
//! `race` is the staggered "happy eyeballs" racer intended to decide which of
//! the two (or of a longer ladder) actually gets used.
//!
//! Both are written and tested. **Neither is selected by any binary.** The
//! client connects over QUIC and only over QUIC — see the `TODO(race)` note in
//! `client/src/net.rs` — so nothing the product runs ever constructs a
//! `tcp::TcpSession` or calls `race::race_routes`. They are therefore parked
//! behind the `transport-tcp` and `transport-race` cargo features, both off by
//! default, and a default build of host/client/service does not contain them.
//!
//! Their tests still run in the normal suite: the gates below are
//! `#[cfg(any(feature = "...", test))]`, and the `test` disjunct is
//! load-bearing rather than redundant. See the `[features]` block in
//! `shared/Cargo.toml` for why, and `parked_modules` in `shared/src/lib.rs` for
//! the tripwire that stops the mechanism being "simplified" away.
//!
//! So read the two paragraphs above as a description of a design that exists in
//! source form, not of what a running DirectDesk does today. Adopting either
//! module means enabling its feature *and* adding a call site.
//!
//! # Layout
//!
//! - [`quic`] — endpoint construction, TLS wiring, framed stream I/O.
//! - `tcp` — *(feature `transport-tcp`, off by default)* the TCP/TLS fallback:
//!   handshake, multiplexing, priority sender.
//! - `race` — *(feature `transport-race`, off by default)* staggered route
//!   racing and the honest route report.
//! - [`reassembly`] — datagram fragments back into [`crate::video::EncodedFrame`]s.
//! - [`session`] — the async driver and the transport-agnostic [`session::Session`] trait.

pub mod quic;
// Parked behind cargo features — see the module docs above. The `test` disjunct
// keeps ~37 tests in the default suite while dropping ~3800 lines from every
// product binary; a bare `#[cfg(feature = "...")]` here would delete those tests
// without failing anything. `shared/src/lib.rs`'s `parked_modules` is the
// tripwire that turns that silent loss into a compile error.
#[cfg(any(feature = "transport-race", test))]
pub mod race;
pub mod reassembly;
pub mod session;
#[cfg(any(feature = "transport-tcp", test))]
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
