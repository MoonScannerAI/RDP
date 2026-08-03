//! In-process, headless, deterministic integration harness for DirectDesk.
//!
//! # What this is
//!
//! A simulated host core and client core wired to each other through
//! [`directdesk_shared::netsim`], driven by a single virtual clock. No sockets,
//! no GPU, no threads, no real time. The transport is the netsim's two-endpoint
//! link; the encoder and decoder are the shared null passthroughs; the injector
//! is the shared mock. Everything between them — fragmentation, reassembly,
//! keyframe demand, control framing, bitrate adaptation, the fallback
//! multiplexer — is the code the product actually runs.
//!
//! # Why it is deterministic
//!
//! Three properties together make a run bit-repeatable:
//!
//! * the netsim decides loss, jitter and reordering at *send* time from a
//!   seeded splitmix64, so the delivery schedule is fixed the moment a packet
//!   is handed over;
//! * nothing in the harness reads a clock, spawns a task, or iterates a
//!   `HashMap` — the tick loop is the only source of time and every collection
//!   is a `Vec`; and
//! * frame content is a pure function of the frame id, so what is on the wire
//!   never depends on how far the run has got.
//!
//! [`assert_repeatable`] exists to keep that honest: it runs the same scenario
//! twice and compares the two transcripts element for element.
//!
//! # Shape of a scenario
//!
//! ```no_run
//! use directdesk_shared::netsim::NetParams;
//! use directdesk_tests::{Route, SimConfig, Sim};
//!
//! let mut params = NetParams::perfect();
//! params.latency_ms = 200;
//! let mut sim = Sim::new(SimConfig::new(params, 0xD1CE_0001))?;
//! sim.run_to(6_000)?;
//!
//! let presented = sim.log().presented();
//! assert!(presented.iter().all(|p| p.hash_ok && p.route == Route::Datagram));
//! # Ok::<(), directdesk_shared::Error>(())
//! ```
//!
//! Every assertion in the matrix is made against [`EventLog`], never against a
//! side effect or a lack of panics.

pub mod client;
pub mod config;
pub mod event;
pub mod frames;
pub mod framing;
pub mod host;
pub mod mux;
pub mod pump;
pub mod sim;

pub use client::{PresentSlot, SimClient};
pub use config::{
    SimConfig, STREAM_CONTROL_C2H, STREAM_CONTROL_H2C, STREAM_FALLBACK_H2C, STREAM_INPUT,
};
pub use event::{EventLog, MuxDelivery, Presented, Route, SimEvent};
pub use frames::{fnv1a64, synth_body, synth_payload, verify_payload};
pub use framing::{
    decode_frame_record, encode_frame_record, encode_mux_record, strip_length_prefix, FramedReader,
    MuxClass, MuxReader, MuxRecord, FRAME_RECORD_HEADER_LEN, MUX_HEADER_LEN,
};
pub use host::{input_seq, SimHost};
pub use mux::{MuxConfig, MuxStats, ReliableMux};
pub use pump::PumpCtx;
pub use sim::{run, Sim};

/// Panic unless two transcripts are identical, naming the first divergence.
///
/// A matrix row asserts on a transcript; running a row twice and passing both
/// logs through here asserts that the transcript is a property of the
/// configuration and the seed alone. Any accidental dependence on address
/// ordering, hash iteration, or wall-clock time shows up as a named mismatch
/// rather than as a test that fails once a fortnight on CI.
///
/// # Panics
///
/// Panics if the logs differ in length or in any element.
pub fn assert_logs_match(a: &EventLog, b: &EventLog, label: &str) {
    assert_eq!(
        a.len(),
        b.len(),
        "{label}: two runs produced {} and {} events",
        a.len(),
        b.len()
    );
    for (i, (x, y)) in a.events().iter().zip(b.events()).enumerate() {
        assert_eq!(x, y, "{label}: transcripts diverge at event {i}");
    }
}

/// Assertion helpers shared by the matrix rows.
pub mod assertions {
    use crate::event::Presented;

    /// Panic unless presented frame ids strictly increase.
    ///
    /// Latest-wins may skip ids — a frame superseded before anyone looked at it
    /// is deliberately dropped — but it may never go backwards, and it may
    /// never show the same frame twice.
    ///
    /// # Panics
    ///
    /// Panics on the first non-increasing pair.
    pub fn assert_strictly_increasing(presented: &[Presented], label: &str) {
        for pair in presented.windows(2) {
            assert!(
                pair[1].frame_id > pair[0].frame_id,
                "{label}: frame {} presented after {} (at {} ms)",
                pair[1].frame_id,
                pair[0].frame_id,
                pair[1].at_ms
            );
        }
    }

    /// Panic unless every presented frame verified against its content hash.
    ///
    /// # Panics
    ///
    /// Panics naming the first frame that failed.
    pub fn assert_all_hashes_ok(presented: &[Presented], label: &str) {
        if let Some(bad) = presented.iter().find(|p| !p.hash_ok) {
            panic!(
                "{label}: frame {} presented at {} ms failed its content hash",
                bad.frame_id, bad.at_ms
            );
        }
    }

    /// Panic unless presented ids are contiguous with no gaps.
    ///
    /// Only meaningful on a lossless row, where nothing may be skipped.
    ///
    /// # Panics
    ///
    /// Panics on the first gap.
    pub fn assert_contiguous(presented: &[Presented], label: &str) {
        for pair in presented.windows(2) {
            assert_eq!(
                pair[1].frame_id,
                pair[0].frame_id + 1,
                "{label}: gap between frames {} and {} at {} ms",
                pair[0].frame_id,
                pair[1].frame_id,
                pair[1].at_ms
            );
        }
    }

    /// Largest capture-to-present age in the slice, or zero if it is empty.
    #[must_use]
    pub fn max_age_ms(presented: &[Presented]) -> u64 {
        presented.iter().map(|p| p.age_ms).max().unwrap_or(0)
    }

    /// Mean capture-to-present age in the slice, or zero if it is empty.
    #[must_use]
    pub fn mean_age_ms(presented: &[Presented]) -> f64 {
        if presented.is_empty() {
            return 0.0;
        }
        let total: u64 = presented.iter().map(|p| p.age_ms).sum();
        total as f64 / presented.len() as f64
    }
}
