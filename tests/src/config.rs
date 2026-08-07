//! Scenario configuration and the channel map both cores agree on.

use directdesk_shared::netsim::NetParams;
use directdesk_shared::protocol::QualityMode;
use directdesk_shared::transport::reassembly::ReassemblyConfig;

use crate::tiles::TileSim;

/// Client → host, reliable: input events. Mirrors [`Channel::Input`].
///
/// [`Channel::Input`]: directdesk_shared::protocol::Channel::Input
pub const STREAM_INPUT: u32 = 1;
/// Client → host, reliable: session control. Mirrors [`Channel::Control`].
///
/// [`Channel::Control`]: directdesk_shared::protocol::Channel::Control
pub const STREAM_CONTROL_C2H: u32 = 2;
/// Host → client, reliable: session control.
pub const STREAM_CONTROL_H2C: u32 = 3;
/// Host → client, reliable: the multiplexed TCP-fallback channel.
pub const STREAM_FALLBACK_H2C: u32 = 4;

/// Everything a scenario row varies.
///
/// Defaults describe a 30 fps stream of four-fragment frames on a 5 ms tick,
/// which is the shape most rows want; a row overrides only what it is about.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Link conditions at the start of the run. Rows that change conditions
    /// mid-run call [`crate::Sim::set_params`] between phases.
    pub params: NetParams,
    /// Seed for the netsim RNG. Distinct per row so no two rows share a
    /// loss/jitter schedule.
    pub seed: u64,
    /// Virtual milliseconds per driver tick. Both cores are pumped once per
    /// tick, host first.
    pub tick_ms: u64,
    /// Capture interval; 33 ms is ~30 fps.
    pub frame_interval_ms: u64,
    /// Encoded frame size in bytes, including the content-hash prefix.
    pub frame_bytes: usize,
    /// How often the client writes an input event.
    pub input_interval_ms: u64,
    /// How often the client pings for an RTT sample.
    pub ping_interval_ms: u64,
    /// Nominal length of a client loss-measurement window. Windows always close
    /// on a frame boundary, so the real length is this rounded up to the next
    /// new frame id.
    pub stats_interval_ms: u64,
    /// Quality mode, which picks the adaptor's floor/ceiling/step.
    pub quality: QualityMode,
    /// Reassembler tuning.
    pub reassembly: ReassemblyConfig,
    /// Whether the client may ask to move video onto the reliable path when the
    /// datagram path goes silent.
    ///
    /// Off by default, and deliberately so: a transient outage is not a blocked
    /// network, and a row testing outage recovery must not have its subject
    /// swapped out from under it halfway through. Only the fallback row turns
    /// this on.
    pub fallback_enabled: bool,
    /// How long the client tolerates silence on the datagram path before asking
    /// to fall back to the reliable one.
    pub fallback_probe_ms: u64,
    /// Byte budget per tick on the fallback mux.
    pub mux_bytes_per_tick: usize,
    /// Video backlog the fallback mux will hold before shedding the oldest.
    pub mux_max_video_backlog: usize,
    /// FEC block size for datagram video fragmentation, mirroring
    /// `host/src/net.rs`'s `FEC_BLOCK_SIZE`. `0` (the default) disables FEC
    /// entirely and fragments via [`directdesk_shared::video::fragment_frame`],
    /// which is every existing row's behavior, unchanged.
    pub fec_block: u8,
    /// A one-shot oversized-frame-plus-tail-loss injection (the B3 hardening
    /// scenario). `None` for every row except the one that exercises it.
    pub burst_injection: Option<BurstInjection>,
    /// Mirrors the client's `KeyframeGate` (`client/src/pipeline.rs`, B1): when
    /// set, the simulated client refuses to hand a delta frame to the decoder
    /// unless its id is exactly one past the last frame it admitted, closing
    /// the gap only on a keyframe. Off by default so it can never perturb a
    /// row that isn't testing it.
    pub gate_delta_after_gap: bool,
    /// Refinement tiles and the one congestion window they share with video
    /// (see [`crate::tiles`]). `None` — the default — leaves the host on the
    /// pre-existing path exactly: no capacity model, no status windows, and the
    /// adaptor driven straight from each client loss report, which is what
    /// every other row in the matrix asserts against.
    pub tiles: Option<TileSim>,
}

/// A single deliberately damaged frame: encoded oversized, then has specific
/// fragments withheld from the wire before it is sent.
///
/// Two independent kinds of damage, so a test can combine them the way a real
/// scene-change spike does — some fragments lost to ordinary background
/// conditions scattered through the frame, plus a burst of consecutive loss
/// landing on the *tail* of the transmission (a congested link or an eviction
/// at the sender both look like this):
///
/// * `drop_data_indices` — arbitrary data fragment indices withheld
///   regardless of position, one per FEC block, so that block needs its own
///   parity fragment to recover.
/// * `tail_drop_frags` — the last N fragments of the wire order
///   [`fragment_frame_fec`](directdesk_shared::video::fragment_frame_fec)
///   actually returns are withheld. Before B3 that wire order was every data
///   fragment followed by every parity fragment, so any tail burst destroyed
///   *all* of a frame's redundancy at once; after B3 each block's parity
///   immediately follows its own data, so the same burst can cost at most the
///   trailing block.
#[derive(Debug, Clone)]
pub struct BurstInjection {
    /// The captured frame this applies to (matches `EncodedFrame::frame_id`).
    pub frame_id: u32,
    /// Encoded size to use for this one frame, standing in for the 6-18x
    /// scene-change spike the field bug report measured.
    pub size_bytes: usize,
    /// Data fragment indices to withhold, independent of the tail burst.
    pub drop_data_indices: Vec<u16>,
    /// Fragments to withhold, counted back from the end of the wire order.
    pub tail_drop_frags: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            params: NetParams::perfect(),
            seed: 1,
            tick_ms: 5,
            frame_interval_ms: 33,
            frame_bytes: 4_000,
            input_interval_ms: 100,
            ping_interval_ms: 250,
            stats_interval_ms: 500,
            quality: QualityMode::Balanced,
            reassembly: ReassemblyConfig::default(),
            fallback_enabled: false,
            fallback_probe_ms: 1_000,
            mux_bytes_per_tick: 400,
            mux_max_video_backlog: 3,
            fec_block: 0,
            burst_injection: None,
            gate_delta_after_gap: false,
            tiles: None,
        }
    }
}

impl SimConfig {
    /// A configuration with the given link conditions and seed, defaults for
    /// everything else.
    #[must_use]
    pub fn new(params: NetParams, seed: u64) -> Self {
        Self {
            params,
            seed,
            ..Self::default()
        }
    }

    /// Upper bound on capture-to-present latency, in virtual milliseconds.
    ///
    /// Valid only for a row with **no loss and no reordering**, where a frame is
    /// presented on the first client tick at or after its slowest fragment
    /// lands:
    ///
    /// * `latency_ms` — base one-way delay.
    /// * `jitter_ms` — the largest positive offset any one fragment can draw.
    ///   All fragments of a frame are sent in the same virtual millisecond, so
    ///   the frame completes when the unluckiest one arrives.
    /// * `tick_ms` — the client only looks at the wire on tick boundaries, so
    ///   an arrival can wait up to one tick to be observed.
    ///
    /// Reassembly itself adds nothing: the fragments are concatenated in the
    /// same pump that completes the frame, and presentation happens in that
    /// pump too. Under loss this bound does not apply — a lost fragment costs a
    /// whole frame, and recovery costs a keyframe round trip.
    #[must_use]
    pub fn present_age_bound_ms(&self) -> u64 {
        self.params.latency_ms + self.params.jitter_ms + self.tick_ms
    }

    /// Upper bound on one-way input delivery latency, in virtual milliseconds.
    ///
    /// Input rides a reliable stream, which the netsim never drops or reorders,
    /// so the only terms are the same three: base latency, the worst jitter
    /// draw, and one tick of host polling quantisation.
    #[must_use]
    pub fn input_latency_bound_ms(&self) -> u64 {
        self.params.latency_ms + self.params.jitter_ms + self.tick_ms
    }
}
