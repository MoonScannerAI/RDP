//! Receiver-side **network-domain** audio jitter buffer: a bounded reorder
//! window, an adaptive depth controller, and a clock-drift corrector.
//!
//! Pure, deterministic, and entirely clock-injected — no Windows APIs, no
//! device handles, no I/O. Every timed decision takes `now_ms` from the caller,
//! so the whole module is exercisable at thousands of times real time in a unit
//! test, which is the only way the drift behaviour below can be tested at all.
//!
//! # Two buffers, two jobs — this is the network one
//!
//! There are two elastic buffers between the host's speakers and the client's,
//! and conflating them is the classic way to build an audio path that is both
//! laggy and glitchy:
//!
//! * The **device-domain** buffer is WASAPI's own render endpoint buffer. Its
//!   fill level is `IAudioClient::GetCurrentPadding`, its job is to keep the DAC
//!   fed across OS scheduling jitter, and it is not this module's business.
//! * The **network-domain** buffer is this one. Its job is to absorb the
//!   *network's* variance — reordering, delay spikes, loss — and to hand the
//!   decoder a monotonically increasing, gap-annotated sequence of access units.
//!
//! Nothing here reads a device clock or a device fill level. The caller feeds
//! [`AudioJitterBuffer::observe`] a monotonic millisecond timestamp and acts on
//! what it returns.
//!
//! # Why drift correction is not optional
//!
//! The host's capture crystal and the client's DAC crystal are independent
//! pieces of quartz. Consumer parts are specified to roughly ±25 ppm, so a
//! host/client pair can plausibly differ by 50 ppm. At 50 ppm the two clocks
//! diverge by
//!
//! ```text
//! 50e-6 × 3600 s = 0.18 s = 180 ms per hour
//! ```
//!
//! A buffer with a *fixed* depth therefore fills or empties by 180 ms every
//! hour. Starting at the 80 ms seed depth in a sixteen-packet (~341 ms) window,
//! it hits an edge in around an hour and a half — and then keeps hitting it, on
//! a schedule, for the rest of the session. That is the failure that gets
//! reported as "it works fine for an hour and then goes weird", and it is
//! invisible to every test shorter than the drift period, which is why the
//! long synthetic runs at the bottom of this file exist and why one of them
//! deliberately runs *without* the corrector to show the buffer overflowing on
//! schedule.
//!
//! The fix is to let the buffer's depth be adjusted by removing or inserting
//! whole frames. [`DriftCorrector`] does exactly that, at most once per 2 s
//! window.
//!
//! ## Why the thresholds are what they are
//!
//! One correction is one AAC-LC frame: 1024 samples, which at 48 kHz is
//! 21.333 ms. At most one per 2000 ms window gives a correction authority of
//!
//! ```text
//! 21.333 ms / 2000 ms = 0.010667 = 10,667 ppm
//! ```
//!
//! That is **213× more authority than the ~50 ppm** any real crystal pair
//! needs. The controller is therefore designed to be essentially always idle:
//! at 50 ppm it fires roughly once every
//!
//! ```text
//! 21.333 ms ÷ (180 ms/hour) ≈ 0.118 hours ≈ 7.1 minutes
//! ```
//!
//! One 21 ms discontinuity every seven minutes is inaudible in practice, and
//! the enormous headroom is what lets the deadband be wide (±40 ms) and the
//! EWMA slow. A narrow deadband or a fast average would make the controller
//! chase ordinary network jitter, which *is* audible — it would fire several
//! times a minute, and each firing is a click. The deadband is set by what we
//! can afford to ignore, not by what we are capable of correcting, precisely
//! because we are capable of correcting 200× more than we will ever need.
//!
//! # Wrapping sequence numbers
//!
//! `seq` is a `u32` that wraps. Every ordering decision in this file goes
//! through [`crate::transport::reassembly::is_newer`] — the crate's single
//! RFC-1982 serial comparison, already public and already tested. There is no
//! second implementation here, deliberately: commit 9a1c90a was a hand-rolled
//! wrapping predicate that turned out to be subtly one-sided, and one such
//! predicate per codebase is the correct number.
//!
//! # Known limitation: a wild forward `seq` jump
//!
//! A peer that emits a `seq` far ahead of the stream (a host bug — not an
//! injected datagram, since QUIC authenticates these) is treated as newer,
//! buffered, and eventually delivered, at which point `next_seq` jumps to it and
//! every subsequent *genuine* packet is classified [`DiscardReason::Late`] and
//! dropped, wedging audio for the rest of the session.
//!
//! This is deliberately **not** guarded here, unlike
//! [`crate::transport::reassembly`]'s `max_forward_jump`, because the wire
//! format already carries the designed answer: a legitimate renumbering comes
//! with [`super::FLAG_DISCONTINUITY`] set, and the discontinuity path is
//! specified to be authoritative with no heuristic layered on top. Closing the
//! wedge would also need a tenth [`JitterStats`] counter for its rejections. If
//! it is judged worth closing, that is the shape it should take.

use super::{AudioFrame, AudioPacket};
use crate::error::{Error, Result};
use crate::transport::reassembly::is_newer;

/// Duration of one AAC-LC access unit at 48 kHz: 1024 samples ÷ 48 kHz.
///
/// 48 kHz stereo is the overwhelmingly common Windows shared-mode mix (see
/// [`super::AudioFormat::Stereo48k`]), so it is the default. A 44.1 kHz stream's
/// frames are really 23.22 ms, so this default *under*-states occupancy by 9% on
/// such a stream — which makes the drift corrector marginally more conservative
/// and the prebuffer marginally deeper in wall-clock terms, and changes nothing
/// else. A caller that knows the negotiated format may set
/// [`JitterConfig::frame_ms`] exactly.
pub const DEFAULT_FRAME_MS: f32 = 1024.0 / 48.0;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tuning knobs for [`AudioJitterBuffer`] and its two controllers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JitterConfig {
    /// Reorder window depth, in packets. Default 16 (~341 ms at 21.3 ms/frame).
    ///
    /// A hard bound on how much audio the network-domain buffer can hold, and
    /// therefore on how much reordering it can absorb. `0` is treated as `1` so
    /// that forward progress is always possible.
    ///
    /// Sized so the specified [`Self::target_min_ms`]..[`Self::target_max_ms`]
    /// range is actually reachable rather than merely stated: at 16 packets the
    /// window holds `(16 - 1) × frame_ms` ≈ 320 ms after the one slot
    /// [`AudioJitterBuffer::prebuffer_ms`] reserves, which clears the 300 ms
    /// ceiling with room to spare. A shallower window silently clamps every
    /// target above its own capacity — see that function's docs for what
    /// happens when it does.
    pub window_depth: usize,
    /// How long to hold up delivery waiting for a missing `seq` before declaring
    /// it lost. Default 40 ms (~2 frames).
    ///
    /// Deliberately well below [`Self::target_min_ms`]: waiting longer than the
    /// buffer's own floor would mean the wait itself causes the underrun it is
    /// trying to prevent. The window filling to [`Self::window_depth`]
    /// short-circuits the wait — at that point we are holding the maximum and
    /// cannot afford to hold anything longer.
    pub reorder_wait_ms: u64,
    /// Duration of one packet's audio. Default [`DEFAULT_FRAME_MS`].
    pub frame_ms: f32,
    /// Withhold delivery after a start, a reset, a discontinuity or an underrun
    /// until the window holds the target depth. Default `true`.
    ///
    /// This is what makes [`Self::target_start_ms`] mean anything. Once playback
    /// is running, occupancy is set purely by the *rate* difference between the
    /// arriving stream and the consuming DAC, so the only moment anything can
    /// choose the operating depth is before the first packet goes out;
    /// thereafter [`DriftCorrector`] maintains it.
    ///
    /// A caller doing its own device-domain prebuffering (WASAPI's render buffer
    /// already is one) may set this `false` and take packets the instant they
    /// are in order.
    pub prebuffer: bool,
    /// Initial target depth in ms. Default 80.
    pub target_start_ms: u32,
    /// Floor for the target depth. Default 60.
    pub target_min_ms: u32,
    /// Ceiling for the target depth. Default 300.
    pub target_max_ms: u32,
    /// Added to the target on an underrun. Default 20.
    pub underrun_step_ms: u32,
    /// Minimum interval between two underrun-driven raises. Default 1000.
    ///
    /// See [`DepthController::observe`] for why an unrate-limited raise turns
    /// one network hiccup into a permanent 220 ms of added latency. Set to `0`
    /// for unlimited raising.
    pub underrun_raise_min_interval_ms: u64,
    /// Subtracted from the target after a clean interval. Default 5.
    pub decay_step_ms: u32,
    /// How long conditions must stay clean before the target decays. Default
    /// 10_000.
    pub decay_after_ms: u64,
    /// Drift sampling interval, and therefore the minimum interval between two
    /// drift corrections. Default 2000.
    pub drift_interval_ms: u64,
    /// Half-width of the drift deadband, in ms. Default 40.
    pub drift_deadband_ms: f32,
    /// EWMA weight on each new drift sample. Default 0.25 (~8 s time constant at
    /// a 2 s sampling interval).
    ///
    /// Heavy smoothing is free here: the quantity being tracked moves at
    /// 180 ms/hour, so nothing is lost by averaging over seconds, and rejecting
    /// transient occupancy swings is the entire point.
    pub drift_alpha: f32,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            window_depth: 16,
            reorder_wait_ms: 40,
            frame_ms: DEFAULT_FRAME_MS,
            prebuffer: true,
            target_start_ms: 80,
            target_min_ms: 60,
            target_max_ms: 300,
            underrun_step_ms: 20,
            underrun_raise_min_interval_ms: 1_000,
            decay_step_ms: 5,
            decay_after_ms: 10_000,
            drift_interval_ms: 2_000,
            drift_deadband_ms: 40.0,
            drift_alpha: 0.25,
        }
    }
}

impl JitterConfig {
    /// Reject settings that would make the buffer silently stop working.
    ///
    /// `window_depth == 0` is tolerated (clamped to 1). The rest are refused,
    /// because each one produces *silence* rather than an error: a non-positive
    /// `frame_ms` makes every occupancy measurement zero, an out-of-range
    /// `drift_alpha` makes the EWMA diverge or freeze, and an inverted target
    /// range makes the clamp in [`DepthController`] meaningless.
    pub fn validate(&self) -> Result<()> {
        // NaN fails every ordered comparison, so each check leads with
        // `!is_finite()` rather than relying on the range test to catch it.
        if !self.frame_ms.is_finite() || self.frame_ms <= 0.0 {
            return Err(Error::Invalid(
                "frame_ms must be finite and positive".into(),
            ));
        }
        if !self.drift_alpha.is_finite() || self.drift_alpha <= 0.0 || self.drift_alpha > 1.0 {
            return Err(Error::Invalid("drift_alpha must be in (0, 1]".into()));
        }
        if !self.drift_deadband_ms.is_finite() || self.drift_deadband_ms < 0.0 {
            return Err(Error::Invalid(
                "drift_deadband_ms must be finite and non-negative".into(),
            ));
        }
        if self.target_min_ms > self.target_max_ms {
            return Err(Error::Invalid(
                "target_min_ms must not exceed target_max_ms".into(),
            ));
        }
        if self.drift_interval_ms == 0 {
            return Err(Error::Invalid("drift_interval_ms must be non-zero".into()));
        }
        Ok(())
    }

    /// The most audio the window can physically hold, in ms.
    #[must_use]
    pub fn window_capacity_ms(&self) -> f32 {
        self.window_depth.max(1) as f32 * self.frame_ms
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Cumulative counters for one receiver's jitter buffer.
///
/// **This type is local-only and must stay that way.** It is deliberately not
/// `Serialize`/`Deserialize` and must never be folded into
/// [`crate::stats::ConnStats`], whose byte layout is pinned by the anti-brick
/// suite: adding a field there changes the postcard encoding of every stats
/// message on the wire and breaks every already-deployed peer. If these numbers
/// need to reach the far end, they go in a *new*, separately versioned message,
/// not by widening the one that is already load-bearing.
///
/// The push counters partition every [`AudioJitterBuffer::push`] call exactly
/// once. With no discontinuities in the stream (which clear the window and so
/// retire packets without any counter moving), that gives a conservation law the
/// property tests assert directly:
///
/// ```text
/// received == duplicate + late + delivered + overflow + window length
/// ```
///
/// `lost` is *not* part of that partition: it counts sequence numbers that were
/// never pushed at all, so it can only ever be inferred, never observed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    /// Packets handed to [`AudioJitterBuffer::push`], accepted or not.
    pub received: u64,
    /// Packets handed out by [`AudioJitterBuffer::pop`].
    pub delivered: u64,
    /// Sequence numbers skipped over by a loss declaration — packets that never
    /// arrived, or arrived after their slot had already been given up on.
    pub lost: u64,
    /// Packets whose `seq` was already in the window, or was the one just
    /// delivered.
    pub duplicate: u64,
    /// Packets older than the buffer's read point: too late to be useful.
    pub late: u64,
    /// Packets evicted from a full window to make room.
    pub overflow: u64,
    /// Times [`AudioJitterBuffer::pop`] was asked for audio and had none.
    ///
    /// An *empty* window counts once per event, not once per silent period,
    /// because the prebuffer re-arms and suppresses further counting until
    /// playback resumes. A window that is merely waiting out the reorder wait
    /// counts once per poll, but that is bounded by
    /// [`JitterConfig::reorder_wait_ms`].
    pub underrun: u64,
    /// Times the drift corrector asked for a frame to be dropped.
    pub drift_drops: u64,
    /// Times the drift corrector asked for a frame of silence to be inserted.
    pub drift_inserts: u64,
}

// ---------------------------------------------------------------------------
// Depth controller
// ---------------------------------------------------------------------------

/// Adaptive target depth for the network-domain buffer.
///
/// Deliberately shaped like [`crate::adapt::BitrateAdaptor`]: injected clock,
/// one `observe` per evidence window, `Option<u32>` returned only when the
/// target actually moved. Same idiom, same testing story, and callers that
/// already drive the bitrate adaptor need no new pattern.
///
/// The policy is asymmetric on purpose. Raising rests on hard evidence (an
/// underrun is a *fact*: audio was needed and was not there) but costs the user
/// latency, so it steps 20 ms at a time and is rate limited. Lowering rests on
/// no evidence at all — "nothing bad happened for ten seconds" — so it creeps
/// down 5 ms at a time, and any single underrun cancels the clean streak.
#[derive(Debug, Clone)]
pub struct DepthController {
    target_ms: u32,
    min_ms: u32,
    max_ms: u32,
    step_ms: u32,
    raise_min_interval_ms: u64,
    decay_step_ms: u32,
    decay_after_ms: u64,
    /// Start of the current uninterrupted clean streak.
    clean_since_ms: Option<u64>,
    /// `None` means "has never raised", so the very first raise is allowed even
    /// at `now_ms == 0`. Same reason `Reassembler::last_keyframe_request_ms` is
    /// an `Option`: a sentinel of `0` silently suppresses the first event of any
    /// session that starts at time zero, which is every test and some real
    /// callers.
    last_raise_ms: Option<u64>,
}

impl DepthController {
    /// Build a controller seeded from `config` and clamped into its own range.
    #[must_use]
    pub fn new(config: &JitterConfig) -> Self {
        let min_ms = config.target_min_ms;
        let max_ms = config.target_max_ms.max(min_ms);
        Self {
            target_ms: config.target_start_ms.clamp(min_ms, max_ms),
            min_ms,
            max_ms,
            step_ms: config.underrun_step_ms,
            raise_min_interval_ms: config.underrun_raise_min_interval_ms,
            decay_step_ms: config.decay_step_ms,
            decay_after_ms: config.decay_after_ms,
            clean_since_ms: None,
            last_raise_ms: None,
        }
    }

    /// Current target depth in ms. Always within
    /// `[target_min_ms, target_max_ms]`.
    #[must_use]
    pub fn target_ms(&self) -> u32 {
        self.target_ms
    }

    /// Feed one observation window. `underran` is true when the buffer was asked
    /// for audio and had none since the previous call. Returns
    /// `Some(new_target_ms)` only when the target changed.
    ///
    /// # Why the raise is rate limited
    ///
    /// The bare policy is "on underrun, `target += 20`". The trouble is that
    /// underruns arrive in *bursts*: once the buffer is empty it stays empty
    /// until the network refills it, so a single 250 ms hiccup produces a dozen
    /// consecutive underruns roughly 21 ms apart. Unlimited, that one transient
    /// walks the target from the 80 ms seed straight to the 300 ms ceiling — a
    /// permanent, very audible 220 ms of added latency bought with one blip, and
    /// recoverable only at 5 ms per 10 s, which is over seven minutes.
    ///
    /// Limiting raises to one per second keeps the response proportionate:
    /// sustained trouble still climbs at 20 ms/s and reaches the ceiling in
    /// 11 s, while a blip costs 20 ms. This mirrors
    /// [`crate::adapt::BitrateAdaptor::observe`], which limits its decreases the
    /// same way and for the same reason. Set
    /// [`JitterConfig::underrun_raise_min_interval_ms`] to `0` for the unlimited
    /// behaviour.
    pub fn observe(&mut self, now_ms: u64, underran: bool) -> Option<u32> {
        if underran {
            // Any underrun cancels the clean streak, whether or not it is
            // allowed to raise the target right now. Otherwise a burst that the
            // rate limit swallows would leave the streak intact and the target
            // could *decay* in the middle of an outage.
            self.clean_since_ms = None;

            let allowed = match self.last_raise_ms {
                None => true,
                Some(prev) => now_ms.saturating_sub(prev) >= self.raise_min_interval_ms,
            };
            if !allowed {
                return None;
            }
            let next = self
                .target_ms
                .saturating_add(self.step_ms)
                .clamp(self.min_ms, self.max_ms);
            if next == self.target_ms {
                return None;
            }
            self.target_ms = next;
            self.last_raise_ms = Some(now_ms);
            return Some(next);
        }

        let since = *self.clean_since_ms.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= self.decay_after_ms && self.target_ms > self.min_ms {
            let next = self
                .target_ms
                .saturating_sub(self.decay_step_ms)
                .max(self.min_ms);
            self.target_ms = next;
            // Restart the streak, so the next decay is another full interval
            // away. This is what makes "at most one decay per clean window" true
            // regardless of how often the caller calls `observe`.
            self.clean_since_ms = Some(now_ms);
            return Some(next);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Drift corrector
// ---------------------------------------------------------------------------

/// The shallow edge of the deadband is never allowed below this many frames.
///
/// See [`DriftCorrector::observe`]. Occupancy is bounded below by zero while the
/// deadband is symmetric in milliseconds, so at low targets the nominal shallow
/// edge falls under one frame and the corrector can only act on a buffer that is
/// already empty — which is an underrun, the louder failure it exists to
/// prevent. 1.5 frames preserves the shallow-side behaviour the 80 ms seed
/// target already has (act with one frame left) across the whole target range,
/// and binds only for targets under 72 ms.
pub const MIN_SHALLOW_EDGE_FRAMES: f32 = 1.5;

/// What the drift corrector wants the caller to do about the buffer's depth.
///
/// This is a **command, not advice**. [`DriftCorrector`] credits itself for the
/// audio it just told the caller to remove or add (see
/// [`DriftCorrector::observe`]), so a caller that ignores a correction will see
/// the corrector under-react until its average catches up on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftCorrection {
    /// The buffer is running deep: one whole frame of audio must disappear.
    ///
    /// *Where* it disappears is the caller's choice — discard the next popped
    /// packet, or drop a decoded PCM frame. Either way exactly one frame's worth
    /// of audio leaves the pipeline in one DAC period, which is what the
    /// corrector accounts for.
    DropFrame,
    /// The buffer is running shallow: one frame period of silence must be played
    /// without consuming a packet.
    InsertSilence,
}

/// Corrects for the independent crystals at each end of the session.
///
/// See the module docs for the arithmetic: at 50 ppm the clocks diverge 180 ms
/// per hour, this controller can correct 10,667 ppm, and so it is expected to
/// fire about once every seven minutes and otherwise sit idle.
#[derive(Debug, Clone)]
pub struct DriftCorrector {
    interval_ms: u64,
    deadband_ms: f32,
    alpha: f32,
    frame_ms: f32,
    ewma_ms: Option<f32>,
    last_sample_ms: Option<u64>,
}

impl DriftCorrector {
    /// Build a corrector from `config`. It starts unseeded.
    #[must_use]
    pub fn new(config: &JitterConfig) -> Self {
        Self {
            interval_ms: config.drift_interval_ms.max(1),
            deadband_ms: config.drift_deadband_ms,
            alpha: config.drift_alpha,
            frame_ms: config.frame_ms,
            ewma_ms: None,
            last_sample_ms: None,
        }
    }

    /// Smoothed occupancy estimate in ms, or `None` before the first sample.
    #[must_use]
    pub fn ewma_ms(&self) -> Option<f32> {
        self.ewma_ms
    }

    /// The occupancy band the corrector will not act inside, for `target_ms`.
    ///
    /// Exposed so a caller (or a test) can see the effect of
    /// [`MIN_SHALLOW_EDGE_FRAMES`] rather than having to re-derive it.
    #[must_use]
    pub fn deadband_bounds(&self, target_ms: u32) -> (f32, f32) {
        let target = target_ms as f32;
        let low = (target - self.deadband_ms).max(MIN_SHALLOW_EDGE_FRAMES * self.frame_ms);
        (low, target + self.deadband_ms)
    }

    /// Forget everything and re-seed on the next sample.
    ///
    /// Called whenever occupancy changes for a reason that is not drift: a
    /// discontinuity empties the window, and feeding that into the average would
    /// look like an enormous negative drift and provoke a burst of silence
    /// insertions to "fix" something that was never broken.
    pub fn reset(&mut self) {
        self.ewma_ms = None;
        self.last_sample_ms = None;
    }

    /// Offer an occupancy observation. Samples at most once per
    /// [`JitterConfig::drift_interval_ms`] regardless of how often it is called,
    /// and returns at most one correction per sample.
    ///
    /// The cadence is enforced here rather than left to the caller so that a
    /// caller which polls every DAC period (~21 ms) gets the same behaviour as
    /// one that polls every two seconds. A controller whose gain depends on its
    /// call rate is a controller that will be mistuned by the first refactor of
    /// its caller.
    ///
    /// # Anti-windup
    ///
    /// After firing, the corrector adjusts its own average by one frame, as if
    /// the correction had already taken effect. Without this, one genuine
    /// excursion produces a *burst* of corrections: the average lags real
    /// occupancy by several samples, so it stays outside the deadband and fires
    /// again and again while the buffer it is correcting is already back in
    /// range — several clicks where one was needed, and an over-corrected buffer
    /// afterwards.
    ///
    /// The credit is exact in both directions because a correction always moves
    /// exactly one frame across the buffer boundary:
    /// [`DriftCorrection::DropFrame`] consumes two packets in one DAC period
    /// instead of one, and [`DriftCorrection::InsertSilence`] consumes none.
    /// That holds whether the caller discards the extra frame before or after
    /// decoding it.
    ///
    /// # The asymmetric deadband
    ///
    /// The deadband is symmetric in milliseconds, but occupancy is not: it is
    /// bounded below by zero and quantised to whole frames. At the 60 ms floor
    /// target the nominal shallow edge is 20 ms — under one 21.3 ms frame — so
    /// the buffer would have to be *already empty* before the corrector could
    /// act, and an empty buffer is an underrun. [`MIN_SHALLOW_EDGE_FRAMES`]
    /// floors that edge; see [`Self::deadband_bounds`].
    pub fn observe(
        &mut self,
        now_ms: u64,
        fill_ms: f32,
        target_ms: u32,
    ) -> Option<DriftCorrection> {
        match self.last_sample_ms {
            // The seeding sample sets the average and nothing else. One sample
            // is not evidence of drift, and at stream start occupancy is near
            // zero, so acting on it would guarantee a spurious silence insertion
            // in the first seconds of every session.
            None => {
                self.last_sample_ms = Some(now_ms);
                self.ewma_ms = Some(fill_ms);
                return None;
            }
            Some(prev) if now_ms.saturating_sub(prev) < self.interval_ms => return None,
            Some(_) => {}
        }
        self.last_sample_ms = Some(now_ms);

        let ewma = match self.ewma_ms {
            Some(prev) => self.alpha * fill_ms + (1.0 - self.alpha) * prev,
            None => fill_ms,
        };
        self.ewma_ms = Some(ewma);

        let (low, high) = self.deadband_bounds(target_ms);
        if ewma > high {
            self.ewma_ms = Some(ewma - self.frame_ms);
            return Some(DriftCorrection::DropFrame);
        }
        if ewma < low {
            self.ewma_ms = Some(ewma + self.frame_ms);
            return Some(DriftCorrection::InsertSilence);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Push outcome
// ---------------------------------------------------------------------------

/// Why a packet was not buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// This `seq` is already in the window, or is the one just delivered.
    Duplicate,
    /// This `seq` is behind the buffer's read point. Playing it would mean going
    /// backwards, so it is dropped.
    Late,
}

/// What [`AudioJitterBuffer::push`] did with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// Buffered. Nothing else for the caller to do.
    Buffered,
    /// Buffered, and the window was cleared first because this packet carried
    /// [`super::FLAG_DISCONTINUITY`].
    ///
    /// The caller **must** flush its AAC decoder before feeding it the next
    /// popped packet. An AAC-LC decoder carries filterbank overlap state from
    /// the previous frame; running it across a capture gap of unknown length
    /// produces a smeared artefact rather than a clean cut.
    BufferedFlushDecoder,
    /// Dropped without being buffered.
    Discarded(DiscardReason),
}

impl PushOutcome {
    /// True when the caller must flush its decoder before the next pop.
    #[must_use]
    pub fn needs_decoder_flush(self) -> bool {
        matches!(self, PushOutcome::BufferedFlushDecoder)
    }

    /// True when the packet entered the window.
    #[must_use]
    pub fn was_buffered(self) -> bool {
        !matches!(self, PushOutcome::Discarded(_))
    }
}

/// What [`AudioJitterBuffer::observe`] wants the caller to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JitterAdjust {
    /// `Some` only when the depth controller moved its target this call.
    /// Informational — the buffer has already applied it.
    pub target_ms: Option<u32>,
    /// `Some` when the caller must remove or insert one frame. See
    /// [`DriftCorrection`].
    pub drift: Option<DriftCorrection>,
}

// ---------------------------------------------------------------------------
// The buffer
// ---------------------------------------------------------------------------

/// Bounded reorder window with an adaptive target depth and drift correction.
///
/// # The two supported pacings, and what each caller owes
///
/// [`push`](Self::push) is always "once per arriving packet". What varies is
/// what drives [`pop`](Self::pop), and the two shapes are **not**
/// interchangeable:
///
/// * **DAC-paced.** `pop` once per frame period, off a real playback clock.
///   This is the textbook shape and the one [`DriftCorrection`]'s accounting is
///   written in ("one frame per DAC period"). Occupancy is then set purely by
///   the rate difference between the arriving stream and the consuming DAC,
///   which is exactly the quantity [`DriftCorrector`] exists to null out.
/// * **Packet-paced.** `pop` driven by arrivals, because the real playback
///   clock lives further downstream, behind a device buffer the caller meters
///   separately. This is what `directdesk_client`'s `AudioLoop` does, and it is
///   a legitimate shape — but only under the contract below.
///
/// The naive packet-paced caller — "one `push`, then at most one `pop`, per
/// arrival" — is wrong, and wrong in two directions at once, because it makes
/// occupancy a **ratchet instead of a control loop**:
///
/// * Every period the buffer *withholds* is a push with no matching pop, so
///   occupancy rises by one packet and nothing ever brings it back down: such a
///   consumer has no way to take two packets in one period. One 40 ms reorder
///   wait costs ~2 packets of permanent added latency, and a lossy link walks
///   occupancy to [`JitterConfig::window_depth`] and leaves it there for the
///   session.
/// * Symmetrically, every arrival the buffer *discards* is a pop with no
///   matching push. A stream carrying duplicates — the host's redundancy mode
///   re-sends packet N−1 behind packet N, which is 50% duplicates by design —
///   then runs two pops per accepted push, drains the window to empty in a few
///   periods, starves, re-arms the prebuffer, refills in silence, and repeats.
///   Audio chopped several times a second by the very feature meant to repair
///   the link.
///
/// A packet-paced caller therefore owes two things:
///
/// 1. **Pop only for a packet that was accepted** — see
///    [`PushOutcome::was_buffered`]. A discard is not a period of audio.
/// 2. **Keep popping while [`buffered_ms`](Self::buffered_ms) is above
///    [`target_ms`](Self::target_ms)**, so a withheld period can be caught up
///    on the arrival that resolves it. Draining is lossless: it moves audio
///    from this buffer into the caller's device buffer, it discards nothing.
///    Together with (1) this pins occupancy to the depth target instead of
///    letting it wander, which is what the DAC-paced caller gets for free.
///
/// [`observe`](Self::observe) is once per period either way — it consumes the
/// underrun flag, so a skipped call loses the one event the depth controller
/// most needs to hear about.
///
/// # Why `push` takes no clock
///
/// Every other `push` in this crate takes `now_ms`; this one does not, because
/// the reorder window has exactly one timed decision — how long to wait for a
/// missing `seq` — and that decision is only ever made at [`pop`](Self::pop),
/// where somebody is actually waiting for the audio. A `now_ms` on `push` would
/// be an unused parameter that every later reader has to prove is unused.
#[derive(Debug)]
pub struct AudioJitterBuffer {
    config: JitterConfig,
    /// Unordered; bounded by `config.window_depth`. At this size a linear scan
    /// beats any ordered structure and is inherently deterministic.
    window: Vec<AudioFrame>,
    /// The `seq` the buffer wants next. Seeded by the first accepted packet, and
    /// thereafter always `last_delivered + 1`.
    next_seq: Option<u32>,
    /// The `seq` most recently handed out.
    last_delivered: Option<u32>,
    /// When the current gap at `next_seq` was first noticed, for the reorder
    /// wait.
    gap_since_ms: Option<u64>,
    /// True while withholding delivery to reach the target depth.
    prebuffering: bool,
    /// Set by `pop` on a starve, consumed by `observe`.
    underran_since_observe: bool,
    depth: DepthController,
    drift: DriftCorrector,
    stats: JitterStats,
}

impl AudioJitterBuffer {
    /// Build a buffer. `config.window_depth` of `0` is clamped to `1`.
    #[must_use]
    pub fn new(config: JitterConfig) -> Self {
        Self {
            window: Vec::with_capacity(config.window_depth.max(1) + 1),
            next_seq: None,
            last_delivered: None,
            gap_since_ms: None,
            prebuffering: config.prebuffer,
            underran_since_observe: false,
            depth: DepthController::new(&config),
            drift: DriftCorrector::new(&config),
            stats: JitterStats::default(),
            config,
        }
    }

    /// The configuration this buffer was built with.
    #[must_use]
    pub fn config(&self) -> &JitterConfig {
        &self.config
    }

    /// Cumulative counters. See [`JitterStats`] — local only, never on the wire.
    #[must_use]
    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    /// Current target depth, in ms.
    #[must_use]
    pub fn target_ms(&self) -> u32 {
        self.depth.target_ms()
    }

    /// Packets currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.window.len()
    }

    /// True when nothing is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// The `seq` the buffer will deliver next, if it has seen anything yet.
    #[must_use]
    pub fn next_seq(&self) -> Option<u32> {
        self.next_seq
    }

    /// True once the prebuffer has filled and delivery has begun.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !self.prebuffering && self.last_delivered.is_some()
    }

    /// Buffered audio in ms: packet count × [`JitterConfig::frame_ms`].
    ///
    /// Counts *packets held*, not the span from `next_seq` to the newest `seq`.
    /// A gap in the middle of the window is a hole that will be concealed, not
    /// audio that will be played, so counting it would tell the drift corrector
    /// the buffer is deeper than it is — exactly backwards, since a gappy window
    /// is the situation in which running out is most likely.
    #[must_use]
    pub fn buffered_ms(&self) -> f32 {
        self.window.len() as f32 * self.config.frame_ms
    }

    /// Effective window depth, never zero.
    fn depth_packets(&self) -> usize {
        self.config.window_depth.max(1)
    }

    /// How full the window must get before delivery starts.
    ///
    /// Clamped to what the window can physically hold. At the shipped default
    /// (16 packets, ~341 ms) that clamp is inactive across the whole configured
    /// target range: `(window_depth - 1) × frame_ms` ≈ 320 ms comfortably
    /// clears the 300 ms ceiling. The clamp itself stays regardless, because
    /// `window_depth` is a caller-settable knob — nothing stops a caller (or a
    /// future default) from choosing one shallower than its own target range
    /// again, and without the clamp that is a livelock: a target driven to the
    /// ceiling by a bad patch of network would demand an occupancy the window
    /// can never reach — `pop` returns `None` forever, which counts an
    /// underrun, which raises a target that is already at its ceiling. Silence
    /// for the rest of the session, with no error anywhere. The clamp also
    /// leaves one slot free, so that reaching the prebuffer level does not
    /// simultaneously trip the window-is-full loss rule.
    ///
    /// The honest consequence, for any configuration where it still binds, is
    /// that a target above roughly `(window_depth - 1) × frame_ms` is
    /// aspirational: the window, not the controller, bounds real occupancy.
    /// `prebuffer_never_demands_more_than_the_window_can_hold` reconstructs such
    /// a configuration deliberately, so the clamp stays exercised even though
    /// the shipped default no longer needs it.
    fn prebuffer_ms(&self) -> f32 {
        let capacity = self.depth_packets().saturating_sub(1) as f32 * self.config.frame_ms;
        (self.depth.target_ms() as f32).min(capacity.max(self.config.frame_ms))
    }

    /// Offer an arriving packet to the window.
    ///
    /// Order of decisions, and why:
    ///
    /// 1. **Discontinuity first, unconditionally.** The flag is the sender
    ///    saying "the stream you were following no longer exists". It is
    ///    authoritative and takes no heuristic: the window is cleared,
    ///    `next_seq` becomes this packet's `seq`, and — crucially —
    ///    `last_delivered` is cleared too. Keeping the old `last_delivered`
    ///    would let the late/duplicate guard silently veto the reset whenever
    ///    the new numbering happened to start behind the old one, which is
    ///    exactly the case the reset exists for (an encoder restart puts `seq`
    ///    back to 0).
    /// 2. **Duplicate**, against the window and against the packet just
    ///    delivered.
    /// 3. **Late**, against `next_seq`, using
    ///    [`crate::transport::reassembly::is_newer`].
    /// 4. Otherwise accept, then evict if that pushed the window over depth.
    ///
    /// Checking duplicate before late matters for the packet equal to
    /// `last_delivered`: it is behind `next_seq`, so the late test would also
    /// catch it, but filing a retransmitted copy of the frame we just played
    /// under "late" would hide a different phenomenon in the same counter.
    pub fn push(&mut self, packet: &AudioPacket<'_>) -> PushOutcome {
        self.stats.received += 1;

        if packet.discontinuity {
            self.window.clear();
            self.next_seq = Some(packet.seq);
            self.last_delivered = None;
            self.gap_since_ms = None;
            self.prebuffering = self.config.prebuffer;
            // Occupancy just went to zero for a reason that has nothing to do
            // with anyone's crystal.
            self.drift.reset();
            self.window.push(AudioFrame::from_packet(packet));
            return PushOutcome::BufferedFlushDecoder;
        }

        if self.last_delivered == Some(packet.seq)
            || self.window.iter().any(|p| p.seq == packet.seq)
        {
            self.stats.duplicate += 1;
            return PushOutcome::Discarded(DiscardReason::Duplicate);
        }

        if let Some(next) = self.next_seq {
            // Accept `seq >= next` in serial order. `is_newer` is false for
            // equality, so the wanted packet itself needs the explicit test.
            if packet.seq != next && !is_newer(packet.seq, next) {
                self.stats.late += 1;
                return PushOutcome::Discarded(DiscardReason::Late);
            }
        }

        self.window.push(AudioFrame::from_packet(packet));
        if self.next_seq.is_none() {
            // The first packet of the stream defines where we start. There is no
            // "correct" starting point to recover: a receiver that joins mid
            // stream starts wherever it joined.
            self.next_seq = Some(packet.seq);
        }
        if self.window.len() > self.depth_packets() {
            self.evict_oldest();
        }
        PushOutcome::Buffered
    }

    /// Take the next packet, if one is due.
    ///
    /// Returns `None` in three distinct situations, which the caller can tell
    /// apart via [`stats`](Self::stats) and [`is_running`](Self::is_running) but
    /// need not: filling the prebuffer, waiting out the reorder window for a
    /// straggler, or starving. All three mean "play silence this period".
    ///
    /// The loss rule: if `next_seq` is not present, wait for
    /// [`JitterConfig::reorder_wait_ms`] **or** until the window is full,
    /// whichever comes first, then declare every `seq` from `next_seq` up to the
    /// window's oldest lost in a single step and deliver that oldest packet. One
    /// jump, not one per missing packet, so a 500-packet outage costs one
    /// decision rather than 500 extra periods of silence.
    pub fn pop(&mut self, now_ms: u64) -> Option<AudioFrame> {
        if self.window.is_empty() {
            if self.is_running() {
                self.starve();
                // Refill to depth before resuming rather than resuming on the
                // very next packet — otherwise one starve becomes a run of them,
                // each raising the target.
                self.prebuffering = self.config.prebuffer;
            }
            self.gap_since_ms = None;
            return None;
        }

        if self.prebuffering {
            if self.buffered_ms() < self.prebuffer_ms() {
                return None;
            }
            self.prebuffering = false;
        }

        // `push` seeds `next_seq` on the first accepted packet, so a non-empty
        // window always has one. Recovering rather than `expect`ing keeps a
        // future refactor from turning an invariant slip into a panic on the
        // client's audio thread.
        let next = match self.next_seq {
            Some(next) => next,
            None => {
                let seq = self.window[0].seq;
                self.next_seq = Some(seq);
                seq
            }
        };

        if let Some(idx) = self.window.iter().position(|p| p.seq == next) {
            let packet = self.window.swap_remove(idx);
            self.deliver(packet.seq);
            self.gap_since_ms = None;
            return Some(packet);
        }

        let since = *self.gap_since_ms.get_or_insert(now_ms);
        let waited = now_ms.saturating_sub(since) >= self.config.reorder_wait_ms;
        let full = self.window.len() >= self.depth_packets();
        if !waited && !full {
            // Still hoping. From the DAC's point of view this is a starve just
            // the same — it asked and got nothing — so it feeds the depth
            // controller. It does *not* re-arm the prebuffer: the window is not
            // empty, and refilling from a partly full window would throw away
            // the wait we are in the middle of.
            self.starve();
            return None;
        }

        let idx = self
            .oldest_index()
            .unwrap_or(0)
            .min(self.window.len().saturating_sub(1));
        let packet = self.window.swap_remove(idx);
        let skipped = packet.seq.wrapping_sub(next);
        self.stats.lost = self.stats.lost.saturating_add(u64::from(skipped));
        self.deliver(packet.seq);
        self.gap_since_ms = None;
        Some(packet)
    }

    /// Run both controllers. Call once per DAC period with a monotonic clock.
    ///
    /// The drift corrector is skipped while the buffer is not
    /// [`running`](Self::is_running): a prebuffering window is filling, not
    /// drifting, and sampling it would seed the average near zero and provoke a
    /// silence insertion in the first seconds of every session.
    pub fn observe(&mut self, now_ms: u64) -> JitterAdjust {
        let underran = std::mem::replace(&mut self.underran_since_observe, false);
        let target_ms = self.depth.observe(now_ms, underran);

        let drift = if self.is_running() {
            let fill_ms = self.buffered_ms();
            let target_now = self.depth.target_ms();
            self.drift.observe(now_ms, fill_ms, target_now)
        } else {
            None
        };
        match drift {
            Some(DriftCorrection::DropFrame) => self.stats.drift_drops += 1,
            Some(DriftCorrection::InsertSilence) => self.stats.drift_inserts += 1,
            None => {}
        }

        JitterAdjust { target_ms, drift }
    }

    /// Drop everything and start over, as for a new session on the same buffer.
    ///
    /// Keeps the learned depth target and the cumulative counters: the target is
    /// what this session learned about this link and is still true, and the
    /// counters are a session total by definition.
    pub fn reset(&mut self) {
        self.window.clear();
        self.next_seq = None;
        self.last_delivered = None;
        self.gap_since_ms = None;
        self.prebuffering = self.config.prebuffer;
        self.underran_since_observe = false;
        self.drift.reset();
    }

    fn deliver(&mut self, seq: u32) {
        self.stats.delivered += 1;
        self.last_delivered = Some(seq);
        self.next_seq = Some(seq.wrapping_add(1));
    }

    fn starve(&mut self) {
        self.stats.underrun += 1;
        self.underran_since_observe = true;
    }

    /// Index of the window's oldest packet in serial order.
    ///
    /// Every window member satisfies `seq >= next_seq` in serial order (`push`
    /// enforces it), so `seq - next_seq` is a genuine distance in `0..2^31` and
    /// plain integer comparison on those offsets is total and unambiguous. That
    /// is why this does not fold `is_newer` pairwise: a pairwise fold over an
    /// intransitive relation has no defined answer if the inputs ever span more
    /// than half the id space, whereas an offset from a common origin always
    /// does.
    fn oldest_index(&self) -> Option<usize> {
        let next = self.next_seq?;
        self.window
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| p.seq.wrapping_sub(next))
            .map(|(i, _)| i)
    }

    /// Evict the oldest packet to make room.
    ///
    /// "Oldest" is a property of `seq`, not of arrival time, so a very late
    /// arrival that is itself the oldest thing in the window is the packet that
    /// goes — which is right: it is the one whose playback deadline is nearest
    /// and whose neighbours are already gone.
    fn evict_oldest(&mut self) {
        if let Some(idx) = self.oldest_index() {
            self.window.swap_remove(idx);
            self.stats.overflow += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Imported here rather than at module scope: the buffer itself never names
    // a concrete format (it carries whatever the packet declared), so a
    // production-scope import would be genuinely unused. `check.ps1` runs
    // clippy without `--all-targets`, so it lints only non-test code and would
    // report exactly that.
    use crate::audio::AudioFormat;
    use proptest::prelude::*;
    use std::collections::HashSet;

    static PAYLOAD: [u8; 4] = [0xA5, 0x5A, 0x0F, 0xF0];

    fn pkt(seq: u32) -> AudioPacket<'static> {
        AudioPacket {
            seq,
            capture_ms: seq.wrapping_mul(21),
            discontinuity: false,
            format: AudioFormat::Stereo48k,
            payload: &PAYLOAD,
        }
    }

    fn disc(seq: u32) -> AudioPacket<'static> {
        AudioPacket {
            discontinuity: true,
            ..pkt(seq)
        }
    }

    /// Ordering behaviour is independent of the prebuffer, and mixing the two
    /// into one fixture makes every ordering test also a latency test. The
    /// prebuffer gets its own tests below.
    fn plain() -> JitterConfig {
        JitterConfig {
            prebuffer: false,
            ..JitterConfig::default()
        }
    }

    /// Pop until the window is empty, advancing the clock past the reorder wait
    /// whenever the buffer withholds.
    ///
    /// Polling at a *fixed* `now_ms` would stall on the first gap forever: the
    /// wait starts at the poll that notices the gap, so it can never expire
    /// against a clock that does not move. That is real behaviour, not a test
    /// artefact — it is why the timing tests below poll twice.
    fn drain(buf: &mut AudioJitterBuffer, start_ms: u64) -> Vec<u32> {
        let mut out = Vec::new();
        let mut now = start_ms;
        let step = buf.config().reorder_wait_ms + 1;
        for _ in 0..10_000 {
            if let Some(p) = buf.pop(now) {
                out.push(p.seq);
            } else if buf.is_empty() {
                return out;
            } else {
                now += step;
            }
        }
        panic!("drain did not terminate — the buffer is withholding a non-empty window");
    }

    // -- reorder window ----------------------------------------------------

    /// The trivial case, pinned because everything else is a deviation from it.
    #[test]
    fn packets_arriving_in_order_are_delivered_in_order_with_no_loss() {
        let mut buf = AudioJitterBuffer::new(plain());
        for seq in 0..6 {
            assert_eq!(buf.push(&pkt(seq)), PushOutcome::Buffered);
        }
        assert_eq!(drain(&mut buf, 0), vec![0, 1, 2, 3, 4, 5]);
        let s = buf.stats();
        assert_eq!(s.delivered, 6);
        assert_eq!(s.lost, 0);
        assert_eq!(s.duplicate, 0);
        assert_eq!(s.late, 0);
        assert_eq!(s.overflow, 0);
    }

    /// A single swapped pair is what the reorder window is *for*: both packets
    /// must come out in the right order, and nothing may be declared lost.
    #[test]
    fn a_single_swapped_pair_is_repaired_without_declaring_loss() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(0));
        assert_eq!(buf.pop(0).unwrap().seq, 0);

        // 2 overtakes 1 on the wire.
        buf.push(&pkt(2));
        assert!(buf.pop(0).is_none(), "must hold 2 back and wait for 1");
        buf.push(&pkt(1));
        assert_eq!(buf.pop(1).unwrap().seq, 1);
        assert_eq!(buf.pop(1).unwrap().seq, 2);
        assert_eq!(buf.stats().lost, 0, "nothing was actually lost");
    }

    /// The wait is bounded. Held one millisecond short of it, released one
    /// millisecond past it — an off-by-one either way is invisible in ordinary
    /// traffic and shows up only as a permanent extra frame of latency.
    #[test]
    fn a_missing_packet_is_declared_lost_once_the_reorder_wait_expires() {
        let cfg = plain();
        let wait = cfg.reorder_wait_ms;
        let mut buf = AudioJitterBuffer::new(cfg);
        buf.push(&pkt(0));
        assert_eq!(buf.pop(0).unwrap().seq, 0);

        buf.push(&pkt(2)); // 1 never arrives
        assert!(buf.pop(100).is_none(), "the wait starts at the first miss");
        assert!(
            buf.pop(100 + wait - 1).is_none(),
            "one ms short of the wait must still hold"
        );
        let got = buf.pop(100 + wait).expect("the wait expired");
        assert_eq!(got.seq, 2);
        assert_eq!(buf.stats().lost, 1, "exactly seq 1 was declared lost");
        assert_eq!(buf.next_seq(), Some(3));
    }

    /// A full window cannot afford to wait: it is already holding the maximum,
    /// so the next arrival would evict something. Loss is declared immediately,
    /// with no regard for `reorder_wait_ms`.
    #[test]
    fn a_full_window_declares_loss_immediately_without_waiting() {
        let cfg = plain();
        let depth = cfg.window_depth;
        let mut buf = AudioJitterBuffer::new(cfg);
        buf.push(&pkt(0));
        assert_eq!(buf.pop(0).unwrap().seq, 0);

        // seq 1 is missing; fill the window from 2 upwards.
        for seq in 2..2 + depth as u32 {
            buf.push(&pkt(seq));
        }
        assert_eq!(buf.len(), depth);
        // `now_ms` has not moved, so the wait provably has not expired.
        let got = buf.pop(0).expect("a full window must not wait");
        assert_eq!(got.seq, 2);
        assert_eq!(buf.stats().lost, 1);
    }

    /// A gap far wider than the window is one jump, and every skipped sequence
    /// number is counted — not one, and not the window depth.
    #[test]
    fn a_gap_wider_than_the_window_is_one_jump_counting_every_skipped_seq() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(10));
        assert_eq!(buf.pop(0).unwrap().seq, 10);

        // A 500-packet outage, then the stream resumes.
        buf.push(&pkt(511));
        assert!(buf.pop(1_000).is_none(), "the wait starts here");
        let got = buf.pop(1_100).expect("the wait expired");
        assert_eq!(got.seq, 511);
        assert_eq!(buf.stats().lost, 500, "seqs 11..=510 inclusive");
        assert_eq!(buf.stats().delivered, 2, "one jump, not 500 pops");
    }

    /// `u32` sequence numbers wrap, and the window must not notice.
    ///
    /// A naive `<` comparison classifies seq 0 as older than `u32::MAX` and
    /// discards it as late, at which point the stream stops dead — the kind of
    /// bug that is only ever found in production.
    #[test]
    fn sequence_numbers_wrap_through_u32_max_without_stalling() {
        let mut buf = AudioJitterBuffer::new(plain());
        let base = u32::MAX - 2;
        for i in 0..6u32 {
            assert!(buf.push(&pkt(base.wrapping_add(i))).was_buffered());
        }
        assert_eq!(
            drain(&mut buf, 0),
            vec![u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 1, 2],
            "delivery must continue across the wrap"
        );
        assert_eq!(buf.stats().lost, 0);
        assert_eq!(buf.stats().late, 0);
    }

    /// Reordering *across* the wrap, which is where a hand-rolled predicate
    /// breaks even when the in-order wrap above happens to work.
    #[test]
    fn reordering_across_the_wrap_is_repaired_and_pre_wrap_stragglers_are_late() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(u32::MAX));
        assert_eq!(buf.pop(0).unwrap().seq, u32::MAX);

        // 1 overtakes 0, both on the far side of the wrap.
        buf.push(&pkt(1));
        assert!(buf.pop(0).is_none());
        buf.push(&pkt(0));
        assert_eq!(buf.pop(0).unwrap().seq, 0);
        assert_eq!(buf.pop(0).unwrap().seq, 1);

        // A straggler from before the wrap is behind the read point, not four
        // billion packets ahead of it.
        assert_eq!(
            buf.push(&pkt(u32::MAX - 5)),
            PushOutcome::Discarded(DiscardReason::Late)
        );
    }

    /// This module owns no serial arithmetic of its own. The property is
    /// asserted against the shared predicate directly, so that a future local
    /// re-derivation shows up as a disagreement here rather than as a stall in
    /// production a month later.
    #[test]
    fn ordering_agrees_with_the_shared_is_newer_predicate() {
        // The shared predicate's contract, restated where this module relies on
        // it. If these fail, `is_newer` changed under us.
        assert!(is_newer(0, u32::MAX), "wrap-forward is newer");
        assert!(!is_newer(u32::MAX, 0), "and not the other way");
        assert!(!is_newer(7, 7), "equality is not newer");
        assert!(
            is_newer(0x8000_0000, 1),
            "just inside the forward half-space"
        );
        assert!(!is_newer(0x8000_0001, 1), "just outside it");

        // And the buffer classifies by exactly that rule.
        for (delivered, arriving, expect_late) in [
            (u32::MAX, 0u32, false),
            (u32::MAX, u32::MAX - 1, true),
            (0u32, u32::MAX, true),
            (100u32, 101u32, false),
            (100u32, 99u32, true),
        ] {
            let mut buf = AudioJitterBuffer::new(plain());
            buf.push(&pkt(delivered));
            assert_eq!(buf.pop(0).unwrap().seq, delivered);
            let outcome = buf.push(&pkt(arriving));
            assert_eq!(
                outcome == PushOutcome::Discarded(DiscardReason::Late),
                expect_late,
                "arriving {arriving} after delivering {delivered}"
            );
        }
    }

    #[test]
    fn a_duplicate_of_a_buffered_packet_is_discarded() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(5));
        assert_eq!(
            buf.push(&pkt(5)),
            PushOutcome::Discarded(DiscardReason::Duplicate)
        );
        assert_eq!(buf.len(), 1, "the window must not hold it twice");
        assert_eq!(buf.stats().duplicate, 1);
        assert_eq!(drain(&mut buf, 0), vec![5]);
    }

    /// A retransmitted copy of the frame just played is a *duplicate*, not a
    /// late packet, even though it is equally behind the read point. Two
    /// different phenomena, two different counters.
    #[test]
    fn a_duplicate_of_the_last_delivered_packet_is_counted_as_a_duplicate() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(5));
        assert_eq!(buf.pop(0).unwrap().seq, 5);
        assert_eq!(
            buf.push(&pkt(5)),
            PushOutcome::Discarded(DiscardReason::Duplicate)
        );
        let s = buf.stats();
        assert_eq!(s.duplicate, 1);
        assert_eq!(s.late, 0, "not classified as late");
    }

    /// A packet that arrives after its slot was given up on must be dropped, not
    /// played: playing it would hand the decoder audio that goes backwards in
    /// time.
    #[test]
    fn a_late_packet_is_discarded_and_never_delivered() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(0));
        assert_eq!(buf.pop(0).unwrap().seq, 0);
        buf.push(&pkt(2));
        assert!(buf.pop(1_000).is_none());
        assert_eq!(buf.pop(1_100).unwrap().seq, 2, "1 declared lost");

        // 1 finally shows up.
        assert_eq!(
            buf.push(&pkt(1)),
            PushOutcome::Discarded(DiscardReason::Late)
        );
        assert!(buf.is_empty());
        assert_eq!(buf.stats().late, 1);
        assert_eq!(buf.stats().delivered, 2, "1 was never delivered");
    }

    // -- discontinuity -----------------------------------------------------

    #[test]
    fn discontinuity_clears_the_window_and_signals_a_decoder_flush() {
        let mut buf = AudioJitterBuffer::new(plain());
        for seq in 0..4 {
            buf.push(&pkt(seq));
        }
        assert_eq!(buf.pop(0).unwrap().seq, 0);
        assert_eq!(buf.len(), 3);

        let outcome = buf.push(&disc(900));
        assert_eq!(outcome, PushOutcome::BufferedFlushDecoder);
        assert!(
            outcome.needs_decoder_flush(),
            "the caller must be told to flush the AAC decoder"
        );
        assert_eq!(buf.len(), 1, "the stale window is gone");
        assert_eq!(buf.next_seq(), Some(900));

        let got = buf.pop(0).expect("the discontinuity packet itself");
        assert_eq!(got.seq, 900);
        assert!(
            got.discontinuity,
            "the flag survives into the popped packet"
        );
        assert_eq!(
            buf.stats().lost,
            0,
            "a discontinuity is a reset, not 896 lost packets"
        );
    }

    /// The flag is authoritative even when the new numbering starts *behind* the
    /// old one — an encoder restart resets `seq` to 0, and that is the case
    /// where a surviving `last_delivered` would silently veto the reset and
    /// discard the entire new stream as late. Forever.
    #[test]
    fn discontinuity_overrides_a_backwards_sequence_jump() {
        let mut buf = AudioJitterBuffer::new(plain());
        buf.push(&pkt(50_000));
        assert_eq!(buf.pop(0).unwrap().seq, 50_000);

        assert_eq!(buf.push(&disc(0)), PushOutcome::BufferedFlushDecoder);
        assert_eq!(buf.push(&pkt(1)), PushOutcome::Buffered);
        assert_eq!(drain(&mut buf, 0), vec![0, 1]);
        assert_eq!(buf.stats().late, 0, "the new stream must not read as late");
    }

    /// A discontinuity empties the window; the drift corrector must not read
    /// that as the buffer having drained away under it.
    #[test]
    fn discontinuity_reseeds_the_drift_corrector() {
        let cfg = JitterConfig {
            drift_interval_ms: 100,
            ..plain()
        };
        let mut buf = AudioJitterBuffer::new(cfg);
        for seq in 0..6 {
            buf.push(&pkt(seq));
        }
        let _ = buf.pop(0);
        buf.observe(0);
        buf.observe(1_000);
        assert!(buf.drift.ewma_ms().is_some(), "seeded while running");

        buf.push(&disc(1_000));
        assert!(
            buf.drift.ewma_ms().is_none(),
            "a discontinuity is not evidence about anyone's crystal"
        );
    }

    // -- overflow ----------------------------------------------------------

    #[test]
    fn overflow_evicts_the_oldest_packet_and_never_grows_the_window() {
        let cfg = plain();
        let depth = cfg.window_depth;
        let mut buf = AudioJitterBuffer::new(cfg);

        // seq 0 never arrives, so nothing can be popped in order.
        for seq in 1..=(depth as u32 + 3) {
            buf.push(&pkt(seq));
            assert!(
                buf.len() <= depth,
                "the window must never exceed its depth (at seq {seq})"
            );
        }
        assert_eq!(buf.len(), depth);
        assert_eq!(buf.stats().overflow, 3);

        // The three oldest went; the newest `depth` remain.
        let got = drain(&mut buf, 10_000);
        assert_eq!(got.first().copied(), Some(4), "1..=3 were evicted");
        assert_eq!(got.len(), depth);
    }

    /// A packet that arrives so late it is the oldest thing in a full window is
    /// the eviction victim — including when it is the arrival itself. It is the
    /// packet whose deadline is nearest and whose neighbours are already gone.
    #[test]
    fn overflow_evicts_by_sequence_order_not_by_arrival_order() {
        let cfg = JitterConfig {
            window_depth: 3,
            ..plain()
        };
        let mut buf = AudioJitterBuffer::new(cfg);
        buf.push(&pkt(10));
        assert_eq!(buf.pop(0).unwrap().seq, 10);

        for seq in [20, 21, 22] {
            buf.push(&pkt(seq));
        }
        assert_eq!(buf.len(), 3);
        // seq 11 is older than everything held: it is the one that goes.
        buf.push(&pkt(11));
        assert_eq!(buf.stats().overflow, 1);
        assert_eq!(drain(&mut buf, 10_000), vec![20, 21, 22]);
    }

    // -- prebuffer ---------------------------------------------------------

    #[test]
    fn delivery_waits_for_the_prebuffer_then_runs_freely() {
        let cfg = JitterConfig::default(); // prebuffer on, 80 ms target
        let needed = (cfg.target_start_ms as f32 / cfg.frame_ms).ceil() as u32;
        let mut buf = AudioJitterBuffer::new(cfg);

        for seq in 0..needed - 1 {
            buf.push(&pkt(seq));
            assert!(
                buf.pop(0).is_none(),
                "must not deliver at {} ms of a {} ms target",
                buf.buffered_ms(),
                buf.target_ms()
            );
        }
        buf.push(&pkt(needed - 1));
        assert_eq!(buf.pop(0).unwrap().seq, 0, "prebuffer reached, so run");
        assert!(buf.is_running());
        // And thereafter it delivers on demand.
        assert_eq!(buf.pop(0).unwrap().seq, 1);
        assert_eq!(
            buf.stats().underrun,
            0,
            "filling the prebuffer is not starving"
        );
    }

    /// The whole point of raising the default window to 16 packets: the
    /// specified [`JitterConfig::target_min_ms`]..[`JitterConfig::target_max_ms`]
    /// range must be reachable, not merely stated in a doc comment. Seeds the
    /// depth controller straight at the 300 ms ceiling and checks
    /// `prebuffer_ms` directly, rather than comparing capacities by hand,
    /// because that clamp is the mechanism that would silently shrink the
    /// range if the window were ever too shallow again — see
    /// `prebuffer_never_demands_more_than_the_window_can_hold` for exactly what
    /// that looks like.
    #[test]
    fn the_default_window_can_hold_the_whole_target_range() {
        let cfg = JitterConfig {
            target_start_ms: JitterConfig::default().target_max_ms,
            ..JitterConfig::default()
        };
        let buf = AudioJitterBuffer::new(cfg);
        assert_eq!(
            buf.prebuffer_ms(),
            cfg.target_max_ms as f32,
            "the window must be able to hold the full {} ms ceiling unclamped, \
             or the default window depth does not actually cover the specified \
             target range",
            cfg.target_max_ms
        );
    }

    /// The livelock guard.
    ///
    /// The target range can reach 300 ms regardless of how the window is
    /// configured; a window shallower than that is a configuration
    /// [`AudioJitterBuffer`] still has to survive. An unclamped prebuffer would
    /// demand an occupancy the window can never reach: `pop` returns `None`
    /// forever, which counts an underrun, which raises a target that is
    /// already at its ceiling. Permanent silence with no error anywhere — the
    /// same shape of livelock as commit 9a1c90a.
    ///
    /// The shipped default (16 packets, ~341 ms) no longer reaches this on its
    /// own — see `the_default_window_can_hold_the_whole_target_range` — so the
    /// scenario is rebuilt here with the *old* default depth of 8 (~170 ms,
    /// short of the 300 ms ceiling) to prove the clamp in `prebuffer_ms` still
    /// defends a window configured shallower than its own target range.
    #[test]
    fn prebuffer_never_demands_more_than_the_window_can_hold() {
        let cfg = JitterConfig {
            window_depth: 8,
            ..JitterConfig::default()
        };
        let depth = cfg.window_depth as u32;
        let mut buf = AudioJitterBuffer::new(cfg);

        // Each cycle fills the window, drains it dry, and reports the resulting
        // starve — one underrun *event* per cycle, spaced past the raise rate
        // limit so every one of them counts.
        let mut t = 0u64;
        let mut seq = 0u32;
        for _ in 0..40 {
            for _ in 0..depth {
                buf.push(&pkt(seq));
                seq = seq.wrapping_add(1);
            }
            while buf.pop(t).is_some() {}
            buf.observe(t);
            t += cfg.underrun_raise_min_interval_ms;
        }
        assert_eq!(
            buf.target_ms(),
            cfg.target_max_ms,
            "repeated underruns should have driven the target to the ceiling"
        );
        assert!(
            buf.target_ms() as f32 > cfg.window_capacity_ms(),
            "this test only means something if the target exceeds the window"
        );

        // The buffer must still deliver at a target it can never reach.
        let before = buf.stats().delivered;
        for _ in 0..40 {
            for _ in 0..depth {
                buf.push(&pkt(seq));
                seq = seq.wrapping_add(1);
            }
            while buf.pop(t).is_some() {}
            t += 21;
        }
        assert!(
            buf.stats().delivered >= before + 40 * u64::from(depth) - 40,
            "a target above the window's capacity must not deadlock delivery"
        );
    }

    /// An underrun refills to depth rather than resuming on the next packet;
    /// otherwise one starve becomes a run of them, each raising the target.
    #[test]
    fn an_underrun_rearms_the_prebuffer_and_counts_once() {
        let cfg = JitterConfig::default();
        let mut buf = AudioJitterBuffer::new(cfg);
        for seq in 0..5 {
            buf.push(&pkt(seq));
        }
        // The drain's final `None` is the starve: the window went empty while
        // the buffer was running.
        while buf.pop(0).is_some() {}
        assert!(buf.is_empty());
        assert_eq!(buf.stats().underrun, 1);
        assert!(!buf.is_running(), "the prebuffer re-armed");

        // Further empty polls are the same starve, not new ones.
        let _ = buf.pop(50);
        let _ = buf.pop(60);
        assert_eq!(
            buf.stats().underrun,
            1,
            "one starve event, not one per silent period"
        );

        // And a single packet is not the target depth.
        buf.push(&pkt(5));
        assert!(buf.pop(100).is_none());
    }

    // -- depth controller --------------------------------------------------

    #[test]
    fn depth_controller_raises_on_underrun_and_stops_at_the_ceiling() {
        let cfg = JitterConfig::default();
        let mut c = DepthController::new(&cfg);
        assert_eq!(c.target_ms(), cfg.target_start_ms);

        let mut t = 0u64;
        let mut last = c.target_ms();
        for _ in 0..40 {
            if let Some(v) = c.observe(t, true) {
                assert_eq!(v, last + cfg.underrun_step_ms, "one step per raise");
                last = v;
            }
            t += cfg.underrun_raise_min_interval_ms;
        }
        assert_eq!(c.target_ms(), cfg.target_max_ms, "capped at the ceiling");
        assert_eq!(
            c.observe(t, true),
            None,
            "no change reported once already at the ceiling"
        );
    }

    /// One network hiccup produces a burst of consecutive underruns. Without a
    /// rate limit that single event walks the target from 80 ms to the 300 ms
    /// ceiling instantly, and it then takes over seven minutes of clean audio to
    /// creep back down.
    #[test]
    fn depth_controller_raises_at_most_once_per_interval() {
        let cfg = JitterConfig::default();
        let mut c = DepthController::new(&cfg);

        let first = c.observe(0, true).expect("the first underrun raises");
        assert_eq!(first, cfg.target_start_ms + cfg.underrun_step_ms);
        // A burst 21 ms apart, well inside the interval.
        for i in 1..20u64 {
            assert_eq!(c.observe(i * 21, true), None, "a burst must not compound");
        }
        assert_eq!(c.target_ms(), first, "one hiccup, one step");
        // Once the interval has passed, it raises again.
        assert_eq!(
            c.observe(cfg.underrun_raise_min_interval_ms, true),
            Some(first + cfg.underrun_step_ms)
        );
    }

    #[test]
    fn depth_controller_decays_at_most_once_per_clean_window_and_stops_at_the_floor() {
        let cfg = JitterConfig::default();
        let mut c = DepthController::new(&cfg);
        let start = c.target_ms();

        // Nothing happens before the interval elapses, however often we ask.
        for t in (0..cfg.decay_after_ms).step_by(500) {
            assert_eq!(c.observe(t, false), None);
        }
        assert_eq!(
            c.observe(cfg.decay_after_ms, false),
            Some(start - cfg.decay_step_ms)
        );
        // And the clock restarts: the very next call must not decay again.
        assert_eq!(c.observe(cfg.decay_after_ms + 1, false), None);
        assert_eq!(
            c.observe(cfg.decay_after_ms * 2, false),
            Some(start - 2 * cfg.decay_step_ms)
        );

        // Run it into the floor and pin that it stops there.
        let mut t = cfg.decay_after_ms * 2;
        for _ in 0..200 {
            t += cfg.decay_after_ms;
            let _ = c.observe(t, false);
        }
        assert_eq!(c.target_ms(), cfg.target_min_ms);
        assert_eq!(c.observe(t + cfg.decay_after_ms, false), None);
    }

    /// An underrun cancels the clean streak *even when the rate limit swallows
    /// it*, so the target cannot decay in the middle of an outage.
    #[test]
    fn an_underrun_cancels_the_clean_streak_even_when_rate_limited() {
        let cfg = JitterConfig::default();
        let mut c = DepthController::new(&cfg);
        let _ = c.observe(0, true); // raises; starts the rate-limit clock at t=0
        let raised = c.target_ms();

        let _ = c.observe(1, false); // a clean streak would start at t=1
        assert_eq!(
            c.observe(500, true),
            None,
            "only 500 ms since the raise, so the rate limit swallows it"
        );
        let _ = c.observe(600, false); // the streak restarts here instead

        assert_eq!(
            c.observe(cfg.decay_after_ms + 1, false),
            None,
            "a full window past t=1, but only 9_401 ms past the restart at t=600"
        );
        assert_eq!(c.target_ms(), raised);
        assert_eq!(
            c.observe(600 + cfg.decay_after_ms, false),
            Some(raised - cfg.decay_step_ms),
            "and it does decay a full window after the restart"
        );
    }

    #[test]
    fn depth_controller_respects_both_clamps_from_any_seed() {
        for seed in [0u32, 10, 60, 80, 300, 5_000] {
            let cfg = JitterConfig {
                target_start_ms: seed,
                ..JitterConfig::default()
            };
            let mut c = DepthController::new(&cfg);
            assert!(
                (cfg.target_min_ms..=cfg.target_max_ms).contains(&c.target_ms()),
                "seed {seed} must be clamped into range at construction"
            );
            let mut t = 0u64;
            for i in 0..500u64 {
                let _ = c.observe(t, i % 3 == 0);
                t += 1_500;
                assert!(
                    (cfg.target_min_ms..=cfg.target_max_ms).contains(&c.target_ms()),
                    "target escaped its clamps at t={t} from seed {seed}"
                );
            }
        }
    }

    // -- drift corrector ---------------------------------------------------

    #[test]
    fn drift_corrector_never_fires_on_its_seeding_sample() {
        let cfg = JitterConfig::default();
        let mut d = DriftCorrector::new(&cfg);
        // A wildly out-of-band first sample: still nothing, because one sample
        // is not evidence and every stream start looks exactly like this.
        assert_eq!(d.observe(0, 0.0, 80), None);
        assert_eq!(d.ewma_ms(), Some(0.0));
    }

    #[test]
    fn drift_corrector_is_idle_inside_the_deadband() {
        let cfg = JitterConfig::default();
        let mut d = DriftCorrector::new(&cfg);
        let target = 80u32;
        let _ = d.observe(0, target as f32, target);
        let mut t = 0u64;
        for _ in 0..500 {
            t += cfg.drift_interval_ms;
            // Wander well inside the deadband.
            let fill = target as f32 + if t % 4_000 == 0 { 35.0 } else { -35.0 };
            assert_eq!(
                d.observe(t, fill, target),
                None,
                "must not chase ordinary occupancy jitter"
            );
        }
    }

    #[test]
    fn drift_corrector_drops_a_frame_when_the_buffer_runs_deep() {
        let cfg = JitterConfig::default();
        let mut d = DriftCorrector::new(&cfg);
        let target = 80u32;
        let deep = target as f32 + 200.0;
        let _ = d.observe(0, deep, target); // seed

        let mut t = 0u64;
        let mut fired = None;
        for _ in 0..10 {
            t += cfg.drift_interval_ms;
            if let Some(c) = d.observe(t, deep, target) {
                fired = Some(c);
                break;
            }
        }
        assert_eq!(fired, Some(DriftCorrection::DropFrame));
    }

    #[test]
    fn drift_corrector_inserts_silence_when_the_buffer_runs_shallow() {
        let cfg = JitterConfig::default();
        let mut d = DriftCorrector::new(&cfg);
        let target = 200u32;
        let shallow = 10.0f32;
        let _ = d.observe(0, shallow, target);

        let mut t = 0u64;
        let mut fired = None;
        for _ in 0..10 {
            t += cfg.drift_interval_ms;
            if let Some(c) = d.observe(t, shallow, target) {
                fired = Some(c);
                break;
            }
        }
        assert_eq!(fired, Some(DriftCorrection::InsertSilence));
    }

    /// The deadband is symmetric in milliseconds, but occupancy is bounded below
    /// by zero and quantised to whole frames. At the 60 ms floor target the
    /// nominal shallow edge is 20 ms — under one 21.3 ms frame — so an unclamped
    /// corrector could only act on a buffer that was *already empty*, which is
    /// the underrun it exists to prevent. It would silently stop defending the
    /// shallow side exactly when the target had decayed to its floor.
    #[test]
    fn the_shallow_edge_is_never_pushed_below_one_frame_of_audio() {
        let cfg = JitterConfig::default();
        let target = cfg.target_min_ms; // 60
        let d = DriftCorrector::new(&cfg);
        let (low, high) = d.deadband_bounds(target);
        assert!(
            low > cfg.frame_ms,
            "the shallow edge ({low} ms) must leave at least one frame to act on"
        );
        assert_eq!(
            high,
            target as f32 + cfg.drift_deadband_ms,
            "deep edge is untouched"
        );
        // The clamp binds only at low targets; the seed target is unaffected.
        let (seed_low, _) = d.deadband_bounds(cfg.target_start_ms);
        assert_eq!(
            seed_low,
            cfg.target_start_ms as f32 - cfg.drift_deadband_ms,
            "the clamp must not change the specified behaviour at the seed target"
        );

        // With one frame left against the floor target, it acts. Under a literal
        // 20 ms edge it would not, because one frame is 21.3 ms.
        let mut d = DriftCorrector::new(&cfg);
        let _ = d.observe(0, cfg.frame_ms, target);
        assert_eq!(
            d.observe(cfg.drift_interval_ms, cfg.frame_ms, target),
            Some(DriftCorrection::InsertSilence)
        );
    }

    /// One correction per window, no matter how often the caller asks. A caller
    /// polling every DAC period must get the same behaviour as one polling every
    /// two seconds, or the controller's gain depends on its call rate.
    #[test]
    fn drift_corrector_fires_at_most_once_per_window() {
        let cfg = JitterConfig::default();
        let mut d = DriftCorrector::new(&cfg);
        let target = 80u32;
        let deep = 1_000.0f32;
        let _ = d.observe(0, deep, target);

        // Poll every 21 ms — a DAC period — for a minute, and record when the
        // corrector actually acts. Asserting on the *spacing* rather than on a
        // count keeps the test exact: it fails for a controller whose cadence
        // follows its call rate, and it does not need re-deriving if the poll
        // rate in this fixture changes.
        let mut fire_times: Vec<u64> = Vec::new();
        for tick in 1..=2_857u64 {
            if d.observe(tick * 21, deep, target).is_some() {
                fire_times.push(tick * 21);
            }
        }
        assert!(
            !fire_times.is_empty(),
            "a 1000 ms buffer against an 80 ms target must be acted on"
        );
        for pair in fire_times.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap >= cfg.drift_interval_ms,
                "two corrections {gap} ms apart, inside the {} ms window",
                cfg.drift_interval_ms
            );
        }
    }

    /// Converging from both directions is the property that matters: the
    /// corrector must walk an out-of-band buffer back into the deadband and then
    /// stop, rather than oscillating around it forever.
    #[test]
    fn drift_corrector_converges_from_both_directions_and_then_goes_idle() {
        let cfg = JitterConfig::default();
        let target = 150u32;

        for start_fill in [target as f32 + 150.0, target as f32 - 140.0] {
            let mut d = DriftCorrector::new(&cfg);
            // Simulate a real buffer: each correction actually moves occupancy.
            let mut fill = start_fill;
            let _ = d.observe(0, fill, target);
            let mut t = 0u64;
            let mut corrections = 0usize;
            for _ in 0..200 {
                t += cfg.drift_interval_ms;
                match d.observe(t, fill, target) {
                    Some(DriftCorrection::DropFrame) => {
                        fill -= cfg.frame_ms;
                        corrections += 1;
                    }
                    Some(DriftCorrection::InsertSilence) => {
                        fill += cfg.frame_ms;
                        corrections += 1;
                    }
                    None => {}
                }
            }
            assert!(corrections > 0, "must act on a {start_fill} ms buffer");
            assert!(
                (fill - target as f32).abs() <= cfg.drift_deadband_ms + cfg.frame_ms,
                "converged to {fill} ms against a {target} ms target"
            );
            // And having converged, it stays quiet.
            let settled = corrections;
            for _ in 0..50 {
                t += cfg.drift_interval_ms;
                assert!(
                    d.observe(t, fill, target).is_none(),
                    "must go idle once inside the deadband"
                );
            }
            assert_eq!(corrections, settled);
        }
    }

    /// The arithmetic in the module docs, asserted rather than merely asserted
    /// in prose. If someone shrinks `drift_interval_ms` or grows `frame_ms`
    /// without revisiting the deadband, this is the test that says the
    /// justification no longer holds.
    #[test]
    fn drift_correction_authority_dwarfs_any_real_crystal_mismatch() {
        let cfg = JitterConfig::default();
        let authority_ppm = 1e6 * cfg.frame_ms / cfg.drift_interval_ms as f32;
        assert!(
            (authority_ppm - 10_667.0).abs() < 50.0,
            "one 21.3 ms frame per 2 s is ~10,667 ppm, got {authority_ppm}"
        );
        // Worst plausible consumer crystal pair: ±25 ppm at each end.
        assert!(
            authority_ppm / 50.0 > 100.0,
            "correction authority must dwarf the mismatch it corrects"
        );
        // And the deadband must be wider than one correction, or the corrector
        // can never land inside it and will oscillate forever.
        assert!(
            cfg.drift_deadband_ms > cfg.frame_ms,
            "a deadband narrower than one frame cannot be converged into"
        );
    }

    // -- long synthetic runs ----------------------------------------------

    /// Drive a whole session's worth of packets through the buffer with the two
    /// clocks deliberately mismatched.
    ///
    /// The client consumes one frame per DAC period; the host produces one frame
    /// per frame period of its *own* clock, which runs `ppm` fast (or slow).
    ///
    /// `correct_drift` is the counterfactual switch. The corrections are values
    /// the caller acts on, so "no drift correction" is simply a caller that
    /// never asks — which is exactly a fixed-depth buffer.
    ///
    /// Returns `(stats, peak packets held, tick of first overflow)`.
    fn run_drifting_session(
        minutes: u64,
        ppm: f64,
        correct_drift: bool,
    ) -> (JitterStats, usize, Option<u64>) {
        let cfg = JitterConfig::default();
        let frame = f64::from(cfg.frame_ms);
        let mut buf = AudioJitterBuffer::new(cfg);

        let ticks = (minutes as f64 * 60_000.0 / frame) as u64;
        // Steady state is reached within seconds; measure the peak after a
        // minute so startup transients do not set it.
        let warmup_ticks = (60_000.0 / frame) as u64;

        let mut produced: u32 = 0;
        let mut peak_held = 0usize;
        let mut first_overflow = None;

        for tick in 0..ticks {
            let client_ms = tick as f64 * frame;
            // By the time the client's clock reads `client_ms`, the host's has
            // read `client_ms × (1 + ppm)` and produced this many frames.
            let host_frames = (client_ms * (1.0 + ppm) / frame) as u32;
            while produced < host_frames {
                buf.push(&pkt(produced));
                produced += 1;
            }
            if tick > warmup_ticks {
                peak_held = peak_held.max(buf.len());
            }

            let now_ms = client_ms as u64;
            let drift = if correct_drift {
                buf.observe(now_ms).drift
            } else {
                None
            };
            match drift {
                // Play silence this period: consume nothing.
                Some(DriftCorrection::InsertSilence) => {}
                // Consume two frames in one period, playing one and discarding
                // the other.
                Some(DriftCorrection::DropFrame) => {
                    let _ = buf.pop(now_ms);
                    let _ = buf.pop(now_ms);
                }
                None => {
                    let _ = buf.pop(now_ms);
                }
            }

            if first_overflow.is_none() && buf.stats().overflow > 0 {
                first_overflow = Some(tick);
            }
        }
        (buf.stats(), peak_held, first_overflow)
    }

    /// The failure this whole controller exists to prevent, demonstrated.
    ///
    /// With the corrector never consulted, a 50 ppm mismatch fills the window by
    /// one packet every ~7 minutes. Starting four packets deep in a
    /// sixteen-packet window, it overflows in around an hour and a half and then
    /// keeps overflowing forever — "it works for an hour and then goes weird",
    /// exactly. (At the old 8-packet default this happened around the
    /// half-hour mark instead; raising the window to reach the specified
    /// target range roughly tripled the time this test has to run for, which
    /// is why the bound below and the simulation length both grew with it.)
    #[test]
    fn without_drift_correction_a_fifty_ppm_session_overflows_eventually() {
        let (stats, _, first_overflow) = run_drifting_session(200, 50e-6, false);
        let overflow_tick = first_overflow.expect(
            "a fixed-depth buffer MUST overflow at 50 ppm — if this stops failing, \
             the simulation stopped modelling drift; the drift did not stop happening",
        );
        let overflow_minute = (overflow_tick as f64 * f64::from(DEFAULT_FRAME_MS)) / 60_000.0;
        // Wide on purpose, same reasoning as the drift_drops band in the
        // two-hour correction test below: the point is the order of magnitude
        // (a 16-packet window growing from a ~4-packet baseline at 180 ms/hour
        // predicts ~87 minutes), not an exact tick count.
        assert!(
            (40.0..160.0).contains(&overflow_minute),
            "expected the first overflow around the ninety-minute mark, got {overflow_minute:.1} min"
        );
        assert!(stats.overflow > 0);
    }

    /// The same session with the corrections applied stays bounded for hours.
    ///
    /// This is the test that cannot be replaced by a shorter one: at 50 ppm
    /// nothing at all goes wrong in the first ten minutes, so every test shorter
    /// than the drift period passes whether the corrector exists or not.
    #[test]
    fn a_two_hour_run_at_fifty_ppm_stays_bounded_with_drift_correction() {
        let cfg = JitterConfig::default();
        let (stats, peak_held, first_overflow) = run_drifting_session(120, 50e-6, true);

        assert_eq!(first_overflow, None, "the window must never overflow");
        assert_eq!(stats.overflow, 0);
        assert_eq!(stats.underrun, 0, "and it must never run dry");
        assert!(
            peak_held < cfg.window_depth,
            "occupancy peaked at {peak_held} of {} slots",
            cfg.window_depth
        );
        assert!(
            stats.drift_drops > 0,
            "the corrector must actually have done something"
        );
        assert_eq!(
            stats.drift_inserts, 0,
            "a host-fast clock only ever needs frames removed"
        );
        // 180 ms/hour ÷ 21.3 ms per correction ≈ 8.4 per hour, so ~17 over two
        // hours. A wide band on purpose: the point is the order of magnitude.
        assert!(
            (5..80).contains(&stats.drift_drops),
            "expected a handful of corrections over two hours, got {}",
            stats.drift_drops
        );
        assert_eq!(stats.lost, 0, "nothing was lost on a lossless link");
        assert_eq!(stats.late, 0);
        assert_eq!(stats.duplicate, 0);
    }

    /// The mirror image: a host-*slow* clock drains the buffer, and the
    /// corrector must insert silence rather than let it run dry. This is the
    /// direction that only works because of [`MIN_SHALLOW_EDGE_FRAMES`] — with a
    /// literal ±40 ms deadband the shallow edge lands under one frame once the
    /// target has decayed to its floor, and the buffer simply underruns instead.
    #[test]
    fn an_hour_at_minus_fifty_ppm_stays_bounded_with_drift_correction() {
        let (stats, _, _) = run_drifting_session(60, -50e-6, true);
        assert_eq!(stats.overflow, 0);
        assert!(
            stats.drift_inserts > 0,
            "a host-slow clock needs silence inserted"
        );
        assert_eq!(stats.drift_drops, 0, "and never needs frames removed");
        assert!(
            stats.underrun <= 3,
            "the corrector should keep starves to near zero, got {}",
            stats.underrun
        );
    }

    // -- the packet-paced caller -------------------------------------------

    /// Drive the buffer the way `directdesk_client`'s `AudioLoop` really does.
    ///
    /// Every other consumer in this file pops on a DAC tick, which models a
    /// caller this codebase does not contain: the client's playback clock lives
    /// downstream of a 400 ms WASAPI render buffer, so its pops are paced by
    /// *arrivals*. This fixture is that shape, implementing the contract in
    /// [`AudioJitterBuffer`]'s docs, and it is the only one here that can see
    /// either half of what that contract prevents — a pop deficit (withheld
    /// periods ratcheting occupancy up with no way back down) or a pop surplus
    /// (discarded arrivals draining the window to empty).
    struct PacketPaced {
        buf: AudioJitterBuffer,
        /// `false` reproduces the naive caller — one push, then at most one pop,
        /// per *arrival* rather than per *accepted packet* — so the tests below
        /// can assert the counterfactual instead of describing it in prose.
        contract: bool,
        delivered: Vec<u32>,
        /// Highest occupancy observed at the end of an arrival, in ms. Measured
        /// after the catch-up drain, because that is the depth the audio
        /// actually waits at; the momentary peak mid-arrival is not latency.
        peak_ms: f32,
    }

    impl PacketPaced {
        fn new(config: JitterConfig, contract: bool) -> Self {
            Self {
                buf: AudioJitterBuffer::new(config),
                contract,
                delivered: Vec::new(),
                peak_ms: 0.0,
            }
        }

        /// One arriving datagram — the body of `AudioLoop::handle_frame_at`.
        fn arrive(&mut self, now_ms: u64, packet: &AudioPacket<'_>) {
            let accepted = self.buf.push(packet).was_buffered();
            let mut played = false;
            if accepted || !self.contract {
                if let Some(p) = self.buf.pop(now_ms) {
                    self.delivered.push(p.seq);
                    played = true;
                }
            }
            if self.contract && played {
                while self.buf.buffered_ms() > self.buf.target_ms() as f32 {
                    match self.buf.pop(now_ms) {
                        Some(p) => self.delivered.push(p.seq),
                        None => break,
                    }
                }
            }
            self.buf.observe(now_ms);
            self.peak_ms = self.peak_ms.max(self.buf.buffered_ms());
        }
    }

    /// The host's redundancy mode, through the shipped config and the shipped
    /// caller shape.
    ///
    /// `system_audio_redundancy` sends packet N and then re-sends N−1 behind it,
    /// on the stated grounds that this needs "zero client code — the reorder
    /// window already discards duplicates". The window does discard them. What
    /// it cannot do is stop a caller that pops once per *arrival* from spending
    /// a pop on each one: two pops against one accepted push, a four-packet
    /// prebuffer drained in ~85 ms, a starve, a re-armed prebuffer refilled in
    /// silence, and around again — several audible dropouts a second, each
    /// raising the depth target, on the exact link the operator enabled
    /// redundancy to rescue.
    ///
    /// Nothing here is a fixture chosen to flatter the code: `JitterConfig` is
    /// the shipped default (prebuffer and all) and the arrival pattern is what
    /// `host::net::audio::pump` puts on the wire.
    #[test]
    fn a_redundant_stream_neither_starves_the_window_nor_moves_the_depth_target() {
        let cfg = JitterConfig::default();
        let count = 400u32; // ~8.4 s: dozens of drain/starve cycles, if any.
        let feed = |caller: &mut PacketPaced| {
            for seq in 0..count {
                let now = u64::from(seq) * 21;
                caller.arrive(now, &pkt(seq));
                if seq > 0 {
                    // "having sent packet N, send N-1 again behind it"
                    caller.arrive(now, &pkt(seq - 1));
                }
            }
        };

        let mut caller = PacketPaced::new(cfg, true);
        feed(&mut caller);

        let s = caller.buf.stats();
        assert_eq!(
            s.duplicate,
            u64::from(count - 1),
            "every re-send must be recognised as a duplicate"
        );
        assert_eq!(
            s.underrun, 0,
            "a duplicate is not a period of missing audio, so nothing may starve"
        );
        assert_eq!(s.lost, 0, "nothing was lost on a lossless link");
        assert_eq!(s.overflow, 0);
        assert_eq!(
            caller.buf.target_ms(),
            cfg.target_start_ms,
            "nothing starved, so the depth controller had no reason to move"
        );
        assert!(
            caller.peak_ms <= cfg.target_start_ms as f32 + cfg.frame_ms,
            "occupancy peaked at {} ms against an {} ms target: the window must \
             sit at its target, not wander",
            caller.peak_ms,
            cfg.target_start_ms
        );
        // Every packet played exactly once, in order, with only the prebuffer's
        // worth still in hand at the end.
        let expected: Vec<u32> = (0..count - 3).collect();
        assert_eq!(caller.delivered, expected);
        assert_eq!(caller.buf.len(), 3);

        // The counterfactual, so this test fails for the right reason if the
        // contract is ever un-implemented: the same stream, the same config,
        // one pop per arrival.
        let mut naive = PacketPaced::new(cfg, false);
        feed(&mut naive);
        assert!(
            naive.buf.stats().underrun >= 10,
            "one pop per arrival must starve repeatedly on this stream, or this \
             test is no longer reproducing the defect (got {})",
            naive.buf.stats().underrun
        );
        assert!(
            naive.buf.target_ms() > cfg.target_start_ms,
            "and those starves must be visibly walking the depth target up"
        );
    }

    /// The other half of the same mismatch: a withheld period must be caught up
    /// on, not added to the latency for the rest of the session.
    ///
    /// On a lost packet the window withholds for `reorder_wait_ms` (~2 packet
    /// periods). For a caller that pops at most once per arrival each withheld
    /// period is a push with no pop — permanent, because such a caller can never
    /// take two packets in one period. Six losses is enough to walk occupancy
    /// from three packets to fifteen and leave it there: ~320 ms of
    /// network-domain latency against an 80 ms design point, for the rest of the
    /// session, on a link losing one packet in forty.
    ///
    /// The depth controller is pinned here (`underrun_step_ms: 0`) on purpose.
    /// Its reaction to loss is a separate and deliberate policy with its own
    /// tests above; leaving it live would make this test about two coupled
    /// loops and turn a sharp bound into arithmetic about both. Every other
    /// knob is the shipped default.
    #[test]
    fn a_reorder_wait_is_caught_up_on_rather_than_added_to_the_latency_forever() {
        let cfg = JitterConfig {
            underrun_step_ms: 0,
            ..JitterConfig::default()
        };
        let target = cfg.target_start_ms as f32;
        let count = 600u32;
        let dropped: Vec<u32> = (1..count).filter(|s| s % 40 == 0).collect();
        assert!(dropped.len() >= 14, "the run must contain enough losses");

        let mut caller = PacketPaced::new(cfg, true);
        for seq in 0..count {
            if dropped.contains(&seq) {
                continue;
            }
            caller.arrive(u64::from(seq) * 21, &pkt(seq));
        }

        // The bound: steady occupancy is the largest whole number of packets
        // that fits under the target, and a loss adds at most the two withheld
        // arrivals plus the one that resolves them before the drain runs. Three
        // frames of headroom over the target covers that with room to spare, and
        // is less than half where the naive caller ends up.
        assert!(
            caller.peak_ms <= target + 3.0 * cfg.frame_ms,
            "occupancy peaked at {} ms against a pinned {target} ms target",
            caller.peak_ms
        );
        assert!(
            caller.buf.buffered_ms() <= target,
            "and it ends the run back at the target, not above it"
        );
        let s = caller.buf.stats();
        assert_eq!(s.overflow, 0, "the window must never reach its cap");
        assert_eq!(
            s.lost,
            dropped.len() as u64,
            "exactly the packets that were actually dropped, and no others"
        );
        // Delivery kept up: everything that arrived came out, in order, bar the
        // handful still held at the target depth.
        for pair in caller.delivered.windows(2) {
            assert!(pair[1] > pair[0], "delivered {} after {}", pair[1], pair[0]);
        }
        assert!(
            caller.delivered.iter().all(|seq| !dropped.contains(seq)),
            "a packet that never arrived cannot have been delivered"
        );
        assert_eq!(
            caller.delivered.len() + caller.buf.len(),
            count as usize - dropped.len(),
            "no packet was stranded"
        );

        // The counterfactual: the same lossy stream, one pop per arrival.
        let mut naive = PacketPaced::new(cfg, false);
        for seq in 0..count {
            if dropped.contains(&seq) {
                continue;
            }
            naive.arrive(u64::from(seq) * 21, &pkt(seq));
        }
        assert!(
            naive.buf.buffered_ms() >= 300.0,
            "one pop per arrival must ratchet occupancy from the {target} ms \
             target up against the window's ceiling, or this test is no longer \
             reproducing the defect (got {} ms)",
            naive.buf.buffered_ms()
        );
        assert!(
            naive.buf.buffered_ms() > 4.0 * caller.buf.buffered_ms(),
            "and the gap between the two — {} ms against {} ms — is the added \
             latency the contract removes, on the same stream at the same target",
            naive.buf.buffered_ms(),
            caller.buf.buffered_ms()
        );
        // Not asserted, because it does not happen and it is worth saying why:
        // the ratchet stops one slot short of evicting anything. At 15 held
        // packets the next arrival makes the window *full*, which short-circuits
        // the reorder wait, so the loss resolves immediately and occupancy stops
        // growing. The damage is ~320 ms of permanent latency, not overflow.
    }

    // -- properties --------------------------------------------------------

    proptest! {
        /// The two invariants the rest of the pipeline depends on, over
        /// arbitrary arrival orders, delays, duplicates and pop cadences:
        ///
        /// 1. **Never out of order.** Every delivered `seq` is strictly newer
        ///    than the one before it, in RFC-1982 serial order. A decoder fed a
        ///    backwards frame produces an audible artefact and, for AAC-LC,
        ///    corrupts its overlap state for the frame after it too.
        /// 2. **Never twice.** No `seq` is ever delivered more than once.
        ///
        /// Plus the [`JitterStats`] conservation law, which is what makes the
        /// counters usable as evidence rather than decoration.
        ///
        /// Discontinuities are deliberately excluded here: resetting the stream
        /// is precisely the operation that is *allowed* to deliver a lower `seq`
        /// next, so folding it in would weaken invariant 1 to nothing. It has
        /// its own unit tests above, and the boundedness property below runs
        /// with discontinuities on.
        #[test]
        fn random_arrival_orders_never_deliver_out_of_order_or_twice(
            base in any::<u32>(),
            delays in prop::collection::vec(0u64..=150u64, 1..=48usize),
            dup_every in 1usize..=7,
            pop_every_ms in 5u64..=40,
        ) {
            let frame_ms = 21u64;
            let mut arrivals: Vec<(u64, u32)> = delays
                .iter()
                .enumerate()
                .map(|(i, d)| (i as u64 * frame_ms + d, base.wrapping_add(i as u32)))
                .collect();
            // Sprinkle duplicates, which the network genuinely does produce.
            for i in (0..delays.len()).step_by(dup_every) {
                arrivals.push((i as u64 * frame_ms + 5, base.wrapping_add(i as u32)));
            }
            arrivals.sort_by_key(|(t, _)| *t);

            let mut buf = AudioJitterBuffer::new(plain());
            let end = arrivals.last().map_or(0, |(t, _)| *t) + 400;
            let mut next_arrival = 0usize;
            let mut popped: Vec<u32> = Vec::new();

            for now in 0..=end {
                while next_arrival < arrivals.len() && arrivals[next_arrival].0 <= now {
                    buf.push(&pkt(arrivals[next_arrival].1));
                    next_arrival += 1;
                }
                if now % pop_every_ms == 0 {
                    if let Some(p) = buf.pop(now) {
                        popped.push(p.seq);
                    }
                }
            }
            // Drain far enough into the future that every reorder wait expires,
            // so nothing is left stranded in the window.
            popped.extend(drain(&mut buf, end + 10_000));

            // 1. Strictly increasing in serial order.
            for pair in popped.windows(2) {
                prop_assert!(
                    is_newer(pair[1], pair[0]),
                    "delivered {} after {} — that is backwards",
                    pair[1],
                    pair[0]
                );
            }
            // 2. Never the same seq twice. Implied by 1 over this span, but
            //    asserted directly so a change to `is_newer` cannot hide it.
            let unique: HashSet<u32> = popped.iter().copied().collect();
            prop_assert_eq!(unique.len(), popped.len(), "a seq was delivered twice");
            prop_assert!(popped.len() <= delays.len());

            // 3. Every push landed in exactly one bucket.
            let s = buf.stats();
            prop_assert!(buf.is_empty(), "the drain must empty the window");
            prop_assert_eq!(
                s.received,
                s.duplicate + s.late + s.delivered + s.overflow,
                "stats do not account for every push: {:?}",
                s
            );
            prop_assert_eq!(s.delivered, popped.len() as u64);
        }

        /// The window is bounded no matter what arrives, which is what keeps a
        /// broken or hostile sender from growing the receiver's memory. Runs the
        /// whole generator *including* discontinuities, since boundedness must
        /// hold on every path whether the ordering invariant does or not.
        ///
        /// # Bounded is only half of it
        ///
        /// A window that is bounded because it never hands anything back is
        /// *silence*, and this generator reaches exactly that state: `any::<u32>()`
        /// produces the wild forward `seq` the module docs call out, after which
        /// every genuine packet reads [`DiscardReason::Late`] forever. Occupancy
        /// stays small throughout — the boundedness assertion is perfectly happy
        /// — which is precisely how a wedged buffer would ship.
        ///
        /// So the run ends with a liveness check as well. `drain` panics rather
        /// than returning if the buffer stops making progress on a non-empty
        /// window, so calling it *is* the assertion: whatever is still held must
        /// come out once the reorder wait has expired. The `delivered > 0` floor
        /// below is weaker than it looks — the generator always opens with a
        /// discontinuity, which always delivers — but it costs nothing and it
        /// pins the floor against a future change to the generator.
        #[test]
        fn the_window_is_bounded_under_any_arrival_pattern(
            depth in 1usize..=16,
            seqs in prop::collection::vec(any::<u32>(), 1..=200),
            disc_every in 3usize..=40,
        ) {
            let cfg = JitterConfig { window_depth: depth, ..plain() };
            let mut buf = AudioJitterBuffer::new(cfg);
            for (i, seq) in seqs.iter().copied().enumerate() {
                if i % disc_every == 0 {
                    buf.push(&disc(seq));
                } else {
                    buf.push(&pkt(seq));
                }
                prop_assert!(
                    buf.len() <= depth,
                    "window grew to {} with depth {}",
                    buf.len(),
                    depth
                );
                if i % 3 == 0 {
                    let _ = buf.pop(i as u64 * 7);
                }
            }

            let _ = drain(&mut buf, 10_000_000);
            prop_assert!(
                buf.is_empty(),
                "the window still holds {} packets after a drain past every \
                 reorder wait — it has stopped making progress",
                buf.len()
            );
            prop_assert!(
                buf.stats().delivered > 0,
                "received {} packets and delivered none: bounded, and silent",
                buf.stats().received
            );
        }
    }

    // -- configuration -----------------------------------------------------

    #[test]
    fn validate_rejects_settings_that_would_produce_silence_rather_than_errors() {
        assert!(JitterConfig::default().validate().is_ok());
        for (name, cfg) in [
            (
                "zero frame",
                JitterConfig {
                    frame_ms: 0.0,
                    ..Default::default()
                },
            ),
            (
                "nan frame",
                JitterConfig {
                    frame_ms: f32::NAN,
                    ..Default::default()
                },
            ),
            (
                "zero alpha",
                JitterConfig {
                    drift_alpha: 0.0,
                    ..Default::default()
                },
            ),
            (
                "alpha over one",
                JitterConfig {
                    drift_alpha: 1.5,
                    ..Default::default()
                },
            ),
            (
                "negative deadband",
                JitterConfig {
                    drift_deadband_ms: -1.0,
                    ..Default::default()
                },
            ),
            (
                "inverted target range",
                JitterConfig {
                    target_min_ms: 400,
                    ..Default::default()
                },
            ),
            (
                "zero drift interval",
                JitterConfig {
                    drift_interval_ms: 0,
                    ..Default::default()
                },
            ),
        ] {
            assert!(cfg.validate().is_err(), "{name} must be rejected");
        }
        // A zero depth is tolerated, not rejected: it is clamped to one slot so
        // that forward progress is still possible.
        let zero_depth = JitterConfig {
            window_depth: 0,
            ..plain()
        };
        assert!(zero_depth.validate().is_ok());
        let mut buf = AudioJitterBuffer::new(zero_depth);
        buf.push(&pkt(0));
        buf.push(&pkt(1));
        assert_eq!(buf.len(), 1, "a zero depth still holds one packet");
        assert!(buf.pop(0).is_some(), "and still makes progress");
    }

    #[test]
    fn reset_clears_the_stream_but_keeps_the_learned_target_and_counters() {
        let mut buf = AudioJitterBuffer::new(plain());
        for seq in 0..4 {
            buf.push(&pkt(seq));
        }
        let _ = buf.pop(0);
        let before = buf.stats();
        buf.reset();
        assert!(buf.is_empty());
        assert_eq!(buf.next_seq(), None);
        assert_eq!(buf.stats(), before, "counters are a session total");
        assert_eq!(buf.target_ms(), plain().target_start_ms);
        // And a stream that restarts behind the old one is not "late".
        assert_eq!(buf.push(&pkt(0)), PushOutcome::Buffered);
    }
}
