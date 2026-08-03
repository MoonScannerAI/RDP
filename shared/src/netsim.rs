//! Deterministic, in-process network simulator for the integration test matrix.
//!
//! # Virtual time
//!
//! There are no sockets, no threads, no timers and no calls into
//! [`std::time`] anywhere in this module. The simulator owns a single `u64`
//! millisecond clock that only ever moves when the caller asks it to, via
//! [`NetSim::tick`] or [`NetSim::advance`]. A test therefore controls the
//! entire timeline: "send three datagrams, jump 40 ms, assert nothing arrived
//! yet, jump 10 ms more, assert all three arrived" is an exact, repeatable
//! statement rather than a race.
//!
//! # Determinism guarantee
//!
//! Given the same [`NetParams`], the same seed and the same sequence of API
//! calls, a [`NetSim`] produces a bit-identical delivery transcript — the same
//! packets, dropped in the same places, arriving at the same virtual
//! milliseconds, in the same order. Two things make that true:
//!
//! * **Every scheduling decision is made at send time.** Loss, jitter and
//!   reordering are rolled when the packet is handed to the simulator, so the
//!   full schedule is fixed the moment the send returns. Receiving never
//!   consults the RNG.
//! * **Total ordering.** Every in-flight item carries a monotonically
//!   increasing sequence number, and selection is always by
//!   `(deliver_at_ms, seq)`. Ties can never be broken by allocation address or
//!   hash iteration order; the only map used internally is a [`BTreeMap`],
//!   and public accessors sort before returning.
//!
//! # Why the RNG is hand-rolled
//!
//! [`SimRng`] is a hand-written splitmix64. It deliberately does **not** use
//! the `rand` crate: `rand`'s generators are not contractually reproducible
//! across versions, so a routine `cargo update` could silently rewrite every
//! recorded test transcript in the repository. Sixteen lines of splitmix64
//! pinned in this file means the schedule is stable forever, independent of
//! dependency drift.
//!
//! # Model
//!
//! Two endpoints, [`Endpoint::A`] and [`Endpoint::B`], connected by a link
//! carrying two kinds of traffic:
//!
//! * **Datagrams** — unreliable and unordered, like QUIC datagrams or raw UDP.
//!   They can be dropped by loss or by an outage window, and can be reordered.
//! * **Streams** — reliable and ordered per stream id, like a QUIC or TCP
//!   stream. Stream bytes are never lost and never reorder relative to
//!   themselves; during an outage they are held and delivered once the outage
//!   ends.
//!
//! An outage means the link is down, so it applies at both ends of a packet's
//! journey: a datagram is dropped if it is *sent* during a window **or** would
//! *arrive* during one, and a stream chunk that would land mid-outage is
//! pushed out to the far side of it. Checking only the send instant would let
//! everything already in flight sail through the dead period, which would
//! quietly invalidate any test asserting that nothing arrives while the link
//! is down.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Largest one-way latency (and jitter) accepted by [`NetParams::validate`],
/// in milliseconds. Anything beyond a minute is a configuration typo, not a
/// network condition worth simulating.
pub const MAX_LATENCY_MS: u64 = 60_000;

/// Longest accepted single outage window, in virtual milliseconds (one hour).
///
/// Bounded so that an accidentally unbounded outage fails at construction
/// instead of making the link dead forever and hanging a drain loop.
pub const MAX_OUTAGE_MS: u64 = 60 * 60 * 1_000;

/// Default maximum datagram payload size used by every preset, in bytes.
///
/// 1200 is the conventional conservative QUIC-safe payload size (fits inside a
/// 1280-byte IPv6 minimum MTU with room for headers).
pub const DEFAULT_MTU: usize = 1200;

// ---------------------------------------------------------------------------
// RNG
// ---------------------------------------------------------------------------

/// A tiny, hand-written splitmix64 pseudo-random generator.
///
/// Reproducibility is the entire point: the algorithm is written out here so
/// that the simulator's schedules never change as a side effect of updating a
/// dependency. It is *not* cryptographically secure and must never be used for
/// key material — see [`crate::crypto`] for that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    /// Creates a generator from a 64-bit seed. Every seed is valid, including
    /// zero.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next 64-bit output and advances the state.
    ///
    /// This is the splitmix64 finalizer over a Weyl sequence with the golden
    /// ratio increment; the constants are the canonical published ones and
    /// must not be changed without accepting that every stored transcript in
    /// the test suite becomes invalid.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value uniformly distributed in `[0.0, 1.0)`.
    ///
    /// Built from the top 24 bits of [`SimRng::next_u64`], which is exactly the
    /// `f32` mantissa width, so the result is exact and strictly below `1.0`
    /// (the largest possible output is `1.0 - 2^-24`).
    pub fn next_f32_unit(&mut self) -> f32 {
        // 2^24, exactly representable in f32.
        const SCALE: f32 = 16_777_216.0;
        ((self.next_u64() >> 40) as f32) / SCALE
    }

    /// Returns a value in `[0, n)`, or `0` when `n == 0`.
    ///
    /// Uses plain modulo reduction. That is very slightly biased toward small
    /// values when `n` does not divide `2^64`, which is irrelevant here: `n` is
    /// always a tiny jitter span, so the bias is on the order of `2^-58`. It is
    /// used because it is trivially reproducible.
    pub fn next_range(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// A window of total connectivity failure on the simulated link.
///
/// The window is half-open: it covers `start_ms <= t < start_ms + duration_ms`.
/// A zero-length outage therefore never affects anything. Overlapping or
/// back-to-back outages chain into one effective window (see
/// [`NetParams::outage_end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outage {
    /// Virtual millisecond at which connectivity is lost.
    pub start_ms: u64,
    /// How long connectivity stays lost, in milliseconds.
    pub duration_ms: u64,
}

impl Outage {
    /// Creates an outage window starting at `start_ms` lasting `duration_ms`.
    pub fn new(start_ms: u64, duration_ms: u64) -> Self {
        Self {
            start_ms,
            duration_ms,
        }
    }

    /// First virtual millisecond at which connectivity is restored (exclusive
    /// end of the window). Saturates rather than overflowing.
    pub fn end_ms(&self) -> u64 {
        self.start_ms.saturating_add(self.duration_ms)
    }

    /// Whether `t_ms` falls inside this window.
    pub fn contains(&self, t_ms: u64) -> bool {
        self.duration_ms > 0 && t_ms >= self.start_ms && t_ms < self.end_ms()
    }
}

/// Link conditions applied by a [`NetSim`].
///
/// All fields are plain data so a matrix of conditions can be described in a
/// config file and deserialized; nothing here holds a handle or a clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetParams {
    /// Base one-way latency in milliseconds, applied to both datagrams and
    /// stream chunks.
    pub latency_ms: u64,
    /// Maximum jitter in milliseconds. Each packet draws a uniform offset in
    /// `[-jitter_ms, +jitter_ms]` which is added to `latency_ms`; the resulting
    /// one-way delay is clamped at `0` so delivery is never scheduled in the
    /// past.
    pub jitter_ms: u64,
    /// Probability in percent (`0.0..=100.0`) that a datagram is dropped.
    /// Stream bytes are never affected — streams are reliable.
    pub loss_pct: f32,
    /// Probability in percent (`0.0..=100.0`) that a surviving datagram is
    /// reordered.
    ///
    /// Reordering is modelled as an extra delay of exactly `latency_ms` on top
    /// of the packet's normal delay, which lands it behind packets sent after
    /// it. This is deterministic and needs no second RNG pass over the queue.
    /// Note that with `latency_ms == 0` the extra delay is zero, so the roll is
    /// still counted in [`SimStats::datagrams_reordered`] but has no visible
    /// effect.
    pub reorder_pct: f32,
    /// Maximum datagram payload size in bytes. A larger payload is rejected at
    /// send time with [`Error::Oversized`]. Streams are byte streams and are
    /// not subject to the MTU.
    pub mtu: usize,
    /// Windows during which the link is completely down. A datagram is dropped
    /// if it is sent inside a window *or* would arrive inside one; stream bytes
    /// are never lost, but a chunk that would arrive inside a window is delayed
    /// until after it.
    pub outages: Vec<Outage>,
}

impl NetParams {
    /// An ideal link: zero latency, zero jitter, zero loss, zero reordering,
    /// [`DEFAULT_MTU`] and no outages. Datagrams are deliverable in the same
    /// virtual millisecond they are sent, in send order.
    pub fn perfect() -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
            loss_pct: 0.0,
            reorder_pct: 0.0,
            mtu: DEFAULT_MTU,
            outages: Vec::new(),
        }
    }

    /// Wired LAN: 2 ms latency, no jitter, no loss, no reordering.
    pub fn lan() -> Self {
        Self {
            latency_ms: 2,
            jitter_ms: 0,
            loss_pct: 0.0,
            reorder_pct: 0.0,
            mtu: DEFAULT_MTU,
            outages: Vec::new(),
        }
    }

    /// Decent Wi-Fi: 15 ms latency, 5 ms jitter, 1% loss, 1% reordering.
    pub fn wifi() -> Self {
        Self {
            latency_ms: 15,
            jitter_ms: 5,
            loss_pct: 1.0,
            reorder_pct: 1.0,
            mtu: DEFAULT_MTU,
            outages: Vec::new(),
        }
    }

    /// Cross-country WAN: 60 ms latency, 20 ms jitter, 2% loss, 3% reordering.
    pub fn wan() -> Self {
        Self {
            latency_ms: 60,
            jitter_ms: 20,
            loss_pct: 2.0,
            reorder_pct: 3.0,
            mtu: DEFAULT_MTU,
            outages: Vec::new(),
        }
    }

    /// Hostile link (congested mobile tether): 150 ms latency, 60 ms jitter,
    /// 8% loss, 10% reordering.
    pub fn bad() -> Self {
        Self {
            latency_ms: 150,
            jitter_ms: 60,
            loss_pct: 8.0,
            reorder_pct: 10.0,
            mtu: DEFAULT_MTU,
            outages: Vec::new(),
        }
    }

    /// Rejects nonsensical configurations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if a percentage is NaN or outside
    /// `0.0..=100.0`, if `mtu` is zero, or if `latency_ms` / `jitter_ms`
    /// exceeds [`MAX_LATENCY_MS`].
    pub fn validate(&self) -> Result<()> {
        // `contains` on a range is false for NaN, so this covers NaN and
        // infinities without ever comparing floats for equality.
        if !(0.0..=100.0).contains(&self.loss_pct) {
            return Err(Error::Invalid(format!(
                "netsim: loss_pct must be within 0.0..=100.0, got {}",
                self.loss_pct
            )));
        }
        if !(0.0..=100.0).contains(&self.reorder_pct) {
            return Err(Error::Invalid(format!(
                "netsim: reorder_pct must be within 0.0..=100.0, got {}",
                self.reorder_pct
            )));
        }
        if self.mtu == 0 {
            return Err(Error::Invalid("netsim: mtu must be non-zero".to_string()));
        }
        if self.latency_ms > MAX_LATENCY_MS {
            return Err(Error::Invalid(format!(
                "netsim: latency_ms {} exceeds limit {}",
                self.latency_ms, MAX_LATENCY_MS
            )));
        }
        if self.jitter_ms > MAX_LATENCY_MS {
            return Err(Error::Invalid(format!(
                "netsim: jitter_ms {} exceeds limit {}",
                self.jitter_ms, MAX_LATENCY_MS
            )));
        }
        // An unbounded outage is almost always a mistake (`Outage::new(0,
        // u64::MAX)` would silently make the link dead for all time and hang a
        // drain-to-quiescence loop instead of failing). Refuse it here so the
        // error arrives at construction, where it is obvious.
        for o in &self.outages {
            if o.duration_ms == 0 {
                return Err(Error::Invalid(
                    "netsim: outage duration must be non-zero".into(),
                ));
            }
            if o.duration_ms > MAX_OUTAGE_MS {
                return Err(Error::Invalid(format!(
                    "netsim: outage duration {} exceeds limit {}",
                    o.duration_ms, MAX_OUTAGE_MS
                )));
            }
        }
        Ok(())
    }

    /// If `t_ms` falls inside an outage, returns the virtual millisecond at
    /// which connectivity is restored; otherwise returns `None`.
    ///
    /// Overlapping and immediately adjacent outages are chained, so a link that
    /// is down from 100..200 and again from 200..300 reports a single
    /// restoration point of 300. Iteration is over a `Vec` in declaration
    /// order, so the answer never depends on hash ordering.
    pub fn outage_end(&self, t_ms: u64) -> Option<u64> {
        let mut end: Option<u64> = None;
        let mut cursor = t_ms;
        // Each pass can only extend the cursor past at least one more outage,
        // so `len() + 1` passes is an upper bound on reaching a fixed point.
        for _ in 0..=self.outages.len() {
            let mut extended = false;
            for outage in &self.outages {
                if outage.contains(cursor) {
                    cursor = outage.end_ms();
                    end = Some(cursor);
                    extended = true;
                }
            }
            if !extended {
                break;
            }
        }
        end
    }
}

impl Default for NetParams {
    /// Equivalent to [`NetParams::perfect`].
    fn default() -> Self {
        Self::perfect()
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// One of the two ends of the simulated link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Endpoint {
    /// The first endpoint; by convention the host / initiator in tests.
    A,
    /// The second endpoint; by convention the client / responder in tests.
    B,
}

impl Endpoint {
    /// The endpoint on the other side of the link.
    pub fn peer(self) -> Endpoint {
        match self {
            Endpoint::A => Endpoint::B,
            Endpoint::B => Endpoint::A,
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Cumulative counters, for assertions in tests.
///
/// After a run has been drained to quiescence the datagram counters balance:
/// `datagrams_sent == datagrams_delivered + datagrams_dropped_loss +
/// datagrams_dropped_outage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimStats {
    /// Datagrams accepted by [`NetSim::send_datagram`] (MTU rejections are not
    /// counted, since nothing was ever put on the wire).
    pub datagrams_sent: u64,
    /// Datagrams discarded by the random loss model.
    pub datagrams_dropped_loss: u64,
    /// Datagrams discarded because the link was down when they were sent.
    pub datagrams_dropped_outage: u64,
    /// Datagrams handed back by [`NetSim::recv_datagram`].
    pub datagrams_delivered: u64,
    /// Datagrams that drew an extra reordering delay.
    pub datagrams_reordered: u64,
    /// Stream bytes accepted by [`NetSim::send_stream`].
    pub stream_bytes_sent: u64,
    /// Stream bytes handed back by [`NetSim::recv_stream`].
    pub stream_bytes_delivered: u64,
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// What an in-flight item is carrying.
#[derive(Debug, Clone)]
enum Payload {
    /// An unreliable datagram.
    Datagram(Vec<u8>),
    /// A reliable, ordered chunk belonging to a stream.
    Stream { id: u32, bytes: Vec<u8> },
}

/// An item on the wire, scheduled for delivery.
#[derive(Debug, Clone)]
struct InFlight {
    /// Virtual millisecond at or after which the item becomes receivable.
    deliver_at_ms: u64,
    /// Global send order; breaks `deliver_at_ms` ties so ordering is total.
    seq: u64,
    /// Endpoint that will receive this item.
    dst: Endpoint,
    /// The carried bytes.
    kind: Payload,
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------

/// A deterministic two-endpoint network simulator driven by virtual time.
///
/// See the [module documentation](self) for the determinism contract.
#[derive(Debug, Clone)]
pub struct NetSim {
    params: NetParams,
    rng: SimRng,
    now_ms: u64,
    next_seq: u64,
    queue: Vec<InFlight>,
    /// Last scheduled delivery time per `(sender, stream id)`, used to clamp
    /// stream chunks into monotonic order. A `BTreeMap` rather than a `HashMap`
    /// so iteration (if ever added) is deterministic.
    last_stream_deliver: BTreeMap<(Endpoint, u32), u64>,
    stats: SimStats,
}

impl NetSim {
    /// Creates a simulator with the given link conditions and RNG seed, with
    /// the virtual clock at zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if `params` fails [`NetParams::validate`].
    pub fn new(params: NetParams, seed: u64) -> Result<NetSim> {
        params.validate()?;
        Ok(NetSim {
            params,
            rng: SimRng::new(seed),
            now_ms: 0,
            next_seq: 0,
            queue: Vec::new(),
            last_stream_deliver: BTreeMap::new(),
            stats: SimStats::default(),
        })
    }

    /// The current virtual time, in milliseconds since the simulator was
    /// created.
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// The link conditions currently in force.
    pub fn params(&self) -> &NetParams {
        &self.params
    }

    /// A snapshot of the cumulative counters.
    pub fn stats(&self) -> SimStats {
        self.stats
    }

    /// Number of items still on the wire: datagrams and stream chunks that have
    /// been sent but not yet received, including any that are already due.
    ///
    /// Tests drain to quiescence by advancing time and receiving until this
    /// reaches zero.
    pub fn in_flight(&self) -> usize {
        self.queue.len()
    }

    /// Replaces the link conditions mid-run.
    ///
    /// Items already in flight keep the schedule they were given at send time;
    /// only subsequent sends see the new conditions. The RNG state is
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if `params` fails [`NetParams::validate`].
    pub fn set_params(&mut self, params: NetParams) -> Result<()> {
        params.validate()?;
        self.params = params;
        Ok(())
    }

    /// Moves the virtual clock to `now_ms`.
    ///
    /// Time is monotonic: a value at or before the current time is ignored and
    /// logged at `warn` level. This never panics, in debug or release, because
    /// a test harness that mis-orders its own ticks should fail its assertions
    /// rather than abort the process.
    pub fn tick(&mut self, now_ms: u64) {
        if now_ms < self.now_ms {
            tracing::warn!(
                requested_ms = now_ms,
                current_ms = self.now_ms,
                "netsim: ignoring backwards tick"
            );
            return;
        }
        self.now_ms = now_ms;
    }

    /// Advances the virtual clock by `delta_ms` (saturating).
    pub fn advance(&mut self, delta_ms: u64) {
        let target = self.now_ms.saturating_add(delta_ms);
        self.tick(target);
    }

    /// Sends an unreliable datagram from `from` to its peer.
    ///
    /// Loss, outage, jitter and reordering are all decided here, so the
    /// delivery schedule is fixed before this call returns. A dropped datagram
    /// still returns `Ok(())` — loss is a normal network event, not an API
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Oversized`] if `payload` is larger than
    /// [`NetParams::mtu`]. Nothing is enqueued and no counter moves in that
    /// case.
    pub fn send_datagram(&mut self, from: Endpoint, payload: Vec<u8>) -> Result<()> {
        let limit = self.params.mtu;
        if payload.len() > limit {
            return Err(Error::Oversized {
                got: payload.len(),
                limit,
            });
        }
        self.stats.datagrams_sent += 1;

        // Every branch below draws exactly three values (loss, jitter, reorder)
        // regardless of outcome, so changing `loss_pct` or adding an outage does
        // not shift the RNG stream for subsequent packets. That is what makes
        // two runs with different impairments comparable packet-for-packet.
        let lost = self.roll_pct(self.params.loss_pct);
        let mut delay = self.jittered_delay();
        let reordered = self.roll_pct(self.params.reorder_pct);

        // A link that is down loses what is on it, not just what enters it.
        // Checking only `now_ms` would let every packet sent in the latency
        // window before an outage sail through the dead period — which would
        // quietly invalidate any test asserting "nothing arrives during the
        // outage". Both the send instant and the arrival instant must be clear.
        if self.params.outage_end(self.now_ms).is_some() {
            self.stats.datagrams_dropped_outage += 1;
            return Ok(());
        }
        if lost {
            self.stats.datagrams_dropped_loss += 1;
            return Ok(());
        }
        if reordered {
            delay = delay.saturating_add(self.params.latency_ms);
        }

        let deliver_at_ms = self.now_ms.saturating_add(delay);
        if self.params.outage_end(deliver_at_ms).is_some() {
            // In flight when the link went down.
            self.stats.datagrams_dropped_outage += 1;
            return Ok(());
        }
        if reordered {
            self.stats.datagrams_reordered += 1;
        }
        self.push(deliver_at_ms, from.peer(), Payload::Datagram(payload));
        Ok(())
    }

    /// Receives the next due datagram at `at`, or `None` if nothing is due.
    ///
    /// "Next" means the smallest `(deliver_at_ms, seq)` among datagrams
    /// addressed to `at` whose delivery time has been reached. Because `seq` is
    /// unique, the ordering is total and identical on every run.
    pub fn recv_datagram(&mut self, at: Endpoint) -> Option<Vec<u8>> {
        let now = self.now_ms;
        let idx = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                item.dst == at
                    && item.deliver_at_ms <= now
                    && matches!(item.kind, Payload::Datagram(_))
            })
            .min_by_key(|(_, item)| (item.deliver_at_ms, item.seq))
            .map(|(idx, _)| idx)?;

        match self.queue.remove(idx).kind {
            Payload::Datagram(bytes) => {
                self.stats.datagrams_delivered += 1;
                Some(bytes)
            }
            // Unreachable: the selection loop above only accepts `Datagram`
            // items. Handled as `None` rather than a panic so a future refactor
            // degrades into a test failure instead of an abort.
            Payload::Stream { .. } => None,
        }
    }

    /// Sends reliable, ordered bytes on stream `id` from `from` to its peer.
    ///
    /// Stream bytes are never dropped and never reordered relative to earlier
    /// bytes on the same `(sender, id)` stream: the computed delivery time is
    /// clamped to be at least that of the previous chunk, and the global `seq`
    /// breaks any tie in send order. Latency and jitter still apply, so a
    /// stream can bunch up but can never invert.
    ///
    /// During an outage the chunk is held rather than lost: its delay is
    /// measured from the moment the outage ends.
    ///
    /// An empty `bytes` slice is a no-op and consumes no randomness.
    ///
    /// # Errors
    ///
    /// Currently infallible; the [`Result`] is part of the API so that future
    /// flow-control limits can be enforced without a breaking change. Note that
    /// [`NetParams::mtu`] does *not* apply to streams — they are byte streams,
    /// and framing is the caller's business.
    pub fn send_stream(&mut self, from: Endpoint, id: u32, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.stats.stream_bytes_sent += bytes.len() as u64;

        let base = self.params.outage_end(self.now_ms).unwrap_or(self.now_ms);
        let delay = self.jittered_delay();
        let mut deliver_at_ms = base.saturating_add(delay);

        // Reliable streams are held, not lost — but a chunk that would have
        // landed mid-outage has to wait for the link to come back, exactly as a
        // retransmit would. Without this, stream bytes sent just before an
        // outage would be delivered during it.
        if let Some(end) = self.params.outage_end(deliver_at_ms) {
            deliver_at_ms = end.saturating_add(delay);
        }

        let key = (from, id);
        if let Some(previous) = self.last_stream_deliver.get(&key).copied() {
            deliver_at_ms = deliver_at_ms.max(previous);
        }
        self.last_stream_deliver.insert(key, deliver_at_ms);

        self.push(
            deliver_at_ms,
            from.peer(),
            Payload::Stream {
                id,
                bytes: bytes.to_vec(),
            },
        );
        Ok(())
    }

    /// Drains every due byte of stream `id` at `at`, concatenated in order.
    ///
    /// Returns an empty vector when nothing is due. Chunks that are still in
    /// flight stay queued; a later call picks them up.
    pub fn recv_stream(&mut self, at: Endpoint, id: u32) -> Vec<u8> {
        let mut due: Vec<(u64, u64, usize)> = Vec::new();
        for (idx, item) in self.queue.iter().enumerate() {
            if item.dst != at || item.deliver_at_ms > self.now_ms {
                continue;
            }
            if let Payload::Stream { id: sid, .. } = &item.kind {
                if *sid == id {
                    due.push((item.deliver_at_ms, item.seq, idx));
                }
            }
        }
        if due.is_empty() {
            return Vec::new();
        }
        // `seq` is unique, so this is a total order and the sort is stable in
        // effect regardless of the algorithm used.
        due.sort_unstable();

        let mut out: Vec<u8> = Vec::new();
        for entry in &due {
            if let Payload::Stream { bytes, .. } = &self.queue[entry.2].kind {
                out.extend_from_slice(bytes);
            }
        }

        // Remove from the back so earlier indices stay valid.
        let mut indices: Vec<usize> = due.iter().map(|entry| entry.2).collect();
        indices.sort_unstable();
        for idx in indices.into_iter().rev() {
            self.queue.remove(idx);
        }

        self.stats.stream_bytes_delivered += out.len() as u64;
        out
    }

    /// Sorted, deduplicated list of stream ids that have any bytes queued for
    /// `at`, whether already due or still in flight.
    ///
    /// Useful for a test driver that wants to poll every active stream without
    /// knowing the ids up front.
    pub fn stream_ids(&self, at: Endpoint) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .queue
            .iter()
            .filter(|item| item.dst == at)
            .filter_map(|item| match &item.kind {
                Payload::Stream { id, .. } => Some(*id),
                Payload::Datagram(_) => None,
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    // -- internals ----------------------------------------------------------

    /// Draws one uniform value and reports whether an event of probability
    /// `pct` percent occurred.
    ///
    /// The comparison happens in the unit domain (`r < pct / 100.0`) rather
    /// than scaling `r` up to percent. That matters at the endpoints: at
    /// `pct == 100.0` the threshold is exactly `1.0` and the draw is always
    /// below it, whereas `r * 100.0` can round up to exactly `100.0` in `f32`
    /// and let a packet through.
    fn roll_pct(&mut self, pct: f32) -> bool {
        self.rng.next_f32_unit() < pct / 100.0
    }

    /// One-way delay for the next packet: base latency plus a uniform jitter
    /// offset in `[-jitter_ms, +jitter_ms]`, clamped at zero.
    ///
    /// Always consumes exactly one RNG draw, including when `jitter_ms` is
    /// zero, so that changing the jitter setting does not shift the RNG stream
    /// in a way that is surprising to reason about.
    fn jittered_delay(&mut self) -> u64 {
        let jitter = self.params.jitter_ms;
        let span = jitter.saturating_mul(2).saturating_add(1);
        let offset = self.rng.next_range(span) as i64 - jitter as i64;
        let delay = self.params.latency_ms as i64 + offset;
        delay.max(0) as u64
    }

    /// Appends an item to the wire with the next global sequence number.
    fn push(&mut self, deliver_at_ms: u64, dst: Endpoint, kind: Payload) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.queue.push(InFlight {
            deliver_at_ms,
            seq,
            dst,
            kind,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Repeatedly receive everything due, step 1 ms, until `until_ms`.
    fn drain_datagrams(sim: &mut NetSim, at: Endpoint, until_ms: u64) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            while let Some(payload) = sim.recv_datagram(at) {
                out.push((sim.now_ms(), payload));
            }
            if sim.now_ms() >= until_ms {
                break;
            }
            sim.advance(1);
        }
        out
    }

    /// Send `count` numbered datagrams at t=0 and return the delivery
    /// transcript.
    fn transcript(params: &NetParams, seed: u64, count: usize) -> Vec<(u64, Vec<u8>)> {
        let mut sim = NetSim::new(params.clone(), seed).expect("preset params are valid");
        for i in 0..count {
            let hi = ((i >> 8) & 0xff) as u8;
            let lo = (i & 0xff) as u8;
            sim.send_datagram(Endpoint::A, vec![hi, lo])
                .expect("payload is under the mtu");
        }
        drain_datagrams(&mut sim, Endpoint::B, 2_000)
    }

    #[test]
    fn same_seed_same_schedule() {
        let params = NetParams::bad();
        let first = transcript(&params, 0xDEAD_BEEF, 200);
        let second = transcript(&params, 0xDEAD_BEEF, 200);
        assert_eq!(first, second, "same seed must reproduce the transcript");
        assert!(!first.is_empty(), "8% loss should not eat 200 packets");
    }

    #[test]
    fn different_seed_differs() {
        let params = NetParams::bad();
        let first = transcript(&params, 7, 200);
        let second = transcript(&params, 99_991, 200);
        assert_ne!(
            first, second,
            "200 packets through 60ms jitter cannot coincide across seeds"
        );
    }

    #[test]
    fn perfect_params_lossless_ordered() {
        let mut sim = NetSim::new(NetParams::perfect(), 0).expect("perfect params are valid");
        for i in 0..64u8 {
            sim.send_datagram(Endpoint::A, vec![i]).expect("under mtu");
        }
        for i in 0..64u8 {
            assert_eq!(sim.recv_datagram(Endpoint::B), Some(vec![i]));
        }
        assert!(sim.recv_datagram(Endpoint::B).is_none());
        assert_eq!(sim.in_flight(), 0);
        assert_eq!(sim.stats().datagrams_delivered, 64);
    }

    #[test]
    fn loss_zero_delivers_all() {
        let mut params = NetParams::wan();
        params.loss_pct = 0.0;
        let mut sim = NetSim::new(params, 11).expect("valid");
        for i in 0..100u8 {
            sim.send_datagram(Endpoint::A, vec![i]).expect("under mtu");
        }
        let got = drain_datagrams(&mut sim, Endpoint::B, 1_000);
        assert_eq!(got.len(), 100);
        assert_eq!(sim.stats().datagrams_dropped_loss, 0);
        assert_eq!(sim.in_flight(), 0);
    }

    #[test]
    fn loss_hundred_delivers_none() {
        let mut params = NetParams::perfect();
        params.loss_pct = 100.0;
        let mut sim = NetSim::new(params, 3).expect("valid");
        for i in 0..50u8 {
            sim.send_datagram(Endpoint::A, vec![i]).expect("under mtu");
        }
        let got = drain_datagrams(&mut sim, Endpoint::B, 500);
        assert!(got.is_empty(), "100% loss must deliver nothing");
        assert_eq!(sim.stats().datagrams_dropped_loss, 50);
        assert_eq!(sim.stats().datagrams_delivered, 0);
        assert_eq!(sim.in_flight(), 0);
    }

    #[test]
    fn mtu_enforced() {
        let mut params = NetParams::perfect();
        params.mtu = 16;
        let mut sim = NetSim::new(params, 1).expect("valid");

        sim.send_datagram(Endpoint::A, vec![0u8; 16])
            .expect("exactly at the mtu is allowed");

        let err = sim
            .send_datagram(Endpoint::A, vec![0u8; 17])
            .expect_err("over the mtu must be rejected");
        match err {
            Error::Oversized { got, limit } => {
                assert_eq!(got, 17);
                assert_eq!(limit, 16);
            }
            other => panic!("expected Oversized, got {other:?}"),
        }
        // The rejected send must not be counted or enqueued.
        assert_eq!(sim.stats().datagrams_sent, 1);
        assert_eq!(sim.in_flight(), 1);
    }

    #[test]
    fn latency_respected() {
        let mut params = NetParams::perfect();
        params.latency_ms = 50;
        let mut sim = NetSim::new(params, 2).expect("valid");

        sim.send_datagram(Endpoint::A, vec![9]).expect("under mtu");
        sim.tick(49);
        assert!(sim.recv_datagram(Endpoint::B).is_none(), "early at t=49");
        sim.tick(50);
        assert_eq!(sim.recv_datagram(Endpoint::B), Some(vec![9]));
    }

    #[test]
    fn outage_drops_datagrams_but_holds_stream() {
        let mut params = NetParams::perfect();
        params.latency_ms = 10;
        params.outages = vec![Outage::new(100, 100)];
        let mut sim = NetSim::new(params, 4).expect("valid");

        sim.tick(150);
        sim.send_datagram(Endpoint::A, vec![1, 2, 3])
            .expect("under mtu");
        sim.send_stream(Endpoint::A, 1, b"hello")
            .expect("stream ok");

        assert_eq!(sim.stats().datagrams_dropped_outage, 1);
        assert_eq!(sim.stats().datagrams_dropped_loss, 0);

        sim.tick(1_000);
        assert!(
            sim.recv_datagram(Endpoint::B).is_none(),
            "outage datagram is gone for good"
        );
        assert_eq!(sim.recv_stream(Endpoint::B, 1), b"hello".to_vec());
        assert_eq!(sim.in_flight(), 0);
    }

    /// A packet already in flight when the link goes down must be lost. Sending
    /// at t=30 with 80 ms latency lands at t=110, inside the 100..200 outage.
    #[test]
    fn in_flight_datagram_is_lost_when_the_link_drops() {
        let mut params = NetParams::perfect();
        params.latency_ms = 80;
        params.outages = vec![Outage::new(100, 100)];
        let mut sim = NetSim::new(params, 7).expect("valid");

        sim.tick(30);
        sim.send_datagram(Endpoint::A, vec![9, 9])
            .expect("under mtu");
        assert_eq!(
            sim.stats().datagrams_dropped_outage,
            1,
            "arrival lands mid-outage"
        );

        sim.tick(1_000);
        assert!(sim.recv_datagram(Endpoint::B).is_none());
        assert_eq!(sim.in_flight(), 0);

        let s = sim.stats();
        assert_eq!(
            s.datagrams_sent,
            s.datagrams_delivered + s.datagrams_dropped_loss + s.datagrams_dropped_outage
        );
    }

    /// The stream mirror of the above: reliable bytes are held, not lost, but
    /// they must not be delivered *during* the outage.
    #[test]
    fn in_flight_stream_chunk_waits_out_the_outage() {
        let mut params = NetParams::perfect();
        params.latency_ms = 80;
        params.outages = vec![Outage::new(100, 100)];
        let mut sim = NetSim::new(params, 8).expect("valid");

        sim.tick(30);
        sim.send_stream(Endpoint::A, 1, b"abc").expect("stream ok");

        // Nothing may arrive while the link is down.
        for t in [110u64, 150, 199] {
            sim.tick(t);
            assert!(
                sim.recv_stream(Endpoint::B, 1).is_empty(),
                "delivered during outage at {t}"
            );
        }
        sim.tick(1_000);
        assert_eq!(sim.recv_stream(Endpoint::B, 1), b"abc".to_vec());
        assert_eq!(sim.in_flight(), 0);
    }

    /// Changing an impairment must not shift the RNG stream: the same seed and
    /// the same call sequence produce the same jitter draws whether or not
    /// packets are being lost.
    #[test]
    fn rng_stream_is_stable_across_loss_settings() {
        /// Delivery time keyed by payload marker, for whatever survives.
        fn transcript(loss_pct: f32) -> BTreeMap<u8, u64> {
            let mut params = NetParams::perfect();
            params.latency_ms = 50;
            params.jitter_ms = 20;
            params.loss_pct = loss_pct;
            let mut sim = NetSim::new(params, 4242).expect("valid");
            for i in 0..60u8 {
                sim.send_datagram(Endpoint::A, vec![i]).expect("under mtu");
            }
            let mut out = BTreeMap::new();
            for t in 0..500u64 {
                sim.tick(t);
                while let Some(p) = sim.recv_datagram(Endpoint::B) {
                    out.insert(p[0], sim.now_ms());
                }
            }
            out
        }

        let lossless = transcript(0.0);
        let lossy = transcript(50.0);
        assert_eq!(lossless.len(), 60, "nothing is lost at 0%");
        assert!(
            lossy.len() > 10 && lossy.len() < 60,
            "got {} survivors",
            lossy.len()
        );
        for (marker, when) in &lossy {
            assert_eq!(
                lossless.get(marker),
                Some(when),
                "packet {marker} shifted in time when loss_pct changed"
            );
        }
    }

    #[test]
    fn unbounded_outage_is_rejected() {
        let mut params = NetParams::perfect();
        params.outages = vec![Outage::new(0, u64::MAX)];
        assert!(params.validate().is_err());
        params.outages = vec![Outage::new(0, 0)];
        assert!(params.validate().is_err());
    }

    #[test]
    fn stream_is_ordered_under_jitter() {
        let mut sim = NetSim::new(NetParams::bad(), 1_234).expect("valid");
        let mut expected: Vec<u8> = Vec::new();
        for i in 0..100u32 {
            let chunk = i.to_le_bytes();
            sim.send_stream(Endpoint::A, 9, &chunk).expect("stream ok");
            expected.extend_from_slice(&chunk);
            sim.advance(1);
        }

        let mut got: Vec<u8> = Vec::new();
        for _ in 0..2_000 {
            got.extend_from_slice(&sim.recv_stream(Endpoint::B, 9));
            sim.advance(1);
        }
        got.extend_from_slice(&sim.recv_stream(Endpoint::B, 9));

        assert_eq!(got, expected, "stream bytes must arrive in send order");
        assert_eq!(sim.in_flight(), 0);
        assert_eq!(sim.stats().stream_bytes_sent, 400);
        assert_eq!(sim.stats().stream_bytes_delivered, 400);
    }

    #[test]
    fn stream_and_datagram_independent() {
        let mut params = NetParams::perfect();
        params.latency_ms = 5;
        let mut sim = NetSim::new(params, 77).expect("valid");

        let mut expected_stream: Vec<u8> = Vec::new();
        for i in 0..20u8 {
            sim.send_datagram(Endpoint::A, vec![0xD0, i])
                .expect("under mtu");
            let chunk = [0x5E, i];
            sim.send_stream(Endpoint::A, 3, &chunk).expect("stream ok");
            expected_stream.extend_from_slice(&chunk);
        }

        assert_eq!(sim.stream_ids(Endpoint::B), [3u32]);
        assert!(sim.stream_ids(Endpoint::A).is_empty());

        sim.tick(100);
        let datagrams = drain_datagrams(&mut sim, Endpoint::B, 100);
        let stream = sim.recv_stream(Endpoint::B, 3);

        assert_eq!(datagrams.len(), 20);
        for (i, (_, payload)) in datagrams.iter().enumerate() {
            let expected: Vec<u8> = vec![0xD0, i as u8];
            assert_eq!(payload, &expected);
        }
        assert_eq!(stream, expected_stream);
        assert!(sim.stream_ids(Endpoint::B).is_empty());
        assert_eq!(sim.in_flight(), 0);
    }

    #[test]
    fn tick_backwards_is_ignored() {
        let mut sim = NetSim::new(NetParams::perfect(), 0).expect("valid");
        sim.tick(100);
        sim.tick(50);
        assert_eq!(sim.now_ms(), 100);
        sim.advance(5);
        assert_eq!(sim.now_ms(), 105);
    }

    #[test]
    fn stats_add_up() {
        let mut params = NetParams::wan();
        params.outages = vec![Outage::new(10, 20)];
        let mut sim = NetSim::new(params, 8_675_309).expect("valid");

        for i in 0..150usize {
            sim.send_datagram(Endpoint::A, vec![(i & 0xff) as u8])
                .expect("under mtu");
            sim.advance(1);
        }
        let delivered = drain_datagrams(&mut sim, Endpoint::B, 2_000);

        let s = sim.stats();
        assert_eq!(delivered.len() as u64, s.datagrams_delivered);
        assert_eq!(s.datagrams_sent, 150);
        assert!(s.datagrams_dropped_outage > 0, "outage window was crossed");
        assert_eq!(
            s.datagrams_sent,
            s.datagrams_delivered + s.datagrams_dropped_loss + s.datagrams_dropped_outage
        );
        assert_eq!(sim.in_flight(), 0);
    }

    #[test]
    fn set_params_midrun_keeps_scheduled_packets() {
        let mut params = NetParams::perfect();
        params.latency_ms = 50;
        let mut sim = NetSim::new(params, 5).expect("valid");

        sim.send_datagram(Endpoint::A, vec![1]).expect("under mtu");
        sim.set_params(NetParams::perfect()).expect("valid");
        sim.send_datagram(Endpoint::A, vec![2]).expect("under mtu");

        // The zero-latency packet sent second is due immediately; the packet
        // sent first keeps its 50 ms schedule.
        assert_eq!(sim.recv_datagram(Endpoint::B), Some(vec![2]));
        assert!(sim.recv_datagram(Endpoint::B).is_none());
        sim.tick(50);
        assert_eq!(sim.recv_datagram(Endpoint::B), Some(vec![1]));
        assert_eq!(sim.in_flight(), 0);
    }

    #[test]
    fn validate_rejects_bad_params() {
        let mut p = NetParams::perfect();
        p.mtu = 0;
        assert!(p.validate().is_err(), "zero mtu");

        let mut p = NetParams::perfect();
        p.loss_pct = 101.0;
        assert!(p.validate().is_err(), "loss above 100%");

        let mut p = NetParams::perfect();
        p.loss_pct = f32::NAN;
        assert!(p.validate().is_err(), "NaN loss");

        let mut p = NetParams::perfect();
        p.reorder_pct = -1.0;
        assert!(p.validate().is_err(), "negative reorder");

        let mut p = NetParams::perfect();
        p.latency_ms = MAX_LATENCY_MS + 1;
        assert!(p.validate().is_err(), "absurd latency");

        assert!(NetSim::new(p, 0).is_err(), "constructor validates");
        assert!(NetParams::perfect().validate().is_ok());
        assert!(NetParams::lan().validate().is_ok());
        assert!(NetParams::wifi().validate().is_ok());
        assert!(NetParams::wan().validate().is_ok());
        assert!(NetParams::bad().validate().is_ok());
    }

    #[test]
    fn rng_is_reproducible_and_outages_chain() {
        let mut a = SimRng::new(42);
        let mut b = SimRng::new(42);
        for _ in 0..1_000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }

        let mut r = SimRng::new(7);
        for _ in 0..10_000 {
            let unit = r.next_f32_unit();
            assert!((0.0..1.0).contains(&unit), "unit draw out of range: {unit}");
            assert!(r.next_range(5) < 5);
            assert_eq!(r.next_range(1), 0);
            assert_eq!(r.next_range(0), 0);
        }

        // Outage windows chain across adjacent gaps.
        let params = NetParams {
            outages: vec![Outage::new(100, 100), Outage::new(200, 50)],
            ..NetParams::perfect()
        };
        assert_eq!(params.outage_end(150), Some(250));
        assert_eq!(params.outage_end(99), None);
        assert_eq!(params.outage_end(250), None);
    }
}
