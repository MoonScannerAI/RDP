//! Staggered route racing — "happy eyeballs" for DirectDesk transports.
//!
//! # The problem
//!
//! A DirectDesk client has several ways to reach a host, ordered by how good
//! the resulting session will be:
//!
//! | # | Candidate | Route reported on success |
//! |---|-----------|---------------------------|
//! | 0 | QUIC over IPv4 | [`TransportRoute::DirectUdp`] |
//! | 1 | QUIC over IPv6 | [`TransportRoute::DirectIpv6`] |
//! | 2 | UDP hole punch | [`TransportRoute::UdpHolePunched`] |
//! | 3 | TCP/TLS fallback | [`TransportRoute::DirectTcp`] |
//! | 4 | Relay | [`TransportRoute::Relayed`] |
//!
//! Trying them strictly in order is slow: a firewall that blackholes UDP costs
//! a full connect timeout before TCP is even attempted. Trying them all at once
//! is fast but wasteful, and it reliably picks the *worst* route on a healthy
//! network, because TCP handshakes complete first on a short RTT.
//!
//! # The policy, stated plainly
//!
//! - **Stagger.** Candidate `N+1` starts [`RaceConfig::stagger_ms`] after
//!   candidate `N` (250 ms by default), not after `N` fails. A dead UDP path
//!   therefore delays TCP by 750 ms, not by a connect timeout.
//! - **Grace.** The first success does *not* automatically win. If a
//!   lower-priority candidate finishes first, the racer waits
//!   [`RaceConfig::grace_ms`] (500 ms) for any still-running higher-priority
//!   candidate to beat it. A top-priority success wins instantly — there is
//!   nothing better to wait for.
//! - **No new attempts after a success.** Once anything has connected, the
//!   racer stops starting candidates further down the ladder.
//! - **Honest reporting.** The winner's [`TransportRoute`] is whatever actually
//!   won. A relayed session reports [`TransportRoute::Relayed`], never
//!   "direct".
//! - **Clean cancellation.** Losing attempts are dropped the instant a winner
//!   is declared, which cancels their futures.
//! - **Diagnosable failure.** When everything fails the error carries one
//!   [`AttemptFailure`] per candidate — route, name, reason, and the elapsed
//!   time at which it gave up — which is exactly what the diagnostics pane
//!   needs to render.
//!
//! # Why an injected clock
//!
//! [`Race`] is a hand-written [`Future`]: it owns no tasks, spawns nothing, and
//! reads time only through [`RaceClock`]. That makes the entire policy testable
//! by polling it with a [`ManualClock`] and stepping virtual time — no runtime,
//! no sleeps, no flaky timing. [`TokioClock`] is the production driver.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use parking_lot::Mutex;

use crate::error::{Error, Result};
use crate::stats::TransportRoute;

/// Delay between starting consecutive candidates.
pub const DEFAULT_STAGGER_MS: u64 = 250;

/// How long a lower-priority success waits for a higher-priority attempt.
pub const DEFAULT_GRACE_MS: u64 = 500;

/// Ceiling on the whole race, after which the best result so far is taken (or
/// the race fails).
pub const DEFAULT_OVERALL_TIMEOUT_MS: u64 = 20_000;

/// A connection attempt: a future that either yields a connection or explains
/// why it could not.
pub type Attempt<T> = Pin<Box<dyn Future<Output = Result<T>> + Send>>;

/// A timer handed back by a [`RaceClock`].
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// The only way [`Race`] observes time.
///
/// Implementations must be monotonic: `now_ms` may never go backwards.
pub trait RaceClock: Send + Sync {
    /// Milliseconds since some fixed, implementation-chosen origin.
    fn now_ms(&self) -> u64;
    /// A future that completes at or after `at_ms` on this clock.
    fn sleep_until(&self, at_ms: u64) -> Sleep;
}

/// The production clock: [`tokio::time`], with an origin at construction.
///
/// Uses `tokio::time::Instant`, so `tokio::time::pause()` works on it too.
#[derive(Debug)]
pub struct TokioClock {
    origin: tokio::time::Instant,
}

impl TokioClock {
    /// A clock whose zero is now.
    pub fn new() -> Arc<Self> {
        Arc::new(Self { origin: tokio::time::Instant::now() })
    }
}

impl RaceClock for TokioClock {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn sleep_until(&self, at_ms: u64) -> Sleep {
        let deadline = self.origin + Duration::from_millis(at_ms);
        Box::pin(tokio::time::sleep_until(deadline))
    }
}

/// Shared state of a [`ManualClock`], kept behind its own `Arc` so the futures
/// handed out by `sleep_until` can be `'static` without any unsafe pointer
/// games.
#[derive(Debug, Default)]
struct ManualState {
    now: Mutex<u64>,
    wakers: Mutex<Vec<std::task::Waker>>,
}

/// A clock whose time only moves when a test moves it.
///
/// Public because it is genuinely useful to the host and client crates: any
/// route-selection policy built on [`Race`] can be tested the same way, with no
/// runtime and no real sleeps.
#[derive(Debug, Default, Clone)]
pub struct ManualClock {
    state: Arc<ManualState>,
}

impl ManualClock {
    /// A clock sitting at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Jump forward by `delta_ms` and wake anything sleeping.
    pub fn advance(&self, delta_ms: u64) {
        *self.state.now.lock() += delta_ms;
        self.wake_all();
    }

    /// Jump to an absolute time. Never moves backwards.
    pub fn set(&self, at_ms: u64) {
        {
            let mut n = self.state.now.lock();
            *n = (*n).max(at_ms);
        }
        self.wake_all();
    }

    fn wake_all(&self) {
        let waiters: Vec<_> = self.state.wakers.lock().drain(..).collect();
        for w in waiters {
            w.wake();
        }
    }
}

impl RaceClock for ManualClock {
    fn now_ms(&self) -> u64 {
        *self.state.now.lock()
    }

    fn sleep_until(&self, at_ms: u64) -> Sleep {
        Box::pin(ManualSleep { at_ms, state: self.state.clone() })
    }
}

struct ManualSleep {
    at_ms: u64,
    state: Arc<ManualState>,
}

impl Future for ManualSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if *self.state.now.lock() >= self.at_ms {
            return Poll::Ready(());
        }
        self.state.wakers.lock().push(cx.waker().clone());
        Poll::Pending
    }
}

// ---------------------------------------------------------------------------
// Candidates, results, errors
// ---------------------------------------------------------------------------

/// One rung on the connection ladder.
pub struct Candidate<T> {
    /// The route to report if this candidate wins. Must be honest.
    pub route: TransportRoute,
    /// Human-readable name, used in diagnostics output.
    pub name: String,
    /// The work.
    pub attempt: Attempt<T>,
}

impl<T> fmt::Debug for Candidate<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("route", &self.route)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<T: 'static> Candidate<T> {
    /// Wrap a connect future as a candidate.
    pub fn new<F>(route: TransportRoute, name: impl Into<String>, attempt: F) -> Self
    where
        F: Future<Output = Result<T>> + Send + 'static,
    {
        Self { route, name: name.into(), attempt: Box::pin(attempt) }
    }

    /// A candidate that is not implemented yet (hole punching, relay).
    ///
    /// It fails immediately rather than being omitted, so the ladder shape and
    /// the diagnostics output stay honest about what was tried.
    pub fn unavailable(
        route: TransportRoute,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let reason = reason.into();
        Self::new(route, name, async move { Err(Error::Transport(reason)) })
    }
}

/// Why one candidate did not win.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptFailure {
    /// The route that candidate would have provided.
    pub route: TransportRoute,
    /// The candidate's name.
    pub name: String,
    /// The error text, for the diagnostics pane.
    pub detail: String,
    /// Milliseconds from race start to the failure.
    pub at_ms: u64,
}

impl fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}) after {} ms: {}", self.name, self.route.label(), self.at_ms, self.detail)
    }
}

/// What the race produced.
#[derive(Debug)]
pub struct RaceOutcome<T> {
    /// The winning connection.
    pub value: T,
    /// The route that actually won.
    pub route: TransportRoute,
    /// The winning candidate's name.
    pub name: String,
    /// Milliseconds from race start to the decision (includes any grace wait).
    pub elapsed_ms: u64,
    /// Everything that failed along the way. Useful even on success.
    pub failures: Vec<AttemptFailure>,
}

/// Every candidate failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceError {
    /// One entry per candidate, in ladder order.
    pub failures: Vec<AttemptFailure>,
    /// Milliseconds from race start to giving up.
    pub elapsed_ms: u64,
    /// True when the overall timeout fired with attempts still running.
    pub timed_out: bool,
}

impl fmt::Display for RaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.timed_out {
            write!(f, "no route connected within {} ms", self.elapsed_ms)?;
        } else {
            write!(f, "no route connected after {} ms", self.elapsed_ms)?;
        }
        for fail in &self.failures {
            write!(f, "; {fail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RaceError {}

impl From<RaceError> for Error {
    fn from(e: RaceError) -> Self {
        Error::Transport(e.to_string())
    }
}

/// Racing tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaceConfig {
    /// Delay between starting consecutive candidates. `0` starts them all at
    /// once.
    pub stagger_ms: u64,
    /// How long a lower-priority success waits to be beaten. `0` means first
    /// success wins outright.
    pub grace_ms: u64,
    /// Hard ceiling on the whole race.
    pub overall_timeout_ms: u64,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            stagger_ms: DEFAULT_STAGGER_MS,
            grace_ms: DEFAULT_GRACE_MS,
            overall_timeout_ms: DEFAULT_OVERALL_TIMEOUT_MS,
        }
    }
}

impl RaceConfig {
    /// Reject configurations that cannot make a sensible decision.
    pub fn validate(&self, candidates: usize) -> Result<()> {
        if candidates == 0 {
            return Err(Error::Invalid("route race needs at least one candidate".into()));
        }
        if self.overall_timeout_ms == 0 {
            return Err(Error::Invalid("race overall timeout must be non-zero".into()));
        }
        // The last candidate must get a chance to start before the deadline,
        // otherwise the ladder silently degrades to a shorter one.
        let last_start = self.stagger_ms.saturating_mul(candidates as u64 - 1);
        if last_start >= self.overall_timeout_ms {
            return Err(Error::Invalid(format!(
                "stagger {} ms x {} candidates does not fit in a {} ms race",
                self.stagger_ms, candidates, self.overall_timeout_ms
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The racer
// ---------------------------------------------------------------------------

struct Slot<T> {
    route: TransportRoute,
    name: String,
    attempt: Option<Attempt<T>>,
    started: bool,
    /// Virtual time at which this candidate was started, for tests and
    /// diagnostics.
    started_at_ms: Option<u64>,
    finished: bool,
}

/// The staggered race, as a future.
///
/// Drop it to cancel every attempt still running.
pub struct Race<T> {
    slots: Vec<Slot<T>>,
    config: RaceConfig,
    clock: Arc<dyn RaceClock>,
    start_ms: u64,
    next_index: usize,
    winner: Option<(usize, T)>,
    grace_deadline_ms: Option<u64>,
    failures: Vec<AttemptFailure>,
    timer: Option<(u64, Sleep)>,
    done: bool,
}

impl<T> fmt::Debug for Race<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Race")
            .field("candidates", &self.slots.len())
            .field("started", &self.next_index)
            .field("failures", &self.failures.len())
            .field("has_winner", &self.winner.is_some())
            .finish()
    }
}

/// Build a race over `candidates` with an explicit clock.
///
/// Candidates are tried in the order given; index 0 is the most preferred.
pub fn race_with_clock<T>(
    candidates: Vec<Candidate<T>>,
    config: RaceConfig,
    clock: Arc<dyn RaceClock>,
) -> Result<Race<T>> {
    config.validate(candidates.len())?;
    let start_ms = clock.now_ms();
    let slots = candidates
        .into_iter()
        .map(|c| Slot {
            route: c.route,
            name: c.name,
            attempt: Some(c.attempt),
            started: false,
            started_at_ms: None,
            finished: false,
        })
        .collect();
    Ok(Race {
        slots,
        config,
        clock,
        start_ms,
        next_index: 0,
        winner: None,
        grace_deadline_ms: None,
        failures: Vec::new(),
        timer: None,
        done: false,
    })
}

/// Race `candidates` on the tokio clock.
///
/// The convenience entry point for production code.
pub async fn race_routes<T: Unpin>(
    candidates: Vec<Candidate<T>>,
    config: RaceConfig,
) -> Result<RaceOutcome<T>> {
    let race = race_with_clock(candidates, config, TokioClock::new())?;
    race.await.map_err(Error::from)
}

impl<T> Race<T> {
    /// The virtual time at which each candidate was started, `None` if it never
    /// was. Exposed for tests and for the diagnostics timeline.
    pub fn start_times_ms(&self) -> Vec<Option<u64>> {
        self.slots.iter().map(|s| s.started_at_ms.map(|t| t - self.start_ms)).collect()
    }

    /// Drop every attempt still in flight. Cancellation is just `Drop` on the
    /// futures, but doing it at the decision point rather than whenever the
    /// caller drops the race is what makes "cancel losers cleanly" true.
    fn cancel_all(&mut self) {
        for slot in &mut self.slots {
            slot.attempt = None;
        }
        self.timer = None;
    }

    fn finish_ok(&mut self, elapsed_ms: u64) -> Poll<std::result::Result<RaceOutcome<T>, RaceError>>
    where
        T: Unpin,
    {
        let (idx, value) = self.winner.take().expect("finish_ok without a winner");
        let route = self.slots[idx].route;
        let name = self.slots[idx].name.clone();
        let failures = std::mem::take(&mut self.failures);
        self.cancel_all();
        self.done = true;
        Poll::Ready(Ok(RaceOutcome { value, route, name, elapsed_ms, failures }))
    }

    fn finish_err(
        &mut self,
        elapsed_ms: u64,
        timed_out: bool,
    ) -> Poll<std::result::Result<RaceOutcome<T>, RaceError>> {
        let mut failures = std::mem::take(&mut self.failures);
        // A candidate that was still running (or never started) when the
        // overall timeout fired still deserves a diagnostics line.
        for slot in &self.slots {
            if !slot.finished {
                failures.push(AttemptFailure {
                    route: slot.route,
                    name: slot.name.clone(),
                    detail: if slot.started {
                        "still connecting when the race timed out".into()
                    } else {
                        "never started: the race ended first".into()
                    },
                    at_ms: elapsed_ms,
                });
            }
        }
        failures.sort_by_key(|f| {
            self.slots.iter().position(|s| s.name == f.name).unwrap_or(usize::MAX)
        });
        self.cancel_all();
        self.done = true;
        Poll::Ready(Err(RaceError { failures, elapsed_ms, timed_out }))
    }
}

impl<T: Unpin> Future for Race<T> {
    type Output = std::result::Result<RaceOutcome<T>, RaceError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.done, "Race polled after completion");

        loop {
            let now = this.clock.now_ms();
            let elapsed = now.saturating_sub(this.start_ms);

            // --- 1. Start whatever the stagger says is due. --------------
            // Nothing new starts once something has already connected: the
            // point of the ladder is to stop descending.
            if this.winner.is_none() {
                while this.next_index < this.slots.len() {
                    let due = this.config.stagger_ms.saturating_mul(this.next_index as u64);
                    if elapsed < due {
                        break;
                    }
                    let slot = &mut this.slots[this.next_index];
                    slot.started = true;
                    slot.started_at_ms = Some(now);
                    this.next_index += 1;
                }
            }

            // --- 2. Poll everything running, best candidate first. -------
            for i in 0..this.slots.len() {
                let slot = &mut this.slots[i];
                if !slot.started || slot.finished {
                    continue;
                }
                let Some(attempt) = slot.attempt.as_mut() else {
                    continue;
                };
                match attempt.as_mut().poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(value)) => {
                        slot.finished = true;
                        slot.attempt = None;
                        // A better (lower-index) success always replaces a
                        // provisional one; a worse one is ignored outright.
                        let better = match &this.winner {
                            None => true,
                            Some((prev, _)) => i < *prev,
                        };
                        if better {
                            this.winner = Some((i, value));
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        slot.finished = true;
                        slot.attempt = None;
                        let (route, name) = (slot.route, slot.name.clone());
                        this.failures.push(AttemptFailure {
                            route,
                            name,
                            detail: e.to_string(),
                            at_ms: elapsed,
                        });
                    }
                }
            }

            // --- 3. Decide. ---------------------------------------------
            if let Some((widx, _)) = &this.winner {
                let widx = *widx;
                // Is anything strictly better still able to win?
                let contender = this.slots[..widx].iter().any(|s| !s.finished);
                if !contender {
                    return this.finish_ok(elapsed);
                }
                if this.config.grace_ms == 0 {
                    return this.finish_ok(elapsed);
                }
                let deadline = *this.grace_deadline_ms.get_or_insert(now + this.config.grace_ms);
                if now >= deadline {
                    return this.finish_ok(elapsed);
                }
            } else if this.next_index == this.slots.len()
                && this.slots.iter().all(|s| s.finished)
            {
                return this.finish_err(elapsed, false);
            }

            if elapsed >= this.config.overall_timeout_ms {
                return if this.winner.is_some() {
                    this.finish_ok(elapsed)
                } else {
                    this.finish_err(elapsed, true)
                };
            }

            // --- 4. Sleep until the next instant that could change a
            //        decision: the next stagger tick, the end of the grace
            //        window, or the overall deadline.
            let mut wake_at = this.start_ms + this.config.overall_timeout_ms;
            if this.winner.is_none() && this.next_index < this.slots.len() {
                let due = this
                    .start_ms
                    .saturating_add(this.config.stagger_ms.saturating_mul(this.next_index as u64));
                wake_at = wake_at.min(due);
            }
            if let Some(d) = this.grace_deadline_ms {
                wake_at = wake_at.min(d);
            }

            let rearm = match &this.timer {
                Some((at, _)) => *at != wake_at,
                None => true,
            };
            if rearm {
                this.timer = Some((wake_at, this.clock.sleep_until(wake_at)));
            }
            let timer = &mut this.timer.as_mut().expect("timer just armed").1;
            match timer.as_mut().poll(cx) {
                // Time has moved to `wake_at`; go round again and re-evaluate.
                // Each such pass either starts a candidate, ends the grace
                // window, or ends the race, so this cannot spin.
                Poll::Ready(()) => {
                    this.timer = None;
                    continue;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The standard ladder
// ---------------------------------------------------------------------------

/// The candidate ladder DirectDesk uses, in order, as (route, name) pairs.
///
/// Kept as data so the host, the client and the diagnostics pane cannot drift
/// apart about what "the ladder" is.
pub const LADDER: [(TransportRoute, &str); 5] = [
    (TransportRoute::DirectUdp, "QUIC IPv4"),
    (TransportRoute::DirectIpv6, "QUIC IPv6"),
    (TransportRoute::UdpHolePunched, "UDP hole punch"),
    (TransportRoute::DirectTcp, "TCP/TLS fallback"),
    (TransportRoute::Relayed, "Relay"),
];

/// Reason string used by the not-yet-implemented rungs.
pub const NOT_IMPLEMENTED: &str = "not implemented in this build";

/// A hole-punch candidate that is immediately unavailable (M5 work).
pub fn hole_punch_stub<T: 'static>() -> Candidate<T> {
    Candidate::unavailable(LADDER[2].0, LADDER[2].1, NOT_IMPLEMENTED)
}

/// A relay candidate that is immediately unavailable (M6 work).
pub fn relay_stub<T: 'static>() -> Candidate<T> {
    Candidate::unavailable(LADDER[4].0, LADDER[4].1, NOT_IMPLEMENTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // -----------------------------------------------------------------
    // A deterministic harness: no runtime, no sleeps, virtual time only.
    // -----------------------------------------------------------------

    fn poll_once<F: Future + Unpin>(f: &mut F) -> Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        Pin::new(f).poll(&mut cx)
    }

    /// Step virtual time in 10 ms ticks up to `limit_ms`, polling each tick.
    /// Returns the virtual time at which the race resolved and its output.
    fn drive<T: Unpin>(
        race: &mut Race<T>,
        clock: &ManualClock,
        limit_ms: u64,
    ) -> (u64, std::result::Result<RaceOutcome<T>, RaceError>) {
        let mut t = 0;
        loop {
            clock.set(t);
            if let Poll::Ready(out) = poll_once(race) {
                return (t, out);
            }
            assert!(t <= limit_ms, "race did not resolve within {limit_ms} ms");
            t += 10;
        }
    }

    /// An attempt that resolves at a fixed point on the manual clock, and
    /// records the first virtual instant at which it was polled.
    struct Scripted {
        clock: Arc<ManualClock>,
        at_ms: u64,
        ok: bool,
        detail: &'static str,
        first_poll_ms: Arc<Mutex<Option<u64>>>,
        dropped: Arc<AtomicU64>,
    }

    impl Future for Scripted {
        type Output = Result<&'static str>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            let now = self.clock.now_ms();
            {
                let mut first = self.first_poll_ms.lock();
                if first.is_none() {
                    *first = Some(now);
                }
            }
            if now < self.at_ms {
                return Poll::Pending;
            }
            if self.ok {
                Poll::Ready(Ok(self.detail))
            } else {
                Poll::Ready(Err(Error::Transport(self.detail.to_string())))
            }
        }
    }

    impl Drop for Scripted {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Script {
        clock: Arc<ManualClock>,
        drops: Arc<AtomicU64>,
        first_polls: Vec<Arc<Mutex<Option<u64>>>>,
    }

    impl Script {
        fn new(clock: Arc<ManualClock>) -> Self {
            Self { clock, drops: Arc::new(AtomicU64::new(0)), first_polls: Vec::new() }
        }

        fn at(
            &mut self,
            route: TransportRoute,
            name: &'static str,
            at_ms: u64,
            ok: bool,
        ) -> Candidate<&'static str> {
            let first = Arc::new(Mutex::new(None));
            self.first_polls.push(first.clone());
            Candidate::new(
                route,
                name,
                Scripted {
                    clock: self.clock.clone(),
                    at_ms,
                    ok,
                    detail: name,
                    first_poll_ms: first,
                    dropped: self.drops.clone(),
                },
            )
        }

        /// Never resolves.
        fn hangs(&mut self, route: TransportRoute, name: &'static str) -> Candidate<&'static str> {
            self.at(route, name, u64::MAX, false)
        }

        fn first_poll(&self, i: usize) -> Option<u64> {
            *self.first_polls[i].lock()
        }
    }

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------

    #[test]
    fn race_config_rejects_nonsense() {
        let c = RaceConfig::default();
        assert!(c.validate(5).is_ok());
        assert!(c.validate(0).is_err(), "no candidates is a caller bug");
        assert!(RaceConfig { overall_timeout_ms: 0, ..c }.validate(5).is_err());
        // A 250 ms stagger over 5 candidates needs a full second of headroom.
        assert!(RaceConfig { overall_timeout_ms: 500, ..c }.validate(5).is_err());
    }

    #[test]
    fn ladder_is_ordered_and_honest() {
        assert_eq!(LADDER.len(), 5);
        assert_eq!(LADDER[0].0, TransportRoute::DirectUdp);
        assert_eq!(LADDER[3].0, TransportRoute::DirectTcp);
        assert_eq!(LADDER[4].0, TransportRoute::Relayed);
        assert!(!LADDER[4].0.is_direct(), "the relay rung must not claim to be direct");
    }

    // -----------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------

    #[test]
    fn primary_wins_immediately_without_a_grace_wait() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 30, true),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 40, true),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("primary should win");
        assert_eq!(outcome.route, TransportRoute::DirectUdp);
        assert_eq!(outcome.value, "QUIC IPv4");
        assert_eq!(at, 30, "no grace wait when the best candidate wins");
        assert!(outcome.failures.is_empty());
    }

    #[test]
    fn candidates_start_on_the_stagger_not_all_at_once() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 900, true),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (_, out) = drive(&mut race, &clock, 5_000);
        out.expect("tcp should win");

        assert_eq!(s.first_poll(0), Some(0), "the best candidate starts at once");
        assert_eq!(s.first_poll(1), Some(250), "second candidate waits one stagger");
        assert_eq!(s.first_poll(2), Some(500), "third candidate waits two staggers");
    }

    #[test]
    fn slow_primary_loses_to_tcp_after_the_grace_window() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 5_000, true),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 5_000, true),
            hole_punch_stub(),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 800, true),
            relay_stub(),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("tcp should win after the grace period");
        assert_eq!(outcome.route, TransportRoute::DirectTcp);
        assert_eq!(at, 1_300, "800 ms to connect plus a 500 ms grace window");
        // The hole-punch stub failed on the way; that belongs in diagnostics.
        assert!(outcome.failures.iter().any(|f| f.route == TransportRoute::UdpHolePunched));
    }

    #[test]
    fn primary_succeeding_inside_the_grace_window_beats_tcp() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 1_000, true),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
            hole_punch_stub(),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 800, true),
            relay_stub(),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("primary should win inside the grace window");
        assert_eq!(outcome.route, TransportRoute::DirectUdp);
        assert_eq!(at, 1_000, "resolves the instant the better route lands");
        assert!(at < 1_300, "must not wait out the grace window it no longer needs");
    }

    #[test]
    fn a_worse_route_finishing_during_grace_does_not_displace_the_winner() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 300, true),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 350, true),
        ];
        // Stagger off so the worse candidate is genuinely in flight and lands
        // *during* the grace window rather than never starting.
        let cfg = RaceConfig { stagger_ms: 0, ..RaceConfig::default() };
        let mut race = race_with_clock(cands, cfg, clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("ipv6 should win");
        assert_eq!(outcome.route, TransportRoute::DirectIpv6);
        assert_eq!(outcome.value, "QUIC IPv6");
        assert_eq!(at, 800, "300 ms + 500 ms grace for the still-running IPv4 attempt");
    }

    #[test]
    fn a_better_route_displaces_the_winner_without_extending_the_grace_window() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 600, true),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 550, true),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("ipv6 should displace tcp");
        assert_eq!(outcome.route, TransportRoute::DirectIpv6);
        // TCP won provisionally at 550, opening a grace window to 1050. IPv6
        // beat it at 600, but IPv4 is still running, so we wait out the
        // *original* window — a promotion must not restart the clock.
        assert_eq!(at, 1_050);
    }

    #[test]
    fn no_new_candidates_start_after_a_success() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 300, true),
            s.hangs(TransportRoute::DirectTcp, "TCP/TLS fallback"),
            s.hangs(TransportRoute::Relayed, "Relay"),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let outcome = out.expect("ipv6 wins");
        assert_eq!(outcome.route, TransportRoute::DirectIpv6);
        assert_eq!(at, 800, "300 ms + 500 ms grace for the IPv4 attempt");
        // TCP was due at 500 ms and the relay at 750 ms, but IPv6 had already
        // connected by then. Descending the ladder past a working route is
        // exactly what this policy exists to prevent.
        assert!(s.first_poll(2).is_none(), "the TCP rung must never have been started");
        assert!(s.first_poll(3).is_none(), "the relay rung must never have been started");
    }

    #[test]
    fn losing_attempts_are_dropped_at_the_decision_point() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let drops = s.drops.clone();
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 100, true),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
            s.hangs(TransportRoute::DirectTcp, "TCP/TLS fallback"),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let (_, out) = drive(&mut race, &clock, 5_000);
        out.expect("primary wins");
        // The winner's own future is dropped when it resolves; the two losers
        // are dropped by `cancel_all`, while the `Race` itself is still alive.
        assert_eq!(drops.load(Ordering::SeqCst), 3, "every attempt future must be released");
    }

    #[test]
    fn every_candidate_failing_reports_every_candidate() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 100, false),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 400, false),
            hole_punch_stub(),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 900, false),
            relay_stub(),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        let (_, out) = drive(&mut race, &clock, 5_000);
        let err = out.expect_err("everything failed");
        assert!(!err.timed_out);
        assert_eq!(err.failures.len(), 5, "one diagnostics line per candidate");
        let routes: Vec<_> = err.failures.iter().map(|f| f.route).collect();
        assert_eq!(
            routes,
            vec![
                TransportRoute::DirectUdp,
                TransportRoute::DirectIpv6,
                TransportRoute::UdpHolePunched,
                TransportRoute::DirectTcp,
                TransportRoute::Relayed,
            ],
            "failures are reported in ladder order"
        );
        // The stubs must say why they were unavailable, not just "failed".
        assert!(err.failures[2].detail.contains(NOT_IMPLEMENTED));
        assert!(err.failures[4].detail.contains(NOT_IMPLEMENTED));
        let text = err.to_string();
        assert!(text.contains("QUIC IPv4") && text.contains("TCP/TLS fallback"), "{text}");
    }

    #[test]
    fn overall_timeout_reports_the_candidates_still_hanging() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.at(TransportRoute::DirectIpv6, "QUIC IPv6", 100, false),
            s.hangs(TransportRoute::DirectTcp, "TCP/TLS fallback"),
        ];
        let cfg = RaceConfig { overall_timeout_ms: 2_000, ..RaceConfig::default() };
        let mut race = race_with_clock(cands, cfg, clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        let err = out.expect_err("nothing connected");
        assert!(err.timed_out);
        assert_eq!(at, 2_000);
        assert_eq!(err.failures.len(), 3);
        assert!(err.failures[0].detail.contains("still connecting"));
        assert!(err.failures[1].detail.contains("QUIC IPv6"));
    }

    #[test]
    fn zero_grace_takes_the_first_success_outright() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.at(TransportRoute::DirectUdp, "QUIC IPv4", 1_000, true),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 300, true),
        ];
        let cfg = RaceConfig { grace_ms: 0, ..RaceConfig::default() };
        let mut race = race_with_clock(cands, cfg, clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 5_000);
        assert_eq!(out.expect("tcp wins").route, TransportRoute::DirectTcp);
        assert_eq!(at, 300);
    }

    #[test]
    fn zero_stagger_starts_everything_at_once() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
            s.at(TransportRoute::DirectTcp, "TCP/TLS fallback", 50, true),
        ];
        let cfg = RaceConfig { stagger_ms: 0, ..RaceConfig::default() };
        let mut race = race_with_clock(cands, cfg, clock.clone()).expect("build race");
        let (_, out) = drive(&mut race, &clock, 5_000);
        out.expect("tcp wins");
        assert_eq!(s.first_poll(0), Some(0));
        assert_eq!(s.first_poll(1), Some(0));
        assert_eq!(s.first_poll(2), Some(0));
    }

    #[test]
    fn start_times_are_visible_for_diagnostics() {
        let clock = ManualClock::new();
        let mut s = Script::new(clock.clone());
        let cands = vec![
            s.hangs(TransportRoute::DirectUdp, "QUIC IPv4"),
            s.hangs(TransportRoute::DirectIpv6, "QUIC IPv6"),
        ];
        let mut race =
            race_with_clock(cands, RaceConfig::default(), clock.clone()).expect("build race");
        clock.set(0);
        let _ = poll_once(&mut race);
        assert_eq!(race.start_times_ms(), vec![Some(0), None]);
        clock.set(300);
        let _ = poll_once(&mut race);
        assert_eq!(race.start_times_ms(), vec![Some(0), Some(300)]);
    }

    #[test]
    fn race_error_converts_into_a_transport_error() {
        let e = RaceError {
            failures: vec![AttemptFailure {
                route: TransportRoute::DirectTcp,
                name: "TCP/TLS fallback".into(),
                detail: "connection refused".into(),
                at_ms: 120,
            }],
            elapsed_ms: 900,
            timed_out: false,
        };
        let converted: Error = e.into();
        let text = converted.to_string();
        assert!(text.contains("connection refused"), "{text}");
        assert!(text.contains("Direct TCP"), "{text}");
    }

    #[test]
    fn stubs_fail_immediately_and_name_themselves() {
        let clock = ManualClock::new();
        let cands: Vec<Candidate<&'static str>> = vec![hole_punch_stub(), relay_stub()];
        let cfg = RaceConfig { stagger_ms: 0, ..RaceConfig::default() };
        let mut race = race_with_clock(cands, cfg, clock.clone()).expect("build race");
        let (at, out) = drive(&mut race, &clock, 1_000);
        let err = out.expect_err("stubs cannot connect");
        assert_eq!(at, 0, "an unavailable rung must not cost any time");
        assert_eq!(err.failures.len(), 2);
        assert_eq!(err.failures[0].route, TransportRoute::UdpHolePunched);
        assert_eq!(err.failures[1].route, TransportRoute::Relayed);
    }

    // -----------------------------------------------------------------
    // The real driver, on the real clock.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn tokio_clock_drives_the_same_policy() {
        let cands: Vec<Candidate<&'static str>> = vec![
            Candidate::new(TransportRoute::DirectUdp, "QUIC IPv4", async { Ok("udp") }),
            hole_punch_stub(),
            Candidate::new(TransportRoute::DirectTcp, "TCP/TLS fallback", async { Ok("tcp") }),
            relay_stub(),
        ];
        let outcome = race_routes(cands, RaceConfig::default()).await.expect("udp wins");
        assert_eq!(outcome.route, TransportRoute::DirectUdp);
        assert_eq!(outcome.value, "udp");
        // Only the top rung ran, so nothing failed and nothing was staggered in.
        assert!(outcome.failures.is_empty());
    }

    #[tokio::test]
    async fn tokio_clock_reports_total_failure() {
        let cands: Vec<Candidate<&'static str>> = vec![
            Candidate::unavailable(TransportRoute::DirectUdp, "QUIC IPv4", "no udp here"),
            hole_punch_stub(),
            Candidate::unavailable(TransportRoute::DirectTcp, "TCP/TLS fallback", "refused"),
            relay_stub(),
        ];
        let cfg = RaceConfig { stagger_ms: 0, ..RaceConfig::default() };
        let err = race_routes(cands, cfg).await.expect_err("nothing can connect");
        let text = err.to_string();
        assert!(text.contains("no udp here"), "{text}");
        assert!(text.contains("refused"), "{text}");
        assert!(text.contains(NOT_IMPLEMENTED), "{text}");
    }
}
