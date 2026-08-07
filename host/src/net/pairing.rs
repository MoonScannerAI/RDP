//! The two gates in front of a session: the host's pairing window and the
//! failed-authentication throttle.
//!
//! Both are small state machines that take `now_ms` on every call instead of
//! reading a clock, so expiry and lockout are testable without sleeping.
//! [`PairingSlot::now_ms`] is the one place a clock is read, and the monotonic
//! time base it hands out is what the throttle and every rate limiter are
//! measured against.
//!
//! Only the *admission decision* lives here. The protocol these two gate —
//! the SPAKE2 exchange, the challenge signatures, the trusted-key store — is
//! in [`crate::net`], and so is every side effect (events, logging, closing
//! the connection).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use parking_lot::Mutex;

use directdesk_shared::crypto::pairing::{PairingCode, PAIRING_TTL_MS};

/// Wall-clock budget for everything from `accept_streams` to `AuthOk`.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 15_000;
/// Consecutive authentication failures from one address before a lockout.
pub const AUTH_FAIL_LIMIT: u32 = 3;
/// How long an address stays locked out after [`AUTH_FAIL_LIMIT`] failures.
pub const AUTH_LOCKOUT_MS: u64 = 30_000;
/// Failures older than this stop counting toward the limit.
pub const AUTH_FAIL_WINDOW_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// Pairing window
// ---------------------------------------------------------------------------

/// What the UI needs to render an armed pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingDisplay {
    /// The eight digits, already grouped as `1234 5678`.
    pub grouped: String,
    /// The raw digits. Present because the UI must display them and the
    /// loopback test must be able to type them; never logged.
    pub digits: String,
    /// Milliseconds until the code stops being accepted.
    pub remaining_ms: u64,
}

pub(super) struct Armed {
    pub(super) code: PairingCode,
    pub(super) armed_ms: u64,
    pub(super) ttl_ms: u64,
}

/// The host's single pairing window, and the monotonic clock everything else
/// in this module is timed against.
///
/// Shared between the UI (which arms it and shows the countdown) and the
/// listener (which consumes it). The state machine itself takes `now_ms` on
/// every call, so expiry is testable without sleeping; [`Self::now_ms`] is the
/// one place that reads a clock, and it is an [`Instant`], never the wall
/// clock, so a system time change cannot extend or void a pairing window.
///
/// Both halves share one slot precisely so the countdown the user is reading
/// and the deadline the listener enforces cannot drift apart.
pub struct PairingSlot {
    inner: Mutex<Option<Armed>>,
    clock: Instant,
}

impl Default for PairingSlot {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
            clock: Instant::now(),
        }
    }
}

impl std::fmt::Debug for PairingSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let armed = self.inner.lock().is_some();
        f.debug_struct("PairingSlot")
            .field("armed", &armed)
            .finish()
    }
}

impl PairingSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds since this slot was created. The shared time base for the
    /// pairing window, the authentication throttle and every rate limiter.
    pub fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    /// Arm with a fresh random code, replacing anything already armed.
    pub fn arm(&self, now_ms: u64) -> PairingDisplay {
        self.arm_with(PairingCode::generate(), now_ms, PAIRING_TTL_MS)
    }

    /// Arm with a specific code and TTL. Used by tests.
    pub fn arm_with(&self, code: PairingCode, now_ms: u64, ttl_ms: u64) -> PairingDisplay {
        let display = PairingDisplay {
            grouped: code.display_grouped(),
            digits: code.expose().to_string(),
            remaining_ms: ttl_ms,
        };
        *self.inner.lock() = Some(Armed {
            code,
            armed_ms: now_ms,
            ttl_ms,
        });
        display
    }

    /// The armed code, or `None` when nothing is armed or it has expired.
    ///
    /// Expiry is evaluated lazily here so the UI's countdown and the
    /// listener's acceptance decision can never disagree.
    pub fn snapshot(&self, now_ms: u64) -> Option<PairingDisplay> {
        let mut guard = self.inner.lock();
        let armed = guard.as_ref()?;
        match remaining_ms(armed, now_ms) {
            Some(remaining_ms) => Some(PairingDisplay {
                grouped: armed.code.display_grouped(),
                digits: armed.code.expose().to_string(),
                remaining_ms,
            }),
            None => {
                *guard = None;
                None
            }
        }
    }

    /// Whether a live code is armed right now.
    pub fn is_armed(&self, now_ms: u64) -> bool {
        self.snapshot(now_ms).is_some()
    }

    /// Consume the code. Single use: a second `PairStart` finds nothing.
    pub(super) fn take(&self, now_ms: u64) -> Option<Armed> {
        let mut guard = self.inner.lock();
        let armed = guard.take()?;
        remaining_ms(&armed, now_ms).map(|_| armed)
    }

    /// Cancel an armed code (user pressed Cancel, or pairing finished).
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }
}

fn remaining_ms(armed: &Armed, now_ms: u64) -> Option<u64> {
    let deadline = armed.armed_ms.saturating_add(armed.ttl_ms);
    if now_ms > deadline {
        None
    } else {
        Some(deadline - now_ms)
    }
}

// ---------------------------------------------------------------------------
// Failed-authentication throttle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct FailRecord {
    failures: u32,
    last_fail_ms: u64,
    locked_until_ms: u64,
}

/// Per-source-address lockout after repeated authentication failures.
///
/// Pairing codes are eight digits and single-use, and the trusted-key check is
/// a signature verification — neither is guessable online. This exists to make
/// a scripted attempt expensive and, more usefully, to make the attempt
/// *visible* in the UI and the log.
#[derive(Debug, Default)]
pub struct AuthThrottle {
    peers: HashMap<IpAddr, FailRecord>,
}

impl AuthThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds this address must wait, or `None` if it may try now.
    pub fn locked_for_ms(&self, ip: &IpAddr, now_ms: u64) -> Option<u64> {
        let rec = self.peers.get(ip)?;
        (rec.locked_until_ms > now_ms).then(|| rec.locked_until_ms - now_ms)
    }

    /// Record a failure. Returns `true` when this failure triggered a lockout.
    pub fn record_failure(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        self.gc(now_ms);
        let rec = self.peers.entry(ip).or_insert(FailRecord {
            failures: 0,
            last_fail_ms: now_ms,
            locked_until_ms: 0,
        });
        // A long-quiet address starts over rather than accumulating forever.
        if now_ms.saturating_sub(rec.last_fail_ms) > AUTH_FAIL_WINDOW_MS {
            rec.failures = 0;
        }
        rec.failures += 1;
        rec.last_fail_ms = now_ms;
        if rec.failures >= AUTH_FAIL_LIMIT {
            rec.failures = 0;
            rec.locked_until_ms = now_ms.saturating_add(AUTH_LOCKOUT_MS);
            true
        } else {
            false
        }
    }

    /// A successful authentication clears the address's history.
    pub fn record_success(&mut self, ip: &IpAddr) {
        self.peers.remove(ip);
    }

    /// Number of addresses currently being tracked.
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }

    fn gc(&mut self, now_ms: u64) {
        self.peers.retain(|_, r| {
            r.locked_until_ms > now_ms
                || now_ms.saturating_sub(r.last_fail_ms) <= AUTH_FAIL_WINDOW_MS
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::crypto::pairing::PAIRING_CODE_DIGITS;

    // -- pairing window ----------------------------------------------------

    #[test]
    fn pairing_code_is_eight_digits_and_grouped() {
        let slot = PairingSlot::new();
        let d = slot.arm(0);
        assert_eq!(d.digits.len(), PAIRING_CODE_DIGITS);
        assert!(d.digits.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(d.grouped, format!("{} {}", &d.digits[..4], &d.digits[4..]));
        assert_eq!(d.remaining_ms, PAIRING_TTL_MS);
    }

    #[test]
    fn pairing_window_expires_on_the_injected_clock() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("12345678").unwrap(), 1_000, 120_000);
        assert!(slot.is_armed(1_000));
        assert!(slot.is_armed(121_000), "the last millisecond still counts");
        assert!(!slot.is_armed(121_001));
        // Expiry is sticky: the slot cleared itself on the way past.
        assert!(!slot.is_armed(1_000));
    }

    #[test]
    fn pairing_countdown_shrinks() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("11112222").unwrap(), 0, 10_000);
        assert_eq!(slot.snapshot(0).unwrap().remaining_ms, 10_000);
        assert_eq!(slot.snapshot(7_500).unwrap().remaining_ms, 2_500);
        assert!(slot.snapshot(10_001).is_none());
    }

    #[test]
    fn pairing_code_is_single_use() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("87654321").unwrap(), 0, 120_000);
        let first = slot.take(10).expect("first use");
        assert_eq!(first.code.expose(), "87654321");
        assert!(
            slot.take(20).is_none(),
            "a second PairStart must find nothing"
        );
        assert!(!slot.is_armed(20));
    }

    #[test]
    fn expired_code_cannot_be_taken() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("13571357").unwrap(), 0, 1_000);
        assert!(slot.take(1_001).is_none());
    }

    #[test]
    fn arming_replaces_the_previous_code() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("11111111").unwrap(), 0, 120_000);
        slot.arm_with(PairingCode::parse("22222222").unwrap(), 5_000, 120_000);
        assert_eq!(slot.snapshot(5_000).unwrap().digits, "22222222");
        assert_eq!(slot.snapshot(5_000).unwrap().remaining_ms, 120_000);
    }

    #[test]
    fn cancel_clears_the_window() {
        let slot = PairingSlot::new();
        slot.arm(0);
        slot.clear();
        assert!(!slot.is_armed(0));
    }

    #[test]
    fn pairing_slot_debug_never_shows_the_code() {
        let slot = PairingSlot::new();
        let d = slot.arm(0);
        let s = format!("{slot:?}");
        assert!(!s.contains(&d.digits), "{s}");
        assert!(s.contains("armed: true"));
    }

    // -- throttle ----------------------------------------------------------

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn three_failures_lock_the_address_out() {
        let mut t = AuthThrottle::new();
        assert!(t.locked_for_ms(&ip(1), 0).is_none());
        assert!(!t.record_failure(ip(1), 0));
        assert!(!t.record_failure(ip(1), 100));
        assert!(
            t.locked_for_ms(&ip(1), 100).is_none(),
            "two strikes is not a lockout"
        );
        assert!(t.record_failure(ip(1), 200));
        assert_eq!(t.locked_for_ms(&ip(1), 200), Some(AUTH_LOCKOUT_MS));
    }

    #[test]
    fn lockout_expires() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(2), i);
        }
        assert!(t.locked_for_ms(&ip(2), AUTH_LOCKOUT_MS).is_some());
        assert!(t.locked_for_ms(&ip(2), AUTH_LOCKOUT_MS + 3).is_none());
    }

    #[test]
    fn lockout_is_per_address() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(3), i);
        }
        assert!(t.locked_for_ms(&ip(3), 0).is_some());
        assert!(t.locked_for_ms(&ip(4), 0).is_none());
    }

    #[test]
    fn old_failures_stop_counting() {
        let mut t = AuthThrottle::new();
        assert!(!t.record_failure(ip(5), 0));
        assert!(!t.record_failure(ip(5), AUTH_FAIL_WINDOW_MS + 1));
        assert!(
            !t.record_failure(ip(5), AUTH_FAIL_WINDOW_MS + 2),
            "the first failure aged out, so this is only the second"
        );
    }

    #[test]
    fn success_clears_the_history() {
        let mut t = AuthThrottle::new();
        t.record_failure(ip(6), 0);
        t.record_failure(ip(6), 1);
        t.record_success(&ip(6));
        assert_eq!(t.tracked(), 0);
        assert!(
            !t.record_failure(ip(6), 2),
            "counting restarts after a success"
        );
    }

    #[test]
    fn a_locked_out_address_can_be_locked_out_again() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(7), i);
        }
        let after = AUTH_LOCKOUT_MS + 10;
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(7), after + i);
        }
        assert!(t.locked_for_ms(&ip(7), after + 10).is_some());
    }
}
