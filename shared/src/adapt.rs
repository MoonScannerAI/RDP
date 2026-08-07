//! Adaptive-bitrate state machine (transport-agnostic, deterministic,
//! unit-testable). Feed it loss/RTT observations; it emits bitrate targets.
//!
//! Policy (AIMD flavored for high-RTT WAN):
//! - loss > 2% or RTT inflation > 50% over baseline → multiplicative decrease
//! - stable for `raise_after_ms` → additive increase toward the mode ceiling
//! - hard floor/ceiling from the active quality mode

use crate::protocol::QualityMode;

#[derive(Debug, Clone, Copy)]
pub struct AdaptConfig {
    pub floor_kbps: u32,
    pub ceiling_kbps: u32,
    pub start_kbps: u32,
    /// Additive step when raising.
    pub step_kbps: u32,
    /// How long conditions must stay clean before raising.
    pub raise_after_ms: u32,
    /// Multiplicative factor on decrease (e.g. 0.7).
    pub decrease_factor: f32,
}

impl AdaptConfig {
    pub fn for_mode(mode: QualityMode) -> Self {
        match mode {
            QualityMode::TextDesktop => Self {
                // Text is the demanding case, not the cheap one: sharp glyph edges are
                // high-frequency detail and a low ceiling destroys them. A static desktop
                // already costs almost nothing (capture suppresses unchanged frames), so a
                // high ceiling is only actually spent during scrolls and redraws — which is
                // exactly when text needs the bits. The ceiling is deliberately above what a
                // typical residential uplink sustains because it is not meant to be the binding
                // constraint — the AIMD adaptor plus the host's bitrate cap measure the real
                // link and back off, whereas a low ceiling is a guess that binds even on a
                // good day.
                floor_kbps: 1_500,
                ceiling_kbps: 28_000,
                start_kbps: 12_000,
                step_kbps: 500,
                raise_after_ms: 3_000,
                decrease_factor: 0.7,
            },
            QualityMode::Balanced => Self {
                floor_kbps: 1_500,
                ceiling_kbps: 15_000,
                start_kbps: 8_000,
                step_kbps: 750,
                raise_after_ms: 3_000,
                decrease_factor: 0.7,
            },
            QualityMode::Motion => Self {
                floor_kbps: 2_000,
                ceiling_kbps: 15_000,
                start_kbps: 10_000,
                step_kbps: 1_000,
                raise_after_ms: 2_000,
                decrease_factor: 0.75,
            },
            QualityMode::LowBandwidth => Self {
                floor_kbps: 300,
                ceiling_kbps: 2_500,
                start_kbps: 1_000,
                step_kbps: 200,
                raise_after_ms: 4_000,
                decrease_factor: 0.6,
            },
        }
    }
}

#[derive(Debug)]
pub struct BitrateAdaptor {
    cfg: AdaptConfig,
    current_kbps: u32,
    baseline_rtt_ms: f32,
    clean_since_ms: Option<u64>,
    last_change_ms: u64,
}

impl BitrateAdaptor {
    pub fn new(cfg: AdaptConfig) -> Self {
        Self {
            current_kbps: cfg.start_kbps,
            cfg,
            baseline_rtt_ms: f32::MAX,
            clean_since_ms: None,
            last_change_ms: 0,
        }
    }

    pub fn current(&self) -> u32 {
        self.current_kbps
    }

    pub fn set_mode(&mut self, mode: QualityMode, now_ms: u64) {
        let cfg = AdaptConfig::for_mode(mode);
        self.current_kbps = self.current_kbps.clamp(cfg.floor_kbps, cfg.ceiling_kbps);
        self.cfg = cfg;
        self.clean_since_ms = None;
        self.last_change_ms = now_ms;
    }

    /// Feed an observation window. Returns Some(new_kbps) when the target
    /// changed. `now_ms` is a monotonic timestamp supplied by the caller.
    pub fn observe(&mut self, now_ms: u64, loss: f32, rtt_ms: f32) -> Option<u32> {
        if rtt_ms.is_finite() && rtt_ms > 0.0 {
            self.baseline_rtt_ms = self.baseline_rtt_ms.min(rtt_ms);
        }
        let rtt_inflated = self.baseline_rtt_ms.is_finite()
            && self.baseline_rtt_ms != f32::MAX
            && rtt_ms > self.baseline_rtt_ms * 1.5
            && rtt_ms - self.baseline_rtt_ms > 30.0;
        let congested = loss > 0.02 || rtt_inflated;

        if congested {
            self.clean_since_ms = None;
            // Don't decrease more than once per second.
            if now_ms.saturating_sub(self.last_change_ms) >= 1_000 {
                let next = ((self.current_kbps as f32 * self.cfg.decrease_factor) as u32)
                    .max(self.cfg.floor_kbps);
                if next != self.current_kbps {
                    self.current_kbps = next;
                    self.last_change_ms = now_ms;
                    return Some(next);
                }
            }
            return None;
        }

        let since = *self.clean_since_ms.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= self.cfg.raise_after_ms as u64
            && self.current_kbps < self.cfg.ceiling_kbps
        {
            let next = (self.current_kbps + self.cfg.step_kbps).min(self.cfg.ceiling_kbps);
            self.current_kbps = next;
            self.clean_since_ms = Some(now_ms);
            self.last_change_ms = now_ms;
            return Some(next);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decreases_on_loss_and_recovers() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        // establish baseline rtt
        assert_eq!(a.observe(0, 0.0, 200.0), None);
        // lossy window → decrease
        let dec = a.observe(1_100, 0.05, 200.0).expect("should decrease");
        assert!(dec < start);
        // clean windows → eventually raises
        let mut t = 2_000;
        let mut raised = None;
        for _ in 0..20 {
            t += 1_000;
            if let Some(v) = a.observe(t, 0.0, 200.0) {
                raised = Some(v);
                break;
            }
        }
        assert!(raised.unwrap() > dec);
    }

    #[test]
    fn respects_floor() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::LowBandwidth));
        let mut t = 0;
        for _ in 0..50 {
            t += 1_100;
            a.observe(t, 0.5, 400.0);
        }
        assert_eq!(
            a.current(),
            AdaptConfig::for_mode(QualityMode::LowBandwidth).floor_kbps
        );
    }
}
