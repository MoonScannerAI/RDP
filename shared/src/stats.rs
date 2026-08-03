//! Connection statistics + route reporting shared by both ends.

use serde::{Deserialize, Serialize};

/// The actual transport route in use. Displayed prominently and never
/// allowed to claim "direct" for a relayed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportRoute {
    DirectUdp,
    DirectIpv6,
    UdpHolePunched,
    DirectTcp,
    Relayed,
}

impl TransportRoute {
    pub fn label(&self) -> &'static str {
        match self {
            TransportRoute::DirectUdp => "Direct UDP",
            TransportRoute::DirectIpv6 => "Direct IPv6",
            TransportRoute::UdpHolePunched => "UDP hole punched",
            TransportRoute::DirectTcp => "Direct TCP",
            TransportRoute::Relayed => "Relayed",
        }
    }

    pub fn is_direct(&self) -> bool {
        !matches!(self, TransportRoute::Relayed)
    }
}

/// Periodic statistics snapshot exchanged over the control channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ConnStats {
    pub rtt_ms: f32,
    pub jitter_ms: f32,
    /// Fraction 0.0..=1.0 over the reporting window.
    pub loss: f32,
    pub bandwidth_kbps: u32,
    pub fps_capture: f32,
    pub fps_encode: f32,
    pub fps_decode: f32,
    pub fps_present: f32,
    pub bitrate_kbps: u32,
    pub frames_dropped: u32,
    pub keyframes_requested: u32,
    /// Milliseconds capture→send on host, or receive→present on client.
    pub pipeline_ms: f32,
}

/// Validate stats received from the peer (they're informational; reject NaN
/// and absurd values so the UI never renders garbage).
pub fn validate_stats(s: &ConnStats) -> bool {
    let finite = s.rtt_ms.is_finite()
        && s.jitter_ms.is_finite()
        && s.loss.is_finite()
        && s.fps_capture.is_finite()
        && s.fps_encode.is_finite()
        && s.fps_decode.is_finite()
        && s.fps_present.is_finite()
        && s.pipeline_ms.is_finite();
    finite
        && (0.0..=1.0).contains(&s.loss)
        && s.rtt_ms >= 0.0
        && s.rtt_ms < 60_000.0
        && s.bandwidth_kbps < 10_000_000
        && s.bitrate_kbps < 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_labels_honest() {
        assert!(!TransportRoute::Relayed.is_direct());
        assert_eq!(TransportRoute::Relayed.label(), "Relayed");
        assert!(TransportRoute::DirectTcp.is_direct());
    }

    #[test]
    fn stats_validation() {
        assert!(validate_stats(&ConnStats::default()));
        let bad = ConnStats {
            loss: 1.5,
            ..Default::default()
        };
        assert!(!validate_stats(&bad));
        let bad = ConnStats {
            rtt_ms: f32::NAN,
            ..Default::default()
        };
        assert!(!validate_stats(&bad));
    }
}
