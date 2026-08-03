//! Connection-test observation types and the prober that produces them.
//!
//! The *vocabulary* lives here: the facts a probe run may observe about this
//! machine's network position, plus a summary report the UI renders. Keeping the
//! types in the contract crate lets the settings UI, the service, and the prober
//! agree on the wire shape.
//!
//! The prober itself is split across two private-ish submodules:
//! - [`stun`] — a hand-rolled RFC 5389/8489 binding client (codec + async I/O).
//! - [`probe`] — [`probe::run_probe`], which turns socket results into
//!   [`Observation`]s.
//!
//! Design rules:
//! - Observations are FACTS with timestamps, never conclusions. "Possible
//!   CGNAT" is an observation; "you must use a relay" is a decision made
//!   elsewhere from a set of observations.
//! - Nothing here is allowed to overstate connectivity. A route is only
//!   reported as direct when it was actually established directly (see
//!   [`crate::stats::TransportRoute`]).
//! - Everything is `serde`-serializable so a probe run can be logged, sent over
//!   the service IPC, or attached to a diagnostics bundle verbatim.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

pub mod probe;
pub mod stun;

pub use probe::{
    classify_mapping, is_cgnat_v4, is_private_v4, is_public_v4, run_probe, FirewallGap,
    MappingSample, MappingVerdict, ProbeConfig, DEFAULT_STUN_SERVERS,
};
pub use stun::{StunError, TransactionId};

/// How confident a probe is in an observation it could not prove outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Inferred from a single weak signal.
    Low,
    /// Multiple consistent signals, no direct proof.
    Medium,
    /// Directly proven (e.g. a packet actually arrived).
    High,
}

/// The NAT mapping behaviour inferred from STUN responses across servers.
///
/// Terms follow RFC 4787 (BEHAVE) rather than the older "cone/symmetric"
/// vocabulary, because the old terms conflate mapping and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatMapping {
    /// No NAT observed: the reflexive address equals a local address.
    Open,
    /// Same external mapping regardless of destination — hole punching works.
    EndpointIndependent,
    /// Mapping varies by destination address but not port.
    AddressDependent,
    /// Mapping varies per destination endpoint — hole punching usually fails.
    AddressAndPortDependent,
    /// Probes were inconsistent or too few servers answered.
    Unknown,
}

impl NatMapping {
    /// Whether UDP hole punching has a realistic chance of succeeding.
    pub fn hole_punch_friendly(&self) -> bool {
        matches!(self, NatMapping::Open | NatMapping::EndpointIndependent)
    }

    /// Short human-readable label for the diagnostics UI.
    pub fn label(&self) -> &'static str {
        match self {
            NatMapping::Open => "No NAT",
            NatMapping::EndpointIndependent => "Endpoint-independent NAT",
            NatMapping::AddressDependent => "Address-dependent NAT",
            NatMapping::AddressAndPortDependent => "Address-and-port-dependent NAT",
            NatMapping::Unknown => "Unknown NAT behaviour",
        }
    }
}

/// Which transport a probe used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeTransport {
    /// UDP (the QUIC path).
    Udp,
    /// TCP (the TLS fallback path).
    Tcp,
}

/// Gateway port-mapping protocol families we can detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortMappingProtocol {
    /// UPnP IGD.
    Upnp,
    /// NAT Port Mapping Protocol (RFC 6886).
    NatPmp,
    /// Port Control Protocol (RFC 6887).
    Pcp,
}

/// One thing the prober actually observed. Facts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    /// A routable public IPv4 address was observed as our reflexive address.
    PublicV4Discovered { addr: Ipv4Addr, port: u16 },
    /// A global-scope IPv6 address is configured on a local interface.
    PublicV6Discovered { addr: Ipv6Addr },
    /// The reflexive address is itself in the CGNAT range 100.64.0.0/10, or the
    /// local address is private while the reflexive address is also private.
    PossibleCgnat {
        reflexive: Ipv4Addr,
        confidence: Confidence,
    },
    /// Our local address is private and the reflexive address is public — an
    /// ordinary NAT, and we know both sides of the mapping.
    BehindNat {
        local: Ipv4Addr,
        reflexive: Ipv4Addr,
    },
    /// STUN produced consistent mapping behaviour across servers.
    NatMappingObserved {
        mapping: NatMapping,
        servers_agreeing: u8,
        servers_probed: u8,
    },
    /// No UDP probe of any kind got a reply — UDP is very likely blocked.
    UdpBlocked { probes_sent: u32, timeout_ms: u32 },
    /// UDP works: at least one probe round-tripped.
    UdpAvailable { rtt_ms: u32 },
    /// A direct TCP connection to the listener succeeded (fallback is viable).
    DirectTcpAvailable { addr: SocketAddr, rtt_ms: u32 },
    /// A direct TCP connection was attempted and refused or timed out.
    DirectTcpUnavailable { addr: SocketAddr, reason: String },
    /// The external mapping changed between two probes — the NAT rebinds
    /// aggressively, so keep-alives must be frequent and the route may flap.
    MappingChanged {
        before: SocketAddr,
        after: SocketAddr,
        after_ms: u32,
    },
    /// A UPnP/NAT-PMP capable gateway answered a discovery request. We do NOT
    /// automatically create mappings; this is informational for the user.
    PortMappingProtocolAvailable { protocol: PortMappingProtocol },
    /// The observed path MTU for UDP, discovered by probing with DF set.
    PathMtuObserved { bytes: u16 },
    /// A named STUN/probe server failed to answer at all.
    ProbeServerUnreachable { server: String, timeout_ms: u32 },
    /// The local machine has more than one candidate egress interface.
    MultipleEgressInterfaces { count: u8 },
    /// A Windows Firewall rule for the DirectDesk listener appears to be absent.
    FirewallRuleMissing {
        port: u16,
        transport: ProbeTransport,
    },
}

impl Observation {
    /// Whether this observation is bad news the user should see prominently.
    pub fn is_problem(&self) -> bool {
        matches!(
            self,
            Observation::PossibleCgnat { .. }
                | Observation::UdpBlocked { .. }
                | Observation::DirectTcpUnavailable { .. }
                | Observation::MappingChanged { .. }
                | Observation::ProbeServerUnreachable { .. }
                | Observation::FirewallRuleMissing { .. }
        )
    }
}

/// A complete probe run: every observation plus when the run started.
///
/// The report deliberately carries no verdict field. Consumers derive their own
/// conclusion from the observations so the reasoning stays visible to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    /// Unix milliseconds when the run started. Informational only — nothing in
    /// this crate makes a security decision from it.
    pub started_at_ms: u64,
    /// How long the whole run took.
    pub duration_ms: u32,
    /// Every observation, in the order it was made.
    pub observations: Vec<Observation>,
}

impl ProbeReport {
    /// Create an empty report for a run starting at `started_at_ms`.
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            started_at_ms,
            duration_ms: 0,
            observations: Vec::new(),
        }
    }

    /// Record one observation.
    pub fn push(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    /// All observations flagged as problems, in order.
    pub fn problems(&self) -> impl Iterator<Item = &Observation> {
        self.observations.iter().filter(|o| o.is_problem())
    }

    /// The NAT mapping behaviour if one was observed.
    pub fn nat_mapping(&self) -> Option<NatMapping> {
        self.observations.iter().find_map(|o| match o {
            Observation::NatMappingObserved { mapping, .. } => Some(*mapping),
            _ => None,
        })
    }

    /// True when at least one UDP probe round-tripped.
    pub fn udp_works(&self) -> bool {
        self.observations
            .iter()
            .any(|o| matches!(o, Observation::UdpAvailable { .. }))
    }

    /// True when a direct TCP connection was proven to work.
    pub fn direct_tcp_works(&self) -> bool {
        self.observations
            .iter()
            .any(|o| matches!(o, Observation::DirectTcpAvailable { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_mapping_hole_punch_honesty() {
        assert!(NatMapping::EndpointIndependent.hole_punch_friendly());
        assert!(!NatMapping::AddressAndPortDependent.hole_punch_friendly());
        assert!(!NatMapping::Unknown.hole_punch_friendly());
    }

    #[test]
    fn report_queries() {
        let mut r = ProbeReport::new(1_700_000_000_000);
        r.push(Observation::UdpAvailable { rtt_ms: 12 });
        r.push(Observation::NatMappingObserved {
            mapping: NatMapping::EndpointIndependent,
            servers_agreeing: 3,
            servers_probed: 3,
        });
        r.push(Observation::UdpBlocked {
            probes_sent: 4,
            timeout_ms: 800,
        });

        assert!(r.udp_works());
        assert!(!r.direct_tcp_works());
        assert_eq!(r.nat_mapping(), Some(NatMapping::EndpointIndependent));
        assert_eq!(r.problems().count(), 1);
    }

    #[test]
    fn observations_roundtrip_postcard() {
        let obs = Observation::PossibleCgnat {
            reflexive: Ipv4Addr::new(100, 90, 1, 2),
            confidence: Confidence::Medium,
        };
        let bytes = postcard::to_stdvec(&obs).unwrap();
        let back: Observation = crate::protocol::decode_strict(&bytes).unwrap();
        assert_eq!(obs, back);
    }
}
