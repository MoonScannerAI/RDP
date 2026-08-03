//! The connection-test prober: turns socket results into [`Observation`]s.
//!
//! [`run_probe`] never returns `Err`. "The network is weird" is the thing this
//! module exists to *describe*, so a hostile network produces a partial
//! [`ProbeReport`], not an error. The only failures worth an error here would be
//! programmer misuse, and the API is shaped so there isn't any.
//!
//! # What the prober does
//! 1. Works out which local addresses are used to reach the internet, by
//!    `connect()`ing unbound UDP sockets at well-known destinations and reading
//!    back `local_addr()`. This asks the routing table without sending a packet
//!    and without an interface-enumeration dependency.
//! 2. Sends STUN binding requests from ONE socket to several servers, so the
//!    reflexive addresses can be compared (RFC 4787 mapping behaviour).
//! 3. Repeats one request from a SECOND socket, to catch NATs that hand out
//!    external addresses from a pool.
//! 4. Repeats one request from the FIRST socket after a delay, to catch NATs
//!    that rebind aggressively ([`Observation::MappingChanged`]).
//! 5. Optionally makes one TCP connection to a caller-supplied `host:port` —
//!    this is how the client tests whether the host's forwarded TCP port is
//!    actually reachable from here.
//!
//! # Deliberately not done here
//! - **Path MTU** ([`Observation::PathMtuObserved`]) is not emitted. Discovering
//!   it means sending DF-set datagrams of decreasing size, and on Windows the
//!   DF bit needs `IP_DONTFRAGMENT` via a raw socket option that neither `tokio`
//!   nor `std` exposes. Rather than reach for a socket-options dependency for a
//!   nice-to-have, we emit nothing — silence is honest, a guess would not be.
//! - **UPnP / NAT-PMP / PCP** ([`Observation::PortMappingProtocolAvailable`]) is
//!   not emitted. NAT-PMP and PCP are easy datagrams, but UPnP needs SSDP plus
//!   an XML device description, and reporting only two of the three families
//!   would read as "your router can't do this" when it can. This is the natural
//!   home for it later; the observation variant is already reserved.
//! - **Firewall inspection** ([`Observation::FirewallRuleMissing`]) is NOT done
//!   here. This crate is the shared contract and must not talk to the Windows
//!   Firewall COM API; the service already knows which rules it installed.
//!   Callers that know a rule is missing pass it in as
//!   [`ProbeConfig::known_firewall_gaps`] and the prober echoes it into the
//!   report, so the UI still renders one coherent list of observations.
//! - **IPv6 STUN.** [`Observation::PublicV6Discovered`] is emitted from the
//!   local routing table, which is direct evidence that a global IPv6 address is
//!   configured. Round-tripping STUN over IPv6 as well would double the run time
//!   to restate a fact we already hold. (The codec parses IPv6
//!   XOR-MAPPED-ADDRESS regardless — servers answer with it over v6 transport.)

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use super::stun::{self, TransactionId};
use super::{Confidence, NatMapping, Observation, ProbeReport, ProbeTransport};

/// STUN servers used when the caller does not supply a list.
///
/// Two entries share a hostname on purpose: probing one server IP on two ports
/// is what distinguishes an address-dependent mapping from an
/// address-and-port-dependent one (RFC 4787 §4.1). Hostname resolution is cached
/// per run, so both entries are guaranteed to land on the same address.
///
/// `stun.nextcloud.com` is the one that answers on two ports today (checked
/// against the live servers). If it ever stops, the run degrades gracefully:
/// without the port pair the classifier falls back to the weaker
/// [`NatMapping::AddressDependent`] claim rather than guessing.
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:443",
    "stun.nextcloud.com:3478",
];

/// Destinations used to ask the routing table which local address egresses.
/// No packet is sent to any of them — `connect()` on a UDP socket only picks a
/// route and binds a source address.
const V4_ROUTE_PROBES: &[&str] =
    &["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53", "208.67.222.222:53"];
const V6_ROUTE_PROBES: &[&str] = &["[2001:4860:4860::8888]:53", "[2606:4700:4700::1111]:53"];

/// Give up on any single DNS lookup after this long.
const DNS_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Stop a receive loop that keeps erroring rather than spinning on it.
const MAX_CONSECUTIVE_SOCKET_ERRORS: u32 = 64;

/// A firewall gap the *caller* already knows about.
///
/// The prober cannot see Windows Firewall rules from this crate (see the module
/// docs); the service can, and passes what it knows in so the report is one
/// list rather than two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallGap {
    /// The listener port the missing rule would have covered.
    pub port: u16,
    /// Which transport the missing rule would have covered.
    pub transport: ProbeTransport,
}

/// Inputs to a probe run. Every field has a sane default; `..Default::default()`
/// is the expected way to build one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// STUN servers as `host:port`. At least two are needed before mapping
    /// behaviour can be classified at all.
    pub stun_servers: Vec<String>,
    /// Budget for one STUN round. All servers are probed concurrently from a
    /// single socket, so this bounds the whole round, not each server. Each
    /// unanswered request is retransmitted once at the halfway mark.
    pub stun_timeout_ms: u32,
    /// Ceiling on the whole run. Every phase clamps itself to what is left, and
    /// a run that runs out of budget returns what it has.
    pub total_budget_ms: u32,
    /// How long to wait before re-probing from the same socket to see whether
    /// the external mapping moved. Zero disables the re-probe.
    pub remap_delay_ms: u32,
    /// Optional `host:port` to try a direct TCP connection to. The client points
    /// this at the host's advertised TCP fallback port.
    pub tcp_target: Option<String>,
    /// Budget for the TCP connection attempt.
    pub tcp_timeout_ms: u32,
    /// Firewall gaps the caller already knows about; echoed into the report as
    /// [`Observation::FirewallRuleMissing`]. The prober never inspects the
    /// firewall itself.
    pub known_firewall_gaps: Vec<FirewallGap>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| (*s).to_string()).collect(),
            stun_timeout_ms: 3_000,
            total_budget_ms: 10_000,
            remap_delay_ms: 1_200,
            tcp_target: None,
            tcp_timeout_ms: 3_000,
            known_firewall_gaps: Vec::new(),
        }
    }
}

impl ProbeConfig {
    /// Also test a direct TCP connection to `host:port`.
    pub fn with_tcp_target(mut self, target: impl Into<String>) -> Self {
        self.tcp_target = Some(target.into());
        self
    }

    /// Replace the STUN server list.
    pub fn with_stun_servers<I, S>(mut self, servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.stun_servers = servers.into_iter().map(Into::into).collect();
        self
    }

    /// Report firewall gaps the caller already established.
    pub fn with_firewall_gaps(mut self, gaps: impl IntoIterator<Item = FirewallGap>) -> Self {
        self.known_firewall_gaps = gaps.into_iter().collect();
        self
    }
}

/// One (server, reflexive address) pair, the unit of mapping classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingSample {
    /// The server that answered.
    pub server: SocketAddr,
    /// The reflexive address it reported.
    pub reflexive: SocketAddr,
}

/// The outcome of classifying a set of [`MappingSample`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingVerdict {
    /// Mapping behaviour in RFC 4787 terms.
    pub mapping: NatMapping,
    /// How many answers agreed on the most common reflexive address.
    pub servers_agreeing: u8,
    /// How many servers were probed.
    pub servers_probed: u8,
}

/// True for the RFC 6598 carrier-grade NAT range 100.64.0.0/10.
pub fn is_cgnat_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// True for addresses that cannot appear on the public internet as a source:
/// RFC 1918 space, loopback, link-local, and 0.0.0.0/8.
pub fn is_private_v4(addr: Ipv4Addr) -> bool {
    addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.octets()[0] == 0
}

/// True for an address that looks like a genuinely routable public IPv4 —
/// which explicitly excludes the CGNAT range, because being handed one of those
/// as a reflexive address means we are *not* directly reachable.
pub fn is_public_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    !is_private_v4(addr)
        && !is_cgnat_v4(addr)
        && !addr.is_multicast()
        && !addr.is_broadcast()
        && !addr.is_documentation()
        && o[0] != 240 // 240.0.0.0/4, reserved
}

/// True for a global-scope IPv6 unicast address (2000::/3), excluding the
/// documentation prefix. Link-local, ULA, and multicast are all outside 2000::/3.
fn is_global_unicast_v6(addr: Ipv6Addr) -> bool {
    let s = addr.segments();
    (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Classify NAT mapping behaviour from reflexive addresses seen across servers.
///
/// Honesty rules baked in here:
/// - Fewer than two answers can never be classified: the result is
///   [`NatMapping::Unknown`], not an optimistic guess.
/// - [`NatMapping::AddressAndPortDependent`] is claimed only with direct
///   evidence: two answers from the SAME server address on DIFFERENT ports that
///   disagree. Without that evidence, differing mappings across different server
///   addresses are reported as [`NatMapping::AddressDependent`], which is the
///   weakest claim consistent with the data. Both answer `false` to
///   [`NatMapping::hole_punch_friendly`], so the softer label never overstates
///   what will work.
/// - [`NatMapping::Open`] requires the reflexive address to equal a local
///   address, not merely to look public.
pub fn classify_mapping(
    local_v4: Option<Ipv4Addr>,
    samples: &[MappingSample],
    servers_probed: u8,
) -> MappingVerdict {
    let answered = u8::try_from(samples.len()).unwrap_or(u8::MAX);
    let probed = servers_probed.max(answered);

    if samples.len() < 2 {
        return MappingVerdict {
            mapping: NatMapping::Unknown,
            servers_agreeing: answered,
            servers_probed: probed,
        };
    }

    let mut counts: HashMap<SocketAddr, u8> = HashMap::new();
    for s in samples {
        *counts.entry(s.reflexive).or_insert(0) += 1;
    }
    let agreeing = counts.values().copied().max().unwrap_or(0);

    if counts.len() == 1 {
        let reflexive = samples[0].reflexive;
        let open = matches!((local_v4, reflexive.ip()), (Some(l), IpAddr::V4(r)) if l == r);
        return MappingVerdict {
            mapping: if open { NatMapping::Open } else { NatMapping::EndpointIndependent },
            servers_agreeing: agreeing,
            servers_probed: probed,
        };
    }

    // Mappings disagree. Do we have same-address/different-port evidence?
    let port_dependent = samples.iter().enumerate().any(|(i, a)| {
        samples[i + 1..].iter().any(|b| {
            a.server.ip() == b.server.ip()
                && a.server.port() != b.server.port()
                && a.reflexive != b.reflexive
        })
    });

    MappingVerdict {
        mapping: if port_dependent {
            NatMapping::AddressAndPortDependent
        } else {
            NatMapping::AddressDependent
        },
        servers_agreeing: agreeing,
        servers_probed: probed,
    }
}

/// Run a connection test and describe what was observed.
///
/// Never returns `Err`: a run that could do nothing at all returns a report with
/// few or no observations. Bounded by [`ProbeConfig::total_budget_ms`].
#[tracing::instrument(name = "nettest.run_probe", skip_all, fields(
    servers = config.stun_servers.len(),
    budget_ms = config.total_budget_ms,
))]
pub async fn run_probe(config: &ProbeConfig) -> ProbeReport {
    let started_at_ms = unix_millis();
    let start = Instant::now();
    let deadline = start + Duration::from_millis(u64::from(config.total_budget_ms));

    // UDP and TCP phases are independent, so run them together and stay inside
    // the budget instead of spending it twice.
    let (mut observations, tcp_observations) =
        tokio::join!(udp_phase(config, deadline), tcp_phase(config, deadline));
    observations.extend(tcp_observations);

    for gap in &config.known_firewall_gaps {
        observations
            .push(Observation::FirewallRuleMissing { port: gap.port, transport: gap.transport });
    }

    let mut report = ProbeReport::new(started_at_ms);
    report.duration_ms = millis_u32(start.elapsed());
    report.observations = observations;
    info!(
        duration_ms = report.duration_ms,
        observations = report.observations.len(),
        problems = report.problems().count(),
        "probe run complete"
    );
    report
}

// ---------------------------------------------------------------------------
// UDP phase
// ---------------------------------------------------------------------------

async fn udp_phase(config: &ProbeConfig, deadline: Instant) -> Vec<Observation> {
    let mut obs = Vec::new();

    // --- local routing facts -------------------------------------------------
    let egress = discover_egress().await;
    let interface_count = egress.v4.len().max(egress.v6.len());
    if interface_count > 1 {
        obs.push(Observation::MultipleEgressInterfaces {
            count: u8::try_from(interface_count).unwrap_or(u8::MAX),
        });
    }
    if let Some(v6) = egress.v6.first() {
        obs.push(Observation::PublicV6Discovered { addr: *v6 });
    }
    let local_v4 = egress.v4.first().copied();
    debug!(?local_v4, v6 = egress.v6.len(), "egress discovery done");

    // --- sockets -------------------------------------------------------------
    let primary = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            // Cannot bind a UDP socket at all. That is a local failure, not an
            // observation about the network, so we say nothing about UDP rather
            // than claiming it is blocked.
            warn!(error = %e, "could not bind probe socket; skipping UDP phase");
            return obs;
        }
    };

    let (targets, unresolved) = resolve_targets(&config.stun_servers, deadline).await;
    for name in unresolved {
        obs.push(Observation::ProbeServerUnreachable {
            server: name,
            timeout_ms: millis_u32(DNS_TIMEOUT),
        });
    }
    if targets.is_empty() {
        // Nothing was probed, so "no reply" would be meaningless. Emit neither
        // UdpAvailable nor UdpBlocked.
        return obs;
    }

    // --- round 1: every server, one socket -----------------------------------
    let budget = clamp_to_deadline(Duration::from_millis(u64::from(config.stun_timeout_ms)), deadline);
    let round = stun_round(&primary, &targets, budget).await;
    let mut probes_sent = round.probes_sent;

    for name in &round.unanswered {
        obs.push(Observation::ProbeServerUnreachable {
            server: name.clone(),
            timeout_ms: config.stun_timeout_ms,
        });
    }

    if round.answers.is_empty() {
        obs.push(Observation::UdpBlocked { probes_sent, timeout_ms: config.stun_timeout_ms });
        return obs;
    }

    let best_rtt = round.answers.iter().map(|a| a.rtt_ms).min().unwrap_or(0);
    obs.push(Observation::UdpAvailable { rtt_ms: best_rtt });

    // --- what the reflexive address says -------------------------------------
    let reflexive = modal_reflexive(&round.answers);
    if let SocketAddr::V4(v4) = reflexive {
        let addr = *v4.ip();
        if is_public_v4(addr) {
            obs.push(Observation::PublicV4Discovered { addr, port: v4.port() });
            if let Some(local) = local_v4 {
                if is_private_v4(local) && local != addr {
                    obs.push(Observation::BehindNat { local, reflexive: addr });
                }
            }
        } else if is_cgnat_v4(addr) {
            // RFC 6598 reserved this range for exactly this situation, so seeing
            // it as our own reflexive address is direct evidence.
            obs.push(Observation::PossibleCgnat { reflexive: addr, confidence: Confidence::High });
        } else if is_private_v4(addr) && local_v4.is_some_and(|l| l != addr) {
            // A private reflexive address that is not ours means at least one
            // more translation layer we cannot see past. Could be a carrier,
            // could be an enterprise edge — hence Medium.
            obs.push(Observation::PossibleCgnat { reflexive: addr, confidence: Confidence::Medium });
        }
    }

    // --- mapping behaviour ----------------------------------------------------
    let samples: Vec<MappingSample> = round
        .answers
        .iter()
        .map(|a| MappingSample { server: a.server_addr, reflexive: a.reflexive })
        .collect();
    let mut verdict = classify_mapping(
        local_v4,
        &samples,
        u8::try_from(targets.len()).unwrap_or(u8::MAX),
    );

    // --- second socket: does the NAT hand out addresses from a pool? ----------
    let first = &round.answers[0];
    if Instant::now() < deadline {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(secondary) => {
                let probe_budget = clamp_to_deadline(
                    Duration::from_millis(u64::from(config.stun_timeout_ms).min(1_500)),
                    deadline,
                );
                let target = [Target { name: first.server_name.clone(), addr: first.server_addr }];
                let second = stun_round(&secondary, &target, probe_budget).await;
                probes_sent += second.probes_sent;
                if let Some(answer) = second.answers.first() {
                    if answer.reflexive.ip() != first.reflexive.ip() {
                        // Two local sockets, same server, different external IP:
                        // the NAT has an address pool, so nothing we concluded
                        // about mapping behaviour generalises.
                        warn!(
                            a = %first.reflexive,
                            b = %answer.reflexive,
                            "external address differs per local socket (NAT pool)"
                        );
                        verdict.mapping = NatMapping::Unknown;
                    }
                }
            }
            Err(e) => debug!(error = %e, "could not bind secondary probe socket"),
        }
    }

    obs.push(Observation::NatMappingObserved {
        mapping: verdict.mapping,
        servers_agreeing: verdict.servers_agreeing,
        servers_probed: verdict.servers_probed,
    });

    // --- re-probe after a delay: does the mapping hold still? -----------------
    if config.remap_delay_ms > 0 {
        let delay = Duration::from_millis(u64::from(config.remap_delay_ms));
        let probe_budget = Duration::from_millis(u64::from(config.stun_timeout_ms).min(1_500));
        if Instant::now() + delay + probe_budget <= deadline {
            tokio::time::sleep(delay).await;
            let target = [Target { name: first.server_name.clone(), addr: first.server_addr }];
            let again = stun_round(&primary, &target, probe_budget).await;
            probes_sent += again.probes_sent;
            if let Some(answer) = again.answers.first() {
                if answer.reflexive != first.reflexive {
                    obs.push(Observation::MappingChanged {
                        before: first.reflexive,
                        after: answer.reflexive,
                        after_ms: config.remap_delay_ms,
                    });
                }
            }
        } else {
            debug!("no budget left for the re-probe; skipping MappingChanged check");
        }
    }

    debug!(probes_sent, "udp phase done");
    obs
}

/// The most frequently reported reflexive address, ties broken by first seen.
fn modal_reflexive(answers: &[Answer]) -> SocketAddr {
    let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
    for a in answers {
        *counts.entry(a.reflexive).or_insert(0) += 1;
    }
    let best = counts.values().copied().max().unwrap_or(0);
    answers
        .iter()
        .map(|a| a.reflexive)
        .find(|r| counts.get(r).copied().unwrap_or(0) == best)
        .unwrap_or_else(|| answers[0].reflexive)
}

// ---------------------------------------------------------------------------
// TCP phase
// ---------------------------------------------------------------------------

async fn tcp_phase(config: &ProbeConfig, deadline: Instant) -> Vec<Observation> {
    let Some(target) = config.tcp_target.as_deref() else {
        return Vec::new();
    };
    let mut obs = Vec::new();

    let names = [target.to_string()];
    let (targets, unresolved) = resolve_targets(&names, deadline).await;
    if !unresolved.is_empty() || targets.is_empty() {
        // Nothing to connect to: we cannot name a SocketAddr, so this is a
        // server-unreachable fact rather than a TCP verdict.
        obs.push(Observation::ProbeServerUnreachable {
            server: target.to_string(),
            timeout_ms: millis_u32(DNS_TIMEOUT),
        });
        return obs;
    }

    let addr = targets[0].addr;
    let budget = clamp_to_deadline(Duration::from_millis(u64::from(config.tcp_timeout_ms)), deadline);
    let started = Instant::now();
    match tokio::time::timeout(budget, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // A completed handshake is the only thing that proves reachability.
            drop(stream);
            obs.push(Observation::DirectTcpAvailable {
                addr,
                rtt_ms: millis_u32(started.elapsed()),
            });
        }
        Ok(Err(e)) => {
            obs.push(Observation::DirectTcpUnavailable { addr, reason: e.to_string() });
        }
        Err(_) => {
            obs.push(Observation::DirectTcpUnavailable {
                addr,
                reason: format!("timed out after {} ms", millis_u32(budget)),
            });
        }
    }
    obs
}

// ---------------------------------------------------------------------------
// STUN plumbing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Target {
    name: String,
    addr: SocketAddr,
}

#[derive(Debug, Clone)]
struct Answer {
    server_name: String,
    server_addr: SocketAddr,
    reflexive: SocketAddr,
    rtt_ms: u32,
}

#[derive(Debug, Default)]
struct RoundOutcome {
    answers: Vec<Answer>,
    unanswered: Vec<String>,
    probes_sent: u32,
}

/// Probe every target from one socket, concurrently, and collect what answers.
///
/// Requests go out together and replies are demultiplexed by transaction ID, so
/// the round costs one timeout rather than one per server. Each still-unanswered
/// request is retransmitted once at the halfway mark (RFC 5389 §7.2.1 wants
/// retransmission; one extra try is plenty for a diagnostic).
async fn stun_round(sock: &UdpSocket, targets: &[Target], budget: Duration) -> RoundOutcome {
    let mut out = RoundOutcome::default();
    if targets.is_empty() || budget.is_zero() {
        out.unanswered = targets.iter().map(|t| t.name.clone()).collect();
        return out;
    }

    let round_start = Instant::now();
    let round_end = round_start + budget;
    let txids: Vec<TransactionId> = targets.iter().map(|_| TransactionId::random()).collect();
    let by_txid: HashMap<TransactionId, usize> =
        txids.iter().enumerate().map(|(i, t)| (*t, i)).collect();
    let mut answered = vec![false; targets.len()];
    let mut sent_at = vec![round_start; targets.len()];
    let mut buf = [0u8; stun::MAX_MESSAGE_LEN];

    for attempt in 0..2u32 {
        for (i, target) in targets.iter().enumerate() {
            if answered[i] {
                continue;
            }
            let req = stun::binding_request(&txids[i]);
            sent_at[i] = Instant::now();
            match sock.send_to(&req, target.addr).await {
                Ok(_) => out.probes_sent += 1,
                Err(e) => debug!(server = %target.name, error = %e, "stun send failed"),
            }
        }

        // First attempt gets half the budget so a retransmission still fits.
        let window_end = if attempt == 0 { round_start + budget / 2 } else { round_end };
        let mut errors = 0u32;

        while !answered.iter().all(|a| *a) {
            let now = Instant::now();
            if now >= window_end {
                break;
            }
            let recv = tokio::time::timeout(window_end - now, sock.recv_from(&mut buf)).await;
            let (n, from) = match recv {
                Err(_elapsed) => break,
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    // On Windows an ICMP port-unreachable for a datagram we sent
                    // earlier surfaces as ConnectionReset on the NEXT recv of an
                    // unconnected UDP socket. It says nothing about the other
                    // servers, so keep listening.
                    errors += 1;
                    if e.kind() == io::ErrorKind::ConnectionReset
                        && errors < MAX_CONSECUTIVE_SOCKET_ERRORS
                    {
                        continue;
                    }
                    debug!(error = %e, "stun recv failed");
                    break;
                }
            };
            errors = 0;

            let Some(txid) = stun::peek_transaction_id(&buf[..n]) else {
                continue;
            };
            let Some(&i) = by_txid.get(&txid) else {
                continue;
            };
            if answered[i] {
                continue;
            }
            // The transaction ID already makes this hard to forge off-path;
            // requiring the source address to match costs nothing.
            if from.ip() != targets[i].addr.ip() {
                debug!(expected = %targets[i].addr, got = %from, "stun reply from wrong host");
                continue;
            }
            match stun::parse_binding_response(&buf[..n], &txid) {
                Ok(reflexive) => {
                    answered[i] = true;
                    out.answers.push(Answer {
                        server_name: targets[i].name.clone(),
                        server_addr: targets[i].addr,
                        reflexive,
                        rtt_ms: millis_u32(sent_at[i].elapsed()),
                    });
                    debug!(server = %targets[i].name, %reflexive, "stun answer");
                }
                Err(e) => debug!(server = %targets[i].name, error = %e, "bad stun response"),
            }
        }

        if answered.iter().all(|a| *a) || Instant::now() >= round_end {
            break;
        }
    }

    out.unanswered = targets
        .iter()
        .zip(answered.iter())
        .filter(|(_, ok)| !**ok)
        .map(|(t, _)| t.name.clone())
        .collect();
    out
}

/// Resolve `host:port` strings to IPv4 socket addresses, caching by hostname.
///
/// Caching matters for correctness, not just speed: the default list probes one
/// hostname on two ports, and the port-dependence test is only valid if both
/// land on the same server address.
async fn resolve_targets(names: &[String], deadline: Instant) -> (Vec<Target>, Vec<String>) {
    let mut targets = Vec::new();
    let mut failed = Vec::new();
    let mut cache: HashMap<String, Option<IpAddr>> = HashMap::new();

    for name in names {
        let Some((host, port)) = split_host_port(name) else {
            warn!(server = %name, "malformed host:port in probe config");
            failed.push(name.clone());
            continue;
        };

        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_ipv4() {
                targets.push(Target { name: name.clone(), addr: SocketAddr::new(ip, port) });
            }
            continue;
        }

        let resolved = match cache.get(host) {
            Some(ip) => *ip,
            None => {
                let budget = clamp_to_deadline(DNS_TIMEOUT, deadline);
                let ip = match tokio::time::timeout(budget, tokio::net::lookup_host((host, port)))
                    .await
                {
                    Ok(Ok(mut it)) => it.find(|a| a.is_ipv4()).map(|a| a.ip()),
                    Ok(Err(e)) => {
                        debug!(%host, error = %e, "dns lookup failed");
                        None
                    }
                    Err(_) => {
                        debug!(%host, "dns lookup timed out");
                        None
                    }
                };
                cache.insert(host.to_string(), ip);
                ip
            }
        };

        match resolved {
            Some(ip) => targets.push(Target { name: name.clone(), addr: SocketAddr::new(ip, port) }),
            None => failed.push(name.clone()),
        }
    }

    (targets, failed)
}

/// Split `host:port`, including the `[v6]:port` form.
fn split_host_port(s: &str) -> Option<(&str, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        Some((host, port))
    } else {
        let (host, port) = s.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        Some((host, port.parse().ok()?))
    }
}

// ---------------------------------------------------------------------------
// Local routing facts
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Egress {
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
}

/// Ask the routing table which local addresses egress towards the internet.
///
/// `connect()` on a UDP socket sends nothing: it picks a route and binds a
/// source address, which `local_addr()` then reports. Probing several distinct
/// destinations catches policy routing and multi-homing without an
/// interface-enumeration dependency.
///
/// IPv4 and IPv6 counts are compared rather than summed, so an ordinary
/// dual-stack machine with one NIC is never miscounted as multi-homed.
async fn discover_egress() -> Egress {
    let mut out = Egress::default();

    for dest in V4_ROUTE_PROBES {
        if let Some(IpAddr::V4(ip)) = egress_for(dest, "0.0.0.0:0").await {
            if !ip.is_unspecified() && !out.v4.contains(&ip) {
                out.v4.push(ip);
            }
        }
    }
    for dest in V6_ROUTE_PROBES {
        if let Some(IpAddr::V6(ip)) = egress_for(dest, "[::]:0").await {
            if is_global_unicast_v6(ip) && !out.v6.contains(&ip) {
                out.v6.push(ip);
            }
        }
    }
    out
}

async fn egress_for(dest: &str, bind: &str) -> Option<IpAddr> {
    let sock = UdpSocket::bind(bind).await.ok()?;
    let dest: SocketAddr = dest.parse().ok()?;
    sock.connect(dest).await.ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn millis_u32(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

/// Shrink `want` so it cannot run past the run's overall deadline.
fn clamp_to_deadline(want: Duration, deadline: Instant) -> Duration {
    let left = deadline.saturating_duration_since(Instant::now());
    want.min(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn sample(server: &str, reflexive: &str) -> MappingSample {
        MappingSample {
            server: server.parse().unwrap(),
            reflexive: reflexive.parse().unwrap(),
        }
    }

    // --- address classification ---------------------------------------------

    #[test]
    fn cgnat_range_boundaries() {
        assert!(!is_cgnat_v4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(is_cgnat_v4(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat_v4(Ipv4Addr::new(100, 90, 1, 2)));
        assert!(is_cgnat_v4(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat_v4(Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!is_cgnat_v4(Ipv4Addr::new(99, 64, 0, 1)));
        assert!(!is_cgnat_v4(Ipv4Addr::new(101, 64, 0, 1)));
    }

    #[test]
    fn cgnat_addresses_are_never_reported_as_public() {
        // The whole point: a CGNAT reflexive address must not look like success.
        for a in [
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 100, 50, 3),
            Ipv4Addr::new(100, 127, 255, 254),
        ] {
            assert!(!is_public_v4(a), "{a} was treated as public");
            assert!(!is_private_v4(a), "{a} is CGNAT, not RFC 1918");
        }
    }

    #[test]
    fn private_and_public_classification() {
        for a in [
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 4, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
        ] {
            assert!(is_private_v4(a), "{a} should be private");
            assert!(!is_public_v4(a), "{a} should not be public");
        }
        for a in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(172, 32, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(24, 30, 100, 7),
        ] {
            assert!(is_public_v4(a), "{a} should be public");
            assert!(!is_private_v4(a));
        }
        // Reserved and documentation space is not "public" either.
        assert!(!is_public_v4(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_public_v4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn global_v6_detection() {
        assert!(is_global_unicast_v6("2606:4700::1111".parse().unwrap()));
        assert!(is_global_unicast_v6("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_global_unicast_v6("2001:db8::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("fd00::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("::1".parse().unwrap()));
        assert!(!is_global_unicast_v6("ff02::1".parse().unwrap()));
    }

    // --- mapping classification ----------------------------------------------

    #[test]
    fn one_answer_is_never_classified() {
        let s = [sample("8.8.8.8:19302", "24.30.100.5:41000")];
        let v = classify_mapping(None, &s, 4);
        assert_eq!(v.mapping, NatMapping::Unknown);
        assert_eq!(v.servers_agreeing, 1);
        assert_eq!(v.servers_probed, 4);
    }

    #[test]
    fn no_answers_is_unknown() {
        let v = classify_mapping(None, &[], 3);
        assert_eq!(v.mapping, NatMapping::Unknown);
        assert_eq!(v.servers_agreeing, 0);
        assert_eq!(v.servers_probed, 3);
    }

    #[test]
    fn identical_mappings_are_endpoint_independent() {
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("1.1.1.1:3478", "24.30.100.5:41000"),
            sample("9.9.9.9:3478", "24.30.100.5:41000"),
        ];
        let v = classify_mapping(Some(Ipv4Addr::new(192, 168, 1, 20)), &s, 3);
        assert_eq!(v.mapping, NatMapping::EndpointIndependent);
        assert_eq!(v.servers_agreeing, 3);
        assert_eq!(v.servers_probed, 3);
        assert!(v.mapping.hole_punch_friendly());
    }

    #[test]
    fn reflexive_equal_to_local_is_open() {
        let s = [
            sample("8.8.8.8:19302", "24.30.100.7:41000"),
            sample("1.1.1.1:3478", "24.30.100.7:41000"),
        ];
        let v = classify_mapping(Some(Ipv4Addr::new(24, 30, 100, 7)), &s, 2);
        assert_eq!(v.mapping, NatMapping::Open);
    }

    #[test]
    fn differing_mappings_across_hosts_are_address_dependent() {
        // No two samples share a server IP, so there is no evidence about port
        // dependence: claim only what the data supports.
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("1.1.1.1:3478", "24.30.100.5:41001"),
            sample("9.9.9.9:3478", "24.30.100.5:41002"),
        ];
        let v = classify_mapping(None, &s, 3);
        assert_eq!(v.mapping, NatMapping::AddressDependent);
        assert_eq!(v.servers_agreeing, 1);
        assert!(!v.mapping.hole_punch_friendly());
    }

    #[test]
    fn same_host_different_port_disagreeing_is_address_and_port_dependent() {
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("8.8.8.8:19305", "24.30.100.5:41001"),
            sample("1.1.1.1:3478", "24.30.100.5:41002"),
        ];
        let v = classify_mapping(None, &s, 3);
        assert_eq!(v.mapping, NatMapping::AddressAndPortDependent);
        assert_eq!(v.servers_probed, 3);
    }

    #[test]
    fn same_host_different_port_agreeing_stays_address_dependent() {
        // Ports on one host agree; a different host disagrees. That is exactly
        // address-dependent behaviour.
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("8.8.8.8:19305", "24.30.100.5:41000"),
            sample("1.1.1.1:3478", "24.30.100.5:41009"),
        ];
        let v = classify_mapping(None, &s, 3);
        assert_eq!(v.mapping, NatMapping::AddressDependent);
        assert_eq!(v.servers_agreeing, 2);
    }

    #[test]
    fn agreeing_count_is_the_modal_group() {
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("1.1.1.1:3478", "24.30.100.5:41000"),
            sample("9.9.9.9:3478", "24.30.100.5:49999"),
        ];
        let v = classify_mapping(None, &s, 4);
        assert_eq!(v.servers_agreeing, 2);
        assert_eq!(v.servers_probed, 4);
    }

    #[test]
    fn servers_probed_never_understates_answers() {
        let s = [
            sample("8.8.8.8:19302", "24.30.100.5:41000"),
            sample("1.1.1.1:3478", "24.30.100.5:41000"),
        ];
        // A caller passing a nonsense count cannot make the report incoherent.
        let v = classify_mapping(None, &s, 0);
        assert_eq!(v.servers_probed, 2);
    }

    // --- config / parsing -----------------------------------------------------

    #[test]
    fn host_port_splitting() {
        assert_eq!(split_host_port("stun.l.google.com:19302"), Some(("stun.l.google.com", 19302)));
        assert_eq!(split_host_port("1.2.3.4:3478"), Some(("1.2.3.4", 3478)));
        assert_eq!(split_host_port("[2001:db8::1]:3478"), Some(("2001:db8::1", 3478)));
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port("host:notaport"), None);
        assert_eq!(split_host_port(":3478"), None);
        assert_eq!(split_host_port(""), None);
        assert_eq!(split_host_port("host:99999"), None);
    }

    #[test]
    fn default_config_is_sane() {
        let c = ProbeConfig::default();
        assert!(c.stun_servers.len() >= 3, "need enough servers to classify mapping");
        // The port-dependence test needs one hostname listed on two ports.
        let mut hosts: Vec<&str> =
            c.stun_servers.iter().filter_map(|s| split_host_port(s).map(|(h, _)| h)).collect();
        hosts.sort_unstable();
        let before = hosts.len();
        hosts.dedup();
        assert!(before > hosts.len(), "default list must repeat a host on two ports");
        // Every phase must fit the overall budget.
        assert!(c.stun_timeout_ms + c.remap_delay_ms <= c.total_budget_ms);
        assert!(c.tcp_target.is_none());
        assert!(c.known_firewall_gaps.is_empty());
    }

    #[test]
    fn config_roundtrips_through_postcard() {
        let c = ProbeConfig::default()
            .with_tcp_target("example.invalid:7443")
            .with_firewall_gaps([FirewallGap { port: 7443, transport: ProbeTransport::Tcp }]);
        let bytes = postcard::to_stdvec(&c).unwrap();
        let back: ProbeConfig = crate::protocol::decode_strict(&bytes).unwrap();
        assert_eq!(c, back);
    }

    // --- offline end-to-end with a fake STUN server ---------------------------

    /// Minimal STUN responder on loopback. `map` decides which reflexive address
    /// to report, given the requester's address and how many requests that exact
    /// source address has made so far (1-based) — enough to imitate both a
    /// stable NAT and one that rebinds.
    async fn fake_stun_server<F>(map: F) -> SocketAddr
    where
        F: Fn(SocketAddr, u32) -> SocketAddr + Send + Sync + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut counts: HashMap<SocketAddr, u32> = HashMap::new();
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let Some(txid) = stun::peek_transaction_id(&buf[..n]) else {
                    continue;
                };
                let count = counts.entry(from).or_insert(0);
                *count += 1;
                let reflexive = map(from, *count);
                let resp = encode_success(&txid, reflexive);
                let _ = sock.send_to(&resp, from).await;
            }
        });
        addr
    }

    /// Encode a binding success response with an XOR-MAPPED-ADDRESS.
    fn encode_success(txid: &TransactionId, reflexive: SocketAddr) -> Vec<u8> {
        let mut value = vec![0u8, 0, 0, 0];
        let xport = reflexive.port() ^ ((stun::MAGIC_COOKIE >> 16) as u16);
        value[2..4].copy_from_slice(&xport.to_be_bytes());
        let cookie = stun::MAGIC_COOKIE.to_be_bytes();
        match reflexive.ip() {
            IpAddr::V4(v4) => {
                value[1] = 0x01;
                let mut o = v4.octets();
                for (i, b) in o.iter_mut().enumerate() {
                    *b ^= cookie[i];
                }
                value.extend_from_slice(&o);
            }
            IpAddr::V6(v6) => {
                value[1] = 0x02;
                let mut o = v6.octets();
                let mut key = [0u8; 16];
                key[0..4].copy_from_slice(&cookie);
                key[4..16].copy_from_slice(txid.as_bytes());
                for (b, k) in o.iter_mut().zip(key.iter()) {
                    *b ^= *k;
                }
                value.extend_from_slice(&o);
            }
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&0x0101u16.to_be_bytes());
        msg.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(txid.as_bytes());
        msg.extend_from_slice(&0x0020u16.to_be_bytes());
        msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
        msg.extend_from_slice(&value);
        msg
    }

    /// Config that only talks to loopback, so the test never touches a network.
    fn offline_config(servers: Vec<SocketAddr>) -> ProbeConfig {
        ProbeConfig {
            stun_servers: servers.iter().map(|s| s.to_string()).collect(),
            stun_timeout_ms: 2_000,
            total_budget_ms: 9_000,
            remap_delay_ms: 0,
            tcp_target: None,
            tcp_timeout_ms: 1_000,
            known_firewall_gaps: Vec::new(),
        }
    }

    #[tokio::test]
    async fn probe_against_two_stable_fake_servers() {
        let reflexive: SocketAddr = "24.30.100.7:5555".parse().unwrap();
        let a = fake_stun_server(move |_, _| reflexive).await;
        let b = fake_stun_server(move |_, _| reflexive).await;

        let report = run_probe(&offline_config(vec![a, b])).await;

        assert!(report.udp_works(), "loopback STUN must round-trip: {report:?}");
        assert_eq!(report.nat_mapping(), Some(NatMapping::EndpointIndependent));
        assert!(report.observations.contains(&Observation::PublicV4Discovered {
            addr: Ipv4Addr::new(24, 30, 100, 7),
            port: 5555,
        }));
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::UdpBlocked { .. })));
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::ProbeServerUnreachable { .. })));
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::MappingChanged { .. })));
    }

    #[tokio::test]
    async fn per_socket_mapping_on_one_host_reads_as_port_dependent() {
        // Both fakes live on 127.0.0.1, so they are the same address on
        // different ports: disagreement there is direct port-dependence
        // evidence.
        let a = fake_stun_server(|_, _| "24.30.100.7:5555".parse().unwrap()).await;
        let b = fake_stun_server(|_, _| "24.30.100.7:6666".parse().unwrap()).await;

        let report = run_probe(&offline_config(vec![a, b])).await;

        assert_eq!(report.nat_mapping(), Some(NatMapping::AddressAndPortDependent));
        assert!(!report.nat_mapping().unwrap().hole_punch_friendly());
    }

    #[tokio::test]
    async fn cgnat_reflexive_is_reported_and_never_called_public() {
        let reflexive: SocketAddr = "100.75.3.9:5555".parse().unwrap();
        let a = fake_stun_server(move |_, _| reflexive).await;
        let b = fake_stun_server(move |_, _| reflexive).await;

        let report = run_probe(&offline_config(vec![a, b])).await;

        assert!(report.observations.contains(&Observation::PossibleCgnat {
            reflexive: Ipv4Addr::new(100, 75, 3, 9),
            confidence: Confidence::High,
        }));
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::PublicV4Discovered { .. })));
        assert!(report.problems().count() >= 1);
    }

    #[tokio::test]
    async fn a_rebinding_nat_produces_mapping_changed() {
        // Report a different port the second time this source address asks. The
        // re-probe reuses the first socket, so it is that socket's second
        // request; the secondary socket has its own count.
        let server = fake_stun_server(|_, count| {
            if count <= 1 {
                "24.30.100.7:5555".parse().unwrap()
            } else {
                "24.30.100.7:6666".parse().unwrap()
            }
        })
        .await;

        let mut cfg = offline_config(vec![server]);
        cfg.remap_delay_ms = 50;
        let report = run_probe(&cfg).await;

        let changed = report.observations.iter().find_map(|o| match o {
            Observation::MappingChanged { before, after, .. } => Some((*before, *after)),
            _ => None,
        });
        let (before, after) = changed.expect("expected MappingChanged");
        assert_eq!(before, "24.30.100.7:5555".parse::<SocketAddr>().unwrap());
        assert_eq!(after, "24.30.100.7:6666".parse::<SocketAddr>().unwrap());
        // One server can never classify mapping behaviour.
        assert_eq!(report.nat_mapping(), Some(NatMapping::Unknown));
    }

    /// A fake server imitating a NAT with an external address pool: the first
    /// local socket it sees is mapped to 24.30.100.7, the second to .8, and so
    /// on, stably per source.
    async fn pool_stun_server() -> SocketAddr {
        let assigned: Arc<Mutex<HashMap<SocketAddr, u8>>> = Arc::new(Mutex::new(HashMap::new()));
        fake_stun_server(move |from, _| {
            let mut m = assigned.lock().unwrap();
            let next = 7 + u8::try_from(m.len()).unwrap_or(0);
            let octet = *m.entry(from).or_insert(next);
            format!("24.30.100.{octet}:5555").parse().unwrap()
        })
        .await
    }

    #[tokio::test]
    async fn a_nat_address_pool_downgrades_the_mapping_to_unknown() {
        // Both fakes hand out a different external IP per local socket, so it
        // does not matter which one answers first. Nothing we could conclude
        // about mapping behaviour would generalise, so the verdict must collapse
        // to Unknown rather than claim hole punching works.
        let a = pool_stun_server().await;
        let b = pool_stun_server().await;

        let report = run_probe(&offline_config(vec![a, b])).await;
        assert_eq!(report.nat_mapping(), Some(NatMapping::Unknown));
        // The round-1 answers still agreed, so without the second socket this
        // would have been reported as hole-punch friendly.
        assert!(report.udp_works());
    }

    #[tokio::test]
    async fn dead_servers_produce_unreachable_and_blocked() {
        // 127.0.0.1 with nothing listening: sends succeed, nothing answers.
        let dead: Vec<SocketAddr> =
            vec!["127.0.0.1:9".parse().unwrap(), "127.0.0.1:10".parse().unwrap()];
        let mut cfg = offline_config(dead);
        cfg.stun_timeout_ms = 300;
        cfg.total_budget_ms = 3_000;

        let report = run_probe(&cfg).await;

        assert_eq!(
            report
                .observations
                .iter()
                .filter(|o| matches!(o, Observation::ProbeServerUnreachable { .. }))
                .count(),
            2
        );
        let blocked = report.observations.iter().find_map(|o| match o {
            Observation::UdpBlocked { probes_sent, timeout_ms } => Some((*probes_sent, *timeout_ms)),
            _ => None,
        });
        let (sent, timeout) = blocked.expect("expected UdpBlocked");
        assert!(sent >= 2, "should have counted the datagrams it sent, got {sent}");
        assert_eq!(timeout, 300);
        assert!(!report.udp_works());
        assert_eq!(report.nat_mapping(), None);
    }

    #[tokio::test]
    async fn unresolvable_server_is_reported_not_fatal() {
        let mut cfg = offline_config(vec![]);
        cfg.stun_servers = vec!["this-host-does-not-exist.invalid:3478".into()];
        cfg.total_budget_ms = 4_000;

        let report = run_probe(&cfg).await;

        assert!(report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::ProbeServerUnreachable { .. })));
        // Nothing was probed, so claiming UDP is blocked would be a lie.
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::UdpBlocked { .. })));
    }

    #[tokio::test]
    async fn no_servers_configured_yields_no_udp_verdict() {
        let report = run_probe(&offline_config(vec![])).await;
        assert!(!report.udp_works());
        assert!(!report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::UdpBlocked { .. })));
    }

    #[tokio::test]
    async fn tcp_check_reports_a_real_listener_and_a_refused_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let mut cfg = offline_config(vec![]);
        cfg.tcp_target = Some(addr.to_string());
        let report = run_probe(&cfg).await;
        assert!(report.direct_tcp_works(), "{report:?}");

        // Now a port with nothing on it.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        let mut cfg = offline_config(vec![]);
        cfg.tcp_target = Some(closed_addr.to_string());
        let report = run_probe(&cfg).await;
        assert!(!report.direct_tcp_works());
        assert!(report
            .observations
            .iter()
            .any(|o| matches!(o, Observation::DirectTcpUnavailable { .. })));
    }

    #[tokio::test]
    async fn known_firewall_gaps_are_echoed_into_the_report() {
        let cfg = offline_config(vec![]).with_firewall_gaps([
            FirewallGap { port: 7443, transport: ProbeTransport::Tcp },
            FirewallGap { port: 7443, transport: ProbeTransport::Udp },
        ]);
        let report = run_probe(&cfg).await;
        assert!(report.observations.contains(&Observation::FirewallRuleMissing {
            port: 7443,
            transport: ProbeTransport::Udp
        }));
        assert_eq!(report.problems().count(), 2);
    }

    #[tokio::test]
    async fn run_stays_inside_its_budget() {
        // Two black holes plus a re-probe, with a budget far smaller than the
        // sum of the phases: the deadline must win.
        let mut cfg = offline_config(vec![
            "192.0.2.1:3478".parse().unwrap(),
            "192.0.2.2:3478".parse().unwrap(),
        ]);
        cfg.stun_timeout_ms = 5_000;
        cfg.remap_delay_ms = 5_000;
        cfg.total_budget_ms = 800;
        cfg.tcp_target = Some("192.0.2.3:7443".into());
        cfg.tcp_timeout_ms = 5_000;

        let started = Instant::now();
        let report = run_probe(&cfg).await;
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(2_500), "run took {elapsed:?}");
        assert!(report.duration_ms <= 2_500);
    }

    #[tokio::test]
    async fn report_timestamp_and_duration_are_populated() {
        let report = run_probe(&offline_config(vec![])).await;
        assert!(report.started_at_ms > 1_600_000_000_000, "unix ms looks wrong");
        assert!(report.duration_ms < 10_000);
    }

    // --- live network -----------------------------------------------------------

    /// Hits real STUN servers. Run with:
    /// `cargo test -p directdesk-shared --lib -- --ignored nettest`
    #[tokio::test]
    #[ignore = "requires internet access; hits public STUN servers"]
    async fn live_probe_against_public_stun_servers() {
        let cfg = ProbeConfig::default();
        let report = run_probe(&cfg).await;

        println!("--- live probe report ---");
        println!("started_at_ms: {}", report.started_at_ms);
        println!("duration_ms:   {}", report.duration_ms);
        for o in &report.observations {
            println!("  {o:?}");
        }
        println!("nat_mapping:   {:?}", report.nat_mapping());
        println!("udp_works:     {}", report.udp_works());
        println!("problems:      {}", report.problems().count());

        assert!(report.duration_ms <= cfg.total_budget_ms + 1_500);
        assert!(!report.observations.is_empty(), "a live run should observe something");
    }
}
