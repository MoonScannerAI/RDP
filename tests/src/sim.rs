//! The virtual-time driver that turns a [`SimConfig`] into an event log.
//!
//! One loop, one clock, no threads:
//!
//! ```text
//! for now_ms in (0..duration).step_by(tick_ms) {
//!     net.tick(now_ms);
//!     host.pump(now_ms);     // capture, encode, fragment, send
//!     client.pump(now_ms);   // receive, reassemble, decode, present
//! }
//! ```
//!
//! The host is pumped before the client at each instant, so a datagram sent at
//! `t` is visible at `t` — the netsim delivers anything whose scheduled arrival
//! has been reached, and a zero-latency link therefore has zero-tick delivery
//! rather than a spurious one-tick floor.
//!
//! A run is split into phases by calling [`Sim::run_to`] repeatedly and
//! changing the link with [`Sim::set_params`] in between. Items already in
//! flight keep the schedule they were given at send time, so a phase change is
//! a change to the *future*, exactly as a real network condition would be.

use directdesk_shared::error::Result;
use directdesk_shared::netsim::{NetParams, NetSim, SimStats};

use crate::client::SimClient;
use crate::config::SimConfig;
use crate::event::EventLog;
use crate::host::SimHost;
use crate::pump::PumpCtx;

/// A wired host, client and link driven by a single virtual clock.
#[derive(Debug)]
pub struct Sim {
    cfg: SimConfig,
    net: NetSim,
    host: SimHost,
    client: SimClient,
    log: EventLog,
    now_ms: u64,
}

impl Sim {
    /// Build a session from `cfg`, with the clock at zero.
    ///
    /// # Errors
    ///
    /// Returns [`directdesk_shared::Error::Invalid`] if the link parameters,
    /// the reassembler configuration, or the tick length are unusable.
    pub fn new(cfg: SimConfig) -> Result<Sim> {
        cfg.reassembly.validate()?;
        if cfg.tick_ms == 0 {
            return Err(directdesk_shared::Error::Invalid(
                "sim: tick_ms must be non-zero".into(),
            ));
        }
        let net = NetSim::new(cfg.params.clone(), cfg.seed)?;
        Ok(Sim {
            host: SimHost::new(cfg.clone()),
            client: SimClient::new(cfg.clone()),
            log: EventLog::new(),
            now_ms: 0,
            net,
            cfg,
        })
    }

    /// The configuration this session was built from.
    #[must_use]
    pub fn config(&self) -> &SimConfig {
        &self.cfg
    }

    /// Current virtual time. Equal to the instant of the *next* tick, so after
    /// `run_to(1000)` with a 5 ms tick the last pump was at 995.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// The transcript so far.
    #[must_use]
    pub fn log(&self) -> &EventLog {
        &self.log
    }

    /// The host core.
    #[must_use]
    pub fn host(&self) -> &SimHost {
        &self.host
    }

    /// The client core.
    #[must_use]
    pub fn client(&self) -> &SimClient {
        &self.client
    }

    /// Link counters.
    #[must_use]
    pub fn net_stats(&self) -> SimStats {
        self.net.stats()
    }

    /// Items still on the wire.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.net.in_flight()
    }

    /// Change the link conditions for everything sent from now on.
    ///
    /// # Errors
    ///
    /// Returns [`directdesk_shared::Error::Invalid`] if `params` is not valid.
    pub fn set_params(&mut self, params: NetParams) -> Result<()> {
        self.net.set_params(params)
    }

    /// Run one tick.
    ///
    /// # Errors
    ///
    /// Propagates a core failure. Malformed peer traffic is not a failure; see
    /// [`SimHost::pump`] and [`SimClient::pump`].
    pub fn step(&mut self) -> Result<()> {
        let now_ms = self.now_ms;
        self.net.tick(now_ms);
        let mut ctx = PumpCtx {
            net: &mut self.net,
            now_ms,
            log: &mut self.log,
        };
        self.host.pump(&mut ctx)?;
        self.client.pump(&mut ctx)?;
        self.now_ms = now_ms.saturating_add(self.cfg.tick_ms);
        Ok(())
    }

    /// Run until the clock reaches `until_ms`.
    ///
    /// # Errors
    ///
    /// Propagates a core failure from [`Sim::step`].
    pub fn run_to(&mut self, until_ms: u64) -> Result<()> {
        while self.now_ms < until_ms {
            self.step()?;
        }
        Ok(())
    }

    /// Run for a further `duration_ms`.
    ///
    /// # Errors
    ///
    /// Propagates a core failure from [`Sim::step`].
    pub fn run_for(&mut self, duration_ms: u64) -> Result<()> {
        let target = self.now_ms.saturating_add(duration_ms);
        self.run_to(target)
    }
}

/// Build a session and run it straight through to `duration_ms`.
///
/// # Errors
///
/// Propagates construction or pump failures.
pub fn run(cfg: SimConfig, duration_ms: u64) -> Result<Sim> {
    let mut sim = Sim::new(cfg)?;
    sim.run_to(duration_ms)?;
    Ok(sim)
}
