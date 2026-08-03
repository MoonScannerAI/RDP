//! The per-tick context handed to both cores.
//!
//! Every component in the harness is driven the same way: it is called once per
//! virtual tick with the simulator, the current virtual millisecond, and the
//! event log. Nothing reads a clock, spawns a task, or waits — `now_ms` is the
//! only notion of time that exists.

use directdesk_shared::netsim::NetSim;

use crate::event::EventLog;

/// Simulator, clock and log, borrowed for the duration of one tick.
#[derive(Debug)]
pub struct PumpCtx<'a> {
    /// The link both cores talk through.
    pub net: &'a mut NetSim,
    /// The virtual millisecond this tick represents.
    pub now_ms: u64,
    /// Where observations go.
    pub log: &'a mut EventLog,
}
