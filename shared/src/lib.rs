//! directdesk-shared: wire protocol, validation, crypto, transport contracts.
//!
//! Every DirectDesk executable (host, client, service) depends on this crate.
//! The types here ARE the compatibility contract — change with care and bump
//! [`protocol::PROTOCOL_VERSION`] on any wire-visible change.

pub mod adapt;
pub mod crypto;
pub mod error;
pub mod geometry;
pub mod input;
pub mod input_state;
pub mod logging;
// Parked behind cargo features: written, tested, and reachable from no product
// code path. `netsim` is used only by the `directdesk-tests` crate, which turns
// the feature on in its own manifest; `nettest` is used by nothing at all yet.
//
// The `test` disjunct is load-bearing, NOT redundant. It is what keeps these
// modules' tests in the default `cargo test --workspace` run while removing the
// code from every product binary. Reduce either gate to a bare
// `#[cfg(feature = "...")]` and the suite silently loses those tests without
// failing — see the `[features]` block in `shared/Cargo.toml` and the
// `parked_modules` tripwire at the bottom of this file.
#[cfg(any(feature = "netsim", test))]
pub mod netsim;
#[cfg(any(feature = "nettest", test))]
pub mod nettest;
pub mod protocol;
pub mod secret;
pub mod stats;
pub mod svc_ipc;
pub mod tiles;
pub mod traits;
pub mod transport;
pub mod video;
pub mod winutil;

pub use error::{Error, Result};

/// Compile-time tripwire for the parked-module feature gates.
///
/// Four modules — `transport::tcp`, `transport::race`, `nettest` and
/// `netsim` — are parked behind cargo features and gated with
/// `#[cfg(any(feature = "...", test))]`. That `test` disjunct is the whole
/// mechanism: it keeps roughly 105 tests in the default
/// `cargo test --workspace` run while removing ~7100 lines from every product
/// binary.
///
/// The failure mode this module guards against is silent. If someone "tidies"
/// one of those gates down to a bare `#[cfg(feature = "...")]`, the default test
/// run does **not** go red. The tests simply cease to exist: the suite prints a
/// smaller number and passes. A test suite that stops testing without saying so
/// is worse than no suite at all, because it still reads as evidence.
///
/// So this module names one cheap public item from each parked module. Under a
/// bare feature gate those paths stop resolving and the crate fails to COMPILE,
/// which nobody can miss. The runtime assertions are almost beside the point —
/// the compile is the assertion. Every item named here is a `const` or a pure
/// function: no sockets, no async, no clock, so this cannot become flaky.
#[cfg(test)]
mod parked_modules {
    /// Fails to compile if any parked module's gate loses its `test` disjunct.
    #[test]
    fn parked_modules_still_reach_the_test_harness() {
        // transport::tcp — framing constant, no I/O.
        assert_eq!(crate::transport::tcp::FRAME_HEADER_LEN, 5);

        // transport::race — race timing constant, no clock read.
        assert!(crate::transport::race::DEFAULT_STAGGER_MS > 0);

        // nettest — one item from each submodule, so that splitting this
        // feature into `nettest-stun` / `nettest-probe` later cannot quietly
        // re-open half of the same hole.
        assert_eq!(crate::nettest::stun::MAGIC_COOKIE, 0x2112_A442);
        let private = std::net::Ipv4Addr::new(10, 0, 0, 1);
        assert!(crate::nettest::is_private_v4(private));

        // netsim — datagram size constant, no simulation run.
        assert_eq!(crate::netsim::DEFAULT_MTU, 1200);
    }
}
