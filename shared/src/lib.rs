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
pub mod netsim;
pub mod nettest;
pub mod protocol;
pub mod secret;
pub mod stats;
pub mod svc_ipc;
pub mod tiles;
pub mod traits;
pub mod transport;
pub mod video;

pub use error::{Error, Result};
