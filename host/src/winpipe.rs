//! Win32 primitives for the UAC click-through path's named pipes: the host's
//! synchronous client of the service's control pipe and of the SYSTEM
//! worker's data pipe (see [`uac_client`](crate::uac_client)), and the
//! `uac_injector` binary's own pipe server.
//!
//! These used to be hand-duplicated here and in `service/src/winutil.rs`
//! (this module said as much). The host and the service hand raw kernel
//! handles to each other and to the SYSTEM worker, so they need *identical*
//! ownership and `Send`/`Sync` semantics; the single definition now lives in
//! the contract crate as `directdesk_shared::winutil`, and this module is
//! just its re-export for existing callers in this crate.

pub use directdesk_shared::winutil::{from_wide_ptr, pcwstr, wide, Event, OwnedHandle};
