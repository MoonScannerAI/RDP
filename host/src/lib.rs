//! DirectDesk host: capture, encode, serve, inject.
//!
//! The media pipeline owns the "screen to bytes" path on Windows:
//!
//! * [`capture`] — Desktop Duplication API (`IDXGIOutputDuplication`) frame source.
//! * [`convert`] — BGRA to NV12 on the GPU (D3D11 VideoProcessor) with a CPU fallback.
//! * [`mf_encoder`] — Media Foundation H.264 MFT selected by the capture adapter's LUID.
//! * [`input_inject`] — `SendInput` injection with held-key tracking.
//! * [`session`] — the orchestration struct the transport plugs into.
//!
//! On top of it sit the pieces that make it a product:
//!
//! * [`net`] — the QUIC listener: pairing, mutual authentication, video
//!   datagrams, input, session control.
//! * [`config`] — `%ProgramData%\DirectDesk\host.json`. No secrets.
//! * [`ui`] — the status window and the notification-area icon.
//!
//! Everything implements the contracts in `directdesk_shared::traits`.

pub mod capture;
pub mod config;
pub mod convert;
pub mod input_inject;
pub mod mf_encoder;
pub mod mfinit;
pub mod net;
pub mod session;
pub mod testsupport;
pub mod ui;

pub use directdesk_shared as shared;
