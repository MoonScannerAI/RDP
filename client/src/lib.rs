//! directdesk-client: decode, present, and capture input for a DirectDesk
//! session.
//!
//! The crate is deliberately transport-agnostic. Everything the network layer
//! needs is [`session::TransportEndpoints`]; nothing in here opens a socket.
//!
//! Module map:
//!
//! * [`decoder`]      — Media Foundation H.264 → RGBA8, decodes every frame.
//! * [`renderer`]     — latest-wins frame slot + letterboxed egui presentation.
//! * [`input_capture`]— low-level keyboard hook, release chord, pointer mapping.
//! * [`session`]      — the channel seam between UI and transport.
//! * [`pipeline`]     — background decode / loopback-demo frame sources.
//! * [`ui`]           — the eframe application shell.
//! * [`config`]       — `%APPDATA%\DirectDesk\client.json` (no secrets).

pub mod config;
pub mod decoder;
pub mod input_capture;
pub mod net;
pub mod pipeline;
pub mod renderer;
pub mod session;
pub mod ui;
