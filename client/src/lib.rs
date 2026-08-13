//! directdesk-client: decode, present, and capture input for a DirectDesk
//! session.
//!
//! The crate is deliberately transport-agnostic. Everything the network layer
//! needs is [`session::TransportEndpoints`]; nothing in here opens a socket.
//!
//! Module map:
//!
//! * [`decoder`]      — Media Foundation H.264 → RGBA8, decodes every frame.
//! * [`audio_decoder`]— Media Foundation AAC-LC → interleaved 16-bit PCM.
//! * [`audio_render`] — WASAPI shared-mode playback; padding *is* the latency.
//! * [`renderer`]     — latest-wins frame slot + letterboxed egui presentation.
//! * [`input_capture`]— low-level keyboard hook, release chord, pointer mapping.
//! * [`session`]      — the channel seam between UI and transport.
//! * [`connect`]      — supervisor that spawns/cancels the transport driver.
//! * [`pipeline`]     — background decode / loopback-demo frame sources.
//! * [`tiles`]        — lossless static-region tile store + compositor.
//! * [`ui`]           — the eframe application shell.
//! * [`config`]       — `%APPDATA%\DirectDesk\client.json` (no secrets).
//! * [`monitors`]     — monitor-choice vocabulary + selection resolution.

pub mod audio_decoder;
pub mod audio_render;
pub mod config;
pub mod connect;
pub mod decoder;
pub mod input_capture;
pub mod monitors;
pub mod net;
pub mod pipeline;
pub mod renderer;
pub mod session;
pub mod tiles;
pub mod ui;
