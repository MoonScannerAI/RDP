//! The platform-neutral application entry point.
//!
//! `main.rs` (Windows) and the `directdesk-android` crate's `android_main` both
//! build a [`PlatformConfig`] and hand it to [`run`]. Everything that differs
//! between platforms is a field here; everything else — the tokio runtime, the
//! connect supervisor, the decode threads, the eframe app — lives in `run` and
//! is shared.
//!
//! CONTRACT (Phase 1.0 scaffold): the types below are fixed; `run` is filled in
//! by the W1 refactor, which moves the body of `main.rs::main` here without
//! changing Windows behaviour.

use std::path::PathBuf;
use std::sync::Arc;

use directdesk_shared::crypto::storage::SecretStore;

use crate::connect::StreamCaps;
use crate::pipeline::NewDecoder;

/// Which interaction model the UI uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UiProfile {
    /// Mouse + physical keyboard: today's Windows client, unchanged.
    #[default]
    Desktop,
    /// Touchscreen: trackpad gestures, on-screen keyboard, compact toolbar.
    /// Selected on Android, and on Windows by `--touch-ui` for testing.
    Touch,
}

/// Launch-time options that come from the command line on Windows (and are
/// mostly defaults on Android).
#[derive(Debug, Clone, Default)]
pub struct LaunchArgs {
    /// Pre-fills the host field and auto-connects once on the first frame.
    pub host: Option<String>,
    pub udp_port: Option<u16>,
    pub pair_code: Option<String>,
    pub loopback_demo: bool,
    pub demo_fps: u32,
    pub demo_second_window: bool,
    pub capture_on_start: bool,
    pub hold_capture: bool,
}

/// Everything platform-specific that [`run`] needs.
pub struct PlatformConfig {
    pub profile: UiProfile,
    /// Directory for `client.json`. `None` = the desktop default
    /// (`dirs::config_dir()/DirectDesk`). Android passes the app's private
    /// files directory.
    pub data_dir: Option<PathBuf>,
    /// The secret store for the client identity and trusted hosts, or why it
    /// could not be opened (the UI then runs with Connect disabled).
    pub store: Result<Arc<dyn SecretStore>, String>,
    /// How decode threads build their H.264 decoder (Media Foundation on
    /// Windows, MediaCodec on Android).
    pub new_decoder: NewDecoder,
    /// Hello capabilities and stream preferences. Android: no audio, no tiles,
    /// no multi-monitor, 30 fps.
    pub caps: StreamCaps,
    /// Name shown on the host when no name is saved in `client.json`.
    pub default_display_name: String,
    pub launch: LaunchArgs,
    /// Window/viewport options; on Android this carries `android_app`.
    pub native_options: eframe::NativeOptions,
}

/// Run the client until its window closes.
pub fn run(cfg: PlatformConfig) -> anyhow::Result<()> {
    let _ = cfg;
    todo!("W1: move main.rs wiring here")
}
