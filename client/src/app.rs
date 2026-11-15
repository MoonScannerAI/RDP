//! The platform-neutral application entry point.
//!
//! `main.rs` (Windows) and the `directdesk-android` crate's `android_main` both
//! build a [`PlatformConfig`] and hand it to [`run`]. Everything that differs
//! between platforms is a field here; everything else — the tokio runtime, the
//! connect supervisor, the decode threads, the eframe app — lives in `run` and
//! is shared.
//!
//! `run` is the body `main.rs::main` used to have, moved here verbatim in order
//! of construction; the platform-specific values it used to compute inline
//! (secret store, decoder factory, stream caps, machine name, window options)
//! now arrive as [`PlatformConfig`] fields instead.

use std::path::PathBuf;
use std::sync::Arc;

use directdesk_shared::crypto::storage::SecretStore;

use crate::config::{self, ClientConfig};
use crate::connect::{ConnectSupervisor, StreamCaps};
use crate::pipeline::{self, NewDecoder};
use crate::renderer::FrameSlot;
use crate::session::{ClientSession, TransportEndpoints};
use crate::ui::{AppInit, ClientApp, SourceMode};

/// `tracing` target for the log lines `run` inherited from `main.rs`.
///
/// They used to be emitted from the `DirectDeskClient` binary crate, whose
/// module path — and so the target the console and file layers print — is
/// `DirectDeskClient`. Pinning it keeps those lines byte-identical to what
/// the Windows client has always logged, rather than silently becoming
/// `directdesk_client::app` because the code moved crates.
const LOG_TARGET: &str = "DirectDeskClient";

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
///
/// Safe to call more than once per process (Android can re-enter
/// `android_main`): each call builds and tears down its own runtime, session
/// and threads, and the config-directory override tolerates being set again.
pub fn run(cfg: PlatformConfig) -> anyhow::Result<()> {
    let PlatformConfig {
        profile,
        data_dir,
        store,
        new_decoder,
        caps,
        default_display_name,
        launch,
        native_options,
    } = cfg;

    // Before the first `ClientConfig::load()`: the override decides which
    // file that (and every later `save()`) touches.
    if let Some(dir) = data_dir {
        config::set_config_dir(dir);
    }

    let mut config = ClientConfig::load();
    // An explicit `--host` both pre-fills the field and auto-triggers a connect.
    let host_given = launch.host.is_some();
    if let Some(host) = launch.host {
        config.host_address = host;
    }
    if let Some(p) = launch.udp_port {
        config.udp_port = p;
    }

    let (session, transport) = ClientSession::new();
    let slot = Arc::new(FrameSlot::new());
    // The second monitor's frame slot. Created unconditionally — whether a
    // session ever carries a second stream is decided per connection, in the
    // handshake — and stays empty until one does.
    let slot2 = Arc::new(FrameSlot::new());

    let mode = if launch.loopback_demo {
        SourceMode::LoopbackDemo
    } else {
        SourceMode::Live
    };

    // One long-lived runtime shared by the connect supervisor for the whole app.
    // The supervisor holds only a `Handle`; this owns the worker threads and is
    // dropped (shutting the runtime down) once the window closes.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    // The name shown on the host: a remembered name wins, else the platform's
    // default (the machine name on Windows).
    let display_name = {
        let saved = config.display_name.trim();
        if saved.is_empty() {
            default_display_name
        } else {
            saved.chars().filter(|c| !c.is_control()).take(64).collect()
        }
    };

    // Build the connect supervisor for Live mode. `--loopback-demo` has no
    // transport at all; if the secret store cannot be opened we keep the
    // channels alive (so the UI still runs) but Connect stays disabled.
    let (supervisor, transport_for_app) = match mode {
        SourceMode::LoopbackDemo => {
            tracing::warn!(
                target: LOG_TARGET,
                "--loopback-demo: synthetic frames at {} fps; decoder and network are BYPASSED",
                launch.demo_fps
            );
            spawn_input_sink(transport);
            (None, None)
        }
        SourceMode::Live => match store {
            Ok(store) => {
                let supervisor =
                    ConnectSupervisor::new(runtime.handle().clone(), store, transport, caps);
                (Some(supervisor), None)
            }
            Err(e) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "secret store unavailable ({e}); transport disabled"
                );
                (None, Some(transport))
            }
        },
    };

    // An explicit CLI `--host` auto-triggers one connect on the first frame; a
    // merely-remembered host just pre-fills the form. Needs a live supervisor.
    let auto_connect = host_given && supervisor.is_some();
    let initial_pair_code = launch.pair_code.clone();

    let video_rx = session.video_rx.clone();
    let video2_rx = session.video2_rx.clone();
    let demo_fps = launch.demo_fps;
    let demo_second_window = launch.demo_second_window;
    let capture_on_start = launch.capture_on_start;
    let hold_capture = launch.hold_capture;

    eframe::run_native(
        "DirectDesk",
        native_options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let repaint = {
                let ctx = ctx.clone();
                move || ctx.request_repaint()
            };
            let mut pipeline = match mode {
                SourceMode::LoopbackDemo => {
                    pipeline::spawn_demo_source(slot.clone(), demo_fps, repaint)
                }
                SourceMode::Live => {
                    // The decode thread asks for a keyframe when a decode fails,
                    // so it needs the outbound control channel.
                    let control_tx = session.control_tx.clone();
                    pipeline::spawn_decode_thread(
                        new_decoder,
                        video_rx,
                        slot.clone(),
                        control_tx,
                        repaint,
                    )
                }
            };

            // The second decode path, attached once here exactly like the tile
            // and audio threads: whether a connection carries a second monitor
            // is decided per handshake, long after this point, and the thread
            // costs one parked poll until a stream-1 frame actually arrives (it
            // builds no decoder before then). Wiring it here rather than on
            // connect also means a mid-session `SelectMonitors` needs no thread
            // plumbing at all.
            let stream1_status = match mode {
                SourceMode::Live => {
                    // Repaints the *child* viewport, not the root: the second
                    // window paints on its own cadence, which is the whole
                    // reason it is a deferred viewport.
                    let repaint2 = move || {
                        ctx.request_repaint_of(crate::ui::second_window::stream1_viewport_id())
                    };
                    pipeline.attach_decode_thread(
                        new_decoder,
                        video2_rx,
                        slot2.clone(),
                        session.control_tx.clone(),
                        repaint2,
                    )
                }
                // `--loopback-demo` has no transport, so nothing could ever
                // reach a second decode thread — unless `--demo-second-window`
                // asked for a synthetic source to feed the second slot
                // instead, exercising the same window/focus/close/diagnostics
                // path with no dual-monitor host at all. Without that flag the
                // gauges still exist so the UI has something honest to read:
                // they report nothing measured.
                SourceMode::LoopbackDemo => {
                    if demo_second_window {
                        let repaint2 = move || {
                            ctx.request_repaint_of(crate::ui::second_window::stream1_viewport_id())
                        };
                        pipeline.attach_demo_thread(slot2.clone(), demo_fps, repaint2)
                    } else {
                        Arc::new(pipeline::SourceStatus::default())
                    }
                }
            };

            Ok(Box::new(ClientApp::new(
                cc,
                AppInit {
                    config,
                    session,
                    transport: transport_for_app,
                    slot,
                    slot2,
                    stream1_status,
                    pipeline,
                    mode,
                    supervisor,
                    display_name,
                    initial_pair_code,
                    auto_connect,
                    capture_on_start,
                    hold_capture,
                    demo_second_window,
                    profile,
                },
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe failed: {e}"))?;

    // The window has closed and `ClientApp` (with the supervisor) has been
    // dropped, cancelling any live connection. Drop the runtime to stop its
    // worker threads.
    drop(runtime);

    Ok(())
}

/// Demo mode has no transport, so drain the outbound channels and count what
/// the UI produces. This is how `--loopback-demo` proves input capture works.
fn spawn_input_sink(mut transport: TransportEndpoints) {
    std::thread::Builder::new()
        .name("directdesk-input-sink".into())
        .spawn(move || {
            use directdesk_shared::input::InputEvent;
            use directdesk_shared::protocol::InputMsg;

            let (mut keys, mut moves, mut buttons, mut wheels, mut releases) =
                (0u64, 0u64, 0u64, 0u64, 0u64);
            let mut last_log = std::time::Instant::now();
            while let Some(msg) = transport.input_rx.blocking_recv() {
                match msg {
                    InputMsg::Event(InputEvent::Key { .. }) => keys += 1,
                    InputMsg::Event(InputEvent::MouseMove { .. }) => moves += 1,
                    InputMsg::Event(InputEvent::MouseButton { .. }) => buttons += 1,
                    InputMsg::Event(InputEvent::MouseWheel { .. }) => wheels += 1,
                    InputMsg::ReleaseAll => releases += 1,
                    // Appended alongside `features::MULTI_MONITOR`; the capture
                    // path cannot produce one until that feature is wired, so
                    // this sink has nothing to count yet.
                    InputMsg::EventOn { .. } => {}
                }
                if last_log.elapsed() >= std::time::Duration::from_secs(2) {
                    last_log = std::time::Instant::now();
                    tracing::info!(
                        target: LOG_TARGET,
                        keys,
                        moves,
                        buttons,
                        wheels,
                        releases,
                        "input sink totals"
                    );
                }
            }
            tracing::info!(
                target: LOG_TARGET,
                keys,
                moves,
                buttons,
                wheels,
                releases,
                "input sink final totals"
            );
        })
        .expect("spawn input sink");
}
