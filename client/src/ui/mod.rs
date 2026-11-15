//! eframe application shell: connect screen, streaming view, toolbar,
//! diagnostics.
//!
//! The app owns the UI-side half of [`ClientSession`] and never talks to the
//! network directly — everything arrives and leaves through those channels, so
//! the transport wave plugs in without touching this file.
//!
//! eframe 0.35 splits a frame into [`eframe::App::logic`] (state, no drawing)
//! and [`eframe::App::ui`] (drawing only); this app keeps to that split.
//!
//! # Two profiles
//!
//! [`UiProfile::Desktop`] is the Windows client exactly as it always was.
//! [`UiProfile::Touch`] (Android, or `--touch-ui`) swaps in, and only in that
//! profile:
//!
//! * the streaming view: [`touch_view::TouchView`] gestures + pinch zoom
//!   instead of mouse forwarding, with hardware-keyboard keys still forwarded;
//! * capture that follows the session (on at go-live, off at session end)
//!   instead of a toggle, gated on a focus debounce that ignores Android's
//!   one-frame focus flicker on resume;
//! * the egui [`keyboard::Keyboard`] — Remote while streaming (toolbar button
//!   or Back toggles it), Local on the connect screen whenever a text field
//!   has focus, its events injected through `raw_input_hook`; the system IME
//!   is never requested;
//! * a compact auto-hiding overlay toolbar instead of the top panel;
//! * on Windows only, mouse-to-touch synthesis so all of it runs with a mouse.
//!
//! Frame order in Touch: `raw_input_hook` (strip Back, synthesize touches,
//! inject local keyboard events) → `logic` (focus debounce, session drain,
//! capture policy, Back, key repeat) → `ui` (toolbar first, so its rect is
//! current when the streaming view filters touches; then the views).

pub mod connect_form;
pub mod diagnostics;
pub mod keyboard;
pub mod second_window;
pub mod touch_shell;
pub mod touch_view;

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use directdesk_shared::protocol::{ControlMsg, InputMsg, MonitorInfo, QualityMode};
use directdesk_shared::stats::{validate_stats, ConnStats, TransportRoute};
use parking_lot::Mutex;

use crate::app::UiProfile;
use crate::config::ClientConfig;
use crate::connect::{ConnectSupervisor, DisconnectHandle, StoppingDriver};
use crate::input_capture::{chord_pressed, CaptureLoss, InputCapture, RELEASE_CHORD};
use crate::monitors::{self, MonitorChoice};
use crate::pipeline::{Pipeline, SourceStatus};
use crate::renderer::{describe_scale, is_exact_scale, FrameSlot, Presenter, MAIN_VIDEO_TEXTURE};
use crate::session::{ClientSession, ConnectionState, TransportEndpoints};
use crate::tiles::TileStore;
use crate::ui::keyboard::{Keyboard, KeyboardOutput, KeyboardTarget};
use crate::ui::second_window::SecondaryShared;
#[cfg(not(target_os = "android"))]
use crate::ui::touch_shell::MouseTouchSynth;
use crate::ui::touch_shell::{
    back_action, click_dismisses_text_focus, split_action_row, split_for_keyboard, strip_back_key,
    touch_wants_capture, without_injected, BackAction, BackgroundShared, BackgroundWatchdog,
    FocusDebounce, FocusEdge, OverlayTouchFilter, ResumeAction, ResumeAfterBackground,
    ToolbarState, WatchdogAction, ACTION_ROW_PTS, BACKGROUND_WATCHDOG_POLL, HEARTBEAT_REPAINT,
    TOUCH_TARGET_PTS,
};
use crate::ui::touch_view::TouchView;

/// An outstanding UAC prompt on the remote host, awaiting an operator
/// decision. Shown as a banner over the session view; auto-dismisses so a
/// stale prompt (host recovered on its own, or the operator stepped away)
/// doesn't linger forever.
struct ElevationBanner {
    title: String,
    shown_at: Instant,
}

/// How long an elevation banner stays up without a response before it
/// auto-dismisses. Purely a local UI timeout — it does not tell the host
/// anything; if the operator wants to arm elevation after this they'd need
/// a fresh `ElevationPrompt` from the host.
const ELEVATION_BANNER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default TTL sent with `ArmElevation` when the operator clicks "Allow
/// once": long enough to cover clicking through a slow UAC dialog, short
/// enough that a stray arm doesn't stay live for an unrelated later prompt.
const DEFAULT_ELEVATION_TTL_SECS: u32 = 20;

/// FPS choices offered by the picker, in display order. `0` means "Auto —
/// follow whatever the host is already running at"; every other entry must
/// fall within `UI_MIN_TARGET_FPS..=MAX_TARGET_FPS` (see the test below) so
/// the picker can never offer a value the config's own sanitizing would
/// immediately clamp away.
pub const FPS_CHOICES: [u32; 8] = [0, 60, 45, 30, 24, 20, 15, 10];

/// How the frame source was created, for honest labelling in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    /// Real path: transport → decoder → renderer.
    Live,
    /// `--loopback-demo`: synthetic frames, no decode, no network.
    LoopbackDemo,
}

/// How long the watchdog lets a `ReleaseAll` reach the wire before it raises
/// the shutdown that ends the session (the two travel different paths into
/// the driver, and the driver's `select!` has no order between them).
const RELEASE_BEFORE_BYE: Duration = Duration::from_millis(150);

/// Touch: the UI's half of the background watchdog (see
/// `touch_shell::BackgroundWatchdog`). The thread holds only a `Weak` to the
/// shared state, so dropping this (with the app) ends it within a poll.
struct BackgroundGuard {
    shared: Arc<BackgroundShared>,
    driver: DisconnectHandle,
}

impl BackgroundGuard {
    /// Start the watchdog thread. `None` (logged) if it cannot be spawned:
    /// the app then simply behaves as before.
    fn start(
        driver: DisconnectHandle,
        input_tx: tokio::sync::mpsc::Sender<InputMsg>,
    ) -> Option<Self> {
        let shared = Arc::new(BackgroundShared::new(Instant::now()));
        let weak = Arc::downgrade(&shared);
        let thread_driver = driver.clone();
        let spawned = std::thread::Builder::new()
            .name("directdesk-bg-watchdog".into())
            .spawn(move || background_watchdog(weak, thread_driver, input_tx));
        match spawned {
            Ok(_) => Some(Self { shared, driver }),
            Err(e) => {
                tracing::error!("could not start the background watchdog: {e}");
                None
            }
        }
    }
}

/// The watchdog thread: ends a session whose UI has stopped drawing (the app
/// is in the background) the way the UI's own Disconnect would — input
/// released on the host, a graceful close with `Bye`, no reconnect — then
/// reports it once the driver has gone, for the reconnect on resume.
fn background_watchdog(
    shared: Weak<BackgroundShared>,
    driver: DisconnectHandle,
    input_tx: tokio::sync::mpsc::Sender<InputMsg>,
) {
    let mut dog = BackgroundWatchdog::default();
    let mut stopping: Option<StoppingDriver> = None;
    loop {
        std::thread::sleep(BACKGROUND_WATCHDOG_POLL);
        let Some(shared) = shared.upgrade() else {
            return; // the app is gone
        };
        let now = Instant::now();
        let alive = match &stopping {
            Some(s) => !s.has_exited(),
            None => driver.is_running(),
        };
        match dog.step(&shared, now, alive) {
            WatchdogAction::Nothing => {}
            WatchdogAction::Disconnect => {
                tracing::info!(
                    no_frame_for = ?shared.heartbeat_age(now),
                    "touch: the app is in the background — ending the session \
                     (disconnected because backgrounded)"
                );
                // Lift anything the host holds for us before the session goes.
                let _ = input_tx.try_send(InputMsg::ReleaseAll);
                std::thread::sleep(RELEASE_BEFORE_BYE);
                stopping = driver.shut_down();
            }
            WatchdogAction::Settled => {
                tracing::info!(
                    exited = stopping.as_ref().is_none_or(StoppingDriver::has_exited),
                    "touch: background disconnect complete; reconnecting on resume"
                );
                stopping = None;
            }
        }
    }
}

pub struct AppInit {
    pub config: ClientConfig,
    pub session: ClientSession,
    /// Kept alive so the channels stay open until a transport claims them.
    pub transport: Option<TransportEndpoints>,
    pub slot: Arc<FrameSlot>,
    /// The stream-1 frame slot, written by the second decode thread.
    pub slot2: Arc<FrameSlot>,
    /// The second decode path's own status gauges. Separate from
    /// `pipeline.status` (stream 0's) so neither stream's numbers can be a lie
    /// about the other.
    pub stream1_status: Arc<SourceStatus>,
    pub pipeline: Pipeline,
    pub mode: SourceMode,
    /// Drives `net::run_client` on the shared runtime in response to the connect
    /// screen. `None` when no transport is available (loopback demo, or the
    /// secret store could not be opened).
    pub supervisor: Option<ConnectSupervisor>,
    /// Effective initial display name (persisted name, else the machine name).
    pub display_name: String,
    /// Pre-fills the pairing-code box (`--pair-code`). Never persisted.
    pub initial_pair_code: Option<String>,
    /// Connect once on the first frame (an explicit CLI `--host` was given).
    pub auto_connect: bool,
    /// Test aid (`--capture-on-start`): install the keyboard hook immediately
    /// so the capture path can be exercised without a click.
    pub capture_on_start: bool,
    /// Test aid (`--hold-capture`): install the hook on launch and keep it
    /// installed across focus/minimize changes (only a window close, or the
    /// release chord, tears it down). Lets the capture path be exercised on a
    /// machine where another app keeps stealing foreground focus.
    pub hold_capture: bool,
    /// Test aid (`--demo-second-window`): the caller has already attached a
    /// second synthetic source to `slot2` (mirroring `--loopback-demo`'s
    /// primary source), so open the second window immediately rather than
    /// waiting for a `MonitorList` that a loopback session will never
    /// receive. `main`'s arg parsing rejects this flag without
    /// `--loopback-demo`, so it is meaningless (and never set) under
    /// `SourceMode::Live`.
    pub demo_second_window: bool,
    /// Interaction model. `Touch` (Android, or `--touch-ui` on Windows) never
    /// installs the low-level keyboard hook; `Desktop` is today's client.
    pub profile: crate::app::UiProfile,
}

pub struct ClientApp {
    config: ClientConfig,
    session: ClientSession,
    _transport: Option<TransportEndpoints>,
    slot: Arc<FrameSlot>,
    pipeline: Pipeline,
    /// The pipeline's lossless refinement store. Held here so every place that
    /// already invalidates presentation state can invalidate the overlay in the
    /// same breath — a tile describes *screen content*, so it outlives any one
    /// decoded frame and nothing else would ever drop it.
    tiles: Arc<TileStore>,
    presenter: Presenter,
    input: InputCapture,
    mode: SourceMode,
    /// Spawns/cancels the transport driver. `None` when no transport is wired.
    supervisor: Option<ConnectSupervisor>,

    state: ConnectionState,
    route: Option<TransportRoute>,
    stats: Option<ConnStats>,
    stats_at: Option<Instant>,

    address_input: String,
    udp_port_input: String,
    name_input: String,
    code_input: String,
    /// Set when the connect form fails validation; shown under the form.
    form_error: Option<String>,
    /// Connect once on the first frame, from an explicit CLI `--host`.
    auto_connect: bool,
    show_diagnostics: bool,
    fullscreen: bool,
    notice: Option<String>,
    /// Set while the host has an active UAC prompt the operator can approve.
    elevation: Option<ElevationBanner>,
    /// Cached once per frame: `MouseWheel` events carry no position.
    pointer: Option<egui::Pos2>,
    /// Periodic counter dump, so a headless run is still verifiable.
    metrics_logged_at: Instant,
    /// Pending `--capture-on-start`; consumed on the first frame, because the
    /// hook must be installed from the thread running the message pump.
    capture_on_start: bool,
    /// `--hold-capture` test mode: keep capture engaged through focus loss.
    hold_capture: bool,
    /// The user asked for the keyboard back (release chord, toolbar, or a hook
    /// that would not install). Latches the auto re-arm off until they ask for
    /// capture again — without it, every release was undone on the next frame.
    /// Deliberately not persisted: each launch starts willing to capture.
    user_released: bool,

    /// Host dims/fps/bitrate from the most recent `VideoConfig`, kept
    /// separately from `Presenter::frame_size()` so the 1:1 button works
    /// before the first frame has decoded.
    host_video: Option<(u32, u32, u32, u32)>,
    /// Measured toolbar chrome height, in egui points: the gap between the
    /// window's full content height and the video viewport. Measured rather
    /// than hardcoded so it survives style and font changes.
    chrome_points: f32,
    /// fps the host most recently reported via `VideoConfig`; shown next to
    /// the FPS control as the only in-app confirmation the host actually
    /// honoured a request.
    host_reported_fps: Option<u32>,
    /// When we last re-sent `StartStream` to reassert a lower fps after a
    /// reconnect silently reverted it. Rate-limits `should_reassert_fps`.
    last_fps_reassert: Option<Instant>,

    /// Snap to a fixed integer scale automatically the first time the host's
    /// video format is learned on a connection. `0` = off, `1` = snap to 1:1,
    /// `2` = snap to 2x. Loaded from and persisted to
    /// `ClientConfig::auto_snap_scale` (see `ClientApp::new` and `persist`).
    /// Defaults off: auto-resizing a user's window without being asked is a
    /// bigger surprise than leaving them at a fractional scale.
    auto_snap_scale: u32,
    /// Set when `auto_snap_scale` is nonzero and a fresh `VideoConfig` just
    /// taught us the host's dims for the first time this connection. Consumed
    /// (and cleared) by `toolbar`, which is where `ctx` and `chrome_points`
    /// are available to actually resize the window.
    pending_auto_snap: bool,

    /// Tint composited tiles green so their coverage is visible at a glance.
    /// Bring-up aid; mirrored into the pipeline (which the decode thread
    /// reads) whenever it changes. Deliberately not persisted.
    tile_highlight: bool,

    // -- Second monitor (stream 1). All of this is inert on a session that
    // -- never negotiated MULTI_MONITOR: `monitors` stays `None`, which is the
    // -- single gate every one of these paths reads.
    /// The stream-1 frame slot. Held here (as well as inside `stream1`) because
    /// the teardown sites clear it without needing the lock.
    stream1_slot: Arc<FrameSlot>,
    /// Stream 1's decode gauges, for the metrics dump.
    stream1_status: Arc<SourceStatus>,
    /// State the deferred child viewport's paint callback shares with this
    /// struct. See `second_window` for why it has to live behind a mutex.
    stream1: Arc<Mutex<SecondaryShared>>,
    /// UI intent: whether the second OS window should exist this pass. The
    /// deferred viewport lives only while it is re-declared, so this flag *is*
    /// the window's lifetime.
    stream1_window_open: bool,
    /// What the operator has said about the second window *this session*.
    ///
    /// The host re-sends its whole `MonitorList` on any topology change — a
    /// resolution change or a re-arrange, not only a plug/unplug — so the
    /// decision of whether a second window should be up cannot be re-derived
    /// from the persisted connect-screen choice each time: that would slam a
    /// toolbar-opened window shut, and re-open one the operator had dismissed.
    /// This field is what survives those re-sends. A host-driven `StreamStopped`
    /// deliberately does **not** touch it: that is not the operator's decision,
    /// so a monitor that comes back brings its window back with it.
    stream1_intent: SecondWindowIntent,
    /// Stream 1's dims/fps/bitrate from the most recent `StreamConfig { id: 1 }`,
    /// for the window title. The stream-1 twin of `host_video`.
    stream1_video: Option<(u32, u32, u32, u32)>,
    /// Which monitor id stream 1 is showing, per the host's `StreamConfig`.
    /// Used only to look its name up for the title.
    stream1_monitor: Option<u8>,
    /// The host's `MonitorList` for this session, or `None` when none ever
    /// arrived.
    ///
    /// **`None` is the degrade signal**: an old host that does not echo the
    /// `MULTI_MONITOR` bit sends no list at all, so this is also the gate on
    /// every mid-session `SelectMonitors` re-send — the UI is the only place
    /// that knows whether the feature was negotiated.
    monitors: Option<Vec<MonitorInfo>>,
    /// Interaction model, from [`AppInit::profile`].
    profile: UiProfile,

    // -- Touch profile. Everything below is inert in `UiProfile::Desktop`:
    // -- nothing reads or writes it outside a `profile == Touch` gate.
    /// Trackpad gestures, pinch zoom and the cursor sprite for the main window.
    touch: TouchView,
    /// The on-screen keyboard: Remote while streaming, Local on the connect
    /// screen. Hidden unless asked for.
    keyboard: Keyboard,
    /// The operator's keyboard toggle while streaming (toolbar or Back).
    osk_streaming: bool,
    /// Window focus with Android's one-frame resume flicker filtered out.
    touch_focus: FocusDebounce,
    /// The session was live last frame (edge for "show the toolbar").
    touch_was_live: bool,
    /// The compact overlay toolbar: expanded until a deadline.
    touch_toolbar: ToolbarState,
    /// The overlay toolbar's rect *this* frame (it is drawn before the video).
    touch_toolbar_rect: Option<egui::Rect>,
    /// Fingers that started on an overlay; the gesture layer never sees them.
    touch_filter: OverlayTouchFilter,
    /// Local keyboard events waiting for the next frame's `raw_input_hook`.
    pending_local_events: Vec<egui::Event>,
    /// What `raw_input_hook` injected into the current frame. Subtracted from
    /// the events the streaming view forwards, so a local keystroke can never
    /// reach the host as if typed on a hardware keyboard.
    injected_events: Vec<egui::Event>,
    /// Back presses stripped from this frame's raw input, acted on in `logic`.
    back_presses: u32,
    /// Connect-screen text fields drawn last frame: (id, rect).
    connect_text_edits: Vec<(egui::Id, egui::Rect)>,
    /// The connect-screen field that had focus last frame.
    connect_focus: Option<egui::Id>,
    /// Scroll the focused field into view on its next draw (the keyboard just
    /// took the bottom of the screen, or focus moved).
    connect_scroll_pending: bool,
    /// The connect form's "Advanced" section (UDP port) is expanded.
    touch_advanced_open: bool,
    /// The heartbeat + watchdog that end a session left running in the
    /// background. `None` without a transport (nothing to end).
    background: Option<BackgroundGuard>,
    /// Reconnect-once-on-resume after the watchdog ended a session.
    bg_resume: ResumeAfterBackground,
    /// `--touch-ui` on Windows: the mouse plays a single finger.
    #[cfg(not(target_os = "android"))]
    mouse_touch: MouseTouchSynth,
}

impl ClientApp {
    pub fn new(cc: &eframe::CreationContext<'_>, init: AppInit) -> Self {
        // `set_visuals` only edits the *current* theme's style, which the
        // system theme preference then overrides. Pin the preference instead:
        // a remote screen belongs on a dark surround, always.
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        let input_tx = init.session.input_tx.clone();
        // A touch device has no physical keyboard to hook (and Android no
        // `SetWindowsHookEx`); every other part of capture behaves the same.
        let input = match init.profile {
            UiProfile::Touch => InputCapture::without_hook(input_tx.clone()),
            UiProfile::Desktop => InputCapture::new(input_tx.clone()),
        };
        let profile = init.profile;
        if profile == UiProfile::Touch {
            // Tapping the on-screen keyboard is a click outside the focused
            // text field, which by default surrenders its focus before the
            // injected keystroke arrives. Focus is dropped explicitly instead
            // (tap elsewhere, Enter, Back) — see `touch_connect_screen`.
            cc.egui_ctx.options_mut(|o| {
                o.input_options.surrender_focus_on = egui::SurrenderFocusOn::Never;
            });
            // Finger-sized controls everywhere the touch profile reuses
            // desktop widgets (connect form, combo boxes, dialogs).
            cc.egui_ctx.all_styles_mut(|style| {
                style.spacing.interact_size.y = style.spacing.interact_size.y.max(TOUCH_TARGET_PTS);
                style.spacing.button_padding = egui::vec2(10.0, 6.0);
                style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            });
        }
        // `Keyboard::new` starts visible; this app shows it on demand only.
        // Nothing is held yet, so there is nothing to deliver.
        let mut keyboard = Keyboard::new();
        let _ = keyboard.set_visible(false);
        let show_diagnostics = init.config.show_diagnostics;
        let auto_snap_scale = init.config.auto_snap_scale;
        let fullscreen = init.config.start_fullscreen;
        if fullscreen {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
        }
        // The supervisor is built with the platform's `StreamCaps` (the
        // default on Windows: fps 0 = host decides; `StreamCaps::touch_device`
        // on Android: 30) before the persisted config is known. Seed a
        // persisted fps choice into it now so the *first* connect carries it
        // too, not just ones made after the toolbar combo is touched — but
        // only an explicit one: 0 means "Auto", which must not override the
        // platform preset (it used to, silently lifting Android's 30 fps cap).
        // On Windows the preset is itself 0, so skipping 0 changes nothing.
        let mut supervisor = init.supervisor;
        if let Some(sup) = supervisor.as_mut() {
            if let Some(fps) = persisted_fps_override(init.config.preferred_fps) {
                sup.set_preferred_fps(fps);
            }
            // Same reasoning as `begin_connect`: only a session that can
            // offer multi-monitor takes the picker's choice.
            if monitor_picker_offered(profile, Some(sup.offers_multi_monitor())) {
                sup.set_monitor_choice(init.config.monitor_choice);
            }
        }
        // Touch: end sessions left running in the background (Android drops
        // the window and stops calling us; the transport would not notice).
        let background = match (profile, supervisor.as_ref()) {
            (UiProfile::Touch, Some(sup)) => {
                BackgroundGuard::start(sup.disconnect_handle(), input_tx.clone())
            }
            _ => None,
        };

        // Lossless refinement tiles. The store belongs to the pipeline (the
        // decode thread paints from it and is spawned before this app exists);
        // we take a clone to invalidate it and to read its gauges. Both ends of
        // the delivery channel are wired here: the tile thread drains it, and
        // the transport driver publishes into it through a one-time sink,
        // because `run_client`'s argument list is owned by `ConnectSupervisor`.
        let mut pipeline = init.pipeline;
        let tiles = pipeline.tiles();
        pipeline.attach_tile_thread(init.session.tiles_rx.clone());
        // System audio. Attached unconditionally, exactly like the tile thread:
        // whether audio was negotiated is decided per connection, in the
        // handshake, and this thread simply never sees a packet on a session
        // that did not get it. It builds no decoder and opens no endpoint until
        // the first packet's format tells it what to build.
        pipeline.attach_audio_thread(init.session.audio_rx.clone());

        Self {
            address_input: init.config.host_address.clone(),
            udp_port_input: init.config.udp_port.to_string(),
            name_input: init.display_name,
            code_input: init.initial_pair_code.unwrap_or_default(),
            form_error: None,
            auto_connect: init.auto_connect,
            config: init.config,
            session: init.session,
            _transport: init.transport,
            slot: init.slot,
            pipeline,
            tiles,
            presenter: Presenter::new(MAIN_VIDEO_TEXTURE),
            input,
            mode: init.mode,
            supervisor,
            state: if init.mode == SourceMode::LoopbackDemo {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            },
            route: None,
            stats: None,
            stats_at: None,
            show_diagnostics,
            fullscreen,
            notice: None,
            elevation: None,
            pointer: None,
            metrics_logged_at: Instant::now(),
            // `--hold-capture` implies the one-shot install too, so the flag
            // works on its own without also passing `--capture-on-start`.
            capture_on_start: init.capture_on_start || init.hold_capture,
            hold_capture: init.hold_capture,
            user_released: false,
            host_video: None,
            chrome_points: 0.0,
            host_reported_fps: None,
            last_fps_reassert: None,
            auto_snap_scale,
            pending_auto_snap: false,
            tile_highlight: false,
            stream1: Arc::new(Mutex::new(SecondaryShared::new(
                init.slot2.clone(),
                input_tx,
            ))),
            stream1_slot: init.slot2,
            stream1_status: init.stream1_status,
            // Normally waits for a `MonitorList`/toolbar click; `--demo-second-window`
            // has no host to send either, so it starts the window open directly.
            stream1_window_open: init.demo_second_window,
            stream1_intent: SecondWindowIntent::default(),
            stream1_video: None,
            stream1_monitor: None,
            monitors: None,
            profile,
            touch: TouchView::new(),
            keyboard,
            osk_streaming: false,
            touch_focus: FocusDebounce::default(),
            touch_was_live: false,
            touch_toolbar: ToolbarState::default(),
            touch_toolbar_rect: None,
            touch_filter: OverlayTouchFilter::default(),
            pending_local_events: Vec::new(),
            injected_events: Vec::new(),
            back_presses: 0,
            connect_text_edits: Vec::new(),
            connect_focus: None,
            connect_scroll_pending: false,
            touch_advanced_open: false,
            background,
            bg_resume: ResumeAfterBackground::default(),
            #[cfg(not(target_os = "android"))]
            mouse_touch: MouseTouchSynth::default(),
        }
    }

    /// The interaction model this app was built with (fixed for its life).
    pub fn profile(&self) -> UiProfile {
        self.profile
    }

    fn is_touch(&self) -> bool {
        self.profile == UiProfile::Touch
    }

    /// The monitor choice connects and notices act on: the persisted picker
    /// value where the picker is offered, otherwise `Primary` — a hidden
    /// picker's stale value must not produce a "host too old" notice for a
    /// `MonitorList` that can never arrive. Desktop: always the config value.
    fn effective_monitor_choice(&self) -> MonitorChoice {
        if self.monitor_picker_shown() {
            self.config.monitor_choice
        } else {
            MonitorChoice::Primary
        }
    }

    /// See [`monitor_picker_offered`].
    fn monitor_picker_shown(&self) -> bool {
        monitor_picker_offered(
            self.profile,
            self.supervisor
                .as_ref()
                .map(ConnectSupervisor::offers_multi_monitor),
        )
    }

    /// Dump the live counters every couple of seconds. This is what makes a
    /// `--loopback-demo` run verifiable without touching the window.
    fn log_metrics(&mut self, ctx: &egui::Context) {
        if self.metrics_logged_at.elapsed() < std::time::Duration::from_secs(2) {
            return;
        }
        self.metrics_logged_at = Instant::now();
        let (focused, minimized) =
            ctx.input(|i| (i.focused, i.viewport().minimized.unwrap_or(false)));
        tracing::info!(
            fps_decode = format_args!("{:.1}", self.presenter.fps_decode()),
            fps_present = format_args!("{:.1}", self.presenter.fps_present()),
            present_age_ms =
                format_args!("{:.1}", self.presenter.present_age_ms().unwrap_or(f32::NAN)),
            decoded = self.slot.decoded_count(),
            presented = self.slot.presented_count(),
            dropped_at_present = self.slot.dropped_at_present(),
            keys = self.input.keys_forwarded(),
            hook_calls = self.input.hook_calls(),
            hook_active = self.input.hook_active(),
            moves = self.input.moves_sent(),
            capturing = self.input.is_capturing(),
            // Window state, so a "typed but nothing captured" report can be tied
            // to whether DirectDesk was the foreground/visible window.
            focused = focused,
            minimized = minimized,
            // End-to-end confirmation from the host: how many of the keys we sent
            // it actually injected. If this stays flat while `keys` climbs, the
            // host is receiving but not injecting.
            host_injected = self.stats.map(|s| s.input_injected).unwrap_or(0),
            "client metrics"
        );

        // Stream 1 gets its own line, and only while its window is up: a
        // second set of always-present zeroes would read as a measurement of a
        // stream that does not exist. This is what makes a two-monitor run
        // verifiable from the log alone.
        if self.second_window_visible() {
            tracing::info!(
                fps_decode1 = format_args!("{:.1}", self.stream1.lock().fps_decode()),
                decoded1 = self.stream1_slot.decoded_count(),
                presented1 = self.stream1_slot.presented_count(),
                dropped1 = self.stream1_slot.dropped_at_present(),
                gated1 = self.stream1_status.frames_gated(),
                remote1 = format_args!("{:?}", self.stream1_slot.remote_dims()),
                source_error1 = format_args!("{:?}", self.stream1_status.error()),
                "stream 1 metrics"
            );
        }

        // Log presentation geometry separately: scale, resolution, and ppp are
        // the key diagnostics to determine whether the video is being drawn 1:1
        // or at a blurry fractional scale. Logged only when host dims are known.
        let scale = self.presenter.last_scale();
        let ppp = ctx.pixels_per_point();
        if let Some((w, h, _, _)) = self.host_video {
            tracing::info!(
                "presentation: host {}x{}, scale {:.2}x ({}), ppp {:.2}, chrome {:.1}pt",
                w,
                h,
                scale,
                describe_scale(scale),
                ppp,
                self.chrome_points
            );
        }
    }

    fn streaming(&self) -> bool {
        self.presenter.has_frame() || self.state.is_live()
    }

    /// Drain every inbound channel. Never blocks.
    fn drain_session(&mut self) {
        while let Ok(state) = self.session.state_rx.try_recv() {
            if state != self.state {
                tracing::info!("connection state: {}", state.label());
            }
            if !state.is_live() {
                self.presenter.reset();
                self.slot.clear();
                // The overlay describes a screen we are no longer watching, and
                // `run_client` reconnects on its own — so without this a
                // reconnect would paint the *old* session's pixels until every
                // lease ran out. `clear` also disarms until the host's next
                // `Reset`, which closes the race against strips still in flight.
                self.tiles.clear();
                // Touch: release held fingers/keys while capture is still on.
                self.touch_session_end();
                // With background capture on, keep the hook installed across
                // connection churn (connecting, WAN stalls, reconnects) so the
                // capture path is live again the moment the session is. Nothing
                // is swallowed meanwhile — the hook gates that on the session
                // being live — so local typing works right through an outage.
                // Without it, releasing here is what hands the keyboard back.
                if !self.effective_background_capture() {
                    self.input.stop_capture();
                }
                // The second window belongs to the session that opened it: its
                // monitor ids are session-scoped, and `run_client` reconnects
                // on its own, so leaving it up would show the *old* session's
                // pixels under a title derived from ids the next session may
                // reuse for a different panel.
                self.reset_second_window_for_session_end(true);
            }
            self.state = state;
        }
        while let Ok(route) = self.session.route_rx.try_recv() {
            self.route = route;
        }
        while let Ok(stats) = self.session.stats_rx.try_recv() {
            self.accept_stats(stats);
        }
        while let Ok(msg) = self.session.control_rx.try_recv() {
            self.handle_control(msg);
        }
    }

    /// The contract says peer stats are informational and must be screened
    /// before a UI renders them.
    fn accept_stats(&mut self, stats: ConnStats) {
        if validate_stats(&stats) {
            self.stats = Some(stats);
            self.stats_at = Some(Instant::now());
        } else {
            tracing::warn!("discarded implausible ConnStats from peer");
        }
    }

    fn handle_control(&mut self, msg: ControlMsg) {
        match msg {
            ControlMsg::VideoConfig {
                width,
                height,
                fps,
                bitrate_kbps,
                codec,
            } => {
                tracing::info!(
                    "host video config: {width}x{height} @{fps} {bitrate_kbps}kbps {codec:?}"
                );
                // First format learned this connection, so this is the moment
                // "auto 1:1" (if the user opted in) should fire.
                let first_config = self.host_video.is_none();
                // A resolution change makes every resident tile's coordinates
                // mean something else, so the overlay has to go. Gated, because
                // this arm also fires on every fps re-assert (and on the reply
                // to our own `StartStream`): clearing unconditionally would
                // disarm the store several times a minute and the refinement
                // would visibly blink off. See `tiles_invalidated_by_config`.
                if tiles_invalidated_by_config(self.host_video, width, height) {
                    tracing::info!("host resolution changed; dropping refinement tiles");
                    self.tiles.clear();
                }
                // Retain the host's own dims/fps so the 1:1 button and the fps
                // diagnostics work even before a frame has decoded.
                self.host_video = Some((width, height, fps, bitrate_kbps));
                self.host_reported_fps = Some(fps);
                if first_config && self.auto_snap_scale != 0 {
                    self.pending_auto_snap = true;
                }

                // `run_client` reconnects internally using the connect-time
                // params, so a mid-session fps choice would otherwise be
                // silently reverted by an auto-reconnect. Re-assert it here,
                // rate-limited so this can't loop.
                let now = Instant::now();
                if should_reassert_fps(self.config.preferred_fps, fps, self.last_fps_reassert, now)
                {
                    self.apply_preferred_fps();
                    self.last_fps_reassert = Some(now);
                }

                // The honest moment to tell the operator their monitor choice
                // could not be honoured because the *host* is too old: a
                // mutual-feature host's `MonitorList` is republished onto this
                // same lane the instant the session goes live, i.e. strictly
                // before the `VideoConfig` that answers our `StartStream`. So
                // "first config, still no list" means there will never be one.
                // Checking at the `Connected` transition instead would race the
                // republish and cry wolf on every multi-monitor session.
                if first_config {
                    if let Some(note) =
                        old_host_notice(self.monitors.is_some(), self.effective_monitor_choice())
                    {
                        self.notice = Some(note);
                    }
                }

                // A format change invalidates decoder state; the decode thread
                // recovers on the next keyframe, so ask for one now.
                self.session.send_control(ControlMsg::RequestKeyframe);
            }
            ControlMsg::MonitorList { monitors } => {
                tracing::info!(count = monitors.len(), "host monitor list");
                // The picker's label cache. Config belongs to the UI thread —
                // nothing on the transport side may reach into it — which is
                // exactly why the handshake republishes the list onto this lane
                // instead of writing the cache itself.
                self.config.cached_monitor_host = self.config.host_address.clone();
                self.config.cached_monitors = monitors.clone();
                self.config.save();

                // The host re-sends the whole list on *any* topology change —
                // a resolution change or a re-arrange, not just a plug/unplug —
                // so the degrade note is shown once per session, on the first
                // list. Re-showing it on every re-send would nag about a fact
                // the operator already acted on.
                let first_list = self.monitors.is_none();
                let plan = plan_monitor_list(
                    self.stream1_intent,
                    self.effective_monitor_choice(),
                    &monitors,
                );
                if first_list {
                    if let Some(note) = plan.notice {
                        self.notice = Some(note);
                    }
                }
                self.monitors = Some(monitors);

                if plan.want_second_window {
                    self.stream1_window_open = true;
                } else if self.stream1_window_open {
                    // The topology no longer has a second output to show (the
                    // operator's own dismissal is already folded into
                    // `plan.want_second_window` via `stream1_intent`). The host
                    // stops that stream on its own and says so with
                    // `StreamStopped`, so this only drops the local window —
                    // re-sending `SelectMonitors` here would be us telling the
                    // host something it just told us.
                    self.close_second_window(false);
                }
            }
            ControlMsg::StreamConfig {
                id,
                monitor,
                width,
                height,
                fps,
                bitrate_kbps,
                codec,
            } => {
                if id == 0 {
                    // Contract: stream 0 is described by the legacy
                    // `VideoConfig` and `StreamConfig { id: 0 }` "is a bug, not
                    // a synonym". Treating it as an alias would let a buggy host
                    // silently drive the main window through the second
                    // window's state, so it is logged and ignored.
                    tracing::warn!(
                        "host sent StreamConfig for stream 0; ignoring (VideoConfig owns stream 0)"
                    );
                    return;
                }
                tracing::info!(
                    "host stream {id} (monitor {monitor}): \
                     {width}x{height} @{fps} {bitrate_kbps}kbps {codec:?}"
                );
                if id != 1 {
                    // MAX_VIDEO_STREAMS is 2, so there is no slot to put this
                    // in and no decoder that would read it.
                    tracing::warn!("ignoring StreamConfig for unsupported stream {id}");
                    return;
                }
                if self.stream1_intent == SecondWindowIntent::Dismissed {
                    // A `StreamConfig` already in flight when the operator
                    // dismissed the window. Ignored *whole*: recording its dims
                    // would leave stale state describing a stream we just asked
                    // the host to stop, and would title the window with it if
                    // they re-opened before the next real config.
                    tracing::debug!("ignoring StreamConfig for a window the operator closed");
                    return;
                }
                // Only a genuine change of dimensions is a discontinuity worth
                // blanking the window for. `StreamConfig` also arrives in reply
                // to every `StartStream` — which this client sends on every fps
                // re-assert and every quality change — so resetting
                // unconditionally would flash the second window to black
                // several times a minute. Exactly the reasoning (and the shape)
                // of `tiles_invalidated_by_config` on the stream-0 path.
                let discontinuity = stream1_format_changed(self.stream1_video, width, height);
                self.stream1_video = Some((width, height, fps, bitrate_kbps));
                self.stream1_monitor = Some(monitor);
                if discontinuity {
                    // Fresh SPS/PPS and an IDR are coming, and anything already
                    // in flight for the old format is undecodable, so drop the
                    // stale picture rather than showing it under the new title.
                    // The decode thread's own `KeyframeGate` handles the
                    // frame_id side.
                    tracing::info!("stream 1 format changed; dropping its picture");
                    self.stream1_slot.clear();
                    self.stream1.lock().reset(true);
                }
                // Positive evidence the second stream is live.
                self.stream1_window_open = true;
            }
            ControlMsg::StreamStopped { id, reason } => {
                if id == 0 {
                    tracing::warn!("host sent StreamStopped for stream 0; ignoring");
                    return;
                }
                tracing::info!(id, %reason, "host stopped a secondary stream");
                self.notice = Some(format!("Second monitor stopped: {reason}"));
                // `by_user: false` on purpose. The host already stopped
                // encoding, so there is nothing to ask it for, and the operator
                // did not choose this — if the monitor comes back, the
                // `MonitorList` that announces it should bring the window back
                // too.
                self.close_second_window(false);
            }
            ControlMsg::RouteReport(route) => self.route = Some(route),
            ControlMsg::Stats(stats) => self.accept_stats(stats),
            ControlMsg::ClipboardText(text) => {
                self.notice = Some(format!(
                    "Clipboard: {} chars from host",
                    text.chars().count()
                ));
            }
            ControlMsg::SecureDesktopActive(active) => {
                self.notice = active.then(|| {
                    "Host is on the secure desktop (UAC/lock) — capture paused.".to_string()
                });
            }
            ControlMsg::ElevationPrompt { title } => {
                // A fresh prompt supersedes whatever banner (if any) was
                // already showing.
                self.elevation = Some(ElevationBanner {
                    title,
                    shown_at: Instant::now(),
                });
            }
            ControlMsg::ElevationEnded => {
                self.elevation = None;
            }
            ControlMsg::Bye { reason } => {
                self.state = ConnectionState::Failed(format!("Host disconnected: {reason}"));
                self.route = None;
                self.elevation = None;
                self.touch_session_end();
                // Background capture keeps the hook across a host `Bye` so a
                // transient disconnect/reconnect doesn't silently kill capture
                // for the rest of the session (observed: a mid-stream `Bye` tore
                // the hook down and it never re-armed). Swallowing still stops
                // with the session. Otherwise we release outright.
                if !self.effective_background_capture() {
                    self.input.stop_capture();
                }
                self.presenter.reset();
                // Matches `presenter.reset()` above: this site deliberately has
                // no `slot.clear()`, but the overlay must still go — it would
                // otherwise survive a host-initiated disconnect and be blitted
                // onto the first frame of whatever comes next.
                self.tiles.clear();
                // Same treatment for the second window, including the same
                // deliberate omission: its presenter is reset, its slot is not.
                self.reset_second_window_for_session_end(false);
            }
            other => tracing::debug!("unhandled control message: {other:?}"),
        }
    }

    /// Whether the second OS window should exist this pass: the UI intends it,
    /// and there is a live session behind it. Both halves are required — see
    /// the call site in `ui` for the channel-ordering reason.
    fn second_window_visible(&self) -> bool {
        stream1_should_be_visible(self.stream1_window_open, self.state.is_live())
    }

    /// Does the second monitor's window have focus right now?
    ///
    /// Always `false` when that window does not exist, which is what keeps the
    /// single-window case bit-for-bit what it always was: nothing here is even
    /// consulted, and the hook's foreground gate stays the main window's own
    /// `i.focused`.
    ///
    /// Two sources, deliberately. `input_for` reads the child viewport's live
    /// `InputState` from out here — safe for a *flag* (never for events) — and
    /// is authoritative even on a frame the child did not paint. The latched
    /// flag from the child's own pass covers the reverse: a focus change egui
    /// has delivered to the child but not yet reflected in what the parent can
    /// read. Either one saying "focused" is enough; being wrong in that
    /// direction only means the hook passes keys through for one extra frame,
    /// while being wrong the other way double-sends every keystroke in it.
    fn second_window_focused(&self, ctx: &egui::Context) -> bool {
        if !self.second_window_visible() {
            return false;
        }
        // Two statements on purpose: the guard must be dropped before egui is
        // called, so this never holds the child's lock across an egui call —
        // the one shape that could deadlock against the child's own pass.
        let latched = self.stream1.lock().focused;
        latched || ctx.input_for(second_window::stream1_viewport_id(), |i| i.focused)
    }

    /// The second window's per-frame logic: push the capture gate down to the
    /// child and consume anything its last pass reported.
    ///
    /// Runs in `logic`, never in `ui`, so the mutex is only ever taken outside
    /// the parent's paint — the deferred callback takes the same lock, and
    /// holding it across a paint is the one way these two could deadlock.
    fn service_second_window(&mut self, ctx: &egui::Context) {
        if !self.second_window_visible() {
            return;
        }
        // Mirrored down rather than read up: the child's paint callback is a
        // plain `Fn` that cannot reach `ClientApp`. Its forwarders gate on both.
        let closed = {
            let mut shared = self.stream1.lock();
            shared.set_capturing(self.input.is_capturing());
            // `monitors.is_some()` is the proof this session negotiated
            // multi-monitor, and it is the gate on every tagged `EventOn` this
            // window sends — same gate `send_select_monitors` uses, for the
            // same reason: an old host's `decode_strict` reader errors on the
            // variant and takes the whole input stream down with it.
            shared.set_armed(self.monitors.is_some());
            std::mem::take(&mut shared.close_requested)
        };
        // Belt and braces alongside the flag the child latched: `input_for`
        // reads the child viewport's own `InputState` from out here, which is
        // safe for a *flag* but never for events — those have to be consumed
        // inside the child pass or they are read twice, or missed.
        let closed = closed
            || ctx.input_for(second_window::stream1_viewport_id(), |i| {
                i.viewport().close_requested()
            });
        if closed {
            tracing::info!("operator closed the second monitor window");
            self.close_second_window(true);
        }
    }

    /// Whether the "2nd monitor" toggle should appear at all: a live session
    /// that negotiated the feature, against a host with something to show on it.
    fn can_offer_second_window(&self) -> bool {
        self.state.is_live() && self.monitors.as_ref().is_some_and(|m| m.len() >= 2)
    }

    /// Send a mid-session `SelectMonitors`, but only on a session that actually
    /// negotiated the feature.
    ///
    /// The gate is `self.monitors.is_some()` — the arrival of a `MonitorList`
    /// is the *only* proof the `MULTI_MONITOR` bit came back mutual, and the UI
    /// is the only place that knows it. Sending one to a host that never echoed
    /// the bit would put a variant on the wire that its `decode_strict` control
    /// reader has no arm for.
    fn send_select_monitors(&mut self, ids: Vec<u8>) {
        if self.monitors.is_none() {
            tracing::debug!(
                ?ids,
                "SelectMonitors suppressed: this session never negotiated multi-monitor"
            );
            return;
        }
        tracing::info!(?ids, "re-selecting monitors mid-session");
        self.session
            .send_control(ControlMsg::SelectMonitors { ids });
    }

    /// Open (or re-open) the second window and ask the host for its stream.
    ///
    /// The host re-IDRs when a stream is added, and stream 1's own
    /// `KeyframeGate` starts out with no reference chain, so it simply waits for
    /// that IDR — and asks for one itself if it does not come.
    fn open_second_window(&mut self) {
        let Some(monitors) = self.monitors.clone() else {
            return;
        };
        // `Both` regardless of the persisted choice: this button *is* the
        // request for two windows. The persisted choice stays whatever the
        // connect-screen picker says, so it still governs the next connect.
        let resolved = monitors::resolve_selection(MonitorChoice::Both, &monitors);
        if resolved.degraded {
            self.notice = Some(ONE_MONITOR_NOTICE.to_string());
            return;
        }
        // Session intent, so the topology re-sends the host makes on any
        // display change cannot slam this window shut again.
        self.stream1_intent = SecondWindowIntent::Requested;
        self.stream1_window_open = true;
        self.send_select_monitors(resolved.ids);
    }

    /// Close the second window and drop everything it owned.
    ///
    /// `by_user` is the load-bearing distinction:
    ///
    /// * `true` — the operator closed it (title-bar X or the toolbar toggle).
    ///   The host is still encoding that monitor, so tell it to stop, and record
    ///   the intent so no later `MonitorList` can undo their decision.
    /// * `false` — the host stopped the stream (`StreamStopped`) or the
    ///   topology lost the monitor. Nothing to ask the host for, and the intent
    ///   is left alone: if that output comes back, its window comes back too.
    fn close_second_window(&mut self, by_user: bool) {
        if by_user {
            self.stream1_intent = SecondWindowIntent::Dismissed;
            // Drop the stream so the host stops encoding and sending a picture
            // nobody is looking at. `ids[0]` is whatever rides stream 0 under
            // the operator's persisted choice, so this narrows the session to
            // one stream without changing *which* monitor the main window
            // shows.
            let choice = self.effective_monitor_choice();
            let ids = self
                .monitors
                .as_ref()
                .map(|m| monitors::resolve_selection(choice, m).ids)
                .unwrap_or_else(|| vec![0]);
            self.send_select_monitors(ids.into_iter().take(1).collect());
        }
        self.stream1_window_open = false;
        self.stream1_video = None;
        self.stream1_monitor = None;
        // A window that goes away mid-drag leaves the host holding a button
        // that nothing left alive can lift — no more events will ever come from
        // that viewport. `ReleaseAll` is the only message that drops it, and it
        // is deliberately global (the host keeps held state on one injector),
        // so it is sent only when this window actually held something rather
        // than on every close, where it would also drop the main window's keys.
        let held = {
            let mut shared = self.stream1.lock();
            let held = shared.has_buttons_held();
            shared.reset(true);
            held
        };
        if held {
            tracing::info!("second window closed mid-drag — releasing held input");
            self.input.release_all();
        }
    }

    /// Drop every piece of second-window state because the session that owned
    /// it is over.
    ///
    /// Extends the three existing stream-0 teardown sites (`drain_session`'s
    /// non-live branch, `Bye`, and `disconnect`). `clear_slot` mirrors the
    /// asymmetry those sites already have: the `Bye` path deliberately leaves
    /// the pending frame alone.
    ///
    /// `monitors = None` is the important one — it re-arms the "did this
    /// session negotiate multi-monitor?" gate, so nothing is sent on a
    /// connection that has not proven it can take it. `stream1_intent` is reset
    /// too: a fresh connection should honour the persisted choice, not a
    /// decision made about the last one.
    fn reset_second_window_for_session_end(&mut self, clear_slot: bool) {
        self.stream1_window_open = false;
        self.stream1_intent = SecondWindowIntent::default();
        self.stream1_video = None;
        self.stream1_monitor = None;
        self.monitors = None;
        self.stream1.lock().reset(clear_slot);
    }

    /// Title for the second OS window, from whatever has actually been learned
    /// about that monitor.
    fn second_window_title(&self) -> String {
        let dims = self
            .stream1_video
            .map(|(w, h, _, _)| (w, h))
            .or_else(|| self.stream1_slot.remote_dims());
        let name = self.stream1_monitor.and_then(|id| {
            self.monitors
                .as_ref()?
                .iter()
                .find(|m| m.id == id)
                .map(|m| m.name.as_str())
        });
        second_window_title(name, dims)
    }

    /// Whether keys should keep reaching the host while DirectDesk is in the
    /// background: the persisted opt-in, or `--hold-capture` forcing it on for
    /// the run.
    fn effective_background_capture(&self) -> bool {
        // Touch has no hook, so "keep capturing in the background" has
        // nothing to keep: capture there simply follows the session.
        self.profile == UiProfile::Desktop
            && (self.config.capture_in_background || self.hold_capture)
    }

    /// Re-send `StartStream` on the live connection to apply the current
    /// preferred fps (and quality mode) without a wire change or a
    /// reconnect. Safe and sufficient because `StartStream` is idempotent
    /// host-side: it re-applies the quality mode (`BitrateAdaptor::set_mode`
    /// preserves `current_kbps`, so no bitrate reset), forces a keyframe, and
    /// elicits a fresh `VideoConfig`. Reusing it is what keeps this feature
    /// free of any wire change — an older host simply logs and ignores it.
    fn apply_preferred_fps(&mut self) {
        self.session.send_control(ControlMsg::StartStream {
            max_width: 3840,
            max_height: 2160,
            preferred_fps: self.config.preferred_fps,
            quality_mode: self.config.quality_mode,
        });
    }

    /// Runs first every frame: latch any capture loss the hook reported
    /// asynchronously, then service the release chord *globally* — in every
    /// view and every connection state, not just over a live video frame.
    fn reconcile_capture(&mut self, ctx: &egui::Context) {
        match self.input.poll_capture_loss() {
            Some(CaptureLoss::ChordRelease) => {
                self.user_released = true;
                self.notice = Some(released_notice());
            }
            Some(CaptureLoss::InstallError) => {
                // Latch here too: without it the auto re-arm retried a failing
                // install every single frame.
                self.user_released = true;
                let err = self.input.last_error().unwrap_or("unknown error");
                self.notice = Some(format!("Input capture unavailable: {err}"));
            }
            None => {}
        }

        // Two windows, two `InputState`s: the chord typed into the second
        // monitor's window never appears in this one's events, so the child
        // detects it with the same pure predicate and latches a one-shot for us
        // to consume here. Both paths land on the single toggle below, so the
        // chord means the same thing from either window and can never toggle
        // twice for one press.
        let child_chord = self.stream1.lock().take_chord_fired();
        let chord = child_chord || ctx.input(|i| chord_pressed(&i.events));
        if !chord {
            return;
        }
        // The chord toggles: release if we hold the keyboard, otherwise take it
        // back (which also clears the latch).
        if self.input.is_capturing() {
            self.input.stop_capture();
            self.user_released = true;
            self.notice = Some(released_notice());
        } else {
            self.input.start_capture();
            self.user_released = false;
            self.notice = Some("Input captured".into());
        }
    }

    /// Capture must never survive losing focus, minimizing, or closing.
    ///
    /// `focused` is the **any-window** answer: with a second monitor on screen,
    /// clicking into its window is not "DirectDesk lost focus", and dropping
    /// capture there would make the keyboard stop working the moment the
    /// operator looked at the other monitor. `minimized` and `closing` stay the
    /// *main* window's — closing it ends the session, and its close request is
    /// what persists the config.
    fn enforce_capture_invariants(&mut self, ctx: &egui::Context, focused: bool) {
        if !self.input.is_capturing() {
            return;
        }
        let (minimized, closing) = ctx.input(|i| {
            (
                i.viewport().minimized.unwrap_or(false),
                i.viewport().close_requested(),
            )
        });
        // With background capture on we deliberately keep the hook installed
        // across focus/minimize changes — that is the whole point of the
        // setting, and the hook decides per key whether to swallow. A window
        // close still releases, so we never leave keys stuck on exit.
        if closing || (!self.effective_background_capture() && (!focused || minimized)) {
            tracing::info!(focused, minimized, closing, "releasing capture");
            self.input.stop_capture();
            self.notice = Some("Input released (window lost focus)".into());
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            let (color, text) = match &self.state {
                ConnectionState::Connected => (egui::Color32::from_rgb(90, 200, 120), "Connected"),
                ConnectionState::Connecting | ConnectionState::Authenticating => {
                    (egui::Color32::from_rgb(230, 200, 90), self.state.label())
                }
                ConnectionState::Failed(_) => {
                    (egui::Color32::from_rgb(220, 90, 90), self.state.label())
                }
                ConnectionState::Disconnected => (egui::Color32::GRAY, "Disconnected"),
            };
            ui.colored_label(color, egui::RichText::new(text).strong());

            ui.separator();
            ui.label("ROUTE");
            ui.colored_label(
                diagnostics::route_color(self.route),
                egui::RichText::new(diagnostics::route_text(self.route))
                    .strong()
                    .size(15.0),
            );

            // Disconnect is offered whenever a transport driver is (or may be)
            // running, so the user can cancel a slow connect or a live session
            // and return to the connect screen without restarting.
            let active = self
                .supervisor
                .as_ref()
                .is_some_and(ConnectSupervisor::is_connected)
                || matches!(
                    self.state,
                    ConnectionState::Connecting
                        | ConnectionState::Authenticating
                        | ConnectionState::Connected
                );
            if active && self.mode != SourceMode::LoopbackDemo {
                ui.separator();
                if ui.button("Disconnect").clicked() {
                    self.disconnect();
                }
            }

            ui.separator();
            let capturing = self.input.is_capturing();
            let label = if capturing {
                format!("Release input ({RELEASE_CHORD})")
            } else {
                "Capture input".into()
            };
            let hover = format!(
                "Routes the keyboard (including Win and Alt+Tab) to the host.\n\
                 Release with {RELEASE_CHORD}, or by leaving the window.\n\
                 The mouse is forwarded whenever it is over the remote screen."
            );
            if ui
                .add(egui::Button::new(label).selected(capturing))
                .on_hover_text(hover)
                .clicked()
            {
                // Explicit, so a release actually sticks: the latch is what
                // stops the auto re-arm undoing it on the next frame.
                if capturing {
                    self.input.stop_capture();
                    self.user_released = true;
                } else {
                    self.input.start_capture();
                    self.user_released = false;
                }
            }
            if self.user_released {
                ui.weak("released — keys stay local");
            }

            if ui
                .button(if self.fullscreen {
                    "Exit fullscreen"
                } else {
                    "Fullscreen"
                })
                .clicked()
            {
                self.fullscreen = !self.fullscreen;
                ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
            }

            // Shown only where it can actually do something: a session that
            // negotiated the feature (`monitors.is_some()`) against a host that
            // really has a second output. Everywhere else it would be a button
            // whose only possible outcome is an apology.
            if self.can_offer_second_window() {
                ui.separator();
                let open = self.stream1_window_open;
                if ui
                    .add(egui::Button::new("2nd monitor").selected(open))
                    .on_hover_text(
                        "Show the host's second monitor in its own window.\n\
                         Closing that window stops the host encoding it.",
                    )
                    .clicked()
                {
                    if open {
                        self.close_second_window(true);
                    } else {
                        self.open_second_window();
                    }
                }
            }

            let host_dims = self.toolbar_scaling(ui, ctx);

            // The diagnostic that answers "am I actually at a crisp scale?" —
            // unmissable rather than tucked into the diagnostics panel, since
            // it's the signal for whether any encoder work even matters here.
            if let Some((w, h)) = host_dims {
                let scale = self.presenter.last_scale();
                let color = if is_exact_scale(scale) {
                    egui::Color32::from_rgb(90, 200, 120)
                } else {
                    egui::Color32::from_rgb(230, 170, 60)
                };
                ui.separator();
                ui.colored_label(
                    color,
                    egui::RichText::new(format!("{w}x{h} @ {}", describe_scale(scale))).strong(),
                )
                .on_hover_text(
                    "The host's resolution and the scale the video is currently drawn at. \
                     Anything other than an exact 1:1/2x/3x scale means the video is being \
                     resampled, which is what makes small text blurry.",
                );
            }

            ui.toggle_value(&mut self.show_diagnostics, "Diagnostics");

            // Lowering fps at a fixed bitrate puts more bits in each frame,
            // sharpening still text. 0 means "Auto" — the host decides, which
            // is today's behaviour.
            ui.separator();
            ui.label("FPS");
            let current_fps = self.config.preferred_fps;
            let mut chosen_fps = current_fps;
            let combo = egui::ComboBox::from_id_salt("preferred_fps")
                .selected_text(fps_label(current_fps))
                .show_ui(ui, |ui| {
                    for fps in FPS_CHOICES {
                        if ui
                            .selectable_label(current_fps == fps, fps_label(fps))
                            .clicked()
                        {
                            chosen_fps = fps;
                        }
                    }
                });
            combo.response.on_hover_text(
                "Fewer frames per second at the same bitrate means more bits in each \
                 frame — sharper still text over a slow link. Auto follows the host.",
            );
            if chosen_fps != current_fps {
                self.config.preferred_fps = chosen_fps;
                self.config.save();
                if let Some(supervisor) = self.supervisor.as_mut() {
                    supervisor.set_preferred_fps(chosen_fps);
                }
                self.apply_preferred_fps();
            }
            if let Some(host_fps) = self.host_reported_fps {
                ui.weak(format!("(host: {host_fps} fps)"));
            }

            // Security-relevant opt-in, so it says plainly what it does. Off
            // (the default) means switching to a local app gives that app the
            // keyboard instead of shipping every keystroke over the wire.
            const BACKGROUND_HOVER: &str =
                "Keep sending keys to the host while DirectDesk is in the background.\n\
                 Off: your keyboard stays local when you switch apps.";
            if self.hold_capture {
                ui.add_enabled(
                    false,
                    egui::Button::new("Background capture").selected(true),
                )
                .on_disabled_hover_text(format!(
                    "{BACKGROUND_HOVER}\nForced on by --hold-capture."
                ));
            } else {
                ui.toggle_value(&mut self.config.capture_in_background, "Background capture")
                    .on_hover_text(BACKGROUND_HOVER);
            }

            if self.mode == SourceMode::LoopbackDemo {
                ui.separator();
                ui.colored_label(
                    egui::Color32::from_rgb(230, 170, 60),
                    egui::RichText::new("LOOPBACK DEMO").strong(),
                );
            }

            if let Some(err) = self.input.last_error() {
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err);
            } else if let Some(note) = &self.notice {
                ui.separator();
                ui.weak(note);
            }
        });
    }

    /// Draws the integer-scale controls (1:1 / 2x buttons and the auto-snap
    /// combo) and performs any pending auto-snap resize. All three widgets
    /// derive their fit from the same `max_scale`, computed once here, so
    /// they can never disagree with each other. Returns the host's current
    /// video dimensions, in physical pixels, for the scale readout drawn
    /// immediately after this call in `toolbar`.
    fn toolbar_scaling(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> Option<(u32, u32)> {
        // Host dims come from the most recent VideoConfig, falling back to
        // whatever the presenter has actually decoded — so this works even
        // before the first frame arrives.
        let host_dims = self
            .host_video
            .map(|(w, h, _, _)| (w, h))
            .or_else(|| self.presenter.frame_size());
        let ppp = ctx.pixels_per_point();
        // The question is whether the *monitor* can hold the host desktop
        // 1:1, not whether the current window already does — so measure
        // against the screen, not the viewport. `monitor_size` is already in
        // egui points; the host dimensions are physical pixels. When the
        // platform will not tell us the monitor size, let the user try.
        let monitor = ctx.input(|i| i.viewport().monitor_size);
        // The biggest integer scale the monitor can hold — the buttons
        // below and the auto-snap preference all derive their fit from
        // this one number, so they can never disagree with each other.
        let max_scale = host_dims
            .map(|dims| largest_fitting_scale(dims, monitor, ppp, self.chrome_points))
            .unwrap_or(0);

        // A pending auto-snap (opted into via the combo below) fires the
        // moment we have both the host's dims and a fit — same guard the
        // buttons themselves are enabled under, so auto and manual can't
        // disagree.
        if self.pending_auto_snap {
            self.pending_auto_snap = false;
            if let Some((w, h)) = host_dims {
                if self.auto_snap_scale != 0 && self.auto_snap_scale <= max_scale {
                    self.resize_to_integer_scale(ctx, w, h, ppp, self.auto_snap_scale);
                }
            }
        }

        let one_to_one = ui.add_enabled(
            host_dims.is_some() && max_scale >= 1,
            egui::Button::new("1:1"),
        );
        if host_dims.is_none() {
            one_to_one.on_disabled_hover_text(
                "Waiting for the host's video format before this can size the window.",
            );
        } else if max_scale < 1 {
            one_to_one.on_disabled_hover_text(
                "Your screen is too small to show the host desktop at one screen pixel \
                 per host pixel without rescaling.",
            );
        } else if one_to_one
            .on_hover_text(
                "Size the window so the host desktop renders at exactly one screen \
                 pixel per host pixel — no rescaling, sharpest text.",
            )
            .clicked()
        {
            if let Some((w, h)) = host_dims {
                self.resize_to_integer_scale(ctx, w, h, ppp, 1);
            }
        }

        let two_x = ui.add_enabled(
            host_dims.is_some() && max_scale >= 2,
            egui::Button::new("2x"),
        );
        if host_dims.is_none() {
            two_x.on_disabled_hover_text(
                "Waiting for the host's video format before this can size the window.",
            );
        } else if max_scale < 2 {
            two_x.on_disabled_hover_text(
                "Your screen is too small to show the host desktop doubled (every host \
                 pixel drawn as a 2x2 block) without rescaling.",
            );
        } else if two_x
            .on_hover_text(
                "Size the window so every host pixel is drawn as an exact 2x2 block of \
                 screen pixels — twice the size of 1:1, still perfectly sharp, unlike \
                 dragging the window to an arbitrary size, which blurs.",
            )
            .clicked()
        {
            if let Some((w, h)) = host_dims {
                self.resize_to_integer_scale(ctx, w, h, ppp, 2);
            }
        }

        ui.label("Auto-snap");
        let current_snap = self.auto_snap_scale;
        let mut chosen_snap = current_snap;
        let snap_combo = egui::ComboBox::from_id_salt("auto_snap_scale")
            .selected_text(auto_snap_label(current_snap))
            .show_ui(ui, |ui| {
                for scale in [0, 1, 2] {
                    if ui
                        .selectable_label(current_snap == scale, auto_snap_label(scale))
                        .clicked()
                    {
                        chosen_snap = scale;
                    }
                }
            });
        snap_combo.response.on_hover_text(
            "When set to 1:1 or 2x, snap the window to that scale automatically the next \
             time a host connects. Persisted between launches. Off never resizes the \
             window without being asked.",
        );
        if chosen_snap != current_snap {
            self.auto_snap_scale = chosen_snap;
        }

        host_dims
    }

    fn connect_screen(&mut self, ui: &mut egui::Ui) {
        let touch = self.is_touch();
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.heading("DirectDesk");
            ui.add_space(4.0);
            ui.weak("Connect to a host running DirectDesk.");
            ui.add_space(16.0);

            egui::Grid::new("connect_form")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Host");
                    let r = ui.add(
                        fit_text_edit(touch, egui::TextEdit::singleline(&mut self.address_input))
                            .hint_text("hostname or IP")
                            .desired_width(240.0),
                    );
                    self.note_text_edit(&r);
                    ui.end_row();

                    ui.label("UDP port");
                    let r = ui.add(
                        fit_text_edit(touch, egui::TextEdit::singleline(&mut self.udp_port_input))
                            .desired_width(90.0),
                    );
                    self.note_text_edit(&r);
                    ui.end_row();

                    ui.label("Display name");
                    let r = ui.add(
                        fit_text_edit(touch, egui::TextEdit::singleline(&mut self.name_input))
                            .hint_text("shown on the host")
                            .desired_width(240.0),
                    );
                    self.note_text_edit(&r);
                    ui.end_row();

                    ui.label("Pairing code");
                    let r = ui.add(
                        fit_text_edit(touch, egui::TextEdit::singleline(&mut self.code_input))
                            .hint_text("8 digits — first time only")
                            .desired_width(240.0),
                    );
                    self.note_text_edit(&r);
                    ui.end_row();

                    ui.label("Quality");
                    self.quality_combo(ui);
                    ui.end_row();

                    // Hidden where connects never offer multi-monitor (the
                    // touch preset): no `MonitorList` can arrive there, so any
                    // choice but Primary could only end in a false "host too
                    // old" notice.
                    if !self.monitor_picker_shown() {
                        return;
                    }
                    ui.label("Monitors");
                    let current_choice = self.config.monitor_choice;
                    let mut chosen_choice = current_choice;
                    // Only trust the cache when it was written for exactly the
                    // host currently typed into the form — never a stale cache
                    // from a previous host reused by accident.
                    let cache_matches_host = !self.config.cached_monitor_host.is_empty()
                        && self.config.cached_monitor_host == self.address_input.trim();
                    let selected_label = monitors::picker_label(
                        current_choice,
                        &self.config.cached_monitors,
                        cache_matches_host,
                    );
                    egui::ComboBox::from_id_salt("monitor_choice")
                        .selected_text(selected_label)
                        .show_ui(ui, |ui| {
                            for choice in [
                                MonitorChoice::Primary,
                                MonitorChoice::Second,
                                MonitorChoice::Both,
                            ] {
                                let option_label = monitors::picker_label(
                                    choice,
                                    &self.config.cached_monitors,
                                    cache_matches_host,
                                );
                                if ui
                                    .selectable_label(current_choice == choice, option_label)
                                    .clicked()
                                {
                                    chosen_choice = choice;
                                }
                            }
                        });
                    if chosen_choice != current_choice {
                        self.config.monitor_choice = chosen_choice;
                    }
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.weak("Enter the code shown on the host's 'Pair new device' window.");
            ui.weak("Leave the code blank to reconnect to a host you have paired before.");
            if self.monitor_picker_shown() {
                ui.weak(
                    "Monitors: applied if the host reports more than one — otherwise primary only.",
                );
            }

            ui.add_space(12.0);
            // The button names the action it will take, so pairing vs. reconnect
            // is never a surprise: a code in the box means "pair, then connect".
            let pairing = connect_form::is_pairing_mode(&self.code_input);
            let label = if pairing {
                "Pair && Connect"
            } else {
                "Connect"
            };
            let can_connect = !self.address_input.trim().is_empty();
            if ui
                .add_enabled(can_connect, egui::Button::new(label))
                .clicked()
            {
                self.begin_connect();
            }

            ui.add_space(16.0);
            if self.supervisor.is_none() {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 170, 60),
                    "No transport is available in this build — the secret store could \
                     not be opened, so Connect is disabled.",
                );
                ui.weak("Run with --loopback-demo to exercise the render and input path.");
            }
            if let Some(err) = &self.form_error {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err.clone());
            }
        });
    }

    /// The connect form's quality picker (both profiles).
    fn quality_combo(&mut self, ui: &mut egui::Ui) {
        let current = self.config.quality_mode;
        let mut chosen = current;
        egui::ComboBox::from_id_salt("quality")
            .selected_text(current.label())
            .show_ui(ui, |ui| {
                for mode in [
                    QualityMode::TextDesktop,
                    QualityMode::Balanced,
                    QualityMode::Motion,
                    QualityMode::LowBandwidth,
                ] {
                    if ui.selectable_label(current == mode, mode.label()).clicked() {
                        chosen = mode;
                    }
                }
            });
        if chosen != current {
            self.config.quality_mode = chosen;
            self.session.send_control(ControlMsg::QualityChange(chosen));
        }
    }

    /// Shown while the transport driver is racing routes and running the
    /// handshake: a spinner and the live lifecycle label, plus a way out.
    fn connecting_view(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(120.0);
            ui.add(egui::Spinner::new().size(48.0));
            ui.add_space(16.0);
            ui.heading(self.state.label());
            ui.weak(format!("Host {}", self.config.host_address));
            // Touch: the attempt is the automatic one after a resume.
            if let Some(status) = self.bg_resume.status().filter(|_| self.is_touch()) {
                ui.weak(status);
            }
            ui.add_space(20.0);
            if ui.button("Cancel").clicked() {
                self.disconnect();
            }
        });
    }

    /// Shown on a failed / lost connection: the reason and a Back button that
    /// returns to the connect form without restarting the app.
    fn failed_view(&mut self, ui: &mut egui::Ui, reason: String) {
        ui.vertical_centered(|ui| {
            ui.add_space(120.0);
            ui.colored_label(
                egui::Color32::from_rgb(220, 90, 90),
                egui::RichText::new("Connection failed").heading(),
            );
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), reason);
            ui.add_space(20.0);
            if ui.button("Back").clicked() {
                self.disconnect();
            }
        });
    }

    /// Validate the form, remember the reusable fields (never the code), and ask
    /// the supervisor to drive `net::run_client`. The transport reports every
    /// lifecycle state back through `state_rx`, so we set only an optimistic
    /// `Connecting` here for instant feedback.
    fn begin_connect(&mut self) {
        let request = match connect_form::build_request(connect_form::FormInputs {
            host: &self.address_input,
            udp_port: &self.udp_port_input,
            pairing_code: &self.code_input,
            display_name: &self.name_input,
            quality: self.config.quality_mode,
            default_udp_port: self.config.udp_port,
        }) {
            Ok(r) => r,
            Err(e) => {
                self.form_error = Some(e);
                return;
            }
        };
        self.form_error = None;

        // Persist the reusable fields — host, ports, name — but never the code.
        self.config.host_address = request.host.clone();
        self.config.udp_port = request.udp_port;
        self.config.display_name = request.display_name.clone();
        self.address_input = request.host.clone();
        self.udp_port_input = request.udp_port.to_string();
        self.config.save();

        let picker_shown = self.monitor_picker_shown();
        let Some(supervisor) = self.supervisor.as_mut() else {
            self.form_error =
                Some("no transport is available — cannot connect in this build".into());
            return;
        };

        tracing::info!(
            host = %request.host,
            udp = request.udp_port,
            pairing = request.pairing_code.is_some(),
            "connect requested"
        );
        // Seeded once at startup (`ClientApp::new`), but the picker can change
        // the choice afterwards without a reconnect happening in between — push
        // the current config value so this connect carries whatever is showing
        // in the combo right now, not a stale one from launch. A hidden picker
        // pushes nothing: its caps never offer multi-monitor anyway.
        if picker_shown {
            supervisor.set_monitor_choice(self.config.monitor_choice);
        }
        supervisor.connect(request);

        // The route stays unknown until the transport reports one; the driver
        // owns every state from here (Connecting → Authenticating → Connected).
        self.route = None;
        self.state = ConnectionState::Connecting;
        // A single-use code must not linger in the box for a second attempt.
        self.code_input.clear();
    }

    /// Cancel the active connection (or attempt) and return to the connect form.
    fn disconnect(&mut self) {
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.disconnect();
        }
        self.reset_after_disconnect();
    }

    /// The UI half of [`disconnect`](Self::disconnect): everything but telling
    /// the supervisor. The touch reconnect-after-background uses it alone, so
    /// the `connect` that follows *aborts* whatever is left of the old driver
    /// rather than detaching it.
    fn reset_after_disconnect(&mut self) {
        // Touch: lift fingers and keys before capture (and with it the
        // ability to send their releases) goes.
        self.touch_session_end();
        self.input.stop_capture();
        self.presenter.reset();
        self.slot.clear();
        self.tiles.clear();
        self.route = None;
        self.elevation = None;
        self.state = ConnectionState::Disconnected;
        // Forget the host's dims too: "auto 1:1" is meant to fire again on the
        // *next* connect's first `VideoConfig`, and a stale value here would
        // otherwise make that a one-time-per-process behaviour.
        self.host_video = None;
        self.pending_auto_snap = false;
        // No `SelectMonitors` on this path: the connection is being torn down,
        // so there is nothing left to tell the host on.
        self.reset_second_window_for_session_end(true);
    }

    /// Resize the window so the host video renders at exactly `scale` screen
    /// pixels per host pixel (1 = the original 1:1 behaviour, 2 = pixel
    /// doubling, ...). Shared by the 1:1/2x buttons and the auto-snap
    /// preference so those paths can never drift apart.
    fn resize_to_integer_scale(
        &mut self,
        ctx: &egui::Context,
        w: u32,
        h: u32,
        ppp: f32,
        scale: u32,
    ) {
        if self.fullscreen {
            // A resize while fullscreen does nothing: drop out first.
            self.fullscreen = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
        }
        // InnerSize wants egui points; the host dims are physical pixels,
        // hence the `* scale / ppp`. Add the measured chrome back in so the
        // *video*, not the whole window, lands at the requested scale.
        let scale = scale as f32;
        let size = egui::vec2(
            w as f32 * scale / ppp,
            h as f32 * scale / ppp + self.chrome_points,
        );
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
    }

    fn streaming_view(&mut self, ui: &mut egui::Ui) {
        let (viewport, view) = self.presenter.draw(ui);

        // Measured, not hardcoded, so it survives style and font changes: the
        // gap between the full window and the video viewport is whatever the
        // toolbar (and any other chrome) actually took up this frame.
        self.chrome_points = ui.ctx().content_rect().height() - viewport.height();

        let Some(view) = view else {
            ui.painter_at(viewport).text(
                viewport.center(),
                egui::Align2::CENTER_CENTER,
                "Waiting for the first frame…",
                egui::FontId::proportional(16.0),
                egui::Color32::GRAY,
            );
            return;
        };

        let (events, focused) = ui.ctx().input(|i| (i.events.clone(), i.focused));
        if focused {
            // Both paths live in `input_capture` now, shared with the second
            // window's forwarders so the two windows cannot drift apart on the
            // letterbox gate, the drag latch, or the chord filter. Keys are
            // gated on capture inside; pointer events never were.
            self.input
                .forward_pointer_events(&events, viewport, &view, self.pointer);
            self.input.forward_key_events(&events);
            // While keys stream to the host, no egui widget may keep keyboard
            // focus: a toolbar button focused by an earlier click would be
            // re-activated by the next forwarded Space/Enter (observed as the
            // session disconnecting itself mid-typing).
            if self.input.is_capturing() {
                ui.ctx().memory_mut(|mem| {
                    if let Some(id) = mem.focused() {
                        mem.surrender_focus(id);
                    }
                });
            }
        }
        self.input.pump();
    }

    // -----------------------------------------------------------------------
    // Touch profile
    // -----------------------------------------------------------------------

    /// The touch streaming view: video (zoomed/panned by the gesture layer)
    /// above, the on-screen keyboard (when toggled on) in a strip below.
    fn touch_streaming_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let now = Instant::now();
        self.set_keyboard_visible(self.osk_streaming);

        let full = ui.available_rect_before_wrap();
        let (video_area, keyboard_area) =
            split_for_keyboard(full, self.keyboard.desired_height(ctx.content_rect()));
        let (zoom, focus) = (self.touch.zoom(), self.touch.focus());
        let (viewport, view) = ui
            .scope_builder(egui::UiBuilder::new().max_rect(video_area), |ui| {
                self.presenter.draw_zoomed(ui, zoom, focus)
            })
            .inner;
        self.chrome_points = ctx.content_rect().height() - viewport.height();

        if let Some(area) = keyboard_area {
            let out = ui
                .scope_builder(egui::UiBuilder::new().max_rect(area), |ui| {
                    self.keyboard.show(ui, KeyboardTarget::Remote, now)
                })
                .inner;
            self.deliver_keyboard(out);
        }

        let Some(view) = view else {
            ui.painter_at(viewport).text(
                viewport.center(),
                egui::Align2::CENTER_CENTER,
                "Waiting for the first frame…",
                egui::FontId::proportional(16.0),
                egui::Color32::GRAY,
            );
            self.touch.reset(self.input.pointer_mut());
            self.input.pump();
            return;
        };

        if self.touch_focus.is_focused() {
            // Local keyboard events this app injected are not hardware keys.
            let events = ctx.input(|i| without_injected(&i.events, &self.injected_events));
            // Fingers that started on the toolbar (its rect is this frame's:
            // it is drawn before this view) or on any other overlay layer —
            // a window, the elevation banner — belong to egui, not the video.
            let toolbar = self.touch_toolbar_rect;
            let touches = self.touch_filter.filter(&events, |p| {
                toolbar.is_some_and(|r| r.contains(p))
                    || ctx
                        .layer_id_at(p)
                        .is_some_and(|l| l.order != egui::Order::Background)
            });
            self.touch
                .frame(ui, &touches, viewport, &view, self.input.pointer_mut());
            // Bluetooth / USB keyboards. Back was stripped in `raw_input_hook`.
            self.input.forward_key_events(&events);
            if self.input.is_capturing() {
                ctx.memory_mut(|mem| {
                    if let Some(id) = mem.focused() {
                        mem.surrender_focus(id);
                    }
                });
            }
        } else {
            // A real focus loss already released everything (`logic`); keep
            // the cursor on screen meanwhile.
            self.touch.paint_cursor(&ui.painter_at(viewport), &view);
        }
        self.input.pump();
    }

    /// The touch connect screen, laid out for a phone with the on-screen
    /// keyboard (target Local) up whenever a field has focus: a compact form
    /// in a scroll area that ends at the keyboard (the focused field is
    /// scrolled into it), and a sticky action row between the two that keeps
    /// Pair & Connect reachable.
    fn touch_connect_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let now = Instant::now();

        let focused = ctx.memory(|m| m.focused());
        let text_focus = focused.filter(|id| self.connect_text_edits.iter().any(|(t, _)| t == id));
        if text_focus.is_some() && text_focus != self.connect_focus {
            self.connect_scroll_pending = true;
        }
        self.connect_focus = text_focus;
        self.set_keyboard_visible(text_focus.is_some());

        let full = ui.available_rect_before_wrap();
        let (form_area, keyboard_area) =
            split_for_keyboard(full, self.keyboard.desired_height(ctx.content_rect()));
        let (scroll_area, action_area) = split_action_row(form_area, ACTION_ROW_PTS);
        self.connect_text_edits.clear();
        let mut submit = false;
        ui.scope_builder(egui::UiBuilder::new().max_rect(scroll_area), |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| submit |= self.touch_connect_form(ui));
        });
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(action_area)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| submit |= self.touch_connect_actions(ui),
        );
        if let Some(area) = keyboard_area {
            let out = ui
                .scope_builder(egui::UiBuilder::new().max_rect(area), |ui| {
                    self.keyboard.show(ui, KeyboardTarget::Local, now)
                })
                .inner;
            self.deliver_keyboard(out);
        }

        // Focus is never surrendered by egui in Touch (see `new`), so a tap
        // that is neither on the keyboard nor on a field drops it here — the
        // keyboard goes with it on the next frame.
        if let Some(id) = text_focus {
            let click = ctx.input(|i| {
                i.pointer
                    .any_click()
                    .then(|| i.pointer.interact_pos())
                    .flatten()
            });
            let fields: Vec<egui::Rect> = self.connect_text_edits.iter().map(|(_, r)| *r).collect();
            if click.is_some_and(|p| click_dismisses_text_focus(p, keyboard_area, &fields)) {
                ctx.memory_mut(|m| m.surrender_focus(id));
            }
        }

        if submit {
            self.begin_connect();
        }
    }

    /// The touch connect form (inside the scroll area): tight rows, the
    /// pairing code right under the host, the UDP port behind "Advanced".
    /// Returns true when Enter in the host or code field asked to connect.
    fn touch_connect_form(&mut self, ui: &mut egui::Ui) -> bool {
        const FIELD_W: f32 = 300.0;
        let mut submit = false;
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.vertical_centered(|ui| {
            ui.add_space(4.0);
            ui.heading("DirectDesk");
            ui.add_space(2.0);
            egui::Grid::new("touch_connect_form")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Host");
                    let r = ui.add(
                        fit_text_edit(true, egui::TextEdit::singleline(&mut self.address_input))
                            .hint_text("hostname or IP")
                            .desired_width(FIELD_W),
                    );
                    submit |= self.touch_field(&r, connect_form::FormField::Host);
                    ui.end_row();

                    // Digits, spaces and dashes, as on desktop: the code is
                    // normalised by `connect_form` at connect time.
                    ui.label("Pairing code");
                    let r = ui.add(
                        fit_text_edit(true, egui::TextEdit::singleline(&mut self.code_input))
                            .hint_text("8 digits — first time only")
                            .desired_width(FIELD_W),
                    );
                    submit |= self.touch_field(&r, connect_form::FormField::PairingCode);
                    ui.end_row();

                    ui.label("Display name");
                    let r = ui.add(
                        fit_text_edit(true, egui::TextEdit::singleline(&mut self.name_input))
                            .hint_text("shown on the host")
                            .desired_width(FIELD_W),
                    );
                    submit |= self.touch_field(&r, connect_form::FormField::DisplayName);
                    ui.end_row();

                    ui.label("Quality");
                    self.quality_combo(ui);
                    ui.end_row();

                    ui.toggle_value(&mut self.touch_advanced_open, "Advanced");
                    ui.end_row();
                    if self.touch_advanced_open {
                        ui.label("UDP port");
                        let r = ui.add(
                            fit_text_edit(
                                true,
                                egui::TextEdit::singleline(&mut self.udp_port_input),
                            )
                            .desired_width(90.0),
                        );
                        submit |= self.touch_field(&r, connect_form::FormField::UdpPort);
                        ui.end_row();
                    }
                });
            ui.add_space(2.0);
            ui.weak("Pairing code: from the host's 'Pair new device' window. Blank = reconnect.");
            if self.supervisor.is_none() {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 170, 60),
                    "No transport in this build (secret store unavailable) — Connect is disabled.",
                );
            }
            ui.add_space(4.0);
        });
        submit
    }

    /// One touch form field's bookkeeping; true when Enter in it submits.
    fn touch_field(&mut self, r: &egui::Response, field: connect_form::FormField) -> bool {
        self.note_text_edit(r);
        // A singleline `TextEdit` gives up focus on Enter (hardware or
        // on-screen keyboard), which is how egui reports "done".
        connect_form::enter_submits(field)
            && r.lost_focus()
            && r.ctx.input(|i| i.key_pressed(egui::Key::Enter))
    }

    /// The sticky action row (right-to-left): Pair & Connect, then the form
    /// error in whatever room is left. Returns true when the button was hit.
    fn touch_connect_actions(&mut self, ui: &mut egui::Ui) -> bool {
        let rect = ui.max_rect();
        ui.painter().hline(
            rect.x_range(),
            rect.top(),
            ui.visuals().widgets.noninteractive.bg_stroke,
        );
        ui.add_space(12.0);
        let label = if connect_form::is_pairing_mode(&self.code_input) {
            "Pair & Connect"
        } else {
            "Connect"
        };
        let can_connect = !self.address_input.trim().is_empty();
        let clicked = ui
            .add_enabled(
                can_connect,
                egui::Button::new(egui::RichText::new(label).strong())
                    .min_size(egui::vec2(TOUCH_TARGET_PTS * 4.0, TOUCH_TARGET_PTS)),
            )
            .clicked();
        ui.add_space(8.0);
        if let Some(err) = &self.form_error {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(err.as_str()).color(egui::Color32::from_rgb(220, 90, 90)),
                )
                .truncate(),
            );
        }
        clicked
    }

    /// Touch, back from the background while the watchdog is still winding
    /// the old session down: the reconnect follows on its own.
    fn touch_resuming_view(&mut self, ui: &mut egui::Ui, status: &str) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.add(egui::Spinner::new().size(36.0));
            ui.add_space(12.0);
            ui.heading(status);
            ui.weak(format!("Host {}", self.config.host_address));
            ui.add_space(16.0);
            if ui
                .add(
                    egui::Button::new("Cancel")
                        .min_size(egui::vec2(TOUCH_TARGET_PTS * 2.5, TOUCH_TARGET_PTS)),
                )
                .clicked()
            {
                self.bg_resume.cancel();
            }
        });
    }

    /// Touch, once per frame (in `logic`, after the drain): stamp the
    /// heartbeat, act on the watchdog's report, and keep frames coming
    /// while a driver runs so a stale heartbeat really means "no window".
    fn touch_background(&mut self, ctx: &egui::Context, now: Instant) {
        let Some(bg) = &self.background else {
            return;
        };
        bg.shared.beat(now);
        let report = bg.shared.take_report();
        let driver_running = bg.driver.is_running();
        let connecting = matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Authenticating
        );
        if self.bg_resume.on_frame(report, connecting) == ResumeAction::Reconnect {
            tracing::info!(
                host = %self.address_input.trim(),
                "touch: back from the background after the watchdog ended the session \
                 — reconnecting once with the saved pairing"
            );
            // The supervisor still holds the stopped driver: `begin_connect`
            // aborts what is left of it. A code is single-use and was
            // consumed by the original connect; reconnect authenticates.
            self.reset_after_disconnect();
            self.code_input.clear();
            self.begin_connect();
            if self.state != ConnectionState::Connecting {
                // Could not even start (no transport, form invalid): the
                // form shows why.
                self.bg_resume.cancel();
            }
        }
        if self.bg_resume.status().is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if driver_running {
            ctx.request_repaint_after(HEARTBEAT_REPAINT);
        }
    }

    /// Connect-screen bookkeeping for one text field (Touch only): remember it
    /// for the keyboard/dismiss logic and scroll it into view once the
    /// keyboard has taken the bottom of the screen.
    fn note_text_edit(&mut self, r: &egui::Response) {
        if !self.is_touch() {
            return;
        }
        self.connect_text_edits.push((r.id, r.rect));
        if self.connect_scroll_pending && r.has_focus() {
            self.connect_scroll_pending = false;
            r.scroll_to_me(Some(egui::Align::Center));
        }
    }

    /// Show or hide the on-screen keyboard; hiding releases whatever it held.
    fn set_keyboard_visible(&mut self, visible: bool) {
        if self.keyboard.is_visible() == visible {
            return;
        }
        let out = self.keyboard.set_visible(visible);
        self.deliver_keyboard(out);
        if visible && self.state.is_live() {
            // The video viewport is about to shrink under any finger that is
            // down: end the gesture cleanly rather than mid-drag.
            self.touch.reset(self.input.pointer_mut());
        }
    }

    /// Strokes go to the host (dropped by `send_key` unless capture is on);
    /// local events wait for the next frame's `raw_input_hook`.
    fn deliver_keyboard(&mut self, out: KeyboardOutput) {
        for s in out.strokes {
            self.input.send_key(s.scan_code, s.extended, s.down);
        }
        self.pending_local_events.extend(out.events);
    }

    /// Lift everything the touch path holds on the host: on-screen keys and
    /// modifiers, and any gesture button. Call while capture is still on.
    fn touch_release_input(&mut self) {
        if !self.is_touch() {
            return;
        }
        let out = self.keyboard.release_all_output();
        self.deliver_keyboard(out);
        self.touch.reset(self.input.pointer_mut());
        self.touch_filter.clear();
    }

    /// Touch-side teardown at every session-end site (`drain_session`'s
    /// non-live branch, `Bye`, `disconnect`), before capture stops.
    fn touch_session_end(&mut self) {
        if !self.is_touch() {
            return;
        }
        self.osk_streaming = false;
        self.set_keyboard_visible(false);
        self.touch_release_input();
        self.touch.reset_view();
        self.touch_toolbar.hide();
        // No capture toggle on a phone: a chord release (hardware keyboard)
        // lasts for the session it was made in, not forever.
        self.user_released = false;
    }

    /// Touch per-frame state, in `logic`: focus edge, Back, capture policy,
    /// toolbar on go-live, key repeat. `focused` is the debounced focus.
    fn touch_logic(&mut self, ctx: &egui::Context, focused: bool) {
        let now = Instant::now();
        // First: a resume after a background disconnect may start a connect.
        self.touch_background(ctx, now);
        let streaming = self.state == ConnectionState::Connected;

        for _ in 0..std::mem::take(&mut self.back_presses) {
            match back_action(streaming, self.keyboard.is_visible()) {
                BackAction::ToggleKeyboard => self.osk_streaming = !self.osk_streaming,
                BackAction::DismissLocalKeyboard => ctx.memory_mut(|m| {
                    if let Some(id) = m.focused() {
                        m.surrender_focus(id);
                    }
                }),
                BackAction::Nothing => {}
            }
        }

        // Capture follows the session: there is no toggle on a phone. Started
        // here, in `logic`, so it is on before `ui` can produce a single key
        // for a live session; and nothing reaches the host before it is (both
        // `send_key` and `forward_key_events` gate on it).
        let want = touch_wants_capture(self.state.is_live(), focused, self.user_released);
        if want && !self.input.is_capturing() {
            tracing::info!("touch: session live and focused — capture on");
            self.input.start_capture();
        } else if !want && self.input.is_capturing() {
            tracing::info!(live = self.state.is_live(), focused, "touch: capture off");
            self.touch_release_input();
            self.input.stop_capture();
        }
        // Capture can also drop behind this policy's back (the release chord
        // from a hardware keyboard). Strokes go nowhere meanwhile, so the
        // on-screen keyboard must not go on believing it holds a key or a
        // locked modifier down on the host.
        if streaming && !self.input.is_capturing() {
            let _ = self.keyboard.release_all_output();
        }

        // Show the toolbar for a few seconds when a session starts, so the
        // handle's purpose is discoverable.
        let live = self.state.is_live();
        if live && !self.touch_was_live {
            self.touch_toolbar.show(now);
        }
        self.touch_was_live = live;

        // Key repeat on frames where the keyboard is not drawn.
        let out = self.keyboard.tick(now);
        self.deliver_keyboard(out);
        if self.keyboard.is_holding() {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        if !self.pending_local_events.is_empty() {
            ctx.request_repaint();
        }
    }

    /// The compact overlay toolbar (Touch): a small handle at the top centre
    /// that expands into a row of finger-sized buttons and auto-hides. Drawn
    /// *before* the streaming view so its rect is current when that view
    /// decides which fingers belong to the video.
    fn touch_toolbar(&mut self, ctx: &egui::Context) {
        self.touch_toolbar_rect = None;
        if self.state != ConnectionState::Connected {
            return;
        }
        let now = Instant::now();
        let expanded = self.touch_toolbar.is_expanded(now);
        let shown = egui::Area::new(egui::Id::new("touch_toolbar"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 2.0))
            .show(ctx, |ui| {
                if expanded {
                    self.touch_toolbar_expanded(ui, now);
                } else {
                    self.touch_toolbar_handle(ui, now);
                }
            });
        self.touch_toolbar_rect = Some(shown.response.rect);
        if let Some(left) = self.touch_toolbar.remaining(now) {
            ctx.request_repaint_after(left);
        }
    }

    fn touch_toolbar_handle(&mut self, ui: &mut egui::Ui, now: Instant) {
        let (rect, resp) =
            ui.allocate_exact_size(egui::vec2(72.0, TOUCH_TARGET_PTS), egui::Sense::click());
        let pill = egui::Rect::from_center_size(rect.center(), egui::vec2(56.0, 20.0));
        let painter = ui.painter();
        let alpha = if resp.hovered() { 200 } else { 140 };
        painter.rect_filled(pill, 10.0, egui::Color32::from_black_alpha(alpha));
        for dx in [-12.0, 0.0, 12.0] {
            painter.circle_filled(
                pill.center() + egui::vec2(dx, 0.0),
                2.5,
                egui::Color32::from_white_alpha(220),
            );
        }
        if resp.clicked() {
            self.touch_toolbar.show(now);
        }
    }

    fn touch_toolbar_expanded(&mut self, ui: &mut egui::Ui, now: Instant) {
        let button = |label: &str, selected: bool| {
            egui::Button::new(label)
                .selected(selected)
                .min_size(egui::vec2(TOUCH_TARGET_PTS * 1.5, TOUCH_TARGET_PTS))
        };
        egui::Frame::new()
            .fill(egui::Color32::from_rgba_unmultiplied(24, 24, 28, 235))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(70)))
            .corner_radius(8.0)
            .inner_margin(egui::Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (color, text) = match &self.state {
                        ConnectionState::Connected => {
                            (egui::Color32::from_rgb(90, 200, 120), "Connected")
                        }
                        _ => (egui::Color32::GRAY, self.state.label()),
                    };
                    ui.colored_label(color, egui::RichText::new(text).strong());
                    ui.colored_label(
                        diagnostics::route_color(self.route),
                        diagnostics::route_text(self.route),
                    );
                    ui.separator();

                    let mut touched = false;
                    if ui.add(button("Keyboard", self.osk_streaming)).clicked() {
                        self.osk_streaming = !self.osk_streaming;
                        touched = true;
                    }
                    if self.touch.zoom() > 1.0 && ui.add(button("Zoom 1x", false)).clicked() {
                        self.touch.reset_view();
                        touched = true;
                    }
                    if ui
                        .add(button("Diagnostics", self.show_diagnostics))
                        .clicked()
                    {
                        self.show_diagnostics = !self.show_diagnostics;
                        touched = true;
                    }
                    if self.mode == SourceMode::LoopbackDemo {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 170, 60),
                            egui::RichText::new("DEMO").strong(),
                        );
                    } else if ui.add(button("Disconnect", false)).clicked() {
                        self.disconnect();
                        return;
                    }
                    if ui.add(button("Hide", false)).clicked() {
                        self.touch_toolbar.hide();
                    } else if touched {
                        self.touch_toolbar.show(now);
                    }
                });
                if let Some(err) = self.input.last_error() {
                    ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err);
                } else if let Some(note) = &self.notice {
                    ui.weak(note);
                }
            });
    }

    /// `App::ui` for the touch profile. No top panel: the toolbar is an
    /// overlay, drawn first (see `touch_toolbar`).
    fn touch_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.touch_toolbar(&ctx);

        egui::CentralPanel::no_frame()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ui, |ui| match self.state.clone() {
                ConnectionState::Connected => self.touch_streaming_view(ui),
                ConnectionState::Connecting | ConnectionState::Authenticating => {
                    self.set_keyboard_visible(false);
                    self.connecting_view(ui)
                }
                ConnectionState::Failed(reason) => {
                    self.set_keyboard_visible(false);
                    self.failed_view(ui, reason)
                }
                ConnectionState::Disconnected => match self.bg_resume.status() {
                    // Back from the background, old session still closing:
                    // no form to type into until the reconnect starts.
                    Some(status) => {
                        self.set_keyboard_visible(false);
                        self.touch_resuming_view(ui, status)
                    }
                    None => self.touch_connect_screen(ui),
                },
            });

        // Same lifetime rule as the desktop path (see `ui`).
        if self.second_window_visible() {
            let title = self.second_window_title();
            second_window::show(&ctx, &self.stream1, &title);
        }

        self.diagnostics_window(&ctx);
        self.elevation_banner(&ctx);

        // NativeActivity cannot do IME, and the system soft keyboard must
        // never appear: the egui keyboard is the only text input. A focused
        // `TextEdit` asks for IME every frame, so the request is withdrawn
        // every frame, after everything that could have made it.
        ctx.output_mut(|o| o.ime = None);
    }

    /// Draws the "host wants elevation" banner as a floating, non-modal
    /// overlay above the session view. It never blocks input to the stream
    /// underneath — it's a strip anchored to the top of the window, not a
    /// window/dialog of its own.
    fn elevation_banner(&mut self, ctx: &egui::Context) {
        let Some(elevation) = &self.elevation else {
            return;
        };
        let title = elevation.title.clone();

        let mut allow = false;
        let mut dismiss = false;
        egui::Area::new(egui::Id::new("elevation_banner"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 8.0))
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(90, 62, 10))
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(230, 170, 60),
                    ))
                    .corner_radius(6.0)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                egui::Color32::from_rgb(255, 210, 120),
                                format!(
                                    "\u{26a0} The remote PC is asking for Administrator \
                                     approval: \"{title}\". Respond on your behalf?"
                                ),
                            );
                            if ui.button("Allow once").clicked() {
                                allow = true;
                            }
                            if ui.button("Ignore").clicked() {
                                dismiss = true;
                            }
                        });
                    });
            });

        if allow {
            self.session.send_control(ControlMsg::ArmElevation {
                one_shot: true,
                ttl_secs: DEFAULT_ELEVATION_TTL_SECS,
            });
            self.elevation = None;
        } else if dismiss {
            self.elevation = None;
        }
    }

    fn diagnostics_window(&mut self, ctx: &egui::Context) {
        if !self.show_diagnostics {
            return;
        }
        let mut open = true;
        let description = self.pipeline.status.description();
        let error = self.pipeline.status.error();
        let audio = self.pipeline.audio_snapshot();
        let audio_error = self.pipeline.audio_error();

        // Computed unconditionally (all cheap: an atomic load or a brief
        // mutex lock, the same cost `log_metrics` already pays every 2 s and
        // this pays every frame the panel is open) but only ever shown
        // through `stream1`, which is `None` unless the window is actually
        // live right now — see `stream1_should_be_visible`. Nothing here is
        // fabricated for a session that never had a second stream; it is
        // simply never read in that case.
        let stream1_description = self.stream1_status.description();
        let stream1_error = self.stream1_status.error();
        let stream1 = self
            .second_window_visible()
            .then(|| diagnostics::Stream1Diag {
                fps_decode: self.stream1.lock().fps_decode(),
                source_description: &stream1_description,
                source_error: stream1_error.as_deref(),
                frames_decoded: self.stream1_slot.decoded_count(),
                frames_presented: self.stream1_slot.presented_count(),
                frames_dropped_at_present: self.stream1_slot.dropped_at_present(),
                remote_dims: self.stream1_slot.remote_dims(),
                frames_gated: self.stream1_status.frames_gated(),
            });

        // Touch: a phone-sized, scrolling variant, and no tiles window (the
        // touch preset never offers lossless tiles, and two windows do not
        // fit on a phone).
        let show = match self.profile {
            UiProfile::Desktop => diagnostics::show,
            UiProfile::Touch => diagnostics::show_touch,
        };
        show(
            ctx,
            &mut open,
            diagnostics::DiagnosticsInput {
                stats: self.stats.as_ref(),
                stats_age_ms: self.stats_at.map(|t| t.elapsed().as_secs_f32() * 1000.0),
                route: self.route,
                presenter: &self.presenter,
                source_description: &description,
                source_error: error.as_deref(),
                frames_decoded: self.slot.decoded_count(),
                frames_presented: self.slot.presented_count(),
                frames_dropped_at_present: self.slot.dropped_at_present(),
                remote_dims: self.slot.remote_dims(),
                keys_forwarded: self.input.keys_forwarded(),
                moves_sent: self.input.moves_sent(),
                moves_coalesced: self.input.moves_coalesced(),
                audio,
                audio_error: audio_error.as_deref(),
                demo_mode: self.mode == SourceMode::LoopbackDemo,
                stream1,
            },
        );
        self.show_diagnostics = open;
        if self.profile == UiProfile::Desktop {
            self.tiles_window(ctx);
        }
    }

    /// Lossless-refinement counters, shown alongside the diagnostics window and
    /// under the same toggle.
    ///
    /// A window of its own rather than a section inside `diagnostics::show`:
    /// `DiagnosticsInput` is the contract that panel renders and widening it is
    /// not this change's business, whereas the highlight toggle needs `&mut
    /// self` anyway.
    fn tiles_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_diagnostics;
        egui::Window::new("Lossless tiles")
            .open(&mut open)
            .default_width(300.0)
            .resizable(true)
            .show(ctx, |ui| {
                let armed = self.tiles.is_armed();
                let (sw, sh) = self.tiles.store_size();
                let bytes = self.tiles.resident_bytes();
                egui::Grid::new("diag_tiles")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("State");
                        if armed {
                            ui.colored_label(
                                egui::Color32::from_rgb(90, 200, 120),
                                egui::RichText::new(format!("armed for {sw} x {sh}")).monospace(),
                            );
                        } else {
                            // Honest: not armed is not an error — it just means
                            // the host has not sent (or has stopped sending)
                            // refinement for this connection.
                            ui.label(egui::RichText::new("not armed").monospace());
                        }
                        ui.end_row();

                        ui.label("Resident tiles");
                        ui.label(
                            egui::RichText::new(self.tiles.resident_tiles().to_string())
                                .monospace(),
                        );
                        ui.end_row();

                        ui.label("Screen covered");
                        ui.label(
                            egui::RichText::new(
                                match covered_percent(self.tiles.covered_pixels(), (sw, sh)) {
                                    Some(pct) => format!("{pct:.1} %"),
                                    None => "—".to_string(),
                                },
                            )
                            .monospace(),
                        );
                        ui.end_row();

                        ui.label("Resident bytes");
                        ui.label(egui::RichText::new(format_bytes(bytes)).monospace());
                        ui.end_row();

                        ui.label("Admitted / dropped");
                        ui.label(
                            egui::RichText::new(format!(
                                "{} / {}",
                                self.tiles.tiles_admitted(),
                                self.tiles.tiles_dropped_capacity()
                            ))
                            .monospace(),
                        );
                        ui.end_row();

                        ui.label("Messages rejected");
                        ui.label(
                            egui::RichText::new(self.tiles.msgs_rejected().to_string()).monospace(),
                        );
                        ui.end_row();
                    });

                if ui
                    .checkbox(&mut self.tile_highlight, "Highlight composited tiles")
                    .on_hover_text(
                        "Tint every refined region green as it is painted, so tile coverage \
                         is visible against the H.264 picture. Diagnostic only — it changes \
                         what you see, not what is stored.",
                    )
                    .changed()
                {
                    self.pipeline.set_tile_highlight(self.tile_highlight);
                }
            });
        // The window's own close button turns the whole diagnostics toggle off,
        // matching the main panel rather than leaving a second hidden switch.
        if !open {
            self.show_diagnostics = false;
        }
    }

    fn persist(&mut self) {
        self.config.show_diagnostics = self.show_diagnostics;
        self.config.start_fullscreen = self.fullscreen;
        self.config.auto_snap_scale = self.auto_snap_scale;
        self.config.save();
    }
}

impl eframe::App for ClientApp {
    /// State only — no drawing here.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Re-asserted every frame: eframe/egui-winit re-applies the system
        // theme during startup, and a remote screen belongs on a dark surround.
        ctx.set_theme(egui::ThemePreference::Dark);

        // First: consume any asynchronous capture loss and service the release
        // chord, so the latch below reflects this frame's input.
        self.reconcile_capture(ctx);

        // "Is DirectDesk the window the operator is typing into" — the answer
        // every capture decision below turns on, and with a second monitor it
        // is a question about *either* window. Computed once so the auto re-arm,
        // the hook's foreground gate and `enforce_capture_invariants` can never
        // disagree within a frame; on a single-window session it is exactly
        // `i.focused`.
        let main_focused = ctx.input(|i| i.focused);
        let any_focused = main_focused || self.second_window_focused(ctx);

        // Touch: the focus every touch decision uses, debounced so Android's
        // one-frame dropout on resume neither resets a gesture nor drops
        // capture. A real loss (two frames) releases everything here, once.
        let touch = self.is_touch();
        let touch_focused = touch && {
            let edge = self.touch_focus.update(main_focused);
            if edge == FocusEdge::Lost {
                tracing::info!("touch: window focus lost — releasing touch input");
                self.touch_release_input();
            }
            if !main_focused && self.touch_focus.is_focused() {
                // Settle a possible flicker promptly either way.
                ctx.request_repaint();
            }
            self.touch_focus.is_focused()
        };

        // Wait for focus: the window is not focused on the first frame, and
        // `enforce_capture_invariants` would (correctly) drop capture again.
        // `--hold-capture` installs without waiting for focus (the whole point
        // is to survive not having it); plain `--capture-on-start` still waits
        // for the first focused frame. Desktop only: these are hook test aids,
        // and Touch capture follows the session (`touch_logic`).
        if !touch && self.capture_on_start && (self.hold_capture || ctx.input(|i| i.focused)) {
            self.capture_on_start = false;
            tracing::warn!(
                hold_capture = self.hold_capture,
                "installing the keyboard hook on start"
            );
            self.input.start_capture();
        }

        // Auto re-arm — the single place capture is acquired without the user
        // asking. `user_released` gates it: a chord release, a toolbar release
        // or a failed install all latch it, and before that latch existed this
        // block re-installed the hook on the very next frame, which is exactly
        // why "Ctrl+Alt+Shift+F12 does nothing" was reported from the field.
        if !touch && !self.user_released && !self.capture_on_start {
            if self.effective_background_capture() {
                // Capture is meant to survive focus changes here, so the only
                // job is a backstop: if it fell off (a teardown we missed, or
                // Windows silently dropping the low-level hook), re-arm.
                // `is_capturing()` flips true immediately, so this fires once
                // per real teardown rather than every frame.
                if !self.input.is_capturing() {
                    tracing::warn!("hold-capture: re-arming keyboard hook after teardown");
                    self.input.start_capture();
                }
            } else {
                // Capture follows focus (the default): acquire while DirectDesk
                // is the focused, non-minimized window;
                // `enforce_capture_invariants` releases it the instant focus is
                // lost, so keystrokes typed into other local apps are never
                // swallowed/forwarded.
                // Any-window focus, matching the release rule in
                // `enforce_capture_invariants`: working in the second monitor's
                // window must acquire capture, not sit there unable to type.
                let active = any_focused && !ctx.input(|i| i.viewport().minimized.unwrap_or(false));
                if active && !self.input.is_capturing() {
                    self.input.start_capture();
                }
            }
        }

        // An explicit CLI `--host` connects once, on the first frame, so the
        // fields are already populated and the supervisor exists.
        if self.auto_connect {
            self.auto_connect = false;
            if self.mode != SourceMode::LoopbackDemo && !self.address_input.trim().is_empty() {
                self.begin_connect();
            }
        }

        self.pointer = ctx.input(|i| i.pointer.latest_pos());
        // This window's own focus, which is a different question from the one
        // below: it is what releases the modifiers *this* window synthesized
        // when it hands focus over — including to the other DirectDesk window,
        // where the process-wide answer never changes at all. (Touch: the
        // debounced answer, so a flicker does not release them.)
        self.input
            .set_window_focused(if touch { touch_focused } else { main_focused });
        // Route capture by focus: when we're foreground the egui key path owns
        // it and the low-level hook passes through; when not, the hook forwards.
        //
        // "We" means *either* DirectDesk window. The hook is process-global and
        // has no window context, so its gate has to be the OR: with a second
        // monitor on screen the egui path owns keys while the operator is in
        // the child window just as much as in this one, and letting the hook
        // forward as well would double-send every keystroke. With no second
        // window this is exactly `i.focused`, so the single-window semantics —
        // and `swallow_decision` — are untouched.
        self.input.set_any_window_foreground(any_focused);
        // Mirrored per frame rather than at the transition sites, because
        // `self.state` is assigned from several places (drain, Bye, connect,
        // disconnect) and the hook must never read a stale gate.
        self.input.set_session_live(self.state.is_live());
        let background = self.effective_background_capture();
        self.input.set_background_capture(background);
        self.drain_session();
        if let Some(elevation) = &self.elevation {
            if elevation.shown_at.elapsed() >= ELEVATION_BANNER_TIMEOUT {
                self.elevation = None;
            }
        }
        if touch {
            self.touch_logic(ctx, touch_focused);
        } else {
            self.enforce_capture_invariants(ctx, any_focused);
        }
        self.presenter.update(ctx, &self.slot);
        self.service_second_window(ctx);
        self.log_metrics(ctx);

        // Streaming means continuous repaint: the frame slot is written by a
        // background thread, so egui cannot know when new pixels exist. The
        // connecting spinner also needs to keep animating.
        let connecting = matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Authenticating
        );
        if self.streaming() || self.input.has_pending_move() || connecting {
            ctx.request_repaint();
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            self.touch_release_input();
            self.input.stop_capture();
            self.persist();
        }
    }

    /// Touch only, main window only: strip Back (the app's own key, never the
    /// host's), synthesize a finger from the mouse (Windows test aid), and
    /// inject the on-screen keyboard's local events queued last frame.
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if !self.is_touch() || raw_input.viewport_id != egui::ViewportId::ROOT {
            return;
        }
        self.back_presses += strip_back_key(&mut raw_input.events);
        #[cfg(not(target_os = "android"))]
        self.mouse_touch.process(&mut raw_input.events);
        self.injected_events = std::mem::take(&mut self.pending_local_events);
        raw_input
            .events
            .extend(self.injected_events.iter().cloned());
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.is_touch() {
            self.touch_ui(ui);
            return;
        }
        let ctx = ui.ctx().clone();

        // In fullscreen the toolbar would steal rows from the video and force
        // a fractional downscale (host desktop == monitor size leaves zero
        // slack), so hide it unless the pointer is at the top edge or we are
        // not actively streaming.
        let show_toolbar = !self.fullscreen
            || !matches!(self.state, ConnectionState::Connected)
            || ctx.input(|i| i.pointer.hover_pos().is_some_and(|p| p.y < 40.0));
        if show_toolbar {
            egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui, &ctx));
        }

        egui::CentralPanel::no_frame()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ui, |ui| match self.state.clone() {
                ConnectionState::Connected => self.streaming_view(ui),
                ConnectionState::Connecting | ConnectionState::Authenticating => {
                    self.connecting_view(ui)
                }
                ConnectionState::Failed(reason) => self.failed_view(ui, reason),
                ConnectionState::Disconnected => self.connect_screen(ui),
            });

        // A deferred viewport exists only while it is re-declared, so this call
        // *is* the second window's lifetime: not making it is what closes the
        // OS window, which is why it sits here rather than behind any of the
        // drawing branches above.
        //
        // The `is_live` half is not redundant with the teardown sites.
        // `state_rx` and `control_rx` are separate channels, so a dropped
        // connection's queued `MonitorList` can be applied *after* the state
        // change that tore the window down — re-opening it for one pass over
        // the connect screen. Requiring a live session makes that
        // unrepresentable rather than merely unlikely.
        if self.second_window_visible() {
            let title = self.second_window_title();
            second_window::show(&ctx, &self.stream1, &title);
        }

        self.diagnostics_window(&ctx);
        self.elevation_banner(&ctx);
    }
}

impl Drop for ClientApp {
    fn drop(&mut self) {
        // Belt and braces: the hook must not outlive the app under any exit
        // path, including an unwinding panic.
        self.input.stop_capture();
        self.pipeline.shutdown();
        self.persist();
    }
}

/// Touch: a finger-height field (egui 0.35 ignores `TextEdit::min_size().y`,
/// so the height comes from the margin: one ~16 pt row + 2 x 10 pt).
/// Desktop: unchanged.
fn fit_text_edit(touch: bool, edit: egui::TextEdit<'_>) -> egui::TextEdit<'_> {
    if touch {
        edit.margin(egui::Margin::symmetric(6, 10))
    } else {
        edit
    }
}

/// The fps a persisted config should impose on the supervisor's caps at
/// startup: an explicit choice, never "Auto" (0), which defers to the
/// platform preset instead (`StreamCaps::touch_device` caps Android at 30).
pub fn persisted_fps_override(config_fps: u32) -> Option<u32> {
    (config_fps != 0).then_some(config_fps)
}

/// Does the connect screen offer the monitor picker? Only in the desktop
/// profile, and only where connects offer `MULTI_MONITOR` at all
/// (`caps_multi_monitor` is the supervisor's caps; `None` = no supervisor,
/// where the desktop has always shown it). Where it is hidden, every connect
/// and notice acts on `Primary` (`ClientApp::effective_monitor_choice`).
pub fn monitor_picker_offered(profile: UiProfile, caps_multi_monitor: Option<bool>) -> bool {
    profile == UiProfile::Desktop && caps_multi_monitor.unwrap_or(true)
}

/// The one wording for "we gave the keyboard back", used by every release path
/// so the way out is always spelled out.
fn released_notice() -> String {
    format!("Input released ({RELEASE_CHORD}) — click Capture input or press the chord to resume")
}

/// The one wording for "the host only has one screen", shared by every path
/// that can discover it (the `MonitorList` arm and the toolbar toggle) so the
/// operator never sees two different explanations of the same fact.
pub const ONE_MONITOR_NOTICE: &str = "Host reports one monitor — showing primary only.";

/// The one wording for "this host is too old to know about monitors at all".
/// Deliberately distinct from [`ONE_MONITOR_NOTICE`]: "your host cannot do this"
/// and "your host has one screen" call for different actions from the operator.
pub const OLD_HOST_NOTICE: &str = "Host doesn't support monitor selection — showing primary only.";

/// What the operator has said about the second window during *this session*,
/// as distinct from the persisted connect-screen choice.
///
/// The distinction exists because the host re-sends its entire `MonitorList` on
/// any topology change. Deciding "should the second window be up?" purely from
/// `ClientConfig::monitor_choice` would mean every such re-send re-litigates a
/// decision the operator already made with the toolbar — closing a window they
/// opened, or re-opening one they dismissed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecondWindowIntent {
    /// The operator has not touched the toolbar toggle this session, so the
    /// persisted choice governs.
    #[default]
    FromChoice,
    /// They asked for the second window explicitly.
    Requested,
    /// They closed it explicitly.
    Dismissed,
}

/// Whether the second window should be up, given the operator's session intent,
/// their persisted choice, and what the host currently reports.
///
/// The single decision function for the window's existence, so the `MonitorList`
/// arm and any future caller cannot disagree about it.
pub fn wants_second_window(
    intent: SecondWindowIntent,
    choice: MonitorChoice,
    monitors: &[MonitorInfo],
) -> bool {
    // Whether the host has a second output at all — the veto that outranks
    // every intent, since there is nothing to put in the window without one.
    let host_has_two = !monitors::resolve_selection(MonitorChoice::Both, monitors).degraded;
    match intent {
        SecondWindowIntent::Dismissed => false,
        SecondWindowIntent::Requested => host_has_two,
        SecondWindowIntent::FromChoice => {
            monitors::resolve_selection(choice, monitors).ids.len() > 1
        }
    }
}

/// What a host `MonitorList` means for the second window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorListPlan {
    /// Whether the second window should be up after this list.
    pub want_second_window: bool,
    /// Set when the persisted choice could not be honoured as asked. Shown once
    /// per session, on the first list.
    pub notice: Option<String>,
}

/// Resolve a freshly arrived `MonitorList` against session intent and the
/// operator's persisted choice.
///
/// Pure so the cache write, the degrade notice and the window decision are all
/// testable without a `Context`, a session, or a host — the arm in
/// `handle_control` does nothing but apply what this returns.
pub fn plan_monitor_list(
    intent: SecondWindowIntent,
    choice: MonitorChoice,
    monitors: &[MonitorInfo],
) -> MonitorListPlan {
    MonitorListPlan {
        want_second_window: wants_second_window(intent, choice, monitors),
        // Reports on the *persisted* choice only. What the operator did with
        // the toolbar afterwards is not a degradation of anything, so folding
        // intent in here would either suppress a real note or invent one.
        notice: (monitors::resolve_selection(choice, monitors).degraded
            && choice != MonitorChoice::Primary)
            .then(|| ONE_MONITOR_NOTICE.to_string()),
    }
}

/// Whether a `StreamConfig { id: 1, .. }` describes a genuine format change.
///
/// The stream-1 twin of [`tiles_invalidated_by_config`], and it exists for the
/// same reason: this message also arrives in reply to every `StartStream`, which
/// this client sends on every fps re-assert and every quality change. Treating
/// those as discontinuities would blank the second window several times a
/// minute. Only the *dimensions* matter — a new fps or bitrate does not
/// invalidate a single decoded pixel — and the first config of a stream is not a
/// change either, since there is nothing yet to contradict.
pub fn stream1_format_changed(prev: Option<(u32, u32, u32, u32)>, width: u32, height: u32) -> bool {
    prev.is_some_and(|(w, h, _, _)| (w, h) != (width, height))
}

/// Pure core of [`ClientApp::second_window_visible`]: does the second window
/// — and by extension its per-frame diagnostics section and its line in
/// [`ClientApp::log_metrics`] — exist right now?
///
/// Split out so "no second stream this session" (either input `false`) is a
/// plain unit test rather than something only checkable by eye against a live
/// window. A closed window's counters are stale the instant it closes (its
/// slot is cleared in the same call, see `close_second_window`), so the same
/// gate that decides whether the OS window exists also decides whether the
/// diagnostics panel's "Stream 1" section — and the log's "stream 1 metrics"
/// line — exist: showing either from a window that is not currently up would
/// be either empty or lying, and the panel's HONESTY RULE forbids both.
fn stream1_should_be_visible(window_open: bool, live: bool) -> bool {
    window_open && live
}

/// The notice for a host that never sent a `MonitorList` at all.
///
/// `saw_monitor_list` false means the `MULTI_MONITOR` bit never came back
/// mutual — the graceful-degradation case the connect screen promises. Silent
/// when the operator asked for `Primary`, since that is exactly what they got.
pub fn old_host_notice(saw_monitor_list: bool, choice: MonitorChoice) -> Option<String> {
    (!saw_monitor_list && choice != MonitorChoice::Primary).then(|| OLD_HOST_NOTICE.to_string())
}

/// Title for the second monitor's OS window.
///
/// `name` comes off the wire, so it is treated the way every other displayed
/// wire string is: control characters stripped (they can forge line breaks in a
/// title bar) and the length capped, rather than trusted because the host's own
/// docs say it caps at 64 bytes.
pub fn second_window_title(name: Option<&str>, dims: Option<(u32, u32)>) -> String {
    let clean: Option<String> =
        name.map(|n| n.chars().filter(|c| !c.is_control()).take(64).collect());
    let clean = clean.filter(|n| !n.trim().is_empty());
    match (clean, dims) {
        (Some(name), Some((w, h))) => format!("DirectDesk — {name} {w}x{h}"),
        (Some(name), None) => format!("DirectDesk — {name}"),
        (None, Some((w, h))) => format!("DirectDesk — second monitor {w}x{h}"),
        (None, None) => "DirectDesk — second monitor".to_string(),
    }
}

/// Kept free of egui so it's unit-testable without a context.
pub fn fps_label(fps: u32) -> String {
    if fps == 0 {
        "Auto (host)".to_string()
    } else {
        format!("{fps} fps")
    }
}

/// Label for the auto-snap combo. Kept free of egui so it's unit-testable
/// without a context. Any value this build does not know about (a
/// hand-edited or future-written config) reads as "Off" rather than panicking
/// or showing a raw number — `ClientConfig::sanitized` already resets such
/// values to 0, but the UI stays defensive too.
pub fn auto_snap_label(scale: u32) -> &'static str {
    match scale {
        1 => "1:1",
        2 => "2x",
        _ => "Off",
    }
}

/// Whether the monitor can show the host desktop at exactly `scale` screen
/// pixels per host pixel, toolbar chrome included. `scale = 1` is the
/// original 1:1 check; `scale = 2` is pixel-doubled, and so on.
///
/// `host_dims` are physical pixels; `monitor_points` and `chrome_points` are
/// already in egui points (the `monitor_size` idiom and `chrome_points` both
/// come that way), hence dividing the scaled host dims by `ppp` before
/// comparing. Both axes matter: a monitor that is wide enough but not tall
/// enough (or vice versa) still cannot fit the window, and skipping either
/// check is exactly what let this button previously request a window taller
/// than the screen and get silently clamped by Windows. `None` monitor size
/// (the platform won't say) lets the user try anyway rather than blocking
/// them.
pub fn fits_integer_scale(
    host_dims: (u32, u32),
    monitor_points: Option<egui::Vec2>,
    ppp: f32,
    chrome_points: f32,
    scale: u32,
) -> bool {
    let (w, h) = host_dims;
    let scale = scale as f32;
    monitor_points.is_none_or(|monitor| {
        (w as f32 * scale / ppp) <= monitor.x
            && (h as f32 * scale / ppp + chrome_points) <= monitor.y
    })
}

/// The largest integer scale (capped at 3x — there is no realistic use for
/// more) that `fits_integer_scale` allows, or 0 if even 1:1 does not fit.
/// `fits_integer_scale` only gets harder to satisfy as `scale` grows, so a
/// simple top-down search is enough — no need to check every scale below the
/// first one that fits.
fn largest_fitting_scale(
    host_dims: (u32, u32),
    monitor_points: Option<egui::Vec2>,
    ppp: f32,
    chrome_points: f32,
) -> u32 {
    (1..=3)
        .rev()
        .find(|&scale| fits_integer_scale(host_dims, monitor_points, ppp, chrome_points, scale))
        .unwrap_or(0)
}

/// Share of the armed screen the resident tiles cover, or `None` when the store
/// is disarmed and there is nothing honest to divide by.
///
/// `covered_pixels` ignores frame-edge clipping and double-counts nothing (the
/// store is keyed by tile id), so this cannot exceed 100% for a real grid — but
/// it is clamped anyway rather than rendering a number that reads as a bug.
pub fn covered_percent(covered_px: u64, store_size: (u32, u32)) -> Option<f32> {
    let total = u64::from(store_size.0) * u64::from(store_size.1);
    if total == 0 {
        return None;
    }
    Some((covered_px as f64 / total as f64 * 100.0).min(100.0) as f32)
}

/// Byte counts at a glance. Kept free of egui so it is unit-testable.
pub fn format_bytes(bytes: usize) -> String {
    const MIB: usize = 1024 * 1024;
    const KIB: usize = 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Whether a `VideoConfig` invalidates the lossless refinement overlay.
///
/// `prev` is `ClientApp::host_video` *before* this message is applied. Only a
/// genuine change of the host's **dimensions** counts:
///
/// * fps and bitrate changes do not move a single pixel's coordinates, and this
///   arm fires on every fps re-assert — treating those as invalidation would
///   disarm the store repeatedly and the refinement would never settle.
/// * The *first* config of a connection is not a change either. Nothing has
///   been learned yet to contradict, and the paths that end a connection
///   (`drain_session`'s non-live branch, `Bye`, `disconnect`) have already
///   cleared the store. Clearing here as well would be a live hazard rather
///   than a no-op: the host's `Reset` opens the tile stream around the same
///   moment, and a `VideoConfig` processed after it would disarm a store the
///   host believes is armed — leaving refinement off for the whole session,
///   since `Reset` is not re-sent.
pub fn tiles_invalidated_by_config(
    prev: Option<(u32, u32, u32, u32)>,
    width: u32,
    height: u32,
) -> bool {
    prev.is_some_and(|(w, h, _, _)| (w, h) != (width, height))
}

/// Re-assert only when we want a *lower* rate than the host reports and we
/// have not just asked. Never re-asserts upward: the host's configured fps is
/// a ceiling we cannot raise, so `desired >= reported` is already the final
/// answer and asking again would loop forever.
pub fn should_reassert_fps(
    desired: u32,
    reported: u32,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    desired != 0
        && desired < reported
        && last.is_none_or(|t| now.duration_since(t) > Duration::from_secs(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::protocol::{MAX_TARGET_FPS, UI_MIN_TARGET_FPS};

    #[test]
    fn fps_choices_are_auto_or_within_the_ui_range() {
        for fps in FPS_CHOICES {
            assert!(
                fps == 0 || (UI_MIN_TARGET_FPS..=MAX_TARGET_FPS).contains(&fps),
                "fps choice {fps} is neither Auto (0) nor within \
                 UI_MIN_TARGET_FPS..=MAX_TARGET_FPS"
            );
        }
    }

    #[test]
    fn every_quality_mode_has_a_label() {
        for mode in [
            QualityMode::TextDesktop,
            QualityMode::Balanced,
            QualityMode::Motion,
            QualityMode::LowBandwidth,
        ] {
            assert!(!mode.label().is_empty());
        }
    }

    #[test]
    fn auto_fps_in_a_fresh_config_keeps_the_platform_preset() {
        use crate::connect::StreamCaps;
        let seeded = |preset: StreamCaps, config_fps: u32| {
            persisted_fps_override(config_fps).unwrap_or(preset.preferred_fps)
        };
        // Android: a fresh config (0 = Auto) must not lift the 30 fps cap.
        assert_eq!(seeded(StreamCaps::touch_device(), 0), 30);
        // An explicit choice still wins on either platform.
        assert_eq!(seeded(StreamCaps::touch_device(), 15), 15);
        assert_eq!(seeded(StreamCaps::default(), 45), 45);
        // Desktop with Auto: host decides, exactly as before.
        assert_eq!(seeded(StreamCaps::default(), 0), 0);
    }

    #[test]
    fn the_monitor_picker_is_desktop_only_and_needs_multi_monitor_caps() {
        // Desktop: exactly as before (default caps offer it; no supervisor
        // still shows it).
        assert!(monitor_picker_offered(UiProfile::Desktop, Some(true)));
        assert!(monitor_picker_offered(UiProfile::Desktop, None));
        assert!(!monitor_picker_offered(UiProfile::Desktop, Some(false)));
        // Touch never shows it, whatever the caps.
        assert!(!monitor_picker_offered(UiProfile::Touch, Some(true)));
        assert!(!monitor_picker_offered(UiProfile::Touch, Some(false)));
        assert!(!monitor_picker_offered(UiProfile::Touch, None));
        // And with it hidden the effective choice is Primary, which can
        // never raise the "host too old" notice.
        assert_eq!(old_host_notice(false, MonitorChoice::Primary), None);
    }

    #[test]
    fn fps_label_zero_is_auto() {
        assert_eq!(fps_label(0), "Auto (host)");
    }

    #[test]
    fn fps_label_nonzero_shows_the_number() {
        assert_eq!(fps_label(30), "30 fps");
        assert_eq!(fps_label(24), "24 fps");
    }

    #[test]
    fn auto_snap_label_covers_off_and_both_scales() {
        assert_eq!(auto_snap_label(0), "Off");
        assert_eq!(auto_snap_label(1), "1:1");
        assert_eq!(auto_snap_label(2), "2x");
        // A value this build doesn't offer must not panic or show garbage.
        assert_eq!(auto_snap_label(9), "Off");
    }

    #[test]
    fn should_reassert_fps_when_desired_is_lower_and_never_asked() {
        let now = Instant::now();
        assert!(should_reassert_fps(30, 60, None, now));
    }

    #[test]
    fn should_reassert_fps_never_raises_the_rate() {
        // The host's configured fps is a ceiling we cannot raise: asking for
        // 60 while the host already reports 30 is already the final answer.
        let now = Instant::now();
        assert!(!should_reassert_fps(60, 30, None, now));
    }

    #[test]
    fn should_reassert_fps_auto_never_reasserts() {
        let now = Instant::now();
        assert!(!should_reassert_fps(0, 60, None, now));
    }

    #[test]
    fn should_reassert_fps_equal_desired_and_reported_does_not_reassert() {
        let now = Instant::now();
        assert!(!should_reassert_fps(30, 30, None, now));
    }

    #[test]
    fn fits_integer_scale_true_when_monitor_unknown() {
        // Can't check, so let the user try.
        assert!(fits_integer_scale((1920, 1080), None, 1.0, 40.0, 1));
        assert!(fits_integer_scale((1920, 1080), None, 1.0, 40.0, 2));
    }

    #[test]
    fn fits_integer_scale_checks_width() {
        let monitor = egui::vec2(1000.0, 2000.0);
        assert!(!fits_integer_scale(
            (1920, 1080),
            Some(monitor),
            1.0,
            40.0,
            1
        ));
    }

    #[test]
    fn fits_integer_scale_checks_height_including_chrome() {
        // This is bug 1: a monitor exactly as tall (in points) as the host
        // desktop, at ppp 1.0, fits on width but not once the toolbar chrome
        // is added to the height — the old width-only check would have said
        // "fits" here and produced a window Windows had to clamp.
        let monitor = egui::vec2(1920.0, 1080.0);
        assert!(!fits_integer_scale(
            (1920, 1080),
            Some(monitor),
            1.0,
            40.0,
            1
        ));
        // Same desktop, a monitor with enough headroom for the chrome: fits.
        let taller_monitor = egui::vec2(1920.0, 1130.0);
        assert!(fits_integer_scale(
            (1920, 1080),
            Some(taller_monitor),
            1.0,
            40.0,
            1
        ));
    }

    #[test]
    fn fits_integer_scale_scales_host_dims_by_ppp() {
        // The example from the task: 1920x1080 host, a 2560x1600-physical /
        // 1707x1067-point monitor at 150% scaling, comfortably fits a
        // 1280x720-point window plus chrome at 1:1.
        let monitor = egui::vec2(1707.0, 1067.0);
        assert!(fits_integer_scale(
            (1920, 1080),
            Some(monitor),
            1.5,
            40.0,
            1
        ));
    }

    #[test]
    fn fits_integer_scale_at_2x_needs_double_the_room() {
        // Same host and monitor as above, but doubled: 1920x1080 @ 2x wants a
        // 2560x1440-point window plus chrome — this monitor (1707x1067
        // points) cannot hold that, even though 1:1 fits comfortably.
        let monitor = egui::vec2(1707.0, 1067.0);
        assert!(!fits_integer_scale(
            (1920, 1080),
            Some(monitor),
            1.5,
            40.0,
            2
        ));

        // The task's other worked example: a 1280x720 host at 2x is
        // 2560x1440 physical, which fits a 2560x1600-physical /
        // 1707x1067-point screen at 150% scaling with room for the toolbar.
        assert!(fits_integer_scale((1280, 720), Some(monitor), 1.5, 40.0, 2));
    }

    #[test]
    fn largest_fitting_scale_picks_the_biggest_that_fits() {
        let monitor = egui::vec2(1707.0, 1067.0);
        // 1280x720 host fits both 1:1 and 2x on this monitor.
        assert_eq!(
            largest_fitting_scale((1280, 720), Some(monitor), 1.5, 40.0),
            2
        );
        // 1920x1080 host fits 1:1 but not 2x on the same monitor.
        assert_eq!(
            largest_fitting_scale((1920, 1080), Some(monitor), 1.5, 40.0),
            1
        );
        // Nothing fits: too small a monitor even for 1:1.
        let tiny = egui::vec2(100.0, 100.0);
        assert_eq!(
            largest_fitting_scale((1920, 1080), Some(tiny), 1.0, 40.0),
            0
        );
    }

    #[test]
    fn video_config_clears_tiles_only_on_a_real_dimension_change() {
        // The bug this guards: `VideoConfig` also arrives in reply to every fps
        // re-assert and every `StartStream`. If those counted as invalidation
        // the store would be disarmed several times a minute and refinement
        // would never become visible.
        let base = Some((1920u32, 1080u32, 60u32, 8_000u32));
        assert!(!tiles_invalidated_by_config(base, 1920, 1080));

        // Same dims, different fps / bitrate — the exact fps-re-assert case.
        let fps_changed = Some((1920, 1080, 30, 8_000));
        assert!(!tiles_invalidated_by_config(fps_changed, 1920, 1080));
        let bitrate_changed = Some((1920, 1080, 60, 2_500));
        assert!(!tiles_invalidated_by_config(bitrate_changed, 1920, 1080));

        // A genuine resolution change: every tile's coordinates now mean
        // something else, so the overlay must go.
        assert!(tiles_invalidated_by_config(base, 1280, 1080));
        assert!(tiles_invalidated_by_config(base, 1920, 720));
        assert!(tiles_invalidated_by_config(base, 1280, 720));

        // The first config of a connection is not a change. The disconnect
        // paths already cleared the store, and clearing here could disarm a
        // store the host has just armed with its `Reset`.
        assert!(!tiles_invalidated_by_config(None, 1920, 1080));
    }

    #[test]
    fn covered_percent_is_none_until_the_store_is_armed() {
        assert_eq!(covered_percent(0, (0, 0)), None);
        assert_eq!(covered_percent(1_000, (1920, 0)), None);
        assert_eq!(covered_percent(1_000, (0, 1080)), None);
    }

    #[test]
    fn covered_percent_reports_the_share_of_the_armed_screen() {
        assert_eq!(covered_percent(0, (100, 100)), Some(0.0));
        assert_eq!(covered_percent(5_000, (100, 100)), Some(50.0));
        assert_eq!(covered_percent(10_000, (100, 100)), Some(100.0));
        // Never renders as a number that reads like a bug.
        assert_eq!(covered_percent(u64::MAX, (100, 100)), Some(100.0));
    }

    #[test]
    fn format_bytes_scales_its_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
    }

    fn monitor(id: u8, name: &str) -> MonitorInfo {
        MonitorInfo {
            id,
            width: 1920,
            height: 1080,
            origin_x: 0,
            origin_y: 0,
            is_primary: id == 0,
            name: name.into(),
        }
    }

    /// The persisted choice governs until the operator says otherwise.
    const UNTOUCHED: SecondWindowIntent = SecondWindowIntent::FromChoice;

    #[test]
    fn primary_never_wants_a_second_window_and_never_complains() {
        // The default choice got exactly what it asked for on every topology,
        // so it must never produce a notice — including against a host with two
        // screens, where a note would be pure noise.
        for list in [
            vec![],
            vec![monitor(0, "A")],
            vec![monitor(0, "A"), monitor(1, "B")],
        ] {
            let plan = plan_monitor_list(UNTOUCHED, MonitorChoice::Primary, &list);
            assert!(!plan.want_second_window, "{list:?}");
            assert_eq!(plan.notice, None, "{list:?}");
        }
    }

    #[test]
    fn both_opens_the_second_window_on_a_two_monitor_host() {
        let list = [monitor(0, "A"), monitor(1, "B")];
        let plan = plan_monitor_list(UNTOUCHED, MonitorChoice::Both, &list);
        assert!(plan.want_second_window);
        assert_eq!(plan.notice, None, "nothing was degraded");
    }

    #[test]
    fn second_alone_is_one_stream_and_therefore_no_second_window() {
        // `Second` puts the secondary output on stream 0 — one stream, one
        // window. The second window exists only for `Both`.
        let list = [monitor(0, "A"), monitor(1, "B")];
        let plan = plan_monitor_list(UNTOUCHED, MonitorChoice::Second, &list);
        assert!(!plan.want_second_window);
        assert_eq!(plan.notice, None);
    }

    #[test]
    fn a_one_monitor_host_degrades_with_a_visible_note() {
        // The graceful-degradation promise the connect screen makes in writing.
        let list = [monitor(0, "A")];
        for choice in [MonitorChoice::Second, MonitorChoice::Both] {
            let plan = plan_monitor_list(UNTOUCHED, choice, &list);
            assert!(!plan.want_second_window, "{choice:?}");
            assert_eq!(
                plan.notice.as_deref(),
                Some(ONE_MONITOR_NOTICE),
                "{choice:?} must say why it could not be honoured"
            );
        }
    }

    #[test]
    fn an_empty_monitor_list_degrades_but_still_never_nags_primary() {
        assert_eq!(
            plan_monitor_list(UNTOUCHED, MonitorChoice::Primary, &[]).notice,
            None
        );
        assert_eq!(
            plan_monitor_list(UNTOUCHED, MonitorChoice::Both, &[])
                .notice
                .as_deref(),
            Some(ONE_MONITOR_NOTICE)
        );
    }

    #[test]
    fn a_toolbar_opened_window_survives_a_topology_re_send() {
        // The regression the intent model exists for. The host re-sends its
        // whole `MonitorList` on ANY display change — a resolution change or a
        // re-arrange, not only a plug/unplug. Deriving the window's existence
        // from the persisted choice alone would slam a toolbar-opened window
        // shut on the next such re-send, with the host never told to stop, and
        // the next `StreamConfig` would then re-open it: a window that flaps by
        // itself.
        let list = [monitor(0, "A"), monitor(1, "B")];
        for choice in [
            MonitorChoice::Primary,
            MonitorChoice::Second,
            MonitorChoice::Both,
        ] {
            assert!(
                wants_second_window(SecondWindowIntent::Requested, choice, &list),
                "{choice:?}: an explicit request outranks the persisted choice"
            );
        }
    }

    #[test]
    fn a_dismissed_window_stays_shut_however_the_list_is_re_sent() {
        // The operator's close is a decision; no amount of re-sending, and no
        // persisted choice, may overturn it for the rest of the session.
        let list = [monitor(0, "A"), monitor(1, "B")];
        for choice in [
            MonitorChoice::Primary,
            MonitorChoice::Second,
            MonitorChoice::Both,
        ] {
            assert!(
                !wants_second_window(SecondWindowIntent::Dismissed, choice, &list),
                "{choice:?}"
            );
        }
    }

    #[test]
    fn losing_the_second_monitor_closes_the_window_whatever_the_intent() {
        // The one veto that outranks intent: there is nothing to put in the
        // window. Asked for explicitly or implied by the choice, a host that
        // reports one output gets one window.
        for intent in [
            SecondWindowIntent::FromChoice,
            SecondWindowIntent::Requested,
            SecondWindowIntent::Dismissed,
        ] {
            assert!(
                !wants_second_window(intent, MonitorChoice::Both, &[monitor(0, "A")]),
                "{intent:?}"
            );
            assert!(
                !wants_second_window(intent, MonitorChoice::Both, &[]),
                "{intent:?} on an empty list"
            );
        }
    }

    #[test]
    fn the_default_intent_defers_to_the_persisted_choice() {
        assert_eq!(
            SecondWindowIntent::default(),
            SecondWindowIntent::FromChoice
        );
        let list = [monitor(0, "A"), monitor(1, "B")];
        assert!(wants_second_window(
            SecondWindowIntent::default(),
            MonitorChoice::Both,
            &list
        ));
        assert!(!wants_second_window(
            SecondWindowIntent::default(),
            MonitorChoice::Primary,
            &list
        ));
    }

    #[test]
    fn stream1_reconfig_only_counts_as_a_change_when_the_dimensions_move() {
        // `StreamConfig { id: 1 }` also answers every `StartStream`, which this
        // client sends on every fps re-assert and every quality change. If
        // those counted as discontinuities the second window would flash to
        // black several times a minute — the exact bug
        // `tiles_invalidated_by_config` documents on the stream-0 path.
        let base = Some((2560u32, 1440u32, 60u32, 8_000u32));
        assert!(!stream1_format_changed(base, 2560, 1440));
        // Same dims, different fps / bitrate: the fps-re-assert case.
        assert!(!stream1_format_changed(
            Some((2560, 1440, 30, 8_000)),
            2560,
            1440
        ));
        assert!(!stream1_format_changed(
            Some((2560, 1440, 60, 2_500)),
            2560,
            1440
        ));
        // A genuine resolution change on the second monitor.
        assert!(stream1_format_changed(base, 1920, 1440));
        assert!(stream1_format_changed(base, 2560, 1080));
        // The first config of a stream is not a change: nothing to contradict.
        assert!(!stream1_format_changed(None, 2560, 1440));
    }

    /// Feeds `ClientApp::diagnostics_window`'s `stream1: Option<Stream1Diag>`
    /// and `log_metrics`'s "stream 1 metrics" line, so this is the
    /// end-to-end proof of the panel's own claim: "no second stream this
    /// session" (never opened, or the session is not live) must mean
    /// `None`, never a section of zeros.
    #[test]
    fn stream1_diagnostics_are_none_with_no_second_stream_this_session() {
        assert!(
            !stream1_should_be_visible(false, true),
            "never opened this session"
        );
        assert!(
            !stream1_should_be_visible(true, false),
            "window flag set but the session is not live (e.g. disconnected)"
        );
        assert!(!stream1_should_be_visible(false, false));
    }

    #[test]
    fn stream1_diagnostics_appear_once_the_window_is_actually_live() {
        assert!(stream1_should_be_visible(true, true));
    }

    #[test]
    fn an_old_host_is_reported_only_when_the_choice_asked_for_more() {
        // No `MonitorList` ever arrived: the feature bit was not mutual.
        assert_eq!(
            old_host_notice(false, MonitorChoice::Both).as_deref(),
            Some(OLD_HOST_NOTICE)
        );
        assert_eq!(
            old_host_notice(false, MonitorChoice::Second).as_deref(),
            Some(OLD_HOST_NOTICE)
        );
        // `Primary` got what it asked for, so there is nothing to report.
        assert_eq!(old_host_notice(false, MonitorChoice::Primary), None);
        // A list arrived, so this host is not the old one — whatever else may
        // have degraded is `plan_monitor_list`'s to say, and saying both would
        // give the operator two different explanations of one fact.
        for choice in [
            MonitorChoice::Primary,
            MonitorChoice::Second,
            MonitorChoice::Both,
        ] {
            assert_eq!(old_host_notice(true, choice), None, "{choice:?}");
        }
    }

    #[test]
    fn the_two_degrade_notices_are_different_sentences() {
        // "your host cannot do this" and "your host has one screen" call for
        // different actions from the operator, so they must never collapse.
        assert_ne!(ONE_MONITOR_NOTICE, OLD_HOST_NOTICE);
    }

    #[test]
    fn the_second_window_title_uses_whatever_has_been_learned() {
        assert_eq!(
            second_window_title(Some("\\\\.\\DISPLAY2"), Some((2560, 1440))),
            "DirectDesk — \\\\.\\DISPLAY2 2560x1440"
        );
        assert_eq!(
            second_window_title(Some("\\\\.\\DISPLAY2"), None),
            "DirectDesk — \\\\.\\DISPLAY2"
        );
        assert_eq!(
            second_window_title(None, Some((1920, 1080))),
            "DirectDesk — second monitor 1920x1080"
        );
        assert_eq!(
            second_window_title(None, None),
            "DirectDesk — second monitor"
        );
    }

    #[test]
    fn the_second_window_title_never_trusts_the_hosts_name() {
        // `MonitorInfo::name` is display-only wire text. Control characters
        // could forge extra lines in a title bar, and the length cap is ours to
        // enforce rather than the host's to promise.
        let forged = "DISPLAY2\r\nDirectDesk — Administrator";
        let title = second_window_title(Some(forged), None);
        assert!(!title.contains('\n') && !title.contains('\r'), "{title}");

        let long = "M".repeat(500);
        let title = second_window_title(Some(&long), Some((640, 480)));
        assert!(
            title.chars().filter(|c| *c == 'M').count() <= 64,
            "the name must be capped: {title}"
        );

        // A name that is nothing but control characters is no name at all, and
        // must not leave a dangling separator.
        assert_eq!(
            second_window_title(Some("\u{0}\u{7}"), Some((640, 480))),
            "DirectDesk — second monitor 640x480"
        );
    }

    #[test]
    fn should_reassert_fps_is_rate_limited() {
        let t0 = Instant::now();
        // Just asked: must not fire again immediately.
        assert!(!should_reassert_fps(30, 60, Some(t0), t0));
        // Enough time has passed: fires again.
        let later = t0 + Duration::from_secs(3);
        assert!(should_reassert_fps(30, 60, Some(t0), later));
    }
}
