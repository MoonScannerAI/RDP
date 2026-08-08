//! eframe application shell: connect screen, streaming view, toolbar,
//! diagnostics.
//!
//! The app owns the UI-side half of [`ClientSession`] and never talks to the
//! network directly — everything arrives and leaves through those channels, so
//! the transport wave plugs in without touching this file.
//!
//! eframe 0.35 splits a frame into [`eframe::App::logic`] (state, no drawing)
//! and [`eframe::App::ui`] (drawing only); this app keeps to that split.

pub mod connect_form;
pub mod diagnostics;

use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::protocol::{ControlMsg, QualityMode};
use directdesk_shared::stats::{validate_stats, ConnStats, TransportRoute};

use crate::config::ClientConfig;
use crate::connect::ConnectSupervisor;
use crate::input_capture::{
    is_release_chord, wheel_delta, CaptureLoss, InputCapture, RELEASE_CHORD,
};
use crate::pipeline::Pipeline;
use crate::renderer::{describe_scale, is_exact_scale, FrameSlot, Presenter, VideoView};
use crate::session::{ClientSession, ConnectionState, TransportEndpoints};
use crate::tiles::TileStore;

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

pub struct AppInit {
    pub config: ClientConfig,
    pub session: ClientSession,
    /// Kept alive so the channels stay open until a transport claims them.
    pub transport: Option<TransportEndpoints>,
    pub slot: Arc<FrameSlot>,
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
}

impl ClientApp {
    pub fn new(cc: &eframe::CreationContext<'_>, init: AppInit) -> Self {
        // `set_visuals` only edits the *current* theme's style, which the
        // system theme preference then overrides. Pin the preference instead:
        // a remote screen belongs on a dark surround, always.
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        let input = InputCapture::new(init.session.input_tx.clone());
        let show_diagnostics = init.config.show_diagnostics;
        let auto_snap_scale = init.config.auto_snap_scale;
        let fullscreen = init.config.start_fullscreen;
        if fullscreen {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
        }
        // The supervisor is built with `StreamCaps::default()` before the
        // persisted config is known; seed the persisted fps choice into it
        // now so the *first* connect carries it too, not just ones made after
        // the toolbar combo is touched.
        let mut supervisor = init.supervisor;
        if let Some(sup) = supervisor.as_mut() {
            sup.set_preferred_fps(init.config.preferred_fps);
        }

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
            presenter: Presenter::new(),
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
        }
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
                // With background capture on, keep the hook installed across
                // connection churn (connecting, WAN stalls, reconnects) so the
                // capture path is live again the moment the session is. Nothing
                // is swallowed meanwhile — the hook gates that on the session
                // being live — so local typing works right through an outage.
                // Without it, releasing here is what hands the keyboard back.
                if !self.effective_background_capture() {
                    self.input.stop_capture();
                }
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

                // A format change invalidates decoder state; the decode thread
                // recovers on the next keyframe, so ask for one now.
                self.session.send_control(ControlMsg::RequestKeyframe);
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
            }
            other => tracing::debug!("unhandled control message: {other:?}"),
        }
    }

    /// Whether keys should keep reaching the host while DirectDesk is in the
    /// background: the persisted opt-in, or `--hold-capture` forcing it on for
    /// the run.
    fn effective_background_capture(&self) -> bool {
        self.config.capture_in_background || self.hold_capture
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

        let mut chord = false;
        ctx.input(|i| {
            for event in &i.events {
                if let egui::Event::Key {
                    key,
                    physical_key,
                    pressed: true,
                    modifiers,
                    ..
                } = event
                {
                    // The physical key is what the user actually pressed; a
                    // remapped layout can report something else as `key`.
                    chord |= is_release_chord(physical_key.unwrap_or(*key), *modifiers);
                }
            }
        });
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
    fn enforce_capture_invariants(&mut self, ctx: &egui::Context) {
        if !self.input.is_capturing() {
            return;
        }
        let (focused, minimized, closing) = ctx.input(|i| {
            (
                i.focused,
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
                    ui.add(
                        egui::TextEdit::singleline(&mut self.address_input)
                            .hint_text("hostname or IP")
                            .desired_width(240.0),
                    );
                    ui.end_row();

                    ui.label("UDP port");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.udp_port_input).desired_width(90.0),
                    );
                    ui.end_row();

                    ui.label("Display name");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name_input)
                            .hint_text("shown on the host")
                            .desired_width(240.0),
                    );
                    ui.end_row();

                    ui.label("Pairing code");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.code_input)
                            .hint_text("8 digits — first time only")
                            .desired_width(240.0),
                    );
                    ui.end_row();

                    ui.label("Quality");
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
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.weak("Enter the code shown on the host's 'Pair new device' window.");
            ui.weak("Leave the code blank to reconnect to a host you have paired before.");

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

    /// Shown while the transport driver is racing routes and running the
    /// handshake: a spinner and the live lifecycle label, plus a way out.
    fn connecting_view(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(120.0);
            ui.add(egui::Spinner::new().size(48.0));
            ui.add_space(16.0);
            ui.heading(self.state.label());
            ui.weak(format!("Host {}", self.config.host_address));
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
            self.forward_pointer_events(&events, viewport, &view);
            self.forward_key_events(&events);
        }
        self.input.pump();
    }

    /// Forward keystrokes captured through the window (egui) while it is the
    /// foreground window — the reliable path there, since Windows starves the
    /// global low-level hook when our GPU-heavy window is focused. Gated on
    /// capture being enabled so the toggle / release chord still governs it.
    fn forward_key_events(&mut self, events: &[egui::Event]) {
        if !self.input.is_capturing() {
            return;
        }
        for event in events {
            if let egui::Event::Key {
                key,
                physical_key,
                pressed,
                modifiers,
                ..
            } = event
            {
                // The release chord is ours, not the host's — swallow both the
                // press and the release so no half of it lands on the remote
                // machine (`reconcile_capture` already acted on it).
                if is_release_chord(physical_key.unwrap_or(*key), *modifiers) {
                    continue;
                }
                self.input
                    .on_key_event(*physical_key, *key, *pressed, *modifiers);
            }
        }
    }

    fn forward_pointer_events(
        &mut self,
        events: &[egui::Event],
        viewport: egui::Rect,
        view: &VideoView,
    ) {
        for event in events {
            match event {
                egui::Event::PointerMoved(pos) if viewport.contains(*pos) => {
                    self.input.on_pointer_moved(*pos, view);
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } if viewport.contains(*pos) => {
                    self.input.on_pointer_button(*pos, view, *button, *pressed);
                }
                egui::Event::MouseWheel { unit, delta, .. } => {
                    let Some(pos) = self.pointer else { continue };
                    if !viewport.contains(pos) {
                        continue;
                    }
                    if delta.y != 0.0 {
                        self.input
                            .on_wheel(pos, view, wheel_delta(*unit, delta.y), false);
                    }
                    if delta.x != 0.0 {
                        self.input
                            .on_wheel(pos, view, wheel_delta(*unit, delta.x), true);
                    }
                }
                _ => {}
            }
        }
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
        diagnostics::show(
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
            },
        );
        self.show_diagnostics = open;
        self.tiles_window(ctx);
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

        // Wait for focus: the window is not focused on the first frame, and
        // `enforce_capture_invariants` would (correctly) drop capture again.
        // `--hold-capture` installs without waiting for focus (the whole point
        // is to survive not having it); plain `--capture-on-start` still waits
        // for the first focused frame.
        if self.capture_on_start && (self.hold_capture || ctx.input(|i| i.focused)) {
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
        if !self.user_released && !self.capture_on_start {
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
                let active = ctx.input(|i| i.focused && !i.viewport().minimized.unwrap_or(false));
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
        // Route capture by focus: when we're foreground the egui key path owns
        // it and the low-level hook passes through; when not, the hook forwards.
        self.input.set_window_foreground(ctx.input(|i| i.focused));
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
        self.enforce_capture_invariants(ctx);
        self.presenter.update(ctx, &self.slot);
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
            self.input.stop_capture();
            self.persist();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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

/// The one wording for "we gave the keyboard back", used by every release path
/// so the way out is always spelled out.
fn released_notice() -> String {
    format!("Input released ({RELEASE_CHORD}) — click Capture input or press the chord to resume")
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
