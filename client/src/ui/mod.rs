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
use std::time::Instant;

use directdesk_shared::protocol::{ControlMsg, QualityMode};
use directdesk_shared::stats::{validate_stats, ConnStats, TransportRoute};

use crate::config::ClientConfig;
use crate::connect::ConnectSupervisor;
use crate::input_capture::{wheel_delta, InputCapture, RELEASE_CHORD};
use crate::pipeline::Pipeline;
use crate::renderer::{FrameSlot, Presenter, VideoView};
use crate::session::{ClientSession, ConnectionState, TransportEndpoints};

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
}

pub struct ClientApp {
    config: ClientConfig,
    session: ClientSession,
    _transport: Option<TransportEndpoints>,
    slot: Arc<FrameSlot>,
    pipeline: Pipeline,
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
    tcp_port_input: String,
    name_input: String,
    code_input: String,
    /// Set when the connect form fails validation; shown under the form.
    form_error: Option<String>,
    /// Connect once on the first frame, from an explicit CLI `--host`.
    auto_connect: bool,
    show_diagnostics: bool,
    fullscreen: bool,
    notice: Option<String>,
    /// Cached once per frame: `MouseWheel` events carry no position.
    pointer: Option<egui::Pos2>,
    /// Periodic counter dump, so a headless run is still verifiable.
    metrics_logged_at: Instant,
    /// Pending `--capture-on-start`; consumed on the first frame, because the
    /// hook must be installed from the thread running the message pump.
    capture_on_start: bool,
}

impl ClientApp {
    pub fn new(cc: &eframe::CreationContext<'_>, init: AppInit) -> Self {
        // `set_visuals` only edits the *current* theme's style, which the
        // system theme preference then overrides. Pin the preference instead:
        // a remote screen belongs on a dark surround, always.
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        let input = InputCapture::new(init.session.input_tx.clone());
        let show_diagnostics = init.config.show_diagnostics;
        let fullscreen = init.config.start_fullscreen;
        if fullscreen {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(true));
        }
        Self {
            address_input: init.config.host_address.clone(),
            udp_port_input: init.config.udp_port.to_string(),
            tcp_port_input: init.config.tcp_port.to_string(),
            name_input: init.display_name,
            code_input: init.initial_pair_code.unwrap_or_default(),
            form_error: None,
            auto_connect: init.auto_connect,
            config: init.config,
            session: init.session,
            _transport: init.transport,
            slot: init.slot,
            pipeline: init.pipeline,
            presenter: Presenter::new(),
            input,
            mode: init.mode,
            supervisor: init.supervisor,
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
            pointer: None,
            metrics_logged_at: Instant::now(),
            capture_on_start: init.capture_on_start,
        }
    }

    /// Dump the live counters every couple of seconds. This is what makes a
    /// `--loopback-demo` run verifiable without touching the window.
    fn log_metrics(&mut self) {
        if self.metrics_logged_at.elapsed() < std::time::Duration::from_secs(2) {
            return;
        }
        self.metrics_logged_at = Instant::now();
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
            "client metrics"
        );
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
                self.input.stop_capture();
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
            ControlMsg::Bye { reason } => {
                self.state = ConnectionState::Failed(format!("Host disconnected: {reason}"));
                self.route = None;
                self.input.stop_capture();
                self.presenter.reset();
            }
            other => tracing::debug!("unhandled control message: {other:?}"),
        }
    }

    /// Capture must never survive losing focus, minimizing, or closing.
    fn enforce_capture_invariants(&mut self, ctx: &egui::Context) {
        if self.input.poll_chord_release() {
            self.notice = Some(format!("Input released ({RELEASE_CHORD})"));
        }
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
        if !focused || minimized || closing {
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
                self.input.toggle_capture();
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
            ui.toggle_value(&mut self.show_diagnostics, "Diagnostics");

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

                    ui.label("TCP port");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tcp_port_input).desired_width(90.0),
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
                        .selected_text(quality_label(current))
                        .show_ui(ui, |ui| {
                            for mode in [
                                QualityMode::TextDesktop,
                                QualityMode::Balanced,
                                QualityMode::Motion,
                                QualityMode::LowBandwidth,
                            ] {
                                if ui
                                    .selectable_label(current == mode, quality_label(mode))
                                    .clicked()
                                {
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
            tcp_port: &self.tcp_port_input,
            pairing_code: &self.code_input,
            display_name: &self.name_input,
            quality: self.config.quality_mode,
            default_udp_port: self.config.udp_port,
            default_tcp_port: self.config.tcp_port,
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
        self.config.tcp_port = request.tcp_port;
        self.config.display_name = request.display_name.clone();
        self.address_input = request.host.clone();
        self.udp_port_input = request.udp_port.to_string();
        self.tcp_port_input = request.tcp_port.to_string();
        self.config.save();

        let Some(supervisor) = self.supervisor.as_mut() else {
            self.form_error =
                Some("no transport is available — cannot connect in this build".into());
            return;
        };

        tracing::info!(
            host = %request.host,
            udp = request.udp_port,
            tcp = request.tcp_port,
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
        self.route = None;
        self.state = ConnectionState::Disconnected;
    }

    fn streaming_view(&mut self, ui: &mut egui::Ui) {
        let (viewport, view) = self.presenter.draw(ui);

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
        }
        self.input.pump();
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

    fn diagnostics_window(&mut self, ctx: &egui::Context) {
        if !self.show_diagnostics {
            return;
        }
        let mut open = true;
        let description = self.pipeline.status.description();
        let error = self.pipeline.status.error();
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
                demo_mode: self.mode == SourceMode::LoopbackDemo,
            },
        );
        self.show_diagnostics = open;
    }

    fn persist(&mut self) {
        self.config.show_diagnostics = self.show_diagnostics;
        self.config.start_fullscreen = self.fullscreen;
        self.config.save();
    }
}

impl eframe::App for ClientApp {
    /// State only — no drawing here.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Re-asserted every frame: eframe/egui-winit re-applies the system
        // theme during startup, and a remote screen belongs on a dark surround.
        ctx.set_theme(egui::ThemePreference::Dark);

        // Wait for focus: the window is not focused on the first frame, and
        // `enforce_capture_invariants` would (correctly) drop capture again.
        if self.capture_on_start && ctx.input(|i| i.focused) {
            self.capture_on_start = false;
            tracing::warn!("--capture-on-start: installing the keyboard hook");
            self.input.start_capture();
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
        self.drain_session();
        self.enforce_capture_invariants(ctx);
        self.presenter.update(ctx, &self.slot);
        self.log_metrics();

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

        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui, &ctx));

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

pub fn quality_label(mode: QualityMode) -> &'static str {
    match mode {
        QualityMode::TextDesktop => "Text / desktop",
        QualityMode::Balanced => "Balanced",
        QualityMode::Motion => "Motion",
        QualityMode::LowBandwidth => "Low bandwidth",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_quality_mode_has_a_label() {
        for mode in [
            QualityMode::TextDesktop,
            QualityMode::Balanced,
            QualityMode::Motion,
            QualityMode::LowBandwidth,
        ] {
            assert!(!quality_label(mode).is_empty());
        }
    }
}
