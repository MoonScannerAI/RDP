//! The status window.
//!
//! Everything on screen is read from [`StatusSnapshot`], which the listener
//! writes and nobody else invents. If a number is not known the window says so
//! rather than showing a plausible zero, and the route label is whatever the
//! transport actually reports — never "direct" by assumption.
//!
//! Closing the window hides it. The only way to stop serving is the remote
//! access toggle, and the only way to exit is the tray's Quit item.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::crypto::HostIdentity;
use directdesk_shared::protocol::QualityMode;

use super::AppShared;
use crate::config::{HostConfig, MAX_BITRATE_KBPS, MAX_TARGET_FPS, MIN_BITRATE_KBPS};
use crate::net::{NetCommand, NetConfig, NetEvent, NetHandle, NetService, StatusSnapshot};

/// How many recent events the window keeps.
const LOG_LIMIT: usize = 200;

/// Run the host UI. Blocks until the tray's Quit item is used.
pub fn run(
    cfg: HostConfig,
    shared: Arc<AppShared>,
    rt: tokio::runtime::Handle,
    identity: Arc<HostIdentity>,
    store: Arc<dyn SecretStore>,
    start_hidden: bool,
) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 760.0])
            .with_min_inner_size([620.0, 460.0])
            .with_title("DirectDesk Host"),
        ..Default::default()
    };

    eframe::run_native(
        "DirectDesk Host",
        options,
        Box::new(move |cc| {
            Ok(Box::new(HostApp::new(
                cc,
                cfg,
                shared,
                rt,
                identity,
                store,
                start_hidden,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("the host window failed: {e}"))
}

/// Editable copies of the settings, so a half-typed port never reaches the
/// listener.
struct Edit {
    remote_access: bool,
    udp_port: u16,
    quality: QualityMode,
    cap_enabled: bool,
    cap_kbps: u32,
    bitrate_kbps: u32,
    fps: u32,
    start_minimized: bool,
}

impl Edit {
    fn from(cfg: &HostConfig) -> Self {
        Self {
            remote_access: cfg.remote_access_enabled,
            udp_port: cfg.udp_port,
            quality: cfg.quality_mode,
            cap_enabled: cfg.bitrate_cap_kbps.is_some(),
            cap_kbps: cfg.bitrate_cap_kbps.unwrap_or(cfg.bitrate_kbps),
            bitrate_kbps: cfg.bitrate_kbps,
            fps: cfg.target_fps,
            start_minimized: cfg.start_minimized,
        }
    }

    fn cap(&self) -> Option<u32> {
        self.cap_enabled.then_some(self.cap_kbps)
    }
}

pub struct HostApp {
    shared: Arc<AppShared>,
    cfg: HostConfig,
    rt: tokio::runtime::Handle,
    identity: Arc<HostIdentity>,
    store: Arc<dyn SecretStore>,
    net: Option<NetHandle>,
    /// Set while an old listener is draining before a new one binds.
    restarting: bool,
    log: VecDeque<(Duration, String)>,
    started: Instant,
    edit: Edit,
}

impl HostApp {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cc: &eframe::CreationContext<'_>,
        cfg: HostConfig,
        shared: Arc<AppShared>,
        rt: tokio::runtime::Handle,
        identity: Arc<HostIdentity>,
        store: Arc<dyn SecretStore>,
        start_hidden: bool,
    ) -> Self {
        // Captured before the first frame so the tray can show or close a
        // window that has never been drawn — which is the whole point of
        // `--minimized`.
        shared.set_ctx(cc.egui_ctx.clone());
        if start_hidden {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        let mut app = Self {
            edit: Edit::from(&cfg),
            shared,
            cfg,
            rt,
            identity,
            store,
            net: None,
            restarting: false,
            log: VecDeque::new(),
            started: Instant::now(),
        };
        if app.cfg.remote_access_enabled {
            app.start_listener();
        } else {
            app.note("remote access is off; not listening");
        }
        app
    }

    fn note(&mut self, text: impl Into<String>) {
        let text = text.into();
        tracing::debug!("ui: {text}");
        self.log.push_back((self.started.elapsed(), text));
        while self.log.len() > LOG_LIMIT {
            self.log.pop_front();
        }
    }

    fn start_listener(&mut self) {
        let net_cfg = NetConfig::from_host_config(&self.cfg);
        let handle = NetService::start(
            net_cfg,
            &self.rt,
            self.identity.clone(),
            self.store.clone(),
            self.shared.status.clone(),
            self.shared.pairing.clone(),
        );
        self.shared.set_commander(Some(handle.commander()));
        self.shared.set_remote_access(true);
        self.net = Some(handle);
        self.note(format!("listener starting on UDP {}", self.cfg.udp_port));
    }

    /// Stop the listener; a restart follows once the port is actually free.
    fn stop_listener(&mut self, restart: bool) {
        if let Some(handle) = &self.net {
            handle.shutdown();
        }
        self.shared.set_commander(None);
        self.restarting = restart;
        if !restart {
            self.shared.set_remote_access(false);
        }
        self.note(if restart {
            "restarting listener"
        } else {
            "stopping listener"
        });
    }

    /// Rebinding has to wait for the old endpoint to release the port.
    fn poll_restart(&mut self) {
        if !self.restarting {
            return;
        }
        let drained = self.net.as_ref().is_none_or(NetHandle::is_stopped);
        if !drained {
            return;
        }
        self.net = None;
        self.restarting = false;
        if self.cfg.remote_access_enabled {
            self.start_listener();
        } else {
            self.shared.set_remote_access(false);
            self.note("listener stopped");
        }
    }

    fn drain_events(&mut self) {
        let mut lines = Vec::new();
        if let Some(net) = &self.net {
            while let Some(ev) = net.try_event() {
                lines.push(describe(&ev));
            }
        }
        for line in lines {
            self.note(line);
        }
    }

    fn apply_settings(&mut self) {
        let port_changed = self.edit.udp_port != self.cfg.udp_port;
        let access_changed = self.edit.remote_access != self.cfg.remote_access_enabled;

        self.cfg.remote_access_enabled = self.edit.remote_access;
        self.cfg.udp_port = self.edit.udp_port;
        self.cfg.quality_mode = self.edit.quality;
        self.cfg.bitrate_cap_kbps = self.edit.cap();
        self.cfg.bitrate_kbps = self.edit.bitrate_kbps;
        self.cfg.target_fps = self.edit.fps;
        self.cfg.start_minimized = self.edit.start_minimized;
        self.cfg = std::mem::take(&mut self.cfg).sanitized();
        self.edit = Edit::from(&self.cfg);
        self.cfg.save();
        self.note("settings saved");

        // A running listener can take these three live; the rest need a rebind.
        if let Some(net) = &self.net {
            net.command(NetCommand::SetQualityMode(self.cfg.quality_mode));
            net.command(NetCommand::SetBitrateCap(self.cfg.bitrate_cap_kbps));
            net.command(NetCommand::SetTargetFps(self.cfg.target_fps));
        }

        // The frame rate is deliberately NOT in this condition. This host is
        // routinely configured from inside a remote session on the machine
        // itself: adding fps here would tear down the QUIC listener on "Save
        // and apply" and disconnect the very session doing the configuring,
        // with nobody at the far end to reconnect it. The rate is a live-only
        // control — it goes out as `SetTargetFps` above and the pipeline
        // rebuilds just its encoder, leaving the listener alone.
        if access_changed || port_changed {
            match (self.cfg.remote_access_enabled, self.net.is_some()) {
                (true, true) => self.stop_listener(true),
                (true, false) => self.start_listener(),
                (false, true) => self.stop_listener(true),
                (false, false) => self.shared.set_remote_access(false),
            }
        }
    }
}

fn describe(ev: &NetEvent) -> String {
    match ev {
        NetEvent::Listening { bound, addresses } => {
            format!(
                "listening on {bound} ({} address(es) advertised)",
                addresses.len()
            )
        }
        NetEvent::ListenFailed { detail } => format!("listen FAILED: {detail}"),
        NetEvent::Stopped => "listener stopped".into(),
        NetEvent::PairingArmed { ttl_ms, .. } => {
            format!("pairing window open for {} s", ttl_ms / 1000)
        }
        NetEvent::PairingCleared => "pairing window closed".into(),
        NetEvent::Paired { name, fingerprint } => format!("paired with {name} ({fingerprint})"),
        NetEvent::ClientConnected {
            name,
            fingerprint,
            peer,
        } => {
            format!("{name} connected from {peer} ({fingerprint})")
        }
        NetEvent::ClientDisconnected { reason } => format!("client disconnected: {reason}"),
        NetEvent::AuthRejected { peer, detail } => format!("REJECTED {peer}: {detail}"),
        NetEvent::LockedOut { peer, for_ms } => {
            format!("LOCKED OUT {peer} for {} s", for_ms / 1000)
        }
        NetEvent::Warning { detail } => format!("warning: {detail}"),
    }
}

impl eframe::App for HostApp {
    /// Runs even while the window is hidden, which is what keeps a tray-only
    /// host from silently falling behind on its own state.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_restart();
        self.drain_events();

        if ctx.input(|i| i.viewport().close_requested()) && !self.shared.quit_requested() {
            // The window is a view, not the application. Closing it hides it.
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Live stats and a pairing countdown both need a steady tick.
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let status = self.shared.status.lock().clone();
        let now_ms = self.shared.now_ms();
        let pairing = self.shared.pairing.snapshot(now_ms);

        egui::Frame::central_panel(root.style()).show(root, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    self.header(ui, &status);
                    ui.add_space(8.0);
                    self.identity_panel(ui, &status);
                    ui.add_space(8.0);
                    self.pairing_panel(ui, pairing.as_ref());
                    ui.add_space(8.0);
                    self.client_panel(ui, &status);
                    ui.add_space(8.0);
                    self.pipeline_panel(ui, &status);
                    ui.add_space(8.0);
                    self.stats_panel(ui, &status);
                    ui.add_space(8.0);
                    self.settings_panel(ui);
                    ui.add_space(8.0);
                    self.log_panel(ui);
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.button("Hide to tray").clicked() {
                            self.shared.hide_window();
                        }
                        ui.label("Closing this window hides it. Quit from the tray icon.");
                    });
                });
        });
    }
}

// ---------------------------------------------------------------------------
// Panels
// ---------------------------------------------------------------------------

impl HostApp {
    fn header(&mut self, ui: &mut egui::Ui, status: &StatusSnapshot) {
        let view = super::tray_view_of(status, self.shared.remote_access());
        let colour = match view.state {
            super::TrayState::Disabled => egui::Color32::from_rgb(140, 146, 154),
            super::TrayState::Starting => egui::Color32::from_rgb(140, 160, 186),
            super::TrayState::Listening => egui::Color32::from_rgb(64, 148, 236),
            super::TrayState::Connected => egui::Color32::from_rgb(58, 196, 118),
            super::TrayState::Problem => egui::Color32::from_rgb(226, 106, 62),
        };
        ui.horizontal(|ui| {
            ui.heading("DirectDesk Host");
            ui.add_space(12.0);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 6.0, colour);
            ui.label(
                egui::RichText::new(&view.status_line)
                    .color(colour)
                    .strong(),
            );
        });
        if !self.shared.remote_access() {
            ui.colored_label(
                egui::Color32::from_rgb(226, 106, 62),
                "Remote access is OFF — no port is open and nobody can connect.",
            );
        }
    }

    fn identity_panel(&mut self, ui: &mut egui::Ui, status: &StatusSnapshot) {
        egui::CollapsingHeader::new("This host")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("identity")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Name");
                        ui.label(&status.host_name);
                        ui.end_row();

                        ui.strong("Identity key");
                        ui.monospace(&status.host_fingerprint);
                        ui.end_row();

                        ui.strong("TLS pin");
                        ui.monospace(&status.tls_pin);
                        ui.end_row();

                        ui.strong("Paired clients");
                        ui.label(status.trusted_clients.to_string());
                        ui.end_row();

                        ui.strong("Bound socket");
                        match status.bound {
                            Some(b) => ui.monospace(b.to_string()),
                            None => ui.label("not listening"),
                        };
                        ui.end_row();
                    });

                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Reachable at (best effort — the client needs one of these):",
                    )
                    .small(),
                );
                if status.addresses.is_empty() {
                    ui.label("  — no addresses discovered —");
                }
                for addr in &status.addresses {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("  {addr}"));
                        if ui.small_button("copy").clicked() {
                            ui.ctx().copy_text(addr.to_string());
                        }
                    });
                }
                if let Some(err) = &status.last_error {
                    ui.colored_label(
                        egui::Color32::from_rgb(226, 106, 62),
                        format!("Error: {err}"),
                    );
                }
            });
    }

    fn pairing_panel(&mut self, ui: &mut egui::Ui, pairing: Option<&crate::net::PairingDisplay>) {
        egui::CollapsingHeader::new("Pairing")
            .default_open(true)
            .show(ui, |ui| match pairing {
                Some(p) => {
                    ui.label("Type this code on the client:");
                    ui.label(
                        egui::RichText::new(&p.grouped)
                            .monospace()
                            .size(38.0)
                            .strong()
                            .color(egui::Color32::from_rgb(64, 148, 236)),
                    );
                    let total = directdesk_shared::crypto::pairing::PAIRING_TTL_MS as f32;
                    let fraction = (p.remaining_ms as f32 / total).clamp(0.0, 1.0);
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .text(format!("{} s left", p.remaining_ms / 1000)),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel pairing").clicked() {
                            self.shared.send(NetCommand::CancelPairing);
                        }
                        ui.label("The code works once and expires on its own.");
                    });
                }
                None => {
                    ui.horizontal(|ui| {
                        let enabled = self.net.is_some() && self.shared.remote_access();
                        if ui
                            .add_enabled(enabled, egui::Button::new("Pair new device"))
                            .on_disabled_hover_text("Turn remote access on first")
                            .clicked()
                            && !self.shared.send(NetCommand::ArmPairing)
                        {
                            self.note("could not arm pairing: the listener is not running");
                        }
                        ui.label("Opens a 120-second window with a single-use 8-digit code.");
                    });
                }
            });
    }

    fn client_panel(&mut self, ui: &mut egui::Ui, status: &StatusSnapshot) {
        egui::CollapsingHeader::new("Client")
            .default_open(true)
            .show(ui, |ui| match &status.client {
                Some(c) => {
                    egui::Grid::new("client")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Name");
                            ui.label(&c.name);
                            ui.end_row();
                            ui.strong("Identity key");
                            ui.monospace(&c.fingerprint);
                            ui.end_row();
                            ui.strong("Route");
                            ui.label(c.route.label());
                            ui.end_row();
                            ui.strong("Address");
                            ui.monospace(c.peer.to_string());
                            ui.end_row();
                            ui.strong("Connected for");
                            ui.label(format_duration(c.connected_at.elapsed()));
                            ui.end_row();
                        });
                    if ui.button("Disconnect client").clicked()
                        && !self.shared.send(NetCommand::DisconnectClient)
                    {
                        self.note("disconnect failed: the listener is not running");
                    }
                }
                None => {
                    ui.label("Nobody is connected.");
                }
            });
    }

    fn pipeline_panel(&mut self, ui: &mut egui::Ui, status: &StatusSnapshot) {
        egui::CollapsingHeader::new("Capture pipeline")
            .default_open(true)
            .show(ui, |ui| {
                match &status.encoder {
                    Some(e) => {
                        ui.monospace(e);
                    }
                    None => {
                        ui.label("The pipeline starts when the first client connects.");
                    }
                }
                if let Some((w, h)) = status.resolution {
                    ui.label(format!("Capturing {w}×{h}"));
                }
                if let Some(state) = &status.pipeline_state {
                    ui.label(format!("State: {state}"));
                }
                if status.secure_desktop {
                    ui.colored_label(
                        egui::Color32::from_rgb(226, 106, 62),
                        "Secure desktop is up (UAC or lock screen) — capture is paused and all \
                     client input has been released.",
                    );
                }
            });
    }

    fn stats_panel(&mut self, ui: &mut egui::Ui, status: &StatusSnapshot) {
        egui::CollapsingHeader::new("Live statistics")
            .default_open(true)
            .show(ui, |ui| {
                if status.client.is_none() {
                    ui.label("No session — nothing to measure.");
                    return;
                }
                let t = &status.transport;
                let p = &status.pipeline;
                egui::Grid::new("stats")
                    .num_columns(4)
                    .spacing([18.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("RTT");
                        ui.monospace(format!("{:.1} ms", t.rtt_ms));
                        ui.strong("Jitter");
                        ui.monospace(format!("{:.1} ms", t.jitter_ms));
                        ui.end_row();

                        ui.strong("Loss");
                        ui.monospace(format!("{:.2} %", t.loss * 100.0));
                        ui.strong("Link");
                        ui.monospace(format!("{} kbps", t.bandwidth_kbps));
                        ui.end_row();

                        ui.strong("Capture");
                        ui.monospace(format!("{:.1} fps", p.fps_capture));
                        ui.strong("Encode");
                        ui.monospace(format!("{:.1} fps", p.fps_encode));
                        ui.end_row();

                        ui.strong("Encoder out");
                        ui.monospace(format!("{} kbps", p.bitrate_kbps));
                        ui.strong("Target");
                        ui.monospace(format!("{} kbps", status.target_kbps));
                        ui.end_row();

                        ui.strong("Quality");
                        ui.monospace(status.quality_mode.map_or("—", quality_label));
                        ui.strong("Throughput");
                        ui.monospace(format!("{} kbps (1s)", status.delivery.throughput_kbps()));
                        ui.end_row();

                        ui.strong("Delivered");
                        ui.monospace(format!(
                            "{:.0} % (1s)",
                            status.delivery.delivery_ratio() * 100.0
                        ));
                        ui.strong("Backpressure");
                        ui.monospace(format!(
                            "{:.1} % (1s)",
                            status.delivery.backpressure_ratio() * 100.0
                        ));
                        ui.end_row();

                        ui.strong("Frames sent");
                        ui.monospace(format!("{} (total)", status.frames_sent));
                        ui.strong("Bytes sent");
                        ui.monospace(format!("{} (total)", format_bytes(status.bytes_sent)));
                        ui.end_row();

                        ui.strong("Skipped (stale)");
                        ui.monospace(status.frames_coalesced.to_string());
                        ui.strong("Pipeline");
                        ui.monospace(format!("{:.2} ms/frame", p.pipeline_ms));
                        ui.end_row();

                        ui.strong("Paced bursts");
                        ui.monospace(status.pace_deadline_bursts.to_string());
                        ui.strong("Slowest frame");
                        ui.monospace(format!("{} ms (1s)", status.emit_ms_max));
                        ui.end_row();

                        ui.strong("Unfragmentable");
                        ui.monospace(status.frames_unfragmentable.to_string());
                        ui.strong("Skipped (full)");
                        ui.monospace(status.frames_backpressured.to_string());
                        ui.end_row();
                    });
                ui.label(
                egui::RichText::new(
                    "\"Skipped\" counts frames the encoder produced while the link was behind — \
                     stale means a newer frame superseded it, full means the link had no room \
                     for a whole one. The newest frame is always the one sent. \"Paced bursts\" \
                     are big frames sent all at once because spreading them would have taken \
                     too long.",
                )
                .small(),
            );
            });
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Settings")
            .default_open(false)
            .show(ui, |ui| {
                ui.checkbox(&mut self.edit.remote_access, "Remote access enabled");
                ui.horizontal(|ui| {
                    ui.label("UDP port");
                    ui.add(egui::DragValue::new(&mut self.edit.udp_port).range(1_024..=65_535));
                    ui.label("(changing this rebinds the listener)");
                });
                ui.horizontal(|ui| {
                    ui.label("Quality mode");
                    egui::ComboBox::from_id_salt("quality")
                        .selected_text(quality_label(self.edit.quality))
                        .show_ui(ui, |ui| {
                            for mode in [
                                QualityMode::TextDesktop,
                                QualityMode::Balanced,
                                QualityMode::Motion,
                                QualityMode::LowBandwidth,
                            ] {
                                ui.selectable_value(
                                    &mut self.edit.quality,
                                    mode,
                                    quality_label(mode),
                                );
                            }
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("Max frame rate");
                    ui.add(
                        egui::DragValue::new(&mut self.edit.fps)
                            .range(10..=MAX_TARGET_FPS)
                            .suffix(" fps"),
                    );
                    ui.label(
                        "(fewer frames per second at the same bitrate means more bits in each \
                         frame — sharper still text)",
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Starting bitrate");
                    ui.add(
                        egui::DragValue::new(&mut self.edit.bitrate_kbps)
                            .range(MIN_BITRATE_KBPS..=MAX_BITRATE_KBPS)
                            .suffix(" kbps"),
                    );
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.edit.cap_enabled, "Cap bitrate at");
                    ui.add_enabled(
                        self.edit.cap_enabled,
                        egui::DragValue::new(&mut self.edit.cap_kbps)
                            .range(MIN_BITRATE_KBPS..=MAX_BITRATE_KBPS)
                            .suffix(" kbps"),
                    );
                    ui.label("(the adaptive controller never exceeds this)");
                });
                ui.checkbox(&mut self.edit.start_minimized, "Start hidden in the tray");

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save and apply").clicked() {
                        self.apply_settings();
                    }
                    if ui.button("Revert").clicked() {
                        self.edit = Edit::from(&self.cfg);
                    }
                    if let Some(path) = crate::config::config_path() {
                        ui.label(egui::RichText::new(path.display().to_string()).small());
                    }
                });
            });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(format!("Activity ({})", self.log.len()))
            .default_open(false)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for (at, line) in &self.log {
                            ui.monospace(format!("[{:>7}] {line}", format_duration(*at)));
                        }
                    });
            });
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

pub fn quality_label(mode: QualityMode) -> &'static str {
    match mode {
        QualityMode::TextDesktop => "Text / desktop",
        QualityMode::Balanced => "Balanced",
        QualityMode::Motion => "Motion",
        QualityMode::LowBandwidth => "Low bandwidth",
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3_600 {
        format!("{}h{:02}m", secs / 3_600, (secs % 3_600) / 60)
    } else {
        format!("{}:{:02}", secs / 60, secs % 60)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(format_duration(Duration::from_secs(5)), "0:05");
        assert_eq!(format_duration(Duration::from_secs(65)), "1:05");
        assert_eq!(format_duration(Duration::from_secs(3_725)), "1h02m");
    }

    #[test]
    fn byte_counts_read_naturally() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2_048), "2.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn every_quality_mode_has_a_label() {
        for m in [
            QualityMode::TextDesktop,
            QualityMode::Balanced,
            QualityMode::Motion,
            QualityMode::LowBandwidth,
        ] {
            assert!(!quality_label(m).is_empty());
        }
    }

    #[test]
    fn edit_state_roundtrips_the_config() {
        let cfg = HostConfig {
            udp_port: 50_000,
            quality_mode: QualityMode::Motion,
            bitrate_cap_kbps: Some(4_000),
            target_fps: 15,
            start_minimized: true,
            ..HostConfig::default()
        };
        let e = Edit::from(&cfg);
        assert_eq!(e.udp_port, 50_000);
        assert_eq!(e.quality, QualityMode::Motion);
        assert_eq!(e.cap(), Some(4_000));
        assert_eq!(e.fps, 15);
        assert!(e.start_minimized);

        let uncapped = HostConfig {
            bitrate_cap_kbps: None,
            ..HostConfig::default()
        };
        assert_eq!(Edit::from(&uncapped).cap(), None);
    }

    #[test]
    fn event_descriptions_are_specific() {
        let text = describe(&NetEvent::AuthRejected {
            peer: "10.0.0.9".parse().unwrap(),
            detail: "client is not paired with this host".into(),
        });
        assert!(text.contains("10.0.0.9"));
        assert!(text.contains("REJECTED"));

        let text = describe(&NetEvent::ListenFailed {
            detail: "address in use".into(),
        });
        assert!(text.contains("FAILED"), "{text}");
    }
}
