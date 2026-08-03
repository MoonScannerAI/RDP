//! The host's user interface: an eframe status window plus a tray icon.
//!
//! # Two independent surfaces
//!
//! The tray runs on its **own** thread with its **own** Win32 message pump
//! ([`tray`]), not inside the egui event loop. That is deliberate: the contract
//! is that the tray icon is present whenever the host is running, and a tray
//! that lives inside a hidden window's redraw path is a tray that quietly stops
//! responding the moment the window is minimised. "Disconnect client" in
//! particular must work with no window on screen, so the tray thread talks to
//! the listener directly rather than through the UI.
//!
//! Both surfaces read the same [`AppShared`], so what the tooltip says and what
//! the window says can never disagree.
//!
//! # Honesty
//!
//! There is no hidden mode. The tray icon is visible whenever the process is
//! running; its colour and tooltip report exactly one of *remote access off*,
//! *listening*, *client connected*, or *problem*. Nothing in this module can
//! put the host into a state where it is serving a desktop without the tray
//! saying so.

pub mod app;
mod icon;
pub mod tray;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::net::{NetCommand, PairingSlot, StatusSnapshot};

pub use app::run;

/// What the tray icon should look like and say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    /// Remote access is switched off. The listener is closed.
    Disabled,
    /// Enabled, but the listener has not finished binding yet.
    ///
    /// Distinct from [`Self::Problem`] on purpose: the first second of every
    /// launch is "not listening", and crying wolf then teaches the user to
    /// ignore the one state that means something is actually wrong.
    Starting,
    /// Listening, nobody connected.
    Listening,
    /// A client is connected and can see the desktop.
    Connected,
    /// Enabled but not working — the bind failed, or the pipeline did.
    Problem,
}

/// A rendered tray view: what the icon shows and what the tooltip says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    pub state: TrayState,
    pub tooltip: String,
    /// Text for the (disabled) first menu entry.
    pub status_line: String,
    /// Whether "Disconnect client" should be clickable.
    pub can_disconnect: bool,
}

/// Everything the window, the tray thread and the listener share.
pub struct AppShared {
    /// Written by the listener, read by everyone.
    pub status: Arc<Mutex<StatusSnapshot>>,
    /// The pairing window, and the monotonic clock the UI counts down against.
    pub pairing: Arc<PairingSlot>,
    /// `None` while the listener is stopped.
    net_cmd: Mutex<Option<mpsc::UnboundedSender<NetCommand>>>,
    /// Captured in `HostApp::new`, so it exists before the first frame and the
    /// tray can show a window that has never been drawn.
    egui_ctx: Mutex<Option<egui::Context>>,
    /// Mirrors `HostConfig::remote_access_enabled` for the tray.
    remote_access: AtomicBool,
    /// Set by the tray's Quit item. The window refuses to close without it.
    quit: AtomicBool,
}

impl std::fmt::Debug for AppShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppShared")
            .field("remote_access", &self.remote_access.load(Ordering::Relaxed))
            .field("quit", &self.quit.load(Ordering::Relaxed))
            .field("listener", &self.net_cmd.lock().is_some())
            .finish()
    }
}

impl AppShared {
    pub fn new(remote_access: bool) -> Arc<Self> {
        Arc::new(Self {
            status: Arc::new(Mutex::new(StatusSnapshot::default())),
            pairing: Arc::new(PairingSlot::new()),
            net_cmd: Mutex::new(None),
            egui_ctx: Mutex::new(None),
            remote_access: AtomicBool::new(remote_access),
            quit: AtomicBool::new(false),
        })
    }

    /// The shared monotonic clock (see [`PairingSlot::now_ms`]).
    pub fn now_ms(&self) -> u64 {
        self.pairing.now_ms()
    }

    pub fn set_commander(&self, cmd: Option<mpsc::UnboundedSender<NetCommand>>) {
        *self.net_cmd.lock() = cmd;
    }

    /// Send a command to the listener. Returns `false` when nothing is
    /// listening, which the caller should surface rather than swallow.
    pub fn send(&self, cmd: NetCommand) -> bool {
        let guard = self.net_cmd.lock();
        match guard.as_ref() {
            Some(tx) => tx.send(cmd).is_ok(),
            None => false,
        }
    }

    pub fn set_ctx(&self, ctx: egui::Context) {
        *self.egui_ctx.lock() = Some(ctx);
    }

    pub fn ctx(&self) -> Option<egui::Context> {
        self.egui_ctx.lock().clone()
    }

    pub fn remote_access(&self) -> bool {
        self.remote_access.load(Ordering::SeqCst)
    }

    pub fn set_remote_access(&self, on: bool) {
        self.remote_access.store(on, Ordering::SeqCst);
    }

    pub fn quit_requested(&self) -> bool {
        self.quit.load(Ordering::SeqCst)
    }

    /// Ask the whole application to exit. Called only by the tray's Quit item.
    pub fn request_quit(&self) {
        self.quit.store(true, Ordering::SeqCst);
        if let Some(ctx) = self.ctx() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            ctx.request_repaint();
        }
    }

    /// Bring the status window back from the tray.
    pub fn show_window(&self) {
        if let Some(ctx) = self.ctx() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        }
    }

    /// Hide the status window without stopping anything.
    pub fn hide_window(&self) {
        if let Some(ctx) = self.ctx() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    /// Render the current state for the tray. Pure given the snapshot, so the
    /// wording is unit-tested rather than eyeballed.
    pub fn tray_view(&self) -> TrayView {
        tray_view_of(&self.status.lock(), self.remote_access())
    }
}

/// The tray's wording, split out so it can be tested without a tray.
pub fn tray_view_of(status: &StatusSnapshot, remote_access: bool) -> TrayView {
    if !remote_access {
        return TrayView {
            state: TrayState::Disabled,
            tooltip: "DirectDesk — remote access is OFF".into(),
            status_line: "Remote access OFF".into(),
            can_disconnect: false,
        };
    }
    if let Some(client) = &status.client {
        let line = format!("{} connected via {}", client.name, client.route.label());
        return TrayView {
            state: TrayState::Connected,
            tooltip: truncate_tooltip(&format!("DirectDesk — {line}")),
            status_line: line,
            can_disconnect: true,
        };
    }
    if !status.listening {
        return match &status.last_error {
            Some(detail) => TrayView {
                state: TrayState::Problem,
                tooltip: truncate_tooltip(&format!("DirectDesk — not listening: {detail}")),
                status_line: format!("Not listening: {detail}"),
                can_disconnect: false,
            },
            None => TrayView {
                state: TrayState::Starting,
                tooltip: "DirectDesk — starting…".into(),
                status_line: "Starting…".into(),
                can_disconnect: false,
            },
        };
    }
    let where_ = status
        .addresses
        .iter()
        .find(|a| !a.ip().is_loopback() && a.is_ipv4())
        .or_else(|| status.addresses.first())
        .map(|a| a.to_string())
        .or_else(|| status.bound.map(|b| b.to_string()))
        .unwrap_or_else(|| "?".into());
    TrayView {
        state: TrayState::Listening,
        tooltip: truncate_tooltip(&format!("DirectDesk — listening on {where_}")),
        status_line: format!("Listening on {where_}"),
        can_disconnect: false,
    }
}

/// Windows silently drops a tray tooltip over 127 characters.
fn truncate_tooltip(s: &str) -> String {
    const LIMIT: usize = 120;
    if s.chars().count() <= LIMIT {
        return s.to_string();
    }
    let mut out: String = s.chars().take(LIMIT - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ClientInfo;
    use directdesk_shared::stats::TransportRoute;
    use std::net::SocketAddr;
    use std::time::Instant;

    fn listening_status() -> StatusSnapshot {
        StatusSnapshot {
            listening: true,
            bound: Some("0.0.0.0:47990".parse().unwrap()),
            addresses: vec![
                "127.0.0.1:47990".parse().unwrap(),
                "192.168.1.20:47990".parse().unwrap(),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn disabled_is_stated_plainly() {
        let v = tray_view_of(&listening_status(), false);
        assert_eq!(v.state, TrayState::Disabled);
        assert!(v.tooltip.contains("OFF"));
        assert!(!v.can_disconnect);
    }

    #[test]
    fn listening_prefers_a_routable_address_over_loopback() {
        let v = tray_view_of(&listening_status(), true);
        assert_eq!(v.state, TrayState::Listening);
        assert!(v.tooltip.contains("192.168.1.20:47990"), "{}", v.tooltip);
        assert!(!v.can_disconnect);
    }

    #[test]
    fn connected_names_the_client_and_the_real_route() {
        let mut s = listening_status();
        s.client = Some(ClientInfo {
            name: "laptop".into(),
            fingerprint: "a1b2:c3d4:e5f6:0718".into(),
            route: TransportRoute::DirectUdp,
            peer: "192.168.1.55:51000".parse::<SocketAddr>().unwrap(),
            connected_at: Instant::now(),
        });
        let v = tray_view_of(&s, true);
        assert_eq!(v.state, TrayState::Connected);
        assert!(v.tooltip.contains("laptop"));
        assert!(v.tooltip.contains("Direct UDP"));
        assert!(v.can_disconnect);
    }

    #[test]
    fn a_failed_bind_is_a_problem_not_a_silence() {
        let mut s = listening_status();
        s.listening = false;
        s.last_error = Some("bind 0.0.0.0:47990: address in use".into());
        let v = tray_view_of(&s, true);
        assert_eq!(v.state, TrayState::Problem);
        assert!(v.tooltip.contains("address in use"));
    }

    #[test]
    fn not_yet_bound_is_starting_not_broken() {
        // The first second of every launch must not look like a failure, or
        // the orange icon stops meaning anything.
        let mut s = listening_status();
        s.listening = false;
        s.last_error = None;
        let v = tray_view_of(&s, true);
        assert_eq!(v.state, TrayState::Starting);
        assert!(v.tooltip.contains("starting"), "{}", v.tooltip);
        assert!(!v.can_disconnect);
    }

    #[test]
    fn each_state_reads_differently() {
        let listening = listening_status();
        let mut failed = listening.clone();
        failed.listening = false;
        failed.last_error = Some("address in use".into());
        let mut starting = listening.clone();
        starting.listening = false;

        let views = [
            tray_view_of(&listening, false),
            tray_view_of(&starting, true),
            tray_view_of(&listening, true),
            tray_view_of(&failed, true),
        ];
        for (i, a) in views.iter().enumerate() {
            for b in views.iter().skip(i + 1) {
                assert_ne!(a.state, b.state);
                assert_ne!(a.tooltip, b.tooltip);
            }
        }
    }

    #[test]
    fn tooltips_fit_the_shell_limit() {
        let mut s = listening_status();
        s.listening = false;
        s.last_error = Some("x".repeat(400));
        let v = tray_view_of(&s, true);
        assert!(v.tooltip.chars().count() <= 120, "{}", v.tooltip.chars().count());
        assert!(v.tooltip.ends_with('…'));
    }

    #[test]
    fn shared_state_reports_no_listener_instead_of_pretending() {
        let shared = AppShared::new(true);
        assert!(!shared.send(NetCommand::ArmPairing), "no listener means no send");
        assert!(!shared.quit_requested());
        assert!(shared.remote_access());
    }
}
