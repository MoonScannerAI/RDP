//! Diagnostics window: a `ConnStats` snapshot plus locally measured numbers.
//!
//! HONESTY RULE: anything we have not actually measured renders as "—".
//! Network figures come from the host over the control channel; if none have
//! arrived, this panel says so rather than showing zeros that look like data.

use directdesk_shared::stats::{ConnStats, TransportRoute};

use crate::renderer::Presenter;

const DASH: &str = "—";

pub struct DiagnosticsInput<'a> {
    pub stats: Option<&'a ConnStats>,
    /// Age of the newest host stats. Stale numbers are labelled, not hidden.
    pub stats_age_ms: Option<f32>,
    pub route: Option<TransportRoute>,
    pub presenter: &'a Presenter,
    pub source_description: &'a str,
    pub source_error: Option<&'a str>,
    pub frames_decoded: u64,
    pub frames_presented: u64,
    pub frames_dropped_at_present: u64,
    pub remote_dims: Option<(u32, u32)>,
    pub keys_forwarded: u64,
    pub moves_sent: u64,
    pub moves_coalesced: u64,
    pub demo_mode: bool,
}

/// Host stats older than this are called out as stale.
const STALE_AFTER_MS: f32 = 5_000.0;

pub fn show(ctx: &egui::Context, open: &mut bool, input: DiagnosticsInput<'_>) {
    egui::Window::new("Diagnostics")
        .open(open)
        .default_width(380.0)
        .resizable(true)
        .show(ctx, |ui| body(ui, input));
}

fn body(ui: &mut egui::Ui, input: DiagnosticsInput<'_>) {
    if input.demo_mode {
        ui.colored_label(
            egui::Color32::from_rgb(230, 170, 60),
            "LOOPBACK DEMO — synthetic frames, decoder and network bypassed.",
        );
        ui.separator();
    }

    ui.heading("Transport");
    if let Some(age) = input.stats_age_ms {
        if age > STALE_AFTER_MS {
            ui.colored_label(
                egui::Color32::from_rgb(230, 170, 60),
                format!("Host stats are {:.0} s old — figures below are stale.", age / 1000.0),
            );
        }
    }
    egui::Grid::new("diag_transport").num_columns(2).striped(true).show(ui, |ui| {
        row(ui, "Route", route_text(input.route));
        match input.stats {
            Some(s) => {
                row(ui, "RTT", format!("{:.1} ms", s.rtt_ms));
                row(ui, "Jitter", format!("{:.1} ms", s.jitter_ms));
                row(ui, "Loss", format!("{:.2} %", s.loss * 100.0));
                row(ui, "Bandwidth", format!("{} kbps", s.bandwidth_kbps));
                row(ui, "Video bitrate", format!("{} kbps", s.bitrate_kbps));
            }
            None => {
                for name in ["RTT", "Jitter", "Loss", "Bandwidth", "Video bitrate"] {
                    row(ui, name, DASH.to_string());
                }
            }
        }
    });

    ui.add_space(8.0);
    ui.heading("Frame chain");
    egui::Grid::new("diag_frames").num_columns(2).striped(true).show(ui, |ui| {
        // Host-side rates only exist if the host told us.
        match input.stats {
            Some(s) => {
                row(ui, "fps capture (host)", format!("{:.1}", s.fps_capture));
                row(ui, "fps encode (host)", format!("{:.1}", s.fps_encode));
                row(ui, "Host pipeline", format!("{:.1} ms", s.pipeline_ms));
                row(ui, "Keyframes requested", s.keyframes_requested.to_string());
            }
            None => {
                row(ui, "fps capture (host)", DASH.to_string());
                row(ui, "fps encode (host)", DASH.to_string());
                row(ui, "Host pipeline", DASH.to_string());
                row(ui, "Keyframes requested", DASH.to_string());
            }
        }
        // These we measure ourselves, so they are always real.
        row(ui, "fps decode (local)", format!("{:.1}", input.presenter.fps_decode()));
        row(ui, "fps present (local)", format!("{:.1}", input.presenter.fps_present()));
        row(
            ui,
            "Present age",
            match input.presenter.present_age_ms() {
                Some(ms) => format!("{ms:.1} ms"),
                None => DASH.to_string(),
            },
        );
        row(ui, "Frames decoded", input.frames_decoded.to_string());
        row(ui, "Frames presented", input.frames_presented.to_string());
        row(ui, "Dropped at present", input.frames_dropped_at_present.to_string());
    });

    ui.add_space(8.0);
    ui.heading("Decoder");
    egui::Grid::new("diag_decoder").num_columns(2).striped(true).show(ui, |ui| {
        row(ui, "Source", input.source_description.to_string());
        row(
            ui,
            "Presented size",
            match input.presenter.frame_size() {
                Some((w, h)) => format!("{w} x {h}"),
                None => DASH.to_string(),
            },
        );
        row(
            ui,
            "Decoded size",
            match input.remote_dims {
                Some((w, h)) => format!("{w} x {h}"),
                None => DASH.to_string(),
            },
        );
    });
    if let Some(err) = input.source_error {
        ui.colored_label(egui::Color32::from_rgb(220, 90, 90), format!("Decoder error: {err}"));
    }

    ui.add_space(8.0);
    ui.heading("Input");
    egui::Grid::new("diag_input").num_columns(2).striped(true).show(ui, |ui| {
        row(ui, "Keys forwarded", input.keys_forwarded.to_string());
        row(ui, "Mouse moves sent", input.moves_sent.to_string());
        row(ui, "Moves coalesced", input.moves_coalesced.to_string());
    });
}

fn row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.label(label);
    ui.label(egui::RichText::new(value).monospace());
    ui.end_row();
}

/// The route label is the one thing that must never be invented.
pub fn route_text(route: Option<TransportRoute>) -> String {
    match route {
        Some(r) => r.label().to_string(),
        None => DASH.to_string(),
    }
}

/// Relayed connections are visually distinct — the user must be able to tell
/// at a glance that traffic is not direct.
pub fn route_color(route: Option<TransportRoute>) -> egui::Color32 {
    match route {
        Some(r) if r.is_direct() => egui::Color32::from_rgb(90, 200, 120),
        Some(_) => egui::Color32::from_rgb(230, 170, 60),
        None => egui::Color32::GRAY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_route_renders_a_dash_never_a_guess() {
        assert_eq!(route_text(None), DASH);
        assert_eq!(route_color(None), egui::Color32::GRAY);
    }

    #[test]
    fn route_text_comes_straight_from_the_contract() {
        for route in [
            TransportRoute::DirectUdp,
            TransportRoute::DirectIpv6,
            TransportRoute::UdpHolePunched,
            TransportRoute::DirectTcp,
            TransportRoute::Relayed,
        ] {
            assert_eq!(route_text(Some(route)), route.label());
        }
    }

    #[test]
    fn relayed_is_visually_flagged() {
        assert_ne!(route_color(Some(TransportRoute::Relayed)), route_color(Some(TransportRoute::DirectUdp)));
    }
}
