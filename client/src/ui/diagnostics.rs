//! Diagnostics window: a `ConnStats` snapshot plus locally measured numbers.
//!
//! HONESTY RULE: anything we have not actually measured renders as "—".
//! Network figures come from the host over the control channel; if none have
//! arrived, this panel says so rather than showing zeros that look like data.

use directdesk_shared::stats::{ConnStats, TransportRoute};

use crate::pipeline::AudioSnapshot;
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
    /// What the audio thread has measured, or `None` when it has measured
    /// nothing — no session negotiated audio, or none has arrived yet. Under
    /// the HONESTY RULE that is the whole audio section rendered as "—", never
    /// a row of zeros that would read as "audio is running and perfectly
    /// silent".
    pub audio: Option<AudioSnapshot>,
    /// The audio path degraded to silence, and why.
    pub audio_error: Option<&'a str>,
    pub demo_mode: bool,
    /// Stream 1's gauges, or `None` when no second stream is live this
    /// session. The whole "Stream 1" section is omitted (not shown as
    /// dashes) when this is `None`: unlike audio, which every live session
    /// either negotiated or didn't, most sessions never have a second
    /// monitor at all (`MonitorChoice::Primary` is the default), so a
    /// permanent dashed section would read as "something is supposed to be
    /// here" when nothing ever was.
    pub stream1: Option<Stream1Diag<'a>>,
}

/// Stream 1 (second monitor) gauges. Built only while that stream is
/// actually live this session — see [`DiagnosticsInput::stream1`].
///
/// `fps_present` / present-age are deliberately not here: the second
/// window's `Presenter` is private to `ui::second_window` and today only
/// exposes `fps_decode` (`SecondaryShared::fps_decode`). Widening that is a
/// smaller, separate change than inventing a number this panel never
/// actually measured.
pub struct Stream1Diag<'a> {
    pub fps_decode: f32,
    pub source_description: &'a str,
    pub source_error: Option<&'a str>,
    pub frames_decoded: u64,
    pub frames_presented: u64,
    pub frames_dropped_at_present: u64,
    pub remote_dims: Option<(u32, u32)>,
    /// Delta frames [`crate::pipeline::SourceStatus::frames_gated`] refused
    /// pending a keyframe — stream 1's own independent gate and frame_id
    /// space, per `Pipeline::attach_decode_thread`.
    pub frames_gated: u64,
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
                format!(
                    "Host stats are {:.0} s old — figures below are stale.",
                    age / 1000.0
                ),
            );
        }
    }
    egui::Grid::new("diag_transport")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
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
    egui::Grid::new("diag_frames")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
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
            row(
                ui,
                "fps decode (local)",
                format!("{:.1}", input.presenter.fps_decode()),
            );
            row(
                ui,
                "fps present (local)",
                format!("{:.1}", input.presenter.fps_present()),
            );
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
            row(
                ui,
                "Dropped at present",
                input.frames_dropped_at_present.to_string(),
            );
        });

    ui.add_space(8.0);
    ui.heading("Decoder");
    egui::Grid::new("diag_decoder")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
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
        ui.colored_label(
            egui::Color32::from_rgb(220, 90, 90),
            format!("Decoder error: {err}"),
        );
    }

    ui.add_space(8.0);
    ui.heading("Audio");
    egui::Grid::new("diag_audio")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| match input.audio {
            Some(a) => {
                // Two elastic buffers, reported separately on purpose: they are
                // measured in different places and a single "latency" number
                // would hide which one is misbehaving.
                row(
                    ui,
                    "Jitter depth",
                    format!("{} ms (target {} ms)", a.buffered_ms, a.target_ms),
                );
                row(
                    ui,
                    "Output latency",
                    // `None` means no endpoint was opened; it is not zero.
                    optional_ms(a.device_latency_ms),
                );
                row(
                    ui,
                    "Packets",
                    format!("{} of {}", a.packets_delivered, a.packets_received),
                );
                row(ui, "Lost", a.lost.to_string());
                // "Late" is the only counter that moves if the jitter buffer
                // wedges on a wild forward `seq`: in that state nothing is
                // delivered, `underruns` does NOT increment, and the depth
                // target decays as though the stream were healthy. Without
                // this row the failure is invisible at every log level.
                row(ui, "Late", a.late.to_string());
                row(ui, "Underruns (jitter)", a.underruns.to_string());
                row(
                    ui,
                    "Underruns (device)",
                    match a.device_underruns {
                        Some(n) => n.to_string(),
                        None => DASH.to_string(),
                    },
                );
                row(ui, "Drift corrections", a.drift_corrections.to_string());
            }
            None => {
                for name in [
                    "Jitter depth",
                    "Output latency",
                    "Packets",
                    "Lost",
                    "Late",
                    "Underruns (jitter)",
                    "Underruns (device)",
                    "Drift corrections",
                ] {
                    row(ui, name, DASH.to_string());
                }
            }
        });
    if let Some(err) = input.audio_error {
        ui.colored_label(
            egui::Color32::from_rgb(220, 90, 90),
            format!("Audio error: {err}"),
        );
    }

    ui.add_space(8.0);
    ui.heading("Input");
    egui::Grid::new("diag_input")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            row(ui, "Keys forwarded", input.keys_forwarded.to_string());
            row(ui, "Mouse moves sent", input.moves_sent.to_string());
            row(ui, "Moves coalesced", input.moves_coalesced.to_string());
        });

    // Omitted entirely (not a dashed section) when `None` — see the field
    // doc on `DiagnosticsInput::stream1`.
    if let Some(s1) = input.stream1 {
        ui.add_space(8.0);
        ui.heading("Stream 1 (second monitor)");
        egui::Grid::new("diag_stream1")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                row(ui, "Source", s1.source_description.to_string());
                row(ui, "fps decode (local)", format!("{:.1}", s1.fps_decode));
                row(
                    ui,
                    "Decoded size",
                    match s1.remote_dims {
                        Some((w, h)) => format!("{w} x {h}"),
                        None => DASH.to_string(),
                    },
                );
                row(ui, "Frames decoded", s1.frames_decoded.to_string());
                row(ui, "Frames presented", s1.frames_presented.to_string());
                row(
                    ui,
                    "Dropped at present",
                    s1.frames_dropped_at_present.to_string(),
                );
                row(
                    ui,
                    "Frames gated (awaiting keyframe)",
                    s1.frames_gated.to_string(),
                );
            });
        if let Some(err) = s1.source_error {
            ui.colored_label(
                egui::Color32::from_rgb(220, 90, 90),
                format!("Stream 1 decoder error: {err}"),
            );
        }
    }
}

fn row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.label(label);
    ui.label(egui::RichText::new(value).monospace());
    ui.end_row();
}

/// A millisecond figure that may not have been measured at all.
///
/// The HONESTY RULE in one function: `None` is "we never opened the thing that
/// would tell us", which is a different fact from a measured zero and must not
/// render as one.
fn optional_ms(value: Option<u32>) -> String {
    match value {
        Some(ms) => format!("{ms} ms"),
        None => DASH.to_string(),
    }
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

    /// The HONESTY RULE applied to the audio section. An unopened endpoint has
    /// no latency and no underrun count; both must render as "—", because a
    /// zero there reads as "measured, and fine".
    #[test]
    fn an_unmeasured_audio_figure_renders_a_dash_never_a_zero() {
        assert_eq!(optional_ms(None), DASH);
        assert_eq!(optional_ms(Some(0)), "0 ms");
        assert_eq!(optional_ms(Some(400)), "400 ms");

        // A default snapshot is all zeros; it must stay distinguishable from
        // "no snapshot at all", which is what `Option<AudioSnapshot>` buys.
        let measured = AudioSnapshot::default();
        assert_eq!(measured.device_underruns, None);
        assert_eq!(measured.device_latency_ms, None);
    }

    #[test]
    fn relayed_is_visually_flagged() {
        assert_ne!(
            route_color(Some(TransportRoute::Relayed)),
            route_color(Some(TransportRoute::DirectUdp))
        );
    }
}
