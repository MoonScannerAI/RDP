//! DirectDeskClient — connect, decode, display, capture input.
//!
//! Usage:
//! ```text
//! DirectDeskClient [--host <addr>] [--udp-port N]
//!                  [--loopback-demo] [--demo-fps N] [--decoder-selftest]
//! ```
//
// NOTE: deliberately a console subsystem binary for M1 — `--decoder-selftest`,
// `--help` and the tracing console layer all need stdout. Switch to
// `#![windows_subsystem = "windows"]` when the app ships.

use std::sync::Arc;

use directdesk_client::config::ClientConfig;
use directdesk_client::connect::{ConnectSupervisor, StreamCaps};
use directdesk_client::renderer::FrameSlot;
use directdesk_client::session::{ClientSession, TransportEndpoints};
use directdesk_client::ui::{AppInit, ClientApp, SourceMode};
use directdesk_client::{decoder, pipeline};
use directdesk_shared::crypto::storage::{DpapiFileStore, SecretStore};

const USAGE: &str = "\
DirectDeskClient — DirectDesk remote desktop client

  --host <addr>        host name or IP; when set, the client connects on launch
  --udp-port <n>       UDP/QUIC port (default 47990)
  --pair-code <8dig>   pair with the host using this one-time code (first run)
  --loopback-demo      feed the renderer synthetic frames; no network, no decode
  --demo-fps <n>       loopback demo frame rate (default 60)
  --decoder-selftest   create the Media Foundation H.264 MFT, report, and exit
  --capture-on-start   test aid: install the keyboard hook at startup (waits
                       for the window to be focused first)
  --hold-capture       test aid: install at startup and keep the hook armed
                       across focus loss, minimize and reconnects; also forces
                       'Background capture' on for this run, so keys keep going
                       to the host while DirectDesk is in the background
  -h, --help           this text
";

#[derive(Debug)]
struct Args {
    host: Option<String>,
    udp_port: Option<u16>,
    pair_code: Option<String>,
    loopback_demo: bool,
    demo_fps: u32,
    decoder_selftest: bool,
    capture_on_start: bool,
    hold_capture: bool,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            host: None,
            udp_port: None,
            pair_code: None,
            loopback_demo: false,
            demo_fps: 60,
            decoder_selftest: false,
            capture_on_start: false,
            hold_capture: false,
            help: false,
        }
    }
}

/// Consume the value that follows `argv[*i]`, advancing the cursor.
fn value_after(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    argv.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_args(argv: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let argv: Vec<String> = argv.into_iter().collect();
    let mut args = Args::default();
    let mut i = 0usize;

    while i < argv.len() {
        match argv[i].as_str() {
            "--host" => args.host = Some(value_after(&argv, &mut i, "--host")?),
            "--udp-port" => {
                let raw = value_after(&argv, &mut i, "--udp-port")?;
                args.udp_port = Some(raw.parse().map_err(|e| format!("--udp-port: {e}"))?);
            }
            "--pair-code" => args.pair_code = Some(value_after(&argv, &mut i, "--pair-code")?),
            "--demo-fps" => {
                let raw = value_after(&argv, &mut i, "--demo-fps")?;
                args.demo_fps = raw.parse().map_err(|e| format!("--demo-fps: {e}"))?;
            }
            "--loopback-demo" => args.loopback_demo = true,
            "--decoder-selftest" => args.decoder_selftest = true,
            "--capture-on-start" => args.capture_on_start = true,
            "--hold-capture" => args.hold_capture = true,
            "-h" | "--help" => args.help = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    if args.demo_fps == 0 || args.demo_fps > 1000 {
        return Err("--demo-fps must be 1..=1000".into());
    }
    Ok(args)
}

fn main() -> anyhow::Result<()> {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    if args.help {
        println!("{USAGE}");
        return Ok(());
    }

    let _guard =
        directdesk_shared::logging::init("client", directdesk_shared::logging::default_log_dir());
    tracing::info!("DirectDeskClient {} starting", env!("CARGO_PKG_VERSION"));

    if args.decoder_selftest {
        return decoder_selftest();
    }

    let mut config = ClientConfig::load();
    // An explicit `--host` both pre-fills the field and auto-triggers a connect.
    let host_given = args.host.is_some();
    if let Some(host) = args.host {
        config.host_address = host;
    }
    if let Some(p) = args.udp_port {
        config.udp_port = p;
    }

    let (session, transport) = ClientSession::new();
    let slot = Arc::new(FrameSlot::new());

    let mode = if args.loopback_demo {
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

    // The name shown on the host: a remembered name wins, else the machine name.
    let display_name = {
        let saved = config.display_name.trim();
        if saved.is_empty() {
            client_display_name()
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
                "--loopback-demo: synthetic frames at {} fps; decoder and network are BYPASSED",
                args.demo_fps
            );
            spawn_input_sink(transport);
            (None, None)
        }
        SourceMode::Live => match DpapiFileStore::client() {
            Ok(store) => {
                let store: Arc<dyn SecretStore> = Arc::new(store);
                let supervisor = ConnectSupervisor::new(
                    runtime.handle().clone(),
                    store,
                    transport,
                    StreamCaps::default(),
                );
                (Some(supervisor), None)
            }
            Err(e) => {
                tracing::error!("secret store unavailable ({e}); transport disabled");
                (None, Some(transport))
            }
        },
    };

    // An explicit CLI `--host` auto-triggers one connect on the first frame; a
    // merely-remembered host just pre-fills the form. Needs a live supervisor.
    let auto_connect = host_given && supervisor.is_some();
    let initial_pair_code = args.pair_code.clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([640.0, 400.0])
            .with_title("DirectDesk"),
        ..Default::default()
    };

    let video_rx = session.video_rx.clone();
    let demo_fps = args.demo_fps;
    let capture_on_start = args.capture_on_start;
    let hold_capture = args.hold_capture;

    eframe::run_native(
        "DirectDesk",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let repaint = move || ctx.request_repaint();
            let pipeline = match mode {
                SourceMode::LoopbackDemo => {
                    pipeline::spawn_demo_source(slot.clone(), demo_fps, repaint)
                }
                SourceMode::Live => {
                    // The decode thread asks for a keyframe when a decode fails,
                    // so it needs the outbound control channel.
                    let control_tx = session.control_tx.clone();
                    pipeline::spawn_decode_thread(video_rx, slot.clone(), control_tx, repaint)
                }
            };
            Ok(Box::new(ClientApp::new(
                cc,
                AppInit {
                    config,
                    session,
                    transport: transport_for_app,
                    slot,
                    pipeline,
                    mode,
                    supervisor,
                    display_name,
                    initial_pair_code,
                    auto_connect,
                    capture_on_start,
                    hold_capture,
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

/// A friendly name for this client, shown on the host after pairing. Derived
/// from the machine name; sanitised to the crypto layer's name rules.
fn client_display_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "DirectDeskClient".to_string());
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(64).collect();
    if cleaned.trim().is_empty() {
        "DirectDeskClient".to_string()
    } else {
        cleaned
    }
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
                    tracing::info!(keys, moves, buttons, wheels, releases, "input sink totals");
                }
            }
            tracing::info!(
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

fn decoder_selftest() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let report = decoder::self_test();
        print!("{report}");
        tracing::info!("decoder selftest:\n{report}");
    }
    #[cfg(not(windows))]
    println!("decoder selftest: unsupported platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_are_live_mode() {
        let a = args(&[]).unwrap();
        assert!(!a.loopback_demo);
        assert!(!a.decoder_selftest);
        assert_eq!(a.host, None);
        assert_eq!(a.demo_fps, 60);
    }

    #[test]
    fn parses_every_flag() {
        let a = args(&[
            "--host",
            "10.0.0.2",
            "--udp-port",
            "1234",
            "--loopback-demo",
            "--demo-fps",
            "30",
        ])
        .unwrap();
        assert_eq!(a.host.as_deref(), Some("10.0.0.2"));
        assert_eq!(a.udp_port, Some(1234));
        assert!(a.loopback_demo);
        assert_eq!(a.demo_fps, 30);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(args(&["--nope"]).is_err());
        assert!(args(&["--udp-port"]).is_err(), "missing value");
        assert!(args(&["--udp-port", "notanumber"]).is_err());
        assert!(args(&["--udp-port", "99999"]).is_err(), "out of u16 range");
        assert!(args(&["--demo-fps", "0"]).is_err());
    }

    #[test]
    fn parses_capture_flags() {
        let a = args(&[]).unwrap();
        assert!(!a.capture_on_start);
        assert!(!a.hold_capture, "capture is opt-in");

        let a = args(&["--capture-on-start"]).unwrap();
        assert!(a.capture_on_start);
        assert!(!a.hold_capture);

        let a = args(&["--hold-capture"]).unwrap();
        assert!(a.hold_capture);
        // `--hold-capture` implies the startup install on its own; the UI does
        // that mapping, so the parsed flag stays independent here.
        assert!(!a.capture_on_start);

        let a = args(&["--capture-on-start", "--hold-capture"]).unwrap();
        assert!(a.capture_on_start && a.hold_capture);
    }

    #[test]
    fn help_is_recognised() {
        assert!(args(&["--help"]).unwrap().help);
        assert!(args(&["-h"]).unwrap().help);
    }
}
