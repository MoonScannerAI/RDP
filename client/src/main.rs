//! DirectDeskClient — connect, decode, display, capture input.
//!
//! Usage:
//! ```text
//! DirectDeskClient [--host <addr>] [--udp-port N] [--tcp-port N]
//!                  [--loopback-demo] [--demo-fps N] [--decoder-selftest]
//! ```
//
// NOTE: deliberately a console subsystem binary for M1 — `--decoder-selftest`,
// `--help` and the tracing console layer all need stdout. Switch to
// `#![windows_subsystem = "windows"]` when the app ships.

use std::sync::Arc;

use directdesk_client::config::ClientConfig;
use directdesk_client::net::{self, ConnectParams};
use directdesk_client::renderer::FrameSlot;
use directdesk_client::session::{ClientSession, TransportEndpoints};
use directdesk_client::ui::{AppInit, ClientApp, SourceMode};
use directdesk_client::{decoder, pipeline};
use directdesk_shared::crypto::storage::DpapiFileStore;
use tokio::sync::watch;

const USAGE: &str = "\
DirectDeskClient — DirectDesk remote desktop client

  --host <addr>        host name or IP; when set, the client connects on launch
  --udp-port <n>       UDP/QUIC port (default 47990)
  --tcp-port <n>       TCP fallback port (default 47991)
  --pair-code <8dig>   pair with the host using this one-time code (first run)
  --loopback-demo      feed the renderer synthetic frames; no network, no decode
  --demo-fps <n>       loopback demo frame rate (default 60)
  --decoder-selftest   create the Media Foundation H.264 MFT, report, and exit
  --capture-on-start   test aid: install the keyboard hook at startup
  -h, --help           this text
";

#[derive(Debug)]
struct Args {
    host: Option<String>,
    udp_port: Option<u16>,
    tcp_port: Option<u16>,
    pair_code: Option<String>,
    loopback_demo: bool,
    demo_fps: u32,
    decoder_selftest: bool,
    capture_on_start: bool,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            host: None,
            udp_port: None,
            tcp_port: None,
            pair_code: None,
            loopback_demo: false,
            demo_fps: 60,
            decoder_selftest: false,
            capture_on_start: false,
            help: false,
        }
    }
}

/// Consume the value that follows `argv[*i]`, advancing the cursor.
fn value_after(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    argv.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
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
            "--tcp-port" => {
                let raw = value_after(&argv, &mut i, "--tcp-port")?;
                args.tcp_port = Some(raw.parse().map_err(|e| format!("--tcp-port: {e}"))?);
            }
            "--pair-code" => args.pair_code = Some(value_after(&argv, &mut i, "--pair-code")?),
            "--demo-fps" => {
                let raw = value_after(&argv, &mut i, "--demo-fps")?;
                args.demo_fps = raw.parse().map_err(|e| format!("--demo-fps: {e}"))?;
            }
            "--loopback-demo" => args.loopback_demo = true,
            "--decoder-selftest" => args.decoder_selftest = true,
            "--capture-on-start" => args.capture_on_start = true,
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
    if let Some(host) = args.host {
        config.host_address = host;
    }
    if let Some(p) = args.udp_port {
        config.udp_port = p;
    }
    if let Some(p) = args.tcp_port {
        config.tcp_port = p;
    }

    let (session, transport) = ClientSession::new();
    let slot = Arc::new(FrameSlot::new());

    let mode = if args.loopback_demo { SourceMode::LoopbackDemo } else { SourceMode::Live };

    // In Live mode with a configured host, spawn the real transport driver on a
    // dedicated tokio runtime; it claims the transport endpoints. Its lifetime
    // is tied to `driver`, whose shutdown signal is raised once the window
    // closes. `--loopback-demo` is untouched: it has no transport at all.
    let mut driver: Option<NetDriver> = None;
    let (transport_for_app, transport_attached) = match mode {
        SourceMode::LoopbackDemo => {
            tracing::warn!(
                "--loopback-demo: synthetic frames at {} fps; decoder and network are BYPASSED",
                args.demo_fps
            );
            spawn_input_sink(transport);
            (None, false)
        }
        SourceMode::Live if config.host_address.trim().is_empty() => {
            // No host configured: hold the channels open so they stay valid, and
            // let the connect screen prompt for an address. (The connect button
            // cannot yet trigger the driver — see the note in the return.)
            (Some(transport), false)
        }
        SourceMode::Live => match DpapiFileStore::client() {
            Ok(store) => {
                let params = build_connect_params(&config, args.pair_code.clone());
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                let store: Arc<dyn directdesk_shared::crypto::storage::SecretStore> =
                    Arc::new(store);
                let handle = std::thread::Builder::new()
                    .name("directdesk-net".into())
                    .spawn(move || {
                        let rt = tokio::runtime::Builder::new_multi_thread()
                            .enable_all()
                            .build()
                            .expect("build tokio runtime");
                        rt.block_on(net::run_client(transport, params, store, shutdown_rx));
                    })
                    .expect("spawn transport thread");
                driver = Some(NetDriver { shutdown: shutdown_tx, handle });
                (None, true)
            }
            Err(e) => {
                tracing::error!("secret store unavailable ({e}); transport disabled");
                (Some(transport), false)
            }
        },
    };

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

    eframe::run_native(
        "DirectDesk",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let repaint = move || ctx.request_repaint();
            let pipeline = match mode {
                SourceMode::LoopbackDemo => pipeline::spawn_demo_source(slot.clone(), demo_fps, repaint),
                SourceMode::Live => pipeline::spawn_decode_thread(video_rx, slot.clone(), repaint),
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
                    transport_attached,
                    capture_on_start,
                },
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe failed: {e}"))?;

    // The window has closed: stop the transport driver and let it drain.
    if let Some(driver) = driver {
        let _ = driver.shutdown.send(true);
        let _ = driver.handle.join();
    }

    Ok(())
}

/// Handle to the background transport runtime, so the window-close path can stop
/// it cleanly rather than leaking the thread.
struct NetDriver {
    shutdown: watch::Sender<bool>,
    handle: std::thread::JoinHandle<()>,
}

/// Assemble the connect parameters the transport driver needs from persisted
/// config plus the optional one-time pairing code.
fn build_connect_params(config: &ClientConfig, pair_code: Option<String>) -> ConnectParams {
    ConnectParams {
        host: config.host_address.clone(),
        udp_port: config.udp_port,
        tcp_port: config.tcp_port,
        pairing_code: pair_code,
        display_name: client_display_name(),
        quality: config.quality_mode,
        max_width: 3840,
        max_height: 2160,
        preferred_fps: 60,
    }
}

/// A friendly name for this client, shown on the host after pairing. Derived
/// from the machine name; sanitised to the crypto layer's name rules.
fn client_display_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "DirectDeskClient".to_string());
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
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
                }
                if last_log.elapsed() >= std::time::Duration::from_secs(2) {
                    last_log = std::time::Instant::now();
                    tracing::info!(keys, moves, buttons, wheels, releases, "input sink totals");
                }
            }
            tracing::info!(keys, moves, buttons, wheels, releases, "input sink final totals");
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
            "--tcp-port",
            "5678",
            "--loopback-demo",
            "--demo-fps",
            "30",
        ])
        .unwrap();
        assert_eq!(a.host.as_deref(), Some("10.0.0.2"));
        assert_eq!(a.udp_port, Some(1234));
        assert_eq!(a.tcp_port, Some(5678));
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
    fn help_is_recognised() {
        assert!(args(&["--help"]).unwrap().help);
        assert!(args(&["-h"]).unwrap().help);
    }
}
