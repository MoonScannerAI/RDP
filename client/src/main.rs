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

use directdesk_client::app::{self, LaunchArgs, PlatformConfig, UiProfile};
use directdesk_client::connect::StreamCaps;
use directdesk_client::decoder;
use directdesk_shared::crypto::storage::{DpapiFileStore, SecretStore};

const USAGE: &str = "\
DirectDeskClient — DirectDesk remote desktop client

  --host <addr>        host name or IP; when set, the client connects on launch
  --udp-port <n>       UDP/QUIC port (default 47990)
  --pair-code <8dig>   pair with the host using this one-time code (first run)
  --loopback-demo      feed the renderer synthetic frames; no network, no decode
  --demo-fps <n>       loopback demo frame rate (default 60)
  --demo-second-window also feed a synthetic source into the second monitor's
                       window, so its render/focus/close lifecycle and
                       diagnostics are exercisable with no dual-monitor host;
                       requires --loopback-demo
  --decoder-selftest   create the Media Foundation H.264 MFT, report, and exit
  --capture-on-start   test aid: install the keyboard hook at startup (waits
                       for the window to be focused first)
  --hold-capture       test aid: install at startup and keep the hook armed
                       across focus loss, minimize and reconnects; also forces
                       'Background capture' on for this run, so keys keep going
                       to the host while DirectDesk is in the background
  --touch-ui           test aid: run the touch UI profile the Android client
                       uses (no low-level keyboard hook); stream capabilities
                       stay the desktop defaults
  -h, --help           this text
";

#[derive(Debug)]
struct Args {
    host: Option<String>,
    udp_port: Option<u16>,
    pair_code: Option<String>,
    loopback_demo: bool,
    demo_fps: u32,
    demo_second_window: bool,
    decoder_selftest: bool,
    capture_on_start: bool,
    hold_capture: bool,
    touch_ui: bool,
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
            demo_second_window: false,
            decoder_selftest: false,
            capture_on_start: false,
            hold_capture: false,
            touch_ui: false,
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
            "--demo-second-window" => args.demo_second_window = true,
            "--decoder-selftest" => args.decoder_selftest = true,
            "--capture-on-start" => args.capture_on_start = true,
            "--hold-capture" => args.hold_capture = true,
            "--touch-ui" => args.touch_ui = true,
            "-h" | "--help" => args.help = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    if args.demo_fps == 0 || args.demo_fps > 1000 {
        return Err("--demo-fps must be 1..=1000".into());
    }
    if args.demo_second_window && !args.loopback_demo {
        return Err("--demo-second-window requires --loopback-demo".into());
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

    // The client's secret store. Opening it only resolves `%APPDATA%` —
    // nothing touches the disk until a read or write, and nothing is logged —
    // so opening it here, ahead of the config load and even under
    // `--loopback-demo` (which never uses it), changes nothing observable. A
    // failure is reported by `app::run` exactly where it always was: when the
    // Live supervisor would be built.
    let store = DpapiFileStore::client()
        .map(|store| Arc::new(store) as Arc<dyn SecretStore>)
        .map_err(|e| e.to_string());

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([640.0, 400.0])
            .with_title("DirectDesk"),
        ..Default::default()
    };

    app::run(PlatformConfig {
        profile: if args.touch_ui {
            UiProfile::Touch
        } else {
            UiProfile::Desktop
        },
        // `%APPDATA%\DirectDesk\client.json`, as always.
        data_dir: None,
        store,
        new_decoder: decoder::new_decoder,
        caps: StreamCaps::default(),
        default_display_name: client_display_name(),
        launch: LaunchArgs {
            host: args.host,
            udp_port: args.udp_port,
            pair_code: args.pair_code,
            loopback_demo: args.loopback_demo,
            demo_fps: args.demo_fps,
            demo_second_window: args.demo_second_window,
            capture_on_start: args.capture_on_start,
            hold_capture: args.hold_capture,
        },
        native_options,
    })
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
    fn demo_second_window_defaults_off_and_requires_loopback_demo() {
        let a = args(&[]).unwrap();
        assert!(!a.demo_second_window);

        // Politely rejected, same shape as every other bad combination: an
        // `Err` the caller prints alongside `USAGE` and exits 2 for, not a
        // panic — there is no host in demo mode to feed a second stream from,
        // so the combination is meaningless rather than merely unusual.
        let err = args(&["--demo-second-window"]).unwrap_err();
        assert!(
            err.contains("--loopback-demo"),
            "error should name the missing flag: {err}"
        );
    }

    #[test]
    fn demo_second_window_parses_alongside_loopback_demo() {
        let a = args(&["--loopback-demo", "--demo-second-window"]).unwrap();
        assert!(a.loopback_demo);
        assert!(a.demo_second_window);

        // Order must not matter.
        let a = args(&["--demo-second-window", "--loopback-demo"]).unwrap();
        assert!(a.loopback_demo);
        assert!(a.demo_second_window);
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
    fn touch_ui_is_opt_in_and_independent() {
        assert!(!args(&[]).unwrap().touch_ui, "desktop profile by default");
        let a = args(&["--touch-ui"]).unwrap();
        assert!(a.touch_ui);
        assert!(!a.loopback_demo && !a.capture_on_start && !a.hold_capture);
        let a = args(&["--loopback-demo", "--touch-ui"]).unwrap();
        assert!(a.touch_ui && a.loopback_demo);
    }

    #[test]
    fn help_is_recognised() {
        assert!(args(&["--help"]).unwrap().help);
        assert!(args(&["-h"]).unwrap().help);
    }
}
