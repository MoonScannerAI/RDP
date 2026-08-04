//! DirectDeskHost — capture, encode, serve, inject.
//!
//! Default behaviour is the product: load the config, open the QUIC listener if
//! remote access is enabled, put an icon in the notification area, and show the
//! status window. `--minimized` starts with the window hidden; the tray icon is
//! there either way, because a host that is serving a desktop with no visible
//! indicator is exactly the thing this project refuses to be.
//!
//! `--selftest` keeps its original meaning: a headless capture → convert →
//! encode run that needs no network and no GUI.

use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_host::config::HostConfig;
use directdesk_host::session::{HostSession, SessionConfig, SessionState};
use directdesk_host::ui::AppShared;
use directdesk_shared::crypto::storage::{DpapiFileStore, SecretStore};
use directdesk_shared::crypto::HostIdentity;

fn main() -> anyhow::Result<()> {
    // Before anything reads screen geometry: capture must see physical pixels.
    directdesk_host::capture::set_process_dpi_aware();
    let _guard =
        directdesk_shared::logging::init("host", directdesk_shared::logging::default_log_dir());
    tracing::info!("DirectDeskHost {} starting", env!("CARGO_PKG_VERSION"));

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--selftest") {
        let secs = args
            .iter()
            .position(|a| a == "--seconds")
            .and_then(|i| args.get(i + 1))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3);
        std::process::exit(selftest(secs));
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    let minimized = args.iter().any(|a| a == "--minimized");
    serve(minimized)
}

fn print_help() {
    println!("DirectDeskHost {}", env!("CARGO_PKG_VERSION"));
    println!("  (no arguments)             serve: listener + tray icon + status window");
    println!("  --minimized                start with the window hidden in the tray");
    println!("  --selftest [--seconds N]   run capture+encode for N seconds and report");
    println!("  --help                     this text");
    if let Some(path) = directdesk_host::config::config_path() {
        println!();
        println!("config: {}", path.display());
    }
}

/// The normal path: identity, runtime, listener, tray, window.
fn serve(force_minimized: bool) -> anyhow::Result<()> {
    let cfg = HostConfig::load_or_create();
    let (store, identity) = open_identity(&cfg)?;
    tracing::info!(
        host = %identity.name(),
        key = %directdesk_shared::crypto::fingerprint_short(&identity.ed25519_pub()),
        pin = %identity.tls().pin_short(),
        "host identity ready"
    );

    // The listener lives on its own runtime threads; egui keeps the main one.
    // Six workers, not three: the quinn connection driver plus the input
    // ingress hops (input_read_loop -> input_loop) share this pool with a
    // dozen other tasks, while capture/encode/video-egress run as their own
    // normal-priority OS threads that peg cores under 1080p load. Three workers
    // let full video encode starve inbound keystrokes, so typed keys only
    // landed on the host when the client minimized and video demand collapsed.
    // More workers keep the driver and input path scheduled under that load.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .thread_name("dd-net")
        .enable_all()
        .build()?;

    let shared = AppShared::new(cfg.remote_access_enabled);
    // Started before the window so the icon appears even if the window is
    // hidden from the very first frame.
    let tray = directdesk_host::ui::tray::spawn(shared.clone());

    let hidden = force_minimized || cfg.start_minimized;
    let result = directdesk_host::ui::run(
        cfg,
        shared.clone(),
        runtime.handle().clone(),
        identity,
        store,
        hidden,
    );

    // Whatever happened to the window, take the icon down and stop serving.
    shared.request_quit();
    shared.send(directdesk_host::net::NetCommand::Shutdown);
    let _ = tray.join();
    runtime.shutdown_timeout(Duration::from_secs(3));
    tracing::info!("DirectDeskHost stopped");
    result
}

/// Open the secret store and load (or create) the host identity.
///
/// `%ProgramData%` is the right home for a host that will one day start as a
/// service. If it is not writable — a locked-down machine, or a user without
/// rights to it — fall back to the per-user store and say so loudly rather
/// than refusing to start.
fn open_identity(cfg: &HostConfig) -> anyhow::Result<(Arc<dyn SecretStore>, Arc<HostIdentity>)> {
    if let Ok(store) = DpapiFileStore::host() {
        match HostIdentity::load_or_create(&store, &cfg.display_name) {
            Ok(id) => return Ok((Arc::new(store), Arc::new(id))),
            Err(e) => tracing::error!(
                "machine-scope identity store unusable ({e}); falling back to the user store"
            ),
        }
    }
    let store =
        DpapiFileStore::client().map_err(|e| anyhow::anyhow!("no usable secret store: {e}"))?;
    tracing::warn!(
        dir = %store.dir().display(),
        "using the per-user identity store; this host will not work as a service"
    );
    let id = HostIdentity::load_or_create(&store, &cfg.display_name)
        .map_err(|e| anyhow::anyhow!("host identity: {e}"))?;
    Ok((Arc::new(store), Arc::new(id)))
}

/// Headless pipeline check. Exits 0 only if real frames with real bytes came out.
fn selftest(seconds: u64) -> i32 {
    println!("=== DirectDesk host selftest ({seconds}s) ===");
    let cfg = SessionConfig {
        target_fps: 60,
        bitrate_kbps: 12_000,
        idle_repeat_ms: 33,
        ..Default::default()
    };

    let session = match HostSession::start(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FAIL: pipeline did not start: {e}");
            return 1;
        }
    };

    let desc = session.describe();
    println!(
        "adapter       : {} (LUID {:#x})",
        desc.adapter, desc.adapter_luid
    );
    println!(
        "output        : {} at {:?}",
        desc.output, desc.monitor_origin
    );
    println!("resolution    : {}x{}", desc.width, desc.height);
    println!("encoder       : {}", desc.encoder);
    println!("hardware enc  : {}", desc.hardware_encoder);
    println!("gpu convert   : {}", desc.gpu_convert);
    println!("gpu enc input : {}", desc.gpu_encode_input);

    let frames = session.frames();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut received = 0u64;
    let mut bytes = 0u64;
    let mut keyframes = 0u64;
    let mut largest = 0usize;
    let mut first_keyframe_head = Vec::new();

    while Instant::now() < deadline {
        match frames.recv_timeout(Duration::from_millis(200)) {
            Ok(f) => {
                received += 1;
                bytes += f.data.len() as u64;
                largest = largest.max(f.data.len());
                if f.keyframe {
                    keyframes += 1;
                    if first_keyframe_head.is_empty() {
                        first_keyframe_head = f.data.iter().take(8).copied().collect();
                    }
                }
            }
            Err(_) => {
                if let SessionState::Failed(e) = session.state() {
                    eprintln!("FAIL: session failed: {e}");
                    session.shutdown();
                    return 1;
                }
            }
        }
    }

    let stats = session.stats();
    let state = session.state();
    let captured = session.frames_captured();
    let produced = session.frames_encoded();
    session.shutdown();

    println!("--- results ---");
    println!("state         : {state:?}");
    println!("captured      : {captured} frames");
    println!("encoded       : {produced} frames by the encoder");
    println!("received      : {received} frames ({keyframes} keyframes)");
    println!("queue drops   : {}", stats.frames_dropped);
    println!("bytes         : {bytes} (largest frame {largest})");
    println!(
        "fps           : capture {:.1}, encode {:.1}",
        stats.fps_capture, stats.fps_encode
    );
    println!("bitrate       : {} kbps", stats.bitrate_kbps);
    println!("pipeline      : {:.2} ms/frame", stats.pipeline_ms);
    if !first_keyframe_head.is_empty() {
        println!("keyframe head : {first_keyframe_head:02x?}");
    }

    let annexb = first_keyframe_head.starts_with(&[0, 0, 0, 1])
        || first_keyframe_head.starts_with(&[0, 0, 1]);
    let ok = received > 0 && bytes > 0 && keyframes > 0 && annexb;
    if ok {
        println!("PASS");
        0
    } else {
        eprintln!("FAIL: frames={received} bytes={bytes} keyframes={keyframes} annexb={annexb}");
        1
    }
}
