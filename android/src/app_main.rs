//! `android_main`: the NativeActivity entry point. Builds the Android
//! [`PlatformConfig`] and hands it to the shared [`app::run`].

use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use android_activity::{AndroidApp, MainEvent, PollEvent, WindowManagerFlags};
use directdesk_client::app::{self, LaunchArgs, PlatformConfig, UiProfile};
use directdesk_client::connect::StreamCaps;
use directdesk_shared::crypto::storage::{PlainFileStore, SecretStore};
use jni::objects::JObject;
use jni::{jni_sig, jni_str};

use crate::logcat;
use crate::mediacodec;
use crate::sys;

/// Frame rate of the built-in loopback demo, should someone enable it.
const DEMO_FPS: u32 = 30;

/// Called by android-activity on a dedicated thread once the NativeActivity
/// is created, once per Activity instance.
///
/// How long to wait for `MainEvent::Destroy` after `Activity.finish()`.
const FINISH_TIMEOUT: Duration = Duration::from_secs(3);

/// Called by android-activity on a dedicated thread once the NativeActivity
/// is created, once per Activity instance.
///
/// # Process lifetime
///
/// winit 0.30 allows ONE event loop per process (a process-wide
/// `EVENT_LOOP_CREATED` flag that is never reset), while android-activity
/// starts a new `android_main` for every `onCreate`. A second `app::run` in
/// the same process would fail with `RecreationAttempt` and leave a dead
/// Activity. So:
///
/// 1. After [`app::run`] returns (for any reason, panics included) the
///    process ends — but only once the Activity is gone: `Activity.finish()`,
///    wait for `MainEvent::Destroy`, then `_exit(0)`. Measured on the API 34
///    emulator: exiting while the Activity is still the top activity makes
///    ActivityManager restart it at once ("Start proc ... for top-activity"),
///    which with a failing `run` was a restart loop (17 restarts in 7 s), and
///    `exit()`'s static destructors raced hwui's RenderThread into SIGABRT.
///    Hence finish-first, and `_exit` rather than `exit`. If the finish or
///    the Destroy does not happen, this returns instead and android-activity
///    finishes the Activity (the process then stays cached; rule 2 covers
///    the next launch).
/// 2. A second entry in the same process (relaunch into a cached process,
///    or an Activity re-created for a config change not in the manifest's
///    `configChanges`) logs and ends the process immediately with `_exit(0)`.
///    That Activity is the top one, so ActivityManager restarts it once, in
///    a fresh process, where rule 1's path runs normally (measured: one
///    restart, ~150 ms).
#[no_mangle]
fn android_main(app: AndroidApp) {
    logcat::init();

    static RAN_ONCE: AtomicBool = AtomicBool::new(false);
    if RAN_ONCE.swap(true, Ordering::SeqCst) {
        tracing::warn!(
            "android_main entered again in the same process (new Activity); winit \
             cannot create a second event loop, restarting the process"
        );
        exit_now();
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "DirectDesk for Android starting"
    );
    let run_app = app.clone();
    match std::panic::catch_unwind(AssertUnwindSafe(|| run(run_app))) {
        Ok(Ok(())) => tracing::info!("app::run returned"),
        Ok(Err(e)) => tracing::error!("app::run failed: {e:#}"),
        // The panic hook already wrote message, location and backtrace.
        Err(_) => tracing::error!("app::run panicked"),
    }
    finish_then_exit(&app);
}

/// Rule 1 above: finish the Activity, wait for its Destroy, end the process.
/// Returns only if that could not be done.
fn finish_then_exit(app: &AndroidApp) {
    if let Err(e) = request_finish(app) {
        tracing::warn!("Activity.finish() failed ({e}); returning so android-activity finishes it");
        return;
    }
    let deadline = Instant::now() + FINISH_TIMEOUT;
    let mut destroyed = false;
    while !destroyed {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            tracing::warn!(
                "no Destroy within {FINISH_TIMEOUT:?} of Activity.finish(); returning so \
                 android-activity finishes the Activity"
            );
            return;
        }
        // Polling also acknowledges the lifecycle commands (pause, stop, ...)
        // that the Java main thread blocks on, so the finish can progress.
        app.poll_events(Some(left), |event| {
            if let PollEvent::Main(MainEvent::Destroy) = event {
                destroyed = true;
            }
        });
    }
    tracing::info!("Activity destroyed; ending the process");
    exit_now();
}

/// `Activity.finish()` through JNI. android-activity has no API for it; it
/// only finishes the Activity after `android_main` returns.
fn request_finish(app: &AndroidApp) -> Result<(), String> {
    let vm = jni::JavaVM::singleton().map_err(|e| format!("no JavaVM: {e}"))?;
    let activity = app.activity_as_ptr() as jni::sys::jobject;
    vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        // SAFETY: `activity_as_ptr` is a global reference android-activity
        // keeps valid for as long as `app` lives (it outlives this call), and
        // a `Cast` borrows it without ever deleting it.
        let activity = unsafe { env.as_cast_raw::<JObject>(&activity)? };
        env.call_method(&activity, jni_str!("finish"), jni_sig!("()V"), &[])?;
        Ok(())
    })
    .map_err(|e| e.to_string())
}

/// End the process now.
fn exit_now() -> ! {
    // SAFETY: `_exit` is async-signal-safe and skips atexit handlers and C++
    // static destructors — the teardown that raced hwui's RenderThread into
    // SIGABRT with `exit()`. Logcat writes are synchronous, so nothing
    // buffered is lost.
    unsafe { libc::_exit(0) }
}

fn run(app: AndroidApp) -> anyhow::Result<()> {
    app.set_window_flags(
        WindowManagerFlags::KEEP_SCREEN_ON | WindowManagerFlags::FULLSCREEN,
        WindowManagerFlags::empty(),
    );

    let data_dir = app.internal_data_path();
    match &data_dir {
        Some(dir) => tracing::info!("data dir: {}", dir.display()),
        None => tracing::error!("Android reported no internal data path; nothing will persist"),
    }
    let store = open_store(data_dir.as_deref());
    if let Err(e) = &store {
        tracing::error!("secret store unavailable: {e}");
    }
    let default_display_name = default_display_name();
    tracing::info!("default display name: {default_display_name}");

    let cfg = PlatformConfig {
        profile: UiProfile::Touch,
        data_dir,
        store,
        new_decoder: mediacodec::new_decoder,
        caps: StreamCaps::touch_device(),
        default_display_name,
        launch: LaunchArgs {
            demo_fps: DEMO_FPS,
            ..LaunchArgs::default()
        },
        native_options: eframe::NativeOptions {
            android_app: Some(app.clone()),
            ..Default::default()
        },
    };
    app::run(cfg)
}

/// Client identity and trusted hosts: plaintext files under
/// `<internal data>/keys`, private to this app's UID.
fn open_store(data_dir: Option<&Path>) -> Result<Arc<dyn SecretStore>, String> {
    let dir = data_dir
        .ok_or_else(|| "no app-private data directory".to_string())?
        .join("keys");
    // Created up front so an unusable directory disables Connect with a
    // clear reason instead of failing at the first pairing.
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    tracing::info!("secret store: {}", dir.display());
    let store = PlainFileStore::new(&dir)
        .map_err(|e| format!("cannot open secret store {}: {e}", dir.display()))?;
    Ok(Arc::new(store))
}

/// "Android <model>", e.g. "Android Pixel 6".
fn default_display_name() -> String {
    match sys::system_property("ro.product.model") {
        Some(model) => format!("Android {model}"),
        None => "Android device".to_string(),
    }
}
