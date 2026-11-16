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
use eframe::egui_wgpu::{WgpuSetup, WgpuSetupCreateNew};
use eframe::wgpu;
use jni::objects::JObject;
use jni::{jni_sig, jni_str};

use crate::logcat;
use crate::mediacodec;
use crate::store_dir::{self, Migration};
use crate::sys;

/// Frame rate of the built-in loopback demo, should someone enable it.
const DEMO_FPS: u32 = 30;

/// How long to wait for `MainEvent::Destroy` after `Activity.finish()`.
const FINISH_TIMEOUT: Duration = Duration::from_secs(3);

/// How often the destroy watchdog looks at the Activity.
const WATCHDOG_PERIOD: Duration = Duration::from_millis(250);

/// Consecutive failed watchdog checks (~10 s) after which it gives up.
const WATCHDOG_MAX_FAILURES: u32 = 40;

/// Set once this process has started ending the Activity itself (rule 1
/// below). The destroy watchdog (rule 2) then stands down, so the two never
/// both act on the same finish.
static SELF_FINISHING: AtomicBool = AtomicBool::new(false);

/// Called by android-activity on a dedicated thread once the NativeActivity
/// is created, once per Activity instance.
///
/// # Process lifetime
///
/// winit 0.30 allows ONE event loop per process (a process-wide
/// `EVENT_LOOP_CREATED` flag that is never reset), while android-activity
/// starts a new `android_main` for every `onCreate`. A second `app::run` in
/// the same process would fail with `RecreationAttempt` and leave a dead
/// Activity. Worse, winit 0.30.13 ignores `MainEvent::Destroy` (it only logs
/// a TODO), so `app::run` does not return when Android destroys the
/// Activity — while android-activity's `onDestroy` blocks the Java main
/// thread until `android_main` returns. A destroy this process did not start
/// would freeze the window and end in an ANR. So:
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
///    finishes the Activity (the process then stays cached; rule 3 covers
///    the next launch).
/// 2. A destroy watchdog thread checks the Activity every
///    [`WATCHDOG_PERIOD`] and, once Android is taking it down on its own,
///    ends the process with `_exit(0)` instead of letting `onDestroy` hang:
///    * `isFinishing()` — someone else finished it (Back on API < 31, a task
///      removed or cleared, `am`); true from `finish()` on, and set before
///      `onDestroy` for system-side finishes. A finishing Activity is not
///      restarted.
///    * `isChangingConfigurations()` — re-created for a configuration
///      change. The manifest's `configChanges` lists every flag an app can
///      declare, so this takes an undeclarable change (asset paths, e.g. a
///      theme overlay) or `recreate()`; true from the start of the relaunch.
///      A relaunching Activity has no saved state, so ActivityManager would
///      drop it when the process dies; the manifest's `stateNotNeeded`
///      makes it restart the (top) Activity in a fresh process instead.
///      Measured on the API 34 emulator (cutout-overlay toggle): watchdog
///      fires ~125 ms after the ignored Destroy, new process ~130 ms later.
///    * `isDestroyed()` — any other destroy, e.g. the "Don't keep
///      activities" developer option, which destroys a stopped Activity
///      without finishing it: `Activity.performDestroy` sets it before
///      calling `onDestroy`, i.e. while our `onDestroy` is blocked
///      (measured: fires; returning to the app cold-starts it).
/// 3. A second entry in the same process (relaunch into a cached process
///    after rule 1 fell back to returning) logs and ends the process
///    immediately with `_exit(0)`. That Activity is the top one, so
///    ActivityManager restarts it once, in a fresh process, where rule 1's
///    path runs normally (measured: one restart, ~150 ms).
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
    spawn_destroy_watchdog(&app);
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
    // From here on this thread owns the process's end; the watchdog stands
    // down. A watchdog check that was already past its first look at the
    // flag re-reads it after querying the Activity, and even a lost race
    // only ends the process before the Destroy, after `finish()` was
    // accepted, which ActivityManager does not answer with a restart.
    SELF_FINISHING.store(true, Ordering::SeqCst);
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

/// Rule 2 above. The thread owns a clone of `app`, which keeps the Activity
/// global reference it queries valid for the thread's whole life.
fn spawn_destroy_watchdog(app: &AndroidApp) {
    let app = app.clone();
    let spawned = std::thread::Builder::new()
        .name("dd-destroy-watch".into())
        .spawn(move || destroy_watchdog(&app));
    if let Err(e) = spawned {
        tracing::error!("cannot start the destroy watchdog: {e}");
    }
}

fn destroy_watchdog(app: &AndroidApp) {
    let vm = match jni::JavaVM::singleton() {
        Ok(vm) => vm,
        Err(e) => {
            tracing::error!("destroy watchdog: no JavaVM: {e}");
            return;
        }
    };
    let activity = app.activity_as_ptr() as jni::sys::jobject;
    // Attached once, for the thread's life; each check runs in its own
    // local frame (see `destroy_reason`).
    let attached = vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        let mut failures = 0u32;
        loop {
            std::thread::sleep(WATCHDOG_PERIOD);
            if SELF_FINISHING.load(Ordering::SeqCst) {
                return Ok(());
            }
            match destroy_reason(env, activity) {
                Ok(None) => failures = 0,
                Ok(Some(reason)) => {
                    if SELF_FINISHING.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    tracing::warn!(
                        "Activity {reason} by Android, not by us; winit cannot survive its \
                         onDestroy, ending the process"
                    );
                    exit_now();
                }
                Err(e) => {
                    failures += 1;
                    if failures == 1 {
                        tracing::warn!("destroy watchdog: Activity check failed: {e}");
                    }
                    if failures >= WATCHDOG_MAX_FAILURES {
                        tracing::error!(
                            "destroy watchdog: giving up after {failures} failed checks; last: {e}"
                        );
                        return Ok(());
                    }
                }
            }
        }
    });
    if let Err(e) = attached {
        tracing::error!("destroy watchdog stopped: {e}");
    }
}

/// Why the Activity is going away, if it is: one check, in its own JNI local
/// frame so the per-call class and result references never pile up. A Java
/// exception thrown by a call is cleared (and returned as the error) inside
/// the frame, so the frame pops cleanly and the next check starts clean.
fn destroy_reason(
    env: &mut jni::Env<'_>,
    activity: jni::sys::jobject,
) -> jni::errors::Result<Option<&'static str>> {
    env.with_local_frame(8, |env| -> jni::errors::Result<Option<&'static str>> {
        let result = query_activity(env, activity);
        if result.is_err() {
            // Err(CaughtJavaException) if one was pending; else the original.
            env.exception_catch()?;
        }
        result
    })
}

fn query_activity(
    env: &mut jni::Env<'_>,
    activity: jni::sys::jobject,
) -> jni::errors::Result<Option<&'static str>> {
    // SAFETY: `activity` is android-activity's global reference, valid while
    // the watchdog's `AndroidApp` clone lives (the caller's whole life), and
    // a `Cast` borrows it without ever deleting it.
    let activity = unsafe { env.as_cast_raw::<JObject>(&activity)? };
    let finishing = env
        .call_method(&activity, jni_str!("isFinishing"), jni_sig!("()Z"), &[])?
        .z()?;
    if finishing {
        return Ok(Some("finishing"));
    }
    let changing = env
        .call_method(
            &activity,
            jni_str!("isChangingConfigurations"),
            jni_sig!("()Z"),
            &[],
        )?
        .z()?;
    if changing {
        return Ok(Some("re-created for a configuration change"));
    }
    let destroyed = env
        .call_method(&activity, jni_str!("isDestroyed"), jni_sig!("()Z"), &[])?
        .z()?;
    Ok(destroyed.then_some("destroyed"))
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
        native_options: native_options(&app),
    };
    app::run(cfg)
}

/// Widest video texture a typical host needs (a 2560x1600 desktop). An
/// adapter below this cannot show such a host at all.
const MIN_VIDEO_TEXTURE_SIDE: u32 = 2560;
/// What the largest stream needs (the host caps at 4K).
const FULL_VIDEO_TEXTURE_SIDE: u32 = 4096;

/// eframe's defaults (LOW_LATENCY surface included) except for how the wgpu
/// device is requested: see [`device_descriptor`].
fn native_options(app: &AndroidApp) -> eframe::NativeOptions {
    let mut options = eframe::NativeOptions {
        android_app: Some(app.clone()),
        ..Default::default()
    };
    let mut setup = WgpuSetupCreateNew::without_display_handle();
    setup.instance_descriptor.backends = wgpu::Backends::VULKAN | wgpu::Backends::GL;
    setup.device_descriptor = Arc::new(device_descriptor);
    options.wgpu_options.wgpu_setup = WgpuSetup::CreateNew(setup);
    options
}

/// Request exactly the adapter's own limits.
///
/// egui-wgpu's default asks for `wgpu::Limits::default()` (the WebGPU
/// baseline) plus 8192-texel textures, and a device request asking for more
/// than the adapter offers fails outright: under the emulator's SwiftShader
/// Vulkan (`max_uniform_buffer_binding_size` 16384 < 65536) the app never got
/// past startup, and a real GPU reporting the Vulkan minimums would fail the
/// same way. The adapter's own limits always satisfy the request, and they
/// are the most it can do anyway. What the video needs is checked and
/// reported: a stream wider or taller than `max_texture_dimension_2d` cannot
/// be uploaded as one texture.
fn device_descriptor(adapter: &wgpu::Adapter) -> wgpu::DeviceDescriptor<'static> {
    let info = adapter.get_info();
    let limits = adapter.limits();
    let side = limits.max_texture_dimension_2d;
    if side < MIN_VIDEO_TEXTURE_SIDE {
        tracing::error!(
            backend = ?info.backend,
            adapter = %info.name,
            "GPU max texture size {side} < {MIN_VIDEO_TEXTURE_SIDE}: a host desktop wider or \
             taller than {side} pixels cannot be displayed on this device"
        );
    } else if side < FULL_VIDEO_TEXTURE_SIDE {
        tracing::warn!(
            backend = ?info.backend,
            adapter = %info.name,
            "GPU max texture size {side} < {FULL_VIDEO_TEXTURE_SIDE}: a 4K host desktop cannot \
             be displayed on this device"
        );
    }
    tracing::info!(
        backend = ?info.backend,
        adapter = %info.name,
        driver = %info.driver,
        max_texture_dimension_2d = side,
        max_uniform_buffer_binding_size = limits.max_uniform_buffer_binding_size,
        "requesting the wgpu device with the adapter's own limits"
    );
    wgpu::DeviceDescriptor {
        label: Some("directdesk wgpu device"),
        required_limits: limits,
        ..Default::default()
    }
}

/// Client identity and trusted hosts: plaintext files in `<app data>/no_backup`
/// (excluded from backup and device-to-device transfer; see `store_dir`),
/// private to this app's UID. `client.json` stays in the internal data dir.
fn open_store(data_dir: Option<&Path>) -> Result<Arc<dyn SecretStore>, String> {
    let files = data_dir.ok_or_else(|| "no app-private data directory".to_string())?;
    let dir = store_dir::store_dir(files)
        .ok_or_else(|| format!("{} has no parent for no_backup", files.display()))?;
    // Created up front so an unusable directory disables Connect with a
    // clear reason instead of failing at the first pairing.
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let legacy = store_dir::legacy_store_dir(files);
    match store_dir::migrate(&legacy, &dir) {
        Ok(Migration::NothingToMove) => {}
        Ok(Migration::Moved(n)) => tracing::info!(
            "moved {n} secret store file(s) from {} to {}",
            legacy.display(),
            dir.display()
        ),
        Ok(Migration::LeftBehind(n)) => tracing::warn!(
            "{} already holds the secret store; left {n} older file(s) in {}",
            dir.display(),
            legacy.display()
        ),
        Err(e) => tracing::error!(
            "could not move the secret store from {} to {}: {e}",
            legacy.display(),
            dir.display()
        ),
    }
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
