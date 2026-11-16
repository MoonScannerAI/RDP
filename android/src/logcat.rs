//! Logging for the Android app: `tracing` (and the `log` crate, via
//! tracing-subscriber's `tracing-log` bridge) → logcat under tag
//! `DirectDesk`, plus a panic hook that writes the panic, its location and a
//! backtrace straight to logcat.
//!
//! Writes are synchronous `__android_log_write` calls. stdout/stderr are also
//! piped to logcat by android-activity, but through a background thread — a
//! panic followed by `process::exit` can beat it — so nothing here relies on
//! them.
//!
//! Filter: `info` plus quiet wgpu/quinn/rustls, overridable without a rebuild:
//! `adb shell setprop debug.directdesk.log "debug,wgpu_core=warn"` then
//! restart the app.

use std::ffi::CStr;
use std::io;
use std::sync::Once;

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::sys::{self, Priority};

/// The logcat tag for everything this app writes.
pub const TAG: &CStr = c"DirectDesk";

/// Matches the desktop default in `directdesk_shared::logging`, plus naga.
const DEFAULT_FILTER: &str = "info,quinn=warn,rustls=warn,wgpu_core=warn,wgpu_hal=warn,naga=warn";

/// System property holding an `EnvFilter` directive string.
const FILTER_PROPERTY: &str = "debug.directdesk.log";

/// Log one line straight to logcat, bypassing tracing (for use before the
/// subscriber exists, and from the panic hook).
pub fn raw(prio: Priority, msg: &str) {
    sys::log_write(prio, TAG, msg);
}

/// Install the panic hook and the global subscriber. Process-global, so it
/// runs once even if `android_main` is entered again for a new Activity.
pub fn init() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        install_panic_hook();
        install_subscriber();
    });
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown location>".to_string());
        let thread = std::thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");
        raw(
            Priority::Fatal,
            &format!("PANIC in thread '{thread}' at {location}: {msg}"),
        );
        // `force_capture`: RUST_BACKTRACE is never set on a phone. The .so
        // ships unstripped (profile.release strip = "none") and is extracted
        // to disk, so frames symbolize.
        let backtrace = std::backtrace::Backtrace::force_capture();
        raw(Priority::Error, &format!("panic backtrace:\n{backtrace}"));
    }));
}

fn install_subscriber() {
    let custom = sys::system_property(FILTER_PROPERTY);
    let filter = match custom.as_deref().map(EnvFilter::try_new) {
        Some(Ok(f)) => f,
        Some(Err(e)) => {
            raw(
                Priority::Warn,
                &format!("ignoring bad {FILTER_PROPERTY} filter: {e}; using \"{DEFAULT_FILTER}\""),
            );
            EnvFilter::new(DEFAULT_FILTER)
        }
        None => EnvFilter::new(DEFAULT_FILTER),
    };
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(Logcat)
        .with_ansi(false)
        // logcat stamps time, pid/tid and the level letter itself.
        .without_time()
        .with_level(false)
        .with_target(true);
    // `try_init` also installs the `log` → tracing bridge (tracing-log), so
    // winit/eframe/wgpu records land here too.
    if let Err(e) = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
    {
        raw(
            Priority::Warn,
            &format!("tracing subscriber not installed: {e}"),
        );
    }
}

/// `MakeWriter` handing out one buffered line per event at the event's
/// priority. The fmt layer formats an event completely and then writes it in
/// one go, so flushing on drop emits exactly one logcat entry per event.
struct Logcat;

impl<'a> MakeWriter<'a> for Logcat {
    type Writer = LogcatLine;

    fn make_writer(&'a self) -> Self::Writer {
        LogcatLine::new(Priority::Info)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        LogcatLine::new(match *meta.level() {
            Level::ERROR => Priority::Error,
            Level::WARN => Priority::Warn,
            Level::INFO => Priority::Info,
            // logcat has VERBOSE below DEBUG, but release builds of many
            // devices drop it; keep TRACE visible when someone asks for it.
            Level::DEBUG | Level::TRACE => Priority::Debug,
        })
    }
}

struct LogcatLine {
    prio: Priority,
    buf: Vec<u8>,
}

impl LogcatLine {
    fn new(prio: Priority) -> Self {
        Self {
            prio,
            buf: Vec::with_capacity(256),
        }
    }
}

impl io::Write for LogcatLine {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogcatLine {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            raw(self.prio, &String::from_utf8_lossy(&self.buf));
        }
    }
}
