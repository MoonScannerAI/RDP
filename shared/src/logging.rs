//! Central logging init. Every exe calls [`init`] first thing in main().
//! Never log key contents, pairing codes, or secret material — wrap those in
//! [`crate::secret::Secret`] which redacts itself.

use std::path::PathBuf;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Guard that must stay alive for the duration of the process so the file
/// appender flushes on exit (including panics — profiles use panic=unwind).
pub struct LogGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initialize tracing: console + optional daily-rotated file under `log_dir`.
/// `component` names the file, e.g. "host" → host.YYYY-MM-DD.log.
pub fn init(component: &str, log_dir: Option<PathBuf>) -> LogGuard {
    let filter = EnvFilter::try_from_env("DIRECTDESK_LOG").unwrap_or_else(|_| {
        EnvFilter::new("info,quinn=warn,rustls=warn,wgpu_core=warn,wgpu_hal=warn")
    });

    let console = fmt::layer().with_target(true).with_ansi(false);

    let (file_layer, file_guard) = match log_dir {
        Some(dir) => {
            let appender = tracing_appender::rolling::daily(dir, format!("{component}.log"));
            let (nb, guard) = tracing_appender::non_blocking(appender);
            let layer = fmt::layer()
                .with_target(true)
                .with_ansi(false)
                .with_writer(nb);
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(file_layer)
        .init();

    install_panic_hook(component);

    LogGuard {
        _file_guard: file_guard,
    }
}

/// Default log directory: %LOCALAPPDATA%\DirectDesk\logs
pub fn default_log_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|base| PathBuf::from(base).join("DirectDesk").join("logs"))
}

fn install_panic_hook(component: &str) {
    let component = component.to_string();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(component = %component, "panic: {info}");
        prev(info);
    }));
}
