//! The Windows service itself: SCM entry point, control handler, and the
//! start/stop lifecycle of the two things the service owns — the IPC pipe
//! server and the host-agent supervisor.

use std::ffi::OsString;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use directdesk_shared::svc_ipc::PIPE_NAME;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::dispatch::{AutostartQuery, Backend};
use crate::firewall::WindowsFirewall;
use crate::supervisor::Supervisor;

/// Service key name. Must match what `install` creates and what the installer
/// and client expect.
pub const SERVICE_NAME: &str = "DirectDeskService";
/// Name shown in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "DirectDesk Service";
/// Plain-language description — no euphemisms; this is what the service does.
pub const SERVICE_DESCRIPTION: &str = "Starts and supervises the DirectDesk host agent \
    (DirectDeskHost.exe) in the signed-in user's desktop session so that this computer can \
    accept DirectDesk remote-desktop connections, and creates or removes the DirectDesk \
    Windows Firewall rules on request. It listens only on a local, access-controlled named \
    pipe and accepts a fixed set of commands that take no parameters. It does not open any \
    network port itself and does not transfer any data off this computer.";

/// Only one service type applies: our own process.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Connect to the SCM as a service. Blocks until the service stops.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// Entry point the SCM calls on its own thread.
fn service_main(_arguments: Vec<OsString>) {
    // Logging must be up before anything else so failures are recorded.
    let _guard =
        directdesk_shared::logging::init("service", directdesk_shared::logging::default_log_dir());
    if let Err(e) = run_service() {
        tracing::error!("service terminated with an error: {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    tracing::info!("{SERVICE_NAME} {} starting", env!("CARGO_PKG_VERSION"));

    // The control handler runs on an SCM thread; it must return fast, so it
    // only forwards the intent over a channel.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handler = move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    status_handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
    ))?;

    let started = start_components();
    let (mut pipe_server, mut supervisor, mut secure_desktop) = match started {
        Ok(parts) => parts,
        Err(e) => {
            tracing::error!("startup failed: {e:#}");
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                // A non-zero exit code tells the SCM (and the event log) that
                // this was a real failure, not a clean stop.
                exit_code: ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            return Err(e);
        }
    };

    status_handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;
    tracing::info!("{SERVICE_NAME} running");

    // Park until Stop/Shutdown arrives.
    let _ = stop_rx.recv();
    tracing::info!("stop requested");

    status_handle.set_service_status(status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        1,
    ))?;

    // Drain every subsystem before reporting Stopped.
    pipe_server.shutdown();
    supervisor.shutdown();
    if let Some(reasserter) = secure_desktop.as_mut() {
        reasserter.shutdown();
    }

    status_handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
    ))?;
    tracing::info!("{SERVICE_NAME} stopped");
    Ok(())
}

/// Build the backend and start the pipe server, the supervisor, and (when
/// enabled) the secure-desktop reasserter.
#[allow(clippy::type_complexity)]
fn start_components() -> anyhow::Result<(
    crate::pipe::PipeServer,
    Supervisor,
    Option<crate::secure_desktop::Reasserter>,
)> {
    let host_exe = crate::paths::host_exe_path()?;
    let config = crate::config::load_or_create(&crate::paths::config_path());
    tracing::info!(
        host_exe = %host_exe.display(),
        autostart_host = config.autostart_host,
        "loaded service configuration"
    );

    // Opt-in only: no thread, no registry write, unless the operator asked
    // for it in service.json. See ServiceConfig::disable_uac_secure_desktop
    // for the security tradeoff this switch makes.
    let secure_desktop = if config.disable_uac_secure_desktop {
        tracing::warn!(
            "disable_uac_secure_desktop=true: keeping UAC's secure desktop OFF \
             (weakens UAC anti-spoofing protection machine-wide; opt-in tradeoff)"
        );
        Some(crate::secure_desktop::Reasserter::start()?)
    } else {
        None
    };

    let supervisor = Supervisor::start(host_exe.clone(), config.autostart_host)?;
    let backend = Backend {
        firewall: Arc::new(WindowsFirewall::new(host_exe)),
        supervisor: supervisor.shared(),
        autostart: Arc::new(RegistryAutostart),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let pipe_server = crate::pipe::start(PIPE_NAME, backend, crate::pipe::DEFAULT_INSTANCES)?;
    Ok((pipe_server, supervisor, secure_desktop))
}

/// Reports whether the console user has a DirectDesk entry under HKCU\...\Run.
struct RegistryAutostart;

impl AutostartQuery for RegistryAutostart {
    fn autostart_enabled(&self) -> bool {
        crate::winutil::console_user_autostart_enabled()
    }
}

fn status(state: ServiceState, accepted: ServiceControlAccept, checkpoint: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint: if checkpoint == 0 {
            Duration::default()
        } else {
            Duration::from_secs(15)
        },
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_is_stable_and_plain() {
        // These three strings are a sync point with the installer and the UI.
        assert_eq!(SERVICE_NAME, "DirectDeskService");
        assert_eq!(SERVICE_DISPLAY_NAME, "DirectDesk Service");
        assert!(SERVICE_DESCRIPTION.contains("DirectDeskHost.exe"));
        assert!(SERVICE_DESCRIPTION.contains("named pipe"));
        assert!(SERVICE_DESCRIPTION.contains("Firewall"));
        // Windows truncates absurdly long descriptions in the UI.
        assert!(SERVICE_DESCRIPTION.len() < 1024);
    }

    #[test]
    fn status_helper_marks_running_as_stoppable() {
        let s = status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
        );
        assert_eq!(s.current_state, ServiceState::Running);
        assert!(s.controls_accepted.contains(ServiceControlAccept::STOP));
        assert!(s.controls_accepted.contains(ServiceControlAccept::SHUTDOWN));
        assert_eq!(s.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(s.wait_hint, Duration::default());
    }

    #[test]
    fn pending_states_advertise_no_controls_and_a_wait_hint() {
        let s = status(ServiceState::StartPending, ServiceControlAccept::empty(), 1);
        assert!(s.controls_accepted.is_empty());
        assert!(s.wait_hint > Duration::default());
    }

    #[test]
    fn registry_autostart_query_is_total() {
        // Must return a bool rather than panicking, whatever the environment.
        let _ = RegistryAutostart.autostart_enabled();
    }
}
