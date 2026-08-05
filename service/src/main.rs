//! DirectDeskService — the DirectDesk Windows service.
//!
//! Two jobs, both narrow:
//!
//! * launch and supervise `DirectDeskHost.exe` **in the signed-in user's
//!   session, as that user** (see [`supervisor`]), which is the one thing a
//!   user-mode process cannot do for itself;
//! * create and remove the DirectDesk Windows Firewall rules on request
//!   (see [`firewall`]).
//!
//! It exposes those over a local, ACL'd named pipe whose entire vocabulary is a
//! fixed set of parameterless commands (`shared::svc_ipc::SvcRequest`). No path,
//! command line, script, or registry value ever crosses that boundary, so
//! "confused deputy" is not a risk that has to be argued about — the deputy has
//! no way to be told what to do.
//!
//! Command line:
//! ```text
//! DirectDeskService install     create the service (auto start, LocalSystem)
//! DirectDeskService uninstall   stop, delete, and drop the firewall rules
//! DirectDeskService start       start the installed service
//! DirectDeskService stop        stop the installed service
//! DirectDeskService run         run as a service (this is what the SCM calls)
//! ```

mod config;
mod dispatch;
mod firewall;
mod paths;
mod pipe;
mod secure_desktop;
mod supervisor;
mod svc;
mod uac_injector;
mod winutil;

use std::ffi::OsStr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use svc::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};

// Win32 error codes we translate into human sentences.
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_EXISTS: i32 = 1073;
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// How long `start`/`stop` wait for the SCM to reach the requested state.
const STATE_CHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Argument the SCM passes so the exe knows to attach to the service control
/// dispatcher rather than behave as a CLI.
const RUN_VERB: &str = "run";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("install") => finish(cli(install)),
        Some("uninstall") => finish(cli(uninstall)),
        Some("start") => finish(cli(start)),
        Some("stop") => finish(cli(stop)),
        // Explicit `run`, and the no-argument case, both try the SCM first: if
        // we were launched by the service controller we serve, otherwise we
        // explain ourselves instead of hanging.
        Some(RUN_VERB) => finish(run_as_service(true)),
        None => finish(run_as_service(false)),
        Some("-h") | Some("--help") | Some("/?") | Some("help") => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("DirectDeskService: unknown command {other:?}\n");
            eprintln!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    format!(
        "DirectDeskService {version} — {display}\n\
         \n\
         {description}\n\
         \n\
         Usage: DirectDeskService <command>\n\
         \n\
         Commands:\n  \
           install     Register the service (automatic start, runs as LocalSystem). Requires elevation.\n  \
           uninstall   Stop and delete the service, and remove the DirectDesk firewall rules. Requires elevation.\n  \
           start       Start the installed service. Requires elevation.\n  \
           stop        Stop the installed service. Requires elevation.\n  \
           run         Run as a Windows service. The Service Control Manager uses this; it is not\n              \
                       useful from a console.\n",
        version = env!("CARGO_PKG_VERSION"),
        display = SERVICE_DISPLAY_NAME,
        description = SERVICE_DESCRIPTION,
    )
}

fn finish(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("DirectDeskService: {}", explain(&e));
            ExitCode::FAILURE
        }
    }
}

/// Run a management verb with logging initialized so failures are also on disk.
fn cli(f: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    let _guard =
        directdesk_shared::logging::init("service", directdesk_shared::logging::default_log_dir());
    f()
}

/// Turn an error chain into one line, upgrading the common Win32 codes into
/// something a person can act on.
fn explain(e: &anyhow::Error) -> String {
    if let Some(code) = win32_code(e) {
        match code {
            ERROR_ACCESS_DENIED => {
                return "access denied — this command must run elevated (open an \
                        Administrator command prompt and try again)"
                    .to_string();
            }
            ERROR_SERVICE_DOES_NOT_EXIST => {
                return format!(
                    "{SERVICE_NAME} is not installed (run 'DirectDeskService install' first)"
                );
            }
            _ => {}
        }
    }
    let mut s = e.to_string();
    for cause in e.chain().skip(1) {
        s.push_str(&format!(": {cause}"));
    }
    s
}

/// Extract a raw Win32 code from anywhere in an error chain.
fn win32_code(e: &anyhow::Error) -> Option<i32> {
    for cause in e.chain() {
        if let Some(windows_service::Error::Winapi(io)) =
            cause.downcast_ref::<windows_service::Error>()
        {
            return io.raw_os_error();
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if let Some(code) = io.raw_os_error() {
                return Some(code);
            }
        }
    }
    None
}

fn is_code(e: &windows_service::Error, code: i32) -> bool {
    matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}

// ---------------------------------------------------------------------------
// Verbs
// ---------------------------------------------------------------------------

fn service_info() -> anyhow::Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        // Automatic start: the point of the service is to be there before
        // anyone signs in.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![RUN_VERB.into()],
        dependencies: vec![],
        // LocalSystem. Required for WTSQueryUserToken (launching the host in
        // the user's session) and for the firewall API — and for nothing else.
        account_name: None,
        account_password: None,
    })
}

fn install() -> anyhow::Result<()> {
    let info = service_info()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG) {
        Ok(service) => {
            service.set_description(SERVICE_DESCRIPTION)?;
            println!("Installed {SERVICE_NAME} ({SERVICE_DISPLAY_NAME}).");
            println!("  Binary : {}", info.executable_path.display());
            println!("  Start  : automatic, as LocalSystem");
            println!("Start it now with: DirectDeskService start");
            Ok(())
        }
        Err(e) if is_code(&e, ERROR_SERVICE_EXISTS) => {
            // Re-running install (e.g. after an upgrade moved the exe) should
            // refresh the registration rather than fail.
            let service = manager.open_service(
                SERVICE_NAME,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_CONFIG,
            )?;
            service.change_config(&info)?;
            service.set_description(SERVICE_DESCRIPTION)?;
            println!("{SERVICE_NAME} was already installed; its configuration has been updated.");
            println!("  Binary : {}", info.executable_path.display());
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => Some(service),
        Err(e) if is_code(&e, ERROR_SERVICE_DOES_NOT_EXIST) => {
            println!("{SERVICE_NAME} is not installed.");
            None
        }
        Err(e) => return Err(e.into()),
    };

    if let Some(service) = service {
        if service.query_status()?.current_state != ServiceState::Stopped {
            println!("Stopping {SERVICE_NAME}...");
            match service.stop() {
                Ok(_) => wait_for_state(&service, ServiceState::Stopped)?,
                Err(e) if is_code(&e, ERROR_SERVICE_NOT_ACTIVE) => {}
                Err(e) => return Err(e.into()),
            }
        }
        service.delete()?;
        println!("Deleted {SERVICE_NAME}.");
    }

    // Best effort: leaving stale firewall rules behind after an uninstall would
    // be dishonest, but failing to remove them must not fail the uninstall.
    match paths::host_exe_path() {
        Ok(host_exe) => {
            let fw = firewall::WindowsFirewall::new(host_exe);
            match fw.remove_rules() {
                Ok(()) => println!("Removed the {} firewall rule group.", firewall::RULE_GROUP),
                Err(e) => eprintln!(
                    "Warning: could not remove the {} firewall rule group: {e}",
                    firewall::RULE_GROUP
                ),
            }
        }
        Err(e) => eprintln!("Warning: could not resolve the host executable path: {e}"),
    }

    Ok(())
}

fn start() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;

    match service.start(&[] as &[&OsStr]) {
        Ok(()) => {}
        Err(e) if is_code(&e, ERROR_SERVICE_ALREADY_RUNNING) => {
            println!("{SERVICE_NAME} is already running.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    wait_for_state(&service, ServiceState::Running)?;
    println!("{SERVICE_NAME} is running.");
    Ok(())
}

fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;

    match service.stop() {
        Ok(_) => {}
        Err(e) if is_code(&e, ERROR_SERVICE_NOT_ACTIVE) => {
            println!("{SERVICE_NAME} is already stopped.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    wait_for_state(&service, ServiceState::Stopped)?;
    println!("{SERVICE_NAME} is stopped.");
    Ok(())
}

fn wait_for_state(
    service: &windows_service::service::Service,
    want: ServiceState,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + STATE_CHANGE_TIMEOUT;
    loop {
        let state = service.query_status()?.current_state;
        if state == want {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "{SERVICE_NAME} did not reach {want:?} within {}s (it is {state:?})",
                STATE_CHANGE_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Attach to the service control dispatcher. If we were not launched by the
/// SCM, say so plainly instead of failing with a bare error code.
fn run_as_service(explicit: bool) -> anyhow::Result<()> {
    match svc::run() {
        Ok(()) => Ok(()),
        Err(e) if is_code(&e, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) => {
            if explicit {
                eprintln!(
                    "DirectDeskService: 'run' is how the Service Control Manager starts this \
                     program; it cannot be run directly from a console.\n"
                );
                eprintln!("{}", usage());
                anyhow::bail!("not started by the Service Control Manager");
            }
            // Bare invocation from a console or a double-click: explain the tool.
            println!("{}", usage());
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_lists_exactly_the_supported_verbs() {
        let u = usage();
        for verb in ["install", "uninstall", "start", "stop", "run"] {
            assert!(u.contains(verb), "usage should mention {verb}");
        }
        assert!(u.contains("DirectDeskService"));
        assert!(u.contains(SERVICE_DISPLAY_NAME));
    }

    #[test]
    fn service_info_matches_the_installer_contract() {
        let info = service_info().unwrap();
        assert_eq!(info.name, std::ffi::OsString::from("DirectDeskService"));
        assert_eq!(
            info.display_name,
            std::ffi::OsString::from("DirectDesk Service")
        );
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.error_control, ServiceErrorControl::Normal);
        assert_eq!(info.launch_arguments, vec![std::ffi::OsString::from("run")]);
        assert!(info.dependencies.is_empty());
        // LocalSystem is expressed as "no account name", not as a literal.
        assert!(info.account_name.is_none());
        assert!(info.account_password.is_none());
        assert!(info.executable_path.is_absolute());
    }

    #[test]
    fn access_denied_is_explained_as_needing_elevation() {
        let e = anyhow::Error::from(windows_service::Error::Winapi(
            std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED),
        ));
        let msg = explain(&e);
        assert!(msg.contains("elevated"), "got {msg}");
    }

    #[test]
    fn missing_service_is_explained_as_not_installed() {
        let e = anyhow::Error::from(windows_service::Error::Winapi(
            std::io::Error::from_raw_os_error(ERROR_SERVICE_DOES_NOT_EXIST),
        ));
        assert!(explain(&e).contains("not installed"));
    }

    #[test]
    fn other_errors_keep_their_context_chain() {
        let e = anyhow::anyhow!("inner detail").context("outer action");
        let msg = explain(&e);
        assert!(msg.contains("outer action"));
        assert!(msg.contains("inner detail"));
    }

    #[test]
    fn win32_code_is_found_through_context() {
        let e = anyhow::Error::from(windows_service::Error::Winapi(
            std::io::Error::from_raw_os_error(ERROR_SERVICE_EXISTS),
        ))
        .context("creating the service");
        assert_eq!(win32_code(&e), Some(ERROR_SERVICE_EXISTS));
    }

    #[test]
    fn is_code_matches_only_the_right_code() {
        let e =
            windows_service::Error::Winapi(std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED));
        assert!(is_code(&e, ERROR_ACCESS_DENIED));
        assert!(!is_code(&e, ERROR_SERVICE_EXISTS));
    }
}
