//! Request dispatch: the ONLY place a pipe request turns into an action.
//!
//! The IPC surface is the fixed, zero-parameter [`SvcRequest`] enum. There is
//! nothing here that takes a path, a command, a script, a registry value, or
//! any other caller-supplied datum — by construction, not by validation.
//!
//! Everything the dispatcher can touch is behind a trait so the decision logic
//! is unit-testable without a service, a firewall, or an interactive session.

use std::path::PathBuf;
use std::sync::Arc;

use directdesk_shared::svc_ipc::{SvcRequest, SvcResponse, SvcStatus};

pub use crate::uac_injector::UacInjectorOps;

/// Windows Firewall operations the service is willing to perform.
pub trait FirewallOps: Send + Sync {
    /// Create (idempotently) the DirectDesk inbound rule group.
    fn ensure_rules(&self) -> anyhow::Result<()>;
    /// Remove the whole DirectDesk rule group.
    fn remove_rules(&self) -> anyhow::Result<()>;
    /// Are the rules currently present? Best-effort; false when unknown.
    fn rules_present(&self) -> bool;
}

/// Host-agent supervision operations.
pub trait SupervisorOps: Send + Sync {
    /// Is a supervised host process alive right now?
    fn host_running(&self) -> bool;
    /// Ask the supervisor to cycle the host agent.
    fn request_restart(&self) -> anyhow::Result<()>;
}

/// Best-effort read of the console user's autostart entry.
pub trait AutostartQuery: Send + Sync {
    fn autostart_enabled(&self) -> bool;
}

/// The service-side capabilities the dispatcher is allowed to reach.
#[derive(Clone)]
pub struct Backend {
    pub firewall: Arc<dyn FirewallOps>,
    pub supervisor: Arc<dyn SupervisorOps>,
    pub autostart: Arc<dyn AutostartQuery>,
    pub uac: Arc<dyn UacInjectorOps>,
    /// Reported verbatim in [`SvcStatus::service_version`].
    pub service_version: String,
    /// Full path of the installed DirectDesk host binary (the sibling
    /// `DirectDeskHost.exe`). The two UAC-injector verbs are honoured only when
    /// the connected pipe client's image path matches this — see
    /// [`crate::pipe`]'s caller-identity check. Every other verb ignores it.
    pub expected_host_exe: PathBuf,
}

/// Map a fixed request variant onto a response. Pure decision logic.
///
/// `caller_is_trusted_host` is the result of authenticating the connected pipe
/// client's image path against [`Backend::expected_host_exe`]. It gates ONLY the
/// two UAC-injector verbs (the local-UAC-bypass surface): every other verb is
/// parameter-free, already ACL-restricted to same-user callers, and ignores it.
pub fn dispatch(req: SvcRequest, backend: &Backend, caller_is_trusted_host: bool) -> SvcResponse {
    // Requests carry no caller data, so logging the variant is complete and
    // cannot leak anything.
    tracing::info!(request = ?req, "ipc request");

    let response = match req {
        SvcRequest::Ping => SvcResponse::Pong,

        SvcRequest::GetStatus => SvcResponse::Status(SvcStatus {
            service_version: backend.service_version.clone(),
            host_running: backend.supervisor.host_running(),
            firewall_rules_present: backend.firewall.rules_present(),
            autostart_enabled: backend.autostart.autostart_enabled(),
        }),

        SvcRequest::EnsureFirewallRules => match backend.firewall.ensure_rules() {
            Ok(()) => SvcResponse::Ok,
            Err(e) => SvcResponse::Failed { reason: reason(&e) },
        },

        SvcRequest::RemoveFirewallRules => match backend.firewall.remove_rules() {
            Ok(()) => SvcResponse::Ok,
            Err(e) => SvcResponse::Failed { reason: reason(&e) },
        },

        SvcRequest::RestartHostRequested => match backend.supervisor.request_restart() {
            Ok(()) => SvcResponse::Ok,
            Err(e) => SvcResponse::Failed { reason: reason(&e) },
        },

        // The master switch is checked *here*, before the injector is ever
        // touched, so a disabled feature can never spawn a SYSTEM worker.
        SvcRequest::StartUacInjector => {
            if !caller_is_trusted_host {
                // Caller-identity gate: only the installed host binary may drive
                // the SYSTEM click-through. Reject before the injector (and the
                // one-time capability token) is ever touched.
                SvcResponse::Denied {
                    reason: "caller is not the DirectDesk host".into(),
                }
            } else if !backend.uac.enabled() {
                SvcResponse::Denied {
                    reason: "UAC click-through is disabled (uac_clickthrough=false)".to_string(),
                }
            } else {
                match backend.uac.start() {
                    Ok(ready) => SvcResponse::UacInjectorReady {
                        pipe_name: ready.pipe_name,
                        cap_token: ready.cap_token,
                    },
                    Err(e) => SvcResponse::Failed { reason: reason(&e) },
                }
            }
        }

        // Stopping is always safe and idempotent, even when the switch is off —
        // but it still drives the SYSTEM worker, so it too is gated on the
        // caller being the genuine host.
        SvcRequest::StopUacInjector => {
            if !caller_is_trusted_host {
                SvcResponse::Denied {
                    reason: "caller is not the DirectDesk host".into(),
                }
            } else {
                match backend.uac.stop() {
                    Ok(()) => SvcResponse::Ok,
                    Err(e) => SvcResponse::Failed { reason: reason(&e) },
                }
            }
        }
    };

    tracing::info!(response = ?std::mem::discriminant(&response), "ipc response");
    response
}

/// Flatten an error chain into a single bounded line for the wire.
fn reason(e: &anyhow::Error) -> String {
    let mut s = e.to_string();
    for cause in e.chain().skip(1) {
        s.push_str(": ");
        s.push_str(&cause.to_string());
    }
    // Responses are capped by MAX_IPC_MSG; keep the reason well under it.
    s.truncate(512);
    s
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use crate::uac_injector::UacInjectorReady;
    use parking_lot::Mutex;

    #[derive(Default)]
    pub struct MockFirewall {
        pub present: Mutex<bool>,
        pub ensure_calls: Mutex<u32>,
        pub remove_calls: Mutex<u32>,
        pub fail_with: Mutex<Option<String>>,
    }

    impl FirewallOps for MockFirewall {
        fn ensure_rules(&self) -> anyhow::Result<()> {
            *self.ensure_calls.lock() += 1;
            if let Some(msg) = self.fail_with.lock().clone() {
                return Err(anyhow::anyhow!(msg));
            }
            *self.present.lock() = true;
            Ok(())
        }
        fn remove_rules(&self) -> anyhow::Result<()> {
            *self.remove_calls.lock() += 1;
            if let Some(msg) = self.fail_with.lock().clone() {
                return Err(anyhow::anyhow!(msg));
            }
            *self.present.lock() = false;
            Ok(())
        }
        fn rules_present(&self) -> bool {
            *self.present.lock()
        }
    }

    #[derive(Default)]
    pub struct MockSupervisor {
        pub running: Mutex<bool>,
        pub restarts: Mutex<u32>,
        pub fail_with: Mutex<Option<String>>,
    }

    impl SupervisorOps for MockSupervisor {
        fn host_running(&self) -> bool {
            *self.running.lock()
        }
        fn request_restart(&self) -> anyhow::Result<()> {
            *self.restarts.lock() += 1;
            match self.fail_with.lock().clone() {
                Some(msg) => Err(anyhow::anyhow!(msg)),
                None => Ok(()),
            }
        }
    }

    pub struct MockAutostart(pub bool);
    impl AutostartQuery for MockAutostart {
        fn autostart_enabled(&self) -> bool {
            self.0
        }
    }

    /// Records start/stop calls and honours an `enabled` flag. The dispatcher
    /// gates on `enabled()` *before* calling `start`, so a disabled mock should
    /// never see a `start` call.
    #[derive(Default)]
    pub struct MockUacInjector {
        pub enabled: Mutex<bool>,
        pub starts: Mutex<u32>,
        pub stops: Mutex<u32>,
        pub fail_with: Mutex<Option<String>>,
    }

    impl UacInjectorOps for MockUacInjector {
        fn enabled(&self) -> bool {
            *self.enabled.lock()
        }
        fn start(&self) -> anyhow::Result<UacInjectorReady> {
            *self.starts.lock() += 1;
            if let Some(msg) = self.fail_with.lock().clone() {
                return Err(anyhow::anyhow!(msg));
            }
            Ok(UacInjectorReady {
                pipe_name: r"\\.\pipe\DirectDeskUac-1-deadbeefdeadbeef".to_string(),
                cap_token: "00112233445566778899aabbccddeeff".to_string(),
            })
        }
        fn stop(&self) -> anyhow::Result<()> {
            *self.stops.lock() += 1;
            match self.fail_with.lock().clone() {
                Some(msg) => Err(anyhow::anyhow!(msg)),
                None => Ok(()),
            }
        }
    }

    pub struct Harness {
        pub firewall: Arc<MockFirewall>,
        pub supervisor: Arc<MockSupervisor>,
        pub uac: Arc<MockUacInjector>,
        pub backend: Backend,
    }

    pub fn harness() -> Harness {
        let firewall = Arc::new(MockFirewall::default());
        let supervisor = Arc::new(MockSupervisor::default());
        let uac = Arc::new(MockUacInjector::default());
        let backend = Backend {
            firewall: firewall.clone(),
            supervisor: supervisor.clone(),
            autostart: Arc::new(MockAutostart(false)),
            uac: uac.clone(),
            service_version: "9.9.9-test".to_string(),
            expected_host_exe: PathBuf::from(r"C:\Program Files\DirectDesk\DirectDeskHost.exe"),
        };
        Harness {
            firewall,
            supervisor,
            uac,
            backend,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;

    #[test]
    fn ping_returns_pong() {
        let h = harness();
        assert_eq!(
            dispatch(SvcRequest::Ping, &h.backend, true),
            SvcResponse::Pong
        );
    }

    #[test]
    fn get_status_reports_backend_state() {
        let h = harness();
        *h.supervisor.running.lock() = true;
        *h.firewall.present.lock() = true;
        let resp = dispatch(SvcRequest::GetStatus, &h.backend, true);
        match resp {
            SvcResponse::Status(s) => {
                assert_eq!(s.service_version, "9.9.9-test");
                assert!(s.host_running);
                assert!(s.firewall_rules_present);
                assert!(!s.autostart_enabled);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn ensure_and_remove_firewall_rules_flip_presence() {
        let h = harness();
        assert!(!h.firewall.rules_present());
        assert_eq!(
            dispatch(SvcRequest::EnsureFirewallRules, &h.backend, true),
            SvcResponse::Ok
        );
        assert!(h.firewall.rules_present());
        assert_eq!(*h.firewall.ensure_calls.lock(), 1);

        assert_eq!(
            dispatch(SvcRequest::RemoveFirewallRules, &h.backend, true),
            SvcResponse::Ok
        );
        assert!(!h.firewall.rules_present());
        assert_eq!(*h.firewall.remove_calls.lock(), 1);
    }

    #[test]
    fn firewall_failure_becomes_failed_response() {
        let h = harness();
        *h.firewall.fail_with.lock() = Some("access is denied".into());
        match dispatch(SvcRequest::EnsureFirewallRules, &h.backend, true) {
            SvcResponse::Failed { reason } => assert!(reason.contains("access is denied")),
            other => panic!("expected Failed, got {other:?}"),
        }
        match dispatch(SvcRequest::RemoveFirewallRules, &h.backend, true) {
            SvcResponse::Failed { reason } => assert!(reason.contains("access is denied")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn restart_host_nudges_supervisor() {
        let h = harness();
        assert_eq!(
            dispatch(SvcRequest::RestartHostRequested, &h.backend, true),
            SvcResponse::Ok
        );
        assert_eq!(*h.supervisor.restarts.lock(), 1);
    }

    #[test]
    fn restart_failure_becomes_failed_response() {
        let h = harness();
        *h.supervisor.fail_with.lock() = Some("no interactive session".into());
        match dispatch(SvcRequest::RestartHostRequested, &h.backend, true) {
            SvcResponse::Failed { reason } => assert!(reason.contains("no interactive session")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn every_request_variant_is_handled_without_panicking() {
        let h = harness();
        for req in [
            SvcRequest::Ping,
            SvcRequest::GetStatus,
            SvcRequest::EnsureFirewallRules,
            SvcRequest::RemoveFirewallRules,
            SvcRequest::RestartHostRequested,
            SvcRequest::StartUacInjector,
            SvcRequest::StopUacInjector,
        ] {
            // Trusted and untrusted callers both must be handled without panic.
            let _ = dispatch(req, &h.backend, true);
            let _ = dispatch(req, &h.backend, false);
        }
    }

    #[test]
    fn start_uac_injector_is_denied_when_master_switch_is_off() {
        let h = harness();
        // Default harness has the switch off.
        assert!(!*h.uac.enabled.lock());
        // A trusted caller still hits the master-switch denial.
        match dispatch(SvcRequest::StartUacInjector, &h.backend, true) {
            SvcResponse::Denied { reason } => {
                assert!(reason.contains("uac_clickthrough=false"), "got {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        // The injector must not have been touched.
        assert_eq!(*h.uac.starts.lock(), 0);
    }

    #[test]
    fn start_uac_injector_is_denied_for_an_untrusted_caller_even_when_enabled() {
        let h = harness();
        // Feature is ON, but the caller is not the genuine host binary.
        *h.uac.enabled.lock() = true;
        match dispatch(SvcRequest::StartUacInjector, &h.backend, false) {
            SvcResponse::Denied { reason } => {
                assert!(reason.contains("not the DirectDesk host"), "got {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        // The caller-identity gate runs BEFORE the injector, so start() is never
        // reached: no SYSTEM worker is spawned for an untrusted caller.
        assert_eq!(*h.uac.starts.lock(), 0);
    }

    #[test]
    fn start_uac_injector_launches_and_returns_ready_when_enabled() {
        let h = harness();
        *h.uac.enabled.lock() = true;
        // Trusted caller + enabled → Ready.
        match dispatch(SvcRequest::StartUacInjector, &h.backend, true) {
            SvcResponse::UacInjectorReady {
                pipe_name,
                cap_token,
            } => {
                assert!(pipe_name.starts_with(r"\\.\pipe\DirectDeskUac-"));
                assert_eq!(cap_token.len(), 32);
            }
            other => panic!("expected UacInjectorReady, got {other:?}"),
        }
        assert_eq!(*h.uac.starts.lock(), 1);
    }

    #[test]
    fn start_uac_injector_failure_becomes_failed_response() {
        let h = harness();
        *h.uac.enabled.lock() = true;
        *h.uac.fail_with.lock() = Some("no interactive session".into());
        match dispatch(SvcRequest::StartUacInjector, &h.backend, true) {
            SvcResponse::Failed { reason } => assert!(reason.contains("no interactive session")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn stop_uac_injector_calls_stop_once_and_is_ok_even_when_disabled() {
        let h = harness();
        // Switch is off, but Stop is still honoured (idempotent teardown) for the
        // trusted host.
        assert_eq!(
            dispatch(SvcRequest::StopUacInjector, &h.backend, true),
            SvcResponse::Ok
        );
        assert_eq!(*h.uac.stops.lock(), 1);
    }

    #[test]
    fn stop_uac_injector_is_denied_for_an_untrusted_caller() {
        let h = harness();
        match dispatch(SvcRequest::StopUacInjector, &h.backend, false) {
            SvcResponse::Denied { reason } => {
                assert!(reason.contains("not the DirectDesk host"), "got {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        // stop() must not have been driven by an untrusted caller.
        assert_eq!(*h.uac.stops.lock(), 0);
    }

    #[test]
    fn reason_is_bounded_and_includes_causes() {
        let e = anyhow::anyhow!("root cause").context("outer");
        let r = reason(&e);
        assert!(r.starts_with("outer"));
        assert!(r.contains("root cause"));

        let long = anyhow::anyhow!("x".repeat(5000));
        assert!(reason(&long).len() <= 512);
    }
}
