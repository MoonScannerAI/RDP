//! Request dispatch: the ONLY place a pipe request turns into an action.
//!
//! The IPC surface is the fixed, zero-parameter [`SvcRequest`] enum. There is
//! nothing here that takes a path, a command, a script, a registry value, or
//! any other caller-supplied datum — by construction, not by validation.
//!
//! Everything the dispatcher can touch is behind a trait so the decision logic
//! is unit-testable without a service, a firewall, or an interactive session.

use std::sync::Arc;

use directdesk_shared::svc_ipc::{SvcRequest, SvcResponse, SvcStatus};

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
    /// Reported verbatim in [`SvcStatus::service_version`].
    pub service_version: String,
}

/// Map a fixed request variant onto a response. Pure decision logic.
pub fn dispatch(req: SvcRequest, backend: &Backend) -> SvcResponse {
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

    pub struct Harness {
        pub firewall: Arc<MockFirewall>,
        pub supervisor: Arc<MockSupervisor>,
        pub backend: Backend,
    }

    pub fn harness() -> Harness {
        let firewall = Arc::new(MockFirewall::default());
        let supervisor = Arc::new(MockSupervisor::default());
        let backend = Backend {
            firewall: firewall.clone(),
            supervisor: supervisor.clone(),
            autostart: Arc::new(MockAutostart(false)),
            service_version: "9.9.9-test".to_string(),
        };
        Harness {
            firewall,
            supervisor,
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
        assert_eq!(dispatch(SvcRequest::Ping, &h.backend), SvcResponse::Pong);
    }

    #[test]
    fn get_status_reports_backend_state() {
        let h = harness();
        *h.supervisor.running.lock() = true;
        *h.firewall.present.lock() = true;
        let resp = dispatch(SvcRequest::GetStatus, &h.backend);
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
            dispatch(SvcRequest::EnsureFirewallRules, &h.backend),
            SvcResponse::Ok
        );
        assert!(h.firewall.rules_present());
        assert_eq!(*h.firewall.ensure_calls.lock(), 1);

        assert_eq!(
            dispatch(SvcRequest::RemoveFirewallRules, &h.backend),
            SvcResponse::Ok
        );
        assert!(!h.firewall.rules_present());
        assert_eq!(*h.firewall.remove_calls.lock(), 1);
    }

    #[test]
    fn firewall_failure_becomes_failed_response() {
        let h = harness();
        *h.firewall.fail_with.lock() = Some("access is denied".into());
        match dispatch(SvcRequest::EnsureFirewallRules, &h.backend) {
            SvcResponse::Failed { reason } => assert!(reason.contains("access is denied")),
            other => panic!("expected Failed, got {other:?}"),
        }
        match dispatch(SvcRequest::RemoveFirewallRules, &h.backend) {
            SvcResponse::Failed { reason } => assert!(reason.contains("access is denied")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn restart_host_nudges_supervisor() {
        let h = harness();
        assert_eq!(
            dispatch(SvcRequest::RestartHostRequested, &h.backend),
            SvcResponse::Ok
        );
        assert_eq!(*h.supervisor.restarts.lock(), 1);
    }

    #[test]
    fn restart_failure_becomes_failed_response() {
        let h = harness();
        *h.supervisor.fail_with.lock() = Some("no interactive session".into());
        match dispatch(SvcRequest::RestartHostRequested, &h.backend) {
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
        ] {
            let _ = dispatch(req, &h.backend);
        }
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
