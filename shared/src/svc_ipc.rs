//! Service IPC contract: a fixed, ZERO-PARAMETER privileged-op menu over an
//! ACL'd named pipe. The service never accepts commands, paths, script text,
//! or registry values from any client — only these enum variants.

use serde::{Deserialize, Serialize};

pub const PIPE_NAME: &str = r"\\.\pipe\DirectDeskSvc";
/// Max serialized request/response size — these are tiny messages.
pub const MAX_IPC_MSG: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvcRequest {
    Ping,
    GetStatus,
    /// Ensure the DirectDesk firewall rule group exists (exe+port scoped).
    EnsureFirewallRules,
    RemoveFirewallRules,
    /// Ask the service to restart the host agent in the interactive session.
    RestartHostRequested,
    /// Start a transient SYSTEM-integrity input worker that can click the UAC
    /// consent dialog (which the medium-integrity host cannot reach through
    /// UIPI). Still zero-parameter: the *service* mints the data-pipe name and a
    /// one-time capability token and returns them in [`SvcResponse::UacInjectorReady`].
    /// Gated behind the service's `uac_clickthrough` master switch.
    StartUacInjector,
    /// Stop any running SYSTEM injector worker immediately.
    StopUacInjector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvcResponse {
    Pong,
    Status(SvcStatus),
    Ok,
    Denied { reason: String },
    Failed { reason: String },
    /// A SYSTEM injector worker is up. The host connects to `pipe_name` and
    /// presents `cap_token` as the first frame; the token is single-use and was
    /// minted by the service, never supplied by the caller. This is response
    /// (egress) data only — the request that triggered it carried no parameters.
    UacInjectorReady { pipe_name: String, cap_token: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvcStatus {
    pub service_version: String,
    pub host_running: bool,
    pub firewall_rules_present: bool,
    pub autostart_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::decode_strict;

    #[test]
    fn ipc_roundtrip() {
        let req = SvcRequest::EnsureFirewallRules;
        let bytes = postcard::to_stdvec(&req).unwrap();
        assert!(bytes.len() < MAX_IPC_MSG);
        let back: SvcRequest = decode_strict(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn every_request_variant_roundtrips_within_cap() {
        for req in [
            SvcRequest::Ping,
            SvcRequest::GetStatus,
            SvcRequest::EnsureFirewallRules,
            SvcRequest::RemoveFirewallRules,
            SvcRequest::RestartHostRequested,
            SvcRequest::StartUacInjector,
            SvcRequest::StopUacInjector,
        ] {
            let bytes = postcard::to_stdvec(&req).unwrap();
            assert!(bytes.len() < MAX_IPC_MSG);
            assert_eq!(decode_strict::<SvcRequest>(&bytes).unwrap(), req);
        }
    }

    #[test]
    fn uac_injector_ready_roundtrips() {
        let resp = SvcResponse::UacInjectorReady {
            pipe_name: r"\\.\pipe\DirectDeskUac-1-abcdef".into(),
            cap_token: "0123456789abcdef0123456789abcdef".into(),
        };
        let bytes = postcard::to_stdvec(&resp).unwrap();
        assert!(bytes.len() < MAX_IPC_MSG);
        assert_eq!(decode_strict::<SvcResponse>(&bytes).unwrap(), resp);
    }
}
