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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvcResponse {
    Pong,
    Status(SvcStatus),
    Ok,
    Denied { reason: String },
    Failed { reason: String },
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
}
