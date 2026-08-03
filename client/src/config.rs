//! Client-side persisted settings: `%APPDATA%\DirectDesk\client.json`.
//!
//! SECURITY: this file holds **no secrets**. Pairing codes, long-term keys and
//! any other credential material live in the crypto store, never here. Keep it
//! that way — this file is world-readable by anything running as the user.

use std::path::PathBuf;

use directdesk_shared::protocol::{QualityMode, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// Last host address typed by the user (hostname or IP, no port).
    pub host_address: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// Friendly name this client presents to the host. Empty means "derive one
    /// from the machine name"; never holds a secret.
    #[serde(default)]
    pub display_name: String,
    pub quality_mode: QualityMode,
    pub show_diagnostics: bool,
    pub start_fullscreen: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            host_address: String::new(),
            udp_port: DEFAULT_UDP_PORT,
            tcp_port: DEFAULT_TCP_PORT,
            display_name: String::new(),
            quality_mode: QualityMode::Balanced,
            show_diagnostics: false,
            start_fullscreen: false,
        }
    }
}

/// `%APPDATA%\DirectDesk\client.json` (roaming), or `None` if the OS has no
/// config directory for us.
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("DirectDesk").join("client.json"))
}

impl ClientConfig {
    /// Never fails: a missing or corrupt file yields defaults (and a log line).
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<ClientConfig>(&text) {
                Ok(cfg) => {
                    tracing::debug!(path = %path.display(), "loaded client config");
                    cfg.sanitized()
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), "config unreadable ({e}); using defaults");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                tracing::warn!(path = %path.display(), "config read failed ({e}); using defaults");
                Self::default()
            }
        }
    }

    pub fn save(&self) {
        let Some(path) = config_path() else { return };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(path = %parent.display(), "cannot create config dir: {e}");
                return;
            }
        }
        match serde_json::to_string_pretty(self) {
            Ok(text) => {
                if let Err(e) = std::fs::write(&path, text) {
                    tracing::warn!(path = %path.display(), "config write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("config serialize failed: {e}"),
        }
    }

    /// Clamp anything a hand-edited file could have broken.
    fn sanitized(mut self) -> Self {
        if self.udp_port == 0 {
            self.udp_port = DEFAULT_UDP_PORT;
        }
        if self.tcp_port == 0 {
            self.tcp_port = DEFAULT_TCP_PORT;
        }
        self.host_address.truncate(255);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_contract_ports() {
        let c = ClientConfig::default();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.tcp_port, DEFAULT_TCP_PORT);
        assert_eq!(c.udp_port, 47990);
        assert_eq!(c.tcp_port, 47991);
    }

    #[test]
    fn roundtrips_through_json() {
        let c = ClientConfig {
            host_address: "10.0.0.5".into(),
            quality_mode: QualityMode::Motion,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: ClientConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn partial_json_falls_back_to_defaults() {
        // `#[serde(default)]` must tolerate an older/newer file shape.
        let back: ClientConfig = serde_json::from_str(r#"{"host_address":"pc.lan"}"#).unwrap();
        assert_eq!(back.host_address, "pc.lan");
        assert_eq!(back.udp_port, DEFAULT_UDP_PORT);
    }

    #[test]
    fn zero_ports_are_repaired() {
        let c = ClientConfig {
            udp_port: 0,
            tcp_port: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.tcp_port, DEFAULT_TCP_PORT);
    }
}
