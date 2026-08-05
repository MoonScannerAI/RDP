//! Host-side persisted settings: `%ProgramData%\DirectDesk\host.json`.
//!
//! SECURITY: this file holds **no secrets**. The host's Ed25519 identity, its
//! TLS key and the trusted-client list live in the DPAPI store
//! ([`directdesk_shared::crypto::storage::DpapiFileStore::host`]), which writes
//! into the same directory but as encrypted `*.dpapi` blobs. Anything added
//! here is readable by every local user — keep it that way.
//!
//! Loading is deliberately forgiving: a missing file yields defaults and is
//! written back, and a corrupt or partial file yields defaults with a warning
//! rather than refusing to start. A remote-access host that will not launch
//! because someone hand-edited a JSON file is worse than one that launches with
//! documented defaults.

use std::path::PathBuf;

use directdesk_shared::protocol::{QualityMode, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};
use serde::{Deserialize, Serialize};

/// Directory under `%ProgramData%` shared with the DPAPI secret store.
pub const APP_DIR: &str = "DirectDesk";
/// File name inside [`APP_DIR`].
pub const CONFIG_FILE: &str = "host.json";

/// Lowest bitrate the UI will let a user pin the encoder to.
pub const MIN_BITRATE_KBPS: u32 = 300;
/// Highest bitrate the UI will let a user pin the encoder to.
pub const MAX_BITRATE_KBPS: u32 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostConfig {
    /// Master switch. `false` means the QUIC listener is never opened — no
    /// hidden mode: the tray icon then reports "remote access off".
    pub remote_access_enabled: bool,
    /// UDP port for QUIC.
    pub udp_port: u16,
    /// TCP port reserved for the fallback transport (not opened by this build).
    pub tcp_port: u16,
    /// Friendly name sent to clients in `PairComplete` and shown in their UI.
    /// Only used the first time an identity is created; afterwards the stored
    /// identity keeps the name it was paired under.
    pub display_name: String,
    /// Default quality mode for a new session.
    pub quality_mode: QualityMode,
    /// Encoder frame-rate ceiling.
    pub target_fps: u32,
    /// Encoder starting bitrate.
    pub bitrate_kbps: u32,
    /// Hard ceiling the adaptive controller may never exceed. `None` = no cap.
    pub bitrate_cap_kbps: Option<u32>,
    /// Seconds between forced IDR frames.
    pub gop_seconds: u32,
    /// Re-send the last image after this long with no desktop change (ms).
    /// `0` disables the keepalive entirely. See the migration in [`sanitized`]:
    /// the old `33` default is healed on load.
    ///
    /// [`sanitized`]: HostConfig::sanitized
    pub idle_repeat_ms: u32,
    /// Start with the window hidden in the tray. `--minimized` also sets this
    /// for one run without persisting it.
    pub start_minimized: bool,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            remote_access_enabled: true,
            udp_port: DEFAULT_UDP_PORT,
            tcp_port: DEFAULT_TCP_PORT,
            display_name: default_display_name(),
            quality_mode: QualityMode::Balanced,
            target_fps: 60,
            bitrate_kbps: 12_000,
            bitrate_cap_kbps: None,
            gop_seconds: 4,
            idle_repeat_ms: 250,
            start_minimized: false,
        }
    }
}

/// This machine's name, trimmed to what [`validate_name`] accepts.
///
/// [`validate_name`]: directdesk_shared::crypto::identity::validate_name
pub fn default_display_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    sanitize_name(&raw).unwrap_or_else(|| "DirectDesk host".to_string())
}

/// Make an arbitrary string safe to use as a DirectDesk friendly name, or
/// `None` if nothing usable survives.
///
/// Names cross the wire (`PairComplete`, and the label a paired client is
/// stored under), so control characters are stripped and the length is capped
/// at the shared crate's limit rather than trusted.
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return None;
    }
    let limit = directdesk_shared::crypto::identity::MAX_NAME_LEN;
    let mut out = String::with_capacity(limit.min(cleaned.len()));
    for c in cleaned.chars() {
        if out.len() + c.len_utf8() > limit {
            break;
        }
        out.push(c);
    }
    let out = out.trim_end().to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `%ProgramData%\DirectDesk` — the same directory the DPAPI store uses.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|base| PathBuf::from(base).join(APP_DIR))
}

/// `%ProgramData%\DirectDesk\host.json`.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(CONFIG_FILE))
}

impl HostConfig {
    /// Load the config, creating it with defaults if it is missing.
    ///
    /// Never fails: every error path falls back to defaults and logs.
    pub fn load_or_create() -> Self {
        let Some(path) = config_path() else {
            tracing::warn!("ProgramData is not set; using in-memory host defaults");
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<HostConfig>(&text) {
                Ok(cfg) => {
                    tracing::info!(path = %path.display(), "loaded host config");
                    cfg.sanitized()
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), "host config unreadable ({e}); using defaults");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Self::default();
                cfg.save();
                tracing::info!(path = %path.display(), "created host config with defaults");
                cfg
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "host config read failed ({e}); using defaults");
                Self::default()
            }
        }
    }

    /// Persist. Failures are logged, never fatal — a read-only ProgramData must
    /// not stop the host from serving.
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
                    tracing::warn!(path = %path.display(), "host config write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("host config serialize failed: {e}"),
        }
    }

    /// Clamp everything a hand-edited file could have broken.
    pub fn sanitized(mut self) -> Self {
        if self.udp_port == 0 {
            self.udp_port = DEFAULT_UDP_PORT;
        }
        if self.tcp_port == 0 {
            self.tcp_port = DEFAULT_TCP_PORT;
        }
        self.target_fps = self.target_fps.clamp(1, 240);
        self.gop_seconds = self.gop_seconds.clamp(1, 30);
        // Migration: 33 ms was the old default — ~30 identical full frames a
        // second on a still desktop. Every host that ever started once has it
        // persisted, so the fix would never reach them without healing it here.
        // The cost is that a *deliberate* 33 is no longer expressible; nothing
        // offers it and 30/s of identical frames is not what anyone meant.
        if self.idle_repeat_ms == 33 {
            self.idle_repeat_ms = 250;
        }
        self.idle_repeat_ms = self.idle_repeat_ms.min(5_000);
        self.bitrate_kbps = self.bitrate_kbps.clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS);
        self.bitrate_cap_kbps = self
            .bitrate_cap_kbps
            .map(|c| c.clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS));
        self.display_name = sanitize_name(&self.display_name).unwrap_or_else(default_display_name);
        self
    }

    /// The pipeline configuration implied by these settings.
    pub fn pipeline(&self) -> crate::session::SessionConfig {
        crate::session::SessionConfig {
            target_fps: self.target_fps,
            bitrate_kbps: self.bitrate_kbps,
            gop_seconds: self.gop_seconds,
            idle_repeat_ms: self.idle_repeat_ms,
            force_cpu_convert: false,
            frame_queue_depth: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_contract_ports() {
        let c = HostConfig::default();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.udp_port, 47990);
        assert_eq!(c.tcp_port, 47991);
        assert!(c.remote_access_enabled);
    }

    #[test]
    fn roundtrips_through_json() {
        let c = HostConfig {
            display_name: "workstation".into(),
            quality_mode: QualityMode::Motion,
            bitrate_cap_kbps: Some(6_000),
            start_minimized: true,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: HostConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn partial_json_falls_back_to_defaults() {
        let back: HostConfig = serde_json::from_str(r#"{"udp_port":50000}"#).unwrap();
        assert_eq!(back.udp_port, 50_000);
        assert_eq!(back.tcp_port, DEFAULT_TCP_PORT);
        assert!(back.remote_access_enabled);
        assert_eq!(back.target_fps, 60);
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        // A newer build's config must not brick an older one.
        let back: HostConfig =
            serde_json::from_str(r#"{"udp_port":47990,"future_option":true}"#).unwrap();
        assert_eq!(back.udp_port, 47990);
    }

    #[test]
    fn sanitize_repairs_nonsense() {
        let c = HostConfig {
            udp_port: 0,
            tcp_port: 0,
            target_fps: 0,
            gop_seconds: 9_999,
            bitrate_kbps: 1,
            bitrate_cap_kbps: Some(u32::MAX),
            display_name: String::new(),
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.tcp_port, DEFAULT_TCP_PORT);
        assert_eq!(c.target_fps, 1);
        assert_eq!(c.gop_seconds, 30);
        assert_eq!(c.bitrate_kbps, MIN_BITRATE_KBPS);
        assert_eq!(c.bitrate_cap_kbps, Some(MAX_BITRATE_KBPS));
        assert!(!c.display_name.is_empty());
    }

    #[test]
    fn name_sanitizing_matches_shared_validation() {
        use directdesk_shared::crypto::identity::{validate_name, MAX_NAME_LEN};
        assert_eq!(sanitize_name("  desk  ").as_deref(), Some("desk"));
        assert_eq!(sanitize_name("bad\nname").as_deref(), Some("badname"));
        assert_eq!(sanitize_name("   ").as_deref(), None);
        assert_eq!(sanitize_name("").as_deref(), None);

        let long = sanitize_name(&"x".repeat(MAX_NAME_LEN * 3)).unwrap();
        assert_eq!(long.len(), MAX_NAME_LEN);
        assert!(validate_name(&long).is_ok());
        assert!(validate_name(&sanitize_name("héllo wörld").unwrap()).is_ok());
        assert!(validate_name(&default_display_name()).is_ok());
    }

    #[test]
    fn idle_repeat_heals_the_old_default() {
        // A host that has run before has 33 persisted; the bandwidth fix has to
        // reach it on load, not only on a fresh install.
        let healed = HostConfig {
            idle_repeat_ms: 33,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(healed.idle_repeat_ms, 250);
        assert_eq!(HostConfig::default().idle_repeat_ms, 250);

        // Any other value is the operator's, including 0 (keepalive off).
        for kept in [0u32, 100] {
            let c = HostConfig {
                idle_repeat_ms: kept,
                ..Default::default()
            }
            .sanitized();
            assert_eq!(c.idle_repeat_ms, kept);
        }
        // The clamp still applies on top of the migration.
        let clamped = HostConfig {
            idle_repeat_ms: 99_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(clamped.idle_repeat_ms, 5_000);
    }

    #[test]
    fn pipeline_config_follows_settings() {
        let c = HostConfig {
            target_fps: 30,
            bitrate_kbps: 4_000,
            ..Default::default()
        };
        let p = c.pipeline();
        assert_eq!(p.target_fps, 30);
        assert_eq!(p.bitrate_kbps, 4_000);
    }
}
