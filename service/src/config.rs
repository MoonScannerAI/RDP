//! Service configuration: `%ProgramData%\DirectDesk\service.json`.
//!
//! Deliberately tiny and deliberately secret-free — this file is machine-wide
//! and readable by every local user. It holds one policy bit: whether the
//! service is allowed to autostart the host agent in the interactive session.
//! A missing or corrupt file means "disabled", never "enabled".

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Launch (and supervise) the host agent when a user is logged on.
    ///
    /// Defaults to `false` — remote access is off until someone turns it on,
    /// and any parse failure lands here too (see [`parse`]).
    #[serde(default)]
    pub autostart_host: bool,

    /// Keep Windows UAC's secure desktop DISABLED
    /// (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop
    /// = 0`) so a remote operator is never frozen out when a UAC prompt
    /// appears — the secure desktop renders on a desktop a remote input/video
    /// pipeline cannot reach.
    ///
    /// SECURITY TRADEOFF: the secure desktop exists to stop other software on
    /// the machine from spoofing or driving the UAC consent prompt. Disabling
    /// it weakens that anti-spoofing protection machine-wide, not just for
    /// DirectDesk. This is opt-in and defaults to `false`; enable it only on
    /// unattended remote-access hosts where you accept that tradeoff.
    ///
    /// A missing field or a parse failure lands on `false`, same as the other
    /// switches in this file.
    #[serde(default)]
    pub disable_uac_secure_desktop: bool,
}

/// Parse config text. Anything unparseable falls back to the safe default
/// (host autostart OFF) rather than failing the service start.
pub fn parse(text: &str) -> ServiceConfig {
    match serde_json::from_str::<ServiceConfig>(text) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!("service.json is not valid config ({e}); using defaults");
            ServiceConfig::default()
        }
    }
}

/// Serialize the config exactly as it is written to disk.
pub fn to_json(cfg: &ServiceConfig) -> String {
    // unwrap: a struct of bool primitives cannot fail to serialize.
    serde_json::to_string_pretty(cfg).unwrap_or_else(|_| {
        "{\n  \"autostart_host\": false,\n  \
         \"disable_uac_secure_desktop\": false\n}"
            .into()
    })
}

/// Read the config, creating a default file if none exists.
///
/// Never returns an error: an unreadable or unwritable config degrades to the
/// safe default so the service still starts and still answers IPC.
pub fn load_or_create(path: &Path) -> ServiceConfig {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let cfg = ServiceConfig::default();
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    tracing::warn!("could not create {}: {e}", parent.display());
                    return cfg;
                }
            }
            if let Err(e) = std::fs::write(path, to_json(&cfg)) {
                tracing::warn!("could not write default config {}: {e}", path.display());
            } else {
                tracing::info!("created default config at {}", path.display());
            }
            cfg
        }
        Err(e) => {
            tracing::warn!("could not read {} ({e}); using defaults", path.display());
            ServiceConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("directdesk-cfg-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn default_is_disabled() {
        assert!(!ServiceConfig::default().autostart_host);
        assert!(!ServiceConfig::default().disable_uac_secure_desktop);
    }

    #[test]
    fn disable_uac_secure_desktop_defaults_false_and_roundtrips() {
        // Default is false.
        assert!(!ServiceConfig::default().disable_uac_secure_desktop);
        // Missing field (existing config files predate this switch) → false.
        assert!(!parse(r#"{"autostart_host": true}"#).disable_uac_secure_desktop);
        assert!(!parse("{}").disable_uac_secure_desktop);
        // Explicit true parses, and survives a write/read cycle (JSON round-trip).
        assert!(parse(r#"{"disable_uac_secure_desktop": true}"#).disable_uac_secure_desktop);
        let cfg = ServiceConfig {
            disable_uac_secure_desktop: true,
            ..Default::default()
        };
        assert_eq!(parse(&to_json(&cfg)), cfg);
    }

    #[test]
    fn parses_true_and_false() {
        assert!(parse(r#"{"autostart_host": true}"#).autostart_host);
        assert!(!parse(r#"{"autostart_host": false}"#).autostart_host);
    }

    #[test]
    fn missing_field_defaults_to_disabled() {
        assert!(!parse("{}").autostart_host);
    }

    #[test]
    fn garbage_falls_back_to_default_not_panic() {
        assert!(!parse("not json at all").autostart_host);
        assert!(!parse("").autostart_host);
        assert!(!parse("[1,2,3]").autostart_host);
        // A hostile value in the file must not become "enabled".
        assert!(!parse(r#"{"autostart_host": "yes"}"#).autostart_host);
    }

    #[test]
    fn roundtrips_through_written_json() {
        let cfg = ServiceConfig {
            autostart_host: true,
            ..Default::default()
        };
        assert_eq!(parse(&to_json(&cfg)), cfg);
    }

    #[test]
    fn load_or_create_creates_default_file() {
        let dir = scratch("create");
        let path = dir.join("service.json");
        let cfg = load_or_create(&path);
        assert!(!cfg.autostart_host);
        assert!(
            path.exists(),
            "default config file should have been created"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!parse(&text).autostart_host);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_create_reads_existing_file() {
        let dir = scratch("read");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("service.json");
        std::fs::write(&path, r#"{"autostart_host": true}"#).unwrap();
        assert!(load_or_create(&path).autostart_host);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
