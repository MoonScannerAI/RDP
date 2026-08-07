//! Pure connect-form model: parse and validate the user's text inputs and
//! decide pairing-vs-auth mode, with no egui or transport dependency so it can
//! be unit-tested in isolation.
//!
//! The UI owns the live `String` buffers; this module turns them into a checked
//! [`ConnectRequest`] (or a human-readable error) at the moment the user clicks
//! Connect.

use directdesk_shared::crypto::pairing::PAIRING_CODE_DIGITS;
use directdesk_shared::protocol::QualityMode;

use crate::connect::ConnectRequest;

/// Parse a port field. Empty falls back to `default`; anything else must be a
/// non-zero `u16`.
pub fn parse_port(input: &str, default: u16) -> Result<u16, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    match trimmed.parse::<u16>() {
        Ok(0) => Err("port must not be 0".into()),
        Ok(p) => Ok(p),
        Err(_) => Err(format!("'{trimmed}' is not a valid port (1–65535)")),
    }
}

/// Interpret the pairing-code field.
///
/// * empty / whitespace  → `Ok(None)` — steady-state auth (reconnect a known host)
/// * exactly 8 digits (spaces, `-`, `_` ignored) → `Ok(Some(normalised))` — pairing
/// * anything else       → `Err(reason)`
///
/// The normalised form strips separators, matching what
/// `PairingCode::parse` accepts on the wire, so the two never disagree.
pub fn normalize_pairing_code(input: &str) -> Result<Option<String>, String> {
    let digits: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect();
    if digits.is_empty() {
        return Ok(None);
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("pairing code must be digits only".into());
    }
    if digits.len() != PAIRING_CODE_DIGITS {
        return Err(format!("pairing code must be {PAIRING_CODE_DIGITS} digits"));
    }
    Ok(Some(digits))
}

/// True when a non-empty code is present — i.e. the Connect click should pair
/// rather than authenticate. Never errors: used for live button labelling.
pub fn is_pairing_mode(code_input: &str) -> bool {
    code_input.chars().any(|c| c.is_ascii_digit())
}

/// The raw text fields as the UI holds them.
pub struct FormInputs<'a> {
    pub host: &'a str,
    pub udp_port: &'a str,
    pub pairing_code: &'a str,
    pub display_name: &'a str,
    pub quality: QualityMode,
    pub default_udp_port: u16,
}

/// Validate every field and assemble a [`ConnectRequest`], or return the first
/// problem as a message fit for display under the form.
pub fn build_request(form: FormInputs<'_>) -> Result<ConnectRequest, String> {
    let host = form.host.trim();
    if host.is_empty() {
        return Err("enter a host address".into());
    }
    let udp_port =
        parse_port(form.udp_port, form.default_udp_port).map_err(|e| format!("UDP {e}"))?;
    let pairing_code = normalize_pairing_code(form.pairing_code)?;

    Ok(ConnectRequest {
        host: host.to_string(),
        udp_port,
        display_name: form.display_name.to_string(),
        pairing_code,
        quality: form.quality,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_port_uses_default() {
        assert_eq!(parse_port("", 47990), Ok(47990));
        assert_eq!(parse_port("   ", 47991), Ok(47991));
    }

    #[test]
    fn port_parsing_rejects_zero_and_garbage() {
        assert_eq!(parse_port("47000", 1), Ok(47000));
        assert!(parse_port("0", 1).is_err());
        assert!(parse_port("70000", 1).is_err(), "out of u16 range");
        assert!(parse_port("abc", 1).is_err());
    }

    #[test]
    fn blank_code_is_auth_mode() {
        assert_eq!(normalize_pairing_code(""), Ok(None));
        assert_eq!(normalize_pairing_code("   "), Ok(None));
        assert!(!is_pairing_mode(""));
    }

    #[test]
    fn eight_digit_code_is_pairing_mode_and_normalises() {
        assert_eq!(
            normalize_pairing_code("1234 5678"),
            Ok(Some("12345678".into()))
        );
        assert_eq!(
            normalize_pairing_code("1234-5678"),
            Ok(Some("12345678".into()))
        );
        assert!(is_pairing_mode("1234 5678"));
    }

    #[test]
    fn wrong_length_or_nondigit_code_is_rejected() {
        assert!(normalize_pairing_code("1234").is_err(), "too short");
        assert!(normalize_pairing_code("123456789").is_err(), "too long");
        assert!(normalize_pairing_code("12ab5678").is_err(), "non-digit");
    }

    #[test]
    fn build_request_selects_pairing_when_code_present() {
        let req = build_request(FormInputs {
            host: " host.lan ",
            udp_port: "",
            pairing_code: "1111 2222",
            display_name: "me",
            quality: QualityMode::Motion,
            default_udp_port: 47990,
        })
        .unwrap();
        assert_eq!(req.host, "host.lan", "host is trimmed");
        assert_eq!(req.udp_port, 47990, "blank UDP falls back to default");
        assert_eq!(req.pairing_code.as_deref(), Some("11112222"));
        assert_eq!(req.quality, QualityMode::Motion);
    }

    #[test]
    fn build_request_selects_auth_when_code_blank() {
        let req = build_request(FormInputs {
            host: "10.0.0.9",
            udp_port: "47990",
            pairing_code: "",
            display_name: "me",
            quality: QualityMode::Balanced,
            default_udp_port: 47990,
        })
        .unwrap();
        assert_eq!(req.pairing_code, None, "blank code => steady-state auth");
    }

    #[test]
    fn build_request_rejects_empty_host() {
        let err = build_request(FormInputs {
            host: "   ",
            udp_port: "",
            pairing_code: "",
            display_name: "me",
            quality: QualityMode::Balanced,
            default_udp_port: 47990,
        })
        .unwrap_err();
        assert!(err.contains("host"), "{err}");
    }

    #[test]
    fn build_request_reports_bad_port() {
        let err = build_request(FormInputs {
            host: "h",
            udp_port: "99999",
            pairing_code: "",
            display_name: "me",
            quality: QualityMode::Balanced,
            default_udp_port: 47990,
        })
        .unwrap_err();
        assert!(err.starts_with("UDP"), "{err}");
    }
}
