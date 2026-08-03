//! Identity, pairing (SPAKE2), DPAPI secret storage, TLS material.
//!
//! # Trust model
//!
//! DirectDesk does not use a CA. Trust is anchored on two things the user can
//! actually verify:
//!
//! 1. A **pairing code** shown on the host and typed on the client. SPAKE2
//!    turns that low-entropy code into a strong shared key without ever putting
//!    the code (or anything derived from it that is offline-guessable) on the
//!    wire.
//! 2. A **pinned key**. After pairing, each side stores the other's long-term
//!    Ed25519 public key and the SHA-256 of its TLS `SubjectPublicKeyInfo`.
//!    Every later connection must present exactly those.
//!
//! Both the pairing confirmation and the steady-state signatures are bound to
//! the live TLS session through RFC 5705 exporter keying material
//! ([`EXPORTER_LABEL`]). That binding is what stops a machine-in-the-middle
//! from relaying a valid handshake between two honest endpoints: the exporter
//! it sees on each side differs, so the MACs and signatures do not transfer.
//!
//! # Layout
//!
//! - [`identity`] — long-term Ed25519 keys and the self-signed TLS certificate.
//! - [`storage`] — DPAPI-protected on-disk storage and the [`storage::SecretStore`] trait.
//! - [`pairing`] — the SPAKE2 pairing state machines.
//! - [`auth`] — steady-state mutual authentication and the trusted-peer store.
//! - [`tls`] — rustls configuration and the pinning certificate verifier.
//!
//! # Rules for anything in this module
//!
//! - Key material lives in [`crate::secret::Secret`] and is never logged.
//! - Every comparison of a secret or a MAC is constant-time.
//! - No wall-clock reads. Anything time-dependent takes `now_ms: u64` from the
//!   caller so it is deterministic under test.
//! - The `ring` rustls provider is selected explicitly, never `aws-lc-rs`.

pub mod auth;
mod der;
pub mod identity;
pub mod pairing;
pub mod storage;
pub mod tls;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

pub use identity::{ClientIdentity, HostIdentity, TlsIdentity};

/// Length of the TLS exporter value used for channel binding.
pub const EXPORTER_LEN: usize = 32;

/// RFC 5705 exporter label. Changing this breaks compatibility with every
/// previously paired peer, so it is versioned.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-directdesk-channel-binding-v1";

/// RFC 5705 exporter context. Ties the binding to the ALPN generation.
pub const EXPORTER_CONTEXT: &[u8] = b"directdesk/1";

/// 32 bytes of RFC 5705 exporter keying material, identical on both ends of one
/// TLS session and unguessable to anyone else.
///
/// This is a *binding value*, not a secret key: it is safe to mix into MAC and
/// signature inputs, and it must never be used as an encryption key.
pub type Exporter = [u8; EXPORTER_LEN];

/// SHA-256 of a DER `SubjectPublicKeyInfo`. This is the TLS pin.
pub type SpkiHash = [u8; 32];

/// A raw Ed25519 public key.
pub type Ed25519Pub = [u8; 32];

/// SHA-256 convenience wrapper.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Constant-time byte comparison. Returns false for differing lengths (the
/// length itself is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Compute the TLS pin (SHA-256 of the DER `SubjectPublicKeyInfo`) for an X.509
/// certificate.
///
/// This is the same construction as HPKP / `openssl x509 -pubkey | openssl dgst
/// -sha256`, so a user can verify a fingerprint by hand if they want to.
pub fn spki_sha256_from_cert_der(cert_der: &[u8]) -> Result<SpkiHash> {
    let spki = der::subject_public_key_info(cert_der)?;
    Ok(sha256(spki))
}

/// Render a 32-byte fingerprint as lowercase hex.
///
/// Only ever called on public values (key fingerprints), which is why it is
/// allowed to produce a printable string at all.
pub fn fingerprint_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('?'));
        s.push(char::from_digit((b & 0x0F) as u32, 16).unwrap_or('?'));
    }
    s
}

/// Render a fingerprint in short, human-comparable form: the first 8 bytes as
/// four colon-separated hex groups, e.g. `a1b2:c3d4:e5f6:0718`.
pub fn fingerprint_short(bytes: &[u8; 32]) -> String {
    let full = fingerprint_hex(bytes);
    let mut out = String::with_capacity(19);
    for (i, chunk) in full.as_bytes()[..16].chunks(4).enumerate() {
        if i > 0 {
            out.push(':');
        }
        // `chunk` is ASCII hex produced above.
        out.push_str(std::str::from_utf8(chunk).unwrap_or("????"));
    }
    out
}

/// Which end of the protocol a party is playing.
///
/// The role is mixed into every MAC and signature so a message produced by one
/// side can never be reflected back and accepted by the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The machine being controlled (accepts connections).
    Host,
    /// The machine doing the controlling (initiates connections).
    Client,
}

impl Role {
    /// Stable byte label mixed into transcripts. Never change these.
    pub fn label(&self) -> &'static [u8] {
        match self {
            Role::Host => b"host",
            Role::Client => b"client",
        }
    }

    /// The other end.
    pub fn peer(&self) -> Role {
        match self {
            Role::Host => Role::Client,
            Role::Client => Role::Host,
        }
    }
}

/// Reject an exporter that is obviously not real keying material.
///
/// A TLS stack that failed to produce an exporter and handed us zeroes would
/// otherwise silently destroy the channel binding, so we refuse it explicitly.
pub(crate) fn check_exporter(exporter: &Exporter) -> Result<()> {
    if exporter.iter().all(|b| *b == 0) {
        return Err(Error::Crypto("tls exporter is all zeroes".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_rendering() {
        let mut b = [0u8; 32];
        b[0] = 0xA1;
        b[1] = 0xB2;
        b[31] = 0x0F;
        let h = fingerprint_hex(&b);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("a1b2"));
        assert!(h.ends_with("0f"));
        assert_eq!(fingerprint_short(&b), "a1b2:0000:0000:0000");
    }

    #[test]
    fn ct_eq_semantics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn roles_are_distinct_and_involutive() {
        assert_ne!(Role::Host.label(), Role::Client.label());
        assert_eq!(Role::Host.peer(), Role::Client);
        assert_eq!(Role::Client.peer().peer(), Role::Client);
    }

    #[test]
    fn zero_exporter_rejected() {
        assert!(check_exporter(&[0u8; 32]).is_err());
        let mut e = [0u8; 32];
        e[7] = 1;
        assert!(check_exporter(&e).is_ok());
    }

    #[test]
    fn spki_hash_matches_generated_key() {
        let id = crate::crypto::identity::TlsIdentity::generate("test-host").unwrap();
        let from_cert = spki_sha256_from_cert_der(id.cert_der()).unwrap();
        assert_eq!(from_cert, *id.spki_sha256());
    }

    #[test]
    fn spki_hash_rejects_non_certificate() {
        assert!(spki_sha256_from_cert_der(b"not a certificate").is_err());
    }
}
