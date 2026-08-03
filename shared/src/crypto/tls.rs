//! rustls configuration and the key-pinning certificate verifier.
//!
//! # Provider
//!
//! The `ring` provider is selected explicitly everywhere in this file, never
//! the process-wide default. `aws-lc-rs` is never used: it needs a C toolchain
//! at build time, and a mixed-provider process is a source of extremely
//! confusing runtime errors. [`provider`] is the single source of truth.
//!
//! # Verification
//!
//! There is no CA and no hostname check. A DirectDesk client accepts exactly
//! one server certificate: the one whose `SHA-256(SubjectPublicKeyInfo)` equals
//! the pin recorded at pairing time. Everything else about the certificate —
//! issuer, validity dates, SANs, extensions — is deliberately ignored, because
//! none of it carries any trust in this system.
//!
//! That is stricter than webpki's chain validation, not weaker: a public CA
//! could be coerced into issuing for any name, but nobody can produce a
//! different key with the same SPKI hash.
//!
//! # Trust on pair
//!
//! The very first connection has no pin yet. [`ServerPinning::TrustOnPair`]
//! *records* the SPKI it sees and lets the handshake complete — and that is the
//! entire extent of the trust granted. The connection is only usable for the
//! SPAKE2 pairing exchange; nothing else may be sent until pairing succeeds and
//! the recorded pin is cross-checked against the host's `PairComplete`
//! ([`crate::crypto::pairing::PairingClient::accept_pair_complete`]). If pairing
//! fails, the recorded pin is discarded. An attacker who intercepts a
//! first-time connection therefore gets their key *recorded*, then immediately
//! rejected, because they cannot produce the pairing confirmation MAC.

use std::sync::Arc;

use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::crypto::identity::TlsIdentity;
use crate::crypto::{ct_eq, fingerprint_short, spki_sha256_from_cert_der, SpkiHash};
use crate::error::{Error, Result};
use crate::protocol::ALPN;

/// The `ring` crypto provider. Constructed fresh each call; cheap, and avoids
/// any dependence on process-global installation order.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The server name the client sends in SNI.
///
/// It is meaningless — the verifier never looks at it — but TLS requires
/// *something*, and a constant keeps the ClientHello from leaking which host a
/// user is connecting to.
pub const SNI_NAME: &str = "directdesk.invalid";

/// The fixed SNI as a `ServerName`, for `quinn::Endpoint::connect`.
pub fn sni() -> Result<ServerName<'static>> {
    ServerName::try_from(SNI_NAME).map_err(|e| Error::Crypto(format!("bad SNI constant: {e}")))
}

/// Records the SPKI observed during a trust-on-pair handshake.
///
/// Shared between the verifier (which writes) and the pairing driver (which
/// reads it after the handshake and compares it to the host's claim).
#[derive(Debug, Default)]
pub struct ObservedPin {
    inner: Mutex<Option<SpkiHash>>,
}

impl ObservedPin {
    /// A recorder with nothing observed yet.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The pin seen during the handshake, if one completed.
    pub fn get(&self) -> Option<SpkiHash> {
        *self.inner.lock()
    }

    /// Forget the observation (called when pairing fails).
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }

    fn record(&self, pin: SpkiHash) {
        *self.inner.lock() = Some(pin);
    }
}

/// How the client should decide whether to accept the server's certificate.
#[derive(Debug, Clone)]
pub enum ServerPinning {
    /// Normal operation: accept exactly this pin.
    Pinned(SpkiHash),
    /// First contact only: record whatever pin is presented. The caller MUST
    /// run SPAKE2 pairing immediately and abandon the connection if it fails.
    TrustOnPair(Arc<ObservedPin>),
}

/// A [`ServerCertVerifier`] that trusts a single public key.
pub struct PinningVerifier {
    pinning: ServerPinning,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for PinningVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match &self.pinning {
            ServerPinning::Pinned(p) => format!("pinned({})", fingerprint_short(p)),
            ServerPinning::TrustOnPair(_) => "trust-on-pair".to_string(),
        };
        f.debug_struct("PinningVerifier")
            .field("mode", &mode)
            .finish()
    }
}

impl PinningVerifier {
    /// Build a verifier for the given pinning policy.
    pub fn new(pinning: ServerPinning) -> Arc<Self> {
        Arc::new(Self {
            pinning,
            provider: provider(),
        })
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // A DirectDesk host serves exactly one self-signed certificate. A chain
        // is either a different implementation or an attempt to smuggle in a CA
        // path we would otherwise ignore; refuse it outright.
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "directdesk expects a single self-signed certificate".into(),
            ));
        }
        let presented = spki_sha256_from_cert_der(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("cannot read peer SPKI: {e}")))?;

        match &self.pinning {
            ServerPinning::Pinned(expected) => {
                if ct_eq(&presented, expected) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    // The message names the observed pin so a user can compare
                    // it against what the host is showing. Both values are
                    // public, so this leaks nothing.
                    Err(rustls::Error::General(format!(
                        "host key pin mismatch: expected {}, got {}",
                        fingerprint_short(expected),
                        fingerprint_short(&presented)
                    )))
                }
            }
            ServerPinning::TrustOnPair(recorder) => {
                recorder.record(presented);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only, and our configs refuse 1.2, so reaching here
        // means something is badly misconfigured. Fail closed rather than
        // silently accepting a downgrade.
        Err(rustls::Error::General(
            "TLS 1.2 is not supported by DirectDesk".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build the host-side rustls configuration.
///
/// TLS 1.3 only, no client certificates (clients authenticate with Ed25519
/// inside the tunnel), ALPN `directdesk/1`, and 0-RTT explicitly disabled:
/// early data is replayable by definition, and replaying input events into a
/// remote desktop is not an acceptable failure mode.
pub fn server_config(identity: &TlsIdentity) -> Result<Arc<rustls::ServerConfig>> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Crypto(format!("rustls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![identity.rustls_cert()], identity.rustls_key())
        .map_err(|e| Error::Crypto(format!("rustls server cert: {e}")))?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.max_early_data_size = 0;
    cfg.send_half_rtt_data = false;
    Ok(Arc::new(cfg))
}

/// Build the client-side rustls configuration for a pinning policy.
pub fn client_config(pinning: ServerPinning) -> Result<Arc<rustls::ClientConfig>> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Crypto(format!("rustls versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(PinningVerifier::new(pinning))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    cfg.enable_early_data = false;
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix_now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000))
    }

    #[test]
    fn sni_constant_parses() {
        assert!(sni().is_ok());
    }

    #[test]
    fn configs_build_with_alpn_and_no_early_data() {
        let id = TlsIdentity::generate("host").unwrap();
        let s = server_config(&id).unwrap();
        assert_eq!(s.alpn_protocols, vec![ALPN.to_vec()]);
        assert_eq!(s.max_early_data_size, 0);

        let c = client_config(ServerPinning::Pinned(*id.spki_sha256())).unwrap();
        assert_eq!(c.alpn_protocols, vec![ALPN.to_vec()]);
        assert!(!c.enable_early_data);
    }

    #[test]
    fn pinned_verifier_accepts_matching_certificate() {
        let id = TlsIdentity::generate("host").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*id.spki_sha256()));
        let cert = id.rustls_cert();
        assert!(v
            .verify_server_cert(&cert, &[], &sni().unwrap(), &[], unix_now())
            .is_ok());
    }

    #[test]
    fn pinned_verifier_rejects_other_certificate() {
        let good = TlsIdentity::generate("good").unwrap();
        let evil = TlsIdentity::generate("evil").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*good.spki_sha256()));
        let cert = evil.rustls_cert();
        assert!(v
            .verify_server_cert(&cert, &[], &sni().unwrap(), &[], unix_now())
            .is_err());
    }

    #[test]
    fn verifier_rejects_certificate_chains() {
        let id = TlsIdentity::generate("host").unwrap();
        let other = TlsIdentity::generate("other").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*id.spki_sha256()));
        let cert = id.rustls_cert();
        let chain = [other.rustls_cert()];
        assert!(v
            .verify_server_cert(&cert, &chain, &sni().unwrap(), &[], unix_now())
            .is_err());
    }

    #[test]
    fn verifier_rejects_garbage_certificate() {
        let id = TlsIdentity::generate("host").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*id.spki_sha256()));
        let junk = CertificateDer::from(vec![0x30, 0x02, 0x01, 0x00]);
        assert!(v
            .verify_server_cert(&junk, &[], &sni().unwrap(), &[], unix_now())
            .is_err());
    }

    #[test]
    fn trust_on_pair_records_the_pin() {
        let id = TlsIdentity::generate("host").unwrap();
        let recorder = ObservedPin::new();
        let v = PinningVerifier::new(ServerPinning::TrustOnPair(recorder.clone()));
        assert!(recorder.get().is_none());

        let cert = id.rustls_cert();
        v.verify_server_cert(&cert, &[], &sni().unwrap(), &[], unix_now())
            .unwrap();
        assert_eq!(recorder.get(), Some(*id.spki_sha256()));

        recorder.clear();
        assert!(recorder.get().is_none());
    }

    // Note: `verify_tls12_signature` cannot be unit-tested directly because
    // rustls 0.23 keeps `DigitallySignedStruct::new` crate-private. It is
    // unreachable in practice anyway: both configs are built with
    // `with_protocol_versions(&[&TLS13])`, which the config tests above pin.

    #[test]
    fn supported_schemes_are_not_empty() {
        let id = TlsIdentity::generate("host").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*id.spki_sha256()));
        assert!(!v.supported_verify_schemes().is_empty());
    }

    #[test]
    fn verifier_debug_does_not_panic_and_names_mode() {
        let id = TlsIdentity::generate("host").unwrap();
        let v = PinningVerifier::new(ServerPinning::Pinned(*id.spki_sha256()));
        assert!(format!("{v:?}").contains("pinned("));
        let v2 = PinningVerifier::new(ServerPinning::TrustOnPair(ObservedPin::new()));
        assert!(format!("{v2:?}").contains("trust-on-pair"));
    }
}
