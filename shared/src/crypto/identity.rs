//! Long-term identities.
//!
//! Two different keys, doing two different jobs:
//!
//! - An **Ed25519 identity key**. This is what "who you are" means in
//!   DirectDesk. It is exchanged during pairing, pinned by the peer, and used
//!   to sign the steady-state challenge on every later connection. Both hosts
//!   and clients have one.
//! - A **TLS key + self-signed P-256 certificate**, host-side only. This exists
//!   purely to run the QUIC/TLS 1.3 handshake. It carries no trust of its own:
//!   the client pins `SHA-256(SubjectPublicKeyInfo)` at pairing time and
//!   refuses anything else afterwards.
//!
//! Splitting them means the TLS certificate can be rotated (new machine cert,
//! new pin) without destroying the identity a user has already approved — the
//! Ed25519 signature still proves it is the same host, and the client can
//! surface the pin change rather than silently accepting it.
//!
//! Persistence goes through [`SecretStore`], so tests never touch the machine.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::storage::SecretStore;
use crate::crypto::{sha256, spki_sha256_from_cert_der, Ed25519Pub, SpkiHash};
use crate::error::{Error, Result};
use crate::secret::Secret;

/// Storage key for the host's persisted identity.
pub const HOST_IDENTITY_KEY: &str = "host_identity";
/// Storage key for the client's persisted identity.
pub const CLIENT_IDENTITY_KEY: &str = "client_identity";

/// Longest accepted friendly name. Names cross the wire in
/// [`crate::protocol::AuthMsg::PairComplete`], so they are capped.
pub const MAX_NAME_LEN: usize = 64;

/// Format version for persisted identity blobs.
const STORED_VERSION: u8 = 1;

/// SAN placed in the self-signed certificate. Meaningless to the trust
/// decision — the pinning verifier never looks at names — but a certificate
/// with no SAN at all upsets some tooling.
const CERT_SAN: &str = "directdesk.invalid";

/// Reject names that would look wrong in the UI or bloat the wire.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Invalid("name is empty".into()));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::Oversized {
            got: name.len(),
            limit: MAX_NAME_LEN,
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(Error::Invalid("name contains control characters".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TLS identity
// ---------------------------------------------------------------------------

/// A self-signed P-256 certificate and its private key, plus the pin derived
/// from it.
pub struct TlsIdentity {
    cert_der: Vec<u8>,
    key_pkcs8: Secret<Vec<u8>>,
    spki_sha256: SpkiHash,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("cert_len", &self.cert_der.len())
            .field(
                "spki_sha256",
                &crate::crypto::fingerprint_short(&self.spki_sha256),
            )
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl TlsIdentity {
    /// Generate a fresh P-256 key and self-signed certificate.
    ///
    /// `common_name` is cosmetic: it shows up if someone inspects the
    /// certificate, and is never used to make a trust decision.
    pub fn generate(common_name: &str) -> Result<Self> {
        validate_name(common_name)?;
        let key_pair =
            KeyPair::generate().map_err(|e| Error::Crypto(format!("rcgen keygen: {e}")))?;

        let mut params = CertificateParams::new(vec![CERT_SAN.to_string()])
            .map_err(|e| Error::Crypto(format!("rcgen params: {e}")))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("DirectDesk {common_name}"));
        dn.push(DnType::OrganizationName, "DirectDesk");
        params.distinguished_name = dn;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Crypto(format!("rcgen self_signed: {e}")))?;

        let cert_der = cert.der().as_ref().to_vec();
        let mut key_der = key_pair.serialize_der();
        let spki_sha256 = sha256(&key_pair.public_key_der());

        // Cross-check: the pin computed from the certificate we will actually
        // serve must equal the pin computed from the key we generated. If the
        // DER walker and rcgen ever disagree, fail loudly at generation time
        // rather than during a handshake.
        let from_cert = spki_sha256_from_cert_der(&cert_der)?;
        if from_cert != spki_sha256 {
            key_der.zeroize();
            return Err(Error::Crypto(
                "spki pin mismatch between cert and key".into(),
            ));
        }

        Ok(Self {
            cert_der,
            key_pkcs8: Secret::new(key_der),
            spki_sha256,
        })
    }

    /// Rebuild from persisted DER bytes, recomputing (not trusting) the pin.
    pub fn from_der(cert_der: Vec<u8>, key_pkcs8: Vec<u8>) -> Result<Self> {
        if cert_der.is_empty() || key_pkcs8.is_empty() {
            return Err(Error::Crypto("tls identity: empty DER".into()));
        }
        let spki_sha256 = spki_sha256_from_cert_der(&cert_der)?;
        Ok(Self {
            cert_der,
            key_pkcs8: Secret::new(key_pkcs8),
            spki_sha256,
        })
    }

    /// The DER-encoded certificate served to peers.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// `SHA-256(SubjectPublicKeyInfo)` — the value clients pin.
    pub fn spki_sha256(&self) -> &SpkiHash {
        &self.spki_sha256
    }

    /// The pin in short human-comparable form, for the pairing UI.
    pub fn pin_short(&self) -> String {
        crate::crypto::fingerprint_short(&self.spki_sha256)
    }

    /// Certificate in the type rustls wants.
    pub fn rustls_cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }

    /// Private key in the type rustls wants.
    ///
    /// The clone is unavoidable — rustls takes ownership — but the copy is
    /// consumed immediately by config construction and dropped there.
    pub fn rustls_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.expose().clone()))
    }
}

// ---------------------------------------------------------------------------
// Persisted representations
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct StoredHostIdentity {
    version: u8,
    name: String,
    ed25519_seed: [u8; 32],
    tls_cert_der: Vec<u8>,
    tls_key_pkcs8: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredClientIdentity {
    version: u8,
    name: String,
    ed25519_seed: [u8; 32],
}

/// Serialize, hand to the store, and scrub the plaintext buffer.
fn write_stored<T: Serialize>(store: &dyn SecretStore, key: &str, value: &T) -> Result<()> {
    let mut plain = postcard::to_stdvec(value)?;
    let res = store.write(key, &plain);
    plain.zeroize();
    res
}

// ---------------------------------------------------------------------------
// Host identity
// ---------------------------------------------------------------------------

/// The host's long-term identity: Ed25519 key, TLS material, friendly name.
pub struct HostIdentity {
    name: String,
    signing: SigningKey,
    tls: TlsIdentity,
}

impl std::fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIdentity")
            .field("name", &self.name)
            .field(
                "ed25519_pub",
                &crate::crypto::fingerprint_short(&self.ed25519_pub()),
            )
            .field("tls", &self.tls)
            .finish()
    }
}

impl HostIdentity {
    /// Generate a brand-new host identity. Does not persist it.
    pub fn generate(name: &str) -> Result<Self> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_string(),
            signing: SigningKey::generate(&mut OsRng),
            tls: TlsIdentity::generate(name)?,
        })
    }

    /// Load the persisted identity, or generate and persist a new one.
    ///
    /// `name` is only used when creating; an existing identity keeps the name
    /// it was created with so a rename never silently changes what peers see.
    pub fn load_or_create(store: &dyn SecretStore, name: &str) -> Result<Self> {
        if let Some(existing) = Self::load(store)? {
            return Ok(existing);
        }
        let id = Self::generate(name)?;
        id.save(store)?;
        Ok(id)
    }

    /// Load the persisted identity, if there is one.
    pub fn load(store: &dyn SecretStore) -> Result<Option<Self>> {
        let Some(blob) = store.read(HOST_IDENTITY_KEY)? else {
            return Ok(None);
        };
        let stored: StoredHostIdentity = crate::protocol::decode_strict(blob.expose())?;
        if stored.version != STORED_VERSION {
            return Err(Error::Crypto(format!(
                "host identity version {} not supported",
                stored.version
            )));
        }
        validate_name(&stored.name)?;
        let mut seed = stored.ed25519_seed;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let tls = TlsIdentity::from_der(stored.tls_cert_der, stored.tls_key_pkcs8)?;
        Ok(Some(Self {
            name: stored.name,
            signing,
            tls,
        }))
    }

    /// Persist this identity (overwriting any previous one).
    pub fn save(&self, store: &dyn SecretStore) -> Result<()> {
        let stored = StoredHostIdentity {
            version: STORED_VERSION,
            name: self.name.clone(),
            ed25519_seed: self.signing.to_bytes(),
            tls_cert_der: self.tls.cert_der.clone(),
            tls_key_pkcs8: self.tls.key_pkcs8.expose().clone(),
        };
        write_stored(store, HOST_IDENTITY_KEY, &stored)
    }

    /// Replace only the TLS certificate, keeping the Ed25519 identity.
    ///
    /// Peers will see a new pin but the same identity key, which is exactly the
    /// situation the client is expected to surface to the user rather than
    /// accept silently.
    pub fn rotate_tls(&mut self) -> Result<()> {
        self.tls = TlsIdentity::generate(&self.name)?;
        Ok(())
    }

    /// Friendly name shown to the peer.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The long-term public key peers pin.
    pub fn ed25519_pub(&self) -> Ed25519Pub {
        self.signing.verifying_key().to_bytes()
    }

    /// Signing key, for [`crate::crypto::auth`].
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// TLS material.
    pub fn tls(&self) -> &TlsIdentity {
        &self.tls
    }

    /// Shorthand for the TLS pin.
    pub fn spki_sha256(&self) -> &SpkiHash {
        self.tls.spki_sha256()
    }

    /// The [`crate::protocol::AuthMsg::PairComplete`] payload for this host.
    pub fn pair_complete(&self) -> crate::protocol::AuthMsg {
        crate::protocol::AuthMsg::PairComplete {
            host_ed25519_pub: self.ed25519_pub(),
            host_spki_sha256: *self.spki_sha256(),
            host_name: self.name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Client identity
// ---------------------------------------------------------------------------

/// The client's long-term identity. No TLS certificate: the client proves
/// itself with an Ed25519 signature over the channel binding, not with a
/// client certificate.
pub struct ClientIdentity {
    name: String,
    signing: SigningKey,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("name", &self.name)
            .field(
                "ed25519_pub",
                &crate::crypto::fingerprint_short(&self.ed25519_pub()),
            )
            .finish()
    }
}

impl ClientIdentity {
    /// Generate a brand-new client identity. Does not persist it.
    pub fn generate(name: &str) -> Result<Self> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_string(),
            signing: SigningKey::generate(&mut OsRng),
        })
    }

    /// Load the persisted identity, or generate and persist a new one.
    pub fn load_or_create(store: &dyn SecretStore, name: &str) -> Result<Self> {
        if let Some(existing) = Self::load(store)? {
            return Ok(existing);
        }
        let id = Self::generate(name)?;
        id.save(store)?;
        Ok(id)
    }

    /// Load the persisted identity, if there is one.
    pub fn load(store: &dyn SecretStore) -> Result<Option<Self>> {
        let Some(blob) = store.read(CLIENT_IDENTITY_KEY)? else {
            return Ok(None);
        };
        let stored: StoredClientIdentity = crate::protocol::decode_strict(blob.expose())?;
        if stored.version != STORED_VERSION {
            return Err(Error::Crypto(format!(
                "client identity version {} not supported",
                stored.version
            )));
        }
        validate_name(&stored.name)?;
        let mut seed = stored.ed25519_seed;
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Some(Self {
            name: stored.name,
            signing,
        }))
    }

    /// Persist this identity (overwriting any previous one).
    pub fn save(&self, store: &dyn SecretStore) -> Result<()> {
        let stored = StoredClientIdentity {
            version: STORED_VERSION,
            name: self.name.clone(),
            ed25519_seed: self.signing.to_bytes(),
        };
        write_stored(store, CLIENT_IDENTITY_KEY, &stored)
    }

    /// Friendly name shown to the host.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The long-term public key the host pins.
    pub fn ed25519_pub(&self) -> Ed25519Pub {
        self.signing.verifying_key().to_bytes()
    }

    /// Signing key, for [`crate::crypto::auth`].
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// Parse a 32-byte Ed25519 public key, rejecting non-canonical encodings.
pub fn parse_verifying_key(bytes: &Ed25519Pub) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(|e| Error::Crypto(format!("bad ed25519 key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::storage::MemoryStore;

    #[test]
    fn name_validation() {
        assert!(validate_name("desktop").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name("bad\nname").is_err());
    }

    #[test]
    fn tls_identity_generates_consistent_pin() {
        let a = TlsIdentity::generate("host-a").unwrap();
        let b = TlsIdentity::generate("host-b").unwrap();
        assert_ne!(a.spki_sha256(), b.spki_sha256());
        assert_eq!(
            spki_sha256_from_cert_der(a.cert_der()).unwrap(),
            *a.spki_sha256()
        );
        assert_eq!(a.pin_short().len(), 19);
    }

    #[test]
    fn tls_identity_roundtrips_through_der() {
        let a = TlsIdentity::generate("host").unwrap();
        let b = TlsIdentity::from_der(a.cert_der().to_vec(), a.key_pkcs8.expose().clone()).unwrap();
        assert_eq!(a.spki_sha256(), b.spki_sha256());
    }

    #[test]
    fn tls_identity_debug_redacts_key() {
        let a = TlsIdentity::generate("host").unwrap();
        let s = format!("{a:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("key_pkcs8: ["));
    }

    #[test]
    fn host_identity_persists_and_reloads() {
        let store = MemoryStore::new();
        assert!(HostIdentity::load(&store).unwrap().is_none());

        let a = HostIdentity::load_or_create(&store, "workstation").unwrap();
        let b = HostIdentity::load_or_create(&store, "ignored-name").unwrap();

        assert_eq!(a.name(), "workstation");
        assert_eq!(
            b.name(),
            "workstation",
            "existing identity keeps its original name"
        );
        assert_eq!(a.ed25519_pub(), b.ed25519_pub());
        assert_eq!(a.spki_sha256(), b.spki_sha256());
        assert_eq!(a.tls().cert_der(), b.tls().cert_der());
    }

    #[test]
    fn client_identity_persists_and_reloads() {
        let store = MemoryStore::new();
        let a = ClientIdentity::load_or_create(&store, "laptop").unwrap();
        let b = ClientIdentity::load_or_create(&store, "laptop").unwrap();
        assert_eq!(a.ed25519_pub(), b.ed25519_pub());
        assert_eq!(a.name(), "laptop");
    }

    #[test]
    fn stored_blob_is_not_plaintext_readable_as_key() {
        // The MemoryStore keeps plaintext by design; what we assert here is
        // that the serialized form round-trips exactly, not that it is opaque.
        let store = MemoryStore::new();
        let id = HostIdentity::generate("h").unwrap();
        id.save(&store).unwrap();
        let back = HostIdentity::load(&store).unwrap().unwrap();
        assert_eq!(id.ed25519_pub(), back.ed25519_pub());
        assert_eq!(id.tls().cert_der(), back.tls().cert_der());
    }

    #[test]
    fn rotate_tls_keeps_identity_changes_pin() {
        let mut id = HostIdentity::generate("h").unwrap();
        let old_pub = id.ed25519_pub();
        let old_pin = *id.spki_sha256();
        id.rotate_tls().unwrap();
        assert_eq!(id.ed25519_pub(), old_pub);
        assert_ne!(*id.spki_sha256(), old_pin);
    }

    #[test]
    fn pair_complete_matches_identity() {
        let id = HostIdentity::generate("h").unwrap();
        match id.pair_complete() {
            crate::protocol::AuthMsg::PairComplete {
                host_ed25519_pub,
                host_spki_sha256,
                host_name,
            } => {
                assert_eq!(host_ed25519_pub, id.ed25519_pub());
                assert_eq!(host_spki_sha256, *id.spki_sha256());
                assert_eq!(host_name, "h");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_stored_version() {
        let store = MemoryStore::new();
        let stored = StoredClientIdentity {
            version: 99,
            name: "x".into(),
            ed25519_seed: [7u8; 32],
        };
        write_stored(&store, CLIENT_IDENTITY_KEY, &stored).unwrap();
        assert!(ClientIdentity::load(&store).is_err());
    }

    #[test]
    fn parse_verifying_key_roundtrip() {
        let id = ClientIdentity::generate("c").unwrap();
        let vk = parse_verifying_key(&id.ed25519_pub()).unwrap();
        assert_eq!(vk.to_bytes(), id.ed25519_pub());

        // An Ed25519 public key is a compressed curve point, so this is a
        // decompression check, not a whitelist: many arbitrary 32-byte strings
        // *do* decode to a valid point. Scan a fixed set to prove the check
        // really does reject the ones that are not on the curve (roughly half
        // of all candidate y-coordinates are non-squares).
        let rejected = (0u8..64)
            .filter(|i| {
                let mut b = [0u8; 32];
                b[0] = *i;
                b[31] = 0x40 | *i;
                parse_verifying_key(&b).is_err()
            })
            .count();
        assert!(
            rejected > 0,
            "point decompression must reject off-curve encodings"
        );
    }
}
