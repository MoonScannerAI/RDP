//! Steady-state mutual authentication and the trusted-peer store.
//!
//! Pairing happens once. Every connection after that runs this instead:
//!
//! ```text
//! host                                              client
//!   |-- ServerChallenge { nonce_s } ---------------->|
//!   |<- ClientAuth   { client_pub, sig_c } ----------|
//!   |<- ClientChallenge { nonce_c } -----------------|
//!   |  verify sig_c against the trusted-client list  |
//!   |-- ServerAuth   { sig_s } --------------------->|
//!   |-- AuthOk ------------------------------------->|  verify sig_s
//!   |                                                |  against the pinned host key
//! ```
//!
//! where
//!
//! ```text
//! sig_c = Ed25519(client_key, "directdesk/auth/v1/client" || exporter || nonce_s)
//! sig_s = Ed25519(host_key,   "directdesk/auth/v1/host"   || exporter || nonce_c)
//! ```
//!
//! Three things make this sound:
//!
//! - **Freshness.** Each side signs a nonce chosen by the *other* side, so a
//!   recorded signature is useless on a later connection.
//! - **Channel binding.** The TLS exporter is inside the signed message, so a
//!   signature produced on one TLS session cannot be replayed onto another.
//!   This is what makes a relay attack fail even if the relay holds a valid
//!   certificate of its own.
//! - **Role separation.** The domain-separator prefix differs by role, so a
//!   signature made by the client can never be reflected back and accepted as
//!   the host's. (The contract describes the signed value as
//!   `tls_exporter || peer_nonce`; the role prefix is an addition, documented
//!   here, that costs nothing and removes a whole class of reflection bug.)
//!
//! The TLS pin is checked separately, by the certificate verifier in
//! [`crate::crypto::tls`], before any of this runs. Both checks must pass.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::identity::parse_verifying_key;
use crate::crypto::storage::SecretStore;
use crate::crypto::{check_exporter, ct_eq, Ed25519Pub, Exporter, Role, SpkiHash};
use crate::error::{Error, Result};
use crate::protocol::AuthMsg;

/// Storage key for the host's list of trusted clients.
pub const TRUSTED_CLIENTS_KEY: &str = "trusted_clients";
/// Storage key for the client's list of trusted hosts.
pub const TRUSTED_HOSTS_KEY: &str = "trusted_hosts";

/// Format version for the persisted trusted-peer list.
const STORE_VERSION: u8 = 1;

/// Refuse to keep an unbounded peer list in memory or on disk.
pub const MAX_TRUSTED_PEERS: usize = 256;

/// Domain separator prefix for a signature made by the client.
const SIG_CONTEXT_CLIENT: &[u8] = b"directdesk/auth/v1/client";
/// Domain separator prefix for a signature made by the host.
const SIG_CONTEXT_HOST: &[u8] = b"directdesk/auth/v1/host";

fn sig_context(role: Role) -> &'static [u8] {
    match role {
        Role::Client => SIG_CONTEXT_CLIENT,
        Role::Host => SIG_CONTEXT_HOST,
    }
}

/// Build the exact byte string a party of `role` signs.
///
/// `nonce` is always the nonce chosen by the *peer*.
pub fn challenge_message(role: Role, exporter: &Exporter, nonce: &[u8; 32]) -> Vec<u8> {
    let ctx = sig_context(role);
    let mut msg = Vec::with_capacity(ctx.len() + 64);
    msg.extend_from_slice(ctx);
    msg.extend_from_slice(exporter);
    msg.extend_from_slice(nonce);
    msg
}

/// Sign a peer's challenge.
pub fn sign_challenge(
    key: &SigningKey,
    role: Role,
    exporter: &Exporter,
    peer_nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    check_exporter(exporter)?;
    let msg = challenge_message(role, exporter, peer_nonce);
    Ok(key.sign(&msg).to_bytes().to_vec())
}

/// Verify a peer's signature over our challenge.
pub fn verify_challenge(
    peer_pub: &VerifyingKey,
    peer_role: Role,
    exporter: &Exporter,
    our_nonce: &[u8; 32],
    sig: &[u8],
) -> Result<()> {
    check_exporter(exporter)?;
    let bytes: [u8; 64] = sig
        .try_into()
        .map_err(|_| Error::Auth(format!("signature must be 64 bytes, got {}", sig.len())))?;
    let signature = Signature::from_bytes(&bytes);
    let msg = challenge_message(peer_role, exporter, our_nonce);
    peer_pub
        .verify(&msg, &signature)
        .map_err(|_| Error::Auth("signature invalid".into()))
}

/// A fresh 32-byte nonce from the OS CSPRNG.
pub fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

// ---------------------------------------------------------------------------
// Trusted peers
// ---------------------------------------------------------------------------

/// A peer this machine has paired with and will accept in the future.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPeer {
    /// Friendly name, chosen at pairing time. Display only — never trusted.
    pub name: String,
    /// The long-term identity key. This is the primary key of the record.
    pub ed25519_pub: Ed25519Pub,
    /// Expected `SHA-256(SubjectPublicKeyInfo)` of the peer's TLS certificate.
    /// All zeroes for clients, which do not present a certificate.
    pub spki_sha256: SpkiHash,
    /// Unix milliseconds when the record was created. Informational.
    pub added_at_ms: u64,
}

impl TrustedPeer {
    /// Whether this record carries a TLS pin (hosts do, clients do not).
    pub fn has_tls_pin(&self) -> bool {
        self.spki_sha256 != [0u8; 32]
    }

    /// Parse the identity key, rejecting a corrupt stored record.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        parse_verifying_key(&self.ed25519_pub)
    }

    /// Short fingerprint for the UI.
    pub fn fingerprint_short(&self) -> String {
        crate::crypto::fingerprint_short(&self.ed25519_pub)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredPeers {
    version: u8,
    peers: Vec<TrustedPeer>,
}

/// The set of peers this machine trusts, persisted through a
/// [`SecretStore`].
///
/// The list is not secret — it holds only public keys — but it *is*
/// integrity-critical: an attacker who can add an entry owns the machine. It
/// therefore goes through the same DPAPI-protected store as the identity keys,
/// which makes tampering require the ability to call DPAPI with our
/// application entropy rather than merely to write a file.
#[derive(Debug, Clone, Default)]
pub struct TrustedPeers {
    peers: Vec<TrustedPeer>,
}

impl TrustedPeers {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a store. A missing blob is an empty set, not an error.
    pub fn load(store: &dyn SecretStore, key: &str) -> Result<Self> {
        let Some(blob) = store.read(key)? else {
            return Ok(Self::new());
        };
        let stored: StoredPeers = crate::protocol::decode_strict(blob.expose())?;
        if stored.version != STORE_VERSION {
            return Err(Error::Crypto(format!(
                "trusted peer store version {} not supported",
                stored.version
            )));
        }
        if stored.peers.len() > MAX_TRUSTED_PEERS {
            return Err(Error::Oversized {
                got: stored.peers.len(),
                limit: MAX_TRUSTED_PEERS,
            });
        }
        for p in &stored.peers {
            crate::crypto::identity::validate_name(&p.name)?;
            p.verifying_key()?;
        }
        Ok(Self {
            peers: stored.peers,
        })
    }

    /// Persist to a store.
    pub fn save(&self, store: &dyn SecretStore, key: &str) -> Result<()> {
        let stored = StoredPeers {
            version: STORE_VERSION,
            peers: self.peers.clone(),
        };
        let bytes = postcard::to_stdvec(&stored)?;
        store.write(key, &bytes)
    }

    /// Add or replace a peer, keyed on its identity key.
    ///
    /// Returns `true` if this replaced an existing record. Replacing is how a
    /// host's TLS certificate rotation is recorded: the identity key is the
    /// same, the pin changes. Callers are expected to have shown that change to
    /// the user first.
    pub fn upsert(&mut self, peer: TrustedPeer) -> Result<bool> {
        crate::crypto::identity::validate_name(&peer.name)?;
        peer.verifying_key()?;
        if let Some(slot) = self
            .peers
            .iter_mut()
            .find(|p| p.ed25519_pub == peer.ed25519_pub)
        {
            *slot = peer;
            return Ok(true);
        }
        if self.peers.len() >= MAX_TRUSTED_PEERS {
            return Err(Error::Oversized {
                got: self.peers.len() + 1,
                limit: MAX_TRUSTED_PEERS,
            });
        }
        self.peers.push(peer);
        Ok(false)
    }

    /// Remove a peer by identity key. Returns whether anything was removed.
    pub fn remove(&mut self, ed25519_pub: &Ed25519Pub) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| !ct_eq(&p.ed25519_pub, ed25519_pub));
        self.peers.len() != before
    }

    /// Look up a peer by identity key, comparing in constant time.
    pub fn find(&self, ed25519_pub: &Ed25519Pub) -> Option<&TrustedPeer> {
        self.peers
            .iter()
            .find(|p| ct_eq(&p.ed25519_pub, ed25519_pub))
    }

    /// Look up a peer by its TLS pin.
    pub fn find_by_pin(&self, spki_sha256: &SpkiHash) -> Option<&TrustedPeer> {
        if spki_sha256 == &[0u8; 32] {
            return None;
        }
        self.peers
            .iter()
            .find(|p| ct_eq(&p.spki_sha256, spki_sha256))
    }

    /// All records, in insertion order.
    pub fn peers(&self) -> &[TrustedPeer] {
        &self.peers
    }

    /// Number of trusted peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether nothing is trusted yet.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Host-side state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostStage {
    AwaitClientAuth,
    AwaitClientChallenge,
    Complete,
    Failed,
}

/// Host half of the steady-state handshake.
pub struct HostAuthenticator {
    exporter: Exporter,
    server_nonce: [u8; 32],
    stage: HostStage,
    peer: Option<TrustedPeer>,
}

// The exporter must stay unguessable to third parties — it is what binds a
// signature to this TLS session — so it never reaches a formatter.
impl std::fmt::Debug for HostAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostAuthenticator")
            .field("stage", &self.stage)
            .field("peer", &self.peer.as_ref().map(|p| p.name.as_str()))
            .finish_non_exhaustive()
    }
}

impl HostAuthenticator {
    /// Start authentication, producing the `ServerChallenge` to send.
    pub fn start(exporter: &Exporter) -> Result<(Self, AuthMsg)> {
        Self::start_with_nonce(exporter, random_nonce())
    }

    /// [`Self::start`] with an explicit nonce, for deterministic tests.
    pub fn start_with_nonce(exporter: &Exporter, nonce: [u8; 32]) -> Result<(Self, AuthMsg)> {
        check_exporter(exporter)?;
        let me = Self {
            exporter: *exporter,
            server_nonce: nonce,
            stage: HostStage::AwaitClientAuth,
            peer: None,
        };
        Ok((me, AuthMsg::ServerChallenge { nonce }))
    }

    /// Verify the client's `ClientAuth` against the trusted-client list.
    ///
    /// Returns the matched record. An unknown key and a bad signature produce
    /// the same [`Error::Auth`] shape on purpose: the caller sends a single
    /// generic `AuthFail` so a prober cannot tell "not paired" from
    /// "wrong key".
    pub fn on_client_auth(&mut self, msg: &AuthMsg, trusted: &TrustedPeers) -> Result<TrustedPeer> {
        if self.stage != HostStage::AwaitClientAuth {
            self.stage = HostStage::Failed;
            return Err(Error::Auth("unexpected ClientAuth".into()));
        }
        let AuthMsg::ClientAuth {
            client_ed25519_pub,
            sig,
        } = msg
        else {
            self.stage = HostStage::Failed;
            return Err(Error::Auth("expected ClientAuth".into()));
        };
        let Some(peer) = trusted.find(client_ed25519_pub) else {
            self.stage = HostStage::Failed;
            return Err(Error::Auth("client is not paired with this host".into()));
        };
        let vk = peer.verifying_key()?;
        if let Err(e) = verify_challenge(&vk, Role::Client, &self.exporter, &self.server_nonce, sig)
        {
            self.stage = HostStage::Failed;
            return Err(e);
        }
        let peer = peer.clone();
        self.peer = Some(peer.clone());
        self.stage = HostStage::AwaitClientChallenge;
        Ok(peer)
    }

    /// Answer the client's `ClientChallenge` with our signature, then `AuthOk`.
    pub fn on_client_challenge(
        &mut self,
        msg: &AuthMsg,
        host_key: &SigningKey,
    ) -> Result<(AuthMsg, AuthMsg)> {
        if self.stage != HostStage::AwaitClientChallenge {
            self.stage = HostStage::Failed;
            return Err(Error::Auth("unexpected ClientChallenge".into()));
        }
        let AuthMsg::ClientChallenge { nonce } = msg else {
            self.stage = HostStage::Failed;
            return Err(Error::Auth("expected ClientChallenge".into()));
        };
        let sig = sign_challenge(host_key, Role::Host, &self.exporter, nonce)?;
        self.stage = HostStage::Complete;
        Ok((AuthMsg::ServerAuth { sig }, AuthMsg::AuthOk))
    }

    /// The authenticated client, once `on_client_auth` has succeeded.
    pub fn peer(&self) -> Option<&TrustedPeer> {
        self.peer.as_ref()
    }

    /// Whether the handshake finished successfully.
    pub fn is_complete(&self) -> bool {
        self.stage == HostStage::Complete
    }
}

// ---------------------------------------------------------------------------
// Client-side state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientStage {
    AwaitServerChallenge,
    AwaitServerAuth,
    AwaitAuthOk,
    Complete,
    Failed,
}

/// Client half of the steady-state handshake.
pub struct ClientAuthenticator {
    exporter: Exporter,
    client_nonce: [u8; 32],
    host_pub: VerifyingKey,
    stage: ClientStage,
}

impl std::fmt::Debug for ClientAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuthenticator")
            .field("stage", &self.stage)
            .field(
                "host_pub",
                &crate::crypto::fingerprint_short(&self.host_pub.to_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl ClientAuthenticator {
    /// Start authentication against a specific pinned host key.
    pub fn start(exporter: &Exporter, host_pub: &Ed25519Pub) -> Result<Self> {
        Self::start_with_nonce(exporter, host_pub, random_nonce())
    }

    /// [`Self::start`] with an explicit nonce, for deterministic tests.
    pub fn start_with_nonce(
        exporter: &Exporter,
        host_pub: &Ed25519Pub,
        nonce: [u8; 32],
    ) -> Result<Self> {
        check_exporter(exporter)?;
        Ok(Self {
            exporter: *exporter,
            client_nonce: nonce,
            host_pub: parse_verifying_key(host_pub)?,
            stage: ClientStage::AwaitServerChallenge,
        })
    }

    /// Answer the host's challenge and issue our own.
    ///
    /// Returns `(ClientAuth, ClientChallenge)`, to be sent in that order.
    pub fn on_server_challenge(
        &mut self,
        msg: &AuthMsg,
        client_key: &SigningKey,
    ) -> Result<(AuthMsg, AuthMsg)> {
        if self.stage != ClientStage::AwaitServerChallenge {
            self.stage = ClientStage::Failed;
            return Err(Error::Auth("unexpected ServerChallenge".into()));
        }
        let AuthMsg::ServerChallenge { nonce } = msg else {
            self.stage = ClientStage::Failed;
            return Err(Error::Auth("expected ServerChallenge".into()));
        };
        let sig = sign_challenge(client_key, Role::Client, &self.exporter, nonce)?;
        self.stage = ClientStage::AwaitServerAuth;
        Ok((
            AuthMsg::ClientAuth {
                client_ed25519_pub: client_key.verifying_key().to_bytes(),
                sig,
            },
            AuthMsg::ClientChallenge {
                nonce: self.client_nonce,
            },
        ))
    }

    /// Verify the host's signature over our nonce.
    pub fn on_server_auth(&mut self, msg: &AuthMsg) -> Result<()> {
        if self.stage != ClientStage::AwaitServerAuth {
            self.stage = ClientStage::Failed;
            return Err(Error::Auth("unexpected ServerAuth".into()));
        }
        let AuthMsg::ServerAuth { sig } = msg else {
            self.stage = ClientStage::Failed;
            return Err(Error::Auth("expected ServerAuth".into()));
        };
        if let Err(e) = verify_challenge(
            &self.host_pub,
            Role::Host,
            &self.exporter,
            &self.client_nonce,
            sig,
        ) {
            self.stage = ClientStage::Failed;
            return Err(e);
        }
        self.stage = ClientStage::AwaitAuthOk;
        Ok(())
    }

    /// Consume the host's final `AuthOk` (or surface its `AuthFail`).
    pub fn on_auth_ok(&mut self, msg: &AuthMsg) -> Result<()> {
        if self.stage != ClientStage::AwaitAuthOk {
            self.stage = ClientStage::Failed;
            return Err(Error::Auth("unexpected AuthOk".into()));
        }
        match msg {
            AuthMsg::AuthOk => {
                self.stage = ClientStage::Complete;
                Ok(())
            }
            AuthMsg::AuthFail { reason } => {
                self.stage = ClientStage::Failed;
                Err(Error::Auth(format!("host rejected us: {reason}")))
            }
            _ => {
                self.stage = ClientStage::Failed;
                Err(Error::Auth("expected AuthOk".into()))
            }
        }
    }

    /// Whether the handshake finished successfully.
    pub fn is_complete(&self) -> bool {
        self.stage == ClientStage::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::storage::MemoryStore;
    use crate::crypto::{ClientIdentity, HostIdentity};

    fn exporter(b: u8) -> Exporter {
        let mut e = [b; 32];
        e[31] = b ^ 0x0F;
        e
    }

    fn peer_for(name: &str, pubkey: Ed25519Pub, pin: SpkiHash) -> TrustedPeer {
        TrustedPeer {
            name: name.into(),
            ed25519_pub: pubkey,
            spki_sha256: pin,
            added_at_ms: 1,
        }
    }

    #[test]
    fn challenge_message_is_role_separated() {
        let e = exporter(1);
        let n = [9u8; 32];
        assert_ne!(
            challenge_message(Role::Host, &e, &n),
            challenge_message(Role::Client, &e, &n)
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = ClientIdentity::generate("c").unwrap();
        let e = exporter(2);
        let nonce = [3u8; 32];
        let sig = sign_challenge(id.signing_key(), Role::Client, &e, &nonce).unwrap();
        let vk = parse_verifying_key(&id.ed25519_pub()).unwrap();
        assert!(verify_challenge(&vk, Role::Client, &e, &nonce, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let a = ClientIdentity::generate("a").unwrap();
        let b = ClientIdentity::generate("b").unwrap();
        let e = exporter(4);
        let nonce = [5u8; 32];
        let sig = sign_challenge(a.signing_key(), Role::Client, &e, &nonce).unwrap();
        let vk_b = parse_verifying_key(&b.ed25519_pub()).unwrap();
        assert!(verify_challenge(&vk_b, Role::Client, &e, &nonce, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_nonce_exporter_and_role() {
        let a = ClientIdentity::generate("a").unwrap();
        let vk = parse_verifying_key(&a.ed25519_pub()).unwrap();
        let e = exporter(6);
        let nonce = [7u8; 32];
        let sig = sign_challenge(a.signing_key(), Role::Client, &e, &nonce).unwrap();

        assert!(verify_challenge(&vk, Role::Client, &e, &[8u8; 32], &sig).is_err());
        assert!(verify_challenge(&vk, Role::Client, &exporter(9), &nonce, &sig).is_err());
        // A client signature must not verify as a host signature.
        assert!(verify_challenge(&vk, Role::Host, &e, &nonce, &sig).is_err());
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let a = ClientIdentity::generate("a").unwrap();
        let vk = parse_verifying_key(&a.ed25519_pub()).unwrap();
        assert!(verify_challenge(&vk, Role::Client, &exporter(1), &[0u8; 32], &[0u8; 8]).is_err());
    }

    #[test]
    fn zero_exporter_refused() {
        let a = ClientIdentity::generate("a").unwrap();
        assert!(sign_challenge(a.signing_key(), Role::Client, &[0u8; 32], &[1u8; 32]).is_err());
    }

    #[test]
    fn trusted_peers_crud_and_persistence() {
        let store = MemoryStore::new();
        let mut set = TrustedPeers::new();
        assert!(set.is_empty());

        let a = ClientIdentity::generate("a").unwrap();
        let b = ClientIdentity::generate("b").unwrap();
        assert!(!set
            .upsert(peer_for("a", a.ed25519_pub(), [0u8; 32]))
            .unwrap());
        assert!(!set
            .upsert(peer_for("b", b.ed25519_pub(), [7u8; 32]))
            .unwrap());
        assert_eq!(set.len(), 2);
        // Re-adding the same identity key replaces rather than duplicates.
        assert!(set
            .upsert(peer_for("a renamed", a.ed25519_pub(), [0u8; 32]))
            .unwrap());
        assert_eq!(set.len(), 2);
        assert_eq!(set.find(&a.ed25519_pub()).unwrap().name, "a renamed");

        assert!(set.find_by_pin(&[7u8; 32]).is_some());
        assert!(
            set.find_by_pin(&[0u8; 32]).is_none(),
            "all-zero pin must never match"
        );
        assert!(!set.peers()[0].has_tls_pin());
        assert!(set.peers()[1].has_tls_pin());

        set.save(&store, TRUSTED_CLIENTS_KEY).unwrap();
        let back = TrustedPeers::load(&store, TRUSTED_CLIENTS_KEY).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.find(&b.ed25519_pub()).unwrap().name, "b");

        assert!(set.remove(&a.ed25519_pub()));
        assert!(!set.remove(&a.ed25519_pub()));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn missing_store_blob_is_empty_not_error() {
        let store = MemoryStore::new();
        assert!(TrustedPeers::load(&store, TRUSTED_HOSTS_KEY)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn trusted_peers_rejects_corrupt_records() {
        let store = MemoryStore::new();
        let id = ClientIdentity::generate("ok").unwrap();
        // A control character in the name would render as garbage in the UI and
        // must not survive a load.
        let stored = StoredPeers {
            version: STORE_VERSION,
            peers: vec![peer_for("bad\nname", id.ed25519_pub(), [0u8; 32])],
        };
        store
            .write(TRUSTED_HOSTS_KEY, &postcard::to_stdvec(&stored).unwrap())
            .unwrap();
        assert!(TrustedPeers::load(&store, TRUSTED_HOSTS_KEY).is_err());
    }

    #[test]
    fn trusted_peers_rejects_wrong_version() {
        let store = MemoryStore::new();
        let stored = StoredPeers {
            version: 42,
            peers: vec![],
        };
        store
            .write(TRUSTED_HOSTS_KEY, &postcard::to_stdvec(&stored).unwrap())
            .unwrap();
        assert!(TrustedPeers::load(&store, TRUSTED_HOSTS_KEY).is_err());
    }

    #[test]
    fn full_mutual_auth_happy_path() {
        let host = HostIdentity::generate("desk").unwrap();
        let client = ClientIdentity::generate("laptop").unwrap();
        let e = exporter(0x2A);

        let mut trusted = TrustedPeers::new();
        trusted
            .upsert(peer_for("laptop", client.ed25519_pub(), [0u8; 32]))
            .unwrap();

        let (mut h, challenge) = HostAuthenticator::start_with_nonce(&e, [1u8; 32]).unwrap();
        let mut c =
            ClientAuthenticator::start_with_nonce(&e, &host.ed25519_pub(), [2u8; 32]).unwrap();

        let (client_auth, client_challenge) = c
            .on_server_challenge(&challenge, client.signing_key())
            .unwrap();
        let matched = h.on_client_auth(&client_auth, &trusted).unwrap();
        assert_eq!(matched.name, "laptop");

        let (server_auth, ok) = h
            .on_client_challenge(&client_challenge, host.signing_key())
            .unwrap();
        c.on_server_auth(&server_auth).unwrap();
        c.on_auth_ok(&ok).unwrap();

        assert!(h.is_complete());
        assert!(c.is_complete());
        assert_eq!(h.peer().unwrap().ed25519_pub, client.ed25519_pub());
    }

    #[test]
    fn host_rejects_unknown_client() {
        let host = HostIdentity::generate("h").unwrap();
        let client = ClientIdentity::generate("stranger").unwrap();
        let e = exporter(0x2B);
        let (mut h, challenge) = HostAuthenticator::start_with_nonce(&e, [1u8; 32]).unwrap();
        let mut c =
            ClientAuthenticator::start_with_nonce(&e, &host.ed25519_pub(), [2u8; 32]).unwrap();
        let (client_auth, _) = c
            .on_server_challenge(&challenge, client.signing_key())
            .unwrap();
        let err = h
            .on_client_auth(&client_auth, &TrustedPeers::new())
            .unwrap_err();
        assert!(matches!(err, Error::Auth(_)));
    }

    #[test]
    fn host_rejects_forged_signature() {
        let client = ClientIdentity::generate("laptop").unwrap();
        let impostor = ClientIdentity::generate("impostor").unwrap();
        let e = exporter(0x2C);

        let mut trusted = TrustedPeers::new();
        trusted
            .upsert(peer_for("laptop", client.ed25519_pub(), [0u8; 32]))
            .unwrap();

        let (mut h, challenge) = HostAuthenticator::start_with_nonce(&e, [3u8; 32]).unwrap();
        let AuthMsg::ServerChallenge { nonce } = challenge else {
            panic!("wrong variant")
        };

        // Claim to be the trusted client, but sign with the impostor's key.
        let sig = sign_challenge(impostor.signing_key(), Role::Client, &e, &nonce).unwrap();
        let forged = AuthMsg::ClientAuth {
            client_ed25519_pub: client.ed25519_pub(),
            sig,
        };
        assert!(h.on_client_auth(&forged, &trusted).is_err());
        assert!(!h.is_complete());
    }

    #[test]
    fn client_rejects_wrong_host_key() {
        let real_host = HostIdentity::generate("real").unwrap();
        let evil_host = HostIdentity::generate("evil").unwrap();
        let client = ClientIdentity::generate("laptop").unwrap();
        let e = exporter(0x2D);

        let mut trusted = TrustedPeers::new();
        trusted
            .upsert(peer_for("laptop", client.ed25519_pub(), [0u8; 32]))
            .unwrap();

        // The client pinned `real_host`, but `evil_host` answers.
        let (mut h, challenge) = HostAuthenticator::start_with_nonce(&e, [4u8; 32]).unwrap();
        let mut c =
            ClientAuthenticator::start_with_nonce(&e, &real_host.ed25519_pub(), [5u8; 32]).unwrap();
        let (client_auth, client_challenge) = c
            .on_server_challenge(&challenge, client.signing_key())
            .unwrap();
        h.on_client_auth(&client_auth, &trusted).unwrap();
        let (server_auth, _) = h
            .on_client_challenge(&client_challenge, evil_host.signing_key())
            .unwrap();

        assert!(c.on_server_auth(&server_auth).is_err());
        assert!(!c.is_complete());
    }

    #[test]
    fn signature_from_another_session_does_not_replay() {
        let host = HostIdentity::generate("desk").unwrap();
        let client = ClientIdentity::generate("laptop").unwrap();
        let mut trusted = TrustedPeers::new();
        trusted
            .upsert(peer_for("laptop", client.ed25519_pub(), [0u8; 32]))
            .unwrap();

        // Session 1: capture the client's signature.
        let e1 = exporter(0x30);
        let (_h1, ch1) = HostAuthenticator::start_with_nonce(&e1, [6u8; 32]).unwrap();
        let mut c1 =
            ClientAuthenticator::start_with_nonce(&e1, &host.ed25519_pub(), [7u8; 32]).unwrap();
        let (captured, _) = c1.on_server_challenge(&ch1, client.signing_key()).unwrap();

        // Session 2: different exporter AND different nonce. Replay must fail.
        let e2 = exporter(0x31);
        let (mut h2, _ch2) = HostAuthenticator::start_with_nonce(&e2, [8u8; 32]).unwrap();
        assert!(h2.on_client_auth(&captured, &trusted).is_err());
    }

    #[test]
    fn out_of_order_messages_fail_both_sides() {
        let e = exporter(0x32);
        let host = HostIdentity::generate("h").unwrap();
        let (mut h, _) = HostAuthenticator::start_with_nonce(&e, [1u8; 32]).unwrap();
        assert!(h
            .on_client_challenge(
                &AuthMsg::ClientChallenge { nonce: [0u8; 32] },
                host.signing_key()
            )
            .is_err());

        let mut c =
            ClientAuthenticator::start_with_nonce(&e, &host.ed25519_pub(), [2u8; 32]).unwrap();
        assert!(c
            .on_server_auth(&AuthMsg::ServerAuth { sig: vec![0u8; 64] })
            .is_err());
        assert!(!c.is_complete());
    }

    #[test]
    fn auth_fail_is_surfaced() {
        let host = HostIdentity::generate("h").unwrap();
        let client = ClientIdentity::generate("c").unwrap();
        let e = exporter(0x33);
        let (mut h, challenge) = HostAuthenticator::start_with_nonce(&e, [1u8; 32]).unwrap();
        let mut trusted = TrustedPeers::new();
        trusted
            .upsert(peer_for("c", client.ed25519_pub(), [0u8; 32]))
            .unwrap();
        let mut c =
            ClientAuthenticator::start_with_nonce(&e, &host.ed25519_pub(), [2u8; 32]).unwrap();
        let (ca, cc) = c
            .on_server_challenge(&challenge, client.signing_key())
            .unwrap();
        h.on_client_auth(&ca, &trusted).unwrap();
        let (sa, _) = h.on_client_challenge(&cc, host.signing_key()).unwrap();
        c.on_server_auth(&sa).unwrap();

        let err = c
            .on_auth_ok(&AuthMsg::AuthFail {
                reason: "nope".into(),
            })
            .unwrap_err();
        assert!(matches!(err, Error::Auth(_)));
        assert!(!c.is_complete());
    }

    #[test]
    fn authenticator_debug_never_prints_the_exporter() {
        // The exporter is what binds a signature to one TLS session; leaking it
        // into a log would weaken the replay defence.
        let e = exporter(0x5C);
        let host = HostIdentity::generate("h").unwrap();
        let (h, _) = HostAuthenticator::start_with_nonce(&e, [0x5Du8; 32]).unwrap();
        let c =
            ClientAuthenticator::start_with_nonce(&e, &host.ed25519_pub(), [0x5Eu8; 32]).unwrap();

        let leaked = |s: &str| s.contains("92") && s.contains("93");
        let hs = format!("{h:?}");
        let cs = format!("{c:?}");
        assert!(!hs.contains("exporter"), "{hs}");
        assert!(!cs.contains("exporter"), "{cs}");
        assert!(!leaked(&hs));
        assert!(hs.contains("stage"));
        assert!(cs.contains("host_pub"));
    }

    #[test]
    fn peer_list_cap_is_enforced() {
        let mut set = TrustedPeers::new();
        for i in 0..MAX_TRUSTED_PEERS {
            let mut key = [0u8; 32];
            // Valid Ed25519 public keys are needed, so derive real ones.
            let id = ClientIdentity::generate("p").unwrap();
            key.copy_from_slice(&id.ed25519_pub());
            set.upsert(peer_for(&format!("p{i}"), key, [0u8; 32]))
                .unwrap();
        }
        let extra = ClientIdentity::generate("extra").unwrap();
        assert!(set
            .upsert(peer_for("extra", extra.ed25519_pub(), [0u8; 32]))
            .is_err());
    }
}
