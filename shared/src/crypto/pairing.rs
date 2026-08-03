//! SPAKE2 pairing.
//!
//! # The problem
//!
//! The very first time a client meets a host there is nothing to pin yet. The
//! only shared knowledge is an 8-digit code the user reads off the host screen
//! and types into the client. Eight digits is 10^8 — trivially brute-forceable
//! offline. So the code must never appear on the wire, and a wrong guess must
//! cost the attacker a whole *online* attempt against a single-use code.
//!
//! # The construction
//!
//! SPAKE2 (Ed25519 group) turns the low-entropy code into a high-entropy shared
//! key. An eavesdropper learns nothing about the code, and an active attacker
//! gets exactly one guess per exchange — which is why the code here is strictly
//! single-use and expires after [`PAIRING_TTL_MS`].
//!
//! The SPAKE2 key alone would still let a machine-in-the-middle relay the whole
//! exchange between an honest client and an honest host. To stop that, the
//! confirmation MACs are bound to the *TLS session* through RFC 5705 exporter
//! keying material. A relay terminates two different TLS sessions, so the two
//! exporters differ, so the MAC it forwards will not verify.
//!
//! ```text
//! client                                        host
//!   |-- PairStart   { spake_msg = A }  -------->|
//!   |<- PairResponse{ spake_msg = B }  ---------|
//!   |   K   = SPAKE2 key                        |   K = SPAKE2 key
//!   |   T   = A || B                            |   T = A || B
//!   |   CK  = HMAC(K, "…confirm-key")           |   CK = …
//!   |-- PairConfirm { HMAC(CK, T‖E‖"client") }->|  verify
//!   |<- PairConfirm { HMAC(CK, T‖E‖"host")   }--|
//!   |  verify                                   |
//!   |<- PairComplete{ host identity }  ---------|
//! ```
//! `E` is the 32-byte TLS exporter, supplied by the caller so this module has
//! no transport dependency and stays unit-testable.
//!
//! # Rules enforced here
//!
//! - **Single use.** Each state machine accepts each message exactly once. A
//!   replayed `PairStart` or `PairConfirm` is rejected, and any failure is
//!   terminal — a wrong code burns the pairing session rather than allowing a
//!   second guess.
//! - **Expiry.** Every transition re-checks the deadline against the injected
//!   `now_ms`. There is no wall-clock read anywhere in this file.
//! - **Constant time.** MACs are verified with the HMAC crate's constant-time
//!   `verify_slice`; the pin is compared with [`crate::crypto::ct_eq`].

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::crypto::auth::TrustedPeer;
use crate::crypto::{Exporter, Role, SpkiHash, check_exporter, ct_eq};
use crate::error::{Error, Result};
use crate::protocol::AuthMsg;
use crate::secret::Secret;

type HmacSha256 = Hmac<Sha256>;

/// Number of digits in a pairing code.
pub const PAIRING_CODE_DIGITS: usize = 8;

/// How long a pairing code stays valid, in milliseconds.
pub const PAIRING_TTL_MS: u64 = 120_000;

/// Exact size of a SPAKE2 Ed25519-group message: one side byte + one 32-byte
/// group element.
const SPAKE_MSG_LEN: usize = 33;

/// Domain separator for deriving the confirmation key from the SPAKE2 output.
const CONFIRM_KEY_INFO: &[u8] = b"directdesk/pair/v1/confirm-key";

/// SPAKE2 identity string for the client (side A).
const ID_CLIENT: &[u8] = b"directdesk-client";
/// SPAKE2 identity string for the host (side B).
const ID_HOST: &[u8] = b"directdesk-host";

// ---------------------------------------------------------------------------
// Pairing code
// ---------------------------------------------------------------------------

/// An 8-digit single-use pairing code.
///
/// Wrapped in [`Secret`] so it can never be `Debug`-logged. It *is* meant to be
/// shown to the user on the host's screen — that is what [`Self::expose`] and
/// [`Self::display_grouped`] are for — but it must never end up in a log file
/// or a crash dump.
#[derive(Debug)]
pub struct PairingCode(Secret<String>);

impl PairingCode {
    /// Generate a fresh code from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generate a code from a caller-supplied CSPRNG (deterministic in tests).
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut s = String::with_capacity(PAIRING_CODE_DIGITS);
        for _ in 0..PAIRING_CODE_DIGITS {
            s.push(char::from(b'0' + next_digit(rng)));
        }
        Self(Secret::new(s))
    }

    /// Parse user input. Spaces and dashes are ignored so "1234-5678" works.
    pub fn parse(input: &str) -> Result<Self> {
        let digits: String =
            input.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '_').collect();
        if digits.len() != PAIRING_CODE_DIGITS {
            return Err(Error::Pairing(format!(
                "pairing code must be {PAIRING_CODE_DIGITS} digits"
            )));
        }
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Pairing("pairing code must be digits only".into()));
        }
        Ok(Self(Secret::new(digits)))
    }

    /// The raw digits. Only for display to the user and for feeding SPAKE2.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The code split into two groups of four, e.g. `1234 5678`.
    pub fn display_grouped(&self) -> String {
        let s = self.expose();
        let mid = PAIRING_CODE_DIGITS / 2;
        if s.len() == PAIRING_CODE_DIGITS {
            format!("{} {}", &s[..mid], &s[mid..])
        } else {
            s.to_string()
        }
    }
}

/// One uniformly distributed decimal digit, by rejection sampling so there is
/// no modulo bias.
fn next_digit<R: RngCore + CryptoRng>(rng: &mut R) -> u8 {
    // Largest multiple of 10 that fits in u32.
    const LIMIT: u32 = u32::MAX - (u32::MAX % 10) - 9;
    loop {
        let v = rng.next_u32();
        if v <= LIMIT {
            return (v % 10) as u8;
        }
    }
}

// ---------------------------------------------------------------------------
// Shared key schedule
// ---------------------------------------------------------------------------

/// Derive the confirmation key from the raw SPAKE2 output.
fn derive_confirm_key(spake_key: &[u8]) -> Result<Secret<Vec<u8>>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(spake_key)
        .map_err(|_| Error::Crypto("hmac key length".into()))?;
    mac.update(CONFIRM_KEY_INFO);
    Ok(Secret::new(mac.finalize().into_bytes().to_vec()))
}

/// Compute `HMAC(confirm_key, transcript || exporter || role)`.
fn confirm_mac(
    confirm_key: &Secret<Vec<u8>>,
    transcript: &[u8],
    exporter: &Exporter,
    role: Role,
) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(confirm_key.expose())
        .map_err(|_| Error::Crypto("hmac key length".into()))?;
    mac.update(transcript);
    mac.update(exporter);
    mac.update(role.label());
    Ok(mac.finalize().into_bytes().into())
}

/// Constant-time verification of a peer MAC.
fn verify_confirm_mac(
    confirm_key: &Secret<Vec<u8>>,
    transcript: &[u8],
    exporter: &Exporter,
    role: Role,
    provided: &[u8; 32],
) -> Result<()> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(confirm_key.expose())
        .map_err(|_| Error::Crypto("hmac key length".into()))?;
    mac.update(transcript);
    mac.update(exporter);
    mac.update(role.label());
    mac.verify_slice(provided)
        .map_err(|_| Error::Pairing("pairing confirmation failed (wrong code?)".into()))
}

/// Sanity-check an inbound SPAKE2 message before doing any group arithmetic.
fn check_spake_msg(msg: &[u8]) -> Result<()> {
    if msg.len() != SPAKE_MSG_LEN {
        return Err(Error::Pairing(format!(
            "spake message must be {SPAKE_MSG_LEN} bytes, got {}",
            msg.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Where a pairing state machine currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStage {
    /// Host only: waiting for the client's `PairStart`.
    AwaitStart,
    /// Client only: waiting for the host's `PairResponse`.
    AwaitResponse,
    /// Waiting for the peer's `PairConfirm`.
    AwaitConfirm,
    /// Both confirmations verified.
    Complete,
    /// Terminally failed. The code is burned; the user must start over.
    Failed,
}

impl PairingStage {
    /// Whether the state machine can still make progress.
    pub fn is_live(&self) -> bool {
        !matches!(self, PairingStage::Complete | PairingStage::Failed)
    }
}

/// Common expiry/stage bookkeeping shared by both sides.
struct Session {
    started_ms: u64,
    ttl_ms: u64,
    stage: PairingStage,
}

impl Session {
    fn new(started_ms: u64, ttl_ms: u64, stage: PairingStage) -> Self {
        Self { started_ms, ttl_ms, stage }
    }

    fn expires_at_ms(&self) -> u64 {
        self.started_ms.saturating_add(self.ttl_ms)
    }

    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms > self.expires_at_ms()
    }

    /// Gate every transition: correct stage, still live, not expired.
    /// On any failure the session is burned.
    fn enter(&mut self, expected: PairingStage, now_ms: u64) -> Result<()> {
        if self.stage != expected {
            let actual = self.stage;
            self.stage = PairingStage::Failed;
            return Err(Error::Pairing(format!(
                "unexpected pairing message in stage {actual:?} (expected {expected:?})"
            )));
        }
        if self.is_expired(now_ms) {
            self.stage = PairingStage::Failed;
            return Err(Error::Pairing("pairing code expired".into()));
        }
        Ok(())
    }

    fn fail<T>(&mut self, e: Error) -> Result<T> {
        self.stage = PairingStage::Failed;
        Err(e)
    }
}

// ---------------------------------------------------------------------------
// Client side (SPAKE2 side A)
// ---------------------------------------------------------------------------

/// Client half of the pairing exchange.
pub struct PairingClient {
    session: Session,
    spake: Option<Spake2<Ed25519Group>>,
    own_msg: Vec<u8>,
    exporter: Exporter,
    transcript: Vec<u8>,
    confirm_key: Option<Secret<Vec<u8>>>,
}

impl std::fmt::Debug for PairingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingClient").field("stage", &self.session.stage).finish()
    }
}

impl PairingClient {
    /// Begin pairing. Returns the state machine and the `PairStart` to send.
    ///
    /// `exporter` must be the RFC 5705 exporter of the TLS session this
    /// pairing runs inside — see [`crate::crypto::EXPORTER_LABEL`].
    pub fn start(
        code: &PairingCode,
        exporter: &Exporter,
        now_ms: u64,
    ) -> Result<(Self, AuthMsg)> {
        Self::start_with_rng(code, exporter, now_ms, PAIRING_TTL_MS, &mut OsRng)
    }

    /// [`Self::start`] with an injected CSPRNG and TTL, for deterministic tests.
    pub fn start_with_rng<R: RngCore + CryptoRng>(
        code: &PairingCode,
        exporter: &Exporter,
        now_ms: u64,
        ttl_ms: u64,
        rng: &mut R,
    ) -> Result<(Self, AuthMsg)> {
        check_exporter(exporter)?;
        let (spake, msg) = Spake2::<Ed25519Group>::start_a_with_rng(
            &Password::new(code.expose().as_bytes()),
            &Identity::new(ID_CLIENT),
            &Identity::new(ID_HOST),
            rng,
        );
        let me = Self {
            session: Session::new(now_ms, ttl_ms, PairingStage::AwaitResponse),
            spake: Some(spake),
            own_msg: msg.clone(),
            exporter: *exporter,
            transcript: Vec::new(),
            confirm_key: None,
        };
        Ok((me, AuthMsg::PairStart { spake_msg: msg }))
    }

    /// Handle the host's `PairResponse` and produce our `PairConfirm`.
    pub fn on_pair_response(&mut self, msg: &AuthMsg, now_ms: u64) -> Result<AuthMsg> {
        self.session.enter(PairingStage::AwaitResponse, now_ms)?;
        let AuthMsg::PairResponse { spake_msg } = msg else {
            return self.session.fail(Error::Pairing("expected PairResponse".into()));
        };
        if let Err(e) = check_spake_msg(spake_msg) {
            return self.session.fail(e);
        }

        let Some(spake) = self.spake.take() else {
            return self.session.fail(Error::Pairing("spake state already consumed".into()));
        };
        let key = match spake.finish(spake_msg) {
            Ok(k) => k,
            Err(e) => return self.session.fail(Error::Pairing(format!("spake2 failed: {e:?}"))),
        };

        // Transcript is always client-message-then-host-message on both sides.
        self.transcript.clear();
        self.transcript.extend_from_slice(&self.own_msg);
        self.transcript.extend_from_slice(spake_msg);

        let confirm_key = match derive_confirm_key(&key) {
            Ok(k) => k,
            Err(e) => return self.session.fail(e),
        };
        let mac = match confirm_mac(&confirm_key, &self.transcript, &self.exporter, Role::Client) {
            Ok(m) => m,
            Err(e) => return self.session.fail(e),
        };
        self.confirm_key = Some(confirm_key);
        self.session.stage = PairingStage::AwaitConfirm;
        Ok(AuthMsg::PairConfirm { mac })
    }

    /// Verify the host's `PairConfirm`. On success the exchange is complete.
    pub fn on_pair_confirm(&mut self, msg: &AuthMsg, now_ms: u64) -> Result<()> {
        self.session.enter(PairingStage::AwaitConfirm, now_ms)?;
        let AuthMsg::PairConfirm { mac } = msg else {
            return self.session.fail(Error::Pairing("expected PairConfirm".into()));
        };
        let Some(ck) = self.confirm_key.as_ref() else {
            return self.session.fail(Error::Pairing("no confirmation key".into()));
        };
        if let Err(e) = verify_confirm_mac(ck, &self.transcript, &self.exporter, Role::Host, mac) {
            return self.session.fail(e);
        }
        self.session.stage = PairingStage::Complete;
        self.confirm_key = None;
        Ok(())
    }

    /// Accept the host's `PairComplete` and turn it into a trusted peer record.
    ///
    /// `observed_spki` is the pin the TLS layer actually saw on this
    /// connection. If the host claims a different pin than the certificate it
    /// just served, pairing is aborted — that mismatch is the signature of a
    /// relay trying to get its own key pinned.
    pub fn accept_pair_complete(
        &mut self,
        msg: &AuthMsg,
        observed_spki: &SpkiHash,
        now_ms: u64,
    ) -> Result<TrustedPeer> {
        if self.session.stage != PairingStage::Complete {
            return self
                .session
                .fail(Error::Pairing("PairComplete before confirmation".into()));
        }
        let AuthMsg::PairComplete { host_ed25519_pub, host_spki_sha256, host_name } = msg else {
            return self.session.fail(Error::Pairing("expected PairComplete".into()));
        };
        if !ct_eq(host_spki_sha256, observed_spki) {
            return self.session.fail(Error::Pairing(
                "host certificate pin does not match the claimed pin".into(),
            ));
        }
        if let Err(e) = crate::crypto::identity::validate_name(host_name) {
            return self.session.fail(Error::Pairing(format!("bad host name: {e}")));
        }
        // Reject a structurally invalid Ed25519 key now rather than at the
        // first authentication attempt.
        crate::crypto::identity::parse_verifying_key(host_ed25519_pub)?;

        Ok(TrustedPeer {
            name: host_name.clone(),
            ed25519_pub: *host_ed25519_pub,
            spki_sha256: *host_spki_sha256,
            added_at_ms: now_ms,
        })
    }

    /// Current stage.
    pub fn stage(&self) -> PairingStage {
        self.session.stage
    }

    /// Whether both confirmations verified.
    pub fn is_complete(&self) -> bool {
        self.session.stage == PairingStage::Complete
    }
}

// ---------------------------------------------------------------------------
// Host side (SPAKE2 side B)
// ---------------------------------------------------------------------------

/// Host half of the pairing exchange.
pub struct PairingHost {
    session: Session,
    code: PairingCode,
    spake: Option<Spake2<Ed25519Group>>,
    own_msg: Vec<u8>,
    exporter: Option<Exporter>,
    transcript: Vec<u8>,
    confirm_key: Option<Secret<Vec<u8>>>,
}

impl std::fmt::Debug for PairingHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingHost")
            .field("stage", &self.session.stage)
            .field("expires_at_ms", &self.session.expires_at_ms())
            .finish()
    }
}

impl PairingHost {
    /// Arm pairing with a freshly generated code, shown to the user now.
    pub fn new(now_ms: u64) -> Self {
        Self::with_code(PairingCode::generate(), now_ms, PAIRING_TTL_MS)
    }

    /// Arm pairing with a specific code and TTL.
    pub fn with_code(code: PairingCode, now_ms: u64, ttl_ms: u64) -> Self {
        Self {
            session: Session::new(now_ms, ttl_ms, PairingStage::AwaitStart),
            code,
            spake: None,
            own_msg: Vec::new(),
            exporter: None,
            transcript: Vec::new(),
            confirm_key: None,
        }
    }

    /// The code to display to the user.
    pub fn code(&self) -> &PairingCode {
        &self.code
    }

    /// When this code stops being accepted.
    pub fn expires_at_ms(&self) -> u64 {
        self.session.expires_at_ms()
    }

    /// Whether the code has expired as of `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.session.is_expired(now_ms)
    }

    /// Handle the client's `PairStart` and produce `PairResponse`.
    pub fn on_pair_start(
        &mut self,
        msg: &AuthMsg,
        exporter: &Exporter,
        now_ms: u64,
    ) -> Result<AuthMsg> {
        self.on_pair_start_with_rng(msg, exporter, now_ms, &mut OsRng)
    }

    /// [`Self::on_pair_start`] with an injected CSPRNG, for deterministic tests.
    pub fn on_pair_start_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        msg: &AuthMsg,
        exporter: &Exporter,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<AuthMsg> {
        self.session.enter(PairingStage::AwaitStart, now_ms)?;
        if let Err(e) = check_exporter(exporter) {
            return self.session.fail(e);
        }
        let AuthMsg::PairStart { spake_msg } = msg else {
            return self.session.fail(Error::Pairing("expected PairStart".into()));
        };
        if let Err(e) = check_spake_msg(spake_msg) {
            return self.session.fail(e);
        }

        let (spake, own) = Spake2::<Ed25519Group>::start_b_with_rng(
            &Password::new(self.code.expose().as_bytes()),
            &Identity::new(ID_CLIENT),
            &Identity::new(ID_HOST),
            rng,
        );
        let key = match spake.finish(spake_msg) {
            Ok(k) => k,
            Err(e) => return self.session.fail(Error::Pairing(format!("spake2 failed: {e:?}"))),
        };

        self.transcript.clear();
        self.transcript.extend_from_slice(spake_msg);
        self.transcript.extend_from_slice(&own);
        self.own_msg = own.clone();
        self.exporter = Some(*exporter);
        self.confirm_key = Some(match derive_confirm_key(&key) {
            Ok(k) => k,
            Err(e) => return self.session.fail(e),
        });
        self.spake = None;
        self.session.stage = PairingStage::AwaitConfirm;
        Ok(AuthMsg::PairResponse { spake_msg: own })
    }

    /// Verify the client's `PairConfirm` and produce ours.
    pub fn on_pair_confirm(&mut self, msg: &AuthMsg, now_ms: u64) -> Result<AuthMsg> {
        self.session.enter(PairingStage::AwaitConfirm, now_ms)?;
        let AuthMsg::PairConfirm { mac } = msg else {
            return self.session.fail(Error::Pairing("expected PairConfirm".into()));
        };
        let (Some(ck), Some(exporter)) = (self.confirm_key.as_ref(), self.exporter) else {
            return self.session.fail(Error::Pairing("pairing state incomplete".into()));
        };
        if let Err(e) = verify_confirm_mac(ck, &self.transcript, &exporter, Role::Client, mac) {
            return self.session.fail(e);
        }
        let ours = match confirm_mac(ck, &self.transcript, &exporter, Role::Host) {
            Ok(m) => m,
            Err(e) => return self.session.fail(e),
        };
        self.session.stage = PairingStage::Complete;
        self.confirm_key = None;
        Ok(AuthMsg::PairConfirm { mac: ours })
    }

    /// Turn a freshly authenticated client key into a trusted peer record.
    ///
    /// Call this only after (a) pairing reached [`PairingStage::Complete`] and
    /// (b) the client's `ClientAuth` signature verified on the same connection
    /// — see [`crate::crypto::auth`]. Pairing proves the user typed the code;
    /// the signature proves which key belongs to that client.
    ///
    /// The client has no TLS certificate of its own, so `spki_sha256` is all
    /// zeroes for client records.
    pub fn accept_client(
        &self,
        client_ed25519_pub: &crate::crypto::Ed25519Pub,
        name: &str,
        now_ms: u64,
    ) -> Result<TrustedPeer> {
        if self.session.stage != PairingStage::Complete {
            return Err(Error::Pairing("client accepted before pairing completed".into()));
        }
        crate::crypto::identity::validate_name(name)?;
        crate::crypto::identity::parse_verifying_key(client_ed25519_pub)?;
        Ok(TrustedPeer {
            name: name.to_string(),
            ed25519_pub: *client_ed25519_pub,
            spki_sha256: [0u8; 32],
            added_at_ms: now_ms,
        })
    }

    /// Current stage.
    pub fn stage(&self) -> PairingStage {
        self.session.stage
    }

    /// Whether both confirmations verified.
    pub fn is_complete(&self) -> bool {
        self.session.stage == PairingStage::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn exporter(byte: u8) -> Exporter {
        let mut e = [byte; 32];
        e[0] = byte ^ 0x5A;
        e
    }

    struct Rigged {
        client: PairingClient,
        host: PairingHost,
    }

    /// Drive a full pairing with deterministic RNGs.
    fn rig(client_code: &str, host_code: &str, exp_c: Exporter, exp_h: Exporter) -> Rigged {
        let mut crng = StdRng::seed_from_u64(11);
        let mut hrng = StdRng::seed_from_u64(22);
        let (client, start) = PairingClient::start_with_rng(
            &PairingCode::parse(client_code).unwrap(),
            &exp_c,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse(host_code).unwrap(), 0, PAIRING_TTL_MS);
        let _ = host.on_pair_start_with_rng(&start, &exp_h, 0, &mut hrng);
        let _ = start;
        Rigged { client, host }
    }

    #[test]
    fn code_generation_is_eight_digits() {
        let mut rng = StdRng::seed_from_u64(1);
        let c = PairingCode::generate_with_rng(&mut rng);
        assert_eq!(c.expose().len(), PAIRING_CODE_DIGITS);
        assert!(c.expose().bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(c.display_grouped().len(), PAIRING_CODE_DIGITS + 1);
    }

    #[test]
    fn code_generation_is_deterministic_for_a_seed() {
        let a = PairingCode::generate_with_rng(&mut StdRng::seed_from_u64(7));
        let b = PairingCode::generate_with_rng(&mut StdRng::seed_from_u64(7));
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn code_parsing() {
        assert_eq!(PairingCode::parse("1234 5678").unwrap().expose(), "12345678");
        assert_eq!(PairingCode::parse("1234-5678").unwrap().expose(), "12345678");
        assert!(PairingCode::parse("1234567").is_err());
        assert!(PairingCode::parse("123456789").is_err());
        assert!(PairingCode::parse("1234567a").is_err());
    }

    #[test]
    fn code_is_redacted_in_debug() {
        let c = PairingCode::parse("13572468").unwrap();
        let s = format!("{c:?}");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("13572468"));
    }

    #[test]
    fn happy_path() {
        let exp = exporter(0x33);
        let mut crng = StdRng::seed_from_u64(1);
        let mut hrng = StdRng::seed_from_u64(2);
        let code = PairingCode::parse("13572468").unwrap();

        let (mut client, start) = PairingClient::start_with_rng(
            &code,
            &exp,
            1_000,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host = PairingHost::with_code(
            PairingCode::parse("13572468").unwrap(),
            1_000,
            PAIRING_TTL_MS,
        );

        let response = host.on_pair_start_with_rng(&start, &exp, 1_010, &mut hrng).unwrap();
        let client_confirm = client.on_pair_response(&response, 1_020).unwrap();
        let host_confirm = host.on_pair_confirm(&client_confirm, 1_030).unwrap();
        client.on_pair_confirm(&host_confirm, 1_040).unwrap();

        assert!(client.is_complete());
        assert!(host.is_complete());
        assert_eq!(client.stage(), PairingStage::Complete);
    }

    #[test]
    fn wrong_code_fails_at_confirmation() {
        let exp = exporter(0x44);
        let mut r = rig("11112222", "33334444", exp, exp);
        // The host produced a PairResponse even with a mismatched code (SPAKE2
        // reveals nothing at that point); the failure surfaces at confirm.
        let mut hrng = StdRng::seed_from_u64(99);
        let response = {
            // Rebuild a response from the host's own state by re-running the
            // exchange: the rig already consumed PairStart, so drive confirm.
            let _ = &mut hrng;
            AuthMsg::PairResponse { spake_msg: r.host.own_msg.clone() }
        };
        let client_confirm = r.client.on_pair_response(&response, 10).unwrap();
        let err = r.host.on_pair_confirm(&client_confirm, 20).unwrap_err();
        assert!(matches!(err, Error::Pairing(_)));
        assert_eq!(r.host.stage(), PairingStage::Failed);
    }

    #[test]
    fn mismatched_exporter_fails_relay_style() {
        // A relay terminates two TLS sessions, so each honest side sees a
        // different exporter. Even with the correct code, confirmation fails.
        let mut r = rig("55556666", "55556666", exporter(0x01), exporter(0x02));
        let response = AuthMsg::PairResponse { spake_msg: r.host.own_msg.clone() };
        let client_confirm = r.client.on_pair_response(&response, 10).unwrap();
        let err = r.host.on_pair_confirm(&client_confirm, 20).unwrap_err();
        assert!(matches!(err, Error::Pairing(_)));
    }

    #[test]
    fn expiry_is_enforced_on_host() {
        let exp = exporter(0x55);
        let mut crng = StdRng::seed_from_u64(3);
        let mut hrng = StdRng::seed_from_u64(4);
        let code = PairingCode::parse("12341234").unwrap();
        let (_client, start) =
            PairingClient::start_with_rng(&code, &exp, 0, PAIRING_TTL_MS, &mut crng).unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse("12341234").unwrap(), 0, PAIRING_TTL_MS);

        assert!(host.is_expired(PAIRING_TTL_MS + 1));
        let err = host
            .on_pair_start_with_rng(&start, &exp, PAIRING_TTL_MS + 1, &mut hrng)
            .unwrap_err();
        assert!(matches!(err, Error::Pairing(_)));
        assert_eq!(host.stage(), PairingStage::Failed);
    }

    #[test]
    fn expiry_is_enforced_mid_exchange() {
        let exp = exporter(0x56);
        let mut crng = StdRng::seed_from_u64(5);
        let mut hrng = StdRng::seed_from_u64(6);
        let (mut client, start) = PairingClient::start_with_rng(
            &PairingCode::parse("99998888").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host = PairingHost::with_code(
            PairingCode::parse("99998888").unwrap(),
            0,
            PAIRING_TTL_MS,
        );
        let response = host.on_pair_start_with_rng(&start, &exp, 10, &mut hrng).unwrap();
        // Client dawdles past the deadline before answering.
        let err = client.on_pair_response(&response, PAIRING_TTL_MS + 5).unwrap_err();
        assert!(matches!(err, Error::Pairing(_)));
        assert_eq!(client.stage(), PairingStage::Failed);
    }

    #[test]
    fn replayed_pair_start_is_rejected() {
        let exp = exporter(0x66);
        let mut crng = StdRng::seed_from_u64(7);
        let mut hrng = StdRng::seed_from_u64(8);
        let (_c, start) = PairingClient::start_with_rng(
            &PairingCode::parse("10101010").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse("10101010").unwrap(), 0, PAIRING_TTL_MS);
        assert!(host.on_pair_start_with_rng(&start, &exp, 1, &mut hrng).is_ok());
        let err = host.on_pair_start_with_rng(&start, &exp, 2, &mut hrng).unwrap_err();
        assert!(matches!(err, Error::Pairing(_)));
        assert_eq!(host.stage(), PairingStage::Failed);
    }

    #[test]
    fn replayed_confirm_is_rejected_single_use() {
        let exp = exporter(0x77);
        let mut crng = StdRng::seed_from_u64(9);
        let mut hrng = StdRng::seed_from_u64(10);
        let (mut client, start) = PairingClient::start_with_rng(
            &PairingCode::parse("20202020").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse("20202020").unwrap(), 0, PAIRING_TTL_MS);
        let response = host.on_pair_start_with_rng(&start, &exp, 1, &mut hrng).unwrap();
        let cc = client.on_pair_response(&response, 2).unwrap();
        let hc = host.on_pair_confirm(&cc, 3).unwrap();
        client.on_pair_confirm(&hc, 4).unwrap();

        // Replay the client's confirmation at the host: already Complete.
        assert!(host.on_pair_confirm(&cc, 5).is_err());
        assert_eq!(host.stage(), PairingStage::Failed);
        // And the client refuses a replayed host confirmation.
        assert!(client.on_pair_confirm(&hc, 6).is_err());
    }

    #[test]
    fn out_of_order_messages_are_rejected() {
        let exp = exporter(0x88);
        let mut crng = StdRng::seed_from_u64(12);
        let (mut client, _start) = PairingClient::start_with_rng(
            &PairingCode::parse("30303030").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        // A PairConfirm before the response is out of order.
        assert!(client.on_pair_confirm(&AuthMsg::PairConfirm { mac: [0u8; 32] }, 1).is_err());
        assert_eq!(client.stage(), PairingStage::Failed);
    }

    #[test]
    fn malformed_spake_message_is_rejected() {
        let exp = exporter(0x99);
        let mut hrng = StdRng::seed_from_u64(13);
        let mut host =
            PairingHost::with_code(PairingCode::parse("40404040").unwrap(), 0, PAIRING_TTL_MS);
        let bad = AuthMsg::PairStart { spake_msg: vec![0u8; 7] };
        assert!(host.on_pair_start_with_rng(&bad, &exp, 1, &mut hrng).is_err());
        assert_eq!(host.stage(), PairingStage::Failed);
    }

    #[test]
    fn zero_exporter_is_rejected() {
        let mut crng = StdRng::seed_from_u64(14);
        let err = PairingClient::start_with_rng(
            &PairingCode::parse("50505050").unwrap(),
            &[0u8; 32],
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));
    }

    #[test]
    fn pair_complete_requires_matching_pin() {
        let exp = exporter(0xAB);
        let mut crng = StdRng::seed_from_u64(15);
        let mut hrng = StdRng::seed_from_u64(16);
        let (mut client, start) = PairingClient::start_with_rng(
            &PairingCode::parse("60606060").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse("60606060").unwrap(), 0, PAIRING_TTL_MS);
        let response = host.on_pair_start_with_rng(&start, &exp, 1, &mut hrng).unwrap();
        let cc = client.on_pair_response(&response, 2).unwrap();
        let hc = host.on_pair_confirm(&cc, 3).unwrap();
        client.on_pair_confirm(&hc, 4).unwrap();

        let id = crate::crypto::HostIdentity::generate("desk").unwrap();
        let complete = id.pair_complete();

        // Wrong observed pin => rejected.
        let mut wrong = *id.spki_sha256();
        wrong[0] ^= 0xFF;
        let mut c2 = client;
        assert!(c2.accept_pair_complete(&complete, &wrong, 5).is_err());

        // Correct pin on a fresh, completed client => accepted.
        let mut crng = StdRng::seed_from_u64(17);
        let mut hrng = StdRng::seed_from_u64(18);
        let (mut client, start) = PairingClient::start_with_rng(
            &PairingCode::parse("60606060").unwrap(),
            &exp,
            0,
            PAIRING_TTL_MS,
            &mut crng,
        )
        .unwrap();
        let mut host =
            PairingHost::with_code(PairingCode::parse("60606060").unwrap(), 0, PAIRING_TTL_MS);
        let response = host.on_pair_start_with_rng(&start, &exp, 1, &mut hrng).unwrap();
        let cc = client.on_pair_response(&response, 2).unwrap();
        let hc = host.on_pair_confirm(&cc, 3).unwrap();
        client.on_pair_confirm(&hc, 4).unwrap();

        let peer = client.accept_pair_complete(&complete, id.spki_sha256(), 5_000).unwrap();
        assert_eq!(peer.ed25519_pub, id.ed25519_pub());
        assert_eq!(peer.spki_sha256, *id.spki_sha256());
        assert_eq!(peer.name, "desk");
        assert_eq!(peer.added_at_ms, 5_000);
    }

    #[test]
    fn accept_client_requires_completion() {
        let host = PairingHost::with_code(
            PairingCode::parse("70707070").unwrap(),
            0,
            PAIRING_TTL_MS,
        );
        let id = crate::crypto::ClientIdentity::generate("laptop").unwrap();
        assert!(host.accept_client(&id.ed25519_pub(), "laptop", 1).is_err());
    }
}
