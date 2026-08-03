//! Secret storage: DPAPI on Windows, plus a trait so the crypto layer can be
//! unit-tested without touching the machine.
//!
//! # Why DPAPI
//!
//! DirectDesk has no user-supplied master password, so the key that protects
//! the host's long-term identity has to come from the OS. `CryptProtectData`
//! with `CRYPTPROTECT_LOCAL_MACHINE` binds the blob to *this machine*: it can
//! be decrypted by any process on the box, but not by the same file copied to
//! another machine. That is exactly the property we want for a service that
//! must start unattended at boot with no one to type a passphrase.
//!
//! Client secrets use user scope instead, which additionally binds to the
//! logged-in user's credentials.
//!
//! Because machine-scope DPAPI is readable by anything running locally, the
//! *file* ACL is the second half of the story. This milestone writes with
//! restrictive-ish defaults; hardening the ACL to `SYSTEM` + `Administrators`
//! happens in the service milestone. That is a known, deliberate gap.
//!
//! # Secondary entropy
//!
//! Every blob is protected with application-specific secondary entropy derived
//! from a fixed salt and the storage key name. A blob written for
//! `host_identity` therefore cannot be swapped in for `trusted_clients` by an
//! attacker who can write to the directory but cannot call DPAPI with our
//! entropy.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Fixed salt mixed into the DPAPI secondary entropy. Versioned: changing it
/// makes every existing blob undecryptable, so it must not change casually.
const ENTROPY_SALT: &[u8] = b"DirectDesk/dpapi/v1";

/// Subdirectory used under `%ProgramData%` and `%APPDATA%`.
const APP_DIR: &str = "DirectDesk";

/// Which DPAPI protection scope a blob uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpapiScope {
    /// `CRYPTPROTECT_LOCAL_MACHINE` — any process on this machine can decrypt.
    /// Required for the host service, which runs before any user logs in.
    Machine,
    /// Default DPAPI scope — bound to the current user's profile.
    User,
}

impl DpapiScope {
    fn flags(self) -> u32 {
        // CRYPTPROTECT_UI_FORBIDDEN: never pop a UI prompt. A service has no
        // desktop, and a hang here would wedge startup.
        const UI_FORBIDDEN: u32 = 0x1;
        const LOCAL_MACHINE: u32 = 0x4;
        match self {
            DpapiScope::Machine => UI_FORBIDDEN | LOCAL_MACHINE,
            DpapiScope::User => UI_FORBIDDEN,
        }
    }
}

/// A place secrets can be kept. Implemented by [`DpapiFileStore`] in
/// production and [`MemoryStore`] in tests.
///
/// Values handed to `write` and returned by `read` are *plaintext*; the
/// implementation is responsible for protecting them at rest.
pub trait SecretStore: Send + Sync {
    /// Read a blob. `Ok(None)` means "not stored yet", which is not an error.
    fn read(&self, key: &str) -> Result<Option<Secret<Vec<u8>>>>;
    /// Write (or overwrite) a blob.
    fn write(&self, key: &str, plaintext: &[u8]) -> Result<()>;
    /// Remove a blob. Removing something that is not there succeeds.
    fn delete(&self, key: &str) -> Result<()>;
    /// Whether a blob exists, without decrypting it.
    fn exists(&self, key: &str) -> Result<bool>;
}

/// Reject storage keys that could escape the storage directory or collide.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 64 {
        return Err(Error::Invalid("storage key length".into()));
    }
    if !key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err(Error::Invalid("storage key must be [a-z0-9_]".into()));
    }
    Ok(())
}

/// Build the DPAPI secondary entropy for a storage key.
fn entropy_for(key: &str) -> Vec<u8> {
    let mut e = Vec::with_capacity(ENTROPY_SALT.len() + 1 + key.len());
    e.extend_from_slice(ENTROPY_SALT);
    e.push(b'/');
    e.extend_from_slice(key.as_bytes());
    e
}

// ---------------------------------------------------------------------------
// DPAPI FFI
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    use crate::error::{Error, Result};

    /// Build a `CRYPT_INTEGER_BLOB` view over a byte slice.
    ///
    /// DPAPI never writes through the input pointers, so casting away
    /// constness here is sound; the blob lives only for the duration of the
    /// call and borrows `data`.
    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    /// Copy an output blob into a `Vec` and release the DPAPI allocation.
    ///
    /// # Safety
    /// `out` must be an output blob populated by `CryptProtectData` or
    /// `CryptUnprotectData` and not yet freed.
    unsafe fn take_blob(out: &mut CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = if out.pbData.is_null() || out.cbData == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec()
        };
        if !out.pbData.is_null() {
            // Best effort: zero the DPAPI-owned plaintext before releasing it.
            unsafe { std::ptr::write_bytes(out.pbData, 0, out.cbData as usize) };
            unsafe { LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void))) };
            out.pbData = std::ptr::null_mut();
            out.cbData = 0;
        }
        v
    }

    /// Encrypt `plaintext` with DPAPI.
    pub fn protect(plaintext: &[u8], entropy: &[u8], flags: u32) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(Error::Invalid("dpapi: refusing to protect empty data".into()));
        }
        let input = blob(plaintext);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `input`/`ent` point at live slices for the duration of the
        // call; `out` is a valid writable blob we take ownership of below.
        unsafe {
            CryptProtectData(&input, PCWSTR::null(), Some(&ent), None, None, flags, &mut out)
                .map_err(|e| Error::Crypto(format!("CryptProtectData failed: {e}")))?;
            Ok(take_blob(&mut out))
        }
    }

    /// Decrypt a DPAPI blob.
    pub fn unprotect(ciphertext: &[u8], entropy: &[u8], flags: u32) -> Result<Vec<u8>> {
        if ciphertext.is_empty() {
            return Err(Error::Invalid("dpapi: empty ciphertext".into()));
        }
        let input = blob(ciphertext);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as above.
        unsafe {
            CryptUnprotectData(&input, None, Some(&ent), None, None, flags, &mut out)
                .map_err(|e| Error::Crypto(format!("CryptUnprotectData failed: {e}")))?;
            Ok(take_blob(&mut out))
        }
    }
}

#[cfg(not(windows))]
mod dpapi {
    use crate::error::{Error, Result};

    pub fn protect(_plaintext: &[u8], _entropy: &[u8], _flags: u32) -> Result<Vec<u8>> {
        Err(Error::Crypto("DPAPI is only available on Windows".into()))
    }

    pub fn unprotect(_ciphertext: &[u8], _entropy: &[u8], _flags: u32) -> Result<Vec<u8>> {
        Err(Error::Crypto("DPAPI is only available on Windows".into()))
    }
}

/// Encrypt bytes with DPAPI under `scope` and application entropy for `key`.
pub fn protect(plaintext: &[u8], scope: DpapiScope, key: &str) -> Result<Vec<u8>> {
    validate_key(key)?;
    dpapi::protect(plaintext, &entropy_for(key), scope.flags())
}

/// Decrypt a DPAPI blob produced by [`protect`] with the same scope and key.
pub fn unprotect(ciphertext: &[u8], scope: DpapiScope, key: &str) -> Result<Secret<Vec<u8>>> {
    validate_key(key)?;
    Ok(Secret::new(dpapi::unprotect(ciphertext, &entropy_for(key), scope.flags())?))
}

// ---------------------------------------------------------------------------
// File-backed store
// ---------------------------------------------------------------------------

/// DPAPI-protected files under a directory.
///
/// Layout: `<dir>/<key>.dpapi`. Writes go to `<key>.dpapi.tmp` and are renamed
/// so a crash mid-write cannot leave a half-written identity behind.
#[derive(Debug, Clone)]
pub struct DpapiFileStore {
    dir: PathBuf,
    scope: DpapiScope,
}

impl DpapiFileStore {
    /// Store for host secrets: `%ProgramData%\DirectDesk`, machine scope.
    ///
    /// Machine scope is required because the host service starts at boot with
    /// no user profile loaded.
    pub fn host() -> Result<Self> {
        let base = std::env::var_os("ProgramData")
            .ok_or_else(|| Error::Crypto("ProgramData is not set".into()))?;
        Ok(Self::new(Path::new(&base).join(APP_DIR), DpapiScope::Machine))
    }

    /// Store for client secrets: `%APPDATA%\DirectDesk`, user scope.
    pub fn client() -> Result<Self> {
        let base = std::env::var_os("APPDATA")
            .ok_or_else(|| Error::Crypto("APPDATA is not set".into()))?;
        Ok(Self::new(Path::new(&base).join(APP_DIR), DpapiScope::User))
    }

    /// Store rooted at an explicit directory. Used by tests and by the service
    /// when a data directory is configured.
    pub fn new(dir: impl Into<PathBuf>, scope: DpapiScope) -> Self {
        Self { dir: dir.into(), scope }
    }

    /// The directory this store writes into.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The DPAPI scope in use.
    pub fn scope(&self) -> DpapiScope {
        self.scope
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(self.dir.join(format!("{key}.dpapi")))
    }

    fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        Ok(())
    }
}

impl SecretStore for DpapiFileStore {
    fn read(&self, key: &str) -> Result<Option<Secret<Vec<u8>>>> {
        let path = self.path(key)?;
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if blob.is_empty() {
            return Err(Error::Crypto(format!("{key}: stored blob is empty")));
        }
        Ok(Some(unprotect(&blob, self.scope, key)?))
    }

    fn write(&self, key: &str, plaintext: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        self.ensure_dir()?;
        let blob = protect(plaintext, self.scope, key)?;

        let tmp = path.with_extension("dpapi.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        // `rename` over an existing file is atomic enough on NTFS for our
        // purposes and avoids a window where the identity file is truncated.
        std::fs::rename(&tmp, &path).or_else(|_| {
            let _ = std::fs::remove_file(&path);
            std::fs::rename(&tmp, &path)
        })?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path(key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path(key)?.exists())
    }
}

// ---------------------------------------------------------------------------
// In-memory store (tests, and the "ephemeral identity" mode)
// ---------------------------------------------------------------------------

/// Process-local store with no persistence. Used by unit tests and by the
/// headless integration matrix, which must not touch the real machine.
///
/// The contents are plaintext, so `Debug` deliberately shows only key names and
/// blob sizes. A derived `Debug` here would dump private keys into any log line
/// that happened to format the store.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let items = self.items.lock();
        let mut d = f.debug_struct("MemoryStore");
        for (k, v) in items.iter() {
            d.field(k, &format_args!("[REDACTED; {} bytes]", v.len()));
        }
        d.finish()
    }
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored blobs.
    pub fn len(&self) -> usize {
        self.items.lock().len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.items.lock().is_empty()
    }
}

impl Drop for MemoryStore {
    fn drop(&mut self) {
        for (_, v) in self.items.get_mut().iter_mut() {
            v.zeroize();
        }
    }
}

impl SecretStore for MemoryStore {
    fn read(&self, key: &str) -> Result<Option<Secret<Vec<u8>>>> {
        validate_key(key)?;
        Ok(self.items.lock().get(key).map(|v| Secret::new(v.clone())))
    }

    fn write(&self, key: &str, plaintext: &[u8]) -> Result<()> {
        validate_key(key)?;
        if let Some(old) = self.items.lock().insert(key.to_string(), plaintext.to_vec()) {
            let mut old = old;
            old.zeroize();
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        if let Some(mut old) = self.items.lock().remove(key) {
            old.zeroize();
        }
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        Ok(self.items.lock().contains_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        assert!(validate_key("host_identity").is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("../evil").is_err());
        assert!(validate_key("Host").is_err());
        assert!(validate_key("a/b").is_err());
        assert!(validate_key(&"x".repeat(65)).is_err());
    }

    #[test]
    fn entropy_is_key_specific() {
        assert_ne!(entropy_for("a"), entropy_for("b"));
        assert_eq!(entropy_for("a"), entropy_for("a"));
    }

    #[test]
    fn memory_store_roundtrip() {
        let s = MemoryStore::new();
        assert!(s.is_empty());
        assert!(s.read("k").unwrap().is_none());
        assert!(!s.exists("k").unwrap());

        s.write("k", b"hello").unwrap();
        assert!(s.exists("k").unwrap());
        assert_eq!(s.read("k").unwrap().unwrap().expose().as_slice(), b"hello");
        assert_eq!(s.len(), 1);

        s.write("k", b"replaced").unwrap();
        assert_eq!(s.read("k").unwrap().unwrap().expose().as_slice(), b"replaced");
        assert_eq!(s.len(), 1);

        s.delete("k").unwrap();
        s.delete("k").unwrap(); // idempotent
        assert!(s.read("k").unwrap().is_none());
    }

    #[test]
    fn memory_store_debug_redacts_values() {
        let s = MemoryStore::new();
        s.write("host_identity", b"super-secret-key-material").unwrap();
        let d = format!("{s:?}");
        assert!(d.contains("host_identity"), "{d}");
        assert!(d.contains("REDACTED"), "{d}");
        assert!(!d.contains("super-secret"), "{d}");
    }

    #[test]
    fn memory_store_rejects_bad_keys() {
        let s = MemoryStore::new();
        assert!(s.write("BAD", b"x").is_err());
        assert!(s.read("../x").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_user_scope_roundtrip() {
        let secret = b"the quick brown fox jumps over the lazy dog";
        let blob = protect(secret, DpapiScope::User, "unit_test").unwrap();
        assert_ne!(blob.as_slice(), secret.as_slice());
        let back = unprotect(&blob, DpapiScope::User, "unit_test").unwrap();
        assert_eq!(back.expose().as_slice(), secret.as_slice());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_machine_scope_roundtrip() {
        // The host service uses machine scope so it can start at boot with no
        // user profile. Prove it works from an ordinary process too, otherwise
        // the host path would only fail at first run on a real machine.
        let secret = b"machine scoped host identity";
        let blob = protect(secret, DpapiScope::Machine, "unit_test").unwrap();
        let back = unprotect(&blob, DpapiScope::Machine, "unit_test").unwrap();
        assert_eq!(back.expose().as_slice(), secret.as_slice());

        // Documented and deliberate: `CRYPTPROTECT_LOCAL_MACHINE` is a
        // *protect*-time flag. Unprotect does not require it, and any process
        // on this machine can decrypt the blob. Machine scope binds the secret
        // to the box, NOT to a principal — the file ACL is what restricts which
        // local processes can even read the bytes, and hardening that ACL to
        // SYSTEM + Administrators is service-milestone work.
        assert!(
            unprotect(&blob, DpapiScope::User, "unit_test").is_ok(),
            "machine-scope blobs are decryptable by any local process"
        );
        // Secondary entropy still gates it: a wrong key name fails either way.
        assert!(unprotect(&blob, DpapiScope::Machine, "other_key").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_wrong_entropy_fails() {
        let blob = protect(b"secret", DpapiScope::User, "unit_test").unwrap();
        assert!(unprotect(&blob, DpapiScope::User, "other_key").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_rejects_empty() {
        assert!(protect(b"", DpapiScope::User, "unit_test").is_err());
        assert!(unprotect(b"", DpapiScope::User, "unit_test").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn file_store_roundtrip_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("directdesk-test-{}", std::process::id()));
        let store = DpapiFileStore::new(&dir, DpapiScope::User);

        assert!(store.read("host_identity").unwrap().is_none());
        store.write("host_identity", b"payload-1").unwrap();
        assert!(store.exists("host_identity").unwrap());
        assert_eq!(store.read("host_identity").unwrap().unwrap().expose().as_slice(), b"payload-1");

        store.write("host_identity", b"payload-2").unwrap();
        assert_eq!(store.read("host_identity").unwrap().unwrap().expose().as_slice(), b"payload-2");

        // The bytes on disk are not the plaintext.
        let raw = std::fs::read(dir.join("host_identity.dpapi")).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"payload-2"));

        store.delete("host_identity").unwrap();
        assert!(!store.exists("host_identity").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
