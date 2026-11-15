//! TEMPORARY stand-in for `directdesk_shared::crypto::storage::PlainFileStore`.
//!
//! TODO(W2 merge): delete this file and use
//! `directdesk_shared::crypto::storage::PlainFileStore::new(dir)` in
//! `app_main.rs` (search for `TODO(W2 merge)`). It exists only so this branch
//! compiles before W2's store lands; behaviour is meant to match W2's
//! description: plaintext files in an app-private directory.
//!
//! Plaintext is acceptable there because Android's per-app sandbox already
//! restricts `internal_data_path()` to this app's UID (mode 0700, not
//! readable by other apps or `adb` without root), and `allowBackup="false"`
//! keeps the files out of cloud/adb backups.

use std::io::Write;
use std::path::PathBuf;

use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::error::{Error, Result};
use directdesk_shared::secret::Secret;

/// Plaintext secret files: `<dir>/<key>.bin`, written atomically.
#[derive(Debug, Clone)]
pub struct PlainFileStore {
    dir: PathBuf,
}

impl PlainFileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Same key rules as the shared stores: 1-64 chars of `[a-z0-9_]`, so a
    /// key can never name a path outside `dir`.
    fn path(&self, key: &str) -> Result<PathBuf> {
        let valid = !key.is_empty()
            && key.len() <= 64
            && key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !valid {
            return Err(Error::Invalid(
                "storage key must be 1-64 of [a-z0-9_]".into(),
            ));
        }
        Ok(self.dir.join(format!("{key}.bin")))
    }
}

impl SecretStore for PlainFileStore {
    fn read(&self, key: &str) -> Result<Option<Secret<Vec<u8>>>> {
        match std::fs::read(self.path(key)?) {
            Ok(bytes) => Ok(Some(Secret::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, key: &str, plaintext: &[u8]) -> Result<()> {
        let path = self.path(key)?;
        std::fs::create_dir_all(&self.dir)?;
        let tmp = path.with_extension("bin.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(plaintext)?;
            f.sync_all()?;
        }
        // POSIX rename atomically replaces the target.
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path(key)?.exists())
    }
}
