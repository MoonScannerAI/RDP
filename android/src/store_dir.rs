//! Where the secret store (client identity, trusted hosts) lives, and the
//! one-time move out of its first location.
//!
//! The store is in `<app data>/no_backup`, the directory
//! `Context.getNoBackupFilesDir()` names: Android excludes it from cloud
//! backup **and** from device-to-device transfer. `android:allowBackup="false"`
//! alone does not stop the latter for apps targeting API 31+, so a store under
//! `files/` would be copied to a new phone, cloning this device's identity.
//!
//! Plain `std::fs`, no Android types, so the rules are unit-tested off-device.

use std::io;
use std::path::{Path, PathBuf};

/// The store's directory: `no_backup`, the sibling of the internal data
/// path (`<app data>/files`). `None` if that path has no parent.
pub fn store_dir(internal_data: &Path) -> Option<PathBuf> {
    Some(internal_data.parent()?.join("no_backup"))
}

/// Where the store used to live: `<app data>/files/keys`.
pub fn legacy_store_dir(internal_data: &Path) -> PathBuf {
    internal_data.join("keys")
}

/// What [`migrate`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// No key files at the old location.
    NothingToMove,
    /// The new location already has key files, so the old ones (this many)
    /// were left where they are rather than mixed in or overwritten.
    LeftBehind(usize),
    /// This many key files were moved.
    Moved(usize),
}

/// Move the store's key files (`<key>.bin`, `PlainFileStore`'s layout) from
/// `old` to `new` — only when `old` has some and `new` has none. Renames
/// within one filesystem, so contents are never read or copied. An empty
/// `old` (the previous version created it on every launch) is removed; stray
/// `*.tmp` files from an interrupted write are not keys and keep it.
pub fn migrate(old: &Path, new: &Path) -> io::Result<Migration> {
    let old_keys = key_files(old)?;
    if old_keys.is_empty() {
        // Fails (harmlessly) if it is missing or not empty.
        let _ = std::fs::remove_dir(old);
        return Ok(Migration::NothingToMove);
    }
    if !key_files(new)?.is_empty() {
        return Ok(Migration::LeftBehind(old_keys.len()));
    }
    std::fs::create_dir_all(new)?;
    for path in &old_keys {
        if let Some(name) = path.file_name() {
            std::fs::rename(path, new.join(name))?;
        }
    }
    // Fails (harmlessly) if anything else is still in there.
    let _ = std::fs::remove_dir(old);
    Ok(Migration::Moved(old_keys.len()))
}

/// The `*.bin` regular files directly in `dir`; empty if `dir` is missing.
fn key_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut keys = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "bin") && entry.file_type()?.is_file() {
            keys.push(path);
        }
    }
    keys.sort();
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh `<tmp>/files` + its parent, mimicking `/data/user/0/<pkg>`.
    fn app_data(tag: &str) -> (PathBuf, PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dd-android-store-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let files = root.join("files");
        std::fs::create_dir_all(&files).unwrap();
        (root, files)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn store_dir_is_no_backup_next_to_files() {
        let files = Path::new("/data/user/0/dev.directdesk.client/files");
        assert_eq!(
            store_dir(files).unwrap(),
            Path::new("/data/user/0/dev.directdesk.client/no_backup")
        );
        assert_eq!(
            legacy_store_dir(files),
            Path::new("/data/user/0/dev.directdesk.client/files/keys")
        );
        assert_eq!(store_dir(Path::new("/")), None);
    }

    #[test]
    fn moves_key_files_once_and_removes_the_empty_old_dir() {
        let (root, files) = app_data("move");
        let (old, new) = (legacy_store_dir(&files), store_dir(&files).unwrap());
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("identity.bin"), b"id").unwrap();
        std::fs::write(old.join("trusted.bin"), b"tr").unwrap();
        // client.json lives in files/ and is not part of the store.
        std::fs::write(files.join("client.json"), b"{}").unwrap();

        assert_eq!(migrate(&old, &new).unwrap(), Migration::Moved(2));
        assert_eq!(names(&new), ["identity.bin", "trusted.bin"]);
        assert_eq!(std::fs::read(new.join("identity.bin")).unwrap(), b"id");
        assert!(!old.exists(), "empty old dir removed");
        assert!(files.join("client.json").exists());

        // Second launch: nothing left to do.
        assert_eq!(migrate(&old, &new).unwrap(), Migration::NothingToMove);
        assert_eq!(names(&new), ["identity.bin", "trusted.bin"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn never_overwrites_or_mixes_into_an_existing_store() {
        let (root, files) = app_data("keep");
        let (old, new) = (legacy_store_dir(&files), store_dir(&files).unwrap());
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(old.join("identity.bin"), b"old").unwrap();
        std::fs::write(old.join("trusted.bin"), b"old").unwrap();
        std::fs::write(new.join("identity.bin"), b"new").unwrap();

        assert_eq!(migrate(&old, &new).unwrap(), Migration::LeftBehind(2));
        assert_eq!(std::fs::read(new.join("identity.bin")).unwrap(), b"new");
        assert_eq!(names(&new), ["identity.bin"]);
        assert_eq!(names(&old), ["identity.bin", "trusted.bin"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_bin_files_count_and_move() {
        let (root, files) = app_data("tmp");
        let (old, new) = (legacy_store_dir(&files), store_dir(&files).unwrap());
        std::fs::create_dir_all(&old).unwrap();
        // Leftovers of an interrupted write are not keys.
        std::fs::write(old.join("identity.bin.12.0.tmp"), b"partial").unwrap();
        assert_eq!(migrate(&old, &new).unwrap(), Migration::NothingToMove);
        assert!(!new.exists(), "nothing created when nothing moves");

        std::fs::write(old.join("identity.bin"), b"id").unwrap();
        // A stray temp file in the new dir does not make it "non-empty".
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("x.bin.1.1.tmp"), b"partial").unwrap();
        assert_eq!(migrate(&old, &new).unwrap(), Migration::Moved(1));
        assert_eq!(names(&new), ["identity.bin", "x.bin.1.1.tmp"]);
        // The old dir still holds its temp file, so it stays.
        assert_eq!(names(&old), ["identity.bin.12.0.tmp"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_old_dir_is_nothing_to_move() {
        let (root, files) = app_data("none");
        let new = store_dir(&files).unwrap();
        assert_eq!(
            migrate(&legacy_store_dir(&files), &new).unwrap(),
            Migration::NothingToMove
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_old_dir_is_removed() {
        let (root, files) = app_data("empty");
        let old = legacy_store_dir(&files);
        std::fs::create_dir_all(&old).unwrap();
        let new = store_dir(&files).unwrap();
        assert_eq!(migrate(&old, &new).unwrap(), Migration::NothingToMove);
        assert!(!old.exists());
        assert!(files.exists(), "only the empty keys dir goes");
        std::fs::remove_dir_all(root).unwrap();
    }
}
