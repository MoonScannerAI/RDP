//! Filesystem locations the service cares about.
//!
//! Everything is derived from the location of the service executable itself —
//! the service never takes a path from a pipe client, from the registry, or
//! from an environment variable that a non-admin can influence.

use std::path::{Path, PathBuf};

/// Name of the host agent binary that the supervisor launches.
pub const HOST_EXE_NAME: &str = "DirectDeskHost.exe";

/// Directory containing the running service executable
/// (in a real install: `C:\Program Files\DirectDesk`).
pub fn service_exe_dir() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("service exe has no parent directory"))?
        .to_path_buf())
}

/// Absolute path to the host agent, resolved as a sibling of the service exe.
pub fn host_exe_path() -> anyhow::Result<PathBuf> {
    Ok(service_exe_dir()?.join(HOST_EXE_NAME))
}

/// `%ProgramData%\DirectDesk` — machine-wide, non-secret service state.
pub fn program_data_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("DirectDesk")
}

/// `%ProgramData%\DirectDesk\service.json`.
pub fn config_path() -> PathBuf {
    program_data_dir().join("service.json")
}

/// Quote a path for use in a command line (paths may contain spaces).
pub fn quote(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_exe_is_sibling_of_service_exe() {
        let dir = service_exe_dir().unwrap();
        let host = host_exe_path().unwrap();
        assert_eq!(host.parent().unwrap(), dir.as_path());
        assert_eq!(host.file_name().unwrap(), HOST_EXE_NAME);
    }

    #[test]
    fn program_data_dir_is_absolute_and_named() {
        let dir = program_data_dir();
        assert!(dir.is_absolute(), "{dir:?} should be absolute");
        assert_eq!(dir.file_name().unwrap(), "DirectDesk");
        assert_eq!(config_path().file_name().unwrap(), "service.json");
    }

    #[test]
    fn quote_wraps_spaces() {
        let q = quote(Path::new(r"C:\Program Files\DirectDesk\DirectDeskHost.exe"));
        assert!(q.starts_with('"') && q.ends_with('"'));
        assert!(q.contains("Program Files"));
    }
}
