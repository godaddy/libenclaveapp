#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(any(unix, test))]
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::{Builder, TempDir};

use crate::error::Result;

#[derive(Debug)]
pub struct TempConfig {
    _dir: TempDir,
    path: PathBuf,
}

impl TempConfig {
    pub fn write(prefix: &str, file_name: &str, contents: &[u8]) -> Result<Self> {
        let dir = Builder::new().prefix(prefix).tempdir()?;
        set_dir_permissions(dir.path())?;

        let path = dir.path().join(file_name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        set_file_permissions(&path)?;
        file.write_all(contents)?;
        file.flush()?;

        Ok(Self { _dir: dir, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Anonymous in-memory config file (Linux only).
///
/// Uses `memfd_create` to create a file that has no filesystem path.
/// The target app receives `/proc/self/fd/{fd}` as the config path.
/// This eliminates the same-user temp file read attack surface entirely.
///
/// The file descriptor is sealed to prevent modification after creation.
/// When `MemfdConfig` is dropped the fd is closed and the memory is freed.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct MemfdConfig {
    _file: File,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl MemfdConfig {
    /// Path to pass to the target process (e.g., `/proc/self/fd/5`).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Create a temp config using an anonymous in-memory file (Linux only).
///
/// Uses `memfd_create` to create a file that has no filesystem path.
/// The target app receives `/proc/self/fd/{fd}` as the config path.
/// This eliminates the same-user temp file read attack surface entirely.
///
/// The fd is created **without** `MFD_CLOEXEC` so that it is inherited by
/// child processes spawned via `Command::spawn`.
#[cfg(target_os = "linux")]
pub fn create_memfd_config(
    prefix: &str,
    filename: &str,
    contents: &[u8],
) -> std::io::Result<MemfdConfig> {
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let name = CString::new(format!("{prefix}-{filename}"))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // No MFD_CLOEXEC: the fd must be inherited by the child process.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Safety: we just created this fd above and it is valid.
    #[allow(unsafe_code)]
    let mut file = unsafe { File::from_raw_fd(fd) };
    Write::write_all(&mut file, contents)?;

    // Seal the file to prevent modification.
    #[allow(unsafe_code)]
    unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
        );
    }

    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));

    Ok(MemfdConfig { _file: file, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_temp_config() {
        let temp = TempConfig::write("npmenc-test-", "npmrc", b"token=${NPM_TOKEN}\n")
            .expect("temp config");
        let contents = fs::read_to_string(temp.path()).expect("read back");
        assert_eq!(contents, "token=${NPM_TOKEN}\n");
    }
}
