#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fs::{self, OpenOptions};
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
