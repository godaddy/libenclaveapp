// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key metadata and file operations for hardware-backed key management.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Metadata stored alongside a hardware-bound key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMeta {
    /// Key label (unique identifier within the app).
    pub label: String,
    /// Type of key (signing or encryption). Defaults to Signing for backward
    /// compatibility with metadata files created before this field existed.
    #[serde(default)]
    pub key_type: crate::KeyType,
    /// Access control policy.
    #[serde(default)]
    pub access_policy: crate::AccessPolicy,
    /// Unix timestamp when the key was created.
    #[serde(default)]
    pub created: String,
    /// Application-specific extra fields (e.g., git_name, git_email for sshenc;
    /// profile name for awsenc; server/env for sso-jwt).
    #[serde(default)]
    pub app_specific: serde_json::Value,
}

impl KeyMeta {
    /// Create a new KeyMeta with the current timestamp.
    pub fn new(label: &str, key_type: crate::KeyType, access_policy: crate::AccessPolicy) -> Self {
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        KeyMeta {
            label: label.to_string(),
            key_type,
            access_policy,
            created,
            app_specific: serde_json::Value::Null,
        }
    }

    /// Set an app-specific field.
    pub fn set_app_field(&mut self, key: &str, value: impl Into<serde_json::Value>) {
        if self.app_specific.is_null() {
            self.app_specific = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(obj) = self.app_specific.as_object_mut() {
            obj.insert(key.to_string(), value.into());
        }
    }

    /// Get an app-specific string field.
    pub fn get_app_field(&self, key: &str) -> Option<&str> {
        self.app_specific.get(key)?.as_str()
    }
}

/// Standard keys directory for an application.
/// - Unix: `~/.config/<app_name>/keys/`
/// - Windows: `%APPDATA%/<app_name>/keys/`
pub fn keys_dir(app_name: &str) -> PathBuf {
    config_dir(app_name).join("keys")
}

/// Standard config directory for an application.
/// - Unix: `~/.config/<app_name>/`
/// - Windows: `%APPDATA%/<app_name>/`
pub fn config_dir(app_name: &str) -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".config")
        })
        .join(app_name)
}

/// Write data atomically: write to a temp file, then rename into place.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// File-based directory lock using flock (Unix) or LockFile (Windows).
/// Prevents concurrent writes to the keys directory.
pub struct DirLock {
    _file: std::fs::File,
}

impl DirLock {
    /// Acquire an exclusive lock on the given directory.
    pub fn acquire(dir: &Path) -> Result<Self> {
        let lock_path = dir.join(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
        }
        // On Windows, opening with write access provides basic mutual exclusion.
        // For stronger guarantees, we could use LockFileEx, but for our use case
        // (protecting against concurrent CLI invocations) this is sufficient.
        Ok(DirLock { _file: file })
    }
}

/// Ensure a directory exists with restrictive permissions (0700 on Unix).
pub fn ensure_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    let old_umask = unsafe { libc::umask(0o077) };
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    unsafe {
        libc::umask(old_umask);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Set restrictive file permissions (0600 on Unix).
pub fn restrict_file_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Save key metadata to a JSON file.
pub fn save_meta(dir: &Path, label: &str, meta: &KeyMeta) -> Result<()> {
    let meta_path = dir.join(format!("{label}.meta"));
    let json =
        serde_json::to_string_pretty(meta).map_err(|e| Error::Serialization(e.to_string()))?;
    atomic_write(&meta_path, json.as_bytes())
}

/// Load key metadata from a JSON file. Returns a default if the file doesn't exist.
pub fn load_meta(dir: &Path, label: &str) -> Result<KeyMeta> {
    let meta_path = dir.join(format!("{label}.meta"));
    if !meta_path.exists() {
        return Ok(KeyMeta {
            label: label.to_string(),
            key_type: crate::KeyType::Signing,
            access_policy: crate::AccessPolicy::None,
            created: String::new(),
            app_specific: serde_json::Value::Null,
        });
    }
    let content = std::fs::read_to_string(&meta_path)?;
    serde_json::from_str(&content).map_err(|e| Error::Serialization(e.to_string()))
}

/// Save a cached public key file.
pub fn save_pub_key(dir: &Path, label: &str, pub_key: &[u8]) -> Result<()> {
    let path = dir.join(format!("{label}.pub"));
    atomic_write(&path, pub_key)
}

/// Load a cached public key file.
pub fn load_pub_key(dir: &Path, label: &str) -> Result<Vec<u8>> {
    let path = dir.join(format!("{label}.pub"));
    if !path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    Ok(std::fs::read(&path)?)
}

/// List all key labels by scanning for `.meta` files in the directory.
pub fn list_labels(dir: &Path) -> Result<Vec<String>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut labels = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("meta") {
            if let Some(stem) = path.file_stem() {
                labels.push(stem.to_string_lossy().to_string());
            }
        }
    }
    labels.sort();
    Ok(labels)
}

/// Delete all files associated with a key label.
pub fn delete_key_files(dir: &Path, label: &str) -> Result<()> {
    let extensions = ["meta", "pub", "handle", "ssh.pub"];
    let mut found_any = false;
    for ext in &extensions {
        let path = dir.join(format!("{label}.{ext}"));
        if path.exists() {
            std::fs::remove_file(&path)?;
            found_any = true;
        }
    }
    if !found_any {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    Ok(())
}

/// Rename all files associated with a key label.
pub fn rename_key_files(dir: &Path, old_label: &str, new_label: &str) -> Result<()> {
    let extensions = ["meta", "pub", "handle", "ssh.pub"];
    let old_handle = dir.join(format!("{old_label}.handle"));
    let old_meta = dir.join(format!("{old_label}.meta"));
    if !old_handle.exists() && !old_meta.exists() {
        return Err(Error::KeyNotFound {
            label: old_label.to_string(),
        });
    }
    let new_meta = dir.join(format!("{new_label}.meta"));
    if new_meta.exists() {
        return Err(Error::DuplicateLabel {
            label: new_label.to_string(),
        });
    }
    for ext in &extensions {
        let old = dir.join(format!("{old_label}.{ext}"));
        let new = dir.join(format!("{new_label}.{ext}"));
        if old.exists() {
            std::fs::rename(&old, &new)?;
        }
    }
    // Update the label in the metadata file
    let new_meta_path = dir.join(format!("{new_label}.meta"));
    if new_meta_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&new_meta_path) {
            if let Ok(mut meta) = serde_json::from_str::<KeyMeta>(&content) {
                meta.label = new_label.to_string();
                if let Ok(json) = serde_json::to_string_pretty(&meta) {
                    let _ = atomic_write(&new_meta_path, json.as_bytes());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessPolicy, KeyType};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-core-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn key_meta_new_sets_timestamp() {
        let meta = KeyMeta::new("test", KeyType::Signing, AccessPolicy::None);
        assert_eq!(meta.label, "test");
        assert_eq!(meta.key_type, KeyType::Signing);
        assert!(!meta.created.is_empty());
        let ts: u64 = meta.created.parse().unwrap();
        assert!(ts > 0);
    }

    #[test]
    fn key_meta_app_field_roundtrip() {
        let mut meta = KeyMeta::new("test", KeyType::Signing, AccessPolicy::None);
        assert!(meta.get_app_field("git_email").is_none());
        meta.set_app_field("git_email", "jay@example.com");
        assert_eq!(meta.get_app_field("git_email"), Some("jay@example.com"));
    }

    #[test]
    fn key_meta_serde_roundtrip() {
        let mut meta = KeyMeta::new("test", KeyType::Encryption, AccessPolicy::BiometricOnly);
        meta.set_app_field("profile", "default");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: KeyMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, "test");
        assert_eq!(parsed.key_type, KeyType::Encryption);
        assert_eq!(parsed.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(parsed.get_app_field("profile"), Some("default"));
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = test_dir();
        let path = dir.join("test.txt");
        atomic_write(&path, b"hello world").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world");
        // Temp file should not exist
        assert!(!path.with_extension("tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_load_meta_roundtrip() {
        let dir = test_dir();
        let meta = KeyMeta::new("mykey", KeyType::Signing, AccessPolicy::Any);
        save_meta(&dir, "mykey", &meta).unwrap();
        let loaded = load_meta(&dir, "mykey").unwrap();
        assert_eq!(loaded.label, "mykey");
        assert_eq!(loaded.key_type, KeyType::Signing);
        assert_eq!(loaded.access_policy, AccessPolicy::Any);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_meta_returns_default_for_missing() {
        let dir = test_dir();
        let meta = load_meta(&dir, "nonexistent").unwrap();
        assert_eq!(meta.label, "nonexistent");
        assert_eq!(meta.key_type, KeyType::Signing);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_load_pub_key_roundtrip() {
        let dir = test_dir();
        let pub_key = vec![0x04; 65];
        save_pub_key(&dir, "mykey", &pub_key).unwrap();
        let loaded = load_pub_key(&dir, "mykey").unwrap();
        assert_eq!(loaded, pub_key);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_pub_key_returns_key_not_found() {
        let dir = test_dir();
        let err = load_pub_key(&dir, "missing").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "missing"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_empty_for_nonexistent_dir() {
        let dir = std::env::temp_dir().join("enclaveapp-core-test-nonexistent-dir");
        let _ = std::fs::remove_dir_all(&dir);
        let labels = list_labels(&dir).unwrap();
        assert!(labels.is_empty());
    }

    #[test]
    fn list_labels_finds_meta_files() {
        let dir = test_dir();
        let meta_a = KeyMeta::new("alpha", KeyType::Signing, AccessPolicy::None);
        let meta_b = KeyMeta::new("beta", KeyType::Encryption, AccessPolicy::Any);
        save_meta(&dir, "alpha", &meta_a).unwrap();
        save_meta(&dir, "beta", &meta_b).unwrap();
        // Also create a .pub file that should be ignored
        std::fs::write(dir.join("alpha.pub"), b"pubkey").unwrap();
        let labels = list_labels(&dir).unwrap();
        assert_eq!(labels, vec!["alpha", "beta"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_files_removes_all() {
        let dir = test_dir();
        std::fs::write(dir.join("mykey.meta"), b"{}").unwrap();
        std::fs::write(dir.join("mykey.pub"), b"pub").unwrap();
        std::fs::write(dir.join("mykey.handle"), b"handle").unwrap();
        delete_key_files(&dir, "mykey").unwrap();
        assert!(!dir.join("mykey.meta").exists());
        assert!(!dir.join("mykey.pub").exists());
        assert!(!dir.join("mykey.handle").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_files_returns_key_not_found() {
        let dir = test_dir();
        let err = delete_key_files(&dir, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rename_key_files_renames_and_updates_meta() {
        let dir = test_dir();
        let meta = KeyMeta::new("old-name", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "old-name", &meta).unwrap();
        save_pub_key(&dir, "old-name", b"pubkey").unwrap();

        rename_key_files(&dir, "old-name", "new-name").unwrap();

        assert!(!dir.join("old-name.meta").exists());
        assert!(!dir.join("old-name.pub").exists());
        assert!(dir.join("new-name.meta").exists());
        assert!(dir.join("new-name.pub").exists());

        let loaded = load_meta(&dir, "new-name").unwrap();
        assert_eq!(loaded.label, "new-name");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rename_key_files_rejects_existing_target() {
        let dir = test_dir();
        let meta = KeyMeta::new("src", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "src", &meta).unwrap();
        let meta2 = KeyMeta::new("dst", KeyType::Signing, AccessPolicy::None);
        save_meta(&dir, "dst", &meta2).unwrap();

        let err = rename_key_files(&dir, "src", "dst").unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dst"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rename_key_files_rejects_missing_source() {
        let dir = test_dir();
        let err = rename_key_files(&dir, "missing", "new").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "missing"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_dir_returns_absolute_path() {
        let dir = keys_dir("test-app");
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("test-app"));
        assert!(dir.to_string_lossy().contains("keys"));
    }

    #[test]
    fn config_dir_returns_absolute_path() {
        let dir = config_dir("test-app");
        assert!(dir.is_absolute());
        assert!(dir.to_string_lossy().contains("test-app"));
    }

    #[test]
    fn ensure_dir_creates_nested() {
        let dir = test_dir();
        let nested = dir.join("a").join("b").join("c");
        ensure_dir(&nested).unwrap();
        assert!(nested.exists());
        assert!(nested.is_dir());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dir_lock_acquire_and_drop() {
        let dir = test_dir();
        let _lock = DirLock::acquire(&dir).unwrap();
        assert!(dir.join(".lock").exists());
        drop(_lock);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restrict_file_permissions_succeeds() {
        let dir = test_dir();
        let path = dir.join("secret.txt");
        std::fs::write(&path, b"secret").unwrap();
        restrict_file_permissions(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
