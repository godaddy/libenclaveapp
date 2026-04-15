// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! **Test-only** key storage. Stores P-256 private keys as plaintext files.
//!
//! This module is intentionally insecure — it exists solely for testing
//! without hardware security modules or system keyrings. Production code
//! should use `enclaveapp-keyring` (or a hardware backend) instead.

#![cfg_attr(
    not(any(feature = "signing", feature = "encryption")),
    allow(dead_code)
)]

use elliptic_curve::sec1::ToEncodedPoint;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use p256::SecretKey;
use std::path::PathBuf;

/// Always available (no hardware required).
pub fn is_available() -> bool {
    true
}

/// Configuration for the test software backend.
#[derive(Debug)]
pub struct SoftwareConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
}

impl SoftwareConfig {
    #[allow(dead_code)]
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

/// Generate a new P-256 secret key, save it and its public key to disk.
/// Returns the 65-byte uncompressed SEC1 public key.
pub fn generate_and_save(
    config: &SoftwareConfig,
    label: &str,
    key_type: KeyType,
    policy: AccessPolicy,
) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;
    let _lock = metadata::DirLock::acquire(&dir)?;

    let key_path = dir.join(format!("{label}.key"));
    if key_path.exists() || metadata::key_files_exist(&dir, label)? {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    let secret_key = SecretKey::random(&mut elliptic_curve::rand_core::OsRng);
    let public_key = secret_key.public_key();
    let pub_bytes: Vec<u8> = public_key.to_encoded_point(false).as_bytes().to_vec();

    // Plaintext storage (test only)
    let secret_bytes = secret_key.to_bytes();
    metadata::atomic_write(&key_path, &secret_bytes)?;
    metadata::restrict_file_permissions(&key_path)?;

    metadata::save_pub_key(&dir, label, &pub_bytes)?;

    let meta = KeyMeta::new(label, key_type, policy);
    metadata::save_meta(&dir, label, &meta)?;

    Ok(pub_bytes)
}

/// Load a secret key from disk.
pub fn load_secret_key(config: &SoftwareConfig, label: &str) -> Result<SecretKey> {
    validate_label(label)?;
    let key_path = config.keys_dir().join(format!("{label}.key"));
    if !key_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let bytes = std::fs::read(&key_path)?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::KeyOperation {
        operation: "load_secret_key".into(),
        detail: e.to_string(),
    })
}

/// Load the cached public key, or derive it from the secret key.
pub fn load_public_key(config: &SoftwareConfig, label: &str) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    match metadata::load_pub_key(&dir, label) {
        Ok(pub_key) => Ok(pub_key),
        Err(_) => {
            let secret = load_secret_key(config, label)?;
            let pub_bytes: Vec<u8> = secret
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            Ok(pub_bytes)
        }
    }
}

/// List all key labels.
pub fn list_labels(config: &SoftwareConfig) -> Result<Vec<String>> {
    metadata::list_labels(&config.keys_dir())
}

/// Delete a key and all associated files.
pub fn delete_key(config: &SoftwareConfig, label: &str) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    let key_path = dir.join(format!("{label}.key"));
    let key_exists = dir.exists() && (key_path.exists() || metadata::key_files_exist(&dir, label)?);
    if !key_exists {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let _lock = metadata::DirLock::acquire(&dir)?;

    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
    }

    match metadata::delete_key_files(&dir, label) {
        Ok(()) | Err(Error::KeyNotFound { .. }) => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-test-sw-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_config(dir: &std::path::Path) -> SoftwareConfig {
        SoftwareConfig {
            app_name: "test-app".to_string(),
            keys_dir_override: Some(dir.to_path_buf()),
        }
    }

    #[test]
    fn is_available_returns_true() {
        assert!(is_available());
    }

    #[test]
    fn generate_creates_key_pub_meta_files() {
        let dir = test_dir();
        let config = test_config(&dir);
        let pub_key =
            generate_and_save(&config, "test-key", KeyType::Signing, AccessPolicy::None).unwrap();

        assert_eq!(pub_key.len(), 65);
        assert_eq!(pub_key[0], 0x04);
        assert!(dir.join("test-key.key").exists());
        assert!(dir.join("test-key.pub").exists());
        assert!(dir.join("test-key.meta").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_secret_key_roundtrips() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "rt", KeyType::Signing, AccessPolicy::None).unwrap();

        let secret = load_secret_key(&config, "rt").unwrap();
        let pub_bytes: Vec<u8> = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_removes_all_files() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "del", KeyType::Signing, AccessPolicy::None).unwrap();

        delete_key(&config, "del").unwrap();
        assert!(!dir.join("del.key").exists());
        assert!(!dir.join("del.pub").exists());
        assert!(!dir.join("del.meta").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_sorted() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "charlie", KeyType::Signing, AccessPolicy::None).unwrap();
        generate_and_save(&config, "alpha", KeyType::Encryption, AccessPolicy::None).unwrap();
        generate_and_save(&config, "bravo", KeyType::Signing, AccessPolicy::None).unwrap();

        let labels = list_labels(&config).unwrap();
        assert_eq!(labels, vec!["alpha", "bravo", "charlie"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
