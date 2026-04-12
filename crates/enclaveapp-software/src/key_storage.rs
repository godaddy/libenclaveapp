// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared key generation and file storage for the software backend.

use elliptic_curve::sec1::ToEncodedPoint;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use p256::SecretKey;
use std::path::PathBuf;

/// Software keys are always available.
pub fn is_available() -> bool {
    true
}

/// Configuration for the software backend.
#[derive(Debug)]
pub struct SoftwareConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
}

impl SoftwareConfig {
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
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;
    let _lock = metadata::DirLock::acquire(&dir)?;

    // Check for duplicates
    let key_path = dir.join(format!("{label}.key"));
    if key_path.exists() {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    // Generate key
    let secret_key = SecretKey::random(&mut rand::thread_rng());
    let public_key = secret_key.public_key();

    // SEC1 uncompressed public key (65 bytes: 0x04 || X || Y)
    let pub_bytes: Vec<u8> = public_key.to_encoded_point(false).as_bytes().to_vec();

    // Save private key as raw 32-byte scalar
    let secret_bytes = secret_key.to_bytes();
    metadata::atomic_write(&key_path, &secret_bytes)?;
    metadata::restrict_file_permissions(&key_path)?;

    // Save cached public key
    metadata::save_pub_key(&dir, label, &pub_bytes)?;

    // Save metadata
    let meta = KeyMeta::new(label, key_type, policy);
    metadata::save_meta(&dir, label, &meta)?;

    Ok(pub_bytes)
}

/// Load a secret key from disk.
pub fn load_secret_key(config: &SoftwareConfig, label: &str) -> Result<SecretKey> {
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
    let dir = config.keys_dir();
    let _lock = metadata::DirLock::acquire(&dir)?;

    // Remove the private key file
    let key_path = dir.join(format!("{label}.key"));
    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
    }

    metadata::delete_key_files(&dir, label)
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
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-ks-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_config(dir: &std::path::Path) -> SoftwareConfig {
        SoftwareConfig::with_keys_dir("test-app", dir.to_path_buf())
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
    fn generate_rejects_duplicate_labels() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "dup", KeyType::Signing, AccessPolicy::None).unwrap();
        let err =
            generate_and_save(&config, "dup", KeyType::Signing, AccessPolicy::None).unwrap_err();
        match err {
            Error::DuplicateLabel { label } => assert_eq!(label, "dup"),
            other => panic!("expected DuplicateLabel, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_secret_key_roundtrips() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "roundtrip", KeyType::Signing, AccessPolicy::None).unwrap();

        let secret = load_secret_key(&config, "roundtrip").unwrap();
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
    fn load_public_key_returns_65_bytes_starting_with_04() {
        let dir = test_dir();
        let config = test_config(&dir);
        let generated =
            generate_and_save(&config, "pub-test", KeyType::Signing, AccessPolicy::None).unwrap();

        let loaded = load_public_key(&config, "pub-test").unwrap();
        assert_eq!(loaded.len(), 65);
        assert_eq!(loaded[0], 0x04);
        assert_eq!(loaded, generated);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_public_key_falls_back_to_secret_key() {
        let dir = test_dir();
        let config = test_config(&dir);
        let generated =
            generate_and_save(&config, "fallback", KeyType::Signing, AccessPolicy::None).unwrap();

        // Remove the .pub file to force fallback
        std::fs::remove_file(dir.join("fallback.pub")).unwrap();

        let loaded = load_public_key(&config, "fallback").unwrap();
        assert_eq!(loaded, generated);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_removes_all_files() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "del-test", KeyType::Signing, AccessPolicy::None).unwrap();

        delete_key(&config, "del-test").unwrap();
        assert!(!dir.join("del-test.key").exists());
        assert!(!dir.join("del-test.pub").exists());
        assert!(!dir.join("del-test.meta").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_labels_returns_sorted_labels() {
        let dir = test_dir();
        let config = test_config(&dir);
        generate_and_save(&config, "charlie", KeyType::Signing, AccessPolicy::None).unwrap();
        generate_and_save(&config, "alpha", KeyType::Encryption, AccessPolicy::None).unwrap();
        generate_and_save(&config, "bravo", KeyType::Signing, AccessPolicy::None).unwrap();

        let labels = list_labels(&config).unwrap();
        assert_eq!(labels, vec!["alpha", "bravo", "charlie"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_secret_key_fails_for_nonexistent() {
        let dir = test_dir();
        let config = test_config(&dir);
        let err = load_secret_key(&config, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
