// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shared key generation and file storage for the software backend.
//!
//! When a system keyring is available, private keys are encrypted at rest
//! using AES-256-GCM with a random key encryption key (KEK) stored in the
//! keyring. When the keyring is unavailable, keys are stored unencrypted
//! with a one-time warning to stderr.

use elliptic_curve::sec1::ToEncodedPoint;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::{AccessPolicy, Error, KeyType, Result};
use p256::SecretKey;
use std::path::PathBuf;
use std::sync::Once;

/// Version byte for encrypted key files.
const ENCRYPTED_KEY_VERSION: u8 = 0x01;

/// AES-256-GCM nonce size in bytes.
const GCM_NONCE_SIZE: usize = 12;

/// AES-256-GCM authentication tag size in bytes.
const GCM_TAG_SIZE: usize = 16;

/// Raw P-256 secret key size in bytes.
const RAW_KEY_SIZE: usize = 32;

/// KEK size in bytes (AES-256).
const KEK_SIZE: usize = 32;

/// Minimum encrypted key file size: version(1) + nonce(12) + encrypted_key(32) + tag(16).
const MIN_ENCRYPTED_FILE_SIZE: usize = 1 + GCM_NONCE_SIZE + RAW_KEY_SIZE + GCM_TAG_SIZE;

static UNENCRYPTED_WARNING: Once = Once::new();

/// Software keys are always available.
pub fn is_available() -> bool {
    true
}

/// Configuration for the software backend.
#[derive(Debug)]
pub struct SoftwareConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
    /// Whether to attempt keyring-based encryption. Defaults to `true`.
    /// Set to `false` for testing or environments where the keyring
    /// is known to be unavailable.
    pub use_keyring: bool,
}

impl SoftwareConfig {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
            use_keyring: true,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
            use_keyring: true,
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

/// Probe whether the system keyring is functional.
fn keyring_available(app_name: &str) -> bool {
    let entry = match keyring::Entry::new(app_name, "__keyring_probe__") {
        Ok(e) => e,
        Err(_) => return false,
    };
    match entry.set_secret(b"probe") {
        Ok(()) => {
            drop(entry.delete_credential());
            true
        }
        Err(_) => false,
    }
}

/// Save the private key bytes to a `.key` file, encrypting with a keyring-stored
/// KEK when possible. Falls back to unencrypted storage with a stderr warning.
fn save_private_key(
    config: &SoftwareConfig,
    key_path: &std::path::Path,
    secret_bytes: &[u8],
    label: &str,
) -> Result<()> {
    if config.use_keyring && keyring_available(&config.app_name) {
        save_encrypted(&config.app_name, key_path, secret_bytes, label)
    } else {
        if config.use_keyring {
            warn_unencrypted();
        }
        metadata::atomic_write(key_path, secret_bytes)?;
        metadata::restrict_file_permissions(key_path)?;
        Ok(())
    }
}

/// Encrypt the secret key with a random KEK, store the KEK in the keyring,
/// and write the encrypted key to disk.
fn save_encrypted(
    app_name: &str,
    key_path: &std::path::Path,
    secret_bytes: &[u8],
    label: &str,
) -> Result<()> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    // Generate random KEK
    let mut kek = [0_u8; KEK_SIZE];
    rand::thread_rng().fill_bytes(&mut kek);

    // Store KEK in keyring
    let entry = keyring::Entry::new(app_name, label).map_err(|e| Error::KeyOperation {
        operation: "keyring_entry".into(),
        detail: e.to_string(),
    })?;
    entry.set_secret(&kek).map_err(|e| Error::KeyOperation {
        operation: "keyring_store".into(),
        detail: e.to_string(),
    })?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| Error::KeyOperation {
        operation: "aes_init".into(),
        detail: e.to_string(),
    })?;

    let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, secret_bytes).map_err(|e| {
        // Clean up keyring entry on failure
        drop(entry.delete_credential());
        Error::KeyOperation {
            operation: "encrypt_key".into(),
            detail: e.to_string(),
        }
    })?;

    // File format: [version(1)] [nonce(12)] [encrypted_key + tag]
    let mut file_data = Vec::with_capacity(1 + GCM_NONCE_SIZE + encrypted.len());
    file_data.push(ENCRYPTED_KEY_VERSION);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&encrypted);

    metadata::atomic_write(key_path, &file_data)?;
    metadata::restrict_file_permissions(key_path)?;
    Ok(())
}

/// Load the private key bytes from a `.key` file, decrypting if necessary.
fn load_private_key_bytes(
    app_name: &str,
    key_path: &std::path::Path,
    label: &str,
) -> Result<Vec<u8>> {
    let bytes = std::fs::read(key_path)?;

    // Backward compatibility: raw 32-byte key (unencrypted)
    if bytes.len() == RAW_KEY_SIZE {
        return Ok(bytes);
    }

    // Encrypted format: version(1) + nonce(12) + encrypted_key(32) + tag(16) = 61
    if bytes.len() >= MIN_ENCRYPTED_FILE_SIZE && bytes[0] == ENCRYPTED_KEY_VERSION {
        return decrypt_private_key(app_name, &bytes, label);
    }

    // Unknown format
    Err(Error::KeyOperation {
        operation: "load_private_key".into(),
        detail: format!(
            "unrecognized key file format (size={}, version=0x{:02x})",
            bytes.len(),
            bytes.first().copied().unwrap_or(0)
        ),
    })
}

/// Decrypt an encrypted key file using the KEK from the keyring.
fn decrypt_private_key(app_name: &str, file_data: &[u8], label: &str) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let nonce_bytes = &file_data[1..1 + GCM_NONCE_SIZE];
    let encrypted = &file_data[1 + GCM_NONCE_SIZE..];

    // Retrieve KEK from keyring
    let entry = keyring::Entry::new(app_name, label).map_err(|e| Error::KeyOperation {
        operation: "keyring_entry".into(),
        detail: e.to_string(),
    })?;
    let kek = entry.get_secret().map_err(|e| Error::KeyOperation {
        operation: "keyring_retrieve".into(),
        detail: format!("cannot retrieve key encryption key from keyring: {e}"),
    })?;

    if kek.len() != KEK_SIZE {
        return Err(Error::KeyOperation {
            operation: "keyring_retrieve".into(),
            detail: format!(
                "invalid KEK size from keyring: expected {KEK_SIZE}, got {}",
                kek.len()
            ),
        });
    }

    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| Error::KeyOperation {
        operation: "aes_init".into(),
        detail: e.to_string(),
    })?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| Error::KeyOperation {
            operation: "decrypt_key".into(),
            detail: format!("failed to decrypt private key: {e}"),
        })
}

/// Delete the keyring entry for a key, ignoring errors (the entry may not exist
/// if the key was stored unencrypted).
fn delete_keyring_entry(app_name: &str, label: &str) {
    if let Ok(entry) = keyring::Entry::new(app_name, label) {
        drop(entry.delete_credential());
    }
}

/// Print a one-time warning that keys are stored unencrypted.
#[allow(clippy::print_stderr)]
fn warn_unencrypted() {
    UNENCRYPTED_WARNING.call_once(|| {
        eprintln!(
            "warning: system keyring unavailable; private keys will be stored unencrypted on disk"
        );
    });
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

    // Save private key (encrypted if keyring is available, plaintext otherwise)
    let secret_bytes = secret_key.to_bytes();
    save_private_key(config, &key_path, &secret_bytes, label)?;

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
    let bytes = load_private_key_bytes(&config.app_name, &key_path, label)?;
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

    // Remove the keyring entry (ignore errors -- may not exist)
    delete_keyring_entry(&config.app_name, label);

    // Remove the private key file
    let key_path = dir.join(format!("{label}.key"));
    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
    }

    metadata::delete_key_files(&dir, label)
}

/// Encrypt a raw private key with the given KEK using AES-256-GCM.
/// Returns the full encrypted file format bytes.
#[cfg(test)]
fn encrypt_key_bytes(kek: &[u8; KEK_SIZE], secret_bytes: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(kek).expect("valid key size");
    let mut nonce_bytes = [0_u8; GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, secret_bytes).expect("encryption");

    let mut file_data = Vec::with_capacity(1 + GCM_NONCE_SIZE + encrypted.len());
    file_data.push(ENCRYPTED_KEY_VERSION);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&encrypted);
    file_data
}

/// Decrypt an encrypted key file using the given KEK.
/// Returns the raw private key bytes.
#[cfg(test)]
fn decrypt_key_bytes(kek: &[u8; KEK_SIZE], file_data: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    assert_eq!(file_data[0], ENCRYPTED_KEY_VERSION);
    let nonce_bytes = &file_data[1..1 + GCM_NONCE_SIZE];
    let encrypted = &file_data[1 + GCM_NONCE_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(kek).expect("valid key size");
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, encrypted).expect("decryption")
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

    /// Test config with keyring disabled to avoid system keychain prompts.
    fn test_config(dir: &std::path::Path) -> SoftwareConfig {
        SoftwareConfig {
            app_name: "test-app".to_string(),
            keys_dir_override: Some(dir.to_path_buf()),
            use_keyring: false,
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

    // --- Encrypted key format tests (no keyring needed) ---

    #[test]
    fn encrypt_decrypt_key_bytes_roundtrip() {
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let mut secret = [0_u8; RAW_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut secret);

        let encrypted = encrypt_key_bytes(&kek, &secret);
        let decrypted = decrypt_key_bytes(&kek, &encrypted);
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn encrypted_file_format_has_correct_structure() {
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let secret = [0xAB_u8; RAW_KEY_SIZE];
        let encrypted = encrypt_key_bytes(&kek, &secret);

        // version(1) + nonce(12) + encrypted_key(32) + tag(16) = 61
        assert_eq!(encrypted.len(), MIN_ENCRYPTED_FILE_SIZE);
        assert_eq!(encrypted[0], ENCRYPTED_KEY_VERSION);
    }

    #[test]
    fn decrypt_fails_with_wrong_kek() {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::RngCore;

        let mut kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut kek);

        let secret = [0x42_u8; RAW_KEY_SIZE];
        let encrypted = encrypt_key_bytes(&kek, &secret);

        // Try with a different KEK
        let mut wrong_kek = [0_u8; KEK_SIZE];
        rand::thread_rng().fill_bytes(&mut wrong_kek);

        let nonce_bytes = &encrypted[1..1 + GCM_NONCE_SIZE];
        let ciphertext = &encrypted[1 + GCM_NONCE_SIZE..];

        let cipher = Aes256Gcm::new_from_slice(&wrong_kek).unwrap();
        let nonce = Nonce::from_slice(nonce_bytes);
        let result = cipher.decrypt(nonce, ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn backward_compat_raw_key_file_loads() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        // Generate a key and manually write it as a raw 32-byte file (old format)
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let secret_bytes = secret_key.to_bytes();
        let key_path = dir.join("legacy.key");
        std::fs::write(&key_path, &*secret_bytes).unwrap();

        // Also write the metadata so the key is findable
        let meta = KeyMeta::new("legacy", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "legacy", &meta).unwrap();

        // load_secret_key should read the raw bytes directly
        let loaded = load_secret_key(&config, "legacy").unwrap();
        assert_eq!(loaded.to_bytes(), secret_bytes);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unrecognized_file_format_returns_error() {
        let dir = test_dir();
        let config = test_config(&dir);
        metadata::ensure_dir(&dir).unwrap();

        // Write a file that is neither 32 bytes nor starts with 0x01 + valid length
        let key_path = dir.join("bad.key");
        std::fs::write(&key_path, [0x00; 50]).unwrap();

        let meta = KeyMeta::new("bad", KeyType::Signing, AccessPolicy::None);
        metadata::save_meta(&dir, "bad", &meta).unwrap();

        let err = load_secret_key(&config, "bad").unwrap_err();
        match err {
            Error::KeyOperation { operation, .. } => {
                assert_eq!(operation, "load_private_key");
            }
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
