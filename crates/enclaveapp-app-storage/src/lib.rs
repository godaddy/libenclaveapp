// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level application storage for hardware-backed key management.
//!
//! This crate provides shared platform detection, key initialization, and
//! encrypt/decrypt/sign wrapping that all consuming applications need.
//! It replaces the per-app `secure_storage` modules in awsenc and sso-jwt,
//! and the platform detection logic in sshenc.
//!
//! # Usage
//!
//! For encryption (awsenc, sso-jwt):
//! ```no_run
//! use enclaveapp_app_storage::{AppEncryptionStorage, StorageConfig, AccessPolicy, EncryptionStorage};
//!
//! let storage = AppEncryptionStorage::init(StorageConfig {
//!     app_name: "myapp".into(),
//!     key_label: "cache-key".into(),
//!     access_policy: AccessPolicy::BiometricOnly,
//!     extra_bridge_paths: vec![],
//!     keys_dir: None,
//! })?;
//!
//! let ciphertext = storage.encrypt(b"secret")?;
//! let plaintext = storage.decrypt(&ciphertext)?;
//! # Ok::<(), enclaveapp_app_storage::StorageError>(())
//! ```
//!
//! For signing (sshenc):
//! ```no_run
//! use enclaveapp_app_storage::{AppSigningBackend, StorageConfig, AccessPolicy};
//!
//! let backend = AppSigningBackend::init(StorageConfig {
//!     app_name: "sshenc".into(),
//!     key_label: "default".into(),
//!     access_policy: AccessPolicy::None,
//!     extra_bridge_paths: vec![],
//!     keys_dir: None,
//! })?;
//!
//! // Use the underlying signer/key_manager for operations.
//! let signer = backend.signer();
//! let key_manager = backend.key_manager();
//! # Ok::<(), enclaveapp_app_storage::StorageError>(())
//! ```

pub mod encryption;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod platform;
pub mod signing;

// Re-export primary types for consumers.
pub use encryption::{AppEncryptionStorage, EncryptionStorage};
pub use error::{Result, StorageError};
pub use platform::BackendKind;
pub use signing::AppSigningBackend;

// Re-export core types so consumers don't need a separate enclaveapp-core dep.
pub use enclaveapp_core::metadata::KeyMeta;
pub use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
pub use enclaveapp_core::types::{AccessPolicy, KeyType};

/// Configuration for initializing application storage.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Application name (e.g., "awsenc", "sso-jwt", "sshenc").
    /// Used to namespace keys and locate config directories.
    pub app_name: String,
    /// Key label (e.g., "cache-key", "default").
    pub key_label: String,
    /// Access policy for key operations.
    pub access_policy: AccessPolicy,
    /// Extra WSL bridge paths beyond the auto-derived defaults.
    /// The standard discovery and auto-derived paths are tried first.
    /// These are additional fallbacks for app-specific legacy locations.
    pub extra_bridge_paths: Vec<String>,
    /// Override the keys directory (default: `~/.config/<app_name>/keys/`).
    /// sshenc uses `~/.sshenc/keys/` which differs from the standard layout.
    pub keys_dir: Option<std::path::PathBuf>,
}

/// Create encryption storage with automatic platform detection.
/// Returns a trait object for use with mock backends in tests.
pub fn create_encryption_storage(config: StorageConfig) -> Result<Box<dyn EncryptionStorage>> {
    let storage = AppEncryptionStorage::init(config)?;
    Ok(Box::new(storage))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn storage_config_debug() {
        let config = StorageConfig {
            app_name: "test".into(),
            key_label: "key".into(),
            access_policy: AccessPolicy::None,
            extra_bridge_paths: vec![],
            keys_dir: None,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("test"));
        assert!(debug.contains("key"));
    }

    #[test]
    fn storage_config_clone() {
        let config = StorageConfig {
            app_name: "test".into(),
            key_label: "key".into(),
            access_policy: AccessPolicy::BiometricOnly,
            extra_bridge_paths: vec!["/custom/path".into()],
            keys_dir: Some(std::path::PathBuf::from("/custom/keys")),
        };
        let cloned = config.clone();
        assert_eq!(cloned.app_name, "test");
        assert_eq!(cloned.key_label, "key");
        assert_eq!(cloned.access_policy, AccessPolicy::BiometricOnly);
        assert_eq!(cloned.extra_bridge_paths.len(), 1);
    }

    #[test]
    fn storage_error_display() {
        let err = StorageError::NotAvailable;
        assert_eq!(err.to_string(), "hardware security module not available");

        let err = StorageError::EncryptionFailed("bad key".into());
        assert_eq!(err.to_string(), "encryption failed: bad key");

        let err = StorageError::DecryptionFailed("corrupt".into());
        assert_eq!(err.to_string(), "decryption failed: corrupt");

        let err = StorageError::SigningFailed("timeout".into());
        assert_eq!(err.to_string(), "signing failed: timeout");

        let err = StorageError::KeyInitFailed("no hardware".into());
        assert_eq!(err.to_string(), "key initialization failed: no hardware");

        let err = StorageError::KeyNotFound("missing".into());
        assert_eq!(err.to_string(), "key not found: missing");

        let err = StorageError::PolicyMismatch("None vs BiometricOnly".into());
        assert_eq!(
            err.to_string(),
            "key policy mismatch: None vs BiometricOnly"
        );

        let err = StorageError::PlatformError("unsupported".into());
        assert_eq!(err.to_string(), "platform error: unsupported");
    }

    #[test]
    fn re_exports_work() {
        // Verify core types are re-exported.
        let _ = AccessPolicy::None;
        let _ = AccessPolicy::Any;
        let _ = AccessPolicy::BiometricOnly;
        let _ = AccessPolicy::PasswordOnly;
        let _ = KeyType::Signing;
        let _ = KeyType::Encryption;
        let _ = BackendKind::SecureEnclave;
    }
}
