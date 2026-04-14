// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level encryption storage with automatic platform detection.
//!
//! Replaces the per-app `secure_storage` modules in awsenc and sso-jwt.

#[allow(unused_imports)]
use crate::error::{Result, StorageError};
use crate::platform::BackendKind;
use crate::StorageConfig;
#[allow(unused_imports)]
use enclaveapp_core::metadata;
#[allow(unused_imports)]
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
#[allow(unused_imports)]
use enclaveapp_core::types::{AccessPolicy, KeyType};
use std::path::PathBuf;
#[allow(unused_imports)]
use tracing::{debug, warn};

/// High-level encryption storage for consuming applications.
///
/// Handles platform detection, backend initialization, key lifecycle,
/// and encrypt/decrypt operations. This is the primary type consumers use.
///
/// Use via the [`EncryptionStorage`] trait or call methods directly.
pub struct AppEncryptionStorage {
    kind: BackendKind,
    app_name: String,
    key_label: String,
    /// Whether decrypt operations require user presence verification.
    /// Read on Windows (Windows Hello) and macOS (Touch ID); unused on Linux.
    #[allow(dead_code)]
    requires_user_presence: bool,
    inner: StorageInner,
}

// Internal enum dispatch — avoids Box<dyn> for the common case.
enum StorageInner {
    #[cfg(target_os = "macos")]
    SecureEnclave(enclaveapp_apple::SecureEnclaveEncryptor),

    #[cfg(target_os = "windows")]
    Tpm(enclaveapp_windows::TpmEncryptor),

    #[cfg(target_os = "linux")]
    Software(enclaveapp_software::SoftwareEncryptor),

    #[cfg(target_os = "linux")]
    WslBridge {
        bridge_path: PathBuf,
        biometric: bool,
    },
}

impl std::fmt::Debug for AppEncryptionStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppEncryptionStorage")
            .field("kind", &self.kind)
            .field("app_name", &self.app_name)
            .field("key_label", &self.key_label)
            .finish()
    }
}

impl AppEncryptionStorage {
    /// Initialize encryption storage with automatic platform detection.
    ///
    /// 1. Detects the current platform (macOS/Windows/Linux/WSL)
    /// 2. Initializes the appropriate libenclaveapp backend
    /// 3. Checks if a key with the given label exists
    /// 4. If not, generates a new key with the configured access policy
    /// 5. If yes, checks that the existing key's policy matches;
    ///    on mismatch, re-generates (encryption keys protect temporary cached data)
    #[allow(clippy::needless_return, unreachable_code)]
    pub fn init(config: StorageConfig) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            return Self::init_macos(&config);
        }

        #[cfg(target_os = "windows")]
        {
            return Self::init_windows(&config);
        }

        #[cfg(target_os = "linux")]
        {
            if enclaveapp_wsl::is_wsl() {
                return Self::init_wsl(&config);
            }
            return Self::init_linux(&config);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = config;
            Err(StorageError::NotAvailable)
        }
    }

    #[cfg(target_os = "macos")]
    fn init_macos(config: &StorageConfig) -> Result<Self> {
        let encryptor = match &config.keys_dir {
            Some(keys_dir) => enclaveapp_apple::SecureEnclaveEncryptor::with_keys_dir(
                &config.app_name,
                keys_dir.clone(),
            ),
            None => enclaveapp_apple::SecureEnclaveEncryptor::new(&config.app_name),
        };

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        Self::ensure_key(&encryptor, config)?;
        debug!(
            "Secure Enclave encryption ready (app={}, label={}, policy={:?})",
            config.app_name, config.key_label, config.access_policy
        );

        Ok(Self {
            kind: BackendKind::SecureEnclave,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            requires_user_presence: config.access_policy != AccessPolicy::None,
            inner: StorageInner::SecureEnclave(encryptor),
        })
    }

    #[cfg(target_os = "windows")]
    fn init_windows(config: &StorageConfig) -> Result<Self> {
        let encryptor = match &config.keys_dir {
            Some(keys_dir) => {
                enclaveapp_windows::TpmEncryptor::with_keys_dir(&config.app_name, keys_dir.clone())
            }
            None => enclaveapp_windows::TpmEncryptor::new(&config.app_name),
        };

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        Self::ensure_key(&encryptor, config)?;
        debug!(
            "TPM encryption ready (app={}, label={}, policy={:?})",
            config.app_name, config.key_label, config.access_policy
        );

        Ok(Self {
            kind: BackendKind::Tpm,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            requires_user_presence: config.access_policy != AccessPolicy::None,
            inner: StorageInner::Tpm(encryptor),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux(config: &StorageConfig) -> Result<Self> {
        if config.access_policy != AccessPolicy::None {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "warning: biometric/user-presence has no effect on Linux \
                     (no hardware security module)"
                );
            }
        }

        let encryptor = match &config.keys_dir {
            Some(keys_dir) => enclaveapp_software::SoftwareEncryptor::with_keys_dir(
                &config.app_name,
                keys_dir.clone(),
            ),
            None => enclaveapp_software::SoftwareEncryptor::new(&config.app_name),
        };

        // Software backend: always generate with None policy (no hardware to enforce).
        if encryptor.public_key(&config.key_label).is_err() {
            debug!("no existing software key found, generating new key pair");
            encryptor
                .generate(&config.key_label, KeyType::Encryption, AccessPolicy::None)
                .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        }

        debug!("Linux software encryption ready (app={})", config.app_name);

        Ok(Self {
            kind: BackendKind::Software,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            requires_user_presence: false, // Software backend has no user presence
            inner: StorageInner::Software(encryptor),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_wsl(config: &StorageConfig) -> Result<Self> {
        let bridge_path =
            crate::platform::find_bridge_executable(&config.app_name, &config.extra_bridge_paths)
                .ok_or(StorageError::NotAvailable)?;

        debug!(
            "WSL TPM bridge found at {} (app={})",
            bridge_path.display(),
            config.app_name
        );

        let biometric = config.access_policy != AccessPolicy::None;
        enclaveapp_bridge::bridge_init(
            &bridge_path,
            &config.app_name,
            &config.key_label,
            biometric,
        )
        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;

        Ok(Self {
            kind: BackendKind::TpmBridge,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            requires_user_presence: biometric,
            inner: StorageInner::WslBridge {
                bridge_path,
                biometric,
            },
        })
    }

    /// Ensure a key exists with the correct access policy.
    /// If the key exists but has a different policy, re-generate it
    /// (encryption keys protect temporary cached data, so this is safe).
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    fn ensure_key(encryptor: &impl EnclaveEncryptor, config: &StorageConfig) -> Result<()> {
        if encryptor.public_key(&config.key_label).is_ok() {
            // Key exists — check policy match.
            let keys_dir = resolved_keys_dir(config);
            if let Ok(meta) = metadata::load_meta(&keys_dir, &config.key_label) {
                if meta.access_policy != config.access_policy {
                    warn!(
                        "key policy mismatch: existing={:?}, requested={:?}; re-generating key",
                        meta.access_policy, config.access_policy
                    );
                    encryptor
                        .delete_key(&config.key_label)
                        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
                    // Fall through to generate below.
                } else {
                    return Ok(());
                }
            } else {
                warn!(
                    "key metadata unreadable for label {}; re-generating key to enforce requested policy",
                    config.key_label
                );
                encryptor
                    .delete_key(&config.key_label)
                    .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
            }
        }

        debug!("generating new encryption key (label={})", config.key_label);
        encryptor
            .generate(&config.key_label, KeyType::Encryption, config.access_policy)
            .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        Ok(())
    }
}

#[cfg(any(test, target_os = "macos", target_os = "windows"))]
fn resolved_keys_dir(config: &StorageConfig) -> PathBuf {
    config
        .keys_dir
        .clone()
        .unwrap_or_else(|| metadata::keys_dir(&config.app_name))
}

/// Encryption storage trait for dynamic dispatch (used with mock backend).
pub trait EncryptionStorage: Send + Sync {
    /// Encrypt plaintext. No biometric prompt (uses public key only).
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt ciphertext. May trigger biometric if key has access policy.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// Delete the key and associated files.
    fn destroy(&self) -> Result<()>;
    /// Whether the backend is available.
    fn is_available(&self) -> bool;
    /// Human-readable backend name.
    fn backend_name(&self) -> &'static str;
    /// Which backend is in use.
    fn backend_kind(&self) -> BackendKind;
}

impl EncryptionStorage for AppEncryptionStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| StorageError::EncryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge {
                bridge_path,
                biometric,
            } => enclaveapp_bridge::bridge_encrypt(
                bridge_path,
                &self.app_name,
                &self.key_label,
                plaintext,
                *biometric,
            )
            .map_err(|e| StorageError::EncryptionFailed(e.to_string())),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Verify user presence before decryption if required.
        #[cfg(target_os = "windows")]
        if self.requires_user_presence {
            let msg = format!("Verify your identity to decrypt {} data", self.app_name);
            enclaveapp_windows::ui_policy::verify_user_presence(&msg)
                .map_err(|e| StorageError::DecryptionFailed(format!("user presence: {e}")))?;
        }

        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| StorageError::DecryptionFailed(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge {
                bridge_path,
                biometric,
            } => enclaveapp_bridge::bridge_decrypt(
                bridge_path,
                &self.app_name,
                &self.key_label,
                ciphertext,
                *biometric,
            )
            .map_err(|e| StorageError::DecryptionFailed(e.to_string())),
        }
    }

    fn destroy(&self) -> Result<()> {
        match &self.inner {
            #[cfg(target_os = "macos")]
            StorageInner::SecureEnclave(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "windows")]
            StorageInner::Tpm(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::Software(enc) => enc
                .delete_key(&self.key_label)
                .map_err(|e| StorageError::KeyNotFound(e.to_string())),

            #[cfg(target_os = "linux")]
            StorageInner::WslBridge { bridge_path, .. } => {
                enclaveapp_bridge::bridge_delete(bridge_path, &self.app_name, &self.key_label)
                    .map_err(|e| StorageError::KeyNotFound(e.to_string()))
            }
        }
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        match self.kind {
            BackendKind::SecureEnclave => "Secure Enclave",
            BackendKind::Tpm => "TPM 2.0",
            BackendKind::TpmBridge => "TPM 2.0 (WSL Bridge)",
            BackendKind::Software => "Linux (software)",
        }
    }

    fn backend_kind(&self) -> BackendKind {
        self.kind
    }
}

// Send + Sync: all inner types are Send + Sync (encryptors hold file paths and handles).
// The platform crates declare their types as Send + Sync.
#[allow(unsafe_code)]
unsafe impl Send for AppEncryptionStorage {}
#[allow(unsafe_code)]
unsafe impl Sync for AppEncryptionStorage {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use enclaveapp_core::{Error, Result as CoreResult};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct FakeEncryptor {
        key_exists: bool,
        deleted_labels: Mutex<Vec<String>>,
        generated_policies: Mutex<Vec<AccessPolicy>>,
    }

    impl FakeEncryptor {
        fn existing_key() -> Self {
            Self {
                key_exists: true,
                deleted_labels: Mutex::new(Vec::new()),
                generated_policies: Mutex::new(Vec::new()),
            }
        }
    }

    impl EnclaveKeyManager for FakeEncryptor {
        fn generate(
            &self,
            _label: &str,
            _key_type: KeyType,
            policy: AccessPolicy,
        ) -> CoreResult<Vec<u8>> {
            self.generated_policies
                .lock()
                .map_err(|_| Error::KeyOperation {
                    operation: "test_generate".into(),
                    detail: "generated_policies mutex poisoned".into(),
                })?
                .push(policy);
            Ok(vec![0x04; 65])
        }

        fn public_key(&self, label: &str) -> CoreResult<Vec<u8>> {
            if self.key_exists {
                Ok(vec![0x04; 65])
            } else {
                Err(Error::KeyNotFound {
                    label: label.to_string(),
                })
            }
        }

        fn list_keys(&self) -> CoreResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn delete_key(&self, label: &str) -> CoreResult<()> {
            self.deleted_labels
                .lock()
                .map_err(|_| Error::KeyOperation {
                    operation: "test_delete_key".into(),
                    detail: "deleted_labels mutex poisoned".into(),
                })?
                .push(label.to_string());
            Ok(())
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    impl EnclaveEncryptor for FakeEncryptor {
        fn encrypt(&self, _label: &str, _plaintext: &[u8]) -> CoreResult<Vec<u8>> {
            unreachable!("not used in ensure_key tests")
        }

        fn decrypt(&self, _label: &str, _ciphertext: &[u8]) -> CoreResult<Vec<u8>> {
            unreachable!("not used in ensure_key tests")
        }
    }

    fn test_config() -> StorageConfig {
        StorageConfig {
            app_name: "test-app".into(),
            key_label: "cache-key".into(),
            access_policy: AccessPolicy::None,
            extra_bridge_paths: vec![],
            keys_dir: None,
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-app-storage-{name}-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolved_keys_dir_uses_default_when_not_overridden() {
        let config = test_config();
        assert_eq!(resolved_keys_dir(&config), metadata::keys_dir("test-app"));
    }

    #[test]
    fn resolved_keys_dir_uses_override_when_configured() {
        let mut config = test_config();
        config.keys_dir = Some(PathBuf::from("/tmp/custom-keys"));
        assert_eq!(
            resolved_keys_dir(&config),
            PathBuf::from("/tmp/custom-keys")
        );
    }

    #[test]
    fn ensure_key_regenerates_when_metadata_is_unreadable() {
        let temp_dir = test_dir("unreadable-meta");
        let mut config = test_config();
        config.keys_dir = Some(temp_dir.clone());
        config.access_policy = AccessPolicy::BiometricOnly;

        std::fs::write(temp_dir.join("cache-key.meta"), b"{not valid json").unwrap();

        let encryptor = FakeEncryptor::existing_key();
        AppEncryptionStorage::ensure_key(&encryptor, &config).unwrap();

        assert_eq!(
            encryptor.deleted_labels.lock().unwrap().as_slice(),
            ["cache-key"]
        );
        assert_eq!(
            encryptor.generated_policies.lock().unwrap().as_slice(),
            [AccessPolicy::BiometricOnly]
        );

        std::fs::remove_dir_all(temp_dir).unwrap();
    }
}
