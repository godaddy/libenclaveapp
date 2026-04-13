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
        bridge_path: std::path::PathBuf,
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
        let encryptor = enclaveapp_apple::SecureEnclaveEncryptor::new(&config.app_name);

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
            inner: StorageInner::SecureEnclave(encryptor),
        })
    }

    #[cfg(target_os = "windows")]
    fn init_windows(config: &StorageConfig) -> Result<Self> {
        let encryptor = enclaveapp_windows::TpmEncryptor::new(&config.app_name);

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

        let encryptor = enclaveapp_software::SoftwareEncryptor::new(&config.app_name);

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

        Ok(Self {
            kind: BackendKind::TpmBridge,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            inner: StorageInner::WslBridge {
                bridge_path,
                biometric,
            },
        })
    }

    /// Ensure a key exists with the correct access policy.
    /// If the key exists but has a different policy, re-generate it
    /// (encryption keys protect temporary cached data, so this is safe).
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn ensure_key(encryptor: &impl EnclaveEncryptor, config: &StorageConfig) -> Result<()> {
        if encryptor.public_key(&config.key_label).is_ok() {
            // Key exists — check policy match.
            let keys_dir = metadata::keys_dir(&config.app_name);
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
                // Metadata missing but key exists — use as-is.
                return Ok(());
            }
        }

        debug!("generating new encryption key (label={})", config.key_label);
        encryptor
            .generate(&config.key_label, KeyType::Encryption, config.access_policy)
            .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        Ok(())
    }
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
                plaintext,
                *biometric,
            )
            .map_err(|e| StorageError::EncryptionFailed(e.to_string())),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
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
            StorageInner::WslBridge { .. } => {
                // Bridge does not expose key deletion; handled on the Windows host.
                Ok(())
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
