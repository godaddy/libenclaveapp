// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level signing backend with automatic platform detection.
//!
//! Thin wrapper that handles platform detection and initialization.
//! Exposes the underlying `EnclaveSigner` and `EnclaveKeyManager` traits
//! so sshenc can build its richer `KeyBackend` on top.

#[allow(unused_imports)]
use crate::error::{Result, StorageError};
use crate::platform::BackendKind;
use crate::StorageConfig;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use tracing::debug;

/// High-level signing backend for sshenc.
///
/// Provides platform detection and initialization, then exposes the
/// underlying libenclaveapp signer and key manager for the app to use.
/// Does NOT generate keys automatically — sshenc manages its own key lifecycle.
pub struct AppSigningBackend {
    kind: BackendKind,
    inner: SigningInner,
}

enum SigningInner {
    #[cfg(target_os = "macos")]
    SecureEnclave(enclaveapp_apple::SecureEnclaveSigner),

    #[cfg(target_os = "windows")]
    Tpm(enclaveapp_windows::TpmSigner),

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    LinuxTpm(enclaveapp_linux_tpm::LinuxTpmSigner),

    #[cfg(target_os = "linux")]
    Software(enclaveapp_keyring::SoftwareSigner),

    #[cfg(target_os = "linux")]
    WslBridge(BridgeSignerWrapper),
}

/// Wrapper that implements `EnclaveSigner` + `EnclaveKeyManager` by calling
/// the WSL TPM bridge for signing operations.
#[cfg(target_os = "linux")]
struct BridgeSignerWrapper {
    bridge_path: std::path::PathBuf,
    app_name: String,
    key_label: String,
    access_policy: enclaveapp_core::types::AccessPolicy,
}

#[cfg(target_os = "linux")]
impl EnclaveKeyManager for BridgeSignerWrapper {
    fn generate(
        &self,
        _label: &str,
        _key_type: enclaveapp_core::types::KeyType,
        _policy: enclaveapp_core::types::AccessPolicy,
    ) -> enclaveapp_core::Result<Vec<u8>> {
        // Key generation happens via init_signing on the bridge side.
        // Return the public key after init.
        self.public_key(_label)
    }

    fn public_key(&self, _label: &str) -> enclaveapp_core::Result<Vec<u8>> {
        enclaveapp_bridge::bridge_public_key(
            &self.bridge_path,
            &self.app_name,
            &self.key_label,
            self.access_policy,
        )
    }

    fn list_keys(&self) -> enclaveapp_core::Result<Vec<String>> {
        enclaveapp_bridge::bridge_list_keys(
            &self.bridge_path,
            &self.app_name,
            &self.key_label,
            self.access_policy,
        )
    }

    fn delete_key(&self, _label: &str) -> enclaveapp_core::Result<()> {
        enclaveapp_bridge::bridge_delete_signing(&self.bridge_path, &self.app_name, &self.key_label)
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(target_os = "linux")]
impl EnclaveSigner for BridgeSignerWrapper {
    fn sign(&self, _label: &str, data: &[u8]) -> enclaveapp_core::Result<Vec<u8>> {
        enclaveapp_bridge::bridge_sign(
            &self.bridge_path,
            &self.app_name,
            &self.key_label,
            data,
            self.access_policy,
        )
    }
}

// BridgeSignerWrapper holds only paths and strings — safe to send between threads.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl Send for BridgeSignerWrapper {}
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
unsafe impl Sync for BridgeSignerWrapper {}

impl std::fmt::Debug for AppSigningBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSigningBackend")
            .field("kind", &self.kind)
            .finish()
    }
}

impl AppSigningBackend {
    /// Initialize signing backend with automatic platform detection.
    /// Does NOT generate keys — the consumer app manages key lifecycle.
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
            if config.force_keyring {
                debug!("--keyring flag: forcing software keyring backend for signing");
                return Self::init_linux_keyring(&config);
            }
            // On WSL, try the bridge first for TPM signing, fall back to keyring.
            if enclaveapp_wsl::is_wsl() {
                debug!("WSL detected, trying bridge for signing");
                match Self::init_wsl(&config) {
                    Ok(backend) => return Ok(backend),
                    Err(_) => {
                        debug!("WSL bridge not available, falling back to keyring for signing");
                        return Self::init_linux_keyring(&config);
                    }
                }
            }
            return Self::init_linux(&config);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = config;
            Err(crate::error::StorageError::NotAvailable)
        }
    }

    #[cfg(target_os = "macos")]
    fn init_macos(config: &StorageConfig) -> Result<Self> {
        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&config.app_name));
        let signer =
            enclaveapp_apple::SecureEnclaveSigner::with_keys_dir(&config.app_name, keys_dir);

        if !signer.is_available() {
            return Err(crate::error::StorageError::NotAvailable);
        }

        debug!(
            "Secure Enclave signing backend ready (app={})",
            config.app_name,
        );
        Ok(Self {
            kind: BackendKind::SecureEnclave,
            inner: SigningInner::SecureEnclave(signer),
        })
    }

    #[cfg(target_os = "windows")]
    fn init_windows(config: &StorageConfig) -> Result<Self> {
        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&config.app_name));
        let signer = enclaveapp_windows::TpmSigner::with_keys_dir(&config.app_name, keys_dir);

        if !signer.is_available() {
            return Err(crate::error::StorageError::NotAvailable);
        }

        debug!("TPM signing backend ready (app={})", config.app_name,);
        Ok(Self {
            kind: BackendKind::Tpm,
            inner: SigningInner::Tpm(signer),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux(config: &StorageConfig) -> Result<Self> {
        // Try hardware TPM first, fall back to software.
        #[cfg(target_env = "gnu")]
        if enclaveapp_linux_tpm::is_available() {
            let keys_dir = config
                .keys_dir
                .clone()
                .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&config.app_name));
            let signer =
                enclaveapp_linux_tpm::LinuxTpmSigner::with_keys_dir(&config.app_name, keys_dir);
            debug!("Linux TPM signing backend ready (app={})", config.app_name);
            return Ok(Self {
                kind: BackendKind::Tpm,
                inner: SigningInner::LinuxTpm(signer),
            });
        }

        Self::init_linux_keyring(config)
    }

    #[cfg(target_os = "linux")]
    fn init_wsl(config: &StorageConfig) -> Result<Self> {
        let bridge_path =
            crate::platform::find_bridge_executable(&config.app_name, &config.extra_bridge_paths)
                .ok_or(StorageError::NotAvailable)?;

        debug!(
            "WSL TPM signing bridge found at {} (app={})",
            bridge_path.display(),
            config.app_name
        );

        // Verify the bridge is responsive by sending init_signing.
        enclaveapp_bridge::bridge_init_signing(
            &bridge_path,
            &config.app_name,
            &config.key_label,
            config.access_policy,
        )
        .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;

        let wrapper = BridgeSignerWrapper {
            bridge_path,
            app_name: config.app_name.clone(),
            key_label: config.key_label.clone(),
            access_policy: config.access_policy,
        };

        Ok(Self {
            kind: BackendKind::TpmBridge,
            inner: SigningInner::WslBridge(wrapper),
        })
    }

    #[cfg(target_os = "linux")]
    fn init_linux_keyring(config: &StorageConfig) -> Result<Self> {
        if !enclaveapp_keyring::has_keyring_feature() {
            return Err(crate::error::StorageError::NotAvailable);
        }

        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&config.app_name));
        let signer = enclaveapp_keyring::SoftwareSigner::with_keys_dir(&config.app_name, keys_dir);
        debug!(
            "Linux keyring signing backend ready (app={})",
            config.app_name
        );
        Ok(Self {
            kind: BackendKind::Keyring,
            inner: SigningInner::Software(signer),
        })
    }

    /// Access the underlying platform signer.
    pub fn signer(&self) -> &dyn EnclaveSigner {
        match &self.inner {
            #[cfg(target_os = "macos")]
            SigningInner::SecureEnclave(s) => s,

            #[cfg(target_os = "windows")]
            SigningInner::Tpm(s) => s,

            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            SigningInner::LinuxTpm(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::Software(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::WslBridge(s) => s,
        }
    }

    /// Access the underlying key manager.
    pub fn key_manager(&self) -> &dyn EnclaveKeyManager {
        match &self.inner {
            #[cfg(target_os = "macos")]
            SigningInner::SecureEnclave(s) => s,

            #[cfg(target_os = "windows")]
            SigningInner::Tpm(s) => s,

            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            SigningInner::LinuxTpm(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::Software(s) => s,

            #[cfg(target_os = "linux")]
            SigningInner::WslBridge(s) => s,
        }
    }

    /// Which backend is in use.
    pub fn backend_kind(&self) -> BackendKind {
        self.kind
    }
}
