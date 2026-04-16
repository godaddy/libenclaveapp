// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! High-level signing backend with automatic platform detection.
//!
//! Thin wrapper that handles platform detection and initialization.
//! Exposes the underlying `EnclaveSigner` and `EnclaveKeyManager` traits
//! so sshenc can build its richer `KeyBackend` on top.

use crate::error::Result;
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
}

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
            // On WSL, skip the libtss2 TPM probe — there's no local TPM.
            // Go straight to the software keyring backend.
            if enclaveapp_wsl::is_wsl() {
                debug!("WSL detected, skipping local TPM probe for signing");
                return Self::init_linux_software(&config);
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

        Self::init_linux_software(config)
    }

    #[cfg(target_os = "linux")]
    fn init_linux_software(config: &StorageConfig) -> Result<Self> {
        if !enclaveapp_keyring::has_keyring_feature() {
            return Err(crate::error::StorageError::NotAvailable);
        }

        let keys_dir = config
            .keys_dir
            .clone()
            .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&config.app_name));
        let signer = enclaveapp_keyring::SoftwareSigner::with_keys_dir(&config.app_name, keys_dir);
        debug!(
            "Linux software signing backend ready with keyring (app={})",
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
        }
    }

    /// Which backend is in use.
    pub fn backend_kind(&self) -> BackendKind {
        self.kind
    }
}
