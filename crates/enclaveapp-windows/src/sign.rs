// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `TpmSigner` — ECDSA P-256 signing backend using the Windows TPM.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, unused_qualifications, let_underscore_drop)]

use crate::convert::p1363_to_der;
use crate::export::export_public_key;
use crate::key;
use crate::provider;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use sha2::{Digest, Sha256};
use windows::Win32::Security::Cryptography::*;

/// ECDSA P-256 algorithm identifier for CNG.
const ECDSA_P256_ALGORITHM: &str = "ECDSA_P256";

/// Windows TPM-backed ECDSA P-256 signer.
#[derive(Debug)]
pub struct TpmSigner {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
}

impl TpmSigner {
    /// Create a new signer for the given application.
    pub fn new(app_name: &str) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    /// Create a signer with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        TpmSigner {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    fn keys_dir(&self) -> std::path::PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

impl EnclaveKeyManager for TpmSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "TpmSigner only supports signing keys".into(),
            });
        }

        let provider = provider::open_provider()?;
        let (_key_handle, pub_key) = key::create_key(
            &provider,
            &self.app_name,
            label,
            ECDSA_P256_ALGORITHM,
            policy,
        )?;

        // Persist metadata and cached public key to disk.
        let dir = self.keys_dir();
        metadata::ensure_dir(&dir)?;
        let meta = KeyMeta::new(label, key_type, policy);
        metadata::save_meta(&dir, label, &meta)?;
        metadata::save_pub_key(&dir, label, &pub_key)?;

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        // Try the cached file first; fall back to exporting from the TPM.
        let dir = self.keys_dir();
        match metadata::load_pub_key(&dir, label) {
            Ok(pk) => Ok(pk),
            Err(_) => {
                let provider = provider::open_provider()?;
                let key_handle = key::open_key(&provider, &self.app_name, label)?;
                let pub_key = export_public_key(&key_handle)?;
                // Cache for next time.
                let _ = metadata::save_pub_key(&dir, label, &pub_key);
                Ok(pub_key)
            }
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        let provider = provider::open_provider()?;
        key::enumerate_keys(&provider, &self.app_name)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        validate_label(label)?;
        key::delete_key(&self.app_name, label)?;
        let dir = self.keys_dir();
        let _ = metadata::delete_key_files(&dir, label);
        Ok(())
    }

    fn is_available(&self) -> bool {
        provider::is_available()
    }
}

impl EnclaveSigner for TpmSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;
        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;

        // Pre-hash with SHA-256.
        let digest = Sha256::digest(data);

        // Query signature size.
        let mut sig_size: u32 = 0;
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                None,
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash size query: {e}"),
            })?;
        }

        // Produce the P1363 signature.
        let mut sig = vec![0_u8; sig_size as usize];
        unsafe {
            NCryptSignHash(
                key_handle.as_key(),
                None,
                &digest,
                Some(&mut sig),
                &mut sig_size,
                NCRYPT_FLAGS::default(),
            )
            .map_err(|e| Error::SignFailed {
                detail: format!("NCryptSignHash: {e}"),
            })?;
        }
        sig.truncate(sig_size as usize);

        // CNG returns P1363 (r || s); convert to DER.
        Ok(p1363_to_der(&sig))
    }
}
