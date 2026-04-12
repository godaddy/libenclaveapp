// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key lifecycle operations shared between signing and encryption backends.
//!
//! Handles file storage (.handle, .pub, .meta), key listing, loading, and deletion.

use crate::ffi;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::KeyType;
use enclaveapp_core::{Error, Result};
use std::path::PathBuf;

/// Configuration for keychain operations, scoped to an application.
pub struct KeychainConfig {
    pub app_name: String,
    /// Optional override for the keys directory. If None, uses the standard
    /// platform path (~/.config/<app_name>/keys/ on Unix).
    pub keys_dir_override: Option<PathBuf>,
}

impl KeychainConfig {
    pub fn new(app_name: &str) -> Self {
        KeychainConfig {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    /// Create a config with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        KeychainConfig {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| enclaveapp_core::metadata::keys_dir(&self.app_name))
    }
}

/// Check if the Secure Enclave is available.
pub fn is_available() -> bool {
    unsafe { ffi::enclaveapp_se_available() == 1 }
}

/// Generate a new Secure Enclave key.
/// Returns (uncompressed_public_key_65_bytes, data_representation).
pub fn generate_key(key_type: KeyType, auth_policy: i32) -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(Error::NotAvailable);
    }

    let mut pub_key = vec![0u8; 65];
    let mut pub_key_len: i32 = 65;
    let mut data_rep = vec![0u8; 1024];
    let mut data_rep_len: i32 = 1024;

    let rc = match key_type {
        KeyType::Signing => unsafe {
            ffi::enclaveapp_se_generate_signing_key(
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
                data_rep.as_mut_ptr(),
                &mut data_rep_len,
                auth_policy,
            )
        },
        KeyType::Encryption => unsafe {
            ffi::enclaveapp_se_generate_encryption_key(
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
                data_rep.as_mut_ptr(),
                &mut data_rep_len,
                auth_policy,
            )
        },
    };

    if rc != 0 {
        return Err(Error::GenerateFailed {
            detail: format!("FFI returned error code {rc}"),
        });
    }

    pub_key.truncate(pub_key_len as usize);
    data_rep.truncate(data_rep_len as usize);
    Ok((pub_key, data_rep))
}

/// Extract the public key from a persisted data representation.
/// Returns 65-byte uncompressed public key.
pub fn public_key_from_data_rep(key_type: KeyType, data_rep: &[u8]) -> Result<Vec<u8>> {
    let mut pub_key = vec![0u8; 65];
    let mut pub_key_len: i32 = 65;

    let rc = match key_type {
        KeyType::Signing => unsafe {
            ffi::enclaveapp_se_signing_public_key(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
            )
        },
        KeyType::Encryption => unsafe {
            ffi::enclaveapp_se_encryption_public_key(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                pub_key.as_mut_ptr(),
                &mut pub_key_len,
            )
        },
    };

    if rc != 0 {
        return Err(Error::KeyOperation {
            operation: "public_key".into(),
            detail: format!("FFI returned error code {rc}"),
        });
    }

    pub_key.truncate(pub_key_len as usize);
    Ok(pub_key)
}

/// Save a key's data representation, public key, and metadata to the keys directory.
pub fn save_key(
    config: &KeychainConfig,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
    data_rep: &[u8],
    pub_key: &[u8],
) -> Result<()> {
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;

    let _lock = metadata::DirLock::acquire(&dir)?;

    // Check for duplicate
    let handle_path = dir.join(format!("{label}.handle"));
    if handle_path.exists() {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    // Save handle (data representation)
    metadata::atomic_write(&handle_path, data_rep)?;
    metadata::restrict_file_permissions(&handle_path)?;

    // Save public key cache
    metadata::save_pub_key(&dir, label, pub_key)?;

    // Save metadata
    let meta = KeyMeta::new(label, key_type, policy);
    metadata::save_meta(&dir, label, &meta)?;

    Ok(())
}

/// Load a key's data representation from the keys directory.
pub fn load_handle(config: &KeychainConfig, label: &str) -> Result<Vec<u8>> {
    let path = config.keys_dir().join(format!("{label}.handle"));
    if !path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    Ok(std::fs::read(&path)?)
}

/// Load the cached public key for a label. Falls back to extracting from data rep.
pub fn load_pub_key(config: &KeychainConfig, label: &str, key_type: KeyType) -> Result<Vec<u8>> {
    let dir = config.keys_dir();
    match metadata::load_pub_key(&dir, label) {
        Ok(pub_key) => Ok(pub_key),
        Err(_) => {
            let data_rep = load_handle(config, label)?;
            public_key_from_data_rep(key_type, &data_rep)
        }
    }
}

/// List all key labels in the keys directory.
pub fn list_labels(config: &KeychainConfig) -> Result<Vec<String>> {
    metadata::list_labels(&config.keys_dir())
}

/// Delete a key and all associated files.
pub fn delete_key(config: &KeychainConfig, label: &str) -> Result<()> {
    let dir = config.keys_dir();
    let _lock = metadata::DirLock::acquire(&dir)?;
    metadata::delete_key_files(&dir, label)
}
