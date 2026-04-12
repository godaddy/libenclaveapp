// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Secure Enclave encryption backend (ECIES: ECDH + AES-GCM).

use crate::ffi;
use crate::keychain::{self, KeychainConfig};
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

/// ECIES ciphertext overhead: version(1) + ephemeral_pub(65) + nonce(12) + tag(16)
const ECIES_OVERHEAD: usize = 1 + 65 + 12 + 16;

/// ECIES encryption backend using the macOS Secure Enclave.
pub struct SecureEnclaveEncryptor {
    config: KeychainConfig,
}

impl SecureEnclaveEncryptor {
    pub fn new(app_name: &str) -> Self {
        SecureEnclaveEncryptor {
            config: KeychainConfig::new(app_name),
        }
    }
}

impl EnclaveKeyManager for SecureEnclaveEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;

        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SecureEnclaveEncryptor only supports encryption keys".into(),
            });
        }

        let (pub_key, data_rep) = keychain::generate_key(key_type, policy.as_ffi_value())?;
        keychain::save_key(&self.config, label, key_type, policy, &data_rep, &pub_key)?;
        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        keychain::load_pub_key(&self.config, label, KeyType::Encryption)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        keychain::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        keychain::delete_key(&self.config, label)
    }

    fn is_available(&self) -> bool {
        keychain::is_available()
    }
}

impl EnclaveEncryptor for SecureEnclaveEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let data_rep = keychain::load_handle(&self.config, label)?;

        let output_capacity = plaintext.len() + ECIES_OVERHEAD;
        let mut ciphertext = vec![0u8; output_capacity];
        let mut ciphertext_len = output_capacity as i32;

        let rc = unsafe {
            ffi::enclaveapp_se_encrypt(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                plaintext.as_ptr(),
                plaintext.len() as i32,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            )
        };

        if rc != 0 {
            return Err(Error::EncryptFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        ciphertext.truncate(ciphertext_len as usize);
        Ok(ciphertext)
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < ECIES_OVERHEAD {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short".into(),
            });
        }

        let data_rep = keychain::load_handle(&self.config, label)?;

        let max_plaintext = ciphertext.len();
        let mut plaintext = vec![0u8; max_plaintext];
        let mut plaintext_len = max_plaintext as i32;

        let rc = unsafe {
            ffi::enclaveapp_se_decrypt(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                ciphertext.as_ptr(),
                ciphertext.len() as i32,
                plaintext.as_mut_ptr(),
                &mut plaintext_len,
            )
        };

        if rc != 0 {
            return Err(Error::DecryptFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    }
}
