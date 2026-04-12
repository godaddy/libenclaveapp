// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Secure Enclave signing backend.

use crate::ffi;
use crate::keychain::{self, KeychainConfig};
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

/// ECDSA P-256 signing backend using the macOS Secure Enclave.
pub struct SecureEnclaveSigner {
    config: KeychainConfig,
}

impl SecureEnclaveSigner {
    pub fn new(app_name: &str) -> Self {
        SecureEnclaveSigner {
            config: KeychainConfig::new(app_name),
        }
    }
}

impl EnclaveKeyManager for SecureEnclaveSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;

        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SecureEnclaveSigner only supports signing keys".into(),
            });
        }

        let (pub_key, data_rep) = keychain::generate_key(key_type, policy.as_ffi_value())?;
        keychain::save_key(&self.config, label, key_type, policy, &data_rep, &pub_key)?;
        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        keychain::load_pub_key(&self.config, label, KeyType::Signing)
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

impl EnclaveSigner for SecureEnclaveSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        let data_rep = keychain::load_handle(&self.config, label)?;

        let mut sig = vec![0u8; 128]; // DER ECDSA P-256 sig is at most ~72 bytes
        let mut sig_len: i32 = 128;

        let rc = unsafe {
            ffi::enclaveapp_se_sign(
                data_rep.as_ptr(),
                data_rep.len() as i32,
                data.as_ptr(),
                data.len() as i32,
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };

        if rc != 0 {
            return Err(Error::SignFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        sig.truncate(sig_len as usize);
        Ok(sig)
    }
}
