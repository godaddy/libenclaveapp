// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software ECDSA P-256 signing backend.

use crate::key_storage::{self, SoftwareConfig};
use enclaveapp_core::traits::{EnclaveKeyManager, EnclaveSigner};
use enclaveapp_core::types::{validate_label, AccessPolicy, KeyType};
use enclaveapp_core::{Error, Result};

/// Software-based ECDSA P-256 signer.
///
/// Private keys are stored as files on disk (not hardware-backed).
#[derive(Debug)]
pub struct SoftwareSigner {
    config: SoftwareConfig,
}

impl SoftwareSigner {
    pub fn new(app_name: &str) -> Self {
        Self {
            config: SoftwareConfig::new(app_name),
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        Self {
            config: SoftwareConfig::with_keys_dir(app_name, keys_dir),
        }
    }

    /// Disable keyring-based key encryption (for testing or environments
    /// without a keyring daemon).
    pub fn without_keyring(mut self) -> Self {
        self.config.use_keyring = false;
        self
    }
}

impl EnclaveKeyManager for SoftwareSigner {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Signing {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "SoftwareSigner only supports signing keys".into(),
            });
        }
        key_storage::generate_and_save(&self.config, label, key_type, policy)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        key_storage::load_public_key(&self.config, label)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        key_storage::list_labels(&self.config)
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        key_storage::delete_key(&self.config, label)
    }

    fn is_available(&self) -> bool {
        true
    }
}

impl EnclaveSigner for SoftwareSigner {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let secret = key_storage::load_secret_key(&self.config, label)?;
        let signing_key = SigningKey::from(&secret);

        let signature: p256::ecdsa::DerSignature = signing_key.sign(data);
        Ok(signature.as_bytes().to_vec())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-sw-sign-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn generate_and_sign_produces_valid_der() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("sign-key", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig = signer.sign("sign-key", b"hello world").unwrap();

        // DER signature starts with SEQUENCE tag 0x30
        assert_eq!(sig[0], 0x30);
        // Typical P-256 DER signature is 70-72 bytes
        assert!(
            sig.len() >= 68 && sig.len() <= 73,
            "sig len = {}",
            sig.len()
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_produces_different_output_for_different_data() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        signer
            .generate("diff-data", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let sig1 = signer.sign("diff-data", b"data one").unwrap();
        let sig2 = signer.sign("diff-data", b"data two").unwrap();
        assert_ne!(sig1, sig2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sign_fails_for_nonexistent_key() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer.sign("ghost", b"data").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_rejects_encryption_key_type() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let err = signer
            .generate("enc-key", KeyType::Encryption, AccessPolicy::None)
            .unwrap_err();
        match err {
            Error::KeyOperation { .. } => {}
            other => panic!("expected KeyOperation, got: {other}"),
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn public_key_matches_generated() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let generated = signer
            .generate("pk-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let retrieved = signer.public_key("pk-test").unwrap();
        assert_eq!(generated, retrieved);
        assert_eq!(retrieved.len(), 65);
        assert_eq!(retrieved[0], 0x04);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_and_delete_lifecycle() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        assert!(signer.list_keys().unwrap().is_empty());

        signer
            .generate("key-a", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        signer
            .generate("key-b", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-a", "key-b"]);

        signer.delete_key("key-a").unwrap();
        assert_eq!(signer.list_keys().unwrap(), vec!["key-b"]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_available_returns_true() {
        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();
        assert!(signer.is_available());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signature_can_be_verified_with_public_key() {
        use p256::ecdsa::{signature::Verifier, VerifyingKey};

        let dir = test_dir();
        let signer = SoftwareSigner::with_keys_dir("test", dir.clone()).without_keyring();

        let pub_bytes = signer
            .generate("verify-test", KeyType::Signing, AccessPolicy::None)
            .unwrap();
        let data = b"test message for verification";
        let sig_bytes = signer.sign("verify-test", data).unwrap();

        // Reconstruct the verifying key from the public key bytes
        let point = p256::EncodedPoint::from_bytes(&pub_bytes).unwrap();
        let verifying_key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = p256::ecdsa::DerSignature::from_bytes(&sig_bytes).unwrap();
        verifying_key.verify(data, &signature).unwrap();

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
