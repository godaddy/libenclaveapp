// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core TPM 2.0 operations shared between signing and encryption backends.

#![allow(unused_qualifications, let_underscore_drop)]

use enclaveapp_core::metadata;
use enclaveapp_core::{Error, Result};
use std::path::{Path, PathBuf};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context,
};

/// Try to open a TPM context.
pub fn open_context() -> Result<Context> {
    // Try kernel resource manager first (/dev/tpmrm0)
    let device_path = std::path::Path::new("/dev/tpmrm0");
    if device_path.exists() {
        let tcti = TctiNameConf::Device("/dev/tpmrm0".parse::<DeviceConfig>().map_err(|e| {
            Error::KeyOperation {
                operation: "parse_device_config".into(),
                detail: e.to_string(),
            }
        })?);
        return Context::new(tcti).map_err(|e| Error::KeyOperation {
            operation: "open_tpm".into(),
            detail: format!("device TCTI: {e}"),
        });
    }

    // Try tpm2-abrmd
    let tcti = TctiNameConf::Tabrmd(Default::default());
    Context::new(tcti).map_err(|e| Error::KeyOperation {
        operation: "open_tpm".into(),
        detail: format!("no TPM available (tried /dev/tpmrm0 and tpm2-abrmd): {e}"),
    })
}

pub fn is_available() -> bool {
    open_context().is_ok()
}

/// Build the primary ECC storage key template.
///
/// Uses ECC P-256 as a restricted decryption key under the owner hierarchy.
/// The template is deterministic so the same primary is recreated every time.
pub fn primary_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "primary_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| Error::KeyOperation {
                operation: "primary_params".into(),
                detail: e.to_string(),
            })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "primary_build".into(),
            detail: e.to_string(),
        })
}

/// Create the primary storage key. Returns its handle.
pub fn create_primary(ctx: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
    let template = primary_key_template()?;
    let result = ctx
        .create_primary(Hierarchy::Owner, template, None, None, None, None)
        .map_err(|e| Error::KeyOperation {
            operation: "create_primary".into(),
            detail: e.to_string(),
        })?;
    Ok(result.key_handle)
}

/// Build a child ECDSA P-256 signing key template (unrestricted).
pub fn signing_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "signing_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| Error::KeyOperation {
                operation: "signing_params".into(),
                detail: e.to_string(),
            })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "signing_build".into(),
            detail: e.to_string(),
        })
}

/// Build a child ECDH P-256 key template for encryption (unrestricted decryption).
pub fn encryption_key_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "encryption_template".into(),
            detail: e.to_string(),
        })?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_is_decryption_key(true)
                .build()
                .map_err(|e| Error::KeyOperation {
                    operation: "encryption_params".into(),
                    detail: e.to_string(),
                })?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::KeyOperation {
            operation: "encryption_build".into(),
            detail: e.to_string(),
        })
}

/// Extract 65-byte SEC1 uncompressed public key from a TPM ECC public structure.
pub fn extract_public_key(public: &Public) -> Result<Vec<u8>> {
    match public {
        Public::Ecc { unique, .. } => {
            let x = unique.x().value();
            let y = unique.y().value();
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            // Pad to 32 bytes each (P-256 coordinates are 32 bytes)
            let x_pad = 32usize.saturating_sub(x.len());
            point.extend(std::iter::repeat(0u8).take(x_pad));
            point.extend_from_slice(x);
            let y_pad = 32usize.saturating_sub(y.len());
            point.extend(std::iter::repeat(0u8).take(y_pad));
            point.extend_from_slice(y);
            Ok(point)
        }
        _ => Err(Error::KeyOperation {
            operation: "extract_public_key".into(),
            detail: "not an ECC key".into(),
        }),
    }
}

/// Configuration for the Linux TPM backend.
#[derive(Debug)]
pub struct TpmConfig {
    pub app_name: String,
    pub keys_dir_override: Option<PathBuf>,
}

impl TpmConfig {
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    pub fn with_keys_dir(app_name: &str, keys_dir: PathBuf) -> Self {
        Self {
            app_name: app_name.to_string(),
            keys_dir_override: Some(keys_dir),
        }
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.keys_dir_override
            .clone()
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

const TPM_BLOB_EXTENSIONS: [&str; 2] = ["tpm_pub", "tpm_priv"];

fn blob_path(dir: &Path, label: &str, extension: &str) -> Result<PathBuf> {
    enclaveapp_core::types::validate_label(label)?;
    Ok(dir.join(format!("{label}.{extension}")))
}

fn blob_paths(dir: &Path, label: &str) -> Result<[PathBuf; 2]> {
    Ok([
        blob_path(dir, label, TPM_BLOB_EXTENSIONS[0])?,
        blob_path(dir, label, TPM_BLOB_EXTENSIONS[1])?,
    ])
}

pub fn key_artifacts_exist(dir: &Path, label: &str) -> Result<bool> {
    Ok(key_blobs_exist(dir, label)? || metadata::key_files_exist(dir, label))
}

pub fn ensure_label_available(dir: &Path, label: &str) -> Result<()> {
    if key_artifacts_exist(dir, label)? {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }
    Ok(())
}

/// Save TPM key blobs (public + private) to disk.
/// The private blob is TPM-encrypted -- useless without the same physical TPM.
pub fn save_key_blobs(
    dir: &Path,
    label: &str,
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<()> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    metadata::atomic_write(&pub_path, public_blob)?;
    metadata::atomic_write(&priv_path, private_blob)?;
    metadata::restrict_file_permissions(&priv_path)?;
    Ok(())
}

/// Load TPM key blobs from disk.
pub fn load_key_blobs(dir: &Path, label: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    if !pub_path.exists() || !priv_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let public_blob = std::fs::read(&pub_path)?;
    let private_blob = std::fs::read(&priv_path)?;
    Ok((public_blob, private_blob))
}

/// Delete TPM key blob files.
pub fn delete_key_blobs(dir: &Path, label: &str) -> Result<()> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    if !pub_path.exists() && !priv_path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    for path in [pub_path, priv_path] {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

pub fn key_blobs_exist(dir: &Path, label: &str) -> Result<bool> {
    let [pub_path, priv_path] = blob_paths(dir, label)?;
    Ok(pub_path.exists() || priv_path.exists())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("enclaveapp-tpm-test-{pid}-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tpm_config_new_sets_app_name() {
        let config = TpmConfig::new("sshenc");
        assert_eq!(config.app_name, "sshenc");
        assert!(config.keys_dir_override.is_none());
    }

    #[test]
    fn tpm_config_with_keys_dir_overrides_path() {
        let custom = PathBuf::from("/tmp/custom-tpm-keys");
        let config = TpmConfig::with_keys_dir("sshenc", custom.clone());
        assert_eq!(config.app_name, "sshenc");
        assert_eq!(config.keys_dir_override, Some(custom.clone()));
        assert_eq!(config.keys_dir(), custom);
    }

    #[test]
    fn tpm_config_keys_dir_returns_default_when_no_override() {
        let config = TpmConfig::new("test-app");
        let expected = metadata::keys_dir("test-app");
        assert_eq!(config.keys_dir(), expected);
    }

    #[test]
    fn save_load_key_blobs_roundtrip() {
        let dir = test_dir();
        let pub_blob = b"fake-tpm-public-blob-data";
        let priv_blob = b"fake-tpm-private-blob-data";
        save_key_blobs(&dir, "mykey", pub_blob, priv_blob).unwrap();

        let (loaded_pub, loaded_priv) = load_key_blobs(&dir, "mykey").unwrap();
        assert_eq!(loaded_pub, pub_blob);
        assert_eq!(loaded_priv, priv_blob);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_blobs_removes_files() {
        let dir = test_dir();
        save_key_blobs(&dir, "delme", b"pub", b"priv").unwrap();
        assert!(dir.join("delme.tpm_pub").exists());
        assert!(dir.join("delme.tpm_priv").exists());

        delete_key_blobs(&dir, "delme").unwrap();
        assert!(!dir.join("delme.tpm_pub").exists());
        assert!(!dir.join("delme.tpm_priv").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_key_blobs_missing_returns_key_not_found() {
        let dir = test_dir();
        let err = load_key_blobs(&dir, "nonexistent").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nonexistent"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_key_blobs_missing_returns_key_not_found() {
        let dir = test_dir();
        let err = delete_key_blobs(&dir, "nonexistent").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "nonexistent"),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blob_helpers_reject_invalid_labels() {
        let dir = test_dir();
        assert!(save_key_blobs(&dir, "../bad", b"pub", b"priv").is_err());
        assert!(load_key_blobs(&dir, "../bad").is_err());
        assert!(delete_key_blobs(&dir, "../bad").is_err());
        assert!(key_blobs_exist(&dir, "../bad").is_err());
        assert!(ensure_label_available(&dir, "../bad").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
