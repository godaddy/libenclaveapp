// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key lifecycle operations shared between signing and encryption backends.
//!
//! Handles file storage (.handle, .pub, .meta), key listing, loading, and deletion.

use crate::ffi;
use enclaveapp_core::metadata::{self, KeyMeta};
use enclaveapp_core::types::{validate_label, KeyType};
use enclaveapp_core::{Error, Result};
use std::path::PathBuf;

const SE_ERR_BUFFER_TOO_SMALL: i32 = 4;

/// Configuration for keychain operations, scoped to an application.
#[derive(Debug)]
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
            .unwrap_or_else(|| metadata::keys_dir(&self.app_name))
    }
}

/// Check if the Secure Enclave is available.
#[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
pub fn is_available() -> bool {
    unsafe { ffi::enclaveapp_se_available() == 1 }
}

/// Generate a new Secure Enclave key.
/// Returns (uncompressed_public_key_65_bytes, data_representation).
#[allow(unsafe_code)] // FFI calls to CryptoKit Swift bridge
pub fn generate_key(key_type: KeyType, auth_policy: i32) -> Result<(Vec<u8>, Vec<u8>)> {
    if !is_available() {
        return Err(Error::NotAvailable);
    }

    match key_type {
        KeyType::Signing => {
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| unsafe {
                ffi::enclaveapp_se_generate_signing_key(
                    pub_key,
                    pub_key_len,
                    data_rep,
                    data_rep_len,
                    auth_policy,
                )
            })
        }
        KeyType::Encryption => {
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| unsafe {
                ffi::enclaveapp_se_generate_encryption_key(
                    pub_key,
                    pub_key_len,
                    data_rep,
                    data_rep_len,
                    auth_policy,
                )
            })
        }
    }
}

fn generate_key_with_retry<F>(mut generate_ffi: F) -> Result<(Vec<u8>, Vec<u8>)>
where
    F: FnMut(*mut u8, *mut i32, *mut u8, *mut i32) -> i32,
{
    /// Hard cap on resize retries. `SE_ERR_BUFFER_TOO_SMALL` is only
    /// ever legitimately raised by a genuine buffer-sizing shortfall,
    /// which converges in one retry with the Swift-reported length.
    /// Capping at 4 keeps a Swift-side contract bug (e.g. the FFI
    /// starts returning `SE_ERR_BUFFER_TOO_SMALL` for some other
    /// condition) from spinning forever; we surface it as a hard
    /// error the developer can see.
    const MAX_RESIZE_RETRIES: usize = 4;
    /// Uncompressed P-256 public key is always 65 bytes. We allocate
    /// exactly that size and never grow it. If the FFI reports
    /// `pub_key_len > 65`, something violated the contract — surface
    /// it explicitly rather than blindly resizing.
    const UNCOMPRESSED_P256_PUBKEY_LEN: usize = 65;

    let mut data_rep_capacity = 1024_usize;

    for _ in 0..MAX_RESIZE_RETRIES {
        let mut pub_key = vec![0_u8; UNCOMPRESSED_P256_PUBKEY_LEN];
        let mut pub_key_len: i32 = UNCOMPRESSED_P256_PUBKEY_LEN as i32;
        let mut data_rep = vec![0_u8; data_rep_capacity];
        let mut data_rep_len: i32 = data_rep_capacity as i32;

        let rc = generate_ffi(
            pub_key.as_mut_ptr(),
            &mut pub_key_len,
            data_rep.as_mut_ptr(),
            &mut data_rep_len,
        );

        if rc == SE_ERR_BUFFER_TOO_SMALL {
            // Swift's contract for this code: `*_len.pointee` now
            // holds the required size. Honor it only if it's
            // strictly greater than what we sent — otherwise the
            // return code is being used for something other than
            // "need more buffer space," which is a contract
            // violation we refuse to paper over with a retry.
            let returned = usize::try_from(data_rep_len).unwrap_or(0);
            if returned > data_rep_capacity {
                data_rep_capacity = returned;
                continue;
            }
            return Err(Error::GenerateFailed {
                detail: format!(
                    "FFI reported SE_ERR_BUFFER_TOO_SMALL but did not grow data_rep_len \
                     (sent {data_rep_capacity} bytes, got back {returned}) — \
                     Swift bridge contract violation"
                ),
            });
        }

        if rc != 0 {
            return Err(Error::GenerateFailed {
                detail: format!("FFI returned error code {rc}"),
            });
        }

        // Contract sanity: pub_key buffer is fixed at 65 bytes.
        let pub_key_len_usize = usize::try_from(pub_key_len).unwrap_or(0);
        if pub_key_len_usize > UNCOMPRESSED_P256_PUBKEY_LEN {
            return Err(Error::GenerateFailed {
                detail: format!(
                    "FFI reported pub_key_len = {pub_key_len_usize} but the buffer is \
                     fixed at {UNCOMPRESSED_P256_PUBKEY_LEN} bytes — Swift bridge contract violation"
                ),
            });
        }

        pub_key.truncate(pub_key_len_usize);
        let data_rep_len_usize = usize::try_from(data_rep_len).unwrap_or(0);
        data_rep.truncate(data_rep_len_usize);
        return Ok((pub_key, data_rep));
    }

    Err(Error::GenerateFailed {
        detail: format!(
            "Swift bridge repeatedly returned SE_ERR_BUFFER_TOO_SMALL after {MAX_RESIZE_RETRIES} \
             retries — contract violation"
        ),
    })
}

/// Generate a Secure Enclave key and persist its local metadata atomically.
///
/// The SE `dataRepresentation` handle is wrapped with AES-256-GCM under a
/// fresh 32-byte key stored in the macOS login keychain before being
/// written to `.handle` on disk. See [`crate::keychain_wrap`] for the
/// rationale and ciphertext format.
///
/// If any step after the SE key was created fails, the SE key is deleted
/// and the keychain wrapping-key entry is cleaned up so the label is
/// free to reuse.
pub fn generate_and_save_key(
    config: &KeychainConfig,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;
    let _lock = metadata::DirLock::acquire(&dir)?;
    prepare_label_for_save(&dir, label)?;

    let (pub_key, data_rep) = generate_key(key_type, policy.as_ffi_value())?;

    // Generate a fresh wrapping key and store it in the keychain BEFORE
    // encrypting, so a failure on either side leaves a consistent state.
    let wrapping_key = crate::keychain_wrap::generate_wrapping_key();
    let app_name = config.app_name.clone();
    let app_name_for_cleanup = app_name.clone();
    let label_owned = label.to_string();
    if let Err(error) = crate::keychain_wrap::keychain_store(&app_name, label, &wrapping_key) {
        // The SE key was created but we can't store its wrapping key —
        // roll back the SE key so we don't leave an orphaned key that
        // we can never reload.
        drop(delete_key_from_data_rep(&data_rep));
        return Err(error);
    }

    let wrapped_blob = match crate::keychain_wrap::encrypt_blob(&wrapping_key, &data_rep) {
        Ok(blob) => blob,
        Err(error) => {
            drop(crate::keychain_wrap::keychain_delete(&app_name, label));
            drop(delete_key_from_data_rep(&data_rep));
            return Err(error);
        }
    };

    let cleanup = move || {
        drop(crate::keychain_wrap::keychain_delete(
            &app_name_for_cleanup,
            &label_owned,
        ));
        delete_key_from_data_rep(&data_rep)
    };
    persist_saved_key_material(
        &dir,
        label,
        key_type,
        policy,
        &wrapped_blob,
        &pub_key,
        cleanup,
    )?;

    Ok(pub_key)
}

/// Extract the public key from a persisted data representation.
/// Returns 65-byte uncompressed public key.
#[allow(unsafe_code)] // FFI calls to CryptoKit Swift bridge
pub fn public_key_from_data_rep(key_type: KeyType, data_rep: &[u8]) -> Result<Vec<u8>> {
    let mut pub_key = vec![0_u8; 65];
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
#[cfg_attr(not(test), allow(dead_code))]
fn save_key(
    config: &KeychainConfig,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
    data_rep: &[u8],
    pub_key: &[u8],
) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    metadata::ensure_dir(&dir)?;

    let _lock = metadata::DirLock::acquire(&dir)?;
    prepare_label_for_save(&dir, label)?;

    persist_saved_key_material(&dir, label, key_type, policy, data_rep, pub_key, || {
        delete_key_from_data_rep(data_rep)
    })
}

/// Load a key's data representation from the keys directory.
///
/// The `.handle` file may be either a wrapped blob (magic prefix `EHW1`)
/// or a legacy plaintext CryptoKit `dataRepresentation`. Wrapped blobs
/// are decrypted with the wrapping key loaded from the login keychain;
/// legacy plaintext blobs are returned unchanged for transparent
/// migration — they'll be re-wrapped the next time `generate_and_save_key`
/// replaces the label.
pub fn load_handle(config: &KeychainConfig, label: &str) -> Result<Vec<u8>> {
    validate_label(label)?;
    let path = config.keys_dir().join(format!("{label}.handle"));
    if !path.exists() {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let contents = metadata::read_no_follow(&path)?;

    if !crate::keychain_wrap::is_wrapped_handle(&contents) {
        // Legacy plaintext handle (pre-EHW1). Return as-is; the caller
        // can sign/decrypt directly, and the next rotation picks up
        // the wrapping. Logged for visibility.
        tracing::debug!(
            label = label,
            "loaded legacy plaintext SE handle; re-save to upgrade to wrapped format"
        );
        return Ok(contents);
    }

    let wrapping_key = match crate::keychain_wrap::keychain_load(&config.app_name, label)? {
        Some(k) => k,
        None => {
            return Err(Error::KeyOperation {
                operation: "load_handle".into(),
                detail: format!(
                    "wrapped handle for label `{label}` is missing its keychain wrapping key; \
                    the keychain entry may have been deleted or the user denied access"
                ),
            });
        }
    };
    crate::keychain_wrap::decrypt_blob(&wrapping_key, &contents)
}

/// Load the cached public key for a label. Falls back to extracting from data rep.
pub fn load_pub_key(config: &KeychainConfig, label: &str, key_type: KeyType) -> Result<Vec<u8>> {
    validate_label(label)?;
    let dir = config.keys_dir();
    let data_rep = load_handle(config, label)?;
    let pub_key = public_key_from_data_rep(key_type, &data_rep)?;
    metadata::sync_pub_key(&dir, label, &pub_key)
}

/// List all key labels in the keys directory.
pub fn list_labels(config: &KeychainConfig) -> Result<Vec<String>> {
    metadata::list_labels_for_extensions(&config.keys_dir(), &["meta", "handle"])
}

/// Delete a key and all associated files.
///
/// Also removes the key's wrapping-key entry from the login keychain.
/// The keychain removal is best-effort — if it fails for any reason
/// other than "not found" the overall delete still proceeds so the
/// on-disk state isn't left half-cleaned. A leftover keychain entry
/// is harmless if the `.handle` file is gone (no one can use it).
pub fn delete_key(config: &KeychainConfig, label: &str) -> Result<()> {
    validate_label(label)?;
    let dir = config.keys_dir();
    let handle_path = dir.join(format!("{label}.handle"));
    let key_exists =
        dir.exists() && (handle_path.exists() || metadata::key_files_exist(&dir, label)?);
    if !key_exists {
        return Err(Error::KeyNotFound {
            label: label.to_string(),
        });
    }
    let _lock = metadata::DirLock::acquire(&dir)?;
    let result = match load_handle(config, label) {
        Ok(data_rep) => {
            delete_key_from_data_rep(&data_rep).map_err(|error| Error::KeyOperation {
                operation: "delete_key".into(),
                detail: format!("delete Secure Enclave key: {error}"),
            })?;
            metadata::delete_key_files(&dir, label)
        }
        Err(Error::KeyNotFound { .. }) => metadata::delete_key_files(&dir, label),
        Err(error) => Err(Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!(
                "failed to read Secure Enclave handle; preserving local key material for retry: {error}"
            ),
        }),
    };

    // Clean up the keychain wrapping-key entry regardless of whether
    // the local files were fully removed. If it fails here, log but
    // don't propagate — a stale keychain entry without its handle is
    // useless.
    if let Err(error) = crate::keychain_wrap::keychain_delete(&config.app_name, label) {
        tracing::warn!(
            label = label,
            "keychain_delete failed during delete_key (harmless if the handle is already gone): {error}"
        );
    }

    result
}

#[allow(unsafe_code)] // FFI call to CryptoKit Swift bridge
fn delete_key_from_data_rep(data_rep: &[u8]) -> Result<()> {
    let rc = unsafe { ffi::enclaveapp_se_delete_key(data_rep.as_ptr(), data_rep.len() as i32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!("FFI returned error code {rc}"),
        })
    }
}

fn persist_saved_key_material<F>(
    dir: &std::path::Path,
    label: &str,
    key_type: KeyType,
    policy: enclaveapp_core::AccessPolicy,
    data_rep: &[u8],
    pub_key: &[u8],
    cleanup_created_key: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let handle_path = dir.join(format!("{label}.handle"));

    if let Err(error) = metadata::atomic_write(&handle_path, data_rep) {
        return Err(with_cleanup_context(
            "persist handle",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }
    if let Err(error) = metadata::restrict_file_permissions(&handle_path) {
        return Err(with_cleanup_context(
            "persist handle permissions",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }
    if let Err(error) = metadata::save_pub_key(dir, label, pub_key) {
        return Err(with_cleanup_context(
            "persist public key cache",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }

    let meta = KeyMeta::new(label, key_type, policy);
    if let Err(error) = metadata::save_meta(dir, label, &meta) {
        return Err(with_cleanup_context(
            "persist metadata",
            error,
            dir,
            label,
            cleanup_created_key,
        ));
    }

    Ok(())
}

fn prepare_label_for_save(dir: &std::path::Path, label: &str) -> Result<()> {
    let handle_path = dir.join(format!("{label}.handle"));
    let other_files_exist = metadata::key_files_exist(dir, label)?;
    if !handle_path.exists() && !other_files_exist {
        return Ok(());
    }

    if !handle_path.exists() {
        return metadata::delete_key_files(dir, label);
    }

    let data_rep = metadata::read_no_follow(&handle_path).map_err(|error| Error::KeyOperation {
        operation: "prepare_label_for_save".into(),
        detail: format!("failed to read existing Secure Enclave handle: {error}"),
    })?;

    if public_key_from_data_rep(KeyType::Signing, &data_rep).is_ok()
        || public_key_from_data_rep(KeyType::Encryption, &data_rep).is_ok()
    {
        return Err(Error::DuplicateLabel {
            label: label.to_string(),
        });
    }

    delete_key_from_data_rep(&data_rep).map_err(|error| Error::KeyOperation {
        operation: "prepare_label_for_save".into(),
        detail: format!(
            "failed to delete existing Secure Enclave key before reusing label: {error}"
        ),
    })?;

    metadata::delete_key_files(dir, label)
}

fn cleanup_persisted_key_material(dir: &std::path::Path, label: &str) -> Result<()> {
    for extension in ["handle", "pub", "meta", "ssh.pub"] {
        let path = dir.join(format!("{label}.{extension}"));
        if path.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn with_cleanup_context<F>(
    operation: &str,
    error: Error,
    dir: &std::path::Path,
    label: &str,
    cleanup_created_key: F,
) -> Error
where
    F: FnOnce() -> Result<()>,
{
    let mut cleanup_failures = Vec::new();

    if let Err(cleanup_error) = cleanup_persisted_key_material(dir, label) {
        cleanup_failures.push(format!("remove persisted key files: {cleanup_error}"));
    }
    if let Err(cleanup_error) = cleanup_created_key() {
        cleanup_failures.push(format!("delete Secure Enclave key: {cleanup_error}"));
    }

    if cleanup_failures.is_empty() {
        error
    } else {
        Error::GenerateFailed {
            detail: format!(
                "{operation} failed: {error}; cleanup failed: {}",
                cleanup_failures.join("; ")
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keychain_config_new_sets_app_name() {
        let config = KeychainConfig::new("sshenc");
        assert_eq!(config.app_name, "sshenc");
        assert!(config.keys_dir_override.is_none());
    }

    #[test]
    fn keychain_config_new_different_app_name() {
        let config = KeychainConfig::new("awsenc");
        assert_eq!(config.app_name, "awsenc");
    }

    #[test]
    #[allow(unsafe_code)]
    fn generate_key_with_retry_resizes_data_rep_buffer() {
        let mut attempts = 0;
        let (pub_key, data_rep) =
            generate_key_with_retry(|pub_key, pub_key_len, data_rep, data_rep_len| {
                attempts += 1;
                if attempts == 1 {
                    unsafe {
                        *data_rep_len = 2048;
                    }
                    return SE_ERR_BUFFER_TOO_SMALL;
                }

                unsafe {
                    *pub_key_len = 65;
                    *data_rep_len = 2048;
                    std::ptr::write_bytes(pub_key, 0x04, 65);
                    std::ptr::write_bytes(data_rep, 0xAB, 2048);
                }
                0
            })
            .unwrap();

        assert_eq!(attempts, 2);
        assert_eq!(pub_key.len(), 65);
        assert_eq!(data_rep.len(), 2048);
        assert!(data_rep.iter().all(|byte| *byte == 0xAB));
    }

    #[test]
    fn keychain_config_with_keys_dir_overrides_path() {
        let custom = PathBuf::from("/tmp/custom-keys");
        let config = KeychainConfig::with_keys_dir("sshenc", custom.clone());
        assert_eq!(config.app_name, "sshenc");
        assert_eq!(config.keys_dir_override, Some(custom));
    }

    #[test]
    fn keys_dir_returns_default_when_no_override() {
        let config = KeychainConfig::new("test-app");
        let dir = config.keys_dir();
        // Should use the platform default from metadata::keys_dir
        let expected = metadata::keys_dir("test-app");
        assert_eq!(dir, expected);
    }

    #[test]
    fn keys_dir_returns_override_when_set() {
        let custom = PathBuf::from("/tmp/my-custom-keys");
        let config = KeychainConfig::with_keys_dir("test-app", custom.clone());
        assert_eq!(config.keys_dir(), custom);
    }

    #[test]
    fn delete_missing_key_in_missing_dir_returns_key_not_found() {
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-apple-missing-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);
        let err = delete_key(&config, "ghost").unwrap_err();
        match err {
            Error::KeyNotFound { label } => assert_eq!(label, "ghost"),
            other => panic!("expected KeyNotFound, got {other}"),
        }
    }

    #[test]
    fn keychain_operations_reject_invalid_labels() {
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-apple-invalid-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);

        let err = load_handle(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = load_pub_key(&config, "../escape", KeyType::Signing).unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));

        let err = delete_key(&config, "../escape").unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));
    }

    #[test]
    fn save_key_rejects_invalid_labels() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-save-invalid-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&dir));
        let config = KeychainConfig::with_keys_dir("test-app", dir);

        let err = save_key(
            &config,
            "../escape",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            b"pub",
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidLabel { .. }));
    }

    #[test]
    fn save_key_recovers_stale_metadata_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-duplicate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("existing.pub"), b"pub").unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        save_key(
            &config,
            "existing",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            &[0x04; 65],
        )
        .unwrap();
        assert!(dir.join("existing.handle").exists());
        assert!(dir.join("existing.pub").exists());
        assert!(dir.join("existing.meta").exists());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn persist_saved_key_material_cleans_up_files_and_invokes_key_cleanup() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-persist-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir(dir.join("work.meta")).unwrap();

        let mut cleaned_up = false;
        let err = persist_saved_key_material(
            &dir,
            "work",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"handle",
            &[0x04; 65],
            || {
                cleaned_up = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(err, Error::Io(_) | Error::GenerateFailed { .. }));
        assert!(
            cleaned_up,
            "generated Secure Enclave key should be cleaned up"
        );
        assert!(!dir.join("work.handle").exists());
        assert!(!dir.join("work.pub").exists());
        assert!(dir.join("work.meta").is_dir());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delete_key_preserves_files_when_handle_cannot_be_read() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-delete-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let handle_path = dir.join("work.handle");
        std::fs::write(&handle_path, b"handle").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        metadata::save_pub_key(&dir, "work", &[0x04; 65]).unwrap();
        metadata::save_meta(
            &dir,
            "work",
            &KeyMeta::new(
                "work",
                KeyType::Signing,
                enclaveapp_core::AccessPolicy::None,
            ),
        )
        .unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        let err = delete_key(&config, "work").unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));
        assert!(dir.join("work.handle").exists());
        assert!(dir.join("work.pub").exists());
        assert!(dir.join("work.meta").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_labels_includes_handle_without_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-list-live-handle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("alpha.handle"), b"handle").unwrap();
        std::fs::write(dir.join("beta.meta"), b"{}").unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        assert_eq!(list_labels(&config).unwrap(), vec!["alpha", "beta"]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_pub_key_repairs_mismatched_cache_from_handle() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-load-pub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        metadata::save_pub_key(&dir, "cached", &[0x04; 65]).unwrap();
        metadata::atomic_write(&dir.join("cached.handle"), &[0_u8; 32]).unwrap();

        let err = load_pub_key(&config, "cached", KeyType::Signing).unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn save_key_preserves_unreadable_handle_and_reports_error() {
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-apple-save-unreadable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let handle_path = dir.join("existing.handle");
        std::fs::write(&handle_path, b"handle").unwrap();
        metadata::save_pub_key(&dir, "existing", &[0x04; 65]).unwrap();
        metadata::save_meta(
            &dir,
            "existing",
            &KeyMeta::new(
                "existing",
                KeyType::Signing,
                enclaveapp_core::AccessPolicy::None,
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        let config = KeychainConfig::with_keys_dir("test-app", dir.clone());
        let err = save_key(
            &config,
            "existing",
            KeyType::Signing,
            enclaveapp_core::AccessPolicy::None,
            b"new-handle",
            &[0x04; 65],
        )
        .unwrap_err();
        assert!(matches!(err, Error::KeyOperation { .. }));
        assert!(dir.join("existing.handle").exists());
        assert!(dir.join("existing.pub").exists());
        assert!(dir.join("existing.meta").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&handle_path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
