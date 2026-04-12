// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `TpmEncryptor` — ECDH P-256 / ECIES encryption backend using the Windows TPM.

// This module wraps BCrypt/NCrypt C APIs which require unsafe FFI calls.
// The Windows crate's type conversions trigger trivial_casts and ptr_as_ptr
// for API-required pointer casts that cannot be simplified.
#![allow(unsafe_code, trivial_casts, clippy::ptr_as_ptr, unused_qualifications)]
//!
//! ## ECIES Wire Format
//!
//! ```text
//! [0x01] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
//! ```
//!
//! ## Encryption flow
//!
//! 1. Load the stored public key for the label.
//! 2. Generate an ephemeral ECDH P-256 key pair via `BCryptGenerateKeyPair`.
//! 3. Import the stored public key as a BCrypt key.
//! 4. `BCryptSecretAgreement` between the ephemeral private key and the stored
//!    public key.
//! 5. `BCryptDeriveKey` (HASH KDF with SHA-256) to produce a 32-byte AES key.
//! 6. AES-256-GCM encrypt with a random 12-byte nonce.
//! 7. Assemble the output.
//!
//! Decryption uses `NCryptSecretAgreement` (the TPM private key never leaves
//! the hardware) and otherwise mirrors the process.

use crate::convert::{eccpublic_blob_to_sec1, sec1_to_eccpublic_blob};
use crate::key;
use crate::provider;
use enclaveapp_core::metadata;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::validate_label;
use enclaveapp_core::{AccessPolicy, Error, KeyMeta, KeyType, Result};
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// ECDH P-256 algorithm identifier for CNG.
const ECDH_P256_ALGORITHM: &str = "ECDH_P256";

/// BCRYPT_ECDH_PUBLIC_P256_MAGIC (`ECK1`).
const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314B_4345;

/// Version byte prefixed to the ECIES ciphertext envelope.
const ECIES_VERSION: u8 = 0x01;

/// AES-GCM nonce size in bytes.
const GCM_NONCE_SIZE: usize = 12;
/// AES-GCM authentication tag size in bytes.
const GCM_TAG_SIZE: usize = 16;

/// Minimum ciphertext length: version(1) + ephemeral pub(65) + nonce(12) + tag(16).
const MIN_CIPHERTEXT_LEN: usize = 1 + 65 + GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Windows TPM-backed ECDH P-256 encryptor (ECIES).
#[derive(Debug)]
pub struct TpmEncryptor {
    app_name: String,
    keys_dir_override: Option<std::path::PathBuf>,
}

impl TpmEncryptor {
    /// Create a new encryptor for the given application.
    pub fn new(app_name: &str) -> Self {
        TpmEncryptor {
            app_name: app_name.to_string(),
            keys_dir_override: None,
        }
    }

    /// Create an encryptor with a custom keys directory path.
    pub fn with_keys_dir(app_name: &str, keys_dir: std::path::PathBuf) -> Self {
        TpmEncryptor {
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

impl EnclaveKeyManager for TpmEncryptor {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>> {
        validate_label(label)?;
        if key_type != KeyType::Encryption {
            return Err(Error::KeyOperation {
                operation: "generate".into(),
                detail: "TpmEncryptor only supports encryption keys".into(),
            });
        }

        let provider = provider::open_provider()?;
        let (_key_handle, pub_key) = key::create_key(
            &provider,
            &self.app_name,
            label,
            ECDH_P256_ALGORITHM,
            policy,
        )?;

        let dir = self.keys_dir();
        metadata::ensure_dir(&dir)?;
        let meta = KeyMeta::new(label, key_type, policy);
        metadata::save_meta(&dir, label, &meta)?;
        metadata::save_pub_key(&dir, label, &pub_key)?;

        Ok(pub_key)
    }

    fn public_key(&self, label: &str) -> Result<Vec<u8>> {
        validate_label(label)?;
        let dir = self.keys_dir();
        match metadata::load_pub_key(&dir, label) {
            Ok(pk) => Ok(pk),
            Err(_) => {
                let provider = provider::open_provider()?;
                let key_handle = key::open_key(&provider, &self.app_name, label)?;
                let pub_key = crate::export::export_public_key(&key_handle)?;
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

impl EnclaveEncryptor for TpmEncryptor {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;

        // 1. Load the stored public key (SEC1 uncompressed).
        let stored_pub = self.public_key(label)?;

        unsafe { ecies_encrypt(&stored_pub, plaintext) }
    }

    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_label(label)?;

        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(Error::DecryptFailed {
                detail: format!(
                    "ciphertext too short: {} < {MIN_CIPHERTEXT_LEN}",
                    ciphertext.len()
                ),
            });
        }
        if ciphertext[0] != ECIES_VERSION {
            return Err(Error::DecryptFailed {
                detail: format!("unsupported ECIES version: 0x{:02x}", ciphertext[0]),
            });
        }

        let ephemeral_pub = &ciphertext[1..66];
        let nonce = &ciphertext[66..66 + GCM_NONCE_SIZE];
        let ct_and_tag = &ciphertext[66 + GCM_NONCE_SIZE..];
        if ct_and_tag.len() < GCM_TAG_SIZE {
            return Err(Error::DecryptFailed {
                detail: "ciphertext too short for tag".into(),
            });
        }
        let ct = &ct_and_tag[..ct_and_tag.len() - GCM_TAG_SIZE];
        let tag = &ct_and_tag[ct_and_tag.len() - GCM_TAG_SIZE..];

        let provider = provider::open_provider()?;
        let key_handle = key::open_key(&provider, &self.app_name, label)?;

        unsafe { ecies_decrypt(&key_handle, ephemeral_pub, nonce, ct, tag) }
    }
}

// ─── Low-level ECIES helpers (unsafe, Windows-only) ─────────────

/// Encode a Rust `&str` as a null-terminated UTF-16 vector.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ECIES encrypt: ephemeral ECDH + AES-256-GCM.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn ecies_encrypt(stored_pub_sec1: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ecdh_alg_name = to_wide(ECDH_P256_ALGORITHM);
    let eccpub_blob_type = to_wide("ECCPUBLICBLOB");

    // Open BCrypt ECDH provider.
    let mut ecdh_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut ecdh_alg,
        PCWSTR(ecdh_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(ECDH): {e}"),
    })?;

    // Generate ephemeral key pair.
    let mut ephemeral_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateKeyPair(ecdh_alg, &mut ephemeral_key, 256, 0)
        .ok()
        .map_err(|e| {
            let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();
            Error::EncryptFailed {
                detail: format!("BCryptGenerateKeyPair: {e}"),
            }
        })?;
    BCryptFinalizeKeyPair(ephemeral_key, 0).ok().map_err(|e| {
        let _ = BCryptDestroyKey(ephemeral_key).ok();
        let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();
        Error::EncryptFailed {
            detail: format!("BCryptFinalizeKeyPair: {e}"),
        }
    })?;

    // Export ephemeral public key as SEC1 for the output envelope.
    let eph_pub_sec1 = {
        let mut sz: u32 = 0;
        BCryptExportKey(
            ephemeral_key,
            BCRYPT_KEY_HANDLE::default(),
            PCWSTR(eccpub_blob_type.as_ptr()),
            None,
            &mut sz,
            0,
        )
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptExportKey eph size: {e}"),
        })?;
        let mut blob = vec![0_u8; sz as usize];
        BCryptExportKey(
            ephemeral_key,
            BCRYPT_KEY_HANDLE::default(),
            PCWSTR(eccpub_blob_type.as_ptr()),
            Some(&mut blob),
            &mut sz,
            0,
        )
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptExportKey eph: {e}"),
        })?;
        blob.truncate(sz as usize);
        eccpublic_blob_to_sec1(&blob)?
    };

    // Import stored public key into BCrypt.
    let stored_blob = sec1_to_eccpublic_blob(stored_pub_sec1, BCRYPT_ECDH_PUBLIC_P256_MAGIC)?;
    let mut stored_key = BCRYPT_KEY_HANDLE::default();
    BCryptImportKeyPair(
        ecdh_alg,
        BCRYPT_KEY_HANDLE::default(),
        PCWSTR(eccpub_blob_type.as_ptr()),
        &mut stored_key,
        &stored_blob,
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptImportKeyPair: {e}"),
    })?;

    // ECDH: ephemeral private + stored public → shared secret.
    let mut secret = BCRYPT_SECRET_HANDLE::default();
    BCryptSecretAgreement(ephemeral_key, stored_key, &mut secret, 0)
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptSecretAgreement: {e}"),
        })?;

    // Derive 32-byte AES key via HASH KDF (SHA-256).
    let kdf_name = to_wide("HASH");
    let mut derived_key = vec![0_u8; 32];
    let mut derived_len: u32 = 0;
    BCryptDeriveKey(
        secret,
        PCWSTR(kdf_name.as_ptr()),
        None,
        Some(&mut derived_key),
        &mut derived_len,
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptDeriveKey: {e}"),
    })?;
    derived_key.truncate(derived_len as usize);

    // Cleanup ECDH handles.
    let _ = BCryptDestroySecret(secret).ok();
    let _ = BCryptDestroyKey(stored_key).ok();
    let _ = BCryptDestroyKey(ephemeral_key).ok();
    let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();

    // AES-256-GCM encrypt.
    let (nonce, tag, ct) = aes_gcm_encrypt(&derived_key, plaintext)?;

    // Assemble: [version] [ephemeral pub] [nonce] [ciphertext] [tag]
    let mut output = Vec::with_capacity(1 + 65 + GCM_NONCE_SIZE + ct.len() + GCM_TAG_SIZE);
    output.push(ECIES_VERSION);
    output.extend_from_slice(&eph_pub_sec1);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct);
    output.extend_from_slice(&tag);
    Ok(output)
}

/// ECIES decrypt using an NCrypt TPM key handle.
///
/// # Safety
/// Calls raw Win32 BCrypt/NCrypt APIs.
unsafe fn ecies_decrypt(
    tpm_key: &provider::NcryptHandle,
    ephemeral_pub_sec1: &[u8],
    nonce: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let ecdh_alg_name = to_wide(ECDH_P256_ALGORITHM);
    let eccpub_blob_type = to_wide("ECCPUBLICBLOB");

    // Open BCrypt ECDH provider.
    let mut ecdh_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut ecdh_alg,
        PCWSTR(ecdh_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(ECDH): {e}"),
    })?;

    // Import ephemeral public key.
    let eph_blob = sec1_to_eccpublic_blob(ephemeral_pub_sec1, BCRYPT_ECDH_PUBLIC_P256_MAGIC)?;
    let mut eph_key = BCRYPT_KEY_HANDLE::default();
    BCryptImportKeyPair(
        ecdh_alg,
        BCRYPT_KEY_HANDLE::default(),
        PCWSTR(eccpub_blob_type.as_ptr()),
        &mut eph_key,
        &eph_blob,
        0,
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptImportKeyPair(eph): {e}"),
    })?;

    // NCryptSecretAgreement: TPM private key + ephemeral public key.
    // We use the NCrypt variant because the private key lives in the TPM.
    // Convert BCRYPT_KEY_HANDLE → NCRYPT_KEY_HANDLE (both are opaque handles
    // to the same underlying CNG key object).
    let mut secret = NCRYPT_SECRET_HANDLE::default();
    NCryptSecretAgreement(
        tpm_key.as_key(),
        NCRYPT_KEY_HANDLE(eph_key.0 as usize),
        &mut secret,
        NCRYPT_FLAGS::default(),
    )
    .map_err(|e| Error::DecryptFailed {
        detail: format!("NCryptSecretAgreement: {e}"),
    })?;

    // Derive 32-byte AES key.
    let kdf_name = to_wide("HASH");
    let mut derived_key = vec![0_u8; 32];
    let mut derived_len: u32 = 0;
    NCryptDeriveKey(
        secret,
        PCWSTR(kdf_name.as_ptr()),
        None,
        Some(&mut derived_key),
        &mut derived_len,
        0_u32,
    )
    .map_err(|e| Error::DecryptFailed {
        detail: format!("NCryptDeriveKey: {e}"),
    })?;
    derived_key.truncate(derived_len as usize);

    let _ = NCryptFreeObject(NCRYPT_HANDLE(secret.0));
    let _ = BCryptDestroyKey(eph_key).ok();
    let _ = BCryptCloseAlgorithmProvider(ecdh_alg, 0).ok();

    // AES-256-GCM decrypt.
    aes_gcm_decrypt(&derived_key, nonce, ct, tag)
}

// ─── AES-256-GCM via BCrypt ────────────────────────────────────

/// AES-256-GCM encrypt. Returns `(nonce, tag, ciphertext)`.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn aes_gcm_encrypt(
    key_bytes: &[u8],
    plaintext: &[u8],
) -> Result<([u8; GCM_NONCE_SIZE], [u8; GCM_TAG_SIZE], Vec<u8>)> {
    let aes_alg_name = to_wide("AES");
    let chain_mode_prop = to_wide("ChainingMode");
    let gcm_mode = to_wide("ChainingModeGCM");

    let mut aes_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut aes_alg,
        PCWSTR(aes_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(AES): {e}"),
    })?;

    BCryptSetProperty(
        aes_alg.into(),
        PCWSTR(chain_mode_prop.as_ptr()),
        std::slice::from_raw_parts(gcm_mode.as_ptr() as *const u8, gcm_mode.len() * 2),
        0,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptSetProperty(GCM): {e}"),
    })?;

    let mut aes_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateSymmetricKey(aes_alg, &mut aes_key, None, key_bytes, 0)
        .ok()
        .map_err(|e| Error::EncryptFailed {
            detail: format!("BCryptGenerateSymmetricKey: {e}"),
        })?;

    // Random nonce.
    let mut nonce = [0_u8; GCM_NONCE_SIZE];
    BCryptGenRandom(
        BCRYPT_ALG_HANDLE::default(),
        &mut nonce,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptGenRandom: {e}"),
    })?;

    let mut tag = [0_u8; GCM_TAG_SIZE];
    let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1, // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
        pbNonce: nonce.as_mut_ptr(),
        cbNonce: GCM_NONCE_SIZE as u32,
        pbAuthData: ptr::null_mut(),
        cbAuthData: 0,
        pbTag: tag.as_mut_ptr(),
        cbTag: GCM_TAG_SIZE as u32,
        pbMacContext: ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut ciphertext = vec![0_u8; plaintext.len()];
    let mut ct_len: u32 = 0;
    BCryptEncrypt(
        aes_key,
        Some(plaintext),
        Some(&auth_info as *const _ as *const _),
        None,
        Some(&mut ciphertext),
        &mut ct_len,
        BCRYPT_FLAGS::default(),
    )
    .ok()
    .map_err(|e| Error::EncryptFailed {
        detail: format!("BCryptEncrypt(AES-GCM): {e}"),
    })?;
    ciphertext.truncate(ct_len as usize);

    let _ = BCryptDestroyKey(aes_key).ok();
    let _ = BCryptCloseAlgorithmProvider(aes_alg, 0).ok();

    Ok((nonce, tag, ciphertext))
}

/// AES-256-GCM decrypt.
///
/// # Safety
/// Calls raw Win32 BCrypt APIs.
unsafe fn aes_gcm_decrypt(
    key_bytes: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let aes_alg_name = to_wide("AES");
    let chain_mode_prop = to_wide("ChainingMode");
    let gcm_mode = to_wide("ChainingModeGCM");

    let mut aes_alg = BCRYPT_ALG_HANDLE::default();
    BCryptOpenAlgorithmProvider(
        &mut aes_alg,
        PCWSTR(aes_alg_name.as_ptr()),
        None,
        Default::default(),
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptOpenAlgorithmProvider(AES): {e}"),
    })?;

    BCryptSetProperty(
        aes_alg.into(),
        PCWSTR(chain_mode_prop.as_ptr()),
        std::slice::from_raw_parts(gcm_mode.as_ptr() as *const u8, gcm_mode.len() * 2),
        0,
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptSetProperty(GCM): {e}"),
    })?;

    let mut aes_key = BCRYPT_KEY_HANDLE::default();
    BCryptGenerateSymmetricKey(aes_alg, &mut aes_key, None, key_bytes, 0)
        .ok()
        .map_err(|e| Error::DecryptFailed {
            detail: format!("BCryptGenerateSymmetricKey: {e}"),
        })?;

    let mut nonce_copy = [0_u8; GCM_NONCE_SIZE];
    nonce_copy[..nonce.len()].copy_from_slice(nonce);
    let mut tag_copy = [0_u8; GCM_TAG_SIZE];
    tag_copy[..tag.len()].copy_from_slice(tag);

    let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1,
        pbNonce: nonce_copy.as_mut_ptr(),
        cbNonce: GCM_NONCE_SIZE as u32,
        pbAuthData: ptr::null_mut(),
        cbAuthData: 0,
        pbTag: tag_copy.as_mut_ptr(),
        cbTag: GCM_TAG_SIZE as u32,
        pbMacContext: ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut plaintext = vec![0_u8; ciphertext.len()];
    let mut pt_len: u32 = 0;
    BCryptDecrypt(
        aes_key,
        Some(ciphertext),
        Some(&auth_info as *const _ as *const _),
        None,
        Some(&mut plaintext),
        &mut pt_len,
        BCRYPT_FLAGS::default(),
    )
    .ok()
    .map_err(|e| Error::DecryptFailed {
        detail: format!("BCryptDecrypt(AES-GCM): {e}"),
    })?;
    plaintext.truncate(pt_len as usize);

    let _ = BCryptDestroyKey(aes_key).ok();
    let _ = BCryptCloseAlgorithmProvider(aes_alg, 0).ok();

    Ok(plaintext)
}
