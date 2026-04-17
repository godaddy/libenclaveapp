// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Keychain-backed wrapping of Secure Enclave `dataRepresentation` handles.
//!
//! Unsigned / ad-hoc signed macOS builds cannot use SE keys via the modern
//! `kSecAttrTokenIDSecureEnclave` path (it requires a provisioning profile
//! that self-signed binaries cannot satisfy — AMFI kills the process). The
//! alternative is CryptoKit's `SecureEnclave.P256.*.PrivateKey` which
//! exposes a `dataRepresentation: Data` — an opaque handle blob that lets
//! the same device's SE reconstruct the key.
//!
//! The private key itself stays inside the SE. But the handle is on disk,
//! and any same-UID process that reads the file can use it to drive SE
//! operations as us (sign / decrypt). That defeats the only protection
//! the SE model offers against same-UID attackers.
//!
//! This module wraps the handle at rest with AES-256-GCM. The 32-byte
//! wrapping key is stored in the macOS login keychain as a
//! `kSecClassGenericPassword` item. The legacy keychain's access control
//! is bound to the binary's code-signing identity:
//!
//! - Ad-hoc signed (`swiftc`/`rustc` default): one "Always Allow" prompt
//!   per binary hash. After `brew upgrade` the hash changes and the user
//!   is prompted once; subsequent runs are silent until the next upgrade.
//! - Trusted signing identity (Apple Developer ID): transparent across
//!   upgrades — no prompts.
//! - Different binary at different path: always prompted, regardless of
//!   signing.
//!
//! Ciphertext format on disk (replaces the old plain `dataRepresentation`):
//!
//! ```text
//!   [4 bytes magic = "EHW1"] [12 bytes nonce] [ciphertext] [16 bytes tag]
//! ```
//!
//! The magic is both a version marker and the backward-compat sentinel.
//! `load_handle` tries to parse this format first; a legacy `.handle`
//! file that doesn't start with `EHW1` is read as-is, and the caller
//! can re-save it to migrate transparently.

// aes-gcm's Nonce::from_slice still works but triggers a deprecation on
// the transitively-pulled generic-array 0.14; the 1.x migration is
// upstream work in aes-gcm. Silence the warning here so we don't
// block the workspace.
#![allow(deprecated)]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use enclaveapp_core::{Error, Result};
use rand::TryRngCore;

use crate::ffi;

/// Magic bytes that identify a wrapped handle file. The "1" is a format
/// version — if we ever change the wrapping scheme we bump it and keep
/// the old parser for backward compat.
pub(crate) const WRAP_MAGIC: &[u8; 4] = b"EHW1";

/// 32 bytes for AES-256.
pub(crate) const WRAP_KEY_LEN: usize = 32;

/// 12 bytes — AES-GCM standard nonce size.
pub(crate) const WRAP_NONCE_LEN: usize = 12;

/// 16 bytes — AES-GCM tag size.
pub(crate) const WRAP_TAG_LEN: usize = 16;

/// Minimum valid wrapped blob: magic + nonce + empty ciphertext + tag.
pub(crate) const WRAP_MIN_LEN: usize = WRAP_MAGIC.len() + WRAP_NONCE_LEN + WRAP_TAG_LEN;

/// `true` if `bytes` starts with the wrapped-handle magic prefix.
#[must_use]
pub fn is_wrapped_handle(bytes: &[u8]) -> bool {
    bytes.len() >= WRAP_MAGIC.len() && &bytes[..WRAP_MAGIC.len()] == WRAP_MAGIC
}

/// Generate a fresh 32-byte AES-256 wrapping key from the OS CSPRNG.
#[must_use]
pub fn generate_wrapping_key() -> [u8; WRAP_KEY_LEN] {
    let mut key = [0_u8; WRAP_KEY_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut key)
        .expect("OS RNG must succeed");
    key
}

/// Encrypt a handle blob under the given wrapping key using AES-256-GCM.
///
/// Returns `magic || nonce || ciphertext || tag`. Empty plaintext is
/// handled; the output is always at least `WRAP_MIN_LEN` bytes.
pub fn encrypt_blob(wrapping_key: &[u8; WRAP_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|e| Error::KeyOperation {
        operation: "keychain_wrap_encrypt".into(),
        detail: format!("Aes256Gcm::new: {e}"),
    })?;
    let mut nonce_bytes = [0_u8; WRAP_NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| Error::KeyOperation {
            operation: "keychain_wrap_encrypt".into(),
            detail: format!("OS RNG failed: {e}"),
        })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::KeyOperation {
            operation: "keychain_wrap_encrypt".into(),
            detail: format!("AES-GCM encrypt: {e}"),
        })?;

    let mut out = Vec::with_capacity(WRAP_MAGIC.len() + nonce_bytes.len() + ct.len());
    out.extend_from_slice(WRAP_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a wrapped handle blob. Returns the original `dataRepresentation`.
///
/// Input must start with `WRAP_MAGIC`; call [`is_wrapped_handle`] first.
pub fn decrypt_blob(wrapping_key: &[u8; WRAP_KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < WRAP_MIN_LEN {
        return Err(Error::KeyOperation {
            operation: "keychain_wrap_decrypt".into(),
            detail: format!(
                "wrapped blob too short: {} bytes, need >= {WRAP_MIN_LEN}",
                blob.len()
            ),
        });
    }
    if !is_wrapped_handle(blob) {
        return Err(Error::KeyOperation {
            operation: "keychain_wrap_decrypt".into(),
            detail: "wrapped blob missing magic prefix".into(),
        });
    }

    let nonce_start = WRAP_MAGIC.len();
    let ct_start = nonce_start + WRAP_NONCE_LEN;
    let nonce = Nonce::from_slice(&blob[nonce_start..ct_start]);
    let ct_and_tag = &blob[ct_start..];

    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|e| Error::KeyOperation {
        operation: "keychain_wrap_decrypt".into(),
        detail: format!("Aes256Gcm::new: {e}"),
    })?;
    cipher
        .decrypt(nonce, ct_and_tag)
        .map_err(|e| Error::KeyOperation {
            operation: "keychain_wrap_decrypt".into(),
            detail: format!("AES-GCM decrypt: {e}"),
        })
}

/// Compose the keychain service name used for all wrapping keys of a
/// given app. The account is the key `<label>` so every key gets its own
/// wrapping-key entry.
pub fn service_name_for(app_name: &str) -> String {
    format!("com.libenclaveapp.{app_name}")
}

/// Store a wrapping key in the login keychain. Replaces any existing
/// entry for the same service+account pair.
#[allow(unsafe_code)]
pub fn keychain_store(
    app_name: &str,
    label: &str,
    wrapping_key: &[u8; WRAP_KEY_LEN],
) -> Result<()> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();

    // i32 length fields in the Swift signature. Guard against >2GB.
    let service_len = i32::try_from(service_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "keychain_store".into(),
        detail: "service name too long".into(),
    })?;
    let account_len = i32::try_from(account_bytes.len()).map_err(|_| Error::KeyOperation {
        operation: "keychain_store".into(),
        detail: "account name too long".into(),
    })?;
    let secret_len = i32::try_from(wrapping_key.len()).map_err(|_| Error::KeyOperation {
        operation: "keychain_store".into(),
        detail: "secret length too long".into(),
    })?;

    let rc = unsafe {
        ffi::enclaveapp_keychain_store(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            wrapping_key.as_ptr(),
            secret_len,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::KeyOperation {
            operation: "keychain_store".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        })
    }
}

/// Load a wrapping key from the login keychain.
///
/// Returns `None` if no entry exists for this service+account pair. That
/// case is distinguished from a hard error (Keychain locked, access
/// denied) so callers can decide between migration-from-plaintext and
/// real failure.
#[allow(unsafe_code)]
pub fn keychain_load(app_name: &str, label: &str) -> Result<Option<[u8; WRAP_KEY_LEN]>> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();
    let service_len = service_bytes.len() as i32;
    let account_len = account_bytes.len() as i32;

    let mut out = [0_u8; WRAP_KEY_LEN];
    let mut out_len: i32 = out.len() as i32;
    let rc = unsafe {
        ffi::enclaveapp_keychain_load(
            service_bytes.as_ptr(),
            service_len,
            account_bytes.as_ptr(),
            account_len,
            out.as_mut_ptr(),
            &mut out_len,
        )
    };
    match rc {
        0 => {
            if out_len as usize != WRAP_KEY_LEN {
                return Err(Error::KeyOperation {
                    operation: "keychain_load".into(),
                    detail: format!(
                        "loaded wrapping key has unexpected length {out_len}, expected {WRAP_KEY_LEN}"
                    ),
                });
            }
            Ok(Some(out))
        }
        12 => Ok(None), // SE_ERR_KEYCHAIN_NOT_FOUND
        _ => Err(Error::KeyOperation {
            operation: "keychain_load".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        }),
    }
}

/// Delete a wrapping-key entry from the login keychain. Idempotent —
/// treating "not found" as success so `delete_key` can clean up stale
/// state without racing itself.
#[allow(unsafe_code)]
pub fn keychain_delete(app_name: &str, label: &str) -> Result<()> {
    let service = service_name_for(app_name);
    let service_bytes = service.as_bytes();
    let account_bytes = label.as_bytes();
    let rc = unsafe {
        ffi::enclaveapp_keychain_delete(
            service_bytes.as_ptr(),
            service_bytes.len() as i32,
            account_bytes.as_ptr(),
            account_bytes.len() as i32,
        )
    };
    // 12 = SE_ERR_KEYCHAIN_NOT_FOUND, which the Swift side now also
    // returns when no default keychain is reachable. `keychain_delete`
    // is idempotent — treat both "entry already absent" and "no
    // keychain to look in" as success so uninstall / cleanup don't
    // error out in isolated `$HOME` contexts.
    if rc == 0 || rc == 12 {
        Ok(())
    } else {
        Err(Error::KeyOperation {
            operation: "keychain_delete".into(),
            detail: format!("Swift bridge returned error code {rc}"),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ───── Magic-prefix / format sanity ─────

    #[test]
    fn magic_prefix_is_exactly_four_bytes() {
        assert_eq!(WRAP_MAGIC.len(), 4);
        assert_eq!(WRAP_MAGIC, b"EHW1");
    }

    #[test]
    fn is_wrapped_handle_matches_magic() {
        assert!(is_wrapped_handle(b"EHW1...rest-of-blob-doesnt-matter"));
    }

    #[test]
    fn is_wrapped_handle_rejects_short_input() {
        assert!(!is_wrapped_handle(b""));
        assert!(!is_wrapped_handle(b"EHW"));
    }

    #[test]
    fn is_wrapped_handle_rejects_legacy_plaintext() {
        // A plaintext CryptoKit dataRepresentation starts with arbitrary
        // bytes — make sure we don't misidentify one as wrapped.
        assert!(!is_wrapped_handle(b"legacy-plaintext-blob"));
        assert!(!is_wrapped_handle(b"\x00\x00\x00\x00other-format"));
    }

    // ───── generate_wrapping_key ─────

    #[test]
    fn generate_wrapping_key_produces_32_bytes() {
        let key = generate_wrapping_key();
        assert_eq!(key.len(), WRAP_KEY_LEN);
    }

    #[test]
    fn generate_wrapping_key_is_non_trivial() {
        let key = generate_wrapping_key();
        // Reject all-zero or all-identical — OsRng shouldn't ever
        // produce either, but if something went catastrophically
        // wrong upstream the test catches it.
        assert!(key.iter().any(|&b| b != 0));
        assert!(key.iter().any(|&b| b != key[0]));
    }

    #[test]
    fn generate_wrapping_key_values_differ_between_calls() {
        let k1 = generate_wrapping_key();
        let k2 = generate_wrapping_key();
        assert_ne!(k1, k2);
    }

    // ───── encrypt_blob / decrypt_blob round-trip ─────

    #[test]
    fn round_trip_empty_plaintext() {
        let key = generate_wrapping_key();
        let blob = encrypt_blob(&key, b"").unwrap();
        assert_eq!(blob.len(), WRAP_MIN_LEN);
        let recovered = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn round_trip_short_plaintext() {
        let key = generate_wrapping_key();
        let pt = b"hello, keychain";
        let blob = encrypt_blob(&key, pt).unwrap();
        let recovered = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_long_plaintext() {
        let key = generate_wrapping_key();
        // A realistic dataRepresentation is a few hundred bytes. Test
        // both smaller and bigger to cover allocation boundaries.
        let pt: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let blob = encrypt_blob(&key, &pt).unwrap();
        let recovered = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts_for_same_plaintext() {
        // Nonce is random; two encrypts of the same plaintext under
        // the same key must differ.
        let key = generate_wrapping_key();
        let pt = b"same plaintext twice";
        let a = encrypt_blob(&key, pt).unwrap();
        let b = encrypt_blob(&key, pt).unwrap();
        assert_ne!(a, b);
        // But both decrypt back to the same thing.
        assert_eq!(decrypt_blob(&key, &a).unwrap(), pt);
        assert_eq!(decrypt_blob(&key, &b).unwrap(), pt);
    }

    #[test]
    fn wrap_blob_starts_with_magic() {
        let key = generate_wrapping_key();
        let blob = encrypt_blob(&key, b"pt").unwrap();
        assert!(is_wrapped_handle(&blob));
        assert_eq!(&blob[..4], WRAP_MAGIC);
    }

    // ───── Negative cases / tamper detection ─────

    #[test]
    fn decrypt_fails_on_wrong_key() {
        let k1 = generate_wrapping_key();
        let k2 = generate_wrapping_key();
        let blob = encrypt_blob(&k1, b"secret").unwrap();
        let err = decrypt_blob(&k2, &blob).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decrypt"));
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let key = generate_wrapping_key();
        let mut blob = encrypt_blob(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext region.
        let ct_start = WRAP_MAGIC.len() + WRAP_NONCE_LEN;
        blob[ct_start] ^= 0x01;
        let err = decrypt_blob(&key, &blob).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decrypt"));
    }

    #[test]
    fn decrypt_fails_on_tampered_tag() {
        let key = generate_wrapping_key();
        let mut blob = encrypt_blob(&key, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = decrypt_blob(&key, &blob).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decrypt"));
    }

    #[test]
    fn decrypt_fails_on_tampered_nonce() {
        let key = generate_wrapping_key();
        let mut blob = encrypt_blob(&key, b"secret").unwrap();
        blob[WRAP_MAGIC.len()] ^= 0x01;
        let err = decrypt_blob(&key, &blob).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decrypt"));
    }

    #[test]
    fn decrypt_fails_on_truncated_blob() {
        let key = generate_wrapping_key();
        let blob = encrypt_blob(&key, b"secret").unwrap();
        let truncated = &blob[..WRAP_MIN_LEN - 1];
        let err = decrypt_blob(&key, truncated).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn decrypt_fails_on_missing_magic() {
        let key = generate_wrapping_key();
        let mut blob = encrypt_blob(&key, b"secret").unwrap();
        blob[0] = b'X'; // corrupt magic
        let err = decrypt_blob(&key, &blob).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn decrypt_fails_on_legacy_plaintext() {
        // A legacy plaintext dataRepresentation (no wrap) should not
        // accidentally decrypt — the magic check catches it before
        // we ever invoke AES-GCM.
        let key = generate_wrapping_key();
        let legacy = b"this-is-a-plain-dataRepresentation-blob";
        let err = decrypt_blob(&key, legacy).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    // ───── service_name_for ─────

    #[test]
    fn service_name_matches_expected_format() {
        assert_eq!(service_name_for("sshenc"), "com.libenclaveapp.sshenc");
        assert_eq!(service_name_for("awsenc"), "com.libenclaveapp.awsenc");
    }

    // ───── Real-keychain integration tests (macOS only) ─────
    //
    // These exercise the Swift FFI against the system login keychain.
    // They run by default in `cargo test` on macOS. Each test uses a
    // test-unique service+account pair so parallel test runs don't
    // interfere with each other, and each test cleans up after itself
    // via a drop guard so a failing test never leaves an orphaned
    // keychain entry.

    /// RAII cleanup: delete the keychain entry on drop, regardless of
    /// whether the test succeeded. Ensures subsequent test runs see
    /// fresh state.
    struct KeychainEntryGuard {
        app: String,
        label: String,
    }

    impl KeychainEntryGuard {
        fn new(app: &str, label: &str) -> Self {
            Self {
                app: app.to_string(),
                label: label.to_string(),
            }
        }
    }

    impl Drop for KeychainEntryGuard {
        fn drop(&mut self) {
            drop(keychain_delete(&self.app, &self.label));
        }
    }

    /// Generate a test-unique label so tests don't conflict.
    fn unique_test_label(base: &str) -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{base}-{pid}-{nanos}")
    }

    const TEST_APP: &str = "enclaveapp-test";

    #[test]
    fn keychain_roundtrip_basic() {
        let label = unique_test_label("basic");
        let _guard = KeychainEntryGuard::new(TEST_APP, &label);

        let key = generate_wrapping_key();
        keychain_store(TEST_APP, &label, &key).unwrap();
        let loaded = keychain_load(TEST_APP, &label).unwrap().unwrap();
        assert_eq!(loaded, key, "loaded wrapping key must equal stored");
    }

    #[test]
    fn keychain_load_missing_returns_none() {
        let label = unique_test_label("missing");
        // No guard needed — we never stored anything.
        let loaded = keychain_load(TEST_APP, &label).unwrap();
        assert!(loaded.is_none(), "load of absent entry must return None");
    }

    #[test]
    fn keychain_store_is_idempotent_upsert() {
        let label = unique_test_label("upsert");
        let _guard = KeychainEntryGuard::new(TEST_APP, &label);

        let k1 = generate_wrapping_key();
        let k2 = generate_wrapping_key();
        keychain_store(TEST_APP, &label, &k1).unwrap();
        // Store again with a DIFFERENT key — should replace, not error.
        keychain_store(TEST_APP, &label, &k2).unwrap();
        let loaded = keychain_load(TEST_APP, &label).unwrap().unwrap();
        assert_eq!(loaded, k2, "second store must overwrite first");
    }

    #[test]
    fn keychain_delete_is_idempotent() {
        let label = unique_test_label("del-idem");
        // Delete without prior store — should succeed.
        keychain_delete(TEST_APP, &label).unwrap();
        // Delete again — still succeeds.
        keychain_delete(TEST_APP, &label).unwrap();
    }

    #[test]
    fn keychain_delete_actually_removes() {
        let label = unique_test_label("del-real");
        let _guard = KeychainEntryGuard::new(TEST_APP, &label);

        let key = generate_wrapping_key();
        keychain_store(TEST_APP, &label, &key).unwrap();
        assert!(keychain_load(TEST_APP, &label).unwrap().is_some());
        keychain_delete(TEST_APP, &label).unwrap();
        assert!(
            keychain_load(TEST_APP, &label).unwrap().is_none(),
            "load after delete must return None"
        );
    }

    #[test]
    fn keychain_per_label_isolation() {
        // Two labels under the same app get independent entries.
        let label_a = unique_test_label("iso-a");
        let label_b = unique_test_label("iso-b");
        let _ga = KeychainEntryGuard::new(TEST_APP, &label_a);
        let _gb = KeychainEntryGuard::new(TEST_APP, &label_b);

        let ka = generate_wrapping_key();
        let kb = generate_wrapping_key();
        keychain_store(TEST_APP, &label_a, &ka).unwrap();
        keychain_store(TEST_APP, &label_b, &kb).unwrap();
        assert_eq!(keychain_load(TEST_APP, &label_a).unwrap().unwrap(), ka);
        assert_eq!(keychain_load(TEST_APP, &label_b).unwrap().unwrap(), kb);
        // Deleting A does not affect B.
        keychain_delete(TEST_APP, &label_a).unwrap();
        assert!(keychain_load(TEST_APP, &label_a).unwrap().is_none());
        assert_eq!(keychain_load(TEST_APP, &label_b).unwrap().unwrap(), kb);
    }

    #[test]
    fn keychain_per_app_isolation() {
        // Same label under different app names get independent entries.
        let label = unique_test_label("app-iso");
        let app_x = format!("{TEST_APP}-x");
        let app_y = format!("{TEST_APP}-y");
        let _gx = KeychainEntryGuard::new(&app_x, &label);
        let _gy = KeychainEntryGuard::new(&app_y, &label);

        let kx = generate_wrapping_key();
        let ky = generate_wrapping_key();
        keychain_store(&app_x, &label, &kx).unwrap();
        keychain_store(&app_y, &label, &ky).unwrap();
        assert_eq!(keychain_load(&app_x, &label).unwrap().unwrap(), kx);
        assert_eq!(keychain_load(&app_y, &label).unwrap().unwrap(), ky);
    }

    #[test]
    fn full_wrap_unwrap_via_keychain_lifecycle() {
        // End-to-end: generate key → keychain_store → encrypt →
        // keychain_load → decrypt → verify plaintext round-trips.
        let label = unique_test_label("full");
        let _guard = KeychainEntryGuard::new(TEST_APP, &label);

        let plaintext = b"simulated SE dataRepresentation blob with \x00 null \xff bytes";
        let key = generate_wrapping_key();
        keychain_store(TEST_APP, &label, &key).unwrap();
        let wrapped = encrypt_blob(&key, plaintext).unwrap();

        // Now the real load path: get the wrapping key back from the
        // keychain and decrypt the blob.
        let loaded_key = keychain_load(TEST_APP, &label).unwrap().unwrap();
        let recovered = decrypt_blob(&loaded_key, &wrapped).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_under_wrong_keychain_key_fails() {
        // If someone swaps the keychain entry for a different key while
        // the wrapped blob remains the old one, decrypt must fail —
        // proves the keychain entry is actually load-bearing for
        // security rather than just metadata.
        let label = unique_test_label("wrong-key");
        let _guard = KeychainEntryGuard::new(TEST_APP, &label);

        let real_key = generate_wrapping_key();
        let wrapped = encrypt_blob(&real_key, b"secret").unwrap();
        let swapped_key = generate_wrapping_key();
        keychain_store(TEST_APP, &label, &swapped_key).unwrap();
        let loaded_key = keychain_load(TEST_APP, &label).unwrap().unwrap();
        assert_ne!(loaded_key, real_key);
        let err = decrypt_blob(&loaded_key, &wrapped).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decrypt"));
    }
}
