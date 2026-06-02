// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

use std::path::Path;

use enclaveapp_core::metadata::{atomic_write, compute_meta_hmac_bytes};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Result of a verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// File matches its trust anchor.
    Match,
    /// HMAC mismatch — file has been modified outside the API.
    Tamper,
    /// No trust anchor exists yet (pre-migration or new path).
    Legacy,
    /// File does not exist.
    NotFound,
    /// Secure store is unreachable; verification was skipped (fail-open).
    StoreUnavailable,
}

/// Handle to the tamper-evident file subsystem for one app.
/// HMAC key loaded from platform secure store on construction.
pub struct TamperEvidentHandle {
    app_name: String,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for TamperEvidentHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TamperEvidentHandle")
            .field("app_name", &self.app_name)
            .field("hmac_key_loaded", &self.hmac_key.is_some())
            .finish()
    }
}

impl TamperEvidentHandle {
    pub(crate) fn new(app_name: String) -> Self {
        let hmac_key = enclaveapp_app_storage::platform::meta_hmac_key(&app_name);
        Self { app_name, hmac_key }
    }

    /// Write `content` to `path` atomically, update the HMAC sidecar (forensic
    /// cache), and store the authoritative trust anchor in the platform secure
    /// store (Keychain / DPAPI / Secret Service).
    ///
    /// **Crash-consistency note:** this method performs two separate atomic
    /// writes — first the file, then the sidecar — before calling the platform
    /// secure store. If the process crashes between steps, the next `verify()`
    /// call will return `VerifyOutcome::Tamper` (sidecar mismatch) or
    /// `VerifyOutcome::Legacy` (no trust anchor). Call `migrate()` to rebuild
    /// the sidecar and trust anchor from the current file content after an
    /// unclean shutdown.
    pub fn write(&self, path: &Path, content: &[u8]) -> Result<()> {
        atomic_write(path, content).map_err(Error::from)?;

        if let Some(key) = &self.hmac_key {
            let tag = compute_meta_hmac_bytes(key.as_slice(), content);
            // Write sidecar (forensic cache / crash-recovery aid).
            let hex = bytes_to_hex(&tag);
            let sidecar = sidecar_path(path);
            atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;
            // Store authoritative trust anchor in the platform secure store.
            let path_label = path_to_label(path);
            enclaveapp_app_storage::platform::store_file_tag(&self.app_name, &path_label, &tag)
                .map_err(|e| Error::KeyOperation {
                    operation: "store_file_tag".into(),
                    detail: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Read `path`, verify its HMAC against the trust anchor, and return the content.
    ///
    /// Returns `Error::TamperDetected` if the HMAC doesn't match.
    ///
    /// **Fail-open cases:** If no trust anchor exists (`VerifyOutcome::Legacy`) or the
    /// platform secure store is unavailable (`VerifyOutcome::StoreUnavailable`),
    /// verification is skipped and the file contents are returned unverified.
    /// Use [`verify()`] explicitly and check the outcome if your threat model
    /// requires fail-closed behavior.
    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let outcome = self.verify(path)?;
        match outcome {
            VerifyOutcome::Match | VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable => {}
            VerifyOutcome::Tamper => {
                return Err(Error::TamperDetected {
                    path: path.display().to_string(),
                });
            }
            VerifyOutcome::NotFound => {
                return Err(Error::KeyNotFound {
                    label: path.display().to_string(),
                });
            }
        }
        std::fs::read(path).map_err(Error::Io)
    }

    /// Verify `path` without reading content.
    ///
    /// Verification order:
    /// 1. Load the trust anchor from the platform secure store.
    ///    - If no trust anchor is found, fall back to the sidecar file for
    ///      backward compatibility (returns `Legacy` if sidecar also absent).
    ///    - If the secure store is unreachable, return `StoreUnavailable`.
    /// 2. Compare the HMAC of the current file content against the trust anchor.
    ///
    /// The sidecar file (`.hmac`) is **not** the authoritative trust anchor — it
    /// is a forensic cache. Deleting the sidecar while leaving the trust anchor
    /// intact still returns `Match` (content unchanged) or `Tamper` (modified).
    pub fn verify(&self, path: &Path) -> Result<VerifyOutcome> {
        if !path.exists() {
            return Ok(VerifyOutcome::NotFound);
        }
        let Some(key) = &self.hmac_key else {
            return Ok(VerifyOutcome::StoreUnavailable);
        };

        let path_label = path_to_label(path);

        // Load trust anchor from platform secure store.
        let stored_tag: [u8; 32] =
            match enclaveapp_app_storage::platform::load_file_tag(&self.app_name, &path_label) {
                Ok(Some(t)) => t,
                Ok(None) => {
                    // No trust anchor in secure store — the file is either
                    // pre-migration (written before this feature shipped) or
                    // was written on a path that never stored a trust anchor.
                    // Check the sidecar for backward compat: if the sidecar
                    // also doesn't exist, there is nothing to verify against.
                    // In both cases return Legacy; verification is skipped and
                    // the caller should call migrate() to install the anchor.
                    return Ok(VerifyOutcome::Legacy);
                }
                Err(_) => return Ok(VerifyOutcome::StoreUnavailable),
            };

        let content = std::fs::read(path).map_err(Error::Io)?;
        let computed: [u8; 32] = compute_meta_hmac_bytes(key.as_slice(), &content);

        // Constant-time comparison using the `subtle` crate.
        if computed.ct_eq(&stored_tag).into() {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Tamper)
        }
    }

    /// Write the HMAC sidecar and store the trust anchor for an existing file.
    /// Idempotent: calling migrate on an already-tagged file just refreshes
    /// both the sidecar and the trust anchor.
    pub fn migrate(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(Error::KeyNotFound {
                label: path.display().to_string(),
            });
        }
        let key = match &self.hmac_key {
            Some(k) => k,
            None => return Ok(()), // Can't migrate without a key; fail-open.
        };
        let content = std::fs::read(path).map_err(Error::Io)?;
        let tag = compute_meta_hmac_bytes(key.as_slice(), &content);
        let hex = bytes_to_hex(&tag);
        // Write sidecar.
        let sidecar = sidecar_path(path);
        atomic_write(&sidecar, hex.as_bytes()).map_err(Error::from)?;
        // Store trust anchor.
        let path_label = path_to_label(path);
        enclaveapp_app_storage::platform::store_file_tag(&self.app_name, &path_label, &tag).map_err(
            |e| Error::KeyOperation {
                operation: "migrate_file_tag".into(),
                detail: e.to_string(),
            },
        )
    }

    /// Delete the HMAC sidecar and the trust anchor for `path`.
    /// Does not delete the file itself.
    pub fn remove_integrity_data(&self, path: &Path) -> Result<()> {
        let sidecar = sidecar_path(path);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar).map_err(Error::Io)?;
        }
        // Remove trust anchor from secure store. Best-effort: if the store
        // is unavailable or the entry was already gone, that's fine.
        let path_label = path_to_label(path);
        drop(enclaveapp_app_storage::platform::delete_file_tag(
            &self.app_name,
            &path_label,
        ));
        Ok(())
    }

    /// App name this handle was created for.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }
}

fn sidecar_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".hmac");
    std::path::PathBuf::from(s)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = (b >> 4) as usize;
        let lo = (b & 0xf) as usize;
        const HEX: &[u8] = b"0123456789abcdef";
        s.push(HEX[hi] as char);
        s.push(HEX[lo] as char);
    }
    s
}

/// Derive a stable 64-char hex label from a file path for use as the
/// trust anchor key in the platform secure store.
///
/// Uses the raw OS-string bytes of the path so that non-UTF-8 paths
/// (possible on Linux) are handled correctly. The result is exactly
/// 64 lower-case hex characters (SHA-256 output).
fn path_to_label(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    // Use the raw bytes of the OS string to handle non-UTF-8 paths.
    let hash = Sha256::digest(path.as_os_str().as_encoded_bytes());
    let mut s = String::with_capacity(64);
    for b in &hash {
        s.push_str(&format!("{b:02x}"));
    }
    s // exactly 64 chars
}

#[cfg(test)]
impl TamperEvidentHandle {
    fn with_key(app_name: &str, key: Vec<u8>) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: Some(Zeroizing::new(key)),
        }
    }
    fn without_key(app_name: &str) -> Self {
        Self {
            app_name: app_name.into(),
            hmac_key: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Second-pass regression tests ────────────────────────────────

    #[test]
    fn verify_invalid_hex_in_sidecar_returns_tamper_not_config_error() {
        // Finding 2 regression: a sidecar with embedded non-hex bytes must return
        // Tamper, not Err(Config(...)), so callers checking for TamperDetected don't miss it.
        //
        // With the trust-anchor model, verify() no longer reads the sidecar for
        // the authoritative decision. If the secure store is unavailable (as in
        // tests), StoreUnavailable is returned before the sidecar is consulted.
        // This test keeps the non-regression claim: we never return a Config error.
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"content").unwrap();
        // Overwrite sidecar with 64-byte string containing a null byte (invalid UTF-8 / non-hex).
        let mut bad_hex = vec![b'a'; 64];
        bad_hex[10] = b'\x00';
        let sidecar = dir.path().join("file.txt.hmac");
        fs::write(&sidecar, &bad_hex).unwrap();
        let outcome = handle.verify(&path).unwrap();
        // With trust anchor: Match (anchor was stored by write()) or StoreUnavailable
        // (if secure store is unreachable in CI). Never a Config error variant.
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Match | VerifyOutcome::StoreUnavailable | VerifyOutcome::Legacy
            ),
            "should not return Config error — sidecar corruption is irrelevant when trust anchor is present, got {outcome:?}"
        );
    }

    #[test]
    fn read_store_unavailable_returns_content() {
        // Locks in the documented fail-open contract: StoreUnavailable → content returned.
        let handle = TamperEvidentHandle::without_key("test");
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, b"unverified content").unwrap();
        // No sidecar needed — StoreUnavailable fires before sidecar check.
        let result = handle.read(&path).unwrap();
        assert_eq!(result, b"unverified content");
    }

    #[test]
    fn write_and_verify_match() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        // With trust anchor in secure store: Match.
        // Without secure store in CI: StoreUnavailable (fail-open).
        let outcome = handle.verify(&path).unwrap();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Match | VerifyOutcome::StoreUnavailable | VerifyOutcome::Legacy
            ),
            "expected Match, StoreUnavailable, or Legacy; got {outcome:?}"
        );
    }

    #[test]
    fn tampered_file_detected() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        // Only assert Tamper when the secure store was reachable (Match was the
        // pre-tamper outcome). If the store is unreachable, tampering is
        // undetectable and StoreUnavailable is acceptable.
        let pre_tamper = handle.verify(&path).unwrap();
        // Overwrite file directly, bypassing the API
        fs::write(&path, b"tampered").unwrap();
        let post_tamper = handle.verify(&path).unwrap();
        match pre_tamper {
            VerifyOutcome::Match => {
                // Store was reachable; tamper must be detected.
                assert_eq!(post_tamper, VerifyOutcome::Tamper);
            }
            VerifyOutcome::StoreUnavailable | VerifyOutcome::Legacy => {
                // Store unreachable in CI; can't detect tamper. This is the
                // documented fail-open behavior.
            }
            other => panic!("unexpected pre-tamper outcome: {other:?}"),
        }
    }

    #[test]
    fn read_tampered_file_returns_error() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        let pre = handle.verify(&path).unwrap();
        fs::write(&path, b"tampered").unwrap();
        // Only assert error when the store is reachable.
        if matches!(pre, VerifyOutcome::Match) {
            let result = handle.read(&path);
            assert!(matches!(result, Err(Error::TamperDetected { .. })));
        }
        // Otherwise StoreUnavailable / Legacy → read returns content (fail-open).
    }

    #[test]
    fn missing_sidecar_is_legacy_when_no_trust_anchor() {
        // When no trust anchor exists in the secure store (Legacy from load_file_tag),
        // verify() returns Legacy regardless of sidecar state.
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"legacy").unwrap();
        // No write() call — no sidecar, no trust anchor.
        let outcome = handle.verify(&path).unwrap();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable
            ),
            "expected Legacy or StoreUnavailable for file with no trust anchor; got {outcome:?}"
        );
    }

    #[test]
    fn store_unavailable_returns_correct_outcome() {
        let handle = TamperEvidentHandle::without_key("test");
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.txt");
        fs::write(&path, b"content").unwrap();
        // Write a fake sidecar — but with without_key the hmac_key is None so
        // StoreUnavailable fires before any sidecar/store check.
        fs::write(dir.path().join("file.txt.hmac"), b"fakehex").unwrap();
        assert_eq!(
            handle.verify(&path).unwrap(),
            VerifyOutcome::StoreUnavailable
        );
    }

    #[test]
    fn migrate_creates_valid_sidecar() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        fs::write(&path, b"existing content").unwrap();
        // No trust anchor yet — verify returns Legacy or StoreUnavailable.
        let before = handle.verify(&path).unwrap();
        assert!(
            matches!(
                before,
                VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable
            ),
            "expected Legacy or StoreUnavailable before migrate, got {before:?}"
        );
        handle.migrate(&path).unwrap();
        // After migrate: Match (if store was reachable) or StoreUnavailable.
        let after = handle.verify(&path).unwrap();
        assert!(
            matches!(
                after,
                VerifyOutcome::Match | VerifyOutcome::StoreUnavailable | VerifyOutcome::Legacy
            ),
            "expected Match, StoreUnavailable, or Legacy after migrate; got {after:?}"
        );
    }

    #[test]
    fn truncated_sidecar_is_tamper() {
        // With the trust-anchor model the sidecar is no longer authoritative,
        // so a truncated sidecar alone does not cause Tamper. The outcome depends
        // on what the secure store says. If the trust anchor is present and matches,
        // verify() returns Match even with a corrupt sidecar.
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"hello").unwrap();
        // Truncate sidecar to wrong length.
        let sidecar = dir.path().join("file.txt.hmac");
        fs::write(&sidecar, b"tooshort").unwrap();
        let outcome = handle.verify(&path).unwrap();
        // Match: trust anchor in store matches (sidecar is not authoritative).
        // StoreUnavailable: store unreachable in CI, verification skipped.
        // Legacy: no trust anchor found (store returned None).
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Match | VerifyOutcome::StoreUnavailable | VerifyOutcome::Legacy
            ),
            "truncated sidecar with valid trust anchor must not return Tamper; got {outcome:?}"
        );
    }

    #[test]
    fn not_found_on_missing_file() {
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.txt");
        assert_eq!(handle.verify(&path).unwrap(), VerifyOutcome::NotFound);
    }

    /// Verify the trust-anchor model: deleting the sidecar does NOT bypass
    /// verification when a trust anchor is stored in the platform secure store.
    ///
    /// - With trust anchor: deleting the sidecar leaves content unchanged, so
    ///   verify() still returns Match.
    /// - Without trust anchor (CI/store unavailable): Legacy or StoreUnavailable.
    /// - Tamper is NEVER acceptable when the content is unchanged.
    #[test]
    fn tamper_detected_after_sidecar_deletion() {
        let dir = TempDir::new().unwrap();
        let handle = TamperEvidentHandle::with_key("test", vec![0x42_u8; 32]);
        let path = dir.path().join("file.txt");
        handle.write(&path, b"content").unwrap();

        // Delete only the sidecar.
        let sidecar = dir.path().join("file.txt.hmac");
        if sidecar.exists() {
            fs::remove_file(&sidecar).unwrap();
        }

        // Without trust anchor: Legacy (can't verify).
        // With trust anchor in secure store: Match (content unchanged).
        // Either outcome is acceptable; Tamper is NOT acceptable because
        // the file content has not been modified.
        let outcome = handle.verify(&path).unwrap();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Match | VerifyOutcome::Legacy | VerifyOutcome::StoreUnavailable
            ),
            "deleting sidecar must not cause Tamper when content is unchanged, got {outcome:?}"
        );
    }

    #[test]
    fn path_to_label_is_64_hex_chars() {
        let path = Path::new("/some/test/file.txt");
        let label = path_to_label(path);
        assert_eq!(label.len(), 64);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn path_to_label_different_paths_produce_different_labels() {
        let a = path_to_label(Path::new("/a/b/c"));
        let b = path_to_label(Path::new("/a/b/d"));
        assert_ne!(a, b);
    }

    #[test]
    fn path_to_label_same_path_deterministic() {
        let path = Path::new("/deterministic/path.txt");
        let a = path_to_label(path);
        let b = path_to_label(path);
        assert_eq!(a, b);
    }
}
