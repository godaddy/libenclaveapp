// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.

use crate::protocol::*;
use enclaveapp_core::timeout::{wait_with_timeout, LineReaderWithTimeout, TimeoutResult};
use enclaveapp_core::{AccessPolicy, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Maximum response size from the bridge (64 KB).
const MAX_BRIDGE_RESPONSE_BYTES: usize = 64 * 1024;

/// Default timeout for a single bridge request/response cycle. Covers
/// TPM operations including biometric prompts (Windows Hello can take
/// up to ~60s in practice). Override via `ENCLAVEAPP_BRIDGE_TIMEOUT_SECS`.
const DEFAULT_BRIDGE_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for bridge shutdown (after we close stdin, it should exit promptly).
const BRIDGE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn bridge_request_timeout() -> Duration {
    std::env::var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BRIDGE_REQUEST_TIMEOUT)
}

/// Find the bridge executable on the Windows filesystem (from WSL).
///
/// Discovery order:
/// 1. The `ENCLAVEAPP_BRIDGE_PATH` environment variable (or the app-specific
///    `{APP_NAME_UPPER}_BRIDGE_PATH`) — explicit opt-in by the user. Needed for
///    non-admin installs like scoop where the bridge lives under
///    `%USERPROFILE%\scoop\apps\...`, which is not one of the default
///    candidate paths.
/// 2. Among the fixed install locations under `/mnt/c/Program Files/` and
///    `/mnt/c/ProgramData/` that actually exist, the one with the newest
///    modification time. This avoids silently picking a stale binary left
///    behind by a previous installer when the user has since installed a
///    newer version to a different location.
///
/// Only fixed admin-path install locations are included in the auto-discovery
/// fallback. PATH-based lookup via `which` was removed intentionally — a
/// user-writable `$PATH` entry on the WSL side could substitute a malicious
/// bridge binary, and this library performs no Authenticode verification
/// on the resolved executable. Users who install to non-admin paths (scoop,
/// a manual build) must set `ENCLAVEAPP_BRIDGE_PATH` explicitly.
#[allow(clippy::print_stderr)] // user-facing warning for misconfigured env var
pub fn find_bridge(app_name: &str) -> Option<PathBuf> {
    // 1. Explicit env var override (app-specific, then generic).
    let app_specific = format!("{}_BRIDGE_PATH", app_name.to_uppercase().replace('-', "_"));
    for var in [app_specific.as_str(), "ENCLAVEAPP_BRIDGE_PATH"] {
        if let Ok(value) = std::env::var(var) {
            let p = PathBuf::from(&value);
            if p.exists() {
                return Some(p);
            }
            // Env var was set but the path is missing — surface clearly
            // rather than silently falling through to auto-discovery.
            eprintln!(
                "warning: {var}={value} is set but the file does not exist; falling back to auto-discovery"
            );
        }
    }

    // 2. Auto-discovery: newest-mtime wins among existing admin-path candidates.
    let candidates = [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/Program Files/{app_name}/{app_name}-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-bridge.exe"),
    ];
    candidates
        .iter()
        .filter_map(|path| {
            let p = PathBuf::from(path);
            let mtime = std::fs::metadata(&p).ok()?.modified().ok()?;
            Some((p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(path, _)| path)
}

struct BridgeSession {
    child: std::process::Child,
    reader: LineReaderWithTimeout,
    finished: bool,
    request_timeout: Duration,
}

impl BridgeSession {
    fn spawn(bridge_path: &Path) -> Result<Self> {
        let mut child = Command::new(bridge_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| enclaveapp_core::Error::KeyOperation {
                operation: "bridge_spawn".into(),
                detail: e.to_string(),
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| enclaveapp_core::Error::KeyOperation {
                operation: "bridge_read".into(),
                detail: "no stdout".into(),
            })?;

        Ok(Self {
            child,
            reader: LineReaderWithTimeout::new(stdout),
            finished: false,
            request_timeout: bridge_request_timeout(),
        })
    }

    fn request(&mut self, request: &BridgeRequest) -> Result<BridgeResponse> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))?;

        if let Some(ref mut stdin) = self.child.stdin {
            writeln!(stdin, "{request_json}").map_err(enclaveapp_core::Error::Io)?;
            stdin.flush().map_err(enclaveapp_core::Error::Io)?;
        }

        let line = match self.reader.recv_line(self.request_timeout) {
            TimeoutResult::Completed(Ok(line)) => line,
            TimeoutResult::Completed(Err(e)) => return Err(enclaveapp_core::Error::Io(e)),
            TimeoutResult::TimedOut => {
                // Kill the child so we're not leaving a stuck TPM op running.
                drop(self.child.kill());
                drop(self.child.wait());
                self.finished = true;
                return Err(enclaveapp_core::Error::KeyOperation {
                    operation: "bridge_read".into(),
                    detail: format!(
                        "bridge did not respond within {}s (set ENCLAVEAPP_BRIDGE_TIMEOUT_SECS to override)",
                        self.request_timeout.as_secs()
                    ),
                });
            }
        };

        if line.len() > MAX_BRIDGE_RESPONSE_BYTES {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "bridge_read".into(),
                detail: format!("bridge response exceeds {MAX_BRIDGE_RESPONSE_BYTES} byte limit"),
            });
        }

        if line.trim().is_empty() {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "bridge_read".into(),
                detail: "bridge returned no response".into(),
            });
        }

        let response: BridgeResponse = serde_json::from_str(&line)
            .map_err(|e| enclaveapp_core::Error::Serialization(format!("bridge response: {e}")))?;

        Ok(response)
    }

    fn finish(mut self) -> Result<()> {
        drop(self.child.stdin.take());
        // Give the bridge a bounded window to exit cleanly after stdin close.
        // If it hangs (e.g. wedged TPM state), kill it rather than blocking forever.
        let status = match wait_with_timeout(&mut self.child, BRIDGE_SHUTDOWN_TIMEOUT)
            .map_err(enclaveapp_core::Error::Io)?
        {
            TimeoutResult::Completed(status) => status,
            TimeoutResult::TimedOut => {
                drop(self.child.kill());
                drop(self.child.wait());
                self.finished = true;
                return Err(enclaveapp_core::Error::KeyOperation {
                    operation: "bridge_shutdown".into(),
                    detail: format!(
                        "bridge did not exit within {}s after stdin close",
                        BRIDGE_SHUTDOWN_TIMEOUT.as_secs()
                    ),
                });
            }
        };
        self.finished = true;
        if status.success() {
            Ok(())
        } else {
            Err(enclaveapp_core::Error::KeyOperation {
                operation: "bridge".into(),
                detail: format!("bridge exited with status {status}"),
            })
        }
    }
}

impl Drop for BridgeSession {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.child.stdin.take());
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

fn finish_session<T>(session: BridgeSession, result: Result<T>) -> Result<T> {
    let finish_result = session.finish();
    match (result, finish_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

/// Call the bridge with a request and return the response.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    let mut session = BridgeSession::spawn(bridge_path)?;
    let response = session.request(request);
    finish_session(session, response)
}

fn init_request(app_name: &str, key_label: &str, access_policy: AccessPolicy) -> BridgeRequest {
    BridgeRequest {
        method: "init".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    }
}

fn call_bridge_after_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
    request: &BridgeRequest,
) -> Result<BridgeResponse> {
    let mut session = BridgeSession::spawn(bridge_path)?;
    let response = (|| -> Result<BridgeResponse> {
        session
            .request(&init_request(app_name, key_label, access_policy))?
            .require_ok("bridge_init")?;
        session.request(request)
    })();
    finish_session(session, response)
}

/// Initialize the bridge-side key lifecycle for a specific app/label pair.
pub fn bridge_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<()> {
    let response = call_bridge(
        bridge_path,
        &init_request(app_name, key_label, access_policy),
    )?;
    response.require_ok("bridge_init")
}

/// Convenience: encrypt data via the bridge.
pub fn bridge_encrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    plaintext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "encrypt".to_string(),
        params: BridgeParams::new(
            encode_data(plaintext),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_encrypt")
}

/// Convenience: decrypt data via the bridge.
pub fn bridge_decrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    ciphertext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "decrypt".to_string(),
        params: BridgeParams::new(
            encode_data(ciphertext),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_decrypt")
}

/// Destroy the bridge-side key for a specific app/label pair.
/// Sends "delete" on the wire for backward compatibility with existing bridge servers.
pub fn bridge_destroy(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = BridgeRequest {
        method: "delete".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    response.require_ok("bridge_destroy")
}

/// Alias for backward compatibility.
pub fn bridge_delete(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    bridge_destroy(bridge_path, app_name, key_label)
}

// ---------------------------------------------------------------------------
// Signing bridge operations
// ---------------------------------------------------------------------------

fn init_signing_request(
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> BridgeRequest {
    BridgeRequest {
        method: "init_signing".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    }
}

fn call_bridge_after_signing_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
    request: &BridgeRequest,
) -> Result<BridgeResponse> {
    let mut session = BridgeSession::spawn(bridge_path)?;
    let response = (|| -> Result<BridgeResponse> {
        session
            .request(&init_signing_request(app_name, key_label, access_policy))?
            .require_ok("bridge_init_signing")?;
        session.request(request)
    })();
    finish_session(session, response)
}

/// Initialize the bridge-side signing key lifecycle for a specific app/label pair.
pub fn bridge_init_signing(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<()> {
    let response = call_bridge(
        bridge_path,
        &init_signing_request(app_name, key_label, access_policy),
    )?;
    response.require_ok("bridge_init_signing")
}

/// Convenience: sign data via the bridge.
pub fn bridge_sign(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    data: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "sign".to_string(),
        params: BridgeParams::new(
            encode_data(data),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_signing_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_sign")
}

/// Convenience: get the public key via the bridge.
pub fn bridge_public_key(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "public_key".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_signing_init(bridge_path, app_name, key_label, access_policy, &request)?;
    response.decode_result("bridge_public_key")
}

/// Convenience: list signing keys via the bridge.
pub fn bridge_list_keys(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<Vec<String>> {
    let request = BridgeRequest {
        method: "list_keys".to_string(),
        params: BridgeParams::new(
            String::new(),
            access_policy,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response =
        call_bridge_after_signing_init(bridge_path, app_name, key_label, access_policy, &request)?;
    let result_str = response.require_result("bridge_list_keys")?;
    serde_json::from_str(result_str)
        .map_err(|e| enclaveapp_core::Error::Serialization(format!("list_keys JSON: {e}")))
}

/// Delete a signing key via the bridge.
pub fn bridge_delete_signing(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = BridgeRequest {
        method: "delete_signing".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    response.require_ok("bridge_delete_signing")
}

/// Check if a signing key exists on the bridge side without creating it.
///
/// Unlike `bridge_public_key` / `bridge_list_keys`, this does NOT invoke
/// `init_signing`, so the TPM key is never created as a side effect of
/// the check. Use this for duplicate-label guards.
pub fn bridge_signing_key_exists(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
) -> Result<bool> {
    let request = BridgeRequest {
        method: "signing_key_exists".to_string(),
        params: BridgeParams::new(
            String::new(),
            AccessPolicy::None,
            app_name.to_string(),
            key_label.to_string(),
        ),
    };
    let response = call_bridge(bridge_path, &request)?;
    let result = response.require_result("bridge_signing_key_exists")?;
    match result {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(enclaveapp_core::Error::KeyOperation {
            operation: "bridge_signing_key_exists".into(),
            detail: format!("unexpected result: {other}"),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);
    #[cfg(unix)]
    static SCRIPT_TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-test-{}-{}-{}",
            std::process::id(),
            id,
            name
        ));
        fs::write(&path, body).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(unix)]
    fn cleanup_script(path: &Path) {
        drop(fs::remove_file(path));
    }

    #[test]
    fn find_bridge_returns_none_when_not_found() {
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn find_bridge_env_var_override_wins_when_path_exists() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Create a temp file and point the env var at it.
        let script = temp_script("override-bridge", "#!/bin/sh\nexit 0\n");
        std::env::set_var("ENCLAVEAPP_BRIDGE_PATH", &script);
        let found = find_bridge("some-app-that-has-no-admin-install");
        std::env::remove_var("ENCLAVEAPP_BRIDGE_PATH");
        assert_eq!(found.as_deref(), Some(script.as_path()));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn find_bridge_env_var_override_ignored_when_path_missing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        std::env::set_var("ENCLAVEAPP_BRIDGE_PATH", "/nonexistent/path/to/bridge.exe");
        let found = find_bridge("another-nonexistent-app");
        std::env::remove_var("ENCLAVEAPP_BRIDGE_PATH");
        // Env var points at nothing and no admin-path candidate exists → None.
        assert!(found.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_sends_key_label() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"init"'*'"app_name":"awsenc"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_init(&script, "awsenc", "cache-key", AccessPolicy::BiometricOnly).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_encrypt_initializes_before_encrypting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "encrypt.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"encrypt"'*) printf '{"result":"aGVsbG8=","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let plaintext = bridge_encrypt(
            &script,
            "awsenc",
            "cache-key",
            b"ignored",
            AccessPolicy::BiometricOnly,
        )
        .unwrap();
        assert_eq!(plaintext, b"hello");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_sends_delete_request() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete"'*'"key_label":"cache-key"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_destroy(&script, "awsenc", "cache-key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_encrypt_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "encrypt-missing-result.sh",
            r#"#!/bin/sh
read init_line
printf '{"result":"","error":null}\n'
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let error = bridge_encrypt(
            &script,
            "awsenc",
            "cache-key",
            b"ignored",
            AccessPolicy::None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init-missing-result.sh",
            r#"#!/bin/sh
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let error = bridge_init(&script, "awsenc", "cache-key", AccessPolicy::None).unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_oversized_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "oversized.sh",
            "#!/bin/sh\nread req\npython3 -c \"print('{\\\"result\\\":\\\"' + 'A' * 70000 + '\\\",\\\"error\\\":null}')\"\n",
        );
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(
                String::new(),
                AccessPolicy::None,
                "test".into(),
                "key".into(),
            ),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("byte limit") || msg.contains("bridge response"),
            "expected size limit error, got: {msg}"
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_decrypt_initializes_before_decrypting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "decrypt.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"decrypt"'*) printf '{"result":"cGxhaW50ZXh0","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let result =
            bridge_decrypt(&script, "test-app", "key", b"ignored", AccessPolicy::None).unwrap();
        assert_eq!(result, b"plaintext");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_decrypt_rejects_missing_result_payload() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "decrypt-missing.sh",
            r#"#!/bin/sh
read init_line
printf '{"result":"","error":null}\n'
read request_line
printf '{"result":null,"error":null}\n'
"#,
        );
        let err =
            bridge_decrypt(&script, "test-app", "key", b"ignored", AccessPolicy::None).unwrap_err();
        assert!(err.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_destroy_sends_delete_method_on_wire() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "wire-method.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete"'*) printf '{"result":"","error":null}\n' ;;
  *'"method":"destroy"'*) printf '{"result":null,"error":"got destroy instead of delete"}\n' ;;
  *) printf '{"result":null,"error":"unexpected method"}\n' ;;
esac
"#,
        );
        bridge_destroy(&script, "test-app", "key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_alias_works() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete-alias.sh",
            r#"#!/bin/sh
read req
printf '{"result":"","error":null}\n'
"#,
        );
        bridge_delete(&script, "test-app", "key").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_session_drop_kills_child() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("drop-kill.sh", "#!/bin/sh\nwhile true; do sleep 1; done\n");
        // Spawn a session, grab the child PID, then drop it
        let child_pid: u32;
        {
            let session = BridgeSession::spawn(&script).unwrap();
            child_pid = session.child.id();
            // Session dropped here — Drop should kill + wait the child
        }
        // Give the OS a moment to reap
        std::thread::sleep(Duration::from_millis(100));
        // Verify the process is gone using `kill -0 <pid>` (signal 0 checks existence)
        let status = Command::new("kill")
            .args(["-0", &child_pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        assert!(
            status.is_err() || !status.unwrap().success(),
            "bridge child (pid={child_pid}) should no longer exist after Drop"
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_init_sends_biometric_compat_field() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "biometric-compat.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"biometric":true'*'"access_policy":"biometric_only"'*) printf '{"result":"","error":null}\n' ;;
  *'"access_policy":"biometric_only"'*'"biometric":true'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"missing biometric compat field"}\n' ;;
esac
"#,
        );
        bridge_init(&script, "test-app", "key", AccessPolicy::BiometricOnly).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_empty_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("empty-response.sh", "#!/bin/sh\nread req\n");
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        assert!(
            err.to_string().contains("no response") || err.to_string().contains("bridge"),
            "expected bridge error, got: {}",
            err
        );
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_rejects_invalid_json_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script("invalid-json.sh", "#!/bin/sh\nread req\necho 'not json'\n");
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        assert!(err.to_string().contains("bridge response"));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_reaps_child_after_error_response() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let sentinel = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-test-sentinel-{}-{}",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_file(&sentinel));
        let script = temp_script(
            "delete-error.sh",
            &format!(
                r#"#!/bin/sh
sentinel="{}"
trap 'printf done > "$sentinel"' EXIT
read request_line
printf '{{"result":null,"error":"boom"}}\n'
while IFS= read -r _line; do :; done
"#,
                sentinel.display()
            ),
        );
        let error = bridge_destroy(&script, "awsenc", "cache-key").unwrap_err();
        assert!(error.to_string().contains("boom"));
        assert!(
            sentinel.exists(),
            "bridge process should be reaped before returning"
        );
        cleanup_script(&script);
        drop(fs::remove_file(sentinel));
    }

    // ----- Signing bridge client tests -----

    #[cfg(unix)]
    #[test]
    fn bridge_init_signing_sends_init_signing_method() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "init-signing.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"init_signing"'*'"app_name":"sshenc"'*'"key_label":"default"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_init_signing(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_sign_initializes_before_signing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "sign.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init_signing"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"sign"'*) printf '{"result":"c2lnbmF0dXJl","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let signature =
            bridge_sign(&script, "sshenc", "default", b"data", AccessPolicy::None).unwrap();
        assert_eq!(signature, b"signature");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_public_key_initializes_before_requesting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "pubkey.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init_signing"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"public_key"'*) printf '{"result":"cHVia2V5","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let pubkey = bridge_public_key(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        assert_eq!(pubkey, b"pubkey");
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_list_keys_initializes_before_requesting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Write response files to avoid shell quoting issues with embedded JSON.
        let dir = std::env::temp_dir().join("bridge-list-keys-test");
        fs::create_dir_all(&dir).unwrap();
        let resp1 = dir.join("resp1.json");
        let resp2 = dir.join("resp2.json");
        fs::write(&resp1, "{\"result\":\"\",\"error\":null}\n").unwrap();
        fs::write(
            &resp2,
            "{\"result\":\"[\\\"key1\\\",\\\"key2\\\"]\",\"error\":null}\n",
        )
        .unwrap();
        let script = temp_script(
            "list-keys.sh",
            &format!(
                "#!/bin/sh\nread init_line\ncat {}\nread request_line\ncat {}\n",
                resp1.display(),
                resp2.display()
            ),
        );
        let keys = bridge_list_keys(&script, "sshenc", "default", AccessPolicy::None).unwrap();
        assert_eq!(keys, vec!["key1".to_string(), "key2".to_string()]);
        drop(fs::remove_dir_all(&dir));
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_delete_signing_sends_delete_signing_method() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "delete-signing.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"delete_signing"'*'"key_label":"default"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        bridge_delete_signing(&script, "sshenc", "default").unwrap();
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_returns_true() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "exists-true.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"signing_key_exists"'*'"key_label":"mine"'*) printf '{"result":"true","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "mine").unwrap();
        assert!(exists);
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_returns_false() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        let script = temp_script(
            "exists-false.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"signing_key_exists"'*) printf '{"result":"false","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "missing").unwrap();
        assert!(!exists);
        cleanup_script(&script);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_signing_key_exists_does_not_call_init_signing() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Bridge that records every request into a sentinel file and
        // rejects any init_signing request.
        let sentinel = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-exists-nolog-{}-{}",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_file(&sentinel));
        let script = temp_script(
            "exists-no-init.sh",
            &format!(
                r#"#!/bin/sh
read request_line
echo "$request_line" >> "{sentinel}"
case "$request_line" in
  *'"method":"init_signing"'*) printf '{{"result":null,"error":"should not init"}}\n'; exit 0 ;;
  *'"method":"signing_key_exists"'*) printf '{{"result":"false","error":null}}\n' ;;
  *) printf '{{"result":null,"error":"unexpected method"}}\n' ;;
esac
"#,
                sentinel = sentinel.display()
            ),
        );
        let exists = bridge_signing_key_exists(&script, "sshenc", "probe").unwrap();
        assert!(!exists);
        let log = fs::read_to_string(&sentinel).unwrap_or_default();
        assert!(
            !log.contains("init_signing"),
            "exists-check must not invoke init_signing, log was: {log}"
        );
        cleanup_script(&script);
        drop(fs::remove_file(&sentinel));
    }

    #[cfg(unix)]
    #[test]
    fn bridge_read_times_out_on_silent_bridge() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        // Bridge that accepts a request but never responds.
        let script = temp_script("silent-bridge.sh", "#!/bin/sh\nread req\nsleep 120\n");
        // Force a very short timeout for this test.
        std::env::set_var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS", "1");
        let start = std::time::Instant::now();
        let request = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams::new(String::new(), AccessPolicy::None, "t".into(), "k".into()),
        };
        let err = call_bridge(&script, &request).unwrap_err();
        std::env::remove_var("ENCLAVEAPP_BRIDGE_TIMEOUT_SECS");
        // Should fail well before the bridge's 120s sleep finishes.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout should fire quickly, took {:?}",
            start.elapsed()
        );
        let msg = err.to_string();
        assert!(
            msg.contains("did not respond") || msg.contains("timeout"),
            "expected timeout error, got: {msg}"
        );
        cleanup_script(&script);
    }
}
