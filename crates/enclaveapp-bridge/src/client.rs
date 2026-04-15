// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.

use crate::protocol::*;
use enclaveapp_core::{AccessPolicy, Result};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Maximum response size from the bridge (64 KB).
const MAX_BRIDGE_RESPONSE_BYTES: usize = 64 * 1024;

/// Find the bridge executable on the Windows filesystem (from WSL).
///
/// Searches well-known install locations under `/mnt/c/` and falls back
/// to `which` for PATH-based discovery.
pub fn find_bridge(app_name: &str) -> Option<PathBuf> {
    let candidates = [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/Program Files/{app_name}/{app_name}-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-bridge.exe"),
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    for name in [
        format!("{app_name}-tpm-bridge.exe"),
        format!("{app_name}-bridge.exe"),
    ] {
        if let Ok(output) = Command::new("which").arg(&name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }
    None
}

struct BridgeSession {
    child: std::process::Child,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    finished: bool,
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
            stdout: std::io::BufReader::new(stdout),
            finished: false,
        })
    }

    fn request(&mut self, request: &BridgeRequest) -> Result<BridgeResponse> {
        let request_json = serde_json::to_string(request)
            .map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))?;

        if let Some(ref mut stdin) = self.child.stdin {
            writeln!(stdin, "{request_json}").map_err(enclaveapp_core::Error::Io)?;
            stdin.flush().map_err(enclaveapp_core::Error::Io)?;
        }

        let mut line = String::new();
        let bytes_read = self
            .stdout
            .read_line(&mut line)
            .map_err(enclaveapp_core::Error::Io)?;

        if bytes_read > MAX_BRIDGE_RESPONSE_BYTES {
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
        let status = self.child.wait().map_err(enclaveapp_core::Error::Io)?;
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
        std::thread::sleep(std::time::Duration::from_millis(100));
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
}
