// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.

use crate::protocol::*;
use enclaveapp_core::Result;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
        self.stdout
            .read_line(&mut line)
            .map_err(enclaveapp_core::Error::Io)?;
        if line.trim().is_empty() {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "bridge_read".into(),
                detail: "bridge returned no response".into(),
            });
        }

        let response: BridgeResponse = serde_json::from_str(&line)
            .map_err(|e| enclaveapp_core::Error::Serialization(format!("bridge response: {e}")))?;

        if let Some(ref err) = response.error {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "bridge".into(),
                detail: err.clone(),
            });
        }

        Ok(response)
    }

    fn finish(mut self) -> Result<()> {
        drop(self.child.stdin.take());
        let status = self.child.wait().map_err(enclaveapp_core::Error::Io)?;
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

/// Call the bridge with a request and return the response.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    let mut session = BridgeSession::spawn(bridge_path)?;
    let response = session.request(request)?;
    session.finish()?;
    Ok(response)
}

fn init_request(app_name: &str, key_label: &str, biometric: bool) -> BridgeRequest {
    BridgeRequest {
        method: "init".to_string(),
        params: BridgeParams {
            data: String::new(),
            biometric,
            app_name: app_name.to_string(),
            key_label: key_label.to_string(),
        },
    }
}

pub fn bridge_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    biometric: bool,
) -> Result<()> {
    let response = call_bridge(bridge_path, &init_request(app_name, key_label, biometric))?;
    drop(response.result);
    Ok(())
}

fn call_bridge_after_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    biometric: bool,
    request: &BridgeRequest,
) -> Result<BridgeResponse> {
    let mut session = BridgeSession::spawn(bridge_path)?;
    session.request(&init_request(app_name, key_label, biometric))?;
    let response = session.request(request)?;
    session.finish()?;
    Ok(response)
}

pub fn bridge_delete(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = BridgeRequest {
        method: "delete".to_string(),
        params: BridgeParams {
            data: String::new(),
            biometric: false,
            app_name: app_name.to_string(),
            key_label: key_label.to_string(),
        },
    };
    let response = call_bridge(bridge_path, &request)?;
    drop(response.result);
    Ok(())
}

/// Convenience: encrypt data via the bridge.
pub fn bridge_encrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    plaintext: &[u8],
    biometric: bool,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "encrypt".to_string(),
        params: BridgeParams {
            data: encode_data(plaintext),
            biometric,
            app_name: app_name.to_string(),
            key_label: key_label.to_string(),
        },
    };
    let response = call_bridge_after_init(bridge_path, app_name, key_label, biometric, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

/// Convenience: decrypt data via the bridge.
pub fn bridge_decrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    ciphertext: &[u8],
    biometric: bool,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "decrypt".to_string(),
        params: BridgeParams {
            data: encode_data(ciphertext),
            biometric,
            app_name: app_name.to_string(),
            key_label: key_label.to_string(),
        },
    };
    let response = call_bridge_after_init(bridge_path, app_name, key_label, biometric, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);
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
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }
        path
    }

    #[cfg(windows)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "enclaveapp-bridge-test-{}-{}-{}",
            std::process::id(),
            id,
            name
        ));
        let script_path = base.with_extension("ps1");
        let wrapper_path = base.with_extension("cmd");
        fs::write(&script_path, body).unwrap();
        let wrapper = format!(
            "@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"\r\n",
            script_path.display()
        );
        fs::write(&wrapper_path, wrapper).unwrap();
        wrapper_path
    }

    fn cleanup_script(path: &Path) {
        drop(fs::remove_file(path));
        #[cfg(windows)]
        {
            drop(fs::remove_file(path.with_extension("ps1")));
        }
    }

    #[test]
    fn find_bridge_returns_none_when_not_found() {
        // On macOS (or any non-WSL environment), no bridge binary should exist
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none());
    }

    #[test]
    fn bridge_encrypt_initializes_before_encrypting() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        #[cfg(unix)]
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
        #[cfg(windows)]
        let script = temp_script(
            "encrypt",
            r#"$initLine = [Console]::In.ReadLine()
if ($initLine -like '*"method":"init"*' -and $initLine -like '*"key_label":"cache-key"*') {
  [Console]::Out.WriteLine('{"result":"","error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected init request"}')
  exit 0
}
$requestLine = [Console]::In.ReadLine()
if ($requestLine -like '*"method":"encrypt"*') {
  [Console]::Out.WriteLine('{"result":"aGVsbG8=","error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected request"}')
}
"#,
        );

        let plaintext = bridge_encrypt(&script, "awsenc", "cache-key", b"ignored", true).unwrap();
        assert_eq!(plaintext, b"hello");
        cleanup_script(&script);
    }

    #[test]
    fn bridge_delete_sends_delete_request() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        #[cfg(unix)]
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
        #[cfg(windows)]
        let script = temp_script(
            "delete",
            r#"$requestLine = [Console]::In.ReadLine()
if ($requestLine -like '*"method":"delete"*' -and $requestLine -like '*"key_label":"cache-key"*') {
  [Console]::Out.WriteLine('{"result":"","error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected request"}')
}
"#,
        );

        bridge_delete(&script, "awsenc", "cache-key").unwrap();
        cleanup_script(&script);
    }

    #[test]
    fn bridge_init_sends_key_label() {
        let _lock = SCRIPT_TEST_MUTEX.lock().unwrap();
        #[cfg(unix)]
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
        #[cfg(windows)]
        let script = temp_script(
            "init",
            r#"$requestLine = [Console]::In.ReadLine()
if ($requestLine -like '*"method":"init"*' -and $requestLine -like '*"app_name":"awsenc"*' -and $requestLine -like '*"key_label":"cache-key"*') {
  [Console]::Out.WriteLine('{"result":"","error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected request"}')
}
"#,
        );

        bridge_init(&script, "awsenc", "cache-key", true).unwrap();
        cleanup_script(&script);
    }
}
