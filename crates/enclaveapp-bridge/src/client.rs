// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.

use crate::protocol::*;
use enclaveapp_core::{Error, Result};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_BRIDGE_RESPONSE_BYTES: u64 = 64 * 1024;

/// Ordered trusted bridge install locations on the Windows filesystem (from WSL).
pub fn trusted_bridge_paths(app_name: &str) -> Vec<PathBuf> {
    [
        format!("/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"),
        format!("/mnt/c/Program Files/{app_name}/{app_name}-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-bridge.exe"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// Find the bridge executable, preferring explicit trusted paths before
/// standard install locations. Ambient PATH lookup is intentionally excluded.
pub fn find_bridge_with_paths(app_name: &str, extra_paths: &[PathBuf]) -> Option<PathBuf> {
    find_bridge_in_candidates(
        extra_paths
            .iter()
            .cloned()
            .chain(trusted_bridge_paths(app_name)),
    )
}

/// Find the bridge executable in standard trusted install locations.
pub fn find_bridge(app_name: &str) -> Option<PathBuf> {
    find_bridge_with_paths(app_name, &[])
}

fn find_bridge_in_candidates<I>(candidates: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    candidates
        .into_iter()
        .find(|path| is_bridge_binary_candidate(path))
}

fn is_bridge_binary_candidate(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        && has_pe_signature(path)
}

fn has_pe_signature(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut dos_header = [0_u8; 64];
    if file.read_exact(&mut dos_header).is_err() || dos_header[..2] != *b"MZ" {
        return false;
    }

    let pe_offset = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as u64;
    if pe_offset < dos_header.len() as u64 {
        return false;
    }
    if file.seek(SeekFrom::Start(pe_offset)).is_err() {
        return false;
    }

    let mut signature = [0_u8; 4];
    file.read_exact(&mut signature).is_ok() && signature == *b"PE\0\0"
}

struct BridgeProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl BridgeProcess {
    fn spawn(bridge_path: &Path) -> Result<Self> {
        let mut child = Command::new(bridge_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::KeyOperation {
                operation: "bridge_spawn".into(),
                detail: e.to_string(),
            })?;

        let stdin = child.stdin.take().ok_or_else(|| Error::KeyOperation {
            operation: "bridge_write".into(),
            detail: "no stdin".into(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| Error::KeyOperation {
            operation: "bridge_read".into(),
            detail: "no stdout".into(),
        })?;

        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

fn read_bridge_response(
    stdout: &mut std::io::BufReader<ChildStdout>,
    max_response_bytes: u64,
) -> Result<BridgeResponse> {
    let mut line = Vec::new();
    let bytes_read = stdout
        .by_ref()
        .take(max_response_bytes + 1)
        .read_until(b'\n', &mut line)
        .map_err(Error::Io)?;
    if (bytes_read as u64) > max_response_bytes {
        return Err(Error::KeyOperation {
            operation: "bridge_read".into(),
            detail: format!("bridge response exceeded {} bytes", max_response_bytes),
        });
    }

    if line.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::KeyOperation {
            operation: "bridge_read".into(),
            detail: "bridge returned no response".into(),
        });
    }

    let line = String::from_utf8(line)
        .map_err(|e| Error::Serialization(format!("bridge response utf-8: {e}")))?;
    serde_json::from_str(&line).map_err(|e| Error::Serialization(format!("bridge response: {e}")))
}

fn send_bridge_request(
    stdin: &mut ChildStdin,
    stdout: &mut std::io::BufReader<ChildStdout>,
    request: &BridgeRequest,
    max_response_bytes: u64,
) -> Result<BridgeResponse> {
    let request_json =
        serde_json::to_string(request).map_err(|e| Error::Serialization(e.to_string()))?;
    writeln!(stdin, "{request_json}").map_err(Error::Io)?;
    stdin.flush().map_err(Error::Io)?;
    read_bridge_response(stdout, max_response_bytes)
}

fn response_limit_for_request(request: &BridgeRequest) -> u64 {
    let request_data_bytes = request.params.data.len() as u64;
    DEFAULT_MAX_BRIDGE_RESPONSE_BYTES.max(request_data_bytes.saturating_mul(2).saturating_add(1024))
}

fn wait_for_process_exit(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(Error::Io)? {
            return if status.success() {
                Ok(())
            } else {
                Err(Error::KeyOperation {
                    operation: "bridge".into(),
                    detail: format!("bridge exited with status {status}"),
                })
            };
        }

        if Instant::now() >= deadline {
            drop(child.kill());
            drop(child.wait());
            return Err(Error::KeyOperation {
                operation: "bridge_timeout".into(),
                detail: format!("bridge did not exit within {:?}", timeout),
            });
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn run_bridge_exchange_with_timeout<T, F>(
    bridge_path: &Path,
    timeout: Duration,
    worker: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(ChildStdin, ChildStdout) -> Result<T> + Send + 'static,
{
    let BridgeProcess {
        mut child,
        stdin,
        stdout,
    } = BridgeProcess::spawn(bridge_path)?;
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = worker(stdin, stdout);
        let _unused = tx.send(result);
    });

    let response_result = match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            drop(child.kill());
            drop(child.wait());
            let _unused = handle.join();
            return Err(Error::KeyOperation {
                operation: "bridge_timeout".into(),
                detail: format!("bridge request timed out after {:?}", timeout),
            });
        }
        Err(RecvTimeoutError::Disconnected) => {
            drop(child.kill());
            drop(child.wait());
            let _unused = handle.join();
            return Err(Error::KeyOperation {
                operation: "bridge".into(),
                detail: "bridge I/O worker exited unexpectedly".into(),
            });
        }
    };

    let _unused = handle.join();
    wait_for_process_exit(&mut child, timeout)?;
    response_result
}

fn call_bridge_with_timeout(
    bridge_path: &Path,
    request: &BridgeRequest,
    timeout: Duration,
) -> Result<BridgeResponse> {
    let request = request.clone();
    let max_response_bytes = response_limit_for_request(&request);
    run_bridge_exchange_with_timeout(bridge_path, timeout, move |mut stdin, stdout| {
        let mut stdout = std::io::BufReader::new(stdout);
        send_bridge_request(&mut stdin, &mut stdout, &request, max_response_bytes)
    })
}

fn call_bridge_after_init_with_timeout(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    biometric: bool,
    request: &BridgeRequest,
    timeout: Duration,
) -> Result<BridgeResponse> {
    let init_request = init_request(app_name, key_label, biometric);
    let request = request.clone();
    let max_response_bytes = response_limit_for_request(&request);
    run_bridge_exchange_with_timeout(bridge_path, timeout, move |mut stdin, stdout| {
        let mut stdout = std::io::BufReader::new(stdout);
        send_bridge_request(
            &mut stdin,
            &mut stdout,
            &init_request,
            DEFAULT_MAX_BRIDGE_RESPONSE_BYTES,
        )?
        .require_ok("bridge_init")?;
        send_bridge_request(&mut stdin, &mut stdout, &request, max_response_bytes)
    })
}

/// Call the bridge with a request and return the response.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    call_bridge_with_timeout(bridge_path, request, DEFAULT_BRIDGE_TIMEOUT)
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
    let response = call_bridge_with_timeout(
        bridge_path,
        &init_request(app_name, key_label, biometric),
        DEFAULT_BRIDGE_TIMEOUT,
    )?;
    response.require_ok("bridge_init")
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
    response.require_ok("bridge_delete")
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
    let response = call_bridge_after_init_with_timeout(
        bridge_path,
        app_name,
        key_label,
        biometric,
        &request,
        DEFAULT_BRIDGE_TIMEOUT,
    )?;
    response.decode_result("bridge_encrypt")
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
    let response = call_bridge_after_init_with_timeout(
        bridge_path,
        app_name,
        key_label,
        biometric,
        &request,
        DEFAULT_BRIDGE_TIMEOUT,
    )?;
    response.decode_result("bridge_decrypt")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);
    static SCRIPT_TEST_MUTEX: Mutex<()> = Mutex::new(());
    static PATH_TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn lock_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(unix)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = env::temp_dir().join(format!(
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
        let base = env::temp_dir().join(format!(
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

    fn temp_bridge_binary(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "enclaveapp-bridge-bin-{}-{}-{name}",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let mut pe = vec![0_u8; 0x84];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        fs::write(&path, pe).unwrap();
        path
    }

    #[test]
    fn find_bridge_returns_none_when_not_found() {
        // On macOS (or any non-WSL environment), no bridge binary should exist
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none());
    }

    #[test]
    fn find_bridge_with_paths_prefers_explicit_locations() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        let explicit = temp_bridge_binary("explicit-bridge.exe");
        let found = find_bridge_with_paths("demo", std::slice::from_ref(&explicit));
        assert_eq!(found.as_deref(), Some(explicit.as_path()));
        fs::remove_file(&explicit).unwrap();
    }

    #[test]
    fn bridge_discovery_skips_non_file_candidates() {
        let root = env::temp_dir().join(format!(
            "enclaveapp-bridge-discovery-skip-{}",
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).unwrap();

        let non_file = root.join("not-a-bridge");
        fs::create_dir_all(&non_file).unwrap();
        let trusted = temp_bridge_binary("trusted-bridge.exe");

        let found = find_bridge_in_candidates(vec![non_file, trusted.clone()]);
        assert_eq!(found.as_deref(), Some(trusted.as_path()));

        fs::remove_file(&trusted).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn bridge_discovery_skips_non_bridge_files() {
        let root = env::temp_dir().join(format!(
            "enclaveapp-bridge-discovery-invalid-{}",
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).unwrap();

        let invalid = root.join("invalid-bridge.exe");
        fs::write(&invalid, b"#!/bin/sh\nexit 0\n").unwrap();
        let trusted = temp_bridge_binary("trusted-fallback-bridge.exe");

        let found = find_bridge_in_candidates(vec![invalid.clone(), trusted.clone()]);
        assert_eq!(found.as_deref(), Some(trusted.as_path()));

        fs::remove_file(&invalid).unwrap();
        fs::remove_file(&trusted).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn bridge_discovery_rejects_mz_without_pe_signature() {
        let root = env::temp_dir().join(format!(
            "enclaveapp-bridge-discovery-mz-only-{}",
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).unwrap();

        let invalid = root.join("looks-like-bridge.exe");
        fs::write(&invalid, b"MZnot-a-real-pe").unwrap();
        let trusted = temp_bridge_binary("trusted-pe-bridge.exe");

        let found = find_bridge_in_candidates(vec![invalid.clone(), trusted.clone()]);
        assert_eq!(found.as_deref(), Some(trusted.as_path()));

        fs::remove_file(&invalid).unwrap();
        fs::remove_file(&trusted).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn find_bridge_ignores_path_hits() {
        let _lock = lock_mutex(&PATH_TEST_MUTEX);
        let fake_dir = env::temp_dir().join(format!(
            "enclaveapp-bridge-path-test-{}",
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&fake_dir).unwrap();
        let fake_bridge = fake_dir.join("sshenc-tpm-bridge.exe");
        fs::write(&fake_bridge, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&fake_bridge).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&fake_bridge, perms).unwrap();
        }

        let previous_path = env::var_os("PATH");
        let updated_path = match previous_path.as_ref() {
            Some(path) => format!("{}:{}", fake_dir.display(), PathBuf::from(path).display()),
            None => fake_dir.display().to_string(),
        };
        env::set_var("PATH", updated_path);

        let found = find_bridge("sshenc");
        assert!(found.is_none());

        match previous_path {
            Some(path) => env::set_var("PATH", path),
            None => env::remove_var("PATH"),
        }
        drop(fs::remove_file(&fake_bridge));
        drop(fs::remove_dir_all(&fake_dir));
    }

    #[test]
    fn bridge_encrypt_initializes_before_encrypting() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
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
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
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
    fn call_bridge_times_out_when_bridge_never_responds() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        #[cfg(unix)]
        let script = temp_script(
            "hang.sh",
            r#"#!/bin/sh
sleep 2
"#,
        );
        #[cfg(windows)]
        let script = temp_script("hang", r#"Start-Sleep -Seconds 2"#);

        let request = BridgeRequest {
            method: "delete".to_string(),
            params: BridgeParams {
                data: String::new(),
                biometric: false,
                app_name: "awsenc".to_string(),
                key_label: "cache-key".to_string(),
            },
        };
        let err =
            call_bridge_with_timeout(&script, &request, Duration::from_millis(100)).unwrap_err();
        assert!(err.to_string().contains("timed out"));
        cleanup_script(&script);
    }

    #[test]
    fn call_bridge_rejects_oversized_response() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        let payload = format!(
            "{{\"result\":\"{}\",\"error\":null}}\n",
            "A".repeat((DEFAULT_MAX_BRIDGE_RESPONSE_BYTES as usize) + 32)
        );
        #[cfg(unix)]
        let script = temp_script(
            "oversized-response.sh",
            &format!(
                "#!/bin/sh\nprintf '%s' '{}'\n",
                payload.replace('\'', "'\"'\"'")
            ),
        );
        #[cfg(windows)]
        let script = temp_script(
            "oversized-response",
            &format!(r#"[Console]::Out.Write("{payload}")"#),
        );

        let request = BridgeRequest {
            method: "delete".to_string(),
            params: BridgeParams {
                data: String::new(),
                biometric: false,
                app_name: "awsenc".to_string(),
                key_label: "cache-key".to_string(),
            },
        };
        let err = call_bridge(&script, &request).unwrap_err();
        assert!(err.to_string().contains("exceeded"));
        cleanup_script(&script);
    }

    #[test]
    fn call_bridge_accepts_large_encrypt_response_when_request_payload_is_large() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        let result_data = "A".repeat((DEFAULT_MAX_BRIDGE_RESPONSE_BYTES as usize) + 32);
        #[cfg(unix)]
        let script = temp_script(
            "large-response.sh",
            &format!(
                "#!/bin/sh\nread request_line\nprintf '%s' '{}'\n",
                format!("{{\"result\":\"{result_data}\",\"error\":null}}\n")
                    .replace('\'', "'\"'\"'")
            ),
        );
        #[cfg(windows)]
        let script = temp_script(
            "large-response",
            &format!(
                r#"$requestLine = [Console]::In.ReadLine()
[Console]::Out.Write("{{""result"":""{result_data}"",""error"":null}}`n")"#
            ),
        );

        let request = BridgeRequest {
            method: "encrypt".to_string(),
            params: BridgeParams {
                data: "B".repeat(DEFAULT_MAX_BRIDGE_RESPONSE_BYTES as usize),
                biometric: false,
                app_name: "awsenc".to_string(),
                key_label: "cache-key".to_string(),
            },
        };
        let response = call_bridge_with_timeout(&script, &request, Duration::from_secs(2)).unwrap();
        assert_eq!(response.result.as_deref(), Some(result_data.as_str()));
        cleanup_script(&script);
    }

    #[test]
    fn bridge_init_sends_key_label() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
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

    #[test]
    fn bridge_encrypt_rejects_missing_result_payload() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        #[cfg(unix)]
        let script = temp_script(
            "encrypt-missing-result.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*) printf '{"result":"","error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
read request_line
case "$request_line" in
  *'"method":"encrypt"'*) printf '{"result":null,"error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        #[cfg(windows)]
        let script = temp_script(
            "encrypt-missing-result",
            r#"$initLine = [Console]::In.ReadLine()
if ($initLine -like '*"method":"init"*') {
  [Console]::Out.WriteLine('{"result":"","error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected init request"}')
  exit 0
}
$requestLine = [Console]::In.ReadLine()
if ($requestLine -like '*"method":"encrypt"*') {
  [Console]::Out.WriteLine('{"result":null,"error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected request"}')
}
"#,
        );

        let error = bridge_encrypt(&script, "awsenc", "cache-key", b"ignored", true).unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[test]
    fn bridge_init_rejects_missing_result_payload() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        #[cfg(unix)]
        let script = temp_script(
            "init-missing-result.sh",
            r#"#!/bin/sh
read request_line
case "$request_line" in
  *'"method":"init"'*) printf '{"result":null,"error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected request"}\n' ;;
esac
"#,
        );
        #[cfg(windows)]
        let script = temp_script(
            "init-missing-result",
            r#"$requestLine = [Console]::In.ReadLine()
if ($requestLine -like '*"method":"init"*') {
  [Console]::Out.WriteLine('{"result":null,"error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected request"}')
}
"#,
        );

        let error = bridge_init(&script, "awsenc", "cache-key", true).unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[test]
    fn bridge_encrypt_rejects_missing_init_result_payload() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        #[cfg(unix)]
        let script = temp_script(
            "encrypt-missing-init-result.sh",
            r#"#!/bin/sh
read init_line
case "$init_line" in
  *'"method":"init"'*) printf '{"result":null,"error":null}\n' ;;
  *) printf '{"result":null,"error":"unexpected init request"}\n'; exit 0 ;;
esac
"#,
        );
        #[cfg(windows)]
        let script = temp_script(
            "encrypt-missing-init-result",
            r#"$initLine = [Console]::In.ReadLine()
if ($initLine -like '*"method":"init"*') {
  [Console]::Out.WriteLine('{"result":null,"error":null}')
} else {
  [Console]::Out.WriteLine('{"result":null,"error":"unexpected init request"}')
  exit 0
}
"#,
        );

        let error = bridge_encrypt(&script, "awsenc", "cache-key", b"ignored", true).unwrap_err();
        assert!(error.to_string().contains("missing result payload"));
        cleanup_script(&script);
    }

    #[test]
    fn bridge_delete_reaps_child_after_error_response() {
        let _lock = lock_mutex(&SCRIPT_TEST_MUTEX);
        let sentinel = env::temp_dir().join(format!(
            "enclaveapp-bridge-test-sentinel-{}-{}",
            std::process::id(),
            SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        drop(fs::remove_file(&sentinel));
        #[cfg(unix)]
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
        #[cfg(windows)]
        let script = temp_script(
            "delete-error",
            &format!(
                r#"$sentinel = '{}'
try {{
  $requestLine = [Console]::In.ReadLine()
  [Console]::Out.WriteLine('{{"result":null,"error":"boom"}}')
  while (($line = [Console]::In.ReadLine()) -ne $null) {{ }}
}} finally {{
  [System.IO.File]::WriteAllText($sentinel, 'done')
}}
"#,
                sentinel.display()
            ),
        );

        let error = bridge_delete(&script, "awsenc", "cache-key").unwrap_err();
        assert!(error.to_string().contains("boom"));
        assert!(
            sentinel.exists(),
            "bridge process should be reaped before returning"
        );
        cleanup_script(&script);
        drop(fs::remove_file(sentinel));
    }
}
