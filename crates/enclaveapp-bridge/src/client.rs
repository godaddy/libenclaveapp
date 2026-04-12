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
        format!("/mnt/c/Program Files/{app_name}/{app_name}-bridge.exe"),
        format!("/mnt/c/ProgramData/{app_name}/{app_name}-bridge.exe"),
    ];
    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    // Try which
    if let Ok(output) = Command::new("which")
        .arg(format!("{app_name}-bridge.exe"))
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Call the bridge with a request and return the response.
///
/// Spawns the bridge binary, writes the JSON request to its stdin,
/// closes stdin, and reads a single-line JSON response from stdout.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    let mut child = Command::new(bridge_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "bridge_spawn".into(),
            detail: e.to_string(),
        })?;

    // Write request
    let request_json = serde_json::to_string(request)
        .map_err(|e| enclaveapp_core::Error::Serialization(e.to_string()))?;

    if let Some(ref mut stdin) = child.stdin {
        writeln!(stdin, "{request_json}").map_err(enclaveapp_core::Error::Io)?;
    }
    // Close stdin to signal end of input
    drop(child.stdin.take());

    // Read response
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| enclaveapp_core::Error::KeyOperation {
            operation: "bridge_read".into(),
            detail: "no stdout".into(),
        })?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(enclaveapp_core::Error::Io)?;

    // Wait for child
    let status = child.wait().map_err(enclaveapp_core::Error::Io)?;
    if !status.success() && line.is_empty() {
        return Err(enclaveapp_core::Error::KeyOperation {
            operation: "bridge".into(),
            detail: format!("bridge exited with status {status}"),
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

/// Convenience: encrypt data via the bridge.
pub fn bridge_encrypt(
    bridge_path: &Path,
    app_name: &str,
    plaintext: &[u8],
    biometric: bool,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "encrypt".to_string(),
        params: BridgeParams {
            data: encode_data(plaintext),
            biometric,
            app_name: app_name.to_string(),
        },
    };
    let response = call_bridge(bridge_path, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

/// Convenience: decrypt data via the bridge.
pub fn bridge_decrypt(
    bridge_path: &Path,
    app_name: &str,
    ciphertext: &[u8],
    biometric: bool,
) -> Result<Vec<u8>> {
    let request = BridgeRequest {
        method: "decrypt".to_string(),
        params: BridgeParams {
            data: encode_data(ciphertext),
            biometric,
            app_name: app_name.to_string(),
        },
    };
    let response = call_bridge(bridge_path, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_bridge_returns_none_when_not_found() {
        // On macOS (or any non-WSL environment), no bridge binary should exist
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none());
    }
}
