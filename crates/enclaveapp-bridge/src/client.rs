// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Bridge client for WSL/Linux. Spawns the Windows bridge binary and
//! communicates via JSON-RPC over stdin/stdout.

use crate::protocol::*;
use enclaveapp_core::{AccessPolicy, Result};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Find the bridge executable on the Windows filesystem (from WSL).
///
/// Searches only well-known trusted install locations under `/mnt/c/`.
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
    None
}

/// Call the bridge with a request and return the response.
///
/// Spawns the bridge binary, writes the JSON request to its stdin,
/// closes stdin, and reads a single-line JSON response from stdout.
pub fn call_bridge(bridge_path: &Path, request: &BridgeRequest) -> Result<BridgeResponse> {
    let mut child = std::process::Command::new(bridge_path)
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

fn build_request(
    method: &str,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
    data: &[u8],
) -> BridgeRequest {
    BridgeRequest {
        method: method.to_string(),
        params: BridgeParams {
            data: encode_data(data),
            access_policy,
            app_name: app_name.to_string(),
            key_label: key_label.to_string(),
        },
    }
}

/// Initialize the bridge-side key lifecycle for a specific app/label pair.
pub fn bridge_init(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    access_policy: AccessPolicy,
) -> Result<()> {
    let request = build_request("init", app_name, key_label, access_policy, &[]);
    drop(call_bridge(bridge_path, &request)?);
    Ok(())
}

/// Convenience: encrypt data via the bridge.
pub fn bridge_encrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    plaintext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = build_request("encrypt", app_name, key_label, access_policy, plaintext);
    let response = call_bridge(bridge_path, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

/// Convenience: decrypt data via the bridge.
pub fn bridge_decrypt(
    bridge_path: &Path,
    app_name: &str,
    key_label: &str,
    ciphertext: &[u8],
    access_policy: AccessPolicy,
) -> Result<Vec<u8>> {
    let request = build_request("decrypt", app_name, key_label, access_policy, ciphertext);
    let response = call_bridge(bridge_path, &request)?;
    let result = response.result.unwrap_or_default();
    decode_data(&result)
}

/// Destroy the bridge-side key for a specific app/label pair.
pub fn bridge_destroy(bridge_path: &Path, app_name: &str, key_label: &str) -> Result<()> {
    let request = build_request("destroy", app_name, key_label, AccessPolicy::None, &[]);
    drop(call_bridge(bridge_path, &request)?);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn find_bridge_returns_none_when_not_found() {
        // On macOS (or any non-WSL environment), no bridge binary should exist
        let result = find_bridge("enclaveapp-nonexistent-test-app");
        assert!(result.is_none());
    }
}
