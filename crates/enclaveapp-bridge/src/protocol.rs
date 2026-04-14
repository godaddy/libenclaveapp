// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! JSON-RPC protocol types shared between server and client.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Bridge request sent from WSL client to Windows server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRequest {
    /// Method: "init", "encrypt", "decrypt", "delete", "destroy"
    pub method: String,
    /// Parameters.
    pub params: BridgeParams,
}

/// Bridge request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeParams {
    /// Base64-encoded data (plaintext for encrypt, ciphertext for decrypt).
    #[serde(default)]
    pub data: String,
    /// Whether to require biometric authentication.
    #[serde(default)]
    pub biometric: bool,
    /// Application name (determines TPM key name).
    #[serde(default)]
    pub app_name: String,
    /// Key label within the application namespace.
    #[serde(default)]
    pub key_label: String,
}

/// Bridge response from Windows server to WSL client.
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeResponse {
    /// Base64-encoded result data (on success).
    pub result: Option<String>,
    /// Error message (on failure).
    pub error: Option<String>,
}

impl BridgeResponse {
    /// Create a successful response with data.
    pub fn success(data: &str) -> Self {
        BridgeResponse {
            result: Some(data.to_string()),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(msg: &str) -> Self {
        BridgeResponse {
            result: None,
            error: Some(msg.to_string()),
        }
    }

    /// Create a successful response with no data.
    pub fn ok() -> Self {
        BridgeResponse {
            result: Some(String::new()),
            error: None,
        }
    }

    /// Require that the response contains a success result payload.
    pub fn require_result(&self, operation: &str) -> enclaveapp_core::Result<&str> {
        if let Some(error) = &self.error {
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: operation.into(),
                detail: error.clone(),
            });
        }

        self.result
            .as_deref()
            .ok_or_else(|| enclaveapp_core::Error::KeyOperation {
                operation: operation.into(),
                detail: "bridge response missing result payload".into(),
            })
    }

    /// Require an acknowledged success response.
    pub fn require_ok(&self, operation: &str) -> enclaveapp_core::Result<()> {
        let _unused = self.require_result(operation)?;
        Ok(())
    }

    /// Decode a base64-encoded success payload.
    pub fn decode_result(&self, operation: &str) -> enclaveapp_core::Result<Vec<u8>> {
        decode_data(self.require_result(operation)?)
    }
}

/// Encode binary data as base64 for the bridge protocol.
pub fn encode_data(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 data from the bridge protocol.
pub fn decode_data(encoded: &str) -> enclaveapp_core::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| enclaveapp_core::Error::Serialization(format!("base64 decode: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bridge_request_serde_roundtrip() {
        let request = BridgeRequest {
            method: "encrypt".to_string(),
            params: BridgeParams {
                data: "aGVsbG8=".to_string(),
                biometric: true,
                app_name: "test-app".to_string(),
                key_label: "cache-key".to_string(),
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "encrypt");
        assert_eq!(parsed.params.data, "aGVsbG8=");
        assert!(parsed.params.biometric);
        assert_eq!(parsed.params.app_name, "test-app");
        assert_eq!(parsed.params.key_label, "cache-key");
    }

    #[test]
    fn bridge_request_defaults_for_missing_fields() {
        let json = r#"{"method":"init","params":{}}"#;
        let parsed: BridgeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.method, "init");
        assert_eq!(parsed.params.data, "");
        assert!(!parsed.params.biometric);
        assert_eq!(parsed.params.app_name, "");
        assert_eq!(parsed.params.key_label, "");
    }

    #[test]
    fn bridge_response_success_construction() {
        let resp = BridgeResponse::success("c29tZSBkYXRh");
        assert_eq!(resp.result, Some("c29tZSBkYXRh".to_string()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_error_construction() {
        let resp = BridgeResponse::error("something went wrong");
        assert!(resp.result.is_none());
        assert_eq!(resp.error, Some("something went wrong".to_string()));
    }

    #[test]
    fn bridge_response_ok_construction() {
        let resp = BridgeResponse::ok();
        assert_eq!(resp.result, Some(String::new()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_serde_roundtrip() {
        let resp = BridgeResponse::success("dGVzdA==");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.result, Some("dGVzdA==".to_string()));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn encode_decode_roundtrip_empty() {
        let data = b"";
        let encoded = encode_data(data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_small() {
        let data = b"hello, world!";
        let encoded = encode_data(data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_large() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_data_rejects_invalid_base64() {
        let result = decode_data("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn bridge_request_all_methods() {
        for method in &["init", "encrypt", "decrypt", "delete", "destroy"] {
            let request = BridgeRequest {
                method: (*method).to_string(),
                params: BridgeParams {
                    data: String::new(),
                    biometric: false,
                    app_name: "test".to_string(),
                    key_label: "cache-key".to_string(),
                },
            };
            let json = serde_json::to_string(&request).unwrap();
            let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.method, *method);
        }
    }

    #[test]
    fn bridge_response_success_with_empty_result() {
        let resp = BridgeResponse::ok();
        assert_eq!(resp.result, Some(String::new()));
        assert!(resp.error.is_none());

        // Verify it roundtrips through JSON
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.result, Some(String::new()));
    }

    #[test]
    fn bridge_response_error_preserves_message() {
        let msg = "TPM device not found: error code 0x8028000F";
        let resp = BridgeResponse::error(msg);
        assert_eq!(resp.error.as_deref(), Some(msg));
        assert!(resp.result.is_none());

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.error.as_deref(), Some(msg));
    }

    #[test]
    fn encode_decode_binary_data_with_null_bytes() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x00, 0xFF, 0x00, 0xFE];
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_large_data_1mb() {
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_data(&data);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_data_invalid_base64_returns_error() {
        let result = decode_data("!!!not-base64!!!");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("base64"));
    }

    #[test]
    fn decode_data_empty_string_returns_empty_vec() {
        let result = decode_data("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn bridge_params_default_values() {
        let json = r#"{}"#;
        let params: BridgeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.data, "");
        assert!(!params.biometric);
        assert_eq!(params.app_name, "");
    }

    #[test]
    fn find_bridge_returns_none_on_macos() {
        // On macOS there's no /mnt/c/ and no bridge binary
        let result = crate::find_bridge("sshenc");
        assert!(result.is_none());
    }
}
