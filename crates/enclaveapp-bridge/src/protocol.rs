// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! JSON-RPC protocol types shared between server and client.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Bridge request sent from WSL client to Windows server.
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeRequest {
    /// Method: "init", "encrypt", "decrypt", "destroy"
    pub method: String,
    /// Parameters.
    pub params: BridgeParams,
}

/// Bridge request parameters.
#[derive(Debug, Serialize, Deserialize)]
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
            },
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "encrypt");
        assert_eq!(parsed.params.data, "aGVsbG8=");
        assert!(parsed.params.biometric);
        assert_eq!(parsed.params.app_name, "test-app");
    }

    #[test]
    fn bridge_request_defaults_for_missing_fields() {
        let json = r#"{"method":"init","params":{}}"#;
        let parsed: BridgeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.method, "init");
        assert_eq!(parsed.params.data, "");
        assert!(!parsed.params.biometric);
        assert_eq!(parsed.params.app_name, "");
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
}
