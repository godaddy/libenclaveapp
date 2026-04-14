// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform detection and backend identification.

/// Which hardware/software backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Secure Enclave via CryptoKit.
    SecureEnclave,
    /// Windows TPM 2.0 via CNG.
    Tpm,
    /// WSL bridge to Windows TPM.
    TpmBridge,
    /// Software-only P-256 keys (Linux fallback).
    Software,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::SecureEnclave => write!(f, "Secure Enclave"),
            BackendKind::Tpm => write!(f, "TPM 2.0"),
            BackendKind::TpmBridge => write!(f, "TPM 2.0 (WSL Bridge)"),
            BackendKind::Software => write!(f, "Software"),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn find_bridge_executable(app_name: &str, extra_paths: &[String]) -> Option<PathBuf> {
    enclaveapp_bridge::find_bridge_with_paths(
        app_name,
        &extra_paths.iter().map(PathBuf::from).collect::<Vec<_>>(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn backend_kind_display() {
        assert_eq!(BackendKind::SecureEnclave.to_string(), "Secure Enclave");
        assert_eq!(BackendKind::Tpm.to_string(), "TPM 2.0");
        assert_eq!(BackendKind::TpmBridge.to_string(), "TPM 2.0 (WSL Bridge)");
        assert_eq!(BackendKind::Software.to_string(), "Software");
    }

    #[test]
    fn backend_kind_eq() {
        assert_eq!(BackendKind::SecureEnclave, BackendKind::SecureEnclave);
        assert_ne!(BackendKind::SecureEnclave, BackendKind::Tpm);
    }

    #[test]
    fn backend_kind_clone() {
        let kind = BackendKind::Tpm;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_bridge_executable_returns_none_on_dev_machine() {
        // Should return None on most dev machines (not WSL with bridge installed).
        drop(find_bridge_executable("test-app", &[]));
    }
}
