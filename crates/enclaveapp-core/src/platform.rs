// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform detection utilities.

/// Returns true if running on macOS.
pub fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Returns true if running on Windows.
pub fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

/// Returns true if running inside Windows Subsystem for Linux.
pub fn is_wsl() -> bool {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WSL_DISTRO_NAME").is_ok() {
            return true;
        }
        if let Ok(version) = std::fs::read_to_string("/proc/version") {
            let lower = version.to_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// Returns a human-readable name for the current platform's hardware security module.
pub fn hardware_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Secure Enclave"
    } else if cfg!(target_os = "windows") {
        "TPM 2.0"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn is_macos_true_on_macos() {
        assert!(is_macos());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn is_windows_false_on_macos() {
        assert!(!is_windows());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn hardware_name_secure_enclave_on_macos() {
        assert_eq!(hardware_name(), "Secure Enclave");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn is_wsl_false_on_macos() {
        assert!(!is_wsl());
    }
}
