// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL detection and distribution enumeration.

#[cfg(target_os = "windows")]
use std::process::Command;

/// Information about a detected WSL distribution.
#[derive(Debug, Clone)]
pub struct WslDistro {
    /// Distribution name (e.g., "Ubuntu", "Debian").
    pub name: String,
    /// Windows UNC path to the distro's home directory
    /// (e.g., `\\wsl.localhost\Ubuntu\home\user`).
    pub home_path: Option<std::path::PathBuf>,
}

/// Returns true if the current process is running inside WSL.
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

/// Detect installed WSL distributions (runs on Windows host).
///
/// Returns an empty list on non-Windows platforms.
pub fn detect_distros() -> Vec<WslDistro> {
    #[cfg(target_os = "windows")]
    {
        // Run: wsl --list --quiet
        // Parse output (handle BOM, null bytes in UTF-16 output)
        let output = match Command::new("wsl").args(["--list", "--quiet"]).output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        // WSL outputs UTF-16 on some versions, handle both
        let names: Vec<String> = decode_wsl_output(&output.stdout)
            .lines()
            .map(|l| l.trim().replace('\0', ""))
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        names
            .into_iter()
            .map(|name| {
                let home_path = get_distro_home(&name);
                WslDistro { name, home_path }
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    Vec::new()
}

/// Get the home directory path for a WSL distro, converted to a Windows UNC path.
#[cfg(target_os = "windows")]
fn get_distro_home(distro: &str) -> Option<std::path::PathBuf> {
    let home = find_linux_home(distro)?;
    // Convert Linux path to Windows UNC path
    Some(std::path::PathBuf::from(format!(
        "\\\\wsl.localhost\\{distro}{home}"
    )))
}

#[cfg(target_os = "windows")]
pub(crate) fn find_linux_home(distro: &str) -> Option<String> {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "sh", "-lc", "printf '%s' \"$HOME\""])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_linux_home_output(&output.stdout)
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub(crate) fn find_linux_home(_distro: &str) -> Option<String> {
    None
}

pub(crate) fn decode_wsl_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16le(&bytes[2..]);
    }
    if looks_like_utf16le(bytes) {
        return decode_utf16le(bytes);
    }
    String::from_utf8_lossy(bytes).to_string()
}

#[allow(dead_code)]
pub(crate) fn parse_linux_home_output(bytes: &[u8]) -> Option<String> {
    let home = decode_wsl_output(bytes).trim().to_string();
    if home.is_empty() || home.contains('$') || !home.starts_with('/') {
        return None;
    }
    Some(home)
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return false;
    }

    let mut pairs = 0_usize;
    let mut nul_high_bytes = 0_usize;
    for chunk in bytes.chunks_exact(2).take(32) {
        pairs += 1;
        if chunk[1] == 0 {
            nul_high_bytes += 1;
        }
    }

    pairs > 0 && nul_high_bytes * 2 >= pairs
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wsl_false_on_non_linux() {
        // On macOS (where CI runs), is_wsl() must return false.
        #[cfg(not(target_os = "linux"))]
        assert!(!is_wsl());
    }

    #[test]
    fn test_detect_distros_empty_on_non_windows() {
        // On macOS/Linux, detect_distros() returns empty.
        #[cfg(not(target_os = "windows"))]
        assert!(detect_distros().is_empty());
    }

    #[test]
    fn decode_wsl_output_handles_utf16le_without_bom() {
        let bytes = [
            b'U', 0, b'b', 0, b'u', 0, b'n', 0, b't', 0, b'u', 0, b'\n', 0,
        ];
        assert_eq!(decode_wsl_output(&bytes), "Ubuntu\n");
    }

    #[test]
    fn parse_linux_home_output_rejects_unexpanded_variable() {
        assert_eq!(parse_linux_home_output(b"$HOME\n"), None);
    }

    #[test]
    fn parse_linux_home_output_accepts_absolute_path() {
        assert_eq!(
            parse_linux_home_output(b"/home/tester\n"),
            Some("/home/tester".to_string())
        );
    }
}
