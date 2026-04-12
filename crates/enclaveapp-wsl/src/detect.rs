// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL detection and distribution enumeration.

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
        let output = match std::process::Command::new("wsl")
            .args(["--list", "--quiet"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        // WSL outputs UTF-16 on some versions, handle both
        let stdout = String::from_utf8_lossy(&output.stdout);
        let names: Vec<String> = stdout
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
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let home = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if home.is_empty() {
        return None;
    }
    // Convert Linux path to Windows UNC path
    Some(std::path::PathBuf::from(format!(
        "\\\\wsl.localhost\\{distro}{home}"
    )))
}

#[cfg(test)]
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
}
