// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Higher-level WSL installation orchestration.
//!
//! Provides the full "detect distros, find homes, inject shell blocks, install
//! dependencies" flow that sshenc, sso-jwt, and other enclave apps share.

use crate::detect::{detect_distros, WslDistro};
use crate::shell_config::{install_block, uninstall_block, ShellBlockConfig};
use std::path::{Path, PathBuf};

/// Configuration for WSL installation.
#[derive(Debug, Clone)]
pub struct WslInstallConfig {
    /// Application name (used in markers and messages).
    pub app_name: String,
    /// Shell block content to inject (the script body, without markers).
    pub shell_block: String,
    /// Whether to install socat + npiperelay bridge dependencies.
    pub install_bridge_deps: bool,
    /// Optional: path to a Linux binary to copy into each distro.
    pub linux_binary_path: Option<PathBuf>,
    /// Target path for the Linux binary inside each distro
    /// (relative to home, e.g., `.local/bin/myapp`).
    pub linux_binary_target: Option<String>,
}

/// Result of configuring or unconfiguring a single distro.
#[derive(Debug)]
pub struct DistroResult {
    /// Distribution name.
    pub distro_name: String,
    /// Outcome: Ok with a list of actions taken, or Err with an error message.
    pub outcome: Result<Vec<String>, String>,
}

/// Configure all detected WSL distros.
///
/// For each distro:
/// 1. Discovers the home directory via UNC path
/// 2. Copies a Linux binary if configured
/// 3. Injects the managed shell block into `.bashrc`/`.zshrc`
/// 4. Installs bridge dependencies (socat + npiperelay) if configured
///
/// Returns one result per distro so the caller can report progress.
pub fn configure_all_distros(config: &WslInstallConfig) -> Vec<DistroResult> {
    let distros = detect_distros();
    distros
        .into_iter()
        .map(|distro| {
            let name = distro.name.clone();
            let outcome = configure_distro(&distro, config);
            DistroResult {
                distro_name: name,
                outcome,
            }
        })
        .collect()
}

/// Remove configuration from all detected WSL distros.
///
/// For each distro:
/// 1. Removes the managed shell block from `.bashrc`/`.zshrc`/`.profile`
/// 2. Removes the Linux binary if `linux_binary_target` is set
///
/// Returns one result per distro.
pub fn unconfigure_all_distros(config: &WslInstallConfig) -> Vec<DistroResult> {
    let distros = detect_distros();
    distros
        .into_iter()
        .map(|distro| {
            let name = distro.name.clone();
            let outcome = unconfigure_distro(&distro, config);
            DistroResult {
                distro_name: name,
                outcome,
            }
        })
        .collect()
}

/// Find the WSL user's home directory path from Windows as a UNC path.
///
/// Tries `\\wsl$\<distro>\<path>` first, then `\\wsl.localhost\<distro>\<path>`.
#[cfg(target_os = "windows")]
pub fn find_wsl_home(distro: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let linux_home = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if linux_home.is_empty() {
        return None;
    }

    for prefix in &[r"\\wsl$", r"\\wsl.localhost"] {
        let win_path = format!(r"{}\{}{}", prefix, distro, linux_home.replace('/', r"\"));
        let path = PathBuf::from(&win_path);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Stub on non-Windows: always returns None.
#[cfg(not(target_os = "windows"))]
pub fn find_wsl_home(_distro: &str) -> Option<PathBuf> {
    None
}

/// Get the Linux home path string for a distro (e.g., `/home/user`).
#[cfg(target_os = "windows")]
fn find_linux_home(distro: &str) -> Option<String> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Configure a single WSL distro.
fn configure_distro(distro: &WslDistro, config: &WslInstallConfig) -> Result<Vec<String>, String> {
    let home_path = distro
        .home_path
        .as_ref()
        .ok_or_else(|| format!("could not find home directory for {}", distro.name))?;

    let mut actions = Vec::new();

    // Copy Linux binary if configured
    #[cfg(target_os = "windows")]
    if let (Some(src), Some(target)) = (&config.linux_binary_path, &config.linux_binary_target) {
        copy_linux_binary(home_path, src, target, &distro.name, &mut actions)?;
    }

    // Inject shell block into config files
    let block_config = ShellBlockConfig::new(&config.app_name, &config.shell_block);
    inject_shell_configs(home_path, &block_config, &mut actions)?;

    // Install bridge dependencies
    #[cfg(target_os = "windows")]
    if config.install_bridge_deps {
        install_bridge_deps(&distro.name, &mut actions)?;
    }

    Ok(actions)
}

/// Remove configuration from a single WSL distro.
fn unconfigure_distro(
    distro: &WslDistro,
    config: &WslInstallConfig,
) -> Result<Vec<String>, String> {
    let home_path = distro
        .home_path
        .as_ref()
        .ok_or_else(|| format!("could not find home directory for {}", distro.name))?;

    let mut actions = Vec::new();

    // Remove shell blocks
    let block_config = ShellBlockConfig::new(&config.app_name, &config.shell_block);
    for name in &[".bashrc", ".zshrc", ".profile"] {
        let path = home_path.join(name);
        if path.exists() {
            match uninstall_block(&path, &block_config) {
                Ok(crate::shell_config::UninstallResult::Removed) => {
                    actions.push(format!("Removed block from {name}"));
                }
                Ok(crate::shell_config::UninstallResult::NotPresent) => {}
                Err(e) => {
                    return Err(format!("{name}: {e}"));
                }
            }
        }
    }

    // Remove Linux binary if configured
    if let Some(target) = &config.linux_binary_target {
        let binary_path = home_path.join(target);
        if binary_path.exists() {
            std::fs::remove_file(&binary_path).map_err(|e| format!("remove binary: {e}"))?;
            actions.push(format!("Removed ~/{target}"));
        }
    }

    Ok(actions)
}

/// Inject the managed shell block into shell config files.
fn inject_shell_configs(
    home_path: &Path,
    block_config: &ShellBlockConfig,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    let mut configured = false;

    // .bashrc -- primary target for bash users
    let bashrc = home_path.join(".bashrc");
    if bashrc.exists() {
        match install_block(&bashrc, block_config) {
            Ok(crate::shell_config::InstallResult::Installed) => {
                actions.push("Updated .bashrc".to_string());
                configured = true;
            }
            Ok(crate::shell_config::InstallResult::AlreadyPresent) => {
                configured = true;
            }
            Err(e) => return Err(format!(".bashrc: {e}")),
        }
    }

    // .zshrc -- for zsh users
    let zshrc = home_path.join(".zshrc");
    if zshrc.exists() {
        match install_block(&zshrc, block_config) {
            Ok(crate::shell_config::InstallResult::Installed) => {
                actions.push("Updated .zshrc".to_string());
                configured = true;
            }
            Ok(crate::shell_config::InstallResult::AlreadyPresent) => {
                configured = true;
            }
            Err(e) => return Err(format!(".zshrc: {e}")),
        }
    }

    // Fallback: .profile or create .bashrc
    if !configured {
        let profile = home_path.join(".profile");
        if profile.exists() {
            match install_block(&profile, block_config) {
                Ok(crate::shell_config::InstallResult::Installed) => {
                    actions.push("Updated .profile".to_string());
                }
                Ok(crate::shell_config::InstallResult::AlreadyPresent) => {}
                Err(e) => return Err(format!(".profile: {e}")),
            }
        } else {
            // Create .bashrc as last resort
            match install_block(&bashrc, block_config) {
                Ok(_) => {
                    actions.push("Created .bashrc".to_string());
                }
                Err(e) => return Err(format!("create .bashrc: {e}")),
            }
        }
    }

    Ok(())
}

/// Copy a Linux binary into the distro's home directory.
#[cfg(target_os = "windows")]
fn copy_linux_binary(
    home_path: &Path,
    src: &Path,
    target: &str,
    distro_name: &str,
    actions: &mut Vec<String>,
) -> Result<(), String> {
    let dest = home_path.join(target);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create directory {}: {e}", parent.display()))?;
    }
    std::fs::copy(src, &dest).map_err(|e| format!("copy binary: {e}"))?;

    // Make executable via WSL
    if let Some(linux_home) = find_linux_home(distro_name) {
        let linux_path = format!("{linux_home}/{target}");
        let _ = std::process::Command::new("wsl")
            .args(["-d", distro_name, "--", "chmod", "+x", &linux_path])
            .status();
    }

    actions.push(format!("Installed binary to ~/{target}"));
    Ok(())
}

/// Install bridge dependencies (socat + npiperelay) into a WSL distro.
#[cfg(target_os = "windows")]
fn install_bridge_deps(distro_name: &str, actions: &mut Vec<String>) -> Result<(), String> {
    // Check and install socat
    if !wsl_has_command(distro_name, "socat") {
        let status = std::process::Command::new("wsl")
            .args([
                "-d",
                distro_name,
                "--",
                "bash",
                "-c",
                "sudo apt-get install -y socat 2>/dev/null \
                 || sudo apk add socat 2>/dev/null \
                 || sudo dnf install -y socat 2>/dev/null",
            ])
            .status();
        match status {
            Ok(s) if s.success() => actions.push("Installed socat".to_string()),
            _ => actions.push("Warning: could not install socat automatically".to_string()),
        }
    } else {
        actions.push("socat already installed".to_string());
    }

    // Check and install npiperelay
    if !wsl_has_command(distro_name, "npiperelay.exe") {
        let install_script = r#"
            set -e
            ARCH=$(uname -m)
            case "$ARCH" in
                x86_64) GOARCH=amd64 ;;
                aarch64) GOARCH=arm64 ;;
                *) echo "unsupported arch: $ARCH"; exit 1 ;;
            esac
            URL="https://github.com/jstarks/npiperelay/releases/latest/download/npiperelay_linux_${GOARCH}.tar.gz"
            TMP=$(mktemp -d)
            if command -v curl >/dev/null 2>&1; then
                curl -sL "$URL" | tar xz -C "$TMP" 2>/dev/null
            elif command -v wget >/dev/null 2>&1; then
                wget -qO- "$URL" | tar xz -C "$TMP" 2>/dev/null
            else
                echo "no curl or wget"; exit 1
            fi
            if [ -f "$TMP/npiperelay.exe" ]; then
                sudo mv "$TMP/npiperelay.exe" /usr/local/bin/npiperelay.exe
                sudo chmod +x /usr/local/bin/npiperelay.exe
                echo "OK"
            else
                if command -v go >/dev/null 2>&1; then
                    GOBIN=/usr/local/bin go install github.com/jstarks/npiperelay@latest 2>/dev/null && echo "OK" || echo "FAIL"
                else
                    echo "FAIL"
                fi
            fi
            rm -rf "$TMP"
        "#;
        let output = std::process::Command::new("wsl")
            .args(["-d", distro_name, "--", "bash", "-c", install_script])
            .output();
        match output {
            Ok(o) if String::from_utf8_lossy(&o.stdout).contains("OK") => {
                actions.push("Installed npiperelay".to_string());
            }
            _ => {
                actions.push("Warning: could not install npiperelay automatically".to_string());
            }
        }
    } else {
        actions.push("npiperelay already installed".to_string());
    }

    Ok(())
}

/// Check if a command exists in a WSL distro.
#[cfg(target_os = "windows")]
fn wsl_has_command(distro_name: &str, cmd: &str) -> bool {
    std::process::Command::new("wsl")
        .args(["-d", distro_name, "--", "command", "-v", cmd])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Decode WSL output, handling both UTF-8 and UTF-16LE (with BOM).
pub fn decode_wsl_output(bytes: &[u8]) -> String {
    // Check for UTF-16LE BOM (0xFF 0xFE)
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, let_underscore_drop)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("enclaveapp-wsl-install-test-{pid}-{id}-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_inject_shell_configs_bashrc() {
        let dir = test_dir("inject-bashrc");
        std::fs::write(dir.join(".bashrc"), "# existing\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export FOO=bar");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(!actions.is_empty());
        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(content.contains("BEGIN testapp managed block"));
        assert!(content.contains("export FOO=bar"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_zshrc() {
        let dir = test_dir("inject-zshrc");
        std::fs::write(dir.join(".zshrc"), "# zsh config\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export BAR=baz");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".zshrc")));
        let content = std::fs::read_to_string(dir.join(".zshrc")).unwrap();
        assert!(content.contains("export BAR=baz"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_both() {
        let dir = test_dir("inject-both");
        std::fs::write(dir.join(".bashrc"), "# bash\n").unwrap();
        std::fs::write(dir.join(".zshrc"), "# zsh\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export X=1");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".bashrc")));
        assert!(actions.iter().any(|a| a.contains(".zshrc")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_fallback_profile() {
        let dir = test_dir("inject-profile");
        // No .bashrc or .zshrc, only .profile
        std::fs::write(dir.join(".profile"), "# profile\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export Y=2");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".profile")));
        let content = std::fs::read_to_string(dir.join(".profile")).unwrap();
        assert!(content.contains("export Y=2"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_shell_configs_creates_bashrc() {
        let dir = test_dir("inject-create");
        // No existing shell configs at all

        let config = ShellBlockConfig::new("testapp", "export Z=3");
        let mut actions = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions).unwrap();

        assert!(actions.iter().any(|a| a.contains(".bashrc")));
        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(content.contains("export Z=3"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_inject_idempotent() {
        let dir = test_dir("inject-idempotent");
        std::fs::write(dir.join(".bashrc"), "# existing\n").unwrap();

        let config = ShellBlockConfig::new("testapp", "export A=1");
        let mut actions1 = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions1).unwrap();
        let content1 = std::fs::read_to_string(dir.join(".bashrc")).unwrap();

        let mut actions2 = Vec::new();
        inject_shell_configs(&dir, &config, &mut actions2).unwrap();
        let content2 = std::fs::read_to_string(dir.join(".bashrc")).unwrap();

        assert_eq!(content1, content2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unconfigure_distro_removes_blocks() {
        let dir = test_dir("unconfigure");
        std::fs::write(dir.join(".bashrc"), "# before\n").unwrap();

        let block_config = ShellBlockConfig::new("testapp", "export Q=1");
        install_block(dir.join(".bashrc").as_path(), &block_config).unwrap();

        let distro = WslDistro {
            name: "TestDistro".to_string(),
            home_path: Some(dir.clone()),
        };
        let config = WslInstallConfig {
            app_name: "testapp".to_string(),
            shell_block: "export Q=1".to_string(),
            install_bridge_deps: false,
            linux_binary_path: None,
            linux_binary_target: None,
        };
        let result = unconfigure_distro(&distro, &config).unwrap();
        assert!(result.iter().any(|a| a.contains("Removed")));

        let content = std::fs::read_to_string(dir.join(".bashrc")).unwrap();
        assert!(!content.contains("BEGIN testapp managed block"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_decode_wsl_output_utf8() {
        let input = b"Ubuntu\nDebian\n";
        let result = decode_wsl_output(input);
        assert_eq!(result, "Ubuntu\nDebian\n");
    }

    #[test]
    fn test_decode_wsl_output_utf16le_bom() {
        // UTF-16LE with BOM: "Hi\n"
        let mut bytes = vec![0xFF_u8, 0xFE]; // BOM
        for ch in "Hi\n".encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_wsl_output(&bytes);
        assert_eq!(result, "Hi\n");
    }

    #[test]
    fn test_find_wsl_home_non_windows() {
        // On non-Windows, always returns None
        #[cfg(not(target_os = "windows"))]
        assert!(find_wsl_home("Ubuntu").is_none());
    }

    #[test]
    fn test_distro_result_debug() {
        let result = DistroResult {
            distro_name: "Ubuntu".to_string(),
            outcome: Ok(vec!["Updated .bashrc".to_string()]),
        };
        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("Ubuntu"));
    }

    #[test]
    fn test_wsl_install_config_clone() {
        let config = WslInstallConfig {
            app_name: "test".to_string(),
            shell_block: "# test".to_string(),
            install_bridge_deps: false,
            linux_binary_path: None,
            linux_binary_target: None,
        };
        let cloned = config.clone();
        assert_eq!(cloned.app_name, config.app_name);
        assert_eq!(cloned.shell_block, config.shell_block);
    }
}
