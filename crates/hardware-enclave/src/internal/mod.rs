#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]
// Internal platform implementation crates, merged into hardware-enclave.
// These modules are not part of the public API.

pub(crate) mod app_adapter;
pub(crate) mod app_storage;
pub(crate) mod bridge;
pub(crate) mod cache;
pub(crate) mod core;
pub(crate) mod wsl;

#[cfg(target_os = "macos")]
pub(crate) mod apple;

#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub(crate) mod windows_webauthn;

#[cfg(target_os = "linux")]
pub(crate) mod keyring;
#[cfg(all(target_os = "linux", target_env = "gnu", feature = "linux-tpm"))]
pub(crate) mod linux_tpm;

// These are only used by the TPM bridge server binary, not by the library.
// Included for workspace completeness.
pub(crate) mod build_support;
pub(crate) mod tpm_bridge;
