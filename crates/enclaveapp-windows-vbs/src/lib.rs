// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Probe and (eventually) host-side wrappers for the Windows
//! **VBS Enclave user-bound key** path.
//!
//! ## Status
//!
//! This crate currently exposes only [`probe`] — a non-firing
//! prerequisites check. The actual enclave DLL, the EDL boundary,
//! and the `KeyCredentialManager`-bound key flow are scheduled as
//! a follow-up PR (see `docs/vbs-enclave-plan.md` in `gocode-dev`).
//! Until that lands, callers should treat
//! [`Availability::Available`] as "prerequisites are met" and still
//! fall back to the [soft Hello consent gate][soft-gate] for actual
//! encrypt/decrypt operations.
//!
//! [soft-gate]: enclaveapp_windows::hello_gate
//!
//! ## What "VBS Enclave user-bound key" means
//!
//! Microsoft's hardware-enforced Windows Hello encryption path,
//! introduced in Windows 11 24H2 (build 26100.2314+):
//!
//! 1. A signed user-mode DLL (the *enclave*) is loaded into VTL1
//!    (Isolated User Mode), a separate virtualization-protected
//!    address space the host (VTL0) process cannot read.
//! 2. Inside VTL1, the enclave calls
//!    `KeyCredentialManager::RequestCreateAsync` with the
//!    *VirtualizationBasedSecurityEnclave* challenge-response kind.
//!    The resulting key is bound to (a) the current Windows Hello
//!    identity and (b) the enclave's image identity (signer hash +
//!    image hash).
//! 3. Decrypt operations require the OS-mediated Hello gesture
//!    (biometric or PIN) to actually fire — there is no user-mode
//!    Boolean to hook. Code execution as the user in VTL0 cannot
//!    forge a consent or extract the key material.
//!
//! Closes the same-UID code-execution gap that the soft Hello gate
//! ([`enclaveapp_windows::hello_gate`]) accepts.
//!
//! ## Cross-platform
//!
//! Compiles to no-op stubs on non-Windows targets so workspace-wide
//! builds don't break. [`probe`] returns
//! [`Availability::Unavailable`] with [`UnavailableReason::NotWindows`].

#[cfg(target_os = "windows")]
mod windows_impl;

#[cfg(not(target_os = "windows"))]
mod stub;

#[cfg(target_os = "windows")]
use windows_impl as imp;

#[cfg(not(target_os = "windows"))]
use stub as imp;

use std::fmt;

/// Result of a prerequisites check for the VBS Enclave user-bound
/// key path. Callers that opt into VBS via
/// `StorageConfig::prefer_vbs_when_available` should branch on this
/// to choose between VBS and the soft-Hello fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// All prerequisites are met. The VBS user-bound key backend
    /// can be initialized. (Once the enclave DLL implementation
    /// lands; currently the caller still falls back.)
    Available,
    /// At least one prerequisite is not met. The contained
    /// [`UnavailableReason`] identifies the blocking item so the
    /// caller can log it for diagnostic purposes.
    Unavailable(UnavailableReason),
}

/// Specific reason VBS Enclave user-bound keys are unavailable on
/// the current host. Stable enum used for logging and diagnostic
/// reporting; not part of any wire protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnavailableReason {
    /// Host OS is not Windows. The whole feature is Windows-only.
    NotWindows,
    /// Windows build is older than the VBS Enclave user-bound-key
    /// floor (24H2 build 26100.2314+). Contained string is the
    /// detected build number (e.g. `"26100.1742"`) for logging.
    BuildTooOld(String),
    /// Virtualization Based Security is not enabled / not running
    /// on this host. Requires VBS + HVCI configured in Windows
    /// Security → Device security.
    VbsNotRunning,
    /// Hypervisor-protected Code Integrity (HVCI) is not enforced.
    /// Required for the integrity guarantees the user-bound key
    /// depends on.
    HvciNotEnforced,
    /// Windows Hello is not enrolled (no PIN, no biometric) for
    /// the current user. The Hello-bound key cannot be created
    /// without an enrolled identity to bind to.
    HelloNotEnrolled,
    /// The enclave DLL is not present on disk. Will be normal
    /// during the plumbing-only phase before the enclave
    /// implementation lands. After that, this means the host
    /// binary was installed without its enclave sibling.
    EnclaveDllMissing,
    /// Something else blocked detection — typically an unexpected
    /// API failure. Contained string is a short human-readable
    /// description suitable for logging at `tracing::warn` level.
    Other(String),
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnavailableReason::NotWindows => write!(f, "not running on Windows"),
            UnavailableReason::BuildTooOld(build) => {
                write!(
                    f,
                    "Windows build {build} is below the VBS Enclave floor (26100.2314+)"
                )
            }
            UnavailableReason::VbsNotRunning => {
                write!(f, "VBS is not running (enable in Windows Security)")
            }
            UnavailableReason::HvciNotEnforced => {
                write!(f, "HVCI is not enforced (Memory Integrity must be on)")
            }
            UnavailableReason::HelloNotEnrolled => {
                write!(f, "Windows Hello is not enrolled for this user")
            }
            UnavailableReason::EnclaveDllMissing => {
                write!(f, "enclave DLL not found alongside the host binary")
            }
            UnavailableReason::Other(detail) => write!(f, "{detail}"),
        }
    }
}

/// Check whether VBS Enclave user-bound keys can be used on this
/// host. Does not fire any UI; safe to call at startup.
///
/// The check is conservative: anything we cannot positively verify
/// is treated as [`Availability::Unavailable`]. Callers should NOT
/// surface the diagnostic to the user as a failure — falling back
/// to the soft-Hello path is the documented expected behavior on
/// hosts that don't meet the prerequisites yet.
///
/// ## Auto-upgrade
///
/// Apps that opt into `prefer_vbs_when_available` should call
/// `probe()` at every storage-init, not just once. A host that
/// previously returned [`Availability::Unavailable`] (e.g. due to
/// [`UnavailableReason::BuildTooOld`]) may return
/// [`Availability::Available`] after a Windows Update, and the
/// migration code in `enclaveapp-app-storage::encryption` will
/// re-encrypt the bundle under the new VBS-bound key on the next
/// run. See `gocode-dev/docs/vbs-enclave-plan.md` "Migration story"
/// for the UX contract.
pub fn probe() -> Availability {
    imp::probe()
}
