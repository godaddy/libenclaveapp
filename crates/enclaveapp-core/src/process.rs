//! Process-level security hardening.
//!
//! Call `harden_process()` early in `main()` to apply platform-appropriate
//! protections: disable core dumps, block ptrace-based memory reads on
//! Linux, prevent privilege gain from setuid/fcaps (Linux), and lock
//! secret memory pages.

/// Apply process-level security hardening.
///
/// - Disables core dumps (prevents secrets from appearing in crash dumps).
/// - On Linux, sets `PR_SET_DUMPABLE=0` so `/proc/<pid>/mem` is only
///   readable by root, not the same user, and ptrace attach is denied
///   to non-root peers.
/// - On Linux, sets `PR_SET_NO_NEW_PRIVS=1` so any `exec*()` after this
///   point cannot gain privileges via setuid / file capabilities.
/// - On Windows, enables a safe subset of process mitigation policies:
///   strict handle checks, extension-point DLL disable, and image-load
///   restrictions (no remote or low-mandatory-label images). See
///   [`apply_windows_mitigations`] for the per-policy rationale.
///
/// Should be called early in main() before any secrets are loaded.
/// Errors are logged but not fatal — hardening is best-effort.
pub fn harden_process() {
    disable_core_dumps();
    #[cfg(target_os = "linux")]
    {
        set_dumpable_zero();
        set_no_new_privs();
    }
    #[cfg(target_os = "windows")]
    {
        apply_windows_mitigations();
    }
}

/// Disable core dumps to prevent secrets from appearing in crash dumps.
#[cfg(unix)]
fn disable_core_dumps() {
    #[allow(unsafe_code)]
    {
        let rlimit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlimit) };
        if result != 0 {
            // Best-effort: log but don't fail.
            tracing::warn!(
                "failed to disable core dumps: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {
    // Windows: core dumps (minidumps) are controlled by the system, not per-process.
    // WER (Windows Error Reporting) settings control this globally.
}

/// Linux: set `PR_SET_DUMPABLE = 0`.
///
/// Prevents ptrace attach from non-root peers and makes `/proc/<pid>/mem`
/// readable only by root. This closes the main in-memory attack vector
/// against a running enclave-app process from a same-UID attacker.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_dumpable_zero() {
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0, 0, 0) };
    if result != 0 {
        tracing::warn!(
            "failed to set PR_SET_DUMPABLE=0: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Linux: set `PR_SET_NO_NEW_PRIVS = 1`.
///
/// Once set, subsequent `exec*()` calls cannot grant the child new
/// privileges via setuid bits or file capabilities. The enclave apps
/// do not rely on setuid execution, so the restriction is safe and
/// shrinks the post-exec privilege-escalation surface for any child
/// processes the app spawns (e.g. wrapped `npm`, `git`, `awscli`).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_no_new_privs() {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0, 0, 0) };
    if result != 0 {
        tracing::warn!(
            "failed to set PR_SET_NO_NEW_PRIVS=1: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Apply the safe subset of Windows process mitigation policies at
/// startup.
///
/// Each call is best-effort — the policies are non-fatal on failure
/// (unsupported Windows build, already-set, etc.) and simply trace a
/// warning. The policies applied:
///
/// - `PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
///   .RaiseExceptionOnInvalidHandleReference`: any syscall that
///   receives an invalid handle raises `STATUS_INVALID_HANDLE`
///   immediately. Catches handle-confusion bugs that would otherwise
///   silently operate on the wrong object. Safe for standard apps.
/// - `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
///   .DisableExtensionPoints`: blocks legacy DLL-injection extension
///   points (AppInit_DLLs, AppCertDlls, shim engine, IMEs, winevent
///   hooks) from loading into this process. Kills the most common
///   unsigned-DLL-injection vector.
/// - `PROCESS_MITIGATION_IMAGE_LOAD_POLICY
///   .NoRemoteImages` + `.NoLowMandatoryLabelImages`: refuses to
///   load DLLs from UNC paths and from files with the low-mandatory
///   integrity label. Blocks the "drop a DLL onto a writable share
///   and hijack our load search" pattern.
///
/// Deliberately **not** applied:
/// - `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY.MicrosoftSignedOnly` —
///   breaks cargo-built unsigned apps.
/// - `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` (ACG) — breaks JIT
///   frameworks and some crypto providers.
/// - `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY.DisallowWin32kSystemCalls` —
///   UI-less-only, risky for apps that surface any GUI.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn apply_windows_mitigations() {
    use windows::Win32::System::Threading::{
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy,
        SetProcessMitigationPolicy, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
    };

    // Strict handle check — raise on any invalid-handle reference.
    let mut strict = PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY::default();
    unsafe {
        strict
            .Anonymous
            .Anonymous
            .set_RaiseExceptionOnInvalidHandleReference(1);
        strict
            .Anonymous
            .Anonymous
            .set_HandleExceptionsPermanentlyEnabled(1);
        if let Err(e) = SetProcessMitigationPolicy(
            ProcessStrictHandleCheckPolicy,
            std::ptr::from_ref(&strict).cast(),
            std::mem::size_of::<PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY>(),
        ) {
            tracing::warn!("SetProcessMitigationPolicy(StrictHandleCheck) failed: {e}");
        }
    }

    // Extension-point disable — block AppInit DLLs, shim engines, etc.
    let mut extpt = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    unsafe {
        extpt.Anonymous.Anonymous.set_DisableExtensionPoints(1);
        if let Err(e) = SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            std::ptr::from_ref(&extpt).cast(),
            std::mem::size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
        ) {
            tracing::warn!("SetProcessMitigationPolicy(ExtensionPointDisable) failed: {e}");
        }
    }

    // Image-load — block remote and low-mandatory-label images. Do
    // NOT set `PreferSystem32Images` here; cargo-built apps ship
    // their own DLLs alongside the exe and need local-dir loading.
    let mut imgload = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    unsafe {
        imgload.Anonymous.Anonymous.set_NoRemoteImages(1);
        imgload.Anonymous.Anonymous.set_NoLowMandatoryLabelImages(1);
        if let Err(e) = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            std::ptr::from_ref(&imgload).cast(),
            std::mem::size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        ) {
            tracing::warn!("SetProcessMitigationPolicy(ImageLoad) failed: {e}");
        }
    }
}

/// Lock a memory region to prevent it from being paged to swap.
///
/// Call this on buffers containing secrets. The memory will remain in RAM
/// until explicitly unlocked or the process exits.
///
/// Returns true if locking succeeded, false otherwise (e.g., resource limits).
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn mlock_buffer(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) == 0 }
}

/// Unlock a previously locked memory region, allowing it to be paged to swap.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn munlock_buffer(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    unsafe { libc::munlock(ptr.cast::<libc::c_void>(), len) == 0 }
}

/// Lock a memory region to prevent it from being paged to swap (no-op on non-Unix).
#[cfg(not(unix))]
pub fn mlock_buffer(_ptr: *const u8, len: usize) -> bool {
    // Zero-length is trivially successful.
    // On Windows, VirtualLock could be used but requires windows crate dependency
    // which enclaveapp-core doesn't have. Best-effort: return false for non-empty.
    len == 0
}

/// Unlock a previously locked memory region (no-op on non-Unix).
#[cfg(not(unix))]
pub fn munlock_buffer(_ptr: *const u8, len: usize) -> bool {
    len == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_does_not_panic() {
        harden_process();
    }

    #[cfg(unix)]
    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps();
        let mut rlimit = libc::rlimit {
            rlim_cur: 999,
            rlim_max: 999,
        };
        #[allow(unsafe_code)]
        unsafe {
            libc::getrlimit(libc::RLIMIT_CORE, &mut rlimit);
        }
        assert_eq!(rlimit.rlim_cur, 0);
    }

    #[test]
    fn mlock_empty_buffer() {
        assert!(mlock_buffer(std::ptr::null(), 0));
    }

    #[test]
    fn munlock_empty_buffer() {
        assert!(munlock_buffer(std::ptr::null(), 0));
    }
}
