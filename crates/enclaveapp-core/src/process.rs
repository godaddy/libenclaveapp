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
