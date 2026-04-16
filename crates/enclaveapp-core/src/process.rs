//! Process-level security hardening.
//!
//! Call `harden_process()` early in `main()` to apply platform-appropriate
//! protections: disable core dumps and lock secret memory pages.

/// Apply process-level security hardening.
///
/// - Disables core dumps (prevents secrets from appearing in crash dumps)
/// - Should be called early in main() before any secrets are loaded
///
/// Errors are logged but not fatal — hardening is best-effort.
pub fn harden_process() {
    disable_core_dumps();
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
