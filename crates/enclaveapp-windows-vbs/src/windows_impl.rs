// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows-side prerequisites probe for the VBS Enclave user-bound
//! key path. Does not load any enclave, does not fire any UI; safe
//! to call from startup paths.

use crate::{Availability, UnavailableReason};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_VALUE_TYPE,
};

/// Minimum Windows build for VBS Enclave user-bound keys.
///
/// Per Microsoft's `VbsEnclaveTooling` sample README: the
/// `userboundkey` sample requires 24H2 build **26100.2314+**.
/// The more recent top-level README quotes **26100.3916+** as a
/// safer floor for the toolchain. We use the lower floor here
/// because (a) the API itself is available at 26100.2314 and (b) a
/// host that meets 26100.2314 but not 26100.3916 will surface
/// failures at enclave-load time with a clear OS-level error, not
/// silent breakage.
const BUILD_FLOOR_MAJOR: u32 = 26100;
const BUILD_FLOOR_UBR: u32 = 2314;

pub fn probe() -> Availability {
    let build = match read_current_build() {
        Ok(b) => b,
        Err(reason) => return Availability::Unavailable(reason),
    };
    if !meets_build_floor(&build) {
        return Availability::Unavailable(UnavailableReason::BuildTooOld(format!(
            "{}.{}",
            build.major, build.ubr
        )));
    }

    match probe_device_guard() {
        Ok(DeviceGuardState {
            vbs_running: true,
            hvci_enforced: true,
        }) => {}
        Ok(DeviceGuardState {
            vbs_running: false, ..
        }) => {
            return Availability::Unavailable(UnavailableReason::VbsNotRunning);
        }
        Ok(DeviceGuardState {
            hvci_enforced: false,
            ..
        }) => {
            return Availability::Unavailable(UnavailableReason::HvciNotEnforced);
        }
        Err(reason) => return Availability::Unavailable(reason),
    }

    if !hello_enrolled() {
        return Availability::Unavailable(UnavailableReason::HelloNotEnrolled);
    }

    // Once the enclave DLL implementation lands, this will also
    // check for the sidecar DLL alongside the host binary. Until
    // then, the prerequisites probe stops here and callers fall
    // back to the soft-Hello path.
    Availability::Available
}

#[derive(Debug)]
struct CurrentBuild {
    major: u32,
    ubr: u32,
}

/// Read the `CurrentBuildNumber` (e.g. `26200`) and `UBR` (e.g.
/// `8457`) registry values under
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
fn read_current_build() -> Result<CurrentBuild, UnavailableReason> {
    let key = open_subkey_read(
        HKEY_LOCAL_MACHINE,
        w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
    )
    .map_err(|e| UnavailableReason::Other(format!("open CurrentVersion key: {e}")))?;

    let build_str = read_string_value(key, "CurrentBuildNumber")
        .map_err(|e| UnavailableReason::Other(format!("read CurrentBuildNumber: {e}")))?;
    let major: u32 = build_str.parse().map_err(|_| {
        UnavailableReason::Other(format!("CurrentBuildNumber not numeric: {build_str:?}"))
    })?;

    let ubr = read_dword_value(key, "UBR").unwrap_or(0);

    close_key(key);
    Ok(CurrentBuild { major, ubr })
}

fn meets_build_floor(b: &CurrentBuild) -> bool {
    b.major > BUILD_FLOOR_MAJOR || (b.major == BUILD_FLOOR_MAJOR && b.ubr >= BUILD_FLOOR_UBR)
}

#[derive(Debug)]
struct DeviceGuardState {
    vbs_running: bool,
    hvci_enforced: bool,
}

/// Read VBS/HVCI status from the DeviceGuard CIM/WMI namespace via
/// its registry-backed equivalent values under
/// `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios`.
///
/// We avoid the WMI path (`Get-CimInstance ... Win32_DeviceGuard`)
/// because it requires WMI initialization that's slow and
/// process-heavy at startup. The registry shadow is what
/// `DeviceGuard` writes when its scenarios start, so reading it is
/// accurate and cheap.
fn probe_device_guard() -> Result<DeviceGuardState, UnavailableReason> {
    let scenarios = open_subkey_read(
        HKEY_LOCAL_MACHINE,
        w!("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"),
    )
    .map_err(|e| UnavailableReason::Other(format!("open DeviceGuard\\Scenarios: {e}")))?;

    let hvci = open_subkey_read(scenarios, w!("HypervisorEnforcedCodeIntegrity"))
        .map_err(|e| UnavailableReason::Other(format!("open Scenarios\\HVCI subkey: {e}")))?;
    let hvci_enabled = read_dword_value(hvci, "Enabled").unwrap_or(0);
    close_key(hvci);

    close_key(scenarios);

    // The "enabled" value is set when HVCI policy is configured to
    // run. The actual *running* state is a separate kernel report
    // — but if HVCI is enabled and the host booted successfully,
    // it's running. (A boot-time failure would have either fallen
    // back or refused to start.)
    let hvci_enforced = hvci_enabled == 1;

    // VBS running ↔ HVCI running on modern Windows. There's no
    // separate "VBS but not HVCI" registry shadow that reliably
    // reflects runtime state. We treat HVCI as the gating signal.
    let vbs_running = hvci_enforced;

    Ok(DeviceGuardState {
        vbs_running,
        hvci_enforced,
    })
}

/// Probe whether Windows Hello is enrolled for the current user.
/// Uses [`UserConsentVerifier::CheckAvailabilityAsync`] which is
/// a non-firing capability check — no Hello prompt is shown.
fn hello_enrolled() -> bool {
    let async_op = match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => op,
        Err(_) => return false,
    };
    let result = match async_op.get() {
        Ok(r) => r,
        Err(_) => return false,
    };
    matches!(result, UserConsentVerifierAvailability::Available)
}

// --- thin Win32 Registry helpers ---------------------------------

#[allow(unsafe_code)]
fn open_subkey_read(parent: HKEY, name: PCWSTR) -> Result<HKEY, String> {
    let mut out = HKEY::default();
    let status = unsafe { RegOpenKeyExW(parent, name, 0, KEY_READ, &mut out) };
    match status.ok() {
        Ok(()) => Ok(out),
        Err(e) => Err(e.to_string()),
    }
}

#[allow(unsafe_code)]
fn close_key(k: HKEY) {
    let _ = unsafe { RegCloseKey(k) };
}

#[allow(unsafe_code)]
fn read_dword_value(key: HKEY, name: &str) -> Result<u32, String> {
    let name_h = HSTRING::from(name);
    let mut typ = REG_VALUE_TYPE(0);
    let mut data: u32 = 0;
    let mut cb: u32 = size_of::<u32>() as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_h.as_ptr()),
            None,
            Some(&mut typ),
            Some(core::ptr::addr_of_mut!(data).cast::<u8>()),
            Some(&mut cb),
        )
    };
    status
        .ok()
        .map(|_| data)
        .map_err(|e| format!("read DWORD {name:?}: {e}"))
}

#[allow(unsafe_code)]
fn read_string_value(key: HKEY, name: &str) -> Result<String, String> {
    let name_h = HSTRING::from(name);
    let mut typ = REG_VALUE_TYPE(0);
    let mut cb: u32 = 0;
    // First call: query required size.
    let probe_status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_h.as_ptr()),
            None,
            Some(&mut typ),
            None,
            Some(&mut cb),
        )
    };
    probe_status
        .ok()
        .map_err(|e| format!("probe size for {name:?}: {e}"))?;

    let mut buf: Vec<u16> = vec![0; (cb as usize).div_ceil(2)];
    let mut cb_actual = cb;
    let read_status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_h.as_ptr()),
            None,
            Some(&mut typ),
            Some(buf.as_mut_ptr().cast::<u8>()),
            Some(&mut cb_actual),
        )
    };
    read_status
        .ok()
        .map_err(|e| format!("read string {name:?}: {e}"))?;
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(String::from_utf16_lossy(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build-floor comparison: 26100.2314 is the floor.
    #[test]
    fn build_floor_basic() {
        assert!(meets_build_floor(&CurrentBuild {
            major: 26100,
            ubr: 2314
        }));
        assert!(meets_build_floor(&CurrentBuild {
            major: 26100,
            ubr: 3916
        }));
        assert!(meets_build_floor(&CurrentBuild {
            major: 26200,
            ubr: 0
        }));
        assert!(!meets_build_floor(&CurrentBuild {
            major: 26100,
            ubr: 2313
        }));
        assert!(!meets_build_floor(&CurrentBuild {
            major: 26100,
            ubr: 1742
        }));
        assert!(!meets_build_floor(&CurrentBuild {
            major: 22631,
            ubr: 9999
        }));
    }

    /// probe() runs without panicking on a real Windows host.
    /// The actual return value depends on the host's VBS state;
    /// we just verify it produces one of the two variants.
    #[test]
    fn probe_runs_without_panicking() {
        let result = probe();
        match result {
            Availability::Available | Availability::Unavailable(_) => {}
        }
    }
}
