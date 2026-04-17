// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Hello UI policy setup for TPM key operations.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
#![allow(unsafe_code, trivial_casts, clippy::ptr_as_ptr, unused_qualifications)]

use crate::provider::NcryptHandle;
use enclaveapp_core::AccessPolicy;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

/// Set a Windows Hello UI policy on a key handle.
///
/// When the policy is anything other than `None`, the key is marked with
/// `NCRYPT_UI_PROTECT_KEY_FLAG` which causes Windows Hello to prompt the
/// user for authentication before the key can be used.
pub fn set_ui_policy(
    key_handle: &NcryptHandle,
    policy: AccessPolicy,
) -> enclaveapp_core::Result<()> {
    if policy == AccessPolicy::None {
        return Ok(());
    }

    let ui_policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: PCWSTR::null(),
        pszFriendlyName: PCWSTR::null(),
        pszDescription: PCWSTR::null(),
    };

    let prop_name: Vec<u16> = "UI Policy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key_handle.as_key().0),
            PCWSTR(prop_name.as_ptr()),
            std::slice::from_raw_parts(
                &ui_policy as *const _ as *const u8,
                std::mem::size_of::<NCRYPT_UI_POLICY>(),
            ),
            NCRYPT_FLAGS::default(),
        )
    };

    result.map_err(|e| enclaveapp_core::Error::KeyOperation {
        operation: "set_ui_policy".into(),
        detail: format!("NCryptSetProperty(UI Policy): {e}"),
    })
}

/// Read back the `NCRYPT_UI_POLICY` actually set on a CNG key and
/// assert that it matches the requested `AccessPolicy`.
///
/// Defends against a same-user attacker who pre-plants a TPM key with
/// the expected CNG name but without `NCRYPT_UI_PROTECT_KEY_FLAG`. If
/// the app were to open and sign with such a key, the Windows Hello
/// prompt would not fire and the intended presence check would be
/// bypassed. Re-verifying the flag before signing closes that gap.
///
/// Returns `Ok(())` if the key carries the correct `NCRYPT_UI_PROTECT_KEY_FLAG`
/// for the requested policy (or no flag when `expected == None`). Returns
/// an `Error::KeyOperation` if the policy does not match or the query
/// itself fails.
pub fn verify_ui_policy_matches(
    key_handle: &NcryptHandle,
    expected: AccessPolicy,
) -> enclaveapp_core::Result<()> {
    let prop_name: Vec<u16> = "UI Policy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut actual = NCRYPT_UI_POLICY {
        dwVersion: 0,
        dwFlags: 0,
        pszCreationTitle: PCWSTR::null(),
        pszFriendlyName: PCWSTR::null(),
        pszDescription: PCWSTR::null(),
    };
    let mut actual_size: u32 = 0;
    let buf = unsafe {
        std::slice::from_raw_parts_mut(
            &mut actual as *mut _ as *mut u8,
            std::mem::size_of::<NCRYPT_UI_POLICY>(),
        )
    };

    let result = unsafe {
        NCryptGetProperty(
            NCRYPT_HANDLE(key_handle.as_key().0),
            PCWSTR(prop_name.as_ptr()),
            Some(buf),
            &mut actual_size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    };

    let actual_flags: u32 = match result {
        Ok(()) => actual.dwFlags,
        Err(e) => {
            // SPC_E_NO_POLICY / NTE_NOT_FOUND both surface as a missing
            // policy — translate to "no flag set" so the comparison
            // below treats it as AccessPolicy::None.
            if expected == AccessPolicy::None {
                return Ok(());
            }
            return Err(enclaveapp_core::Error::KeyOperation {
                operation: "verify_ui_policy".into(),
                detail: format!(
                    "NCryptGetProperty(UI Policy) for key with expected policy {expected:?}: {e}",
                ),
            });
        }
    };

    let has_protect_flag =
        (actual_flags & NCRYPT_UI_PROTECT_KEY_FLAG) == NCRYPT_UI_PROTECT_KEY_FLAG;

    match (expected, has_protect_flag) {
        (AccessPolicy::None, false) => Ok(()),
        (AccessPolicy::None, true) => Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_ui_policy".into(),
            detail:
                "key has NCRYPT_UI_PROTECT_KEY_FLAG set but metadata expects AccessPolicy::None"
                    .into(),
        }),
        (_, true) => Ok(()),
        (_, false) => Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_ui_policy".into(),
            detail: format!(
                "key is missing NCRYPT_UI_PROTECT_KEY_FLAG but metadata expects {expected:?}"
            ),
        }),
    }
}
