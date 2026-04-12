// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Hello UI policy setup for TPM key operations.

use crate::provider::NcryptHandle;
use enclaveapp_core::AccessPolicy;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

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

    if result.is_err() {
        // Non-fatal: Windows Hello may not be configured on this machine.
        eprintln!("warning: could not set UI policy (Windows Hello may not be available)");
    }
    Ok(())
}
