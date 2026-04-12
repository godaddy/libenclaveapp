// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Key creation, opening, deletion, and enumeration shared between signing
//! and encryption modules.

// This module wraps NCrypt C APIs which require unsafe FFI calls.
// `mem_forget` is used intentionally in `delete_key` because NCryptDeleteKey
// takes ownership of the handle.
#![allow(unsafe_code, clippy::mem_forget, clippy::ptr_as_ptr, unused_qualifications)]

use crate::convert::key_name;
use crate::export::export_public_key;
use crate::provider::{open_provider, NcryptHandle};
use crate::ui_policy::set_ui_policy;
use enclaveapp_core::{AccessPolicy, Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// Create a new TPM-backed key with the given algorithm.
///
/// Returns the key handle and the 65-byte SEC1 uncompressed public key.
pub fn create_key(
    provider: &NcryptHandle,
    app_name: &str,
    label: &str,
    algorithm: &str,
    policy: AccessPolicy,
) -> Result<(NcryptHandle, Vec<u8>)> {
    let name = key_name(app_name, label);
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let algo_wide: Vec<u16> = algorithm.encode_utf16().chain(std::iter::once(0)).collect();

    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(algo_wide.as_ptr()),
            PCWSTR(name_wide.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| Error::GenerateFailed {
            detail: format!("NCryptCreatePersistedKey: {e}"),
        })?;
    }
    let key = NcryptHandle(NCRYPT_HANDLE(key_handle.0));

    // Set UI policy if the caller requested authentication.
    if policy != AccessPolicy::None {
        set_ui_policy(&key, policy)?;
    }

    // Persist the key to the TPM.
    unsafe {
        NCryptFinalizeKey(key.as_key(), NCRYPT_FLAGS::default()).map_err(|e| {
            Error::GenerateFailed {
                detail: format!("NCryptFinalizeKey: {e}"),
            }
        })?;
    }

    let pub_key = export_public_key(&key)?;
    Ok((key, pub_key))
}

/// Open an existing TPM-backed key by application name and label.
pub fn open_key(provider: &NcryptHandle, app_name: &str, label: &str) -> Result<NcryptHandle> {
    let name = key_name(app_name, label);
    let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.as_prov(),
            &mut key_handle,
            PCWSTR(name_wide.as_ptr()),
            CERT_KEY_SPEC::default(),
            NCRYPT_FLAGS::default(),
        )
        .map_err(|_| Error::KeyNotFound {
            label: label.to_string(),
        })?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(key_handle.0)))
}

/// Delete a key from the TPM by application name and label.
pub fn delete_key(app_name: &str, label: &str) -> Result<()> {
    let provider = open_provider()?;
    let key = open_key(&provider, app_name, label)?;

    // NCryptDeleteKey takes ownership of the handle and frees it on success,
    // so we must NOT let the NcryptHandle drop call NCryptFreeObject again.
    let raw_handle = key.as_key();
    std::mem::forget(key);

    unsafe {
        NCryptDeleteKey(raw_handle, 0).map_err(|e| Error::KeyOperation {
            operation: "delete_key".into(),
            detail: format!("NCryptDeleteKey: {e}"),
        })?;
    }
    Ok(())
}

/// Enumerate all keys that match the given application name prefix.
///
/// Returns the label portion (with the `{app_name}-` prefix stripped).
pub fn enumerate_keys(provider: &NcryptHandle, app_name: &str) -> Result<Vec<String>> {
    let prefix = format!("{app_name}-");
    let mut labels = Vec::new();
    let mut enum_state: *mut NCryptKeyName = std::ptr::null_mut();

    loop {
        let result = unsafe {
            NCryptEnumKeys(
                provider.as_prov(),
                PCWSTR::null(),
                &mut enum_state,
                std::ptr::null_mut(),
                NCRYPT_FLAGS::default(),
            )
        };

        if result.is_err() {
            // NTE_NO_MORE_ITEMS or any other error ends enumeration.
            break;
        }

        if !enum_state.is_null() {
            let key_info = unsafe { &*enum_state };
            let name = unsafe { key_info.pszName.to_string() };
            if let Ok(name_str) = name {
                if let Some(stripped) = name_str.strip_prefix(&prefix) {
                    labels.push(stripped.to_string());
                }
            }
            unsafe {
                let _ = NCryptFreeBuffer(enum_state as *mut _);
            }
        }
    }

    labels.sort();
    Ok(labels)
}
