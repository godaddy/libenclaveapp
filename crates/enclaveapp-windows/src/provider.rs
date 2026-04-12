// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! NCrypt provider management and RAII handle wrapper.

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

/// The CNG provider name for TPM-backed keys.
pub const PLATFORM_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// RAII wrapper for NCrypt handles. Calls `NCryptFreeObject` on drop.
pub struct NcryptHandle(pub NCRYPT_HANDLE);

// NCrypt handles are thread-safe opaque pointers.
unsafe impl Send for NcryptHandle {}
unsafe impl Sync for NcryptHandle {}

impl NcryptHandle {
    /// Re-interpret as a provider handle.
    pub fn as_prov(&self) -> NCRYPT_PROV_HANDLE {
        NCRYPT_PROV_HANDLE(self.0 .0)
    }

    /// Re-interpret as a key handle.
    pub fn as_key(&self) -> NCRYPT_KEY_HANDLE {
        NCRYPT_KEY_HANDLE(self.0 .0)
    }
}

impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// Open the TPM platform crypto provider.
pub fn open_provider() -> enclaveapp_core::Result<NcryptHandle> {
    let provider_name: Vec<u16> = PLATFORM_PROVIDER
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut handle = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(&mut handle, PCWSTR(provider_name.as_ptr()), 0).map_err(|e| {
            enclaveapp_core::Error::KeyOperation {
                operation: "open_provider".into(),
                detail: e.to_string(),
            }
        })?;
    }
    Ok(NcryptHandle(NCRYPT_HANDLE(handle.0)))
}

/// Check if the TPM platform crypto provider is available.
pub fn is_available() -> bool {
    open_provider().is_ok()
}
