// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Linux TPM 2.0 backend via tss-esapi.
//!
//! Uses the kernel TPM resource manager (`/dev/tpmrm0`) or `tpm2-abrmd`.
//! Keys are stored as TPM-wrapped blobs -- the private portion is encrypted
//! by the TPM and useless without the same physical hardware.

#[cfg(target_os = "linux")]
mod tpm;

#[cfg(all(target_os = "linux", feature = "signing"))]
mod sign;

#[cfg(all(target_os = "linux", feature = "encryption"))]
mod encrypt;

#[cfg(all(target_os = "linux", feature = "signing"))]
pub use sign::LinuxTpmSigner;

#[cfg(all(target_os = "linux", feature = "encryption"))]
pub use encrypt::LinuxTpmEncryptor;

/// Check if a Linux TPM is available.
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        tpm::is_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
