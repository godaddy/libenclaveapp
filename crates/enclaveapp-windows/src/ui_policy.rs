// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows Hello user presence verification for TPM key operations.
//!
//! Uses `Windows.Security.Credentials.UI.UserConsentVerifier` to show the
//! standard Windows Security dialog (PIN / fingerprint / face), rather than
//! the CNG strong-key-protection password dialog which creates a separate
//! password instead of using the existing Windows Hello credential.

use crate::provider::NcryptHandle;
use enclaveapp_core::AccessPolicy;

/// Set a UI policy on a key handle.
///
/// For the `None` policy, this is a no-op — the key can be used without any
/// user interaction.
///
/// For any other policy, we do NOT set `NCRYPT_UI_PROTECT_KEY_FLAG` (which
/// would show a "create a password" dialog). Instead, user presence is
/// verified at sign/decrypt time via [`verify_user_presence`].
pub fn set_ui_policy(
    _key_handle: &NcryptHandle,
    _policy: AccessPolicy,
) -> enclaveapp_core::Result<()> {
    // User presence verification is handled at operation time by
    // verify_user_presence(), not by CNG key properties.
    // The key metadata records whether user presence is required.
    Ok(())
}

/// Verify user presence via Windows Hello.
///
/// Shows the standard "Windows Security" dialog asking the user to
/// verify their identity with PIN, fingerprint, or face recognition.
///
/// Returns `Ok(())` if the user verified successfully, or an error if
/// verification failed, was cancelled, or Windows Hello is not available.
pub fn verify_user_presence(message: &str) -> enclaveapp_core::Result<()> {
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

    let message = windows::core::HSTRING::from(message);

    let operation = UserConsentVerifier::RequestVerificationAsync(&message).map_err(|e| {
        enclaveapp_core::Error::KeyOperation {
            operation: "verify_user_presence".into(),
            detail: format!("failed to start verification: {e}"),
        }
    })?;

    let result = operation
        .get()
        .map_err(|e| enclaveapp_core::Error::KeyOperation {
            operation: "verify_user_presence".into(),
            detail: format!("verification failed: {e}"),
        })?;

    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_user_presence".into(),
            detail: "user cancelled verification".into(),
        }),
        other => Err(enclaveapp_core::Error::KeyOperation {
            operation: "verify_user_presence".into(),
            detail: format!("verification result: {:?}", other.0),
        }),
    }
}

/// Check if Windows Hello user presence verification is available.
pub fn is_user_presence_available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };

    let Ok(operation) = UserConsentVerifier::CheckAvailabilityAsync() else {
        return false;
    };
    let Ok(result) = operation.get() else {
        return false;
    };
    result == UserConsentVerifierAvailability::Available
}
