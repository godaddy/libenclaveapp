// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! FFI declarations for the CryptoKit Swift bridge.
//!
//! All functions are declared regardless of feature flags since the Swift
//! bridge compiles all functions unconditionally.

#[allow(dead_code)]
extern "C" {
    pub fn enclaveapp_se_available() -> i32;

    // Signing key operations
    pub fn enclaveapp_se_generate_signing_key(
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
        data_rep_out: *mut u8,
        data_rep_len: *mut i32,
        auth_policy: i32,
    ) -> i32;

    pub fn enclaveapp_se_signing_public_key(
        data_rep: *const u8,
        data_rep_len: i32,
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_sign(
        data_rep: *const u8,
        data_rep_len: i32,
        message: *const u8,
        message_len: i32,
        sig_out: *mut u8,
        sig_len: *mut i32,
    ) -> i32;

    // Encryption key operations
    pub fn enclaveapp_se_generate_encryption_key(
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
        data_rep_out: *mut u8,
        data_rep_len: *mut i32,
        auth_policy: i32,
    ) -> i32;

    pub fn enclaveapp_se_encryption_public_key(
        data_rep: *const u8,
        data_rep_len: i32,
        pub_key_out: *mut u8,
        pub_key_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_encrypt(
        data_rep: *const u8,
        data_rep_len: i32,
        plaintext: *const u8,
        plaintext_len: i32,
        ciphertext_out: *mut u8,
        ciphertext_len: *mut i32,
    ) -> i32;

    pub fn enclaveapp_se_decrypt(
        data_rep: *const u8,
        data_rep_len: i32,
        ciphertext: *const u8,
        ciphertext_len: i32,
        plaintext_out: *mut u8,
        plaintext_len: *mut i32,
    ) -> i32;
}
