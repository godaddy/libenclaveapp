// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Core trait hierarchy for hardware-backed key management backends.

use crate::{AccessPolicy, KeyType, Result};

/// Core key management operations. Every platform backend implements this.
pub trait EnclaveKeyManager: Send + Sync {
    /// Generate a new hardware-bound key.
    /// Returns the 65-byte uncompressed SEC1 public key (0x04 || X || Y).
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>>;

    /// Get the public key for an existing key.
    /// Returns the 65-byte uncompressed SEC1 public key.
    fn public_key(&self, label: &str) -> Result<Vec<u8>>;

    /// List all key labels managed by this application.
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Delete a key and all associated metadata/files.
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Check if the hardware security backend is available on this system.
    fn is_available(&self) -> bool;
}

/// ECDSA signing operations. Used by sshenc for SSH key signing.
pub trait EnclaveSigner: EnclaveKeyManager {
    /// Sign a message using the hardware-bound private key.
    ///
    /// On macOS (CryptoKit), the message is hashed internally with SHA-256.
    /// On Windows (CNG), the implementation pre-hashes with SHA-256 then calls NCryptSignHash.
    ///
    /// Returns a DER-encoded ECDSA signature.
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;
}

/// ECIES encryption operations. Used by awsenc and sso-jwt for credential caching.
pub trait EnclaveEncryptor: EnclaveKeyManager {
    /// Encrypt plaintext using the key's public key via ECIES.
    ///
    /// The implementation generates an ephemeral ECDH key pair, derives a
    /// shared secret with the stored key's public key, and encrypts with AES-GCM.
    ///
    /// Returns the ciphertext in the format:
    /// `[1-byte version 0x01] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]`
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the hardware-bound private key.
    ///
    /// The implementation performs ECDH with the ephemeral public key from the
    /// ciphertext, derives the shared secret, and decrypts with AES-GCM.
    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
