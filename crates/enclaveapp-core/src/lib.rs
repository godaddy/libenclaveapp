// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Platform-agnostic types, traits, and utilities for hardware-backed key management.
//!
//! This crate provides the core abstractions shared across macOS Secure Enclave,
//! Windows TPM 2.0, and WSL bridge implementations.

pub mod config;
pub mod error;
pub mod metadata;
pub mod platform;
pub mod traits;
pub mod types;

pub use error::{Error, Result};
pub use metadata::KeyMeta;
pub use traits::{EnclaveEncryptor, EnclaveKeyManager, EnclaveSigner};
pub use types::{AccessPolicy, KeyType};
