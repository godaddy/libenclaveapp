// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Re-exports signing detection from enclaveapp-core for macOS keychain use.
//!
//! The canonical implementation lives in `crate::internal::core::signing` so it's
//! available on all platforms. This module re-exports it for use by the
//! macOS-specific keychain code within this crate.
#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]

pub use crate::internal::core::signing::{ensure_safe_app_name, is_binary_signed};
