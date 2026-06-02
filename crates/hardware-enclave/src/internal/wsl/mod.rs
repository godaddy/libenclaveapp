// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! enclave.
//!
//! Provides generic WSL integration that any enclave app can use:
//! - WSL environment detection and distro enumeration
//! - Managed block injection/removal in shell config files
//! - Shell syntax validation
//! - Higher-level install/uninstall orchestration across distros
//! - Shell integration script generation (export detection, helper functions)
#![allow(dead_code, unused_imports, unused_qualifications, unreachable_patterns)]

mod detect;
pub mod install;
mod shell_config;
pub mod shell_init;

pub use detect::*;
pub use shell_config::*;
