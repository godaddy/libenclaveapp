// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL detection and shell configuration for libenclaveapp.
//!
//! Provides generic WSL integration that any enclave app can use:
//! - WSL environment detection and distro enumeration
//! - Managed block injection/removal in shell config files
//! - Shell syntax validation

mod detect;
mod shell_config;

pub use detect::*;
pub use shell_config::*;
