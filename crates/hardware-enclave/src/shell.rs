// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Shell config block injection and path/value quoting.
//!
//! [`BlockMarkers`] + the `install_block_in_file` / `remove_block_from_file`
//! functions handle adding and removing managed blocks from `.bashrc`,
//! `.zshrc`, SSH config, and similar files.
//!
//! The quoting functions produce correctly-escaped strings for embedding
//! paths and values into config files.

// Config block management
pub use crate::internal::core::config_block::{
    build_block, find_block, has_block, install_block_in_file, read_config_file, remove_block,
    remove_block_from_file, upsert_block, write_config_file, BlockInstallResult, BlockMarkers,
    BlockRemoveResult,
};

// Path and value quoting for config files
pub use crate::internal::core::quoting::quote_config_value;

/// Quote a filesystem path for embedding in an **SSH-style config file**.
///
/// On Windows, backslashes are converted to forward slashes — this is required
/// by OpenSSH's config parser and by Git credential helper entries, which also
/// use the same forward-slash convention.
///
/// Paths containing spaces are wrapped in double quotes.
///
/// # ⚠ Not suitable for all config formats
///
/// This function normalises Windows backslashes to forward slashes. Do **not**
/// use it for formats that require backslash-escaped paths (e.g. the AWS
/// `credential_process` INI directive). Use [`quote_credential_process_arg`]
/// for those.
///
/// # Usage
///
/// ```
/// use hardware_enclave::shell::quote_path_for_ssh_config;
/// use std::path::Path;
///
/// let line = format!("IdentityFile {}", quote_path_for_ssh_config(Path::new("/home/user/.ssh/id")));
/// ```
pub fn quote_path_for_ssh_config(path: &std::path::Path) -> String {
    crate::internal::core::quoting::quote_ssh_path(path)
}

/// Quote a path for the `credential_process` directive in AWS config.
///
/// Uses INI-style escaping (`\"` and `\\`) rather than forward-slash
/// normalisation. Use this for AWS `~/.aws/credentials` or `~/.aws/config`
/// entries. For SSH config paths use [`quote_path_for_ssh_config`] instead.
pub use crate::internal::core::quoting::quote_credential_process_arg;
