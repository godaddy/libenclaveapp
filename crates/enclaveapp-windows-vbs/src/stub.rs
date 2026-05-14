// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Non-Windows stub. Every public entry point returns "not
//! available, this isn't Windows". Lets the workspace build on
//! Linux and macOS without conditionally pulling the crate out of
//! the dependency graph.

use crate::{Availability, UnavailableReason};

pub fn probe() -> Availability {
    Availability::Unavailable(UnavailableReason::NotWindows)
}
