use crate::error::Result;
use crate::types::ResolvedProgram;
use std::collections::BTreeMap;
use std::process::{Command, ExitStatus};

/// Request to launch a target process with environment overrides.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub program: ResolvedProgram,
    pub args: Vec<String>,
    pub env_overrides: BTreeMap<String, String>,
    pub env_removals: Vec<String>,
}

/// Execute a launch request, spawning the target process.
///
/// Secret env var values are locked in RAM (`mlock`) before spawn to prevent
/// them from being paged to swap. After the child exits, the values are
/// zeroized in-place and then unlocked.
///
/// Takes ownership of the `LaunchRequest` so that `env_overrides` values
/// (which may contain secrets) can be overwritten with zeros after the
/// child process exits. Callers that need the request afterwards should
/// clone it before calling `run`.
pub fn run(mut request: LaunchRequest) -> Result<ExitStatus> {
    // Lock secret env var values in RAM before spawn.
    for value in request.env_overrides.values() {
        enclaveapp_core::process::mlock_buffer(value.as_ptr(), value.len());
    }

    let mut command = Command::new(&request.program.path);
    command.args(&request.program.fixed_args);
    command.args(&request.args);

    for key in &request.env_removals {
        command.env_remove(key);
    }

    for (key, value) in &request.env_overrides {
        command.env(key, value);
    }

    let status = command.status()?;

    // Zeroize secret env var values, then unlock.
    for value in request.env_overrides.values_mut() {
        zeroize_str(value);
        enclaveapp_core::process::munlock_buffer(value.as_ptr(), value.len());
    }

    Ok(status)
}

/// Overwrite the contents of a string with zeros without deallocating.
fn zeroize_str(s: &mut str) {
    // Safety: filling the existing UTF-8 bytes with 0 is valid UTF-8 (all NUL).
    // We stay within the existing len — no UB.
    #[allow(unsafe_code)]
    unsafe {
        let bytes = s.as_bytes_mut();
        bytes.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_str_clears_contents() {
        let mut s = String::from("secret-value");
        zeroize_str(&mut s);
        assert!(s.bytes().all(|b| b == 0));
        assert_eq!(s.len(), 12);
    }
}
