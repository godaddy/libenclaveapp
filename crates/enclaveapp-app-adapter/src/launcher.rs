use std::collections::BTreeMap;
use std::process::{Command, ExitStatus};

use crate::error::Result;
use crate::types::ResolvedProgram;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub program: ResolvedProgram,
    pub args: Vec<String>,
    pub env_overrides: BTreeMap<String, String>,
    pub env_removals: Vec<String>,
}

pub fn run(request: &LaunchRequest) -> Result<ExitStatus> {
    let mut command = Command::new(&request.program.path);
    command.args(&request.program.fixed_args);
    command.args(&request.args);

    for key in &request.env_removals {
        command.env_remove(key);
    }

    for (key, value) in &request.env_overrides {
        command.env(key, value);
    }

    Ok(command.status()?)
}
