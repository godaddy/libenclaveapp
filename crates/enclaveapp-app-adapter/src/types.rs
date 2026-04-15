use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Classification of how an enclave app delivers secrets to the target application.
///
/// The adapter selects the least-secret-exposing integration automatically:
/// `HelperTool` > `EnvInterpolation` > `TempMaterializedConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationType {
    /// Type 1: The target app calls back to get credentials on demand.
    /// Secrets never leave the enclave app's process boundary.
    /// Examples: SSH agent protocol, AWS `credential_process`, git credential helpers.
    HelperTool,
    /// Type 2: Config file with `${ENV_VAR}` placeholders + secret env vars via `execve()`.
    /// Secrets exist briefly as environment variables but never touch disk.
    /// Examples: npm `.npmrc` with `${NPM_TOKEN}` interpolation.
    EnvInterpolation,
    /// Type 3: Secrets written to a temp file (0o600 permissions), path passed via flag/env var.
    /// Least secure — secrets briefly exist on disk. File deleted after process exits.
    /// Used when the target app has no plugin or env var interpolation support.
    TempMaterializedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BindingId(String);

impl BindingId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for BindingId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for BindingId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRecord {
    pub id: BindingId,
    pub label: String,
    pub target: String,
    pub secret_env_var: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    ExplicitPath,
    PathLookup,
    CommandV,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgram {
    pub path: PathBuf,
    pub fixed_args: Vec<String>,
    pub strategy: ResolutionStrategy,
    pub shell_hint: Option<String>,
}
