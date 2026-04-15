use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationType {
    HelperTool,
    EnvInterpolation,
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
