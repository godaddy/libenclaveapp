use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unable to determine configuration directory")]
    MissingConfigDir,

    #[error("unable to determine home directory")]
    MissingHomeDir,

    #[error("program not found: {0}")]
    ProgramNotFound(String),

    #[error("shell resolution for `{command}` returned an unsupported result: {raw}")]
    UnsupportedShellResolution { command: String, raw: String },

    #[error("command -v failed for `{command}`: {stderr}")]
    CommandVFailed { command: String, stderr: String },

    #[error("no supported integration type was provided")]
    NoSupportedIntegration,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("missing secret for binding `{0}`")]
    MissingSecret(String),

    #[error("configuration override is required for this integration mode")]
    MissingConfigOverride,

    #[error("application `{app}` does not support integration type `{integration}`")]
    UnsupportedIntegration { app: String, integration: String },

    #[error("no available prepared integration candidate matched the application support matrix")]
    NoAvailableIntegrationCandidate,
}

impl From<enclaveapp_app_storage::StorageError> for AdapterError {
    fn from(value: enclaveapp_app_storage::StorageError) -> Self {
        Self::Storage(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AdapterError>;
