pub mod app_spec;
pub mod binding_store;
pub mod error;
pub mod execution_plan;
pub mod launcher;
pub mod prepare_launch;
pub mod resolver;
pub mod secret_store;
pub mod temp_config;
pub mod types;

pub use app_spec::{AppSpec, ConfigOverride};
pub use binding_store::{
    app_data_dir, app_data_dir_with_env, BindingStore, JsonFileBindingStore, MemoryBindingStore,
};
pub use error::{AdapterError, Result};
pub use execution_plan::choose_integration;
pub use launcher::{run, LaunchRequest};
pub use prepare_launch::{
    prepare_app_launch, prepare_best_app_launch, IntegrationCandidates, IntegrationPayload,
    PreparedAppLaunch,
};
pub use resolver::{resolve_program, ResolveMode, ResolveOptions};
pub use secret_store::{
    EncryptedFileSecretStore, MemorySecretStore, ReadOnlyEncryptedFileSecretStore, SecretStore,
    REDACTED_PLACEHOLDER,
};
pub use temp_config::TempConfig;
pub use types::{BindingId, BindingRecord, IntegrationType, ResolutionStrategy, ResolvedProgram};
