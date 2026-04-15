//! Generic secret delivery substrate for enclave applications.
//!
//! This crate provides the infrastructure for building "enclave apps" — thin
//! wrappers that deliver hardware-backed secrets to target applications.
//!
//! # Integration Types
//!
//! Every enclave app uses one of three integration strategies, classified by
//! how secrets are delivered to the target application:
//!
//! - [`IntegrationType::HelperTool`] — Target app calls back for credentials on demand
//! - [`IntegrationType::EnvInterpolation`] — Config with `${ENV_VAR}` placeholders + secret env vars
//! - [`IntegrationType::TempMaterializedConfig`] — Secrets written to temp file, path passed as flag
//!
//! The adapter automatically selects the least-secret-exposing type.
//!
//! # Key Types
//!
//! - [`AppSpec`] — Declares an app's name, executable, supported integrations
//! - [`BindingStore`] / [`SecretStore`] — Persistent credential management
//! - [`resolve_program`] — Find executables with alias/wrapper resolution
//! - [`prepare_best_app_launch`] — Select integration and prepare process launch
//! - [`run`] — Execute the prepared launch

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
