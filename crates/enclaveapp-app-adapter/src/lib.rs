//! Generic secret delivery substrate for enclave applications.
//!
//! This crate provides the infrastructure for building "enclave apps" — thin
//! wrappers that deliver hardware-backed secrets to target applications.
//!
//! # Integration Types
//!
//! Every enclave app uses one of four integration strategies:
//!
//! - **Type 1** [`IntegrationType::HelperTool`] — Target app calls back for credentials on demand
//! - **Type 2** [`IntegrationType::EnvInterpolation`] — Config with `${ENV_VAR}` placeholders + secret env vars
//! - **Type 3** [`IntegrationType::TempMaterializedConfig`] — Secrets written to temp file, path passed as flag
//! - **Type 4** (CredentialSource) — Obtains, caches, and serves credentials to other enclave apps
//!
//! For Types 1-3, the adapter automatically selects the least-secret-exposing type.
//! Type 4 apps use the [`credential_cache`] module for lifecycle management.
//!
//! # Key Types
//!
//! - [`AppSpec`] — Declares an app's name, executable, supported integrations
//! - [`BindingStore`] / [`SecretStore`] — Persistent credential management
//! - [`resolve_program`] — Find executables with alias/wrapper resolution
//! - [`prepare_best_app_launch`] — Select integration and prepare process launch
//! - [`run`] — Execute the prepared launch
//! - [`credential_cache::LifecyclePolicy`] — Define credential expiration tiers for Type 4 apps
//! - [`credential_cache::classify_credential`] — Determine credential state without decrypting

pub mod app_spec;
pub mod binding_store;
pub mod common;
pub mod credential_cache;
pub mod error;
pub mod execution_plan;
pub mod launcher;
pub mod prepare_launch;
pub mod provenance;
pub mod resolver;
pub mod secret_store;
pub mod state_lock;
pub mod temp_config;
pub mod types;

pub use app_spec::{AppSpec, ConfigOverride};
pub use binding_store::{
    app_data_dir, app_data_dir_with_env, BindingStore, JsonFileBindingStore, MemoryBindingStore,
};
pub use common::restore_previous_secret;
pub use error::{AdapterError, Result};
pub use execution_plan::choose_integration;
pub use launcher::{run, LaunchRequest};
pub use prepare_launch::{
    prepare_app_launch, prepare_best_app_launch, IntegrationCandidates, IntegrationPayload,
    PreparedAppLaunch,
};
pub use provenance::{
    applies_to_config_path, has_any_install_provenance, provenance_for_path,
    remove_provenance_for_path, set_provenance_for_path, InstallProvenance,
};
pub use resolver::{resolve_program, ResolveMode, ResolveOptions};
pub use secret_store::{
    is_redacted_placeholder, EncryptedFileSecretStore, MemorySecretStore,
    ReadOnlyEncryptedFileSecretStore, SecretStore, REDACTED_PLACEHOLDER,
};
pub use state_lock::{with_state_lock, with_state_lock_read_only};
pub use temp_config::TempConfig;
#[cfg(target_os = "linux")]
pub use temp_config::{create_memfd_config, MemfdConfig};
pub use types::{BindingId, BindingRecord, IntegrationType, ResolutionStrategy, ResolvedProgram};

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    pub(crate) static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    thread_local! {
        static ENV_LOCK_DEPTH: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) struct EnvLockGuard {
        guard: Option<MutexGuard<'static, ()>>,
    }

    pub(crate) fn lock_env() -> EnvLockGuard {
        let already_held = ENV_LOCK_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current + 1);
            current > 0
        });
        let guard = if already_held {
            None
        } else {
            Some(ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner()))
        };
        EnvLockGuard { guard }
    }

    impl Drop for EnvLockGuard {
        fn drop(&mut self) {
            ENV_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
            drop(self.guard.take());
        }
    }

    pub(crate) struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        pub(crate) fn set(key: &'static str, value: impl Into<OsString>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value.into());
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
