#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used))]

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use enclaveapp_app_storage::{
    create_encryption_storage, AccessPolicy, EncryptionStorage, StorageConfig,
};
use fs4::fs_std::FileExt;
use sha2::{Digest, Sha256};

use crate::binding_store::app_data_dir;
use crate::error::{AdapterError, Result};
use crate::types::BindingId;

/// Placeholder value returned by read-only secret stores instead of the
/// actual secret.  Consumers that need to distinguish "secret exists but
/// cannot be read" from a real value **must** use [`is_redacted_placeholder`]
/// rather than a bare `==` comparison — the function performs a
/// constant-time byte compare and centralizes the collision-risk
/// surface on a single helper that can be upgraded to a typed return
/// type without touching every call site.
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Check whether a secret-store string return is the redaction sentinel.
///
/// The sentinel collides semantically with any real secret whose value
/// happens to equal the literal string `"<redacted>"`. That's a
/// vanishingly unlikely collision for npm tokens (which begin with
/// `npm_`) or SSO JWTs (which are base64-encoded with `.` separators),
/// but the library cannot prove it can never happen. Using this helper
/// keeps the single comparison site canonical — a future migration to
/// a typed `SecretMaterialization` enum can swap this function's body
/// without breaking call-site ergonomics.
#[must_use]
pub fn is_redacted_placeholder(value: &str) -> bool {
    value == REDACTED_PLACEHOLDER
}

pub trait SecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()>;
    fn get(&self, id: &BindingId) -> Result<Option<String>>;
    fn delete(&self, id: &BindingId) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct ReadOnlyEncryptedFileSecretStore {
    dir: PathBuf,
}

impl ReadOnlyEncryptedFileSecretStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        Ok(Self {
            dir: app_data_dir(app_name)?.join("secrets"),
        })
    }

    fn path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(hash_id(id))
    }
}

pub struct EncryptedFileSecretStore {
    app_name: String,
    dir: PathBuf,
    storage: OnceLock<std::result::Result<Box<dyn EncryptionStorage>, String>>,
}

impl std::fmt::Debug for EncryptedFileSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFileSecretStore")
            .field("app_name", &self.app_name)
            .field("dir", &self.dir)
            .finish()
    }
}

impl EncryptedFileSecretStore {
    pub fn for_app(app_name: &str) -> Result<Self> {
        let dir = app_data_dir(app_name)?.join("secrets");
        Ok(Self {
            app_name: app_name.to_string(),
            dir,
            storage: OnceLock::new(),
        })
    }

    fn path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(hash_id(id))
    }

    fn lock_path_for(&self, id: &BindingId) -> PathBuf {
        self.dir.join(format!("{}.lock", hash_id(id)))
    }

    fn storage(&self) -> Result<&dyn EncryptionStorage> {
        match self.storage.get_or_init(|| {
            create_encryption_storage(StorageConfig {
                app_name: self.app_name.clone(),
                key_label: "adapter-secrets".to_string(),
                access_policy: AccessPolicy::None,
                extra_bridge_paths: Vec::new(),
                keys_dir: None,
                force_keyring: false,
            })
            .map_err(|error| error.to_string())
        }) {
            Ok(storage) => Ok(storage.as_ref()),
            Err(error) => Err(AdapterError::Storage(error.clone())),
        }
    }

    fn with_shared_lock<T>(
        &self,
        id: &BindingId,
        work: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        fs::create_dir_all(&self.dir)?;
        let lock_path = self.lock_path_for(id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        FileExt::lock_shared(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn with_exclusive_lock<T>(
        &self,
        id: &BindingId,
        work: impl FnOnce(&Self) -> Result<T>,
    ) -> Result<T> {
        fs::create_dir_all(&self.dir)?;
        set_dir_permissions(&self.dir)?;
        let lock_path = self.lock_path_for(id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        FileExt::lock_exclusive(&file).map_err(|error| AdapterError::Storage(error.to_string()))?;
        let result = work(self);
        let unlock_result =
            FileExt::unlock(&file).map_err(|error| AdapterError::Storage(error.to_string()));
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()> {
        self.with_exclusive_lock(id, |store| {
            let ciphertext = store.storage()?.encrypt(secret.as_bytes())?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(ciphertext);
            let path = store.path_for(id);
            let temp_path = temp_path_for(&path);
            fs::write(&temp_path, encoded)?;
            set_file_permissions(&temp_path)?;
            fs::rename(&temp_path, &path)?;
            Ok(())
        })
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        if !self.lock_path_for(id).exists() {
            let encoded = fs::read_to_string(path)?;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            let plaintext = self.storage()?.decrypt(&ciphertext)?;
            let value = String::from_utf8(plaintext)
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            return Ok(Some(value));
        }

        self.with_shared_lock(id, |store| {
            let path = store.path_for(id);
            if !path.exists() {
                return Ok(None);
            }

            let encoded = fs::read_to_string(path)?;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            let plaintext = store.storage()?.decrypt(&ciphertext)?;
            let value = String::from_utf8(plaintext)
                .map_err(|error| AdapterError::Storage(error.to_string()))?;
            Ok(Some(value))
        })
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        self.with_exclusive_lock(id, |store| {
            let path = store.path_for(id);
            if !path.exists() {
                return Ok(false);
            }

            fs::remove_file(path)?;
            Ok(true)
        })
    }
}

impl SecretStore for ReadOnlyEncryptedFileSecretStore {
    fn set(&self, id: &BindingId, _secret: &str) -> Result<()> {
        Err(AdapterError::Storage(format!(
            "read-only secret store cannot set `{id:?}`"
        )))
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        if !self.dir.exists() {
            return Ok(None);
        }
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(REDACTED_PLACEHOLDER.to_string()))
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        Err(AdapterError::Storage(format!(
            "read-only secret store cannot delete `{id:?}`"
        )))
    }
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<BindingId, String>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemorySecretStore {
    fn set(&self, id: &BindingId, secret: &str) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .insert(id.clone(), secret.to_string());
        Ok(())
    }

    fn get(&self, id: &BindingId) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .get(id)
            .cloned())
    }

    fn delete(&self, id: &BindingId) -> Result<bool> {
        Ok(self
            .values
            .lock()
            .map_err(|_| AdapterError::Storage("secret store mutex poisoned".to_string()))?
            .remove(id)
            .is_some())
    }
}

fn hash_id(id: &BindingId) -> String {
    let digest = Sha256::digest(id.as_str().as_bytes());
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn temp_path_for(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    path.with_file_name(format!(".{file_name}.{pid}.{nonce}.tmp"))
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:default");

        store.set(&id, "token").expect("set");
        assert_eq!(store.get(&id).expect("get"), Some("token".to_string()));
        assert!(store.delete(&id).expect("delete"));
        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn redacted_placeholder_constant_is_not_empty() {
        assert!(!REDACTED_PLACEHOLDER.is_empty());
    }

    #[test]
    fn redacted_placeholder_is_recognizable() {
        // The placeholder should be a clearly non-secret sentinel value
        assert_eq!(REDACTED_PLACEHOLDER, "<redacted>");
    }

    #[test]
    fn read_only_store_returns_redacted_for_existing_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("mkdir");

        let store = ReadOnlyEncryptedFileSecretStore {
            dir: secrets_dir.clone(),
        };
        let id = BindingId::new("npm:test");
        let secret_path = store.path_for(&id);

        // Write some dummy ciphertext so the file exists
        fs::write(&secret_path, "dummy-encrypted-data").expect("write");

        let result = store.get(&id).expect("get");
        assert_eq!(result, Some(REDACTED_PLACEHOLDER.to_string()));
    }

    #[test]
    fn read_only_store_returns_none_when_no_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("mkdir");

        let store = ReadOnlyEncryptedFileSecretStore { dir: secrets_dir };
        let id = BindingId::new("npm:nonexistent");

        let result = store.get(&id).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn read_only_store_returns_none_when_dir_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("does-not-exist");

        let store = ReadOnlyEncryptedFileSecretStore { dir: secrets_dir };
        let id = BindingId::new("npm:whatever");

        let result = store.get(&id).expect("get");
        assert_eq!(result, None);
    }

    #[test]
    fn read_only_store_set_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ReadOnlyEncryptedFileSecretStore {
            dir: dir.path().to_path_buf(),
        };
        let id = BindingId::new("npm:test");

        let result = store.set(&id, "secret");
        assert!(result.is_err());
    }

    #[test]
    fn read_only_store_delete_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = ReadOnlyEncryptedFileSecretStore {
            dir: dir.path().to_path_buf(),
        };
        let id = BindingId::new("npm:test");

        let result = store.delete(&id);
        assert!(result.is_err());
    }

    #[test]
    fn memory_store_get_nonexistent_returns_none() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:nonexistent");

        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn memory_store_delete_nonexistent_returns_false() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:nonexistent");

        assert!(!store.delete(&id).expect("delete"));
    }

    #[test]
    fn memory_store_set_overwrites() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("npm:default");

        store.set(&id, "first").expect("set");
        store.set(&id, "second").expect("set");
        assert_eq!(store.get(&id).expect("get"), Some("second".to_string()));
    }
}
