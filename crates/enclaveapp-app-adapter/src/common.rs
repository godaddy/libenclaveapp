use anyhow::Result;

use crate::secret_store::SecretStore;
use crate::types::BindingId;

/// Restore a previously-snapshotted secret value (or delete the entry if
/// the snapshot was `None`).  This is the single shared implementation used
/// by management, install, uninstall, and token-source rollback paths.
pub fn restore_previous_secret<S>(
    secret_store: &S,
    id: &BindingId,
    previous_secret: Option<&str>,
) -> Result<()>
where
    S: SecretStore,
{
    match previous_secret {
        Some(secret) => secret_store.set(id, secret)?,
        None => {
            let _ = secret_store.delete(id)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySecretStore;

    #[test]
    fn restore_previous_secret_with_some() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("test:default");

        // Set a current value
        store.set(&id, "current-token").expect("set");

        // Restore a previous value
        restore_previous_secret(&store, &id, Some("previous-token")).expect("restore");

        assert_eq!(
            store.get(&id).expect("get"),
            Some("previous-token".to_string())
        );
    }

    #[test]
    fn restore_previous_secret_with_none() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("test:default");

        // Set a current value
        store.set(&id, "current-token").expect("set");

        // Restore None means delete
        restore_previous_secret(&store, &id, None).expect("restore");

        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn restore_previous_secret_with_none_when_no_existing_value() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("test:nonexistent");

        // Restoring None on a non-existent key should succeed
        restore_previous_secret(&store, &id, None).expect("restore");

        assert_eq!(store.get(&id).expect("get"), None);
    }

    #[test]
    fn restore_previous_secret_overwrites_existing() {
        let store = MemorySecretStore::new();
        let id = BindingId::new("test:default");

        store.set(&id, "first").expect("set");
        restore_previous_secret(&store, &id, Some("second")).expect("restore");
        assert_eq!(store.get(&id).expect("get"), Some("second".to_string()));

        restore_previous_secret(&store, &id, Some("third")).expect("restore again");
        assert_eq!(store.get(&id).expect("get"), Some("third".to_string()));
    }
}
