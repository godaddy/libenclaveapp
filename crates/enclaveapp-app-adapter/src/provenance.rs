use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::types::BindingRecord;

const INSTALL_PROVENANCE_KEY: &str = "install_provenance";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallProvenance {
    pub config_line_origin: String,
    pub installed_from_npmrc: bool,
    pub original_line_kind: Option<String>,
}

pub fn applies_to_config_path(record: &BindingRecord, path: &str) -> bool {
    provenance_for_path(record, path).is_some()
}

pub fn has_any_install_provenance(record: &BindingRecord) -> bool {
    !load_install_provenance(record).is_empty()
        || record.metadata.contains_key("original_config_path")
        || record.metadata.contains_key("config_line_origin")
        || record.metadata.contains_key("installed_from_npmrc")
}

pub fn provenance_for_path(record: &BindingRecord, path: &str) -> Option<InstallProvenance> {
    load_install_provenance(record)
        .get(path)
        .cloned()
        .or_else(|| legacy_provenance_for_path(record, path))
}

pub fn set_provenance_for_path(
    record: &mut BindingRecord,
    path: &Path,
    provenance: InstallProvenance,
) -> Result<()> {
    let path_string = path.to_string_lossy().into_owned();
    let mut all = load_install_provenance(record);
    all.insert(path_string.clone(), provenance.clone());
    store_install_provenance(record, &all)?;
    set_legacy_provenance(record, &path_string, &provenance);
    Ok(())
}

pub fn remove_provenance_for_path(record: &mut BindingRecord, path: &str) -> Result<bool> {
    let mut all = load_install_provenance(record);
    let removed_from_map = all.remove(path).is_some();
    if removed_from_map {
        if all.is_empty() {
            record.metadata.remove(INSTALL_PROVENANCE_KEY);
            clear_legacy_provenance(record);
            return Ok(false);
        }

        store_install_provenance(record, &all)?;
        if let Some((remaining_path, remaining)) = all.iter().next() {
            set_legacy_provenance(record, remaining_path, remaining);
        }
        return Ok(true);
    }

    if record
        .metadata
        .get("original_config_path")
        .is_some_and(|stored| stored == path)
    {
        clear_legacy_provenance(record);
        return Ok(false);
    }

    Ok(!all.is_empty())
}

fn load_install_provenance(record: &BindingRecord) -> BTreeMap<String, InstallProvenance> {
    record
        .metadata
        .get(INSTALL_PROVENANCE_KEY)
        .and_then(|serialized| serde_json::from_str(serialized).ok())
        .unwrap_or_default()
}

fn store_install_provenance(
    record: &mut BindingRecord,
    all: &BTreeMap<String, InstallProvenance>,
) -> Result<()> {
    record.metadata.insert(
        INSTALL_PROVENANCE_KEY.to_string(),
        serde_json::to_string(all)?,
    );
    Ok(())
}

fn legacy_provenance_for_path(record: &BindingRecord, path: &str) -> Option<InstallProvenance> {
    let original_path = record.metadata.get("original_config_path")?;
    if original_path != path {
        return None;
    }

    let config_line_origin = record.metadata.get("config_line_origin")?.clone();
    let installed_from_npmrc = record
        .metadata
        .get("installed_from_npmrc")
        .is_some_and(|value| value == "true");
    let original_line_kind = record.metadata.get("original_line_kind").cloned();
    Some(InstallProvenance {
        config_line_origin,
        installed_from_npmrc,
        original_line_kind,
    })
}

fn set_legacy_provenance(record: &mut BindingRecord, path: &str, provenance: &InstallProvenance) {
    record.metadata.insert(
        "config_line_origin".to_string(),
        provenance.config_line_origin.clone(),
    );
    record
        .metadata
        .insert("original_config_path".to_string(), path.to_string());
    record.metadata.insert(
        "installed_from_npmrc".to_string(),
        provenance.installed_from_npmrc.to_string(),
    );
    match &provenance.original_line_kind {
        Some(kind) => {
            record
                .metadata
                .insert("original_line_kind".to_string(), kind.clone());
        }
        None => {
            record.metadata.remove("original_line_kind");
        }
    }
}

fn clear_legacy_provenance(record: &mut BindingRecord) {
    record.metadata.remove("config_line_origin");
    record.metadata.remove("original_config_path");
    record.metadata.remove("installed_from_npmrc");
    record.metadata.remove("original_line_kind");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::types::BindingId;

    fn test_record() -> BindingRecord {
        BindingRecord {
            id: BindingId::new("test:default"),
            label: "default".to_string(),
            target: "https://example.com".to_string(),
            secret_env_var: "TOKEN".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn set_and_get_provenance_for_path() {
        let mut record = test_record();
        let path = PathBuf::from("/home/user/.npmrc");
        let provenance = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: true,
            original_line_kind: Some("auth_token".to_string()),
        };

        set_provenance_for_path(&mut record, &path, provenance.clone()).expect("set provenance");

        let result = provenance_for_path(&record, "/home/user/.npmrc");
        assert_eq!(result, Some(provenance));
    }

    #[test]
    fn applies_to_config_path_returns_true_when_set() {
        let mut record = test_record();
        let path = PathBuf::from("/home/user/.npmrc");
        let provenance = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: true,
            original_line_kind: None,
        };
        set_provenance_for_path(&mut record, &path, provenance).expect("set provenance");

        assert!(applies_to_config_path(&record, "/home/user/.npmrc"));
        assert!(!applies_to_config_path(&record, "/other/path/.npmrc"));
    }

    #[test]
    fn has_any_install_provenance_empty_record() {
        let record = test_record();
        assert!(!has_any_install_provenance(&record));
    }

    #[test]
    fn has_any_install_provenance_with_provenance() {
        let mut record = test_record();
        let path = PathBuf::from("/home/user/.npmrc");
        let provenance = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: false,
            original_line_kind: None,
        };
        set_provenance_for_path(&mut record, &path, provenance).expect("set provenance");

        assert!(has_any_install_provenance(&record));
    }

    #[test]
    fn has_any_install_provenance_with_legacy_metadata() {
        let mut record = test_record();
        record.metadata.insert(
            "original_config_path".to_string(),
            "/home/user/.npmrc".to_string(),
        );

        assert!(has_any_install_provenance(&record));
    }

    #[test]
    fn remove_provenance_for_path_single_entry() {
        let mut record = test_record();
        let path = PathBuf::from("/home/user/.npmrc");
        let provenance = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: true,
            original_line_kind: None,
        };
        set_provenance_for_path(&mut record, &path, provenance).expect("set provenance");

        let has_remaining =
            remove_provenance_for_path(&mut record, "/home/user/.npmrc").expect("remove");
        assert!(!has_remaining);
        assert!(!has_any_install_provenance(&record));
    }

    #[test]
    fn remove_provenance_for_path_with_multiple_entries() {
        let mut record = test_record();
        let provenance_a = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: true,
            original_line_kind: None,
        };
        let provenance_b = InstallProvenance {
            config_line_origin: "//other.registry/:_authToken".to_string(),
            installed_from_npmrc: false,
            original_line_kind: Some("auth_token".to_string()),
        };
        set_provenance_for_path(&mut record, &PathBuf::from("/path/a"), provenance_a)
            .expect("set a");
        set_provenance_for_path(&mut record, &PathBuf::from("/path/b"), provenance_b)
            .expect("set b");

        let has_remaining = remove_provenance_for_path(&mut record, "/path/a").expect("remove a");
        assert!(has_remaining);
        assert!(provenance_for_path(&record, "/path/b").is_some());
        assert!(provenance_for_path(&record, "/path/a").is_none());
    }

    #[test]
    fn remove_provenance_nonexistent_path() {
        let mut record = test_record();

        let has_remaining =
            remove_provenance_for_path(&mut record, "/no/such/path").expect("remove");
        assert!(!has_remaining);
    }

    #[test]
    fn legacy_provenance_fallback() {
        let mut record = test_record();
        record.metadata.insert(
            "original_config_path".to_string(),
            "/home/user/.npmrc".to_string(),
        );
        record.metadata.insert(
            "config_line_origin".to_string(),
            "//registry.npmjs.org/:_authToken".to_string(),
        );
        record
            .metadata
            .insert("installed_from_npmrc".to_string(), "true".to_string());

        let result = provenance_for_path(&record, "/home/user/.npmrc");
        assert!(result.is_some());
        let prov = result.expect("provenance");
        assert_eq!(prov.config_line_origin, "//registry.npmjs.org/:_authToken");
        assert!(prov.installed_from_npmrc);
        assert_eq!(prov.original_line_kind, None);
    }

    #[test]
    fn legacy_provenance_does_not_match_different_path() {
        let mut record = test_record();
        record.metadata.insert(
            "original_config_path".to_string(),
            "/home/user/.npmrc".to_string(),
        );
        record.metadata.insert(
            "config_line_origin".to_string(),
            "//registry.npmjs.org/:_authToken".to_string(),
        );
        record
            .metadata
            .insert("installed_from_npmrc".to_string(), "true".to_string());

        assert!(provenance_for_path(&record, "/other/path").is_none());
    }

    #[test]
    fn remove_legacy_provenance() {
        let mut record = test_record();
        record.metadata.insert(
            "original_config_path".to_string(),
            "/home/user/.npmrc".to_string(),
        );
        record.metadata.insert(
            "config_line_origin".to_string(),
            "//registry.npmjs.org/:_authToken".to_string(),
        );
        record
            .metadata
            .insert("installed_from_npmrc".to_string(), "true".to_string());

        let has_remaining =
            remove_provenance_for_path(&mut record, "/home/user/.npmrc").expect("remove");
        assert!(!has_remaining);
        assert!(!has_any_install_provenance(&record));
    }

    #[test]
    fn install_provenance_serde_round_trip() {
        let provenance = InstallProvenance {
            config_line_origin: "//registry.npmjs.org/:_authToken".to_string(),
            installed_from_npmrc: true,
            original_line_kind: Some("auth_token".to_string()),
        };

        let json = serde_json::to_string(&provenance).expect("serialize");
        let deserialized: InstallProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(provenance, deserialized);
    }
}
