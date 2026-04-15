#![allow(clippy::panic, clippy::unwrap_used)]
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use enclaveapp_app_adapter::{
    prepare_best_app_launch, run, AppSpec, ConfigOverride, IntegrationCandidates,
    IntegrationPayload, IntegrationType, ResolutionStrategy, ResolvedProgram,
};
use tempfile::TempDir;

fn make_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod");
}

fn resolved_program(path: &std::path::Path) -> ResolvedProgram {
    ResolvedProgram {
        path: path.to_path_buf(),
        fixed_args: Vec::new(),
        strategy: ResolutionStrategy::ExplicitPath,
        shell_hint: None,
    }
}

#[test]
fn helper_tool_launch_runs_without_temp_config() {
    let dir = TempDir::new().expect("temp dir");
    let target = dir.path().join("mock-helper");
    let capture = dir.path().join("capture.txt");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'helper_socket=%s\\narg1=%s\\narg2=%s\\n' \"$HELPER_SOCKET\" \"$1\" \"$2\" > \"{}\"\n",
            capture.display()
        ),
    );

    let spec = AppSpec {
        display_name: "helper-app".to_string(),
        executable_name: "helper-app".to_string(),
        supported_integrations: vec![IntegrationType::HelperTool],
        config_override: ConfigOverride::None,
    };
    let prepared = prepare_best_app_launch(
        &spec,
        resolved_program(&target),
        vec!["publish".to_string()],
        IntegrationCandidates {
            helper_tool: Some(IntegrationPayload::HelperTool {
                env_overrides: BTreeMap::from([(
                    "HELPER_SOCKET".to_string(),
                    "/tmp/helper.sock".to_string(),
                )]),
                extra_args: vec!["--auth-helper".to_string()],
            }),
            ..IntegrationCandidates::default()
        },
    )
    .expect("prepare launch");

    assert!(prepared.temp_config_path.is_none());
    let status = run(&prepared.launch).expect("run helper");
    assert!(status.success());

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("helper_socket=/tmp/helper.sock"));
    assert!(captured.contains("arg1=--auth-helper"));
    assert!(captured.contains("arg2=publish"));
}

#[test]
fn env_interpolation_launch_passes_placeholder_config_and_secret_env() {
    let dir = TempDir::new().expect("temp dir");
    let target = dir.path().join("mock-env");
    let capture = dir.path().join("capture.txt");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nprintf 'env_token=%s\\nconfig=%s\\n' \"$APP_TOKEN\" \"$APP_CONFIG\" > \"{}\"\ncat \"$APP_CONFIG\" >> \"{}\"\n",
            capture.display(),
            capture.display()
        ),
    );

    let spec = AppSpec {
        display_name: "env-app".to_string(),
        executable_name: "env-app".to_string(),
        supported_integrations: vec![IntegrationType::EnvInterpolation],
        config_override: ConfigOverride::EnvironmentVariable {
            name: "APP_CONFIG".to_string(),
        },
    };
    let prepared = prepare_best_app_launch(
        &spec,
        resolved_program(&target),
        vec!["run".to_string()],
        IntegrationCandidates {
            env_interpolation: Some(IntegrationPayload::EnvInterpolation {
                config_bytes: Some(b"token=${APP_TOKEN}\n".to_vec()),
                env_overrides: BTreeMap::from([(
                    "APP_TOKEN".to_string(),
                    "secret-token".to_string(),
                )]),
            }),
            ..IntegrationCandidates::default()
        },
    )
    .expect("prepare launch");

    let status = run(&prepared.launch).expect("run env");
    assert!(status.success());

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("env_token=secret-token"));
    assert!(captured.contains("token=${APP_TOKEN}\n"));
    assert!(!captured.contains("\ntoken=secret-token\n"));
}

#[test]
fn temp_materialized_launch_passes_config_flag_and_materialized_secret() {
    let dir = TempDir::new().expect("temp dir");
    let target = dir.path().join("mock-temp");
    let capture = dir.path().join("capture.txt");

    make_executable_script(
        &target,
        &format!(
            "#!/bin/sh\nconfig_path=\"$2\"\nprintf 'arg1=%s\\nconfig=%s\\n' \"$1\" \"$config_path\" > \"{}\"\ncat \"$config_path\" >> \"{}\"\n",
            capture.display(),
            capture.display()
        ),
    );

    let spec = AppSpec {
        display_name: "temp-app".to_string(),
        executable_name: "temp-app".to_string(),
        supported_integrations: vec![IntegrationType::TempMaterializedConfig],
        config_override: ConfigOverride::CommandLineFlag {
            flag: "--config".to_string(),
        },
    };
    let prepared = prepare_best_app_launch(
        &spec,
        resolved_program(&target),
        vec!["publish".to_string()],
        IntegrationCandidates {
            temp_materialized_config: Some(IntegrationPayload::TempMaterializedConfig {
                config_bytes: b"token=materialized-secret\n".to_vec(),
                env_overrides: BTreeMap::new(),
            }),
            ..IntegrationCandidates::default()
        },
    )
    .expect("prepare launch");

    let status = run(&prepared.launch).expect("run temp");
    assert!(status.success());

    let captured = fs::read_to_string(&capture).expect("capture");
    assert!(captured.contains("arg1=--config"));
    assert!(captured.contains("token=materialized-secret"));
}
