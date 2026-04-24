// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Ensure a per-app helper daemon is running and listening on a
//! Unix socket.
//!
//! The sshenc / awsenc / … family each pair a foreground CLI with a
//! long-lived helper daemon that owns all Secure-Enclave / keychain
//! state, so the CLI binary's code signature never appears on an
//! `SecItem*` call and macOS's legacy-keychain ACL doesn't fire a
//! cross-binary approval prompt on every install. This module is
//! the "make sure the daemon is up to accept RPCs" step that every
//! CLI invocation runs before it proxies a request.
//!
//! Discovery is intentionally PATH-free: a malicious binary sitting
//! on PATH shouldn't be a launchable daemon. [`find_trusted_binary`]
//! limits the search to known install dirs, and spawn arguments are
//! fixed (`--socket <path>`) so no user-controlled flags can leak
//! in.

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bin_discovery;

/// Outcome of [`ensure_daemon_ready`] when the spawn path is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSpawn {
    /// The socket was already accepting connections — nothing was
    /// spawned.
    AlreadyRunning,
    /// The daemon was spawned and became ready within the timeout.
    Spawned { binary: PathBuf },
}

/// Error path for [`ensure_daemon_ready`]. String-only so the helper
/// stays dependency-free of the richer error taxonomies each
/// consumer defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonReadyError {
    /// No trusted copy of `binary_name` could be located. The user
    /// has likely not installed the app, or the install layout
    /// deviates from what [`bin_discovery`] knows about.
    BinaryNotFound { binary_name: String },
    /// Spawn failed (OS refused, binary not executable on the
    /// target architecture, etc.).
    SpawnFailed { binary: PathBuf, reason: String },
    /// A filesystem op on the socket's parent directory failed.
    SocketDirSetupFailed { parent: PathBuf, reason: String },
    /// The daemon was spawned but did not accept a connection on
    /// `socket_path` before the readiness timeout elapsed.
    NotReady {
        socket_path: PathBuf,
        timeout: Duration,
    },
}

impl std::fmt::Display for DaemonReadyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound { binary_name } => {
                write!(f, "{binary_name} binary not found in known install dirs")
            }
            Self::SpawnFailed { binary, reason } => {
                write!(f, "spawning {}: {reason}", binary.display())
            }
            Self::SocketDirSetupFailed { parent, reason } => {
                write!(
                    f,
                    "creating daemon socket dir {}: {reason}",
                    parent.display()
                )
            }
            Self::NotReady {
                socket_path,
                timeout,
            } => write!(
                f,
                "daemon did not become ready at {} within {:?}",
                socket_path.display(),
                timeout
            ),
        }
    }
}

impl std::error::Error for DaemonReadyError {}

/// Exponential-backoff schedule used by [`ensure_daemon_ready`] when
/// it has to wait for a freshly-spawned daemon. 100, 200, 400, 800,
/// 1600 ms — ≈3.1 s in aggregate before giving up.
const READINESS_BACKOFF_MS: &[u64] = &[100, 200, 400, 800, 1600];

/// Total timeout across the [`READINESS_BACKOFF_MS`] schedule. Used
/// when reporting [`DaemonReadyError::NotReady`].
fn readiness_total_timeout() -> Duration {
    Duration::from_millis(READINESS_BACKOFF_MS.iter().sum())
}

/// Make sure `binary_name` is listening on `socket_path`, spawning
/// it via the [`bin_discovery`] search (parameterized by
/// `app_name`) if it isn't already. Returns `AlreadyRunning` if the
/// socket was already live, or `Spawned { binary }` when this call
/// launched it. Errors out without retrying if the binary can't be
/// found or if spawn fails — callers should surface a clear message
/// pointing at the installer rather than silently falling back to
/// an in-process code path, because the whole point of this
/// daemon-only architecture is to keep the CLI's code signature
/// off the crypto FFI.
///
/// Invoke shape is fixed: `<binary> --socket <socket_path>`. Every
/// current consumer (sshenc-agent and awsenc-daemon both) honors
/// that interface; if a future consumer needs a different CLI shape
/// we'll add a parameter instead of allowing unbounded args here,
/// to keep the "no attacker-controlled flags" property.
#[cfg(unix)]
pub fn ensure_daemon_ready(
    binary_name: &str,
    app_name: &str,
    socket_path: &Path,
) -> Result<DaemonSpawn, DaemonReadyError> {
    if is_socket_ready(socket_path) {
        return Ok(DaemonSpawn::AlreadyRunning);
    }

    let binary = bin_discovery::find_trusted_binary(binary_name, app_name).ok_or_else(|| {
        DaemonReadyError::BinaryNotFound {
            binary_name: binary_name.to_string(),
        }
    })?;

    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DaemonReadyError::SocketDirSetupFailed {
                    parent: parent.to_path_buf(),
                    reason: e.to_string(),
                }
            })?;
        }
    }

    use std::process::Stdio;
    std::process::Command::new(&binary)
        .arg("--socket")
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| DaemonReadyError::SpawnFailed {
            binary: binary.clone(),
            reason: e.to_string(),
        })?;

    for backoff_ms in READINESS_BACKOFF_MS {
        std::thread::sleep(Duration::from_millis(*backoff_ms));
        if is_socket_ready(socket_path) {
            return Ok(DaemonSpawn::Spawned { binary });
        }
    }
    Err(DaemonReadyError::NotReady {
        socket_path: socket_path.to_path_buf(),
        timeout: readiness_total_timeout(),
    })
}

/// Windows stub: daemons on Windows talk over named pipes, not Unix
/// sockets, and every current named-pipe daemon is managed as a
/// Service rather than spawned on demand. Callers get
/// `AlreadyRunning` so they proceed to the RPC attempt; the RPC
/// itself will surface any "daemon unreachable" condition.
#[cfg(not(unix))]
pub fn ensure_daemon_ready(
    _binary_name: &str,
    _app_name: &str,
    _socket_path: &Path,
) -> Result<DaemonSpawn, DaemonReadyError> {
    Ok(DaemonSpawn::AlreadyRunning)
}

#[cfg(unix)]
fn is_socket_ready(socket_path: &Path) -> bool {
    socket_path.exists() && UnixStream::connect(socket_path).is_ok()
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_socket(tag: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "enclaveapp-daemon-test-{}-{}-{tag}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("daemon.sock")
    }

    #[test]
    fn already_running_short_circuits_without_spawning() {
        let sock = unique_socket("already-running");
        let _unused = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();

        // binary_name is intentionally bogus — if we reach spawn,
        // this test fails.
        let got =
            ensure_daemon_ready("definitely-not-on-disk", "myapp", &sock).expect("should succeed");
        assert_eq!(got, DaemonSpawn::AlreadyRunning);

        drop(listener);
        let _unused = std::fs::remove_file(&sock);
    }

    #[test]
    fn missing_binary_reports_binary_not_found() {
        let sock = unique_socket("missing-binary");
        let _unused = std::fs::remove_file(&sock);

        let err = ensure_daemon_ready("enclaveapp-definitely-not-a-binary", "myapp", &sock)
            .expect_err("should fail");
        assert!(matches!(err, DaemonReadyError::BinaryNotFound { .. }));

        let _unused = std::fs::remove_file(&sock);
    }
}
