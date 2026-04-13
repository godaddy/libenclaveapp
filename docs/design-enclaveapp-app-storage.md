# Design: `enclaveapp-app-storage` — Shared Application Storage Crate

**Author:** Jay Gowdy  
**Date:** 2026-04-13  
**Updated:** 2026-04-13  
**Status:** Draft

## Repository Layout

All repos are in the `godaddy` GitHub org:
- **libenclaveapp**: `github.com/godaddy/libenclaveapp` — this repo; shared Rust library
- **sshenc**: `github.com/godaddy/sshenc` — SSH key management (signing)
- **awsenc**: `github.com/godaddy/awsenc` — AWS credential caching (encryption)
- **sso-jwt**: `github.com/godaddy/sso-jwt` — SSO JWT caching (encryption)

**Local development layout**: The three consumer apps are checked out as subdirectories of the libenclaveapp repo and `.gitignored`:
```
libenclaveapp/          ← this git repo
├── crates/             ← libenclaveapp workspace crates
├── sshenc/             ← separate git repo, .gitignored
├── awsenc/             ← separate git repo, .gitignored
└── sso-jwt/            ← separate git repo, .gitignored
```

The consumer apps' `Cargo.toml` files use `path = "../crates/enclaveapp-core"` etc., which works locally because `..` from `sso-jwt/` is the libenclaveapp root.

**CI layout**: Consumer app CI workflows (`.github/workflows/ci.yml` and `release.yml`) reference `godaddy/libenclaveapp/.github/workflows/reusable-ci.yml@main` and `reusable-release.yml@main`. The reusable workflows clone libenclaveapp and make the crates available:
```yaml
- name: Clone libenclaveapp
  shell: bash
  run: |
    git clone --depth 1 https://github.com/godaddy/libenclaveapp.git ../libenclaveapp
    cp -r ../libenclaveapp/crates ../crates
    cp ../libenclaveapp/Cargo.toml ../Cargo.toml
```
The `cp` of both `crates/` and `Cargo.toml` into `../` is required because the enclaveapp crates use `edition.workspace = true` and Cargo walks up from `../crates/enclaveapp-*/Cargo.toml` to find the workspace root at `../Cargo.toml`. A symlink does NOT work because Cargo uses the apparent path, not the resolved path, when walking up for workspace resolution.

**When adding `enclaveapp-app-storage` to the workspace**, it must be included in the `cp -r ../libenclaveapp/crates ../crates` path (it already will be since it lives under `crates/`). No CI workflow changes needed beyond what's already in place.

## Problem Statement

Three applications consume libenclaveapp (`sshenc`, `awsenc`, `sso-jwt`). Each has independently implemented nearly identical platform detection, key initialization, and encrypt/decrypt wrapper code. This duplication exists primarily in:

- `awsenc/awsenc-secure-storage/` (~230 LOC across 4 files + mock)
- `sso-jwt/sso-jwt-lib/src/secure_storage/` (~260 LOC across 5 files + mock)
- `sshenc/crates/sshenc-se/` (similar pattern but for signing, ~300 LOC across 4 files)

The code is structurally identical: detect platform, instantiate the right libenclaveapp backend, check if a key exists, generate one if not (with biometric flag mapped to `AccessPolicy`), then wrap encrypt/decrypt or sign with error conversion.

Additionally, all three apps need consistent biometric/user-presence support, and the biometric re-consent mechanism should leverage OS-native hardware authentication rather than brittle application-level heuristics.

## Goals

1. **Eliminate duplication**: A single shared crate replaces the per-app secure storage modules.
2. **Consistent biometric support**: Uniform CLI flags and behavior across all three apps.
3. **OS-native re-consent**: Delegate re-authentication timing to Secure Enclave / TPM / Windows Hello — no application-level session tracking.
4. **Key policy management**: Detect and handle mismatches between configured biometric policy and existing key policy.
5. **Testability**: Shared mock backend for all consumers.

## Non-Goals

- Application-level idle timeout tracking (shell history monitoring, file timestamp touching).
- LAContext-based custom authentication reuse duration on macOS.
- Changes to the underlying libenclaveapp platform crates (enclaveapp-apple, enclaveapp-windows, etc.).
- Changes to ECIES wire format or key storage format.

## Design Decisions

1. **`enclaveapp-app-storage` re-exports core types.** It re-exports `AccessPolicy`, `KeyType`, `KeyMeta`, and the `EnclaveKeyManager`/`EnclaveEncryptor`/`EnclaveSigner` traits from `enclaveapp-core`. Consumers depend only on `enclaveapp-app-storage`, not on both crates.

2. **WSL bridge legacy paths are auto-derived from `app_name`.** The standard pattern is `"/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe"` and `"/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe"`. `StorageConfig` has an `extra_bridge_paths: Vec<String>` for any app-specific additions, defaulting to empty.

3. **sshenc uses `AppSigningBackend` only for platform detection.** sshenc's `KeyBackend` trait has SSH-specific semantics (pub file writing, fingerprinting, metadata with git_name/git_email) that don't belong in the shared crate. `AppSigningBackend` exposes `signer() -> &dyn EnclaveSigner` and `key_manager() -> &dyn EnclaveKeyManager`. sshenc wraps these with SSH-specific logic.

4. **Decrypt returns bare `Vec<u8>`, not `Zeroizing`.** Zeroization is the caller's responsibility. sso-jwt wraps returns in `Zeroizing::new()` at the call site. This avoids forcing a `zeroize` dependency on all consumers.

5. **Single file per concern, not one file per platform.** `encryption.rs` and `signing.rs` use `#[cfg(target_os)]` blocks internally. Each platform's init is ~20 lines — not worth separate files.

---

## Background: How OS-Native Re-Consent Works

### macOS Secure Enclave

When a key is created with `SecAccessControlCreateFlags.biometryAny` (via `makeAccessControl(2)` in `bridge.swift:41-52`), the Secure Enclave requires Touch ID for every private-key operation (ECDH in decrypt, ECDSA in sign). The OS caches the biometric authentication for a brief window (a few seconds) to allow rapid successive operations without re-prompting. After device lock or sufficient idle time, the next operation requires a fresh Touch ID prompt.

The current Swift bridge (`crates/enclaveapp-apple/swift/bridge.swift`) already sets `SecAccessControl` with `.biometryAny` when `auth_policy == 2`. This is correct and sufficient. The bridge imports `LocalAuthentication` (line 19) but does not use `LAContext` — the authentication is handled at the `SecAccessControl` level by the Secure Enclave hardware/firmware.

**Key insight**: Encryption (ECIES encrypt) uses only the public key — no biometric prompt. Decryption performs ECDH with the SE private key — biometric prompt here. Signing uses the SE private key — biometric prompt here.

### Windows TPM 2.0

When `set_ui_policy()` (`crates/enclaveapp-windows/src/ui_policy.rs:19-60`) applies `NCRYPT_UI_PROTECT_KEY_FLAG`, Windows Hello prompts the user on each key operation. Windows manages its own authentication caching. The current implementation already handles `AccessPolicy::Any`, `BiometricOnly`, and `PasswordOnly` identically (all set the same flag); Windows Hello decides the authentication method.

### Linux

Software backend (`enclaveapp-software`) has no hardware to enforce biometric. TPM backend (`enclaveapp-linux-tpm`) does not currently implement access policy enforcement. Biometric is unsupported on Linux — the shared crate should warn and proceed without biometric.

### Why This Is Superior to the Competing Approach

The competing solution uses:
- Shell history monitoring to detect user idle → brittle (shell-specific, easily spoofed, breaks with scripts/cron/non-interactive sessions)
- `0600` file timestamp for cache age → brittle (clock skew, trivially bypassed with `touch`, no actual user-presence verification)

The hardware approach is strictly better:
- Cannot be spoofed — biometric auth is hardware-enforced
- Not shell-specific — works for scripts, `credential_process`, SSH agent, etc.
- Zero application state to manage — no timestamps, no files, no polling
- IT-administrable — device lock policy is managed at the MDM/OS level
- The "idle time" maps to device lock → unlock → re-prompt, which is the actual security-relevant event

---

## Existing Code: What Gets Replaced

### awsenc-secure-storage (entire crate deleted)

**Files to delete:**
- `awsenc/awsenc-secure-storage/src/lib.rs` — `SecureStorage` trait, `StorageError` enum, `create_platform_storage()` dispatcher
- `awsenc/awsenc-secure-storage/src/macos.rs` — `MacosSecureEnclaveStorage` wrapping `SecureEnclaveEncryptor`
- `awsenc/awsenc-secure-storage/src/linux.rs` — `LinuxKeyringStorage` wrapping `SoftwareEncryptor`
- `awsenc/awsenc-secure-storage/src/wsl.rs` — `WslBridgeStorage` wrapping bridge client
- `awsenc/awsenc-secure-storage/src/mock.rs` — `MockStorage` using AES-256-GCM with random key
- `awsenc/awsenc-secure-storage/Cargo.toml`

**Current awsenc trait:**
```rust
pub trait SecureStorage: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn is_available(&self) -> bool;
    fn backend_name(&self) -> &'static str;
}
```
- Uses custom `StorageError` enum (6 variants)
- Returns bare `Vec<u8>` from decrypt (no zeroization)
- No `destroy()` method
- No Windows backend (returns `NotAvailable`)

**Current awsenc entry point:**
```rust
pub fn create_platform_storage(biometric: bool) -> Result<Box<dyn SecureStorage>>
```

### sso-jwt secure_storage module (entire module deleted)

**Files to delete:**
- `sso-jwt/sso-jwt-lib/src/secure_storage/mod.rs` — `SecureStorage` trait, mock, `platform_storage()` dispatcher
- `sso-jwt/sso-jwt-lib/src/secure_storage/macos.rs` — `SecureEnclaveStorage` wrapping `SecureEnclaveEncryptor`
- `sso-jwt/sso-jwt-lib/src/secure_storage/windows.rs` — `TpmStorage` wrapping `TpmEncryptor`
- `sso-jwt/sso-jwt-lib/src/secure_storage/linux.rs` — `KeyringStorage` wrapping `SoftwareEncryptor`
- `sso-jwt/sso-jwt-lib/src/secure_storage/wsl.rs` — `WslTpmBridge` wrapping bridge client

**Current sso-jwt trait:**
```rust
pub trait SecureStorage: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn destroy(&self) -> Result<()>;
}
```
- Uses `anyhow::Result`
- Returns `Zeroizing<Vec<u8>>` from decrypt
- Has `destroy()` method
- Has Windows backend (unlike awsenc)

**Current sso-jwt entry point:**
```rust
pub fn platform_storage(biometric: bool) -> Result<Box<dyn SecureStorage>>
```

### sshenc-se (partial replacement — signing variant)

**Files affected (not deleted, but simplified):**
- `sshenc/crates/sshenc-se/src/macos.rs` — `SecureEnclaveBackend` implementing `KeyBackend`
- `sshenc/crates/sshenc-se/src/windows.rs` — `TpmBackend` implementing `KeyBackend`
- `sshenc/crates/sshenc-se/src/linux.rs` — `LinuxBackend` implementing `KeyBackend`
- `sshenc/crates/sshenc-se/src/backend.rs` — `KeyBackend` trait definition
- `sshenc/crates/sshenc-se/src/lib.rs` — Platform-conditional exports

**Current sshenc KeyBackend trait:**
```rust
pub trait KeyBackend: Send + Sync {
    fn generate(&self, opts: &KeyGenOptions) -> Result<KeyInfo>;
    fn list(&self) -> Result<Vec<KeyInfo>>;
    fn get(&self, label: &str) -> Result<KeyInfo>;
    fn delete(&self, label: &str) -> Result<()>;
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;
    fn is_available(&self) -> bool;
}
```

sshenc's `KeyBackend` has a richer interface than awsenc/sso-jwt's `SecureStorage` because signing keys need list/get/metadata operations. The shared crate provides the platform detection and initialization logic; sshenc still defines its own `KeyBackend` trait but delegates platform setup to the shared crate.

---

## Detailed Duplication Analysis

### Pattern A: macOS Key Initialization (identical in awsenc + sso-jwt)

awsenc `macos.rs:37-65` vs sso-jwt `macos.rs:28-53`:

```rust
// Both apps do exactly this:
let encryptor = SecureEnclaveEncryptor::new(APP_NAME);
if !encryptor.is_available() {
    return Err(/* not available error */);
}
if encryptor.public_key(KEY_LABEL).is_err() {
    let policy = if biometric {
        AccessPolicy::BiometricOnly
    } else {
        AccessPolicy::None
    };
    encryptor.generate(KEY_LABEL, KeyType::Encryption, policy)?;
}
```

Only differences: APP_NAME constant ("awsenc" vs "sso-jwt"), error type (`StorageError` vs `anyhow`), whether biometric flag is stored in struct.

### Pattern B: Linux Software Key Initialization (identical in awsenc + sso-jwt)

awsenc `linux.rs:40-57` vs sso-jwt `linux.rs:32-49`:

```rust
// Both apps do exactly this:
let encryptor = SoftwareEncryptor::new(APP_NAME);
if encryptor.public_key(KEY_LABEL).is_err() {
    encryptor.generate(KEY_LABEL, KeyType::Encryption, AccessPolicy::None)?;
}
```

sso-jwt additionally warns about biometric having no effect. awsenc silently ignores it (doesn't even accept the parameter on Linux).

### Pattern C: WSL Bridge Discovery (identical in awsenc + sso-jwt)

awsenc `wsl.rs:84-100` vs sso-jwt `wsl.rs:75-90`:

```rust
// Both apps do exactly this:
fn find_bridge_executable() -> Option<PathBuf> {
    if let Some(path) = enclaveapp_bridge::find_bridge(APP_NAME) {
        return Some(path);
    }
    for path_str in LEGACY_BRIDGE_PATHS {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}
```

Only difference: APP_NAME and LEGACY_BRIDGE_PATHS constants.

### Pattern D: Encrypt/Decrypt Wrappers (identical structure)

Both apps wrap the same libenclaveapp calls with error conversion:
```rust
fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
    self.encryptor.encrypt(KEY_LABEL, plaintext).map_err(|e| /* convert */)
}
fn decrypt(&self, ciphertext: &[u8]) -> Result</* Vec<u8> or Zeroizing<Vec<u8>> */> {
    let pt = self.encryptor.decrypt(KEY_LABEL, ciphertext).map_err(|e| /* convert */)?;
    Ok(/* optionally wrap in Zeroizing */)
}
```

### Pattern E: Platform Dispatcher (identical structure)

awsenc `lib.rs:53-83` vs sso-jwt `mod.rs:37-66`:

```rust
// Both apps do exactly this:
pub fn create_storage(biometric: bool) -> Result<Box<dyn SecureStorage>> {
    #[cfg(target_os = "macos")]
    { return Ok(Box::new(MacosStorage::new(biometric)?)); }
    #[cfg(target_os = "linux")]
    {
        if wsl::is_wsl() {
            return Ok(Box::new(WslStorage::new(biometric)?));
        }
        return Ok(Box::new(LinuxStorage::new(/* biometric */)?));
    }
    #[cfg(target_os = "windows")]
    { /* awsenc: NotAvailable, sso-jwt: TpmStorage */ }
}
```

### Pattern F: sshenc Backend Init (structurally similar)

sshenc `macos.rs:84-89` uses the same biometric→policy mapping but for signing:

```rust
let policy = if opts.requires_user_presence {
    AccessPolicy::Any  // NOTE: maps to Any, not BiometricOnly
} else {
    AccessPolicy::None
};
self.signer.generate(label_str, KeyType::Signing, policy)?;
```

---

## Design

### New Crate: `crates/enclaveapp-app-storage`

Added to the libenclaveapp workspace. Provides the shared platform detection, key initialization, and encrypt/decrypt/sign wrapping that all consuming apps need.

#### Crate Structure

```
crates/enclaveapp-app-storage/
  Cargo.toml
  src/
    lib.rs          — Public API, re-exports, EncryptionStorage trait
    error.rs        — StorageError enum
    platform.rs     — Platform detection, BackendKind enum, WSL bridge discovery
    encryption.rs   — AppEncryptionStorage struct (platform dispatch, key init, encrypt/decrypt)
    signing.rs      — AppSigningBackend struct (platform dispatch, exposes EnclaveSigner)
    mock.rs         — MockEncryptionStorage (feature-gated behind "mock")
```

The platform-specific code is NOT in separate files per platform. Instead, `encryption.rs` and `signing.rs` use `#[cfg(target_os = "...")]` blocks internally, the same pattern used by `enclaveapp-core`. This avoids a proliferation of tiny files — the per-platform logic is ~20 lines each (instantiate backend, check availability, generate key if needed).

#### Public API

```rust
// crates/enclaveapp-app-storage/src/lib.rs

/// Error type for storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("hardware security module not available")]
    NotAvailable,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("key initialization failed: {0}")]
    KeyInitFailed(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key policy mismatch: {0}")]
    PolicyMismatch(String),
    #[error("platform error: {0}")]
    PlatformError(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Which hardware/software backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    SecureEnclave,
    Tpm,
    TpmBridge,       // WSL → Windows TPM
    Software,
}

/// Configuration for initializing application storage.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Application name (e.g., "awsenc", "sso-jwt", "sshenc").
    /// Used to namespace keys and locate config directories.
    pub app_name: String,
    /// Key label (e.g., "cache-key", "default").
    pub key_label: String,
    /// Access policy for key operations.
    pub access_policy: AccessPolicy,
    /// Extra WSL bridge paths beyond the auto-derived defaults.
    /// The standard discovery (`enclaveapp_bridge::find_bridge(app_name)`)
    /// and auto-derived paths (`/mnt/c/Program Files/{app_name}/{app_name}-tpm-bridge.exe`,
    /// `/mnt/c/ProgramData/{app_name}/{app_name}-tpm-bridge.exe`) are tried first.
    /// These are additional fallbacks for app-specific legacy locations.
    pub extra_bridge_paths: Vec<String>,
}

/// High-level encryption storage for consuming applications.
///
/// Handles platform detection, backend initialization, key lifecycle, and
/// encrypt/decrypt operations. This replaces the per-app secure_storage
/// modules in awsenc and sso-jwt.
pub struct AppEncryptionStorage { /* ... */ }

impl AppEncryptionStorage {
    /// Initialize encryption storage with automatic platform detection.
    ///
    /// 1. Detects the current platform (macOS/Windows/Linux/WSL)
    /// 2. Initializes the appropriate libenclaveapp backend
    /// 3. Checks if a key with the given label exists
    /// 4. If not, generates a new key with the configured access policy
    /// 5. If yes, checks that the existing key's policy matches the config
    ///    (see "Key Policy Mismatch Handling" below)
    pub fn init(config: StorageConfig) -> Result<Self>;

    /// Encrypt plaintext using the hardware-bound key's public key.
    /// No biometric prompt — encryption uses only the public key.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the hardware-bound private key.
    /// If the key was created with biometric policy, this triggers
    /// Touch ID / Windows Hello as enforced by the OS.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Delete the hardware-bound key and all associated files.
    pub fn destroy(&self) -> Result<()>;

    /// Which backend is in use.
    pub fn backend_kind(&self) -> BackendKind;

    /// Human-readable backend name (e.g., "Secure Enclave (biometric)").
    pub fn backend_name(&self) -> &'static str;

    /// Whether the backend is available (always true after successful init).
    pub fn is_available(&self) -> bool;
}

/// High-level signing backend for sshenc.
///
/// Thin wrapper that handles platform detection and initialization.
/// Exposes the underlying `EnclaveSigner` and `EnclaveKeyManager` traits
/// so sshenc can build its richer `KeyBackend` on top.
pub struct AppSigningBackend { /* ... */ }

impl AppSigningBackend {
    /// Initialize signing backend with automatic platform detection.
    /// Does NOT generate keys — sshenc manages key lifecycle itself.
    pub fn init(config: StorageConfig) -> Result<Self>;

    /// Access the underlying platform signer for sign operations.
    pub fn signer(&self) -> &dyn EnclaveSigner;

    /// Access the underlying key manager for generate/list/delete.
    pub fn key_manager(&self) -> &dyn EnclaveKeyManager;

    /// Which backend is in use.
    pub fn backend_kind(&self) -> BackendKind;
}

/// Create encryption storage with automatic platform detection.
/// Convenience function wrapping AppEncryptionStorage::init().
pub fn create_encryption_storage(config: StorageConfig) -> Result<Box<dyn EncryptionStorage>>;
```

#### Trait Definition

The shared crate defines one trait for encryption storage (needed for dynamic dispatch with mock backend):

```rust
/// Encryption storage trait. Object-safe for dynamic dispatch.
pub trait EncryptionStorage: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn destroy(&self) -> Result<()>;
    fn is_available(&self) -> bool;
    fn backend_name(&self) -> &'static str;
    fn backend_kind(&self) -> BackendKind;
}
```

No `SigningBackend` trait is needed — `AppSigningBackend` exposes the underlying `EnclaveSigner` and `EnclaveKeyManager` traits from `enclaveapp-core` directly. sshenc builds its own `KeyBackend` on top.

#### Mock Backend

Feature-gated behind `mock`:

```rust
// Feature: mock
pub mod mock {
    /// Mock encryption storage for testing without hardware.
    /// Uses AES-256-GCM with a random in-memory key.
    pub struct MockEncryptionStorage { /* ... */ }

    impl MockEncryptionStorage {
        pub fn new() -> Self;
    }

    impl EncryptionStorage for MockEncryptionStorage { /* ... */ }
}
```

This replaces both `awsenc-secure-storage`'s `MockStorage` (AES-GCM based, `awsenc-secure-storage/src/mock.rs`) and `sso-jwt`'s `MockStorage` (XOR based, `sso-jwt-lib/src/secure_storage/mod.rs` test module). The AES-GCM version is preferable for realistic testing.

sshenc's mock (`sshenc-test-support`) is unaffected — it mocks the `KeyBackend` trait, not the storage layer.

### Cargo.toml

```toml
[package]
name = "enclaveapp-app-storage"
version.workspace = true
edition.workspace = true
rust-version.workspace = true

[lints]
workspace = true

[features]
default = []
mock = ["aes-gcm", "rand"]
# Feature flags forward to platform crates. Consumer apps enable what they need:
#   awsenc:  features = ["encryption"]
#   sso-jwt: features = ["encryption"]
#   sshenc:  features = ["signing"]
signing = ["enclaveapp-apple/signing", "enclaveapp-windows/signing", "enclaveapp-software/signing"]
encryption = ["enclaveapp-apple/encryption", "enclaveapp-windows/encryption", "enclaveapp-software/encryption"]

[dependencies]
enclaveapp-core = { workspace = true }
thiserror = { workspace = true }
tracing = "0.1"

# Mock backend (feature-gated)
aes-gcm = { workspace = true, optional = true }
rand = { workspace = true, optional = true }

[target.'cfg(target_os = "macos")'.dependencies]
enclaveapp-apple = { workspace = true }

[target.'cfg(target_os = "windows")'.dependencies]
enclaveapp-windows = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
enclaveapp-software = { workspace = true }
enclaveapp-bridge = { workspace = true }
enclaveapp-wsl = { workspace = true }
enclaveapp-linux-tpm = { workspace = true }
```

The `signing` and `encryption` features forward to the platform crates. This means consumer apps don't need to depend on the individual platform crates at all — just `enclaveapp-app-storage` with the right feature.

---

## Key Policy Mismatch Handling

When `AppEncryptionStorage::init()` or `AppSigningBackend::init()` runs, it may find an existing key whose `access_policy` (stored in `.meta` file) differs from the requested policy in `StorageConfig`.

### Scenarios

| Existing Key Policy | Requested Policy | Action |
|---------------------|-----------------|--------|
| `None` | `None` | Use existing key |
| `BiometricOnly` | `BiometricOnly` | Use existing key |
| `None` | `BiometricOnly` | **Mismatch** — must re-generate |
| `BiometricOnly` | `None` | **Mismatch** — must re-generate |
| `Any` | `BiometricOnly` | **Mismatch** — must re-generate |

### Behavior on Mismatch

**For encryption keys** (awsenc, sso-jwt): The key is used for caching temporary data (AWS credentials, JWTs). Re-generating the key means cached data becomes unreadable, which simply forces a re-authentication. This is acceptable.

On mismatch:
1. Log a warning: "Key policy mismatch: existing key has policy X, requested policy Y. Re-generating key."
2. Delete the old key via `delete_key(label)`
3. Generate a new key with the requested policy
4. Cached `.enc` files will fail to decrypt — the consuming app already handles this (falls back to re-auth)

**For signing keys** (sshenc): Re-generating means a new public key, requiring updates to SSH `authorized_keys` files on servers. This is destructive. The shared crate does NOT automatically re-generate signing keys. Instead:
1. Return `Err(StorageError::PolicyMismatch(...))` with a descriptive message
2. sshenc's CLI handles this by prompting the user or requiring a `--force` flag

### Implementation

```rust
fn check_policy_match(
    meta: &KeyMeta,
    requested: AccessPolicy,
    key_type: KeyType,
) -> PolicyAction {
    if meta.access_policy == requested {
        return PolicyAction::UseExisting;
    }
    match key_type {
        KeyType::Encryption => PolicyAction::Regenerate,
        KeyType::Signing => PolicyAction::Error,
    }
}
```

---

## CLI Harmonization

### Current State

| App | Flag | Maps to |
|-----|------|---------|
| sshenc | `--require-user-presence` | `AccessPolicy::Any` |
| sshenc | `--auth-policy <none\|any\|biometric\|password>` | Exact policy |
| awsenc | `--biometric` | `AccessPolicy::BiometricOnly` |
| sso-jwt | `--biometric` | `AccessPolicy::BiometricOnly` |

### Proposed State

All three apps should support the same flags:

| Flag | Maps to | Meaning |
|------|---------|---------|
| `--biometric` | `AccessPolicy::BiometricOnly` | Require biometric (Touch ID / fingerprint) |
| `--user-presence` | `AccessPolicy::Any` | Require any user auth (biometric or password) |
| `--auth-policy <none\|any\|biometric\|password>` | Exact policy | Fine-grained control |
| (none) | `AccessPolicy::None` | No user interaction required |

For backward compatibility:
- sshenc's `--require-user-presence` becomes an alias for `--user-presence`
- awsenc and sso-jwt's `--biometric` continues to work as-is
- Config files: `biometric = true` maps to `AccessPolicy::BiometricOnly` (unchanged)
- Config files: new `auth_policy = "any"` option for fine-grained control

The `StorageConfig` struct accepts `AccessPolicy` directly. The consuming app's CLI layer maps flags to `AccessPolicy`:

```rust
// In each app's CLI argument parsing:
let policy = if args.biometric {
    AccessPolicy::BiometricOnly
} else if args.user_presence {
    AccessPolicy::Any
} else if let Some(p) = args.auth_policy {
    p.parse()?  // "none" | "any" | "biometric" | "password"
} else {
    AccessPolicy::None
};
```

---

## Migration Plan

### Phase 1: Create `enclaveapp-app-storage` crate

1. Add `crates/enclaveapp-app-storage/` to the libenclaveapp workspace
2. Add to `Cargo.toml` workspace members and `[workspace.dependencies]`
3. Implement `error.rs`: `StorageError` enum
4. Implement `platform.rs`: `BackendKind` enum, `find_bridge_executable(app_name, extra_paths)` helper
5. Implement `lib.rs`: `StorageConfig` struct, `EncryptionStorage` trait, re-exports from enclaveapp-core
6. Implement `encryption.rs`: `AppEncryptionStorage` with `#[cfg]` platform dispatch
   - Extract the shared pattern from `awsenc-secure-storage/src/macos.rs` + `sso-jwt/.../macos.rs` (macOS)
   - Extract from `sso-jwt/.../windows.rs` (Windows — awsenc doesn't have this)
   - Extract from both apps' `linux.rs` (Linux software)
   - Extract from both apps' `wsl.rs` (WSL bridge)
   - Add policy mismatch detection (read `.meta`, compare `access_policy`, regenerate if encryption key)
7. Implement `signing.rs`: `AppSigningBackend` with `#[cfg]` platform dispatch
   - Extract platform detection from `sshenc-se/src/lib.rs` + `macos.rs`/`windows.rs`/`linux.rs`
   - Expose `signer()` and `key_manager()` accessors
   - No key generation in init (sshenc manages its own key lifecycle)
8. Implement `mock.rs`: `MockEncryptionStorage` using AES-256-GCM with random key
9. Add tests: `StorageConfig` validation, policy mismatch detection, mock roundtrip
10. Run `cargo test`, `cargo clippy`, `cargo fmt` on libenclaveapp workspace
11. Run consumer app tests to verify no breakage (the new crate doesn't affect existing code yet)

### Phase 2: Migrate awsenc

1. Replace `awsenc-secure-storage` crate dependency with `enclaveapp-app-storage`
2. Delete `awsenc/awsenc-secure-storage/` entirely
3. Update `awsenc/Cargo.toml` workspace members
4. Update `awsenc-cli/src/auth.rs` and `awsenc-cli/src/serve.rs`:
   - Replace `create_platform_storage(biometric)` with:
     ```rust
     AppEncryptionStorage::init(StorageConfig {
         app_name: "awsenc".into(),
         key_label: "cache-key".into(),
         access_policy: if biometric { AccessPolicy::BiometricOnly } else { AccessPolicy::None },
         extra_bridge_paths: vec![],  // auto-derived paths are sufficient
     })?
     ```
   - Replace `storage.encrypt(pt)?` with same (interface unchanged)
   - Replace `storage.decrypt(ct)?` with same (interface unchanged)
5. Update `awsenc-cli/src/cli.rs` to add `--user-presence` and `--auth-policy` flags
6. Update mock usage in tests: replace `awsenc-secure-storage/mock` with `enclaveapp-app-storage/mock`
7. Run `cargo test --workspace --features enclaveapp-app-storage/mock`, `cargo clippy`, `cargo fmt`
8. Verify `awsenc auth` and `awsenc serve` work end-to-end on macOS

### Phase 3: Migrate sso-jwt

1. Replace `secure_storage` module in `sso-jwt-lib` with `enclaveapp-app-storage` dependency
2. Delete `sso-jwt/sso-jwt-lib/src/secure_storage/` entirely
3. Update `sso-jwt-lib/Cargo.toml`:
   - Remove per-platform `enclaveapp-*` dependencies (now transitive through `enclaveapp-app-storage`)
   - Add `enclaveapp-app-storage = { workspace = true, features = ["encryption"] }`
4. Update `sso-jwt-lib/src/lib.rs` and `sso-jwt-lib/src/cache.rs`:
   - Replace `platform_storage(biometric)` with `AppEncryptionStorage::init(...)`
   - Wrap decrypt returns in `Zeroizing::new()` at call sites
5. Update `sso-jwt/src/cli.rs` to add `--user-presence` and `--auth-policy` flags
6. Update mock usage in tests
7. Run `cargo test --workspace`, `cargo clippy`, `cargo fmt`
8. Verify `sso-jwt` works end-to-end on macOS

### Phase 4: Migrate sshenc

sshenc's migration is lighter than awsenc/sso-jwt because it keeps its own `KeyBackend` trait. The shared crate only replaces the platform detection and backend initialization logic.

1. Add `enclaveapp-app-storage` dependency to `sshenc-se/Cargo.toml` with `signing` feature
2. Remove direct dependencies on `enclaveapp-apple`, `enclaveapp-windows`, `enclaveapp-software`, `enclaveapp-linux-tpm` from `sshenc-se/Cargo.toml` (now transitive through `enclaveapp-app-storage`)
3. Refactor `sshenc-se/src/macos.rs`:
   - Replace direct `SecureEnclaveSigner::with_keys_dir("sshenc", sshenc_keys_dir())` with `AppSigningBackend::init(config)`
   - `KeyBackend::sign()` delegates to `self.backend.signer().sign(label, data)`
   - `KeyBackend::generate()` calls `self.backend.key_manager().generate(label, KeyType::Signing, policy)` then does SSH-specific work (pub file writing, fingerprinting, metadata)
   - `KeyBackend::list()` calls `self.backend.key_manager().list_keys()` then loads metadata for each
4. Collapse `sshenc-se/src/macos.rs`, `windows.rs`, `linux.rs` into a single impl that uses `AppSigningBackend` (since platform dispatch is now handled by the shared crate)
5. Update `sshenc-cli` to add `--biometric` flag (maps to `AccessPolicy::BiometricOnly`)
6. Keep existing `--auth-policy` and `--require-user-presence` as-is for backward compatibility
7. Run all tests, clippy, fmt

### Phase 5: Verify and clean up

1. Verify biometric works on real macOS hardware across all three apps
2. Verify policy mismatch detection and key re-generation for encryption keys
3. Verify policy mismatch error for signing keys
4. Remove any dead code in libenclaveapp (nothing expected, but check)
5. Update CLAUDE.md files in all four repos

---

## File-by-File Reference

### Files created (in libenclaveapp)

| File | Purpose |
|------|---------|
| `crates/enclaveapp-app-storage/Cargo.toml` | Crate manifest with feature-forwarding |
| `crates/enclaveapp-app-storage/src/lib.rs` | Public API, re-exports from enclaveapp-core, `EncryptionStorage` trait |
| `crates/enclaveapp-app-storage/src/error.rs` | `StorageError` enum |
| `crates/enclaveapp-app-storage/src/platform.rs` | `BackendKind` enum, WSL bridge discovery helper |
| `crates/enclaveapp-app-storage/src/encryption.rs` | `AppEncryptionStorage` struct with `#[cfg]` platform dispatch |
| `crates/enclaveapp-app-storage/src/signing.rs` | `AppSigningBackend` struct with `#[cfg]` platform dispatch |
| `crates/enclaveapp-app-storage/src/mock.rs` | `MockEncryptionStorage` (feature-gated behind `mock`) |

### Files deleted (in awsenc)

| File | Current LOC | What it does |
|------|-------------|-------------|
| `awsenc-secure-storage/src/lib.rs` | 123 | Trait, error enum, platform dispatcher |
| `awsenc-secure-storage/src/macos.rs` | 127 | SE encryption wrapper |
| `awsenc-secure-storage/src/linux.rs` | 81 | Software encryption wrapper |
| `awsenc-secure-storage/src/wsl.rs` | 121 | WSL bridge wrapper |
| `awsenc-secure-storage/src/mock.rs` | 231 | AES-GCM mock |
| `awsenc-secure-storage/Cargo.toml` | 35 | Crate manifest |

### Files deleted (in sso-jwt)

| File | Current LOC | What it does |
|------|-------------|-------------|
| `sso-jwt-lib/src/secure_storage/mod.rs` | 163 | Trait, mock, platform dispatcher |
| `sso-jwt-lib/src/secure_storage/macos.rs` | 76 | SE encryption wrapper |
| `sso-jwt-lib/src/secure_storage/windows.rs` | 114 | TPM encryption wrapper |
| `sso-jwt-lib/src/secure_storage/linux.rs` | 73 | Software encryption wrapper |
| `sso-jwt-lib/src/secure_storage/wsl.rs` | 131 | WSL bridge wrapper |

### Files modified (in awsenc)

| File | Change |
|------|--------|
| `awsenc/Cargo.toml` | Remove `awsenc-secure-storage` member, add `enclaveapp-app-storage` workspace dep |
| `awsenc-cli/Cargo.toml` | Replace `awsenc-secure-storage` dep with `enclaveapp-app-storage` |
| `awsenc-cli/src/auth.rs` | Use `AppEncryptionStorage::init()` instead of `create_platform_storage()` |
| `awsenc-cli/src/serve.rs` | Same |
| `awsenc-cli/src/cli.rs` | Add `--user-presence`, `--auth-policy` flags |
| `awsenc-core/src/config.rs` | Add `auth_policy` config field alongside existing `biometric` |

### Files modified (in sso-jwt)

| File | Change |
|------|--------|
| `sso-jwt/Cargo.toml` | Add `enclaveapp-app-storage` workspace dep |
| `sso-jwt-lib/Cargo.toml` | Replace per-platform enclaveapp deps with `enclaveapp-app-storage` |
| `sso-jwt-lib/src/lib.rs` | Use `AppEncryptionStorage` instead of `platform_storage()` |
| `sso-jwt-lib/src/cache.rs` | Same, wrap decrypt in `Zeroizing::new()` |
| `sso-jwt/src/cli.rs` | Add `--user-presence`, `--auth-policy` flags |
| `sso-jwt-lib/src/config.rs` | Add `auth_policy` config field alongside existing `biometric` |

### Files modified (in sshenc)

| File | Change |
|------|--------|
| `sshenc/Cargo.toml` | Add `enclaveapp-app-storage` workspace dep, remove direct platform crate deps |
| `sshenc-se/Cargo.toml` | Replace `enclaveapp-apple`/`windows`/`software`/`linux-tpm` deps with `enclaveapp-app-storage` |
| `sshenc-se/src/lib.rs` | Remove per-platform conditional exports, single `Backend` using `AppSigningBackend` |
| `sshenc-se/src/macos.rs` | Delete (platform dispatch moved to shared crate) |
| `sshenc-se/src/windows.rs` | Delete |
| `sshenc-se/src/linux.rs` | Delete |
| `sshenc-se/src/backend.rs` | `KeyBackend` impl wraps `AppSigningBackend` + SSH-specific logic |
| `sshenc-cli/src/commands.rs` | Add `--biometric` flag alongside existing `--auth-policy` |

### Files modified (in libenclaveapp)

| File | Change |
|------|--------|
| `Cargo.toml` | Add `crates/enclaveapp-app-storage` to workspace members and deps |
| `CLAUDE.md` | Add `enclaveapp-app-storage` to architecture section |

---

## Testing Strategy

### Unit Tests (in enclaveapp-app-storage)

- `StorageConfig` validation (empty app_name, empty key_label rejected)
- Policy mismatch detection: `check_policy_match()` for all `AccessPolicy` × `KeyType` combinations
- `BackendKind` display/debug
- `StorageError` display formatting
- WSL bridge discovery with `find_bridge_executable()` (returns None on non-WSL, doesn't panic)
- Mock backend: encrypt → decrypt roundtrip, different ciphertexts for same plaintext, empty plaintext, tampered ciphertext fails, wrong-key decryption fails

### Integration Tests (require hardware, gated behind env vars)

Gated behind `ENCLAVEAPP_TEST_HARDWARE=1`:

- macOS: `AppEncryptionStorage::init()` with `AccessPolicy::None` → encrypt → decrypt roundtrip
- macOS: `AppEncryptionStorage::init()` with `AccessPolicy::BiometricOnly` → key metadata shows BiometricOnly
- macOS: Policy mismatch → key re-generated, old ciphertext fails to decrypt
- macOS: `AppSigningBackend::init()` → `signer().sign()` returns valid DER
- Same patterns for Windows (gated behind `ENCLAVEAPP_TEST_TPM=1`)

### Consumer App Tests (post-migration)

- awsenc: `cargo test --workspace --features enclaveapp-app-storage/mock` — replaces `--features awsenc-secure-storage/mock`
- sso-jwt: `cargo test --workspace` — mock is `#[cfg(test)]` inline, uses `MockEncryptionStorage`
- sshenc: `cargo test --workspace` — unchanged, `sshenc-test-support` mocks `KeyBackend` not storage

