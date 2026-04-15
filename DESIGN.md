# libenclaveapp Design Document

## Goal

Provide a shared Rust substrate for hardware-backed key management so derived applications do not each reimplement:

- platform detection
- Secure Enclave / TPM bootstrap
- key lifecycle and metadata storage
- WSL bridge discovery
- software fallback behavior

The current workspace supports four active consumers:

| Application | Primary use |
|---|---|
| `sshenc` | signing |
| `awsenc` | encrypted credential caching |
| `sso-jwt` | encrypted token caching |
| `npmenc` | encrypted secret storage through an adapter layer |

## Workspace layout

```
libenclaveapp/
  crates/
    enclaveapp-core/          Traits, types, metadata, shared utilities
    enclaveapp-app-storage/   App-level bootstrap for encryption/signing
    enclaveapp-apple/         macOS Secure Enclave backend
    enclaveapp-windows/       Windows TPM backend
    enclaveapp-linux-tpm/     Linux TPM backend
    enclaveapp-software/      Software fallback backend
    enclaveapp-wsl/           WSL detection and shell/profile helpers
    enclaveapp-bridge/        JSON-RPC bridge protocol + WSL client
    enclaveapp-test-support/  Mock backend for tests
```

## Layering

### `enclaveapp-core`

Defines the durable contracts:

- `EnclaveKeyManager`
- `EnclaveSigner`
- `EnclaveEncryptor`
- `KeyType`
- `AccessPolicy`
- metadata and config helpers

This crate has no platform FFI.

### `enclaveapp-app-storage`

This is the application-facing integration layer. It wraps platform selection and key initialization so application code can say:

- create encryption storage for app `awsenc`
- create signing backend for app `sshenc`

It also centralizes WSL bridge lookup, access-policy handling, and app-specific key names.

### Platform backends

- `enclaveapp-apple`: Secure Enclave via CryptoKit Swift bridge
- `enclaveapp-windows`: TPM 2.0 via CNG
- `enclaveapp-linux-tpm`: TPM 2.0 via `tss-esapi`
- `enclaveapp-software`: software fallback for unsupported or non-hardware environments

### WSL support

- `enclaveapp-bridge` defines the JSON-RPC bridge client and protocol
- `enclaveapp-wsl` handles WSL detection, distro enumeration, shell/profile changes, and install helpers

## Access policy model

All backends share the same policy vocabulary:

- `None`
- `Any`
- `BiometricOnly`
- `PasswordOnly`

Applications decide which policy to request. Platform backends map that policy to the best native behavior available.

## ECIES format

Encryption backends use the shared ciphertext format:

```
[0x01 version] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
```

This keeps ciphertext portable across the derived applications that use encryption storage.

## Platform support

| Platform | Signing | Encryption | Notes |
|---|---|---|---|
| macOS | Yes | Yes | Secure Enclave |
| Windows | Yes | Yes | TPM 2.0 / CNG |
| Linux with TPM | Yes | Yes | TPM 2.0 / `tss-esapi` |
| Linux without TPM | Yes | Yes | software fallback |
| WSL | consumer-specific | Yes | Windows host bridge for encryption workloads |

For `sshenc`, WSL signing is handled by the ssh agent bridge path rather than the JSON-RPC encryption bridge.

## Application integration types

Every enclave app is classified by how it delivers secrets to the target application. The `enclaveapp-app-adapter` crate defines three integration types, listed from most secure to least secure:

### Type 1: HelperTool

The target application has native support for auth plugins, credential helpers, or agents. Secrets never leave the enclave app's process boundary — they are returned on demand via a protocol (SSH agent, `credential_process`, etc.). This is the most secure integration because secrets are never written to disk or exposed in environment variables.

### Type 2: EnvInterpolation

The target application reads a config file that supports environment variable interpolation (`${ENV_VAR}`). The enclave app writes a config with placeholders and invokes the target with secret env vars set via `execve()`. Secrets exist briefly as environment variables but never touch disk in plaintext. The `execve()` boundary is critical — the env vars must not be set in a shell where they would be visible in shell history or to child processes beyond the target.

### Type 3: TempMaterializedConfig

The target application can only read a static config file with no env var support. The enclave app writes secrets to a temp file with restricted permissions (0o600 on Unix), invokes the target with a config path override (e.g. `--config /tmp/xxx/app.conf`), and deletes the file after the process exits. This is the least secure integration because secrets briefly exist on disk, but the restricted permissions and automatic cleanup mitigate the risk.

The adapter selects the least-secret-exposing integration automatically: Type 1 > Type 2 > Type 3.

### Consumer mapping

| Consumer | Integration Type | Mechanism |
|---|---|---|
| `sshenc` | Type 1 (HelperTool) | SSH agent protocol; keys used in-process for signing |
| `awsenc` | Type 1 (HelperTool) | `credential_process` directive in `~/.aws/config` |
| `sso-jwt` | Credential source | Provides JWTs for Type 1 or Type 2 apps to consume |
| `npmenc` | Type 2 (EnvInterpolation) | `.npmrc` with `${NPM_TOKEN}` placeholders |
