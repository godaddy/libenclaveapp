# enclaveapp-core

Platform-agnostic types, traits, and utilities for hardware-backed key management.

This crate contains no FFI or platform-specific code. It defines the abstractions that platform backends implement and the shared infrastructure they use.

## Traits

- **`EnclaveKeyManager`** -- key lifecycle: generate, list, get, delete, availability check
- **`EnclaveSigner`** -- ECDSA P-256 signing (extends `EnclaveKeyManager`)
- **`EnclaveEncryptor`** -- ECIES encryption/decryption (extends `EnclaveKeyManager`)

## Types

- **`KeyType`** -- `Signing` or `Encryption`
- **`AccessPolicy`** -- `None`, `Any`, `BiometricOnly`, `PasswordOnly`
- **`KeyMeta`** -- JSON-serializable metadata with app-specific extension fields

## Utilities

- **Metadata** -- `save_meta`/`load_meta`, `save_pub_key`/`load_pub_key`, `list_labels`, `delete_key_files`, `rename_key_files`
- **File I/O** -- `atomic_write` (temp file + rename), `DirLock` (flock-based), `ensure_dir` (with 0700 permissions)
- **Config** -- `load_toml`/`save_toml` with silent defaults for missing files
- **Validation** -- `validate_label` (alphanumeric + hyphens/underscores, max 64 chars), `validate_p256_point` (65-byte SEC1)
- **Platform** -- `is_macos()`, `is_windows()`, `is_wsl()`, `hardware_name()`

## Key storage layout

```
~/.config/<app_name>/keys/
  <label>.meta       JSON metadata
  <label>.pub        65-byte SEC1 public key (cached)
  <label>.handle     CryptoKit dataRepresentation (macOS signing keys only)
```
