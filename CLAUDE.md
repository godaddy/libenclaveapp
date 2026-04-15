# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`libenclaveapp` is a shared Rust library for hardware-backed key management across macOS (Secure Enclave via CryptoKit), Windows (TPM 2.0 via CNG), and Linux (software fallback). It provides signing (ECDSA P-256) and encryption (ECIES via ECDH P-256 + AES-GCM) behind feature flags, plus WSL integration and a TPM bridge for WSL→Windows communication.

Three applications consume this library:
- **sshenc** — SSH key management (signing)
- **awsenc** — AWS credential caching (encryption)
- **sso-jwt** — SSO JWT caching (encryption)

## Build & Development

Rust workspace. Requires Rust 1.75+. macOS builds need Xcode (for swiftc).

```bash
# Build with all features (macOS)
cargo build --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-software/signing,enclaveapp-software/encryption

# Build with all features (Windows)
cargo build --workspace --features enclaveapp-windows/signing,enclaveapp-windows/encryption,enclaveapp-software/signing,enclaveapp-software/encryption

# Build with all features (Linux)
cargo build --workspace --features enclaveapp-software/signing,enclaveapp-software/encryption

# Test everything
cargo test --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-software/signing,enclaveapp-software/encryption

# Lint
cargo clippy --workspace --all-targets --features enclaveapp-apple/signing,enclaveapp-apple/encryption,enclaveapp-software/signing,enclaveapp-software/encryption -- -D warnings

# Format
cargo fmt --all -- --check
```

## Architecture

Rust workspace under `crates/`:

- **enclaveapp-core** — Platform-agnostic types, traits (`EnclaveKeyManager`, `EnclaveSigner`, `EnclaveEncryptor`), metadata (atomic writes, dir locking, JSON key metadata), config helpers (TOML load/save), error types, platform detection. No FFI.
- **enclaveapp-apple** — macOS Secure Enclave via CryptoKit Swift bridge. Unified bridge supporting both P256.Signing (feature `signing`) and P256.KeyAgreement (feature `encryption`). ECIES uses ephemeral ECDH + X9.63 KDF + AES-GCM.
- **enclaveapp-windows** — Windows TPM 2.0 via CNG NCrypt/BCrypt. ECDSA signing (feature `signing`) and ECIES encryption (feature `encryption`). Shared provider/key/export modules. P1363↔DER conversion in cross-platform `convert` module.
- **enclaveapp-wsl** — WSL detection (`is_wsl`, `detect_distros`), managed shell config block injection/removal for `.bashrc`/`.zshrc`, syntax validation. Parameterized by app name.
- **enclaveapp-bridge** — JSON-RPC over stdin/stdout TPM bridge. Client side (WSL discovers and calls Windows bridge binary) and protocol types. Server implementation lives in consuming apps.
- **enclaveapp-software** — Software-only P-256 backend for Linux (feature `signing` and `encryption`). Uses `p256` crate for real ECDSA/ECDH crypto and `aes-gcm` for symmetric encryption. Private keys stored as files on disk (not hardware-backed). Same ECIES wire format as hardware backends.
- **enclaveapp-app-storage** — High-level shared application storage. Automatic platform detection, key initialization, policy mismatch handling, and encrypt/decrypt/sign wrapping. Used by all three consuming apps (awsenc, sso-jwt, sshenc) to eliminate duplicated secure storage code. Includes `MockEncryptionStorage` behind the `mock` feature.
- **enclaveapp-app-adapter** — Generic secret delivery substrate. BindingStore/SecretStore for credential management, AppSpec with 3 integration types, program resolver, process launcher, config block injection, temp config lifecycle. Used by npmenc; available for adoption by other apps.
- **enclaveapp-tpm-bridge** — Shared JSON-RPC TPM bridge server. Parameterized by app_name/key_label.
- **enclaveapp-cache** — Shared binary cache format with configurable magic bytes and length-prefixed blobs.
- **enclaveapp-build-support** — Shared build.rs helper for Windows PE resource compilation.
- **enclaveapp-test-support** — `MockKeyBackend` implementing all three traits with deterministic in-memory operations. XOR-based mock crypto for testing control flow without hardware.

### Key Patterns

- `EnclaveKeyManager` trait is the base — `EnclaveSigner` and `EnclaveEncryptor` extend it.
- Feature flags (`signing`, `encryption`) control which trait implementations are compiled.
- The Swift bridge compiles all functions regardless of features; feature gates are Rust-side only.
- ECIES ciphertext format: `[0x01 version][65-byte ephemeral pubkey][12-byte nonce][ciphertext][16-byte GCM tag]`.
- Key metadata stored as JSON `.meta` files. Public keys cached as `.pub` files. macOS signing keys also have `.handle` files (CryptoKit dataRepresentation).
- All file writes are atomic (write to `.tmp`, rename into place) with directory locking via `flock`.
- Apps pass their `app_name` (e.g., "sshenc", "awsenc") which determines the keys directory path and CNG key name prefix.

## Application Integration Types

Every enclave app is classified by how it delivers secrets to the target application. See [DESIGN.md — Application integration types](DESIGN.md#application-integration-types) for full definitions.

| Type | Name | Secret exposure | Example apps |
|------|------|----------------|-------------|
| **Type 1** | HelperTool | Secrets never leave process | sshenc (SSH agent), awsenc (`credential_process`) |
| **Type 2** | EnvInterpolation | Secrets in env vars via `execve()` | npmenc (`.npmrc` `${NPM_TOKEN}`) |
| **Type 3** | TempMaterializedConfig | Secrets briefly on disk (0o600) | Apps with no plugin or env var support |

The adapter selects the least-secret-exposing integration automatically: Type 1 > Type 2 > Type 3.

**sso-jwt** is a credential source that serves Type 1 or Type 2 apps.

## Platform

- macOS: Secure Enclave via CryptoKit (Swift bridge compiled by build.rs)
- Windows: TPM 2.0 via CNG (NCrypt/BCrypt APIs via `windows` crate)
- Linux: Software-only P-256 keys via `p256`/`aes-gcm` crates (no hardware security)
- WSL: Bridge from Linux to Windows TPM via JSON-RPC subprocess
- All crates compile (as stubs) on all platforms for cross-compilation support

## Commits

Do not add Co-Authored-By lines for Claude Code in commit messages.
