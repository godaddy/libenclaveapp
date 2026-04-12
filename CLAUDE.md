# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`libenclaveapp` is a shared Rust library for hardware-backed key management across macOS (Secure Enclave via CryptoKit) and Windows (TPM 2.0 via CNG). It provides signing (ECDSA P-256) and encryption (ECIES via ECDH P-256 + AES-GCM) behind feature flags, plus WSL integration and a TPM bridge for WSL→Windows communication.

Three applications consume this library:
- **sshenc** — SSH key management (signing)
- **awsenc** — AWS credential caching (encryption)
- **sso-jwt** — SSO JWT caching (encryption)

## Build & Development

Rust workspace. Requires Rust 1.75+. macOS builds need Xcode (for swiftc).

```bash
# Build with all features (macOS)
cargo build --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption

# Build with all features (Windows)
cargo build --workspace --features enclaveapp-windows/signing,enclaveapp-windows/encryption

# Test everything
cargo test --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption

# Lint
cargo clippy --workspace --all-targets --features enclaveapp-apple/signing,enclaveapp-apple/encryption -- -D warnings

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
- **enclaveapp-test-support** — `MockKeyBackend` implementing all three traits with deterministic in-memory operations. XOR-based mock crypto for testing control flow without hardware.

### Key Patterns

- `EnclaveKeyManager` trait is the base — `EnclaveSigner` and `EnclaveEncryptor` extend it.
- Feature flags (`signing`, `encryption`) control which trait implementations are compiled.
- The Swift bridge compiles all functions regardless of features; feature gates are Rust-side only.
- ECIES ciphertext format: `[0x01 version][65-byte ephemeral pubkey][12-byte nonce][ciphertext][16-byte GCM tag]`.
- Key metadata stored as JSON `.meta` files. Public keys cached as `.pub` files. macOS signing keys also have `.handle` files (CryptoKit dataRepresentation).
- All file writes are atomic (write to `.tmp`, rename into place) with directory locking via `flock`.
- Apps pass their `app_name` (e.g., "sshenc", "awsenc") which determines the keys directory path and CNG key name prefix.

## Platform

- macOS: Secure Enclave via CryptoKit (Swift bridge compiled by build.rs)
- Windows: TPM 2.0 via CNG (NCrypt/BCrypt APIs via `windows` crate)
- WSL: Bridge from Linux to Windows TPM via JSON-RPC subprocess
- All crates compile (as stubs) on all platforms for cross-compilation support
