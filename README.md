# libenclaveapp

Shared Rust library for hardware-backed key management across macOS (Secure Enclave), Windows (TPM 2.0), Linux (TPM 2.0), and WSL. Provides signing (ECDSA P-256) and encryption (ECIES via ECDH P-256 + AES-256-GCM) with automatic platform detection.

## What it does

`libenclaveapp` is the foundation for building **enclave apps** — thin wrappers that deliver hardware-protected secrets to target applications. The library handles platform detection, key lifecycle, encrypted storage, and process launching so each app only needs its domain-specific logic.

## Consuming applications

| Application | Type | What it does |
|---|---|---|
| [sshenc](https://github.com/godaddy/sshenc) | [Type 1 (HelperTool)](DESIGN.md#type-1-helpertool) | Hardware-backed SSH key management via agent protocol |
| [awsenc](https://github.com/godaddy/awsenc) | [Type 1 (HelperTool)](DESIGN.md#type-1-helpertool) | Encrypted AWS credential caching via `credential_process` |
| [sso-jwt](https://github.com/godaddy/sso-jwt) | Credential source | Encrypted JWT caching for Type 1/2 apps |
| [npmenc](https://github.com/godaddy/npmenc) | [Type 2 (EnvInterpolation)](DESIGN.md#type-2-envinterpolation) | Secure npm token wrapper via `.npmrc` env var interpolation |

## Application integration types

Every enclave app is classified by how it delivers secrets to the target application. See [DESIGN.md](DESIGN.md#application-integration-types) for full definitions.

| Type | Name | How secrets are delivered | Security |
|------|------|--------------------------|----------|
| **Type 1** | [HelperTool](DESIGN.md#type-1-helpertool) | Target app calls back for credentials on demand (agent protocol, `credential_process`) | Secrets never leave the enclave app's process |
| **Type 2** | [EnvInterpolation](DESIGN.md#type-2-envinterpolation) | Config file with `${ENV_VAR}` placeholders; secrets injected as env vars via `execve()` | Secrets in memory only, never on disk |
| **Type 3** | [TempMaterializedConfig](DESIGN.md#type-3-tempmaterializedconfig) | Secrets written to temp file (0o600), path passed via `--config` flag, file deleted after exit | Secrets briefly on disk with restricted permissions |

The adapter selects the most secure integration automatically: Type 1 > Type 2 > Type 3.

## Platform support

| OS | Architecture | Hardware security | Signing key exportable? | Encryption key exportable? |
|---|---|---|:---:|:---:|
| macOS (signed app) | Apple Silicon | Secure Enclave | **No** | **No** |
| macOS (unsigned/dev) | Apple Silicon | Keychain-wrapped | Yes (encrypted) | Yes (encrypted) |
| Windows | x64, ARM64 | TPM 2.0 | **No** | **No** |
| Linux (glibc) | x64, ARM64 | TPM 2.0 | **No** | **No** |
| Linux (glibc, no TPM) | x64, ARM64 | Keyring-encrypted | Yes (encrypted) | Yes (encrypted) |
| Linux (musl) | x64, ARM64 | None | Yes (plaintext) | Yes (plaintext) |

On Windows, enclave apps work across **PowerShell**, **Command Prompt**, **Git Bash**, and **WSL2** (Ubuntu, Debian). WSL2 accesses the host TPM via a JSON-RPC bridge.

See [DESIGN.md — Platform support](DESIGN.md#platform-support) for the full platform matrix, [security levels](DESIGN.md#security-levels), and [Windows shell environment details](DESIGN.md#windows-shell-environments).

## Cryptography

All backends use **ECDSA P-256** (secp256r1) — the only curve universally supported by the Secure Enclave, Windows TPM, and Linux TPM. This provides **128 bits of classical security**.

- **Signing:** ECDSA with SHA-256 (DER-encoded)
- **Encryption:** ECIES — ephemeral ECDH P-256 + X9.63 KDF + AES-256-GCM

P-256 is **not post-quantum secure**, but the data protected by enclave apps (cached credentials, session tokens) is short-lived (minutes to hours), bounding the practical risk. See [DESIGN.md — Cryptographic primitives](DESIGN.md#cryptographic-primitives) for the full analysis.

## Workspace crates

| Crate | Purpose |
|---|---|
| [enclaveapp-core](crates/enclaveapp-core/) | Traits, types, metadata, config block injection, path quoting, errors |
| [enclaveapp-app-storage](crates/enclaveapp-app-storage/) | App-scoped encryption/signing with automatic platform detection |
| [enclaveapp-app-adapter](crates/enclaveapp-app-adapter/) | Generic secret delivery: binding/secret stores, program resolver, process launcher, temp config |
| [enclaveapp-apple](crates/enclaveapp-apple/) | macOS Secure Enclave backend via CryptoKit Swift bridge |
| [enclaveapp-windows](crates/enclaveapp-windows/) | Windows TPM 2.0 backend via CNG (NCrypt/BCrypt) |
| [enclaveapp-linux-tpm](crates/enclaveapp-linux-tpm/) | Linux TPM 2.0 backend via `tss-esapi` |
| [enclaveapp-software](crates/enclaveapp-software/) | Software-only P-256 fallback for environments without hardware security |
| [enclaveapp-wsl](crates/enclaveapp-wsl/) | WSL detection, distro config, managed shell block injection |
| [enclaveapp-bridge](crates/enclaveapp-bridge/) | JSON-RPC bridge protocol and WSL client for Windows TPM access |
| [enclaveapp-tpm-bridge](crates/enclaveapp-tpm-bridge/) | Shared JSON-RPC TPM bridge server (parameterized by app) |
| [enclaveapp-cache](crates/enclaveapp-cache/) | Shared binary cache format with configurable magic bytes |
| [enclaveapp-build-support](crates/enclaveapp-build-support/) | Shared build.rs helper for Windows PE resource compilation |
| [enclaveapp-test-support](crates/enclaveapp-test-support/) | Mock backends for testing without hardware |

## Architecture

```
consuming app (sshenc, awsenc, sso-jwt, npmenc)
  |
  +-- enclaveapp-app-adapter        secret delivery substrate
  |     bindings, secrets, resolver, launcher, temp config
  |
  +-- enclaveapp-app-storage        platform-detected encrypt/sign
  |     |
  |     +-- enclaveapp-apple        macOS Secure Enclave
  |     +-- enclaveapp-windows      Windows TPM 2.0
  |     +-- enclaveapp-linux-tpm    Linux TPM 2.0
  |     +-- enclaveapp-software     software fallback
  |     +-- enclaveapp-bridge       WSL -> Windows TPM bridge client
  |
  +-- enclaveapp-tpm-bridge         shared bridge server binary
  +-- enclaveapp-cache              shared binary cache format
  +-- enclaveapp-core               traits, types, metadata, utilities
```

## Building

Requires Rust 1.75+. macOS builds require Xcode (for Swift bridge). Linux TPM builds require `tpm2-tss` development libraries.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Feature flags

Platform crates expose `signing` and `encryption` features. Applications enable only what they need:

```toml
# SSH signing app
enclaveapp-apple = { features = ["signing"] }

# Credential caching app
enclaveapp-apple = { features = ["encryption"] }
```

`enclaveapp-app-storage` handles platform selection automatically and is the preferred integration point.

## Documentation

- [DESIGN.md](DESIGN.md) — Architecture, security levels, platform details, cryptographic primitives, integration type taxonomy
- [docs/design-app-adapter-promotion.md](docs/design-app-adapter-promotion.md) — Design for the adapter promotion and deduplication effort

## License

MIT
