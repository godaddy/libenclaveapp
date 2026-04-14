# libenclaveapp

Shared Rust library for hardware-backed key management across macOS (Secure Enclave), Windows (TPM 2.0), Linux (TPM 2.0), and WSL.

## What it does

`libenclaveapp` provides:

- platform-agnostic traits and metadata handling
- platform backends for signing and encryption
- WSL bridge discovery and shell-integration helpers
- a shared `enclaveapp-app-storage` layer that derived applications use for app-scoped encrypted storage

Current derived projects in this workspace:

| Project | Primary use of libenclaveapp |
|---|---|
| [sshenc](https://github.com/godaddy/sshenc) | hardware-backed SSH signing |
| [awsenc](https://github.com/godaddy/awsenc) | encrypted AWS credential caching |
| [sso-jwt](https://github.com/godaddy/sso-jwt) | encrypted JWT caching |
| `npmenc` | encrypted npm token storage and wrapper integration |

## Workspace crates

| Crate | Purpose |
|---|---|
| [enclaveapp-core](crates/enclaveapp-core/) | shared traits, types, metadata, config helpers, errors |
| [enclaveapp-app-storage](crates/enclaveapp-app-storage/) | app-scoped encryption/signing bootstrap used by consuming apps |
| [enclaveapp-apple](crates/enclaveapp-apple/) | macOS Secure Enclave backend via CryptoKit Swift bridge |
| [enclaveapp-windows](crates/enclaveapp-windows/) | Windows TPM 2.0 backend via CNG |
| [enclaveapp-linux-tpm](crates/enclaveapp-linux-tpm/) | Linux TPM 2.0 backend via `tss-esapi` |
| [enclaveapp-software](crates/enclaveapp-software/) | software fallback for environments without hardware |
| [enclaveapp-wsl](crates/enclaveapp-wsl/) | WSL detection, distro config, shell-init helpers |
| [enclaveapp-bridge](crates/enclaveapp-bridge/) | JSON-RPC bridge protocol and WSL client |
| [enclaveapp-test-support](crates/enclaveapp-test-support/) | mock backends for tests |

## Feature flags

Platform crates expose `signing` and `encryption` features. Applications enable only what they need.

```toml
# signing consumer
enclaveapp-apple = { version = "0.1", features = ["signing"] }

# encryption consumer
enclaveapp-apple = { version = "0.1", features = ["encryption"] }
```

`enclaveapp-app-storage` sits above those platform crates and is the preferred integration layer for application code.

## Architecture

```
                  +------------------------+
                  | enclaveapp-core        |
                  | traits, types, metadata|
                  +-----------+------------+
                              |
                  +-----------v------------+
                  | enclaveapp-app-storage |
                  | app bootstrap layer    |
                  +-----+-------+-----+----+
                        |       |     |
        +---------------+       |     +------------------+
        |                       |                        |
+-------v--------+   +----------v---------+   +----------v---------+
| enclaveapp-    |   | enclaveapp-        |   | enclaveapp-        |
| apple          |   | windows            |   | linux-tpm          |
| Secure Enclave |   | Windows TPM        |   | Linux TPM          |
+----------------+   +----------+---------+   +----------+---------+
                                |                       |
                     +----------v---------+   +---------v---------+
                     | enclaveapp-bridge  |   | enclaveapp-       |
                     | WSL JSON-RPC client|   | software          |
                     +----------+---------+   | software fallback |
                                |             +-------------------+
                     +----------v---------+
                     | enclaveapp-wsl     |
                     | WSL install/shell  |
                     +--------------------+
```

## Building

Requires Rust 1.75+. macOS builds require Xcode. Linux TPM builds require `tpm2-tss` development libraries.

```bash
# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check
```

## Platform support

| Platform | Hardware | Signing | Encryption | Notes |
|---|---|---|---|---|
| macOS | Secure Enclave | Yes | Yes | CryptoKit via Swift bridge |
| Windows | TPM 2.0 | Yes | Yes | CNG NCrypt/BCrypt |
| Linux | TPM 2.0 | Yes | Yes | `tss-esapi` |
| Linux (no TPM) | Software | Yes | Yes | weaker protection, intended for CI/dev fallback |
| WSL | Windows TPM via bridge | App-dependent | Yes | encryption uses JSON-RPC bridge; ssh signing uses the sshenc agent bridge |

## License

MIT
