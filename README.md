# libenclaveapp

Shared Rust library for hardware-backed key management across macOS (Secure Enclave), Windows (TPM 2.0), and Linux (TPM 2.0 / software fallback).

## What it does

libenclaveapp provides ECDSA P-256 signing and ECIES encryption using keys that never leave the hardware security module. It handles the platform FFI, key lifecycle, metadata storage, and cross-platform abstractions so that applications don't have to.

Three applications currently consume this library:

- [sshenc](https://github.com/godaddy/sshenc) -- SSH key management (signing)
- [awsenc](https://github.com/godaddy/awsenc) -- AWS credential caching (encryption)
- [sso-jwt](https://github.com/godaddy/sso-jwt) -- SSO JWT caching (encryption)

## Crates

| Crate | Purpose |
|---|---|
| [enclaveapp-core](crates/enclaveapp-core/) | Traits, types, metadata, config helpers, error types |
| [enclaveapp-apple](crates/enclaveapp-apple/) | macOS Secure Enclave via CryptoKit Swift bridge |
| [enclaveapp-windows](crates/enclaveapp-windows/) | Windows TPM 2.0 via CNG (NCrypt/BCrypt) |
| [enclaveapp-linux-tpm](crates/enclaveapp-linux-tpm/) | Linux TPM 2.0 via tss-esapi |
| [enclaveapp-software](crates/enclaveapp-software/) | Software-only P-256 fallback (no hardware required) |
| [enclaveapp-wsl](crates/enclaveapp-wsl/) | WSL detection, shell configuration, install helpers |
| [enclaveapp-bridge](crates/enclaveapp-bridge/) | JSON-RPC TPM bridge for WSL |
| [enclaveapp-test-support](crates/enclaveapp-test-support/) | Mock backend for testing without hardware |

## Feature flags

Platform crates expose `signing` and `encryption` features. Applications enable only what they need:

```toml
# SSH key signing (sshenc)
enclaveapp-apple = { version = "0.1", features = ["signing"] }

# Credential encryption (awsenc, sso-jwt)
enclaveapp-apple = { version = "0.1", features = ["encryption"] }
```

## Architecture

```
                  +-------------------+
                  | enclaveapp-core   |  Traits, types, metadata
                  +-------------------+
                 /     |      |       \
  +------------+  +----------+  +----------+  +-------------+
  | enclaveapp-|  |enclaveapp|  |enclaveapp|  | enclaveapp- |
  | apple      |  | -windows |  | -linux-  |  | software    |
  | (macOS SE) |  | (Win TPM)|  |   tpm    |  | (fallback)  |
  +------------+  +----------+  +----------+  +-------------+
                       |
               +-------------------+
               | enclaveapp-bridge |  WSL <-> Windows TPM
               +-------------------+

  +-------------------+          +-------------------+
  | enclaveapp-wsl    |          | enclaveapp-test-  |
  | WSL detection,    |          | support (mock)    |
  | shell config      |          |                   |
  +-------------------+          +-------------------+
```

### Key traits

```rust
// Base trait -- every platform implements this
trait EnclaveKeyManager {
    fn generate(&self, label: &str, key_type: KeyType, policy: AccessPolicy) -> Result<Vec<u8>>;
    fn public_key(&self, label: &str) -> Result<Vec<u8>>;
    fn list_keys(&self) -> Result<Vec<String>>;
    fn delete_key(&self, label: &str) -> Result<()>;
    fn is_available(&self) -> bool;
}

// ECDSA signing (extends EnclaveKeyManager)
trait EnclaveSigner: EnclaveKeyManager {
    fn sign(&self, label: &str, data: &[u8]) -> Result<Vec<u8>>;
}

// ECIES encryption (extends EnclaveKeyManager)
trait EnclaveEncryptor: EnclaveKeyManager {
    fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, label: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

### ECIES ciphertext format

```
[0x01 version] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
```

## Building

Requires Rust 1.75+. macOS builds require Xcode (for swiftc). Linux TPM builds require tpm2-tss development libraries.

```bash
# macOS
cargo build --workspace --features enclaveapp-apple/signing,enclaveapp-apple/encryption

# Windows
cargo build --workspace --features enclaveapp-windows/signing,enclaveapp-windows/encryption

# Linux (with TPM)
cargo build --workspace --features enclaveapp-linux-tpm/signing,enclaveapp-linux-tpm/encryption

# Tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
```

## Platform support

| Platform | Hardware | Signing | Encryption | Notes |
|---|---|---|---|---|
| macOS | Secure Enclave | Yes | Yes | CryptoKit via Swift bridge, ad-hoc signing OK |
| Windows | TPM 2.0 | Yes | Yes | CNG NCrypt/BCrypt, Windows Hello for auth |
| Linux | TPM 2.0 | Yes | Yes | tss-esapi, /dev/tpmrm0 |
| Linux (no TPM) | Software | Yes | Yes | P-256 on disk, no hardware isolation |
| WSL | Windows TPM | No* | Yes | Via JSON-RPC bridge to Windows host |

*WSL signing is possible through the sshenc agent bridge (socat + npiperelay).

## License

MIT
