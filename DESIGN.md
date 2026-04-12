# libenclaveapp Design Document

## Goal

Shared Rust library for hardware-backed key management, extracted from
duplicated infrastructure across `sshenc`, `awsenc`, and `sso-jwt`. All
three applications depend on libenclaveapp for platform crypto, key
lifecycle, metadata storage, and cross-platform abstractions.

## Architecture

```
libenclaveapp/
  crates/
    enclaveapp-core/          Platform-agnostic types, traits, utilities
    enclaveapp-apple/         macOS Secure Enclave (CryptoKit Swift bridge)
    enclaveapp-windows/       Windows TPM 2.0 (CNG NCrypt/BCrypt)
    enclaveapp-linux-tpm/     Linux TPM 2.0 (tss-esapi)
    enclaveapp-software/      Software fallback (P-256 on disk)
    enclaveapp-wsl/           WSL detection and shell configuration
    enclaveapp-bridge/        JSON-RPC TPM bridge for WSL
    enclaveapp-test-support/  Mock backend for testing without hardware
```

### enclaveapp-core

Platform-agnostic abstractions. No FFI, no platform-specific code.

Key types:
- `KeyType` -- `Signing` (ECDSA) or `Encryption` (ECIES via ECDH)
- `AccessPolicy` -- `None`, `Any`, `BiometricOnly`, `PasswordOnly`
- `KeyMeta` -- label, key type, access policy, timestamps, app-specific data

Key traits:
- `EnclaveKeyManager` -- generate, public_key, list_keys, delete_key, is_available
- `EnclaveSigner` -- sign (extends EnclaveKeyManager)
- `EnclaveEncryptor` -- encrypt, decrypt (extends EnclaveKeyManager)

Utilities: atomic file writes, directory locking, config/metadata TOML
helpers, SEC1 P-256 point validation, standard app data directory resolution.

### enclaveapp-apple

macOS Secure Enclave via CryptoKit Swift bridge. Compiled as a static
library via `build.rs` (swiftc). No Apple Developer certificate or
entitlements required -- CryptoKit works with ad-hoc linker signatures.

Supports both key types:
- `SecureEnclave.P256.Signing.PrivateKey` for ECDSA signing (sshenc)
- `SecureEnclave.P256.KeyAgreement.PrivateKey` for ECIES encryption (awsenc, sso-jwt)

ECIES implementation: ECDH key agreement + X9.63 KDF + AES-GCM. Keys
are stored as opaque `.handle` files (CryptoKit data representations).

### enclaveapp-windows

Windows TPM 2.0 via CNG (`Microsoft Platform Crypto Provider`). Supports
both `BCRYPT_ECDSA_P256_ALGORITHM` (signing) and `BCRYPT_ECDH_P256_ALGORITHM`
(encryption). Key lifecycle, Windows Hello policy, and public key export
are shared between both modes.

### enclaveapp-linux-tpm

Linux TPM 2.0 via `tss-esapi` (TPM2 Software Stack). Uses the kernel TPM
resource manager (`/dev/tpmrm0`). Keys are stored as TPM-wrapped blobs --
the private portion is encrypted by the TPM and useless on another machine.

Supports both signing and encryption. Available on Linux systems with
TPM 2.0 hardware.

### enclaveapp-software

Software-only P-256 backend for environments without hardware security
modules. Uses the `p256` and `aes-gcm` crates. Keys are stored as files
on disk with restrictive permissions (0600). Provides the same API as
hardware backends but without hardware isolation.

Intended for CI, containers, and development environments. Applications
print a one-time warning when using this backend.

### enclaveapp-wsl

WSL detection and shell configuration. Parameterized by app name so all
three applications share the same WSL integration code.

Provides: `is_wsl()` detection, distro enumeration, shell profile
configuration (managed block insertion/removal), dependency installation
(socat, bridge binaries).

### enclaveapp-bridge

JSON-RPC TPM bridge binary for WSL. Runs on the Windows host, accepts
encrypt/decrypt/sign requests over stdin/stdout from WSL processes. The
key name is the only app-specific parameter.

### enclaveapp-test-support

Mock backend implementing all traits with deterministic key generation
and signature production. Used by all three consuming applications for
testing without hardware.

## Feature Flags

Platform crates expose `signing` and `encryption` features:

```toml
# SSH key signing (sshenc)
enclaveapp-apple = { features = ["signing"] }

# Credential encryption (awsenc, sso-jwt)
enclaveapp-apple = { features = ["encryption"] }
```

## ECIES Ciphertext Format

```
[0x01 version] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte GCM tag]
```

The version byte allows future format evolution. The explicit nonce is more
robust than derived nonces. AES-GCM provides authenticated encryption.

## Platform Support

| Platform | Hardware | Signing | Encryption |
|---|---|---|---|
| macOS (Apple Silicon / T2) | Secure Enclave | Yes | Yes |
| Windows | TPM 2.0 | Yes | Yes |
| Linux | TPM 2.0 | Yes | Yes |
| Linux (no TPM) | Software | Yes | Yes |
| WSL | Windows TPM via bridge | Yes* | Yes |

*WSL signing for sshenc uses the agent bridge (socat + npiperelay) rather
than the JSON-RPC bridge.

## Consumers

| Application | Key Type | Backend Features |
|---|---|---|
| sshenc | Signing | ECDSA P-256, SSH agent protocol |
| awsenc | Encryption | ECIES, AWS credential caching |
| sso-jwt | Encryption | ECIES, JWT caching |
