# libenclaveapp Design Document

## Goal

Provide a shared Rust substrate for hardware-backed key management so derived applications do not each reimplement:

- platform detection
- Secure Enclave / TPM bootstrap
- key lifecycle and metadata storage
- WSL bridge discovery
- keyring fallback behavior

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
    enclaveapp-keyring/       Keyring-backed backend (Linux production)
    enclaveapp-test-software/ Test-only plaintext backend
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
- `enclaveapp-keyring`: keyring-backed backend for Linux without TPM (keys encrypted via system keyring)
- `enclaveapp-test-software`: test-only plaintext backend (not for production)

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

## Cryptographic primitives

### ECDSA P-256 (secp256r1 / prime256v1)

All signing and encryption operations use **NIST P-256** (also known as secp256r1 or prime256v1). This is the sole elliptic curve supported across all backends.

**Why P-256:** It is the only curve universally supported by all three hardware targets — Apple Secure Enclave, Windows TPM 2.0 (CNG), and Linux TPM 2.0 (`tss-esapi`). The Secure Enclave in particular only supports P-256 for key agreement and signing. This constraint drives the choice for the entire library.

**Security strength:** P-256 provides approximately **128 bits of classical security**, comparable to AES-128. This exceeds current best-practice minimums (the NIST recommendation is 112 bits through 2030+). P-256 is widely deployed in TLS 1.3, SSH, code signing, and WebAuthn.

**Post-quantum status:** P-256 is **not post-quantum secure**. A sufficiently capable quantum computer running Shor's algorithm could break ECDSA and ECDH on P-256 in polynomial time. However:

- No such quantum computer exists today, and current estimates place cryptographically relevant quantum computers at least a decade away.
- The data protected by enclave apps (cached credentials, session tokens, SSH signatures) is **short-lived** — typically minutes to hours. Even if a quantum computer were available, the secrets would have expired before they could be extracted.
- When post-quantum algorithms are added to the hardware security modules (Apple has indicated post-quantum support in future SE revisions; TPM 2.0 has a PQC profile in draft), the library can adopt them. The version byte in the ECIES format and the trait-based architecture allow new algorithms without breaking existing caches.

For the use cases served by enclave apps (credential caching, SSH signing, token management), P-256 provides strong security today with a clear migration path to post-quantum algorithms when hardware support materializes.

### Signing: ECDSA with SHA-256

- **Curve:** P-256
- **Hash:** SHA-256
- **Signature format:** DER-encoded ASN.1 (converted from P1363 on Windows CNG). The `enclaveapp-windows` crate includes a `convert` module for P1363 ↔ DER conversion.
- **Use case:** SSH key signing (`sshenc`), git commit/tag signing (`gitenc`)

### Encryption: ECIES (ECDH + AES-256-GCM)

- **Key agreement:** ECDH P-256 with ephemeral sender key
- **KDF:** X9.63 KDF with SHA-256 (derives 32-byte AES key from shared secret)
- **Symmetric cipher:** AES-256-GCM (authenticated encryption)
- **Use case:** Credential caching (`awsenc`), token caching (`sso-jwt`), secret storage (`npmenc`)

**Ciphertext format:**

```
[0x01 version] [65-byte ephemeral pubkey (SEC1 uncompressed)] [12-byte nonce] [ciphertext] [16-byte GCM tag]
```

This format is consistent across all backends — a ciphertext produced by the Secure Enclave can be decrypted by the software backend and vice versa (given the same private key material). The version byte allows future format changes without breaking existing caches.

## Platform support

### Target architectures

| OS | Architecture | Hardware security | Backend |
|---|---|---|---|
| macOS | Apple Silicon (aarch64) | Secure Enclave | `enclaveapp-apple` via CryptoKit Swift bridge |
| Windows | x86_64 | TPM 2.0 | `enclaveapp-windows` via CNG (NCrypt/BCrypt) |
| Windows | ARM64 (aarch64) | TPM 2.0 | `enclaveapp-windows` via CNG (NCrypt/BCrypt) |
| Linux | x86_64 (glibc) | TPM 2.0 | `enclaveapp-linux-tpm` via `tss-esapi` |
| Linux | ARM64 (glibc) | TPM 2.0 | `enclaveapp-linux-tpm` via `tss-esapi` |
| Linux | x86_64 (glibc, no TPM) | System keyring | `enclaveapp-keyring` via D-Bus Secret Service |
| Linux | ARM64 (glibc, no TPM) | System keyring | `enclaveapp-keyring` via D-Bus Secret Service |

All architectures support both signing and encryption.

**Minimum OS requirements and hardware security guarantees:**

- **macOS:** Apple Silicon required (Secure Enclave always present). Intel Macs and macOS VMs without SE passthrough are not supported.
- **Windows:** TPM 2.0 required (Windows 10 or Windows 11). TPM 1.2 is not supported — it lacks ECDSA P-256 and ECDH support (only RSA and SHA-1). The CNG Microsoft Platform Crypto Provider targets TPM 2.0 exclusively. Windows 11 guarantees TPM 2.0 is present; Windows 10 machines must have TPM 2.0 hardware.
- **Linux:** TPM 2.0 used when available (glibc only, via `tss-esapi`). Falls back to software keys when no TPM is present. No minimum OS version — TPM availability depends on hardware and kernel configuration.

### Security levels

Not all backends provide the same level of key protection. The properties differ between **signing keys** (used by `sshenc` for SSH/git signatures) and **encryption keys** (used by `awsenc`, `sso-jwt`, `npmenc` for credential/token caching).

#### Signing key security

Signing keys are long-lived identity keys (e.g., SSH keys). At Levels 1-3, the hardware security module **is** the signer — it performs the ECDSA signature operation directly and the private key material never exists in software, in memory, or on disk.

| Level | Backend | Who signs? | Private key exportable? | User presence | Key storage |
|:-----:|---------|-----------|:----------------------:|---------------|-------------|
| **1** | macOS Secure Enclave | **The SE hardware.** `sshenc` sends data to the SE via CryptoKit; the SE performs ECDSA P-256 internally and returns the signature. The private key never exists outside the chip. Works for both signed and unsigned binaries on Apple Silicon. | **No** — impossible. Even root cannot extract it. The `dataRepresentation` on disk is an opaque SE handle (not key material), AES-256-GCM encrypted with a Keychain-stored wrapping key to prevent same-user handle theft. | Touch ID / biometric enforced by SE hardware per-signature (when access policy is set). | Secure Enclave coprocessor + AES-256-GCM wrapped handle on disk + Keychain wrapping key. |
| **2** | Windows TPM 2.0 | **The TPM hardware.** CNG sends signing requests to the TPM via NCrypt. | **No** — key is a non-exportable TPM object. | Windows Hello (biometric/PIN) enforced per-signature via `NCRYPT_UI_POLICY`. | TPM 2.0 chip. |
| **3** | Linux TPM 2.0 | **The TPM hardware.** Signing performed by the TPM via `tss-esapi`. | **No** — key is TPM-resident. | Not enforced (no standard Linux biometric API). | TPM 2.0 device (`/dev/tpmrm0`). glibc only. |
| **4** | Software (Linux glibc) | **Software.** The P-256 private key is decrypted from the keyring into memory and used for signing via the `p256` crate. | **Yes (encrypted at rest)** — P-256 private key on disk, encrypted via system keyring (D-Bus Secret Service / GNOME Keyring / KWallet). | Not enforced. | `~/.config/{app}/keys/` encrypted via keyring. |
| **5** | Software (Linux musl) | **Software.** Private key read from disk into memory. | **Yes (plaintext on disk)** — P-256 private key stored as a file with 0o600 permissions. | Not enforced. | `~/.config/{app}/keys/` plaintext. |

#### Encryption key security

Encryption keys protect cached secrets (AWS credentials, JWTs, npm tokens). At Levels 1-3, the hardware performs the ECDH key agreement internally — the private key never exists in software. The encrypted data can only be decrypted on the same device that created the key.

The blast radius of encryption key compromise is further bounded by the expiration of the cached data (typically minutes to hours).

| Level | Backend | Who decrypts? | Private key exportable? | User presence | Cached data protection |
|:-----:|---------|--------------|:----------------------:|---------------|----------------------|
| **1** | macOS Secure Enclave | **The SE hardware.** ECDH key agreement happens inside the SE. The shared secret is derived internally; only the AES-GCM decryption of the ciphertext body happens in software. Handle blob AES-256-GCM encrypted via Keychain. | **No** — impossible. | Touch ID / biometric can be required per-decrypt. | Ciphertext on disk can only be decrypted by the SE that created the key. Full disk access is insufficient without the SE. |
| **2** | Windows TPM 2.0 | **The TPM hardware** performs ECDH. | **No** — TPM-bound. | Windows Hello can be required per-decrypt. | Only decryptable on the same machine's TPM. |
| **3** | Linux TPM 2.0 | **The TPM hardware** via `tss-esapi`. | **No** — TPM-bound. | Not enforced. | Same machine-binding as Windows TPM. |
| **4** | Software (Linux glibc) | **Software.** P-256 key decrypted from keyring. | **Yes (encrypted at rest)** — keyring-protected. | Not enforced. | Keyring-encrypted key protects cache at rest. |
| **5** | Software (Linux musl) | **Software.** P-256 key read from disk. | **Yes (plaintext on disk)** — 0o600 permissions only. | Not enforced. | Cache protection relies entirely on filesystem permissions. |

#### macOS: Secure Enclave access and key persistence

All supported macOS hardware (Apple Silicon) has a Secure Enclave, and **CryptoKit's `SecureEnclave.P256` APIs work without code signing or entitlements**. Both signed and unsigned builds get full SE access — the SE creates the key and performs all signing/key agreement operations. The private key material never leaves the hardware.

The `com.apple.developer.secure-enclave` entitlement is a **Security.framework** concept for Keychain-stored SE keys (`SecItemAdd` with `kSecAttrTokenIDSecureEnclave`). Since libenclaveapp uses CryptoKit's `dataRepresentation` for key persistence (not Security.framework), the entitlement is not required.

**Handle protection for unsigned apps:** The SE's `dataRepresentation` is an opaque handle blob that allows the same device's SE to reconstruct the key reference. While the private key itself cannot be extracted from this blob, the blob is stored as a file on disk — and another process running as the same user could copy it and use it to request SE operations. To mitigate this same-user attack, we wrap the `dataRepresentation` with **AES-256-GCM** encryption before writing to disk. The AES wrapping key is stored in the **macOS Keychain**, which provides per-application access control.

- **Signed app (code-signed with Developer ID):** The Keychain ACL is bound to the app's code signature. Other apps cannot access the wrapping key. Handle files are protected against same-user attacks.

- **Unsigned app (e.g., Homebrew, `cargo build`):** The Keychain ACL is bound to the binary's hash. The user must authorize access on first use (password/biometric prompt) and click "Always Allow." **After a Homebrew update**, the binary hash changes, invalidating the Keychain ACL — the user must re-authorize. This is a UX trade-off, not a security degradation: the SE still performs all cryptographic operations, and the wrapping key prevents other processes from using the handle.

In both cases, the SE performs all ECDSA signing and ECDH key agreement. The AES-256-GCM wrapping layer protects the persistence of the SE handle, not the cryptographic operations themselves.

#### macOS signed vs. unsigned

On macOS, the `enclaveapp-apple` backend auto-detects which path to use at runtime:

- **Signed/entitled (Level 1):** The app is code-signed with a Developer ID certificate and has the Secure Enclave entitlement. Keys are created inside SE hardware via `SecureEnclave.P256.Signing.PrivateKey` / `SecureEnclave.P256.KeyAgreement.PrivateKey`. The key material physically cannot be extracted. This is the production path for distributed binaries.

- **Unsigned/development (Level 4):** The app is not code-signed or lacks entitlements (typical during local development with `cargo build`). Keys are created via regular `CryptoKit.P256` (not SE-bound). The private key's `dataRepresentation` is encrypted with AES-256-GCM using a wrapping key stored in the macOS Keychain, then written to disk as a `.handle` file. This provides encryption at rest but the keys are not hardware-bound.

#### Linux glibc vs. musl

Glibc builds can access the system keyring (D-Bus Secret Service / GNOME Keyring / KWallet) to encrypt private key files at rest (Level 5). Musl builds (Alpine, static binaries) have no keyring and store keys as plaintext files with 0o600 permissions (Level 6). Both can use TPM 2.0 when available (glibc only, via `tss-esapi`), which upgrades to Level 3.

### Windows shell environments

On Windows, enclave apps operate across multiple shell environments. Each has distinct behavior for path resolution, environment variable handling, and config file locations:

| Environment | Shell | Path style | Config location | Notes |
|---|---|---|---|---|
| PowerShell | `pwsh.exe` / `powershell.exe` | `C:\Users\...` | `%LOCALAPPDATA%` | Native Windows; full TPM access |
| Command Prompt | `cmd.exe` | `C:\Users\...` | `%LOCALAPPDATA%` | Native Windows; full TPM access |
| Git Bash (MSYS2) | `bash.exe` (MinGW) | `/c/Users/...` | `$APPDATA` or `$HOME` | Runs native Windows binaries; TPM available |
| WSL2 (Ubuntu) | `bash` (Linux) | `/home/user/...` | `~/.config/` | Linux binary; TPM via JSON-RPC bridge to Windows host |
| WSL2 (Debian) | `bash` (Linux) | `/home/user/...` | `~/.config/` | Linux binary; TPM via JSON-RPC bridge to Windows host |

**WSL architecture:** WSL2 distros run a real Linux kernel and use native Linux binaries. To access the Windows host's TPM, enclave apps use the JSON-RPC bridge (`enclaveapp-bridge`): the Linux client spawns the Windows bridge binary (located under `/mnt/c/`) via interop and communicates over stdin/stdout. The bridge server (`enclaveapp-tpm-bridge`) runs natively on the Windows host and performs TPM operations.

**Git Bash:** Unlike WSL, Git Bash runs native Windows executables. The Windows binary works directly with the TPM — no bridge is needed. However, path handling requires care: Git Bash presents Windows paths in Unix-style (`/c/Users/...`), and SSH config requires forward slashes even on Windows.

For `sshenc`, WSL signing is handled by the SSH agent bridge path (named pipe relay via `npiperelay`) rather than the JSON-RPC encryption bridge.

### Shell compatibility

Enclave apps are native binaries and work under any shell that can invoke executables. The following shells have been tested on macOS:

| Shell | Version tested | Binary invocation | Shell-init / completions | Env var passthrough (Type 2) |
|-------|---------------|:-----------------:|:------------------------:|:----------------------------:|
| bash (macOS built-in) | 3.2.57 | pass | pass | pass |
| bash (Homebrew) | 5.3.9 | pass | pass | pass |
| zsh (macOS built-in) | 5.9 | pass | pass | pass |
| fish (Homebrew) | 4.6.0 | pass | pass (completions) | pass |
| tcsh (macOS built-in) | 6.21 | pass | — | — |
| dash (Homebrew) | POSIX sh | pass | — | pass |
| nushell (Homebrew) | 0.112.1 | pass | — | — |

**Shell-init scripts** are provided for bash, zsh, and fish. Other shells can invoke the binaries directly.

**Type 2 env var passthrough** (npmenc/npxenc) is verified to work under bash, zsh, fish, and dash. The `execve()` boundary ensures env vars are passed correctly regardless of shell.

**Not tested:** macOS's built-in ksh (`/bin/ksh`) is broken on Apple Silicon — it segfaults on trivial commands like `echo hello` (exit code 139). This is a macOS system issue unrelated to enclave apps. ksh is excluded from the test matrix.

## Application integration types

Every enclave app is classified by how it delivers secrets to the target application. The `enclaveapp-app-adapter` crate defines three integration types, listed from most secure to least secure:

### Type 1: HelperTool

The target application has native support for auth plugins, credential helpers, or agents. Secrets never leave the enclave app's process boundary — they are returned on demand via a protocol (SSH agent, `credential_process`, etc.). This is the most secure integration because secrets are never written to disk or exposed in environment variables.

### Type 2: EnvInterpolation

The target application reads a config file that supports environment variable interpolation (`${ENV_VAR}`). The enclave app writes a config with placeholders and invokes the target with secret env vars set via `execve()`. Secrets exist briefly as environment variables but never touch disk in plaintext. The `execve()` boundary is critical — the env vars must not be set in a shell where they would be visible in shell history or to child processes beyond the target.

### Type 3: TempMaterializedConfig

The target application can only read a static config file with no env var support. The enclave app writes secrets to a temp file with restricted permissions (0o600 on Unix), invokes the target with a config path override (e.g. `--config /tmp/xxx/app.conf`), and deletes the file after the process exits. This is the least secure integration because secrets briefly exist on disk, but the restricted permissions and automatic cleanup mitigate the risk.

The adapter selects the least-secret-exposing integration automatically: Type 1 > Type 2 > Type 3.

### Type 4: CredentialSource

The enclave app does not wrap a target application. Instead, it **is** the credential source — it obtains, encrypts, and caches credentials that other enclave apps (Type 1, 2, or 3) consume. A Type 4 app provides secrets via a CLI command (`sso-jwt get`), a NAPI binding, or a local API, and other tools call it as a credential provider.

This is the most composable integration: a single Type 4 app can serve multiple Type 1/2/3 apps. For example, `sso-jwt` obtains a JWT via the OAuth 2.0 Device Authorization Grant, caches it with hardware-backed encryption, and supplies it to `npmenc` (Type 2) as a token source or to a `credential_process` wrapper (Type 1) as a credential provider.

### Consumer mapping

| Consumer | Integration Type | Mechanism |
|---|---|---|
| `sshenc` | Type 1 (HelperTool) | SSH agent protocol; keys used in-process for signing |
| `awsenc` | Type 1 (HelperTool) | `credential_process` directive in `~/.aws/config` |
| `npmenc` | Type 2 (EnvInterpolation) | `.npmrc` with `${NPM_TOKEN}` placeholders |
| `sso-jwt` | Type 4 (CredentialSource) | Obtains and caches JWTs; consumed by Type 1/2/3 apps as a token provider |
