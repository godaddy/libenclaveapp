# Threat Model

This document describes the security properties and limitations of
libenclaveapp as a shared library for hardware-backed key management.

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Hardware-bound private key | P-256 key in Secure Enclave or TPM | Critical -- non-exportable, device-bound |
| Keyring backend private key | P-256 key encrypted via system keyring | High -- keyring-based, no hardware isolation |
| Public key | SEC1-encoded P-256 public key | Low -- intended to be shared |
| Key metadata | Label, type, access policy, timestamps | Low -- no secrets |
| ECIES ciphertext | Encrypted data produced by `EnclaveEncryptor` | Medium -- useless without the private key |
| ECDSA signature | Produced by `EnclaveSigner` | Low -- non-secret output |

## Trust Boundaries

```
+-------------------------------------------------------------------+
| Consuming application (sshenc, awsenc, sso-jwt, npmenc, etc.)     |
|                                                                    |
|  +-------------------+    +-------------------+                  |
|  | enclaveapp-core   |    | enclaveapp-app-   |                  |
|  | (traits, types)   |    | storage           |                  |
|  +-------------------+    +---------+---------+                  |
|                                     |                             |
|                       +-------------+-------------+               |
|                       | apple / windows / linux   |               |
|                       | tpm / keyring backends    |               |
|                       +-------------+-------------+               |
|                                     |                             |
|                           +---------+---------+                   |
|                           | Hardware Security |  <-- Trust boundary|
|                           | Module (SE/TPM)   |                   |
|                           +-------------------+                   |
+-------------------------------------------------------------------+
```

**Trust boundaries:**
1. Between the Rust process and the hardware security module.
2. Between the application and libenclaveapp's API (trait contracts).
3. Between the keyring backend and the filesystem/keyring.
4. Between WSL and the Windows host (TPM bridge).

## Threats and Mitigations

### T1: Key material extraction (hardware backends)

**Threat:** An attacker attempts to extract the P-256 private key from the
Secure Enclave or TPM.

**Mitigation:** Hardware backends generate keys with non-exportable flags.
CryptoKit's `SecureEnclave.P256` keys and CNG's `Microsoft Platform Crypto
Provider` keys cannot be exported via any software API.

**Residual risk:** Physical attacks on the hardware security module. This
is out of scope -- we rely on Apple's and Microsoft's hardware guarantees.

### T2: Key material extraction (keyring backend)

**Threat:** An attacker extracts the keyring backend's private key.

**Mitigation:**
- Private keys are encrypted via the system keyring (D-Bus Secret Service).
- Key files are stored with 0600 permissions (owner-only).
- The keyring backend is documented as providing no hardware isolation.

**Residual risk:** Any process running as the same user can access the
keyring and decrypt the key file. Root can bypass all protections. The
keyring backend is intended for Linux environments where no TPM is
available. It provides defense-in-depth via keyring encryption but not
against a compromised user session.

### T3: ECIES ciphertext tampering

**Threat:** An attacker modifies ECIES ciphertext to alter the decrypted
plaintext.

**Mitigation:** ECIES uses AES-GCM which provides authenticated encryption.
Any modification to the ciphertext, nonce, ephemeral public key, or tag
causes decryption failure. The version byte (0x01) allows future format
changes without ambiguity.

**Residual risk:** None for integrity. An attacker can delete or replace
the entire ciphertext blob, causing a denial-of-service (application must
re-encrypt), but cannot produce a valid ciphertext without the public key.

### T4: ECIES ciphertext replay

**Threat:** An attacker replays an old ECIES ciphertext.

**Mitigation:** libenclaveapp does not include replay protection in the
ECIES format. The ciphertext is valid as long as the private key exists.
Applications are responsible for their own freshness checks (e.g., checking
timestamps in the encrypted payload).

**Residual risk:** Without application-level checks, an old ciphertext
decrypts successfully. This is by design -- libenclaveapp provides
encryption primitives, not a complete protocol.

### T5: Side-channel attacks

**Threat:** An attacker extracts key material through timing, power
analysis, or electromagnetic emanation from the hardware security module.

**Mitigation:** This is delegated to the hardware vendor. Apple's Secure
Enclave and TPM 2.0 implementations include side-channel protections.
The keyring backend uses the `p256` crate which provides constant-time
scalar operations.

**Residual risk:** Side-channel resistance depends on the hardware and
the `p256` crate implementation. Novel side-channel attacks against any
of these components are out of scope.

### T6: Root/admin compromise

**Threat:** An attacker with root access uses SE/TPM APIs to sign or
decrypt using the application's key.

**Mitigation:**
- Access policies require physical presence on backends that successfully
  apply a user-authentication policy during key creation.
- Without access policy: the key is usable by any process running as the
  user when the device is unlocked.

**Residual risk:** Root can bypass all software protections, inject code
into processes, or replace binaries. Hardware security modules protect
against offline attacks, not a fully compromised running system.

### T7: WSL bridge compromise

**Threat:** An attacker replaces the TPM bridge executable on the Windows
host.

**Mitigation:**
- Default bridge discovery is limited to trusted system locations.
- Any nonstandard bridge path must be supplied explicitly by the caller.
- The bridge communicates via JSON-RPC over stdin/stdout with
  base64-encoded payloads.

**Residual risk:** An attacker with admin rights on Windows can replace
the bridge. But admin rights already grant TPM access.

### T8: Platform trust assumptions

**Threat:** The underlying platform APIs (CryptoKit, CNG, Linux TPM
userspace) have vulnerabilities.

**Mitigation:** libenclaveapp uses stable, well-tested platform APIs:
- macOS: CryptoKit (Apple's modern crypto framework)
- Windows: CNG NCrypt/BCrypt (Microsoft's standard crypto API)
- Linux: `/dev/tpmrm0` via `tss-esapi` (TPM2 Software Stack)

**Residual risk:** Bugs in platform crypto libraries are outside
libenclaveapp's control. Keeping the OS and TPM firmware up to date is
the user's responsibility.

## Keyring Backend Limitations

The keyring backend (`enclaveapp-keyring`) exists for Linux environments
without a TPM. Its security properties are strictly weaker than hardware backends:

- Private keys are encrypted via the system keyring (D-Bus Secret Service).
- Any process running as the same user can access the keyring and decrypt the key.
- No physical-presence enforcement is possible.
- The keyring must be available; if it is not, the backend errors rather
  than falling back to plaintext storage.

## Integration Type Threat Models

The threats above (T1-T8) apply to the **storage layer** — how keys and encrypted data are protected at rest. The following section covers threats specific to each **delivery mechanism** — how secrets move from storage to the target application. See [DESIGN.md](DESIGN.md#application-integration-types) for the full type definitions.

### Type 1: HelperTool

**Security property:** Secrets never leave the enclave app's process. The target application calls back over a protocol (SSH agent socket, AWS `credential_process`, git credential helper) and receives only the operation result (a signature, a credential JSON blob), never the private key or long-lived secret material.

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| **D1: Agent socket hijack.** Another process connects to the agent socket and requests operations. | Unix socket permissions (0o700 directory, 0o600 socket). Named pipe ACLs on Windows. | Any process running as the same user can connect. Root can connect to any socket. Access policies (Touch ID, Windows Hello) mitigate by requiring physical presence per-operation. |
| **D2: `credential_process` output capture.** The credential JSON is written to the target app's stdin, which could be intercepted. | The parent process (e.g., AWS CLI) reads from a pipe — no intermediate files. `credential_process` is a standard AWS mechanism with documented security properties. | A debugger attached to the AWS CLI process can read the pipe. A compromised AWS CLI binary can exfiltrate credentials. |
| **D3: Protocol-level replay.** An attacker replays a captured credential response. | Credentials returned by `credential_process` have expiration times enforced by the consuming service (e.g., STS temporary credentials expire in 1-12 hours). SSH signatures include a nonce from the server, preventing replay. | Credentials are replayable within their validity window. This is inherent to the protocol, not a libenclaveapp issue. |

### Type 2: EnvInterpolation

**Security property:** Secrets are injected as environment variables via `execve()` and exist only in the target process's memory. The config file on disk contains only `${ENV_VAR}` placeholders, never the actual secret.

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| **D4: Environment variable leakage.** The secret env var is visible to the target process and its children. | `execve()` boundary — the env var is set directly on the child process, not exported in the shell. Child processes inherit env vars by default, but the target app's children are expected (npm spawns node, etc.). | `/proc/<pid>/environ` is readable by the same user on Linux. `ps eww` can show env vars. Any process running as the same user can read another process's environment. |
| **D5: Config file left with secret after crash.** If the enclave app crashes after writing a materialized config but before cleanup. | Type 2 never materializes secrets to disk — the config file always contains placeholders. The secret exists only in the env var. | No risk from this vector. Placeholder config files are safe to leave on disk. |
| **D6: Shell history capture.** If the user invokes the enclave app with secrets on the command line. | `--secret-stdin` is the recommended path. `--secret` CLI args carry a warning about process listing visibility. The enclave app itself never puts secrets in command-line arguments when launching the target. | If the user ignores the warning and uses `--secret`, the value is visible in `ps` and shell history. This is a user error, not a library defect. |

### Type 3: TempMaterializedConfig

**Security property:** Secrets are written to a temporary file with restricted permissions (0o600 on Unix), passed to the target app via a `--config` flag or env var, and deleted after the process exits.

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| **D7: Temp file read by another process.** Another process reads the temp file while the target app is running. | 0o600 permissions (owner-only read). Temp directory created with 0o700 permissions. Unique random directory name via `tempfile` crate. | Root can read any file. A process running as the same user can read the file if it knows or guesses the path. The window of exposure is the target process's lifetime. |
| **D8: Temp file not deleted after crash.** If the enclave app crashes or is killed (SIGKILL) before cleanup. | `TempConfig` uses `tempfile::TempDir` which is cleaned up by the OS on process exit for normal termination. `Drop` impl shreds (overwrites with zeros) the file contents before deletion. | SIGKILL prevents Drop from running. The temp file persists until the OS cleans `/tmp` (typically on reboot). The file has 0o600 permissions, limiting exposure. |
| **D9: Temp file on a shared/networked filesystem.** The temp directory is on NFS or a shared mount where permissions are not enforced. | Default temp directory is the OS-provided `$TMPDIR` which is typically local. | If the user overrides the temp directory to a network mount, permissions may not be enforced. This is a deployment configuration issue. |

### Type 4: CredentialSource

**Security property:** The enclave app secures credential *acquisition* (authenticated protocol with the credential provider) and *storage* (hardware-encrypted cache with lifecycle management). It provides **no delivery guardrails** — the credential is handed to the consumer in plaintext and the consumer controls what happens next.

| Threat | Mitigation | Residual risk |
|--------|-----------|---------------|
| **D10: Consumer stores credential insecurely.** The consumer writes the credential to a plaintext file, logs it, or exports it to a long-lived environment variable. | None from the Type 4 app. This is explicitly outside the security boundary. Documentation warns users to consume credentials through Type 1-3 apps where possible. | Any consumer can misuse the credential. This is the fundamental trade-off of Type 4: composability over control. |
| **D11: Credential interception during `get`.** The credential is returned on stdout and could be captured by a parent process or shell. | The credential is printed to stdout (not stderr), so it goes to the calling process's pipe, not the terminal. No intermediate files. | A debugger or compromised parent process can read the pipe. Shell command substitution (`$(sso-jwt get)`) holds the credential in shell memory briefly. |
| **D12: Cache oracle.** An attacker who cannot decrypt the cache can observe cache file timestamps and sizes to infer usage patterns. | Cache headers are unencrypted (timestamps, risk level) by design — this enables state classification without decryption. The encrypted payload does not leak content. | An attacker with read access to the cache directory can determine when credentials were last obtained and their risk level. No credential content is exposed. |
| **D13: Stale credential served from cache.** The cache serves an expired or revoked credential. | Lifecycle policy (Fresh/RefreshWindow/Grace/Expired) with configurable risk-level-based timeouts. Expired credentials trigger re-acquisition. | A revoked credential that hasn't expired by time will be served until the cache entry ages out. The credential provider (OAuth server, etc.) is responsible for revocation enforcement at the service level. |

### Memory Zeroization

**Security property:** Sensitive values (environment variable overrides, credential strings, temp file contents) are overwritten with zeros after use to reduce the window in which they are recoverable from process memory or disk.

| Mitigation | Scope |
|------------|-------|
| `run()` takes ownership of `LaunchRequest` and zeroizes `env_overrides` values after the child process exits. | Types 1-3 |
| `exec_with_credential_owned()` zeroizes the credential string after the child process exits. | Type 4 |
| `TempConfig::drop()` shreds (overwrites with zeros and syncs) the temp file before `TempDir` removes it from disk. | Type 3 |

**Residual risk:** The Rust allocator may leave copies of the original data in freed heap memory. The OS may page secret-containing memory to swap. Compiler optimizations could theoretically elide the zeroization, though the `zeroize` crate uses techniques to prevent this. These are standard limitations of userspace memory zeroization.

## Out of Scope

- **Physical attacks on hardware security modules.**
- **Kernel exploits on any platform.**
- **Supply chain attacks on Rust crates or platform libraries.**
- **Denial of service** (key deletion, cache corruption).
- **Application-level protocol vulnerabilities** (SSH, AWS STS, OAuth).
  libenclaveapp provides crypto primitives; protocol security is the
  consuming application's responsibility.
- **User error in Type 4 consumption.** Type 4 apps cannot control how
  consumers use credentials after delivery. Misuse (plaintext storage,
  logging, excessive sharing) is the consumer's responsibility.
