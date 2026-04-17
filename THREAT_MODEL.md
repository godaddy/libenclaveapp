# Threat Model

What can an attacker do, and what can't they do, against systems using libenclaveapp.

## What we protect

| Asset | Where it lives | Who can access it |
|---|---|---|
| P-256 private key (hardware) | Secure Enclave or TPM chip | Only the hardware — nobody can extract it, including root |
| P-256 private key (keyring) | Encrypted file on disk, KEK in system keyring | Any process running as the same user with keyring access |
| Cached credentials (encrypted) | ECIES ciphertext on disk | Anyone can read the file; only the HSM can decrypt it |
| Cache headers (unencrypted) | Timestamps, risk level in cache file | Anyone with read access — no secrets, but reveals usage patterns |

## What an attacker CANNOT do

**With hardware backends (Secure Enclave, TPM 2.0):**

- **Extract the private key.** It physically cannot leave the chip. There is no API, no debug mode, no root exploit that produces the key bytes. This is the entire point.
- **Use the key from another device.** Keys are device-bound. Stealing the disk image is useless.
- **Use the key without biometrics** (when access policy is set). Touch ID / Windows Hello is enforced by the hardware per-operation. Software cannot bypass this.
- **Tamper with encrypted data.** ECIES uses AES-256-GCM — any modification to the ciphertext is detected and rejected.

**With Type 1 delivery (HelperTool):**

- **Read the private key through the agent socket.** The agent returns signatures, never key material. The SSH agent protocol does not have a "give me the private key" command.

**With Type 2 delivery (EnvInterpolation):**

- **Find secrets in config files on disk.** Config files contain only `${ENV_VAR}` placeholders. The actual secret never touches disk.

## What an attacker CAN do

### Same-user attacks

An attacker running as the same user on the same machine can:

- **Connect to the agent socket and request signatures** (Type 1). Socket permissions and peer UID verification prevent cross-user access, but same-user access is inherent to Unix domain sockets. Access policies (Touch ID) are the only defense — without them, the attacker gets unlimited signatures.

- **Read environment variables of running processes** (Type 2). On Linux, `/proc/<pid>/environ` is readable by the same user. The secret exists in the target process's memory for its entire lifetime.

- **Read temp config files during the target process's lifetime** (Type 3). The file has restricted permissions and a randomized path, but a same-user attacker who can enumerate `/tmp` can find and read it.

- **Access the system keyring and decrypt software keys** (keyring backend). The keyring's access control boundary is the user session, not individual processes.

- **Call the Type 4 credential source and get a plaintext credential.** There are no delivery guardrails — `sso-jwt get` returns the JWT to whoever calls it.

### Root/admin attacks

Root can do everything a same-user attacker can, plus:

- **Attach a debugger to any process** and read secrets from memory.
- **Replace binaries** (enclave apps, target apps, bridge executables) with malicious versions.
- **Access the TPM/SE directly** and perform operations with the app's key (though still cannot extract it).

Hardware access policies (Touch ID, Windows Hello) are the only defense against root — they require physical presence that root cannot fake.

### Offline/physical attacks

- **Stolen disk:** Encrypted cache files are useless without the HSM. Hardware-backed keys cannot be extracted. Keyring-encrypted keys require the user's login session to decrypt.
- **Stolen device (locked):** HSM keys are inaccessible without device unlock. Access-policy-protected keys additionally require biometric/PIN.
- **Stolen device (unlocked):** Same as root access — keys are usable but not extractable.

### Network/protocol attacks

- **ECIES replay:** An old encrypted cache file decrypts successfully as long as the key exists. Applications must check timestamps in the decrypted payload. The library provides cache lifecycle management (`CredentialState`) but not replay prevention at the ECIES layer.
- **Credential replay:** Credentials returned by Type 1 apps (e.g., AWS STS tokens) are replayable within their validity window. SSH signatures include server nonces and cannot be replayed. Credential expiration is the protocol's responsibility.

### Bridge protocol surface

The WSL→Windows bridge is a JSON-RPC channel over a child process's stdin/stdout. Beyond binary replacement (above), the following protocol-level threats are worth naming.

- **Access-policy downgrade via legacy `biometric` field.** `BridgeRequest::params` (`crates/enclaveapp-bridge/src/protocol.rs`) accepts both the new `access_policy` enum and a legacy `biometric: bool` for backward compatibility. `effective_access_policy` reconciles them client-side. If a downgrade-attacker-controlled bridge server ignores `access_policy` and only reads `biometric`, a client that sends `BiometricOnly` could be silently served as `None`. Mitigation: ensure every deployed server honors `access_policy` when present.
- **Method-name confusion (`delete` vs `destroy`).** `bridge_destroy` sends the wire method name `"delete"` for backward compatibility. An older bridge server that only implements `"destroy"` will return an unknown-method error, leaving stale key state. Mitigation: documented in-code; bridge servers should accept both aliases.
- **Accepted guarantees** now explicit in the model: 64 KB response cap (`MAX_BRIDGE_RESPONSE_BYTES`), connection-scoped child kill-on-drop (`BridgeSession::Drop`), and a configurable `ENCLAVEAPP_BRIDGE_TIMEOUT_SECS` read-line timeout.

### FFI trust boundaries

Unsafe FFI surfaces are trusted by design but fragile.

- **Swift ↔ Rust bridge** (`crates/enclaveapp-apple/src/ffi.rs` + `crates/enclaveapp-apple/swift/bridge.swift`). Out-buffer convention relies on the caller sizing buffers correctly; `SE_ERR_BUFFER_TOO_SMALL` return codes can mask unrelated errors if the Rust side assumes buffer sizing is the only failure mode. Any change to Swift bridge signatures requires a coordinated Rust FFI update.
- **Windows CNG raw-pointer casts** (`crates/enclaveapp-windows/src/ui_policy.rs`). `NCRYPT_UI_POLICY` is passed to `NCryptSetProperty` via `&ui_policy as *const _ as *const u8` with a computed `size_of::<NCRYPT_UI_POLICY>()`. This is correct today but fragile to future struct layout changes.
- **NCRYPT UI policy is re-verified before every sign/decrypt.** `ui_policy::verify_ui_policy_matches` reads the CNG key's actual `NCRYPT_UI_POLICY` via `NCryptGetProperty` and rejects the operation if the `UI_PROTECT_KEY_FLAG` does not match the metadata's `AccessPolicy`. Closes the attacker-planted-TPM-key bypass: an attacker who writes a TPM key with the expected CNG name but no UI protect flag no longer gets signatures without Windows Hello. Integration testing on real Windows TPM hardware is still a tracked follow-up.

### Keychain and key-backend-specific risks

- **macOS `.handle` storage is currently plaintext (0600).** DESIGN.md describes AES-GCM wrapping under a Keychain-stored key as the handle-theft defense. That code is not yet merged (see `fix-macos.md`). Until it lands, a same-UID attacker can copy a `.handle` file and replay it against the SE from another process. The SE still refuses to export the private key itself.
- **Cross-binary Keychain access on macOS** for ad-hoc signed builds (Homebrew, `cargo build`) is controlled by binary hash; every rebuild invalidates the ACL and reprompts the user. This is the Keychain enforcing its ACL, not a vulnerability, but it becomes load-bearing once Keychain wrapping lands (see above).
- **Keyring D-Bus peer trust.** The keyring backend talks to the session D-Bus Secret Service. A hostile session bus (another process running as the user that took over the bus) could intercept unlock / decrypt requests. Same-user already-compromised session; out of scope for the library.

### Filesystem races and metadata tamper

- **No `O_NOFOLLOW` on metadata and handle reads.** Reads in `crates/enclaveapp-core/src/metadata.rs` and `crates/enclaveapp-apple/src/keychain.rs` use `std::fs::read`, which follows symlinks. A pre-planted symlink in the keys directory (same-UID attacker) can redirect a read or cause the library to parse an arbitrary file as key material. `atomic_write` uses `create_new` for the temp file (blocking symlink preemption of the temp), but the final `rename` target is not probed with `O_NOFOLLOW`.
- **Unauthenticated `.meta` files.** `KeyMeta.access_policy` is stored as plain JSON (`crates/enclaveapp-core/src/metadata.rs`). A same-UID attacker who edits `<label>.meta` to flip `BiometricOnly` → `None` changes what library-level policy checks see, even though the hardware key's policy was fixed at creation. Effect is: misleading UI / app-level checks on SE/TPM, full bypass on software / keyring backends. This is the backend of the sshenc and awsenc notes on the same subject.
- **Binding-store / temp-config file creation.** Both `JsonFileBindingStore::write_all_unlocked` (`crates/enclaveapp-app-adapter/src/binding_store.rs`) and `TempConfig::write` (`crates/enclaveapp-app-adapter/src/temp_config.rs`) now create their files with `OpenOptions::mode(0o600)` at creation time (Unix), eliminating the prior default-umask window between `create` and `chmod`. On Windows, ACLs continue to inherit from the parent directory, which the install flow narrows.

### Concurrent access

- **Key creation is cross-process serialized.** `DirLock::acquire`
  (`crates/enclaveapp-core/src/metadata.rs`) wraps every backend's
  `generate` / `generate_and_save_key` path before the hardware call:
  Apple (`crates/enclaveapp-apple/src/keychain.rs:136`), Windows CNG
  (`crates/enclaveapp-windows/src/state.rs:25`), keyring
  (`crates/enclaveapp-keyring/src/key_storage.rs:317`), Linux TPM
  (`crates/enclaveapp-linux-tpm/src/{sign,encrypt}.rs`), and
  test-software. Two concurrent first-run invocations block on the
  `fs4` flock and execute sequentially — no SE/TPM slot orphaning.
  `secret_store.rs` uses per-id shared/exclusive flocks for
  adapter-layer secret mutations.
- **Bridge serialization.** Two WSL-side clients hitting the Windows
  bridge concurrently depend on the server serializing requests.
  Clients do not hold a mutex across bridge sessions.

### Process hardening scope

`enclaveapp_core::process::harden_process()` (`crates/enclaveapp-core/src/process.rs`) applies:

- **All Unix:** `setrlimit(RLIMIT_CORE, 0)` — no core dumps.
- **Linux:** `prctl(PR_SET_DUMPABLE, 0)` — `/proc/<pid>/mem` becomes root-only; `ptrace` attach from non-root peers is denied by the kernel even within the same UID.
- **Linux:** `prctl(PR_SET_NO_NEW_PRIVS, 1)` — subsequent `exec*()` cannot gain setuid / file-capabilities privileges; shrinks the surface for wrapped-child-process escalation.

Still not applied: `RLIMIT_AS`, seccomp-bpf system-call filtering, macOS `ptrace(PT_DENY_ATTACH)` (deprecated and fragile), and Windows `SetProcessMitigationPolicy`. Root can still dump memory unconditionally on any platform. Applications that want stricter memory protection must add their own mitigations on top.

### Zeroize coverage

`zeroize` is applied to secret-bearing structures in the launcher (`crates/enclaveapp-app-adapter/src/launcher.rs`) and credential cache (`crates/enclaveapp-app-adapter/src/credential_cache.rs`). It is **not** applied to:

- in-memory P-256 private-key bytes loaded from the keyring / software backend
- intermediate signature / ECIES buffers
- `mlock`ed handle bytes on macOS

Consumer crates that care about tighter memory hygiene should wrap their own sensitive buffers. The SECURITY.md summary has been updated to reflect this.

### App-adapter surface

- **`<redacted>` sentinel.** `crates/enclaveapp-app-adapter/src/secret_store.rs` returns the literal string `"<redacted>"` from read-only stores to stand in for "we know a secret exists but won't hand it over." Consumers that propagate any non-empty return value as a secret will end up using the literal `"<redacted>"` as a password. Callers must compare against the `REDACTED_PLACEHOLDER` constant or adopt a typed return.
- **Launcher env inheritance.** `Launcher::launch` forwards the parent process's full environment plus `env_overrides` to the child, then zeroizes only the env vars it added. Secrets already present in the parent env are propagated unchanged and are not wiped. Documented as an accepted constraint — env-bearing secrets inherited from callers are the caller's responsibility.

### Credential cache header tamper

The cache header (version, magic, timestamps, risk level) in `crates/enclaveapp-app-adapter/src/credential_cache.rs` is unauthenticated. A same-UID attacker with file-write access can edit the header's risk level downward, which nominally extends the client-side `CredentialState` policy windows. The AES-GCM-protected body remains intact, so the attacker cannot decrypt the cached credential.

**Mitigations actually in place today:**

- **Consumer-side `max(header, config)`.** sso-jwt's `effective_cached_risk_level` (`sso-jwt-lib/src/cache.rs:57-59`) and awsenc's equivalent always take the greater of the header-written risk level and the configured minimum. Header downgrade alone cannot reduce the effective risk level below the config.
- **Server-side expiration is authoritative.** AWS STS credentials and SSO JWTs carry their own `Expiration` / `exp`; a rolled-back-header cache still expires at the real server-side time, not the header's.
- **Payload-embedded timestamps.** sso-jwt embeds `token_iat` and `session_start` inside the encrypted payload; awsenc embeds credential `expiration` inside the encrypted `AwsCredentials` JSON. Both consumers recheck these after decrypt, ignoring the unencrypted header's version.

**Not implemented (noted but deferred):** AES-GCM AAD binding of the header to the ciphertext. The cleanest construction would be to thread the full serialized header bytes into the `EncryptionStorage::encrypt` / `decrypt` path as additional authenticated data — any header edit would then fail decryption. Implementing it requires a trait signature change across all four backends (SE, CNG, keyring, software) and every consumer, plus an on-disk format break for the pre-AAD ciphertexts. Given the mitigations above already neutralize the practical risk level downgrade, this is tracked as future work rather than an active gap.

### Build-time trust

`crates/enclaveapp-apple/build.rs` invokes `xcrun`, `swiftc`, and `ar` from the developer's `$PATH` with no pinning or signature verification. Build-environment PATH compromise substitutes the Swift object that ends up statically linked into the binary. This is a developer-machine concern, not a user-runtime concern, but worth an explicit note so release tooling can pin to fixed toolchain paths in CI.

## What we explicitly don't protect against

- Physical attacks on hardware security modules (chip decapping, side-channel emanation)
- Kernel exploits or hypervisor escapes
- Supply chain attacks on Rust crates or platform crypto libraries
- Denial of service (key deletion, cache corruption, socket flooding)
- Application-level protocol vulnerabilities (SSH, AWS STS, OAuth, npm registry)
- User error in Type 4 consumption (exporting credentials to plaintext, logging them)

## Platform-specific notes

**macOS Keychain prompts:** On unsigned builds, the Keychain prompts once per binary hash change (e.g., after `brew upgrade`). Signed builds avoid this. This is the Keychain enforcing its ACL, not a vulnerability.

**WSL bridge:** Communicates over stdin/stdout of a child process. The client (`crates/enclaveapp-bridge/src/client.rs`) discovers the bridge only from a fixed-path list under `/mnt/c/Program Files/<app>/` and `/mnt/c/ProgramData/<app>/`. Replacing the binary at those paths requires Windows admin rights. The previous `which`-based PATH fallback was removed — a user-writable `$PATH` entry on the WSL side could otherwise substitute a malicious bridge binary. Request/response size is capped at 64 KB, the child is reaped via `BridgeSession::Drop`, and reads are bounded. There is still no Authenticode / `WinVerifyTrust` check on the resolved bridge binary; adding one is a tracked hardening gap for environments where the Windows host itself is semi-trusted.

**Keyring backend:** Exists for Linux without TPM. Strictly weaker than hardware backends. Any same-user process can access the keyring. No biometric enforcement. The keyring must be running; if not, the app errors rather than falling back to plaintext.
