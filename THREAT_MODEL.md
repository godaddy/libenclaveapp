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

## What we explicitly don't protect against

- Physical attacks on hardware security modules (chip decapping, side-channel emanation)
- Kernel exploits or hypervisor escapes
- Supply chain attacks on Rust crates or platform crypto libraries
- Denial of service (key deletion, cache corruption, socket flooding)
- Application-level protocol vulnerabilities (SSH, AWS STS, OAuth, npm registry)
- User error in Type 4 consumption (exporting credentials to plaintext, logging them)

## Platform-specific notes

**macOS Keychain prompts:** On unsigned builds, the Keychain prompts once per binary hash change (e.g., after `brew upgrade`). Signed builds avoid this. This is the Keychain enforcing its ACL, not a vulnerability.

**WSL bridge:** Communicates over stdin/stdout of a child process. Replacing the bridge binary requires Windows admin rights — which already grants direct TPM access.

**Keyring backend:** Exists for Linux without TPM. Strictly weaker than hardware backends. Any same-user process can access the keyring. No biometric enforcement. The keyring must be running; if not, the app errors rather than falling back to plaintext.
