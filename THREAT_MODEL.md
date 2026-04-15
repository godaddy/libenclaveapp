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

## Out of Scope

- **Physical attacks on hardware security modules.**
- **Kernel exploits on any platform.**
- **Supply chain attacks on Rust crates or platform libraries.**
- **Denial of service** (key deletion, cache corruption).
- **Application-level protocol vulnerabilities** (SSH, AWS STS, OAuth).
  libenclaveapp provides crypto primitives; protocol security is the
  consuming application's responsibility.
