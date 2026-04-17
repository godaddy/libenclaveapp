# macOS Secure Enclave: Implementation Plan

> **Status (2026-04-17):** Steps 1-6 (the unsigned / Path-2 keychain-
> wrapping pipeline) are **implemented and tested**. Steps 7-8 (the
> entitled / Path-1 flow) are **deferred** — they require a
> provisioning profile which cannot be tested from an unsigned or
> ad-hoc-signed binary. The unsigned path is sufficient for Homebrew
> and cargo-install distribution and closes the original
> `.handle` same-UID theft threat.



## Background

Read `CLAUDE.md` section "macOS Secure Enclave: Design & Findings" for full context. This plan implements the two-tier SE backend described there.

## Problem

The current macOS SE backend stores the CryptoKit `dataRepresentation` blob as a plaintext file (`.handle`, 0600 permissions). Any process running as the same user can read the blob and use the SE key. We need:

1. At-rest encryption of the blob using a Keychain-stored wrapping key
2. A future-proof path that uses native Keychain key items when entitlements are available

## Architecture

Two paths, tried in order. The entitled path is used when available (signed/provisioned apps); the unsigned path is the fallback for Homebrew builds.

### Path 1: Entitled (signed builds, future)

Uses Security.framework for full Keychain-native key lifecycle.

- **Create:** `SecKeyCreateRandomKey` with `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent: true`, `kSecAttrApplicationTag: "<app_name>/<label>"`
- **Use:** `SecItemCopyMatching` by application tag -> SecKey -> `SecKeyCreateSignature` / `SecKeyCopyKeyExchangeResult`
- **Delete:** `SecItemDelete` by application tag -- proper Keychain deletion
- **Detection:** Try `SecKeyCreateRandomKey` with `kSecAttrIsPermanent: true`. If it succeeds, use this path. If it fails with `-34018`, fall back to Path 2.
- **No `.handle` files** -- the key lives entirely in the Keychain
- **Requirement:** `keychain-access-groups` is a **restricted entitlement** enforced by AMFI (AppleMobileFileIntegrity). It requires a **provisioning profile**, not just a code signature. Tested: even an Apple Development certificate without a matching profile causes AMFI to kill the binary ("No matching profile found," AMFI error -413). Self-signed certificates will never satisfy this. This path is only viable for App Store, Enterprise, or Xcode-provisioned builds.

### Path 2: Unsigned (Homebrew builds, current target)

Uses CryptoKit for SE operations + Keychain `kSecClassGenericPassword` for at-rest blob protection.

- **Create:** CryptoKit `SecureEnclave.P256.*.PrivateKey()` -> get `dataRepresentation` blob -> generate random AES-256 wrapping key -> store wrapping key in Keychain as `kSecClassGenericPassword` (service: `com.libenclaveapp.<app_name>`, account: `<label>`) -> encrypt blob with AES-GCM -> write encrypted blob to `.handle` file
- **Use:** Read AES key from Keychain -> decrypt `.handle` -> reconstruct CryptoKit key -> sign/decrypt
- **Delete:** Delete Keychain entry (`SecItemDelete` by service/account) + delete `.handle` file

## Keychain Prompt Behavior (tested)

### How macOS Keychain access control works for `kSecClassGenericPassword`

- `kSecClassGenericPassword` add/find/update/delete works WITHOUT entitlements on unsigned/ad-hoc signed binaries
- `kSecUseDataProtectionKeychain: true` does NOT work -- fails with `-34018`. Use the legacy (file-based) keychain only
- The Keychain scopes access by the binary's **code signing identity**

### Prompt behavior by signing scenario

| Scenario | First run | After rebuild (same path) | Different binary (different path) |
|----------|-----------|--------------------------|-----------------------------------|
| Ad-hoc signed (default from `swiftc`/`rustc`) | No prompt | **Prompt** (code hash changed) | **Prompt** |
| Untrusted self-signed cert | No prompt | **Prompt** (code hash changed) | **Prompt** |
| Trusted signing identity (e.g., Apple Development) | No prompt | **No prompt** (identity unchanged) | **Prompt** |

Key finding: **a trusted signing identity eliminates all upgrade prompts.** The Keychain scopes access by identity, not code hash, when the binary is signed with a trusted cert.

### Tested and confirmed

- Ad-hoc: one "Always Allow" prompt per `brew upgrade` (per binary rebuild at same path). Subsequent runs silent until next upgrade.
- Trusted cert (Apple Development): zero prompts across any number of rebuilds at the same path. Completely transparent.
- Untrusted self-signed cert: same behavior as ad-hoc (prompt on rebuild).
- Cross-binary access (different path): always prompts, regardless of signing.
- Trusting a self-signed cert requires a system password dialog (`security add-trusted-cert`) -- cannot be automated silently in a Homebrew formula.
- **"Deny" is not permanent.** If user clicks "Deny" on the Keychain prompt, the operation fails with `-128` (`errSecUserCanceled`), but the next invocation prompts again. The user is never locked out.
- **"Always Allow" persists** for the current binary until the binary is replaced (e.g., `brew upgrade`). Then one new prompt on first use of the upgraded binary.
- **Unsigned-to-signed transition works.** If a Keychain item was created by an ad-hoc signed binary and a future version at the same path is signed with a real cert, one prompt appears. After "Always Allow," the signed identity has permanent access and no further upgrades prompt. Tested: ad-hoc write → Apple Development signed read → prompted once → access granted.

## Distribution Strategies

### Strategy A: Source-compiled via Homebrew (current)

User runs `brew install sshenc` which compiles from source. Binary is ad-hoc signed by the compiler.

- **UX:** One "Always Allow" Keychain prompt per `brew upgrade`
- **Security:** Keychain blocks cross-binary access. AES-encrypted blob on disk.
- **Effort:** Implement Path 2 only. No signing infrastructure needed.

### Strategy B: Binary bottles signed in CI/CD (recommended future path)

You sign release binaries in CI/CD with a consistent signing identity. Users install via Homebrew bottles (pre-compiled binaries). This eliminates upgrade prompts but does NOT unlock the entitled path (Path 1) — that requires provisioning profiles.

- **UX with self-signed cert:** One trust prompt on first install (`security add-trusted-cert` or system dialog), then zero Keychain prompts ever across all upgrades. Still uses Path 2 (CryptoKit + AES wrapping).
- **UX with Apple Developer ID:** Zero prompts ever. macOS trusts Developer ID signed binaries out of the box via Apple's root CA chain. Still Path 2.
- **Security:** Same as Strategy A, plus binary integrity verification via code signature.
- **Effort:** Set up CI/CD signing pipeline. Create or use a code signing certificate. Produce bottles.

**Important:** Signing with a trusted cert eliminates **Keychain access prompts** (the "Always Allow" dialog on upgrade) but does NOT enable the entitled path. `keychain-access-groups` requires a provisioning profile (tested: AMFI kills the binary with error -413 even with a valid Apple Development cert). Path 1 is only viable for App Store / Enterprise / Xcode-provisioned distribution.

If you use your existing `Apple Development: Jeremiah Gowdy` identity in CI/CD, users would get zero Keychain prompts from day one. Apple's CA chain handles trust automatically. The binary still uses Path 2 (CryptoKit + AES wrapping + Keychain generic password), but the Keychain access is transparent across upgrades because the signing identity is stable.

### Strategy C: Optional local cert setup

Offer a post-install command: `sshenc setup-signing` that:
1. Creates a self-signed code signing cert in the user's login keychain
2. Prompts the user to trust it (one system password dialog)
3. Re-signs the installed binary with the new cert
4. All future upgrades are re-signed with the same cert during `brew upgrade` via a post-install hook

- **UX:** One explicit setup step, then zero prompts forever
- **Security:** Same as Strategy A
- **Effort:** Additional tooling for cert management + Homebrew formula hooks
- **Risk:** Fragile. Homebrew formula hooks, cert management, and re-signing are all potential failure points

## Implementation Steps

### Step 1: Add Keychain generic-password helpers to the Swift bridge

Add to `crates/enclaveapp-apple/swift/bridge.swift`:

```swift
@_cdecl("enclaveapp_keychain_store")
public func enclaveapp_keychain_store(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret: UnsafePointer<UInt8>, _ secret_len: Int32
) -> Int32

@_cdecl("enclaveapp_keychain_load")
public func enclaveapp_keychain_load(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret_out: UnsafeMutablePointer<UInt8>, _ secret_len: UnsafeMutablePointer<Int32>
) -> Int32

@_cdecl("enclaveapp_keychain_delete")
public func enclaveapp_keychain_delete(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32
) -> Int32
```

These operate on `kSecClassGenericPassword` items in the legacy (file-based) keychain with `kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Do NOT use `kSecUseDataProtectionKeychain: true` -- that fails with `-34018` on unsigned builds.

On `store`: delete any existing entry first, then `SecItemAdd`.
On `load`: `SecItemCopyMatching` with `kSecReturnData: true`.
On `delete`: `SecItemDelete` by service + account.

### Step 2: Add Rust FFI declarations

Add to `crates/enclaveapp-apple/src/ffi.rs`:

```rust
pub fn enclaveapp_keychain_store(
    service: *const u8, service_len: i32,
    account: *const u8, account_len: i32,
    secret: *const u8, secret_len: i32,
) -> i32;

pub fn enclaveapp_keychain_load(
    service: *const u8, service_len: i32,
    account: *const u8, account_len: i32,
    secret_out: *mut u8, secret_len: *mut i32,
) -> i32;

pub fn enclaveapp_keychain_delete(
    service: *const u8, service_len: i32,
    account: *const u8, account_len: i32,
) -> i32;
```

### Step 3: Add AES-256-GCM blob wrapping in Rust

In `crates/enclaveapp-apple/src/keychain.rs`, add helper functions:

```rust
fn generate_wrapping_key() -> [u8; 32]  // 32 random bytes via rand
fn encrypt_blob(wrapping_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8>  // AES-256-GCM
fn decrypt_blob(wrapping_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>>
```

Use the `aes-gcm` crate (already a workspace dependency). The encrypted `.handle` format: `[12-byte nonce][ciphertext][16-byte GCM tag]`.

The wrapping key is stored/loaded via the Keychain FFI helpers:
- Service: `"com.libenclaveapp.<app_name>"`
- Account: `"<label>"`

### Step 4: Modify `generate_and_save_key` (unsigned path)

In `keychain.rs`, update `generate_and_save_key`:

1. Call CryptoKit to create the SE key (unchanged)
2. Generate a random 32-byte AES wrapping key
3. Store the wrapping key in the Keychain via `enclaveapp_keychain_store`
4. Encrypt the `dataRepresentation` blob with the wrapping key
5. Write the encrypted blob to `.handle`
6. On failure: delete the Keychain entry + clean up files

### Step 5: Modify `load_handle`

Update to:
1. Read the encrypted `.handle` file
2. Load the wrapping key from the Keychain via `enclaveapp_keychain_load`
3. Decrypt and return the plaintext `dataRepresentation`

For backward compatibility with existing unencrypted `.handle` files: try decrypting first; if that fails (e.g., file is too short for the AES format), fall back to reading as raw `dataRepresentation`. This allows a transparent migration.

### Step 6: Modify `delete_key`

Update to:
1. Delete the Keychain entry via `enclaveapp_keychain_delete`
2. Delete the `.handle` file
3. Delete `.pub`, `.meta`, `.ssh.pub` files

### Step 7: Add entitled path (Path 1)

This can be a separate module or integrated into the existing keychain module behind a runtime check.

Add to `bridge.swift`:
```swift
@_cdecl("enclaveapp_se_create_permanent_key")
// SecKeyCreateRandomKey + kSecAttrIsPermanent + kSecAttrApplicationTag + kSecAttrTokenID SE
// Returns public key. Key lives in Keychain.

@_cdecl("enclaveapp_se_load_permanent_key")
// SecItemCopyMatching by tag, returns SecKey ref for use

@_cdecl("enclaveapp_se_delete_permanent_key")
// SecItemDelete by tag

@_cdecl("enclaveapp_se_sign_permanent")
// SecKeyCreateSignature

@_cdecl("enclaveapp_se_decrypt_permanent")
// SecKeyCopyKeyExchangeResult for ECDH
```

The Rust side would try these first. If `enclaveapp_se_create_permanent_key` returns a "missing entitlement" error code, set a flag and fall back to the CryptoKit path for all subsequent operations.

### Step 8: Detection logic in `generate_and_save_key`

```rust
pub fn generate_and_save_key(...) -> Result<Vec<u8>> {
    // Try entitled path
    match try_permanent_key_create(app_name, label, key_type, policy) {
        Ok(pub_key) => return Ok(pub_key),
        Err(Error::MissingEntitlement) => {
            // Fall through to unsigned path
        }
        Err(e) => return Err(e),
    }

    // Unsigned path: CryptoKit + AES wrapping + Keychain generic password
    let (pub_key, data_rep) = generate_key(key_type, policy.as_ffi_value())?;
    let wrapping_key = generate_wrapping_key();
    keychain_store(app_name, label, &wrapping_key)?;
    let encrypted = encrypt_blob(&wrapping_key, &data_rep);
    // ... write encrypted blob to .handle, save pub/meta ...
}
```

## Dependencies

- `aes-gcm` -- already a workspace dependency
- `rand` -- already available via `p256` crate dependencies
- No new crate dependencies needed

## Files Changed

- `crates/enclaveapp-apple/swift/bridge.swift` -- Keychain helpers + entitled SE key functions
- `crates/enclaveapp-apple/src/ffi.rs` -- new FFI declarations
- `crates/enclaveapp-apple/src/keychain.rs` -- wrapping key management, encrypted blob I/O, two-tier create/load/delete
- `crates/enclaveapp-apple/src/sign.rs` -- may need updates if entitled path uses different sign function
- `crates/enclaveapp-apple/src/encrypt.rs` -- same for encrypt/decrypt
- `crates/enclaveapp-apple/Cargo.toml` -- add `aes-gcm` and `rand` dependencies if not already present

## Testing

- Unit tests for AES blob encrypt/decrypt round-trip
- Unit tests for Keychain store/load/delete (these call real Keychain -- they will work on macOS CI)
- Integration test: full create -> use -> delete cycle for unsigned path
- Manual test: rebuild binary at same path, verify one "Always Allow" prompt (ad-hoc signed)
- Manual test: rebuild binary signed with trusted identity, verify NO prompt
- Manual test: different binary at different path, verify prompt blocks access
- Existing tests must continue to pass (test-software backend, Windows stubs, etc.)

## What NOT to do

- Do NOT use `kSecUseDataProtectionKeychain: true` -- fails with `-34018` on unsigned builds
- Do NOT use `kSecValueData` or `kSecValuePersistentRef` as query keys for SE keys -- they don't work as expected (see CLAUDE.md findings)
- Do NOT claim the entitled path works until it is tested with a signed binary + provisioning profile
- Do NOT break backward compatibility with existing unencrypted `.handle` files -- detect and migrate transparently
- Do NOT attempt to trust a self-signed certificate programmatically during `brew install` -- `security add-trusted-cert` requires a system password dialog that cannot be automated silently
