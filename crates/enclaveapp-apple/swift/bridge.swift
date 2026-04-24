// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

// CryptoKit Secure Enclave bridge for enclaveapp.
//
// Exposes C functions callable from Rust for SE key lifecycle:
// - Check Secure Enclave availability
// - Generate signing and encryption keys
// - Extract public keys from data representations
// - Sign data (ECDSA P-256)
// - Encrypt/decrypt data (ECIES: ECDH + AES-GCM)
//
// Keys are persisted via CryptoKit's dataRepresentation, which is an opaque
// blob containing a handle to the SE key. The actual private key material
// never leaves the Secure Enclave.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Result codes

let SE_OK: Int32 = 0
let SE_ERR_GENERATE: Int32 = 1
let SE_ERR_LOAD: Int32 = 2
let SE_ERR_SIGN: Int32 = 3
/// Returned **only** when a caller-supplied out-buffer is too small to
/// hold the result. The caller is expected to resize per the
/// `*_len.pointee` out-value and retry. It is a **contract error** to
/// use this code for any other failure mode — the Rust side loops on
/// it (expanding the buffer) and a misuse would turn a real error into
/// a retry storm. See `keychain.rs::generate_signing_with_retry` for
/// the retry discipline on the consumer side.
let SE_ERR_BUFFER_TOO_SMALL: Int32 = 4
let SE_ERR_NOT_AVAILABLE: Int32 = 5
let SE_ERR_ENCRYPT: Int32 = 6
let SE_ERR_DECRYPT: Int32 = 7
let SE_ERR_DELETE: Int32 = 8
let SE_ERR_KEYCHAIN_STORE: Int32 = 9
let SE_ERR_KEYCHAIN_LOAD: Int32 = 10
let SE_ERR_KEYCHAIN_DELETE: Int32 = 11
let SE_ERR_KEYCHAIN_NOT_FOUND: Int32 = 12

// MARK: - ECIES format constants

let ECIES_VERSION: UInt8 = 0x01
let ECIES_HEADER_SIZE = 1 + 65 + 12  // version + ephemeral pubkey + nonce
let ECIES_TAG_SIZE = 16

// MARK: - Helper: access control

func makeAccessControl(_ authPolicy: Int32) -> SecAccessControl? {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    switch authPolicy {
    case 1: flags.insert(.userPresence)
    case 2: flags.insert(.biometryAny)
    case 3: flags.insert(.devicePasscode)
    default: return nil
    }
    return SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
    )
}

// MARK: - Helper: copy uncompressed public key

func copyUncompressedPubKey(
    _ rawPub: Data,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let uncompressedLen: Int32 = 65
    if pub_key_len.pointee < uncompressedLen {
        pub_key_len.pointee = uncompressedLen
        return SE_ERR_BUFFER_TOO_SMALL
    }
    pub_key_out[0] = 0x04
    rawPub.copyBytes(to: pub_key_out + 1, count: 64)
    pub_key_len.pointee = uncompressedLen
    return SE_OK
}

// MARK: - Helper: copy data representation

func copyDataRep(
    _ dataRep: Data,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let dataRepCount = Int32(dataRep.count)
    if data_rep_len.pointee < dataRepCount {
        data_rep_len.pointee = dataRepCount
        return SE_ERR_BUFFER_TOO_SMALL
    }
    dataRep.copyBytes(to: data_rep_out, count: dataRep.count)
    data_rep_len.pointee = dataRepCount
    return SE_OK
}

// MARK: - Check availability

@_cdecl("enclaveapp_se_available")
public func enclaveapp_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

// MARK: - Signing key operations

/// Generate a new Secure Enclave P-256 signing key.
/// Returns the data representation (opaque blob for persistence) and raw public key.
///
/// - pub_key_out: buffer for 65-byte uncompressed public key (0x04 || X || Y)
/// - pub_key_len: in/out, must be >= 65
/// - data_rep_out: buffer for data representation
/// - data_rep_len: in/out, must be large enough (typically ~300 bytes)
/// - auth_policy: 0 = no auth, 1 = any, 2 = biometric only, 3 = password only
@_cdecl("enclaveapp_se_generate_signing_key")
public func enclaveapp_se_generate_signing_key(
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>,
    _ auth_policy: Int32
) -> Int32 {
    return traceDuration("se_generate_signing_key auth_policy=\(auth_policy)") {
        guard SecureEnclave.isAvailable else {
            return SE_ERR_NOT_AVAILABLE
        }

        do {
            let key: SecureEnclave.P256.Signing.PrivateKey
            if auth_policy != 0 {
                guard let accessControl = makeAccessControl(auth_policy) else {
                    return SE_ERR_GENERATE
                }
                key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
            } else {
                key = try SecureEnclave.P256.Signing.PrivateKey()
            }

            let rc = copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
            if rc != SE_OK { return rc }

            return copyDataRep(key.dataRepresentation, data_rep_out, data_rep_len)
        } catch {
            return SE_ERR_GENERATE
        }
    }
}

/// Extract the public key from a signing key's persisted data representation.
@_cdecl("enclaveapp_se_signing_public_key")
public func enclaveapp_se_signing_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    return traceDuration("se_signing_public_key") {
        do {
            let data = Data(bytes: data_rep, count: Int(data_rep_len))
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
            return copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
        } catch {
            return SE_ERR_LOAD
        }
    }
}

/// Sign a message using a signing key loaded from its data representation.
/// CryptoKit hashes the message with SHA-256 internally.
/// Returns a DER-encoded ECDSA signature.
@_cdecl("enclaveapp_se_sign")
public func enclaveapp_se_sign(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ message: UnsafePointer<UInt8>,
    _ message_len: Int32,
    _ sig_out: UnsafeMutablePointer<UInt8>,
    _ sig_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    return traceDuration("se_sign message_len=\(message_len)") {
        do {
            let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)

            let msgData = Data(bytes: message, count: Int(message_len))
            let signature = try key.signature(for: msgData)

            let derSig = signature.derRepresentation
            let derCount = Int32(derSig.count)
            if sig_len.pointee < derCount {
                sig_len.pointee = derCount
                return SE_ERR_BUFFER_TOO_SMALL
            }
            derSig.copyBytes(to: sig_out, count: derSig.count)
            sig_len.pointee = derCount

            return SE_OK
        } catch {
            return SE_ERR_SIGN
        }
    }
}

// MARK: - Encryption key operations

/// Generate a new Secure Enclave P-256 key agreement key.
/// Returns the data representation and raw public key.
@_cdecl("enclaveapp_se_generate_encryption_key")
public func enclaveapp_se_generate_encryption_key(
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>,
    _ auth_policy: Int32
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        return SE_ERR_NOT_AVAILABLE
    }

    do {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if auth_policy != 0 {
            guard let accessControl = makeAccessControl(auth_policy) else {
                return SE_ERR_GENERATE
            }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        }

        let rc = copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
        if rc != SE_OK { return rc }

        return copyDataRep(key.dataRepresentation, data_rep_out, data_rep_len)
    } catch {
        return SE_ERR_GENERATE
    }
}

/// Extract the public key from an encryption key's persisted data representation.
@_cdecl("enclaveapp_se_encryption_public_key")
public func enclaveapp_se_encryption_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let data = Data(bytes: data_rep, count: Int(data_rep_len))
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
        return copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
    } catch {
        return SE_ERR_LOAD
    }
}

/// Delete a Secure Enclave key referenced by its persistent data representation.
@_cdecl("enclaveapp_se_delete_key")
public func enclaveapp_se_delete_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32
) -> Int32 {
    let keyRef = Data(bytes: data_rep, count: Int(data_rep_len))
    let query: [String: Any] = [kSecValuePersistentRef as String: keyRef]
    let status = SecItemDelete(query as CFDictionary)
    keychainTrace(
        "op=se_key_delete data_rep_len=\(data_rep_len) status=\(status)"
    )

    switch status {
    case errSecSuccess, errSecItemNotFound:
        return SE_OK
    default:
        return SE_ERR_DELETE
    }
}

/// ECIES encrypt using the SE key's public key.
///
/// 1. Load encryption key from data_rep to get its public key
/// 2. Generate ephemeral P256.KeyAgreement.PrivateKey (in software, NOT in SE)
/// 3. ECDH shared secret between ephemeral private key and SE key's public key
/// 4. Derive symmetric key via X9.63 KDF with ephemeral pubkey as sharedInfo
/// 5. AES-GCM seal
/// 6. Output: [0x01 version] [65-byte ephemeral pubkey] [12-byte nonce] [ciphertext] [16-byte tag]
@_cdecl("enclaveapp_se_encrypt")
public func enclaveapp_se_encrypt(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintext_len: Int32,
    _ ciphertext_out: UnsafeMutablePointer<UInt8>,
    _ ciphertext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        // Load SE key to get its public key
        let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
        let sePubKey = seKey.publicKey

        // Generate ephemeral key pair (in software)
        let ephemeralKey = P256.KeyAgreement.PrivateKey()

        // ECDH: ephemeral private key + SE public key
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: sePubKey)

        // Derive symmetric key with ephemeral pubkey as sharedInfo
        let ephemeralPubRaw = ephemeralKey.publicKey.x963Representation
        let symKey = sharedSecret.x963DerivedSymmetricKey(
            using: SHA256.self,
            sharedInfo: ephemeralPubRaw,
            outputByteCount: 32
        )

        // AES-GCM seal
        let ptData = Data(bytes: plaintext, count: Int(plaintext_len))
        let sealedBox = try AES.GCM.seal(ptData, using: symKey)

        // Build output: version(1) + ephemeral_pub(65) + nonce(12) + ciphertext + tag(16)
        var output = Data()
        output.append(ECIES_VERSION)
        output.append(ephemeralPubRaw)  // 65 bytes (0x04 || x || y)
        output.append(contentsOf: sealedBox.nonce)
        output.append(sealedBox.ciphertext)
        output.append(sealedBox.tag)

        let outputCount = Int32(output.count)
        if ciphertext_len.pointee < outputCount {
            ciphertext_len.pointee = outputCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        output.copyBytes(to: ciphertext_out, count: output.count)
        ciphertext_len.pointee = outputCount

        return SE_OK
    } catch {
        return SE_ERR_ENCRYPT
    }
}

/// ECIES decrypt using the SE key's private key.
///
/// 1. Parse ciphertext: version(1) + ephemeral_pub(65) + nonce(12) + encrypted + tag(16)
/// 2. Reconstruct ephemeral public key
/// 3. ECDH: SE private key + ephemeral public key
/// 4. Derive same symmetric key
/// 5. AES-GCM open
@_cdecl("enclaveapp_se_decrypt")
public func enclaveapp_se_decrypt(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_len: Int32,
    _ plaintext_out: UnsafeMutablePointer<UInt8>,
    _ plaintext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let ctLen = Int(ciphertext_len)
        let minLen = ECIES_HEADER_SIZE + ECIES_TAG_SIZE
        guard ctLen >= minLen else {
            return SE_ERR_DECRYPT
        }

        let ctData = Data(bytes: ciphertext, count: ctLen)

        // Parse version
        guard ctData[0] == ECIES_VERSION else {
            return SE_ERR_DECRYPT
        }

        // Parse ephemeral public key (65 bytes x963)
        let ephemeralPubRaw = ctData[1..<66]
        let ephemeralPubKey = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPubRaw)

        // Parse nonce (12 bytes)
        let nonce = try AES.GCM.Nonce(data: ctData[66..<78])

        // Parse ciphertext + tag
        let encryptedLen = ctLen - ECIES_HEADER_SIZE - ECIES_TAG_SIZE
        let encrypted = ctData[78..<(78 + encryptedLen)]
        let tag = ctData[(78 + encryptedLen)..<ctLen]

        // Load SE key and perform ECDH
        let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
        let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
        let sharedSecret = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)

        // Derive same symmetric key with ephemeral pubkey as sharedInfo
        let symKey = sharedSecret.x963DerivedSymmetricKey(
            using: SHA256.self,
            sharedInfo: ephemeralPubRaw,
            outputByteCount: 32
        )

        // AES-GCM open
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symKey)

        let ptCount = Int32(plaintext.count)
        if plaintext_len.pointee < ptCount {
            plaintext_len.pointee = ptCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        plaintext.copyBytes(to: plaintext_out, count: plaintext.count)
        plaintext_len.pointee = ptCount

        return SE_OK
    } catch {
        return SE_ERR_DECRYPT
    }
}

// MARK: - Keychain helpers (generic-password wrapping keys)
//
// These helpers wrap the legacy (file-based) keychain's
// kSecClassGenericPassword items. Rust calls them to store, load, and
// delete the 32-byte AES wrapping key used to encrypt the SE
// dataRepresentation before it's written to `.handle` on disk.
//
// DO NOT set `kSecUseDataProtectionKeychain: true` — on unsigned builds
// (Homebrew, cargo build) the modern Data Protection keychain returns
// errSecMissingEntitlement (-34018). The legacy keychain accepts
// unsigned callers.
//
// Items are created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
// the device must be unlocked to read them, and they do NOT sync via
// iCloud / migrate across devices.

/// Open the invoking user's login keychain by explicit path.
///
/// Security.framework's default-keychain lookup goes through
/// `CFPreferences`, which is keyed off the process's `$HOME`. A
/// caller that overrides `$HOME` (integration tests via `assert_cmd`,
/// `awsenc serve` invoked by the AWS CLI under a launchd sandbox,
/// cron, etc.) gets `errSecNoDefaultKeychain` back, at which point
/// `SecItemAdd` falls into a system-modal
/// "A keychain cannot be found to store '<account>'" alert.
///
/// We bypass that entirely: `getpwuid(getuid())` returns the real
/// user's home directory from the password database regardless of
/// `$HOME`, and `SecKeychainOpen` on
/// `~/Library/Keychains/login.keychain-db` produces a handle that
/// subsequent `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`
/// calls use via `kSecUseKeychain` / `kSecMatchSearchList`. The
/// first-run "Always Allow" ACL prompt (a SecTrust decision driven
/// by the item op itself, not by default-keychain lookup) still
/// fires normally — unsigned-build UX is preserved.
///
/// `SecKeychainOpen` is deprecated alongside `SecKeychain` but is
/// still the only API that reaches the legacy file-based keychain;
/// the modern Data Protection keychain is unavailable on unsigned
/// builds (see the top-of-module comment).
// MARK: - Crypto-op timing and prompt-detection instrumentation
//
// Every FFI entrypoint below is wrapped with `traceDuration`, which
// measures the wall-clock time of the whole Apple call (including
// CryptoKit's internal `SecKeyCreateSignature` / `SecItemAdd` / …
// invocations). Two outputs come from that measurement:
//
// 1. **Always-on, shippable warning**: if an op takes longer than
//    the threshold (default 1000 ms, overridable via
//    `ENCLAVEAPP_SLOW_OP_THRESHOLD_MS`), write a one-line warning to
//    stderr. Human-visible password / Touch ID / passcode prompts
//    block for ≥1000 ms so any crossing of the threshold almost
//    certainly means a sheet appeared. Normal cold-cache or
//    cold-process starts are well under this.
// 2. **Opt-in verbose trace**: when `ENCLAVEAPP_KEYCHAIN_TRACE=1`
//    is set, write a line for every op (under the threshold or
//    above) and every inner `SecItem*` call with its OSStatus. Used
//    for exhaustive debugging.
//
// The warning branch is cheap and always compiled in; it's safe to
// ship. Users who never hit a prompt never see output.

private let slowCryptoOpThresholdMs: UInt64 = {
    if let raw = ProcessInfo.processInfo.environment["ENCLAVEAPP_SLOW_OP_THRESHOLD_MS"],
       let parsed = UInt64(raw) {
        return parsed
    }
    return 1000
}()

private let keychainTraceEnabled: Bool = {
    ProcessInfo.processInfo.environment["ENCLAVEAPP_KEYCHAIN_TRACE"] == "1"
}()

/// Emit a detail line (inner `SecItem*` OSStatus, etc.) when verbose
/// trace mode is on. No-op otherwise.
private func keychainTrace(_ line: @autoclosure () -> String) {
    guard keychainTraceEnabled else { return }
    FileHandle.standardError.write(Data(("keychain_trace: " + line() + "\n").utf8))
}

/// Measure the duration of `body`. On crossing the slow-op threshold
/// emit a shippable warning (suspected prompt); in verbose mode,
/// always emit a timing line for every call.
private func traceDuration<T>(_ op: String, _ body: () -> T) -> T {
    let start = DispatchTime.now()
    let result = body()
    let elapsed_ms =
        (DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000

    if elapsed_ms >= slowCryptoOpThresholdMs {
        FileHandle.standardError.write(Data((
            "enclaveapp: crypto op '\(op)' took \(elapsed_ms)ms " +
            "(threshold=\(slowCryptoOpThresholdMs)ms) — likely triggered a " +
            "password / biometric prompt. Set ENCLAVEAPP_KEYCHAIN_TRACE=1 " +
            "for per-call detail.\n"
        ).utf8))
    } else if keychainTraceEnabled {
        FileHandle.standardError.write(Data(
            "keychain_trace: op=\(op) elapsed_ms=\(elapsed_ms)\n".utf8
        ))
    }
    return result
}

/// Return `true` when Security.framework can locate a default
/// keychain for this process. Query-only — it never prompts.
private func hasDefaultKeychain() -> Bool {
    var kc: SecKeychain?
    let status = SecKeychainCopyDefault(&kc)
    return status == errSecSuccess && kc != nil
}

/// Open the invoking user's login keychain by explicit absolute path
/// and try a silent empty-password unlock.
private func openLoginKeychain() -> SecKeychain? {
    guard let pw = getpwuid(getuid()) else {
        return nil
    }
    let home = String(cString: pw.pointee.pw_dir)
    // Modern macOS stores the login keychain as `.keychain-db`; older
    // installs may still have `.keychain`. Try both so migrated
    // systems aren't broken.
    let candidates = [
        "\(home)/Library/Keychains/login.keychain-db",
        "\(home)/Library/Keychains/login.keychain",
    ]
    for path in candidates {
        var kc: SecKeychain?
        if SecKeychainOpen(path, &kc) == errSecSuccess, let kc = kc {
            // Best-effort silent unlock with the empty password.
            // Interactive dev sessions are already unlocked (no-op);
            // headless contexts whose keychain is locked but has no
            // password get unlocked here. Any real-password failure
            // surfaces through the subsequent op.
            _ = SecKeychainUnlock(kc, 0, nil, true)
            return kc
        }
    }
    return nil
}

private func makeServiceData(_ service: UnsafePointer<UInt8>, _ len: Int32) -> Data {
    return Data(bytes: service, count: Int(len))
}

private func makeAccountString(_ account: UnsafePointer<UInt8>, _ len: Int32) -> String? {
    let bytes = Data(bytes: account, count: Int(len))
    return String(data: bytes, encoding: .utf8)
}

private func makeServiceString(_ service: UnsafePointer<UInt8>, _ len: Int32) -> String? {
    let bytes = Data(bytes: service, count: Int(len))
    return String(data: bytes, encoding: .utf8)
}

/// Store (or replace) an opaque secret in the keychain as a generic
/// password. Any existing entry with the same service+account pair is
/// removed first, so the call is effectively an upsert.
///
/// When `use_user_presence` is non-zero the item is protected by a
/// `.userPresence` access-control flag (biometric-or-device-passcode)
/// instead of the default code-signature ACL. Accessing the item then
/// triggers a LocalAuthentication prompt instead of the legacy keychain
/// "Always Allow" dialog, and the authorization is tied to the user
/// rather than to a specific binary signature — so rebuilding an
/// unsigned binary no longer invalidates access.
@_cdecl("enclaveapp_keychain_store")
public func enclaveapp_keychain_store(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret: UnsafePointer<UInt8>, _ secret_len: Int32,
    _ use_user_presence: Int32
) -> Int32 {
    return traceDuration("keychain_store userPresence=\(use_user_presence)") {
      guard let serviceStr = makeServiceString(service, service_len) else {
        return SE_ERR_KEYCHAIN_STORE
    }
    guard let accountStr = makeAccountString(account, account_len) else {
        return SE_ERR_KEYCHAIN_STORE
    }
    let secretData = Data(bytes: secret, count: Int(secret_len))

    // Prefer Security.framework's implicit default-keychain routing
    // when a default is available (standard interactive sessions, and
    // GitHub Actions macOS runners). That path reaches the Data
    // Protection keychain on unsigned builds and does NOT trigger the
    // legacy-keychain ACL prompt that blocks headless CI. Only when
    // no default is reachable (typical of `$HOME`-overridden test
    // contexts and launchd sandboxes) do we fall back to opening the
    // login keychain by explicit absolute path and pinning the op to
    // it via `kSecUseKeychain` / `kSecMatchSearchList`.
    let useExplicit = !hasDefaultKeychain()
    let kc: SecKeychain? = useExplicit ? openLoginKeychain() : nil
    if useExplicit && kc == nil {
        return SE_ERR_KEYCHAIN_NOT_FOUND
    }

    var deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceStr,
        kSecAttrAccount as String: accountStr,
    ]
    if let kc = kc { deleteQuery[kSecMatchSearchList as String] = [kc] }
    let predeleteStatus = SecItemDelete(deleteQuery as CFDictionary)
    keychainTrace(
        "op=store_predelete service=\(serviceStr) account=\(accountStr) status=\(predeleteStatus)"
    )

    var addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceStr,
        kSecAttrAccount as String: accountStr,
        kSecValueData as String: secretData,
    ]
    if use_user_presence != 0 {
        // Bind access to user presence (Touch ID or device passcode)
        // via LocalAuthentication. `kSecAttrAccessControl` implies
        // accessibility, so `kSecAttrAccessible` must NOT also be set.
        var acError: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &acError
        ) else {
            acError?.release()
            return SE_ERR_KEYCHAIN_STORE
        }
        addQuery[kSecAttrAccessControl as String] = ac
    } else {
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
    if let kc = kc { addQuery[kSecUseKeychain as String] = kc }
    var status = SecItemAdd(addQuery as CFDictionary, nil)
    keychainTrace(
        "op=store_add service=\(serviceStr) account=\(accountStr) userPresence=\(use_user_presence) status=\(status)"
    )

    // `.userPresence` / `kSecAttrAccessControl` only works on the
    // Data Protection keychain, which returns `errSecMissingEntitlement`
    // (-34018) for unsigned callers. On the legacy keychain the same
    // attribute is rejected with `errSecParam` (-50). If the ACL path
    // fails for either reason, retry once with the plain
    // `kSecAttrAccessible` attribute so unsigned / Homebrew / CI builds
    // can still store wrapping keys — just without the biometric
    // gate. Callers that configured user presence are expected to
    // notice the missing prompts on first sign; surfacing the
    // downgrade via stderr makes that explicit.
    if use_user_presence != 0
        && (status == errSecMissingEntitlement || status == errSecParam)
    {
        FileHandle.standardError.write(Data((
            "enclaveapp: wrapping-key userPresence ACL rejected " +
            "(OSStatus=\(status)); falling back to non-userPresence storage — " +
            "userPresence gate won't fire for this key\n"
        ).utf8))
        addQuery.removeValue(forKey: kSecAttrAccessControl as String)
        addQuery[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        status = SecItemAdd(addQuery as CFDictionary, nil)
        keychainTrace(
            "op=store_add_fallback service=\(serviceStr) account=\(accountStr) status=\(status)"
        )
    }

    return status == errSecSuccess ? SE_OK : SE_ERR_KEYCHAIN_STORE
    }
}

/// Load a previously-stored secret by service+account. Returns
/// `SE_ERR_KEYCHAIN_NOT_FOUND` if no entry exists.
@_cdecl("enclaveapp_keychain_load")
public func enclaveapp_keychain_load(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32,
    _ secret_out: UnsafeMutablePointer<UInt8>, _ secret_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    return traceDuration("keychain_load") {
        guard let serviceStr = makeServiceString(service, service_len) else {
        return SE_ERR_KEYCHAIN_LOAD
    }
    guard let accountStr = makeAccountString(account, account_len) else {
        return SE_ERR_KEYCHAIN_LOAD
    }

    let useExplicit = !hasDefaultKeychain()
    let kc: SecKeychain? = useExplicit ? openLoginKeychain() : nil
    if useExplicit && kc == nil {
        return SE_ERR_KEYCHAIN_NOT_FOUND
    }

    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: serviceStr,
        kSecAttrAccount as String: accountStr,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    if let kc = kc { query[kSecMatchSearchList as String] = [kc] }
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    keychainTrace(
        "op=load service=\(serviceStr) account=\(accountStr) status=\(status)"
    )
    if status == errSecItemNotFound {
        return SE_ERR_KEYCHAIN_NOT_FOUND
    }
    if status != errSecSuccess {
        return SE_ERR_KEYCHAIN_LOAD
    }
    guard let data = item as? Data else {
        return SE_ERR_KEYCHAIN_LOAD
    }

    let count = Int32(data.count)
    if secret_len.pointee < count {
        secret_len.pointee = count
        return SE_ERR_BUFFER_TOO_SMALL
    }
    data.copyBytes(to: secret_out, count: data.count)
    secret_len.pointee = count
    return SE_OK
    }
}

/// Delete the generic-password entry for a service+account pair. It is
/// not an error if the entry does not exist — the caller treats that as
/// idempotent cleanup.
@_cdecl("enclaveapp_keychain_delete")
public func enclaveapp_keychain_delete(
    _ service: UnsafePointer<UInt8>, _ service_len: Int32,
    _ account: UnsafePointer<UInt8>, _ account_len: Int32
) -> Int32 {
    return traceDuration("keychain_delete") {
        guard let serviceStr = makeServiceString(service, service_len) else {
            return SE_ERR_KEYCHAIN_DELETE
        }
        guard let accountStr = makeAccountString(account, account_len) else {
            return SE_ERR_KEYCHAIN_DELETE
        }

        let useExplicit = !hasDefaultKeychain()
        let kc: SecKeychain? = useExplicit ? openLoginKeychain() : nil
        if useExplicit && kc == nil {
            // Delete is idempotent — report not-found so the Rust
            // caller treats the entry as already-gone rather than
            // erroring out.
            return SE_ERR_KEYCHAIN_NOT_FOUND
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceStr,
            kSecAttrAccount as String: accountStr,
        ]
        if let kc = kc { query[kSecMatchSearchList as String] = [kc] }
        let status = SecItemDelete(query as CFDictionary)
        keychainTrace(
            "op=delete service=\(serviceStr) account=\(accountStr) status=\(status)"
        )
        if status == errSecSuccess || status == errSecItemNotFound {
            return SE_OK
        }
        return SE_ERR_KEYCHAIN_DELETE
    }
}
