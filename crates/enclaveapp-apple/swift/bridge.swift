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
let SE_ERR_BUFFER_TOO_SMALL: Int32 = 4
let SE_ERR_NOT_AVAILABLE: Int32 = 5
let SE_ERR_ENCRYPT: Int32 = 6
let SE_ERR_DECRYPT: Int32 = 7

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

/// Extract the public key from a signing key's persisted data representation.
@_cdecl("enclaveapp_se_signing_public_key")
public func enclaveapp_se_signing_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let data = Data(bytes: data_rep, count: Int(data_rep_len))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        return copyUncompressedPubKey(key.publicKey.rawRepresentation, pub_key_out, pub_key_len)
    } catch {
        return SE_ERR_LOAD
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
