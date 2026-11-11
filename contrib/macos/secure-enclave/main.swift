// vault-se: the Secure Enclave side of a macOS "this device" slot
// (docs/format.md 4.2, vault-hw/src/enclave.rs). vaultd runs it next to
// itself in Secret Vault.app:
//
//   vault-se check     exit 0 if this Mac has a usable Secure Enclave
//   vault-se seal      stdin: the slot's 32-byte secret; stdout: the blob
//   vault-se unseal    stdin: a blob; stdout: the 32-byte secret
//
// Errors go to stderr as one sentence, with exit status 1.
//
// The Secure Enclave only does P-256, so a blob is an ECIES box: a P-256
// key made in this Mac's Secure Enclave (never leaves it; the blob keeps
// only the enclave's own encrypted copy, usable on this Mac alone) agrees a
// secret with a one-time key whose public half is in the blob, HKDF-SHA256
// turns that into an AES-256-GCM key, and AES-GCM seals the slot secret.
//
// The enclave key's public half is not kept anywhere, so the vault file
// alone does not give a future quantum computer the two public keys it
// would need to recompute the agreed secret; it would also need this Mac.
//
// Blob: "VMSEP1" | u16 BE length | enclave key data | one-time public key
// (65 bytes, X9.63) | salt (32) | AES-GCM nonce, ciphertext, tag (12+32+16).
// Everything before the AES-GCM part is authenticated with it.
//
// Built by contrib/macos/build-se.sh. With -D VAULT_SE_SOFTWARE it uses an
// ordinary software key instead and writes "VMSOFT" blobs, for testing the
// format on machines without a Secure Enclave (CI); the real build refuses
// those blobs.

import CryptoKit
import Foundation
import Security

#if VAULT_SE_SOFTWARE
let magic = Data("VMSOFT".utf8)
#else
let magic = Data("VMSEP1".utf8)
#endif
let info = Data("secret-vault/secure-enclave/v1".utf8)
let publicLength = 65
let saltLength = 32
let boxLength = 12 + 32 + 16

struct Failure: Error { let message: String }

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func describe(_ error: Error) -> String {
    if let f = error as? Failure { return f.message }
    let ns = error as NSError
    // CryptoKit reports Secure Enclave failures as CryptoKitError or
    // Security framework OSStatus codes.
    if ns.domain == NSOSStatusErrorDomain {
        let text = SecCopyErrorMessageString(OSStatus(ns.code), nil) as String? ?? "error \(ns.code)"
        return "Secure Enclave: \(text)"
    }
    return "Secure Enclave: \(error)"
}

func available() -> Bool {
    #if VAULT_SE_SOFTWARE
    return true
    #else
    return SecureEnclave.isAvailable
    #endif
}

/// A new enclave key: (its data for the blob, its public key).
func newKey() throws -> (Data, P256.KeyAgreement.PublicKey) {
    #if VAULT_SE_SOFTWARE
    let k = P256.KeyAgreement.PrivateKey()
    return (k.rawRepresentation, k.publicKey)
    #else
    var cfError: Unmanaged<CFError>?
    // Usable only while the Mac is unlocked, never synced or backed up to
    // another device; no Touch ID prompt (the master password is the other
    // half of the slot).
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &cfError)
    else {
        throw Failure(message: "Secure Enclave: cannot make the access policy: \(cfError!.takeRetainedValue())")
    }
    let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    return (k.dataRepresentation, k.publicKey)
    #endif
}

func agree(keyData: Data, with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    #if VAULT_SE_SOFTWARE
    return try P256.KeyAgreement.PrivateKey(rawRepresentation: keyData).sharedSecretFromKeyAgreement(with: peer)
    #else
    let k: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
    } catch {
        throw Failure(message: "this slot was made by another Mac's Secure Enclave (or this Mac was erased); it works only on the Mac that added it")
    }
    return try k.sharedSecretFromKeyAgreement(with: peer)
    #endif
}

func wrapKey(_ shared: SharedSecret, onetime: Data, salt: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info + onetime, outputByteCount: 32)
}

func seal(_ secret: Data) throws -> Data {
    guard secret.count == 32 else { throw Failure(message: "vault-se seal: expected a 32-byte secret") }
    let (keyData, enclavePublic) = try newKey()
    guard keyData.count <= Int(UInt16.max) else { throw Failure(message: "Secure Enclave key data too long") }
    let onetime = P256.KeyAgreement.PrivateKey()
    let shared = try onetime.sharedSecretFromKeyAgreement(with: enclavePublic)
    let onetimePublic = onetime.publicKey.x963Representation
    var salt = Data(count: saltLength)
    let rc = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!) }
    guard rc == errSecSuccess else { throw Failure(message: "no random numbers") }

    var header = magic
    header.append(UInt8(keyData.count >> 8))
    header.append(UInt8(keyData.count & 0xff))
    header.append(keyData)
    header.append(onetimePublic)
    header.append(salt)
    let box = try AES.GCM.seal(secret, using: wrapKey(shared, onetime: onetimePublic, salt: salt), authenticating: header)
    guard let combined = box.combined, combined.count == boxLength else { throw Failure(message: "AES-GCM failed") }
    return header + combined
}

func unseal(_ blob: Data) throws -> Data {
    let b = [UInt8](blob)
    guard b.count >= magic.count + 2, Data(b[0..<magic.count]) == magic else {
        if blob.starts(with: Data("VMSOFT".utf8)) {
            throw Failure(message: "this slot was made by a test build of vault-se; add the Secure Enclave again")
        }
        throw Failure(message: "not a Secure Enclave slot")
    }
    var at = magic.count
    let keyLength = Int(b[at]) << 8 | Int(b[at + 1])
    at += 2
    guard b.count == at + keyLength + publicLength + saltLength + boxLength else {
        throw Failure(message: "Secure Enclave slot is damaged (wrong length)")
    }
    let keyData = Data(b[at..<at + keyLength]); at += keyLength
    let onetimePublic = Data(b[at..<at + publicLength]); at += publicLength
    let salt = Data(b[at..<at + saltLength]); at += saltLength
    let header = Data(b[0..<at])
    let box = try AES.GCM.SealedBox(combined: Data(b[at...]))
    let peer = try P256.KeyAgreement.PublicKey(x963Representation: onetimePublic)
    let shared = try agree(keyData: keyData, with: peer)
    do {
        return try AES.GCM.open(box, using: wrapKey(shared, onetime: onetimePublic, salt: salt), authenticating: header)
    } catch {
        throw Failure(message: "Secure Enclave slot is damaged (it does not decrypt)")
    }
}

let args = CommandLine.arguments
guard args.count == 2 else { fail("usage: vault-se check|seal|unseal") }
guard available() else {
    fail("this Mac has no Secure Enclave (it needs Apple silicon or an Intel Mac with a T2 chip)")
}
do {
    switch args[1] {
    case "check":
        // Make and use a throwaway key, which also proves macOS lets this
        // program use the enclave.
        let secret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        guard try unseal(seal(secret)) == secret else { fail("Secure Enclave: check failed") }
        print("Secure Enclave OK")
    case "seal":
        FileHandle.standardOutput.write(try seal(FileHandle.standardInput.readDataToEndOfFile()))
    case "unseal":
        FileHandle.standardOutput.write(try unseal(FileHandle.standardInput.readDataToEndOfFile()))
    default:
        fail("usage: vault-se check|seal|unseal")
    }
} catch {
    fail(describe(error))
}
