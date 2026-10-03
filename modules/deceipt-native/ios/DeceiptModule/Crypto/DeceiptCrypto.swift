//
//  DeceiptCrypto.swift
//  Deceipt iOS native adapter (A4)
//
//  Primitives for `Deceipt-Session-Suite-1` (handshake.md §1) and Pass A/B:
//    * P-256 ECDH (secp256r1), uncompressed points 0x04‖X‖Y
//    * HKDF-SHA-256 (RFC 5869) — implemented explicitly so both the PRK and
//      the OKM are directly checkable against handshake-valid.json
//    * AES-256-GCM (96-bit nonce, 128-bit tag)
//    * SHA-256
//    * Ed25519 (CryptoKit Curve25519.Signing); NO Secure Enclave claim
//
//  Key material is never logged. Session secrets are ephemeral by
//  construction (invariant 4): the long-lived merchant signing key is never
//  used for key agreement.
//

import Foundation
import CryptoKit
import Security

public enum DeceiptCrypto {
    // MARK: Hash / MAC

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func hmacSha256(key: Data, message: Data) -> Data {
        let k = SymmetricKey(data: key)
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: k))
    }

    // MARK: HKDF-SHA-256 (RFC 5869)

    public static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        hmacSha256(key: salt, message: ikm)
    }

    public static func hkdfExpand(prk: Data, info: Data, outputLength: Int) -> Data {
        precondition(outputLength > 0 && outputLength <= 255 * 32)
        var okm = Data()
        var t = Data()
        var counter: UInt8 = 1
        while okm.count < outputLength {
            var input = Data()
            input.append(t)
            input.append(info)
            input.append(counter)
            t = hmacSha256(key: prk, message: input)
            okm.append(t)
            counter = counter &+ 1
        }
        return okm.prefix(outputLength)
    }

    // MARK: Randomness

    public static func randomBytes(_ count: Int) -> Data {
        var out = Data(count: count)
        let ok = out.withUnsafeMutableBytes { raw -> Int32 in
            guard let base = raw.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        if ok != 0 {
            // Fall back to the system generator only if SecRandom is unavailable
            // (never expected on iOS).
            var g = SystemRandomNumberGenerator()
            out = Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &g) })
        }
        return out
    }

    // MARK: AES-256-GCM

    public static func aesGcmSeal(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        guard key.count == 32 else { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.internal, detail: "bad AES key len") }
        guard nonce.count == DeceiptBounds.aeadNonceBytes else { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.internal, detail: "bad nonce len") }
        let k = SymmetricKey(data: key)
        let n = try AES.GCM.Nonce(data: nonce)
        let sealed: AES.GCM.SealedBox
        if aad.isEmpty {
            sealed = try AES.GCM.seal(plaintext, using: k, nonce: n)
        } else {
            sealed = try AES.GCM.seal(plaintext, using: k, nonce: n, authenticating: aad)
        }
        // CryptoKit's combined representation is nonce‖ct‖tag; we already hold
        // the nonce separately, so return ct‖tag only.
        return sealed.ciphertext + sealed.tag
    }

    public static func aesGcmOpen(key: Data, nonce: Data, aad: Data, ciphertextAndTag: Data) throws -> Data {
        guard key.count == 32 else { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.internal, detail: "bad AES key len") }
        guard nonce.count == DeceiptBounds.aeadNonceBytes else { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.internal, detail: "bad nonce len") }
        guard ciphertextAndTag.count >= DeceiptBounds.aeadTagBytes else {
            throw DeceiptFailure("AEAD_AUTH_FAILED", phase: BridgePhase.transfer, detail: "short aead body")
        }
        let k = SymmetricKey(data: key)
        let n = try AES.GCM.Nonce(data: nonce)
        let ct = ciphertextAndTag.prefix(ciphertextAndTag.count - DeceiptBounds.aeadTagBytes)
        let tag = ciphertextAndTag.suffix(DeceiptBounds.aeadTagBytes)
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(nonce: n, ciphertext: ct, tag: tag)
            if aad.isEmpty {
                return try AES.GCM.open(box, using: k)
            }
            return try AES.GCM.open(box, using: k, authenticating: aad)
        } catch {
            throw DeceiptFailure("AEAD_AUTH_FAILED", phase: BridgePhase.transfer)
        }
    }

    /// `nonce = 00000000 ‖ u64_be(counter)` (handshake.md §6.1).
    public static func aeadNonce(counter: UInt64) -> Data {
        var n = Data([0, 0, 0, 0])
        n.append(DeceiptBytes.u64BE(counter))
        return n
    }

    // MARK: P-256 ECDH

    public struct EphemeralKeyPair {
        public let privateKey: P256.KeyAgreement.PrivateKey
        /// 65-byte uncompressed `0x04‖X‖Y` (x9.63), as the transcript requires.
        public var publicKeyBytes: Data { privateKey.publicKey.x963Representation }
        public init() { self.privateKey = P256.KeyAgreement.PrivateKey() }
        public init(privateScalar: Data) throws {
            do { self.privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateScalar) }
            catch { throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.handshake, detail: "bad scalar") }
        }
    }

    /// Decodes a 65-byte uncompressed P-256 point, rejecting anything that
    /// does not lie on the curve (`HANDSHAKE_ECDH_INVALID_POINT`).
    public static func decodeP256PublicKey(_ bytes: Data) throws -> P256.KeyAgreement.PublicKey {
        guard bytes.count == 65, bytes[bytes.startIndex] == 0x04 else {
            throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.handshake, detail: "not uncompressed")
        }
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: bytes)
        } catch {
            throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.handshake, detail: "point off curve")
        }
    }

    /// 32-byte X coordinate of the shared secret.
    public static func ecdhSharedSecretX(privateKey: P256.KeyAgreement.PrivateKey, peerPublicKey: P256.KeyAgreement.PublicKey) -> Data {
        let secret = try! privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return secret.withUnsafeBytes { Data($0) }
    }

    // MARK: Ed25519

    public static func ed25519PublicKey(fromSeed seed: Data) -> Data? {
        guard let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { return nil }
        return k.publicKey.rawRepresentation
    }

    public static func ed25519Sign(seed: Data, message: Data) throws -> Data {
        guard let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.keys, detail: "bad ed25519 seed")
        }
        do { return try k.signature(for: message) }
        catch { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.keys, detail: "sign failed") }
    }

    public static func ed25519Verify(publicKey: Data, signature: Data, message: Data) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pub.isValidSignature(signature, for: message)
    }

    /// Signs with a `Curve25519.Signing.PrivateKey` held by the key store.
    public static func ed25519Sign(privateKey: Curve25519.Signing.PrivateKey, message: Data) throws -> Data {
        do { return try privateKey.signature(for: message) }
        catch { throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.keys, detail: "sign failed") }
    }
}
