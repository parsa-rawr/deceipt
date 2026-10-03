//
//  DeceiptKeyStore.swift
//  Deceipt iOS native adapter (A4) — app target
//
//  Merchant device signing key custody. CryptoKit `Curve25519.Signing` key
//  material lives in the Keychain as a generic password item; the private seed
//  never crosses the bridge and is never logged.
//
//  Accessibility & reset behaviour (documented, DESIGN.md §4.4):
//    * accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//        - available to a backgrounded session after the first unlock;
//        - NEVER synced to iCloud Keychain and NEVER included in an encrypted
//          iTunes/Finder backup (ThisDeviceOnly);
//        - survives app restart and device reboot (after first unlock).
//    * reset = delete the item and generate a fresh key
//      (`merchantKeyDelete` / `merchantKeyGenerate`); a deleted key cannot be
//      recovered, and receipts signed by it remain verifiable only while the
//      corresponding credential is still in circulation.
//
//  NO Secure Enclave claim: CryptoKit cannot store an Ed25519 key in the
//  Secure Enclave (only P-256 signing keys are Secure-Enclave-backed), so this
//  is honestly reported as `keychain_software` (KeyStorageKind).
//

import Foundation
import CryptoKit
import Security

@objc(DeceiptKeyStore)
public final class DeceiptKeyStore: NSObject {
    private let service = "com.deceipt.poc.merchant"
    private let account = "device-signing-key-v1"
    private let metaAccount = "device-signing-meta-v1"

    public struct StoredKey {
        public var seed: Data                 // 32-byte Ed25519 seed
        public var deviceKeyId: Data          // 16-byte opaque id (protected `kid`)
        public var createdAtMs: Int64
        public var credential: Data?          // exact COSE_Sign1 credential bytes
        public var merchantId: Data?
    }

    // MARK: Keychain primitives

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func loadRaw() -> Data? {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private func storeRaw(_ data: Data) throws {
        // Delete any previous item so the accessibility attribute is applied
        // afresh (SecItemUpdate cannot change accessibility reliably).
        SecItemDelete(baseQuery() as CFDictionary)
        var q = baseQuery()
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeceiptFailure("STORAGE_FAILED", phase: BridgePhase.keys, detail: "keychain add \(status)")
        }
    }

    private func deleteRaw() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    // MARK: Public API

    public func load() -> StoredKey? {
        guard let blob = loadRaw(), let decoded = try? decodeBlob(blob) else { return nil }
        return decoded
    }

    @discardableResult
    public func generate() throws -> StoredKey {
        let sk = Curve25519.Signing.PrivateKey()
        let seed = sk.rawRepresentation
        let keyId = DeceiptCrypto.randomBytes(16)
        let key = StoredKey(seed: seed, deviceKeyId: keyId, createdAtMs: Int64(Date().timeIntervalSince1970 * 1000),
                            credential: nil, merchantId: nil)
        try persist(key)
        return key
    }

    public func persist(_ key: StoredKey) throws {
        var blob = Data([0x01])              // version
        blob.append(DeceiptBytes.u16BE(UInt16(key.seed.count)))
        blob.append(key.seed)
        blob.append(DeceiptBytes.u16BE(UInt16(key.deviceKeyId.count)))
        blob.append(key.deviceKeyId)
        blob.append(DeceiptBytes.u64BE(UInt64(bitPattern: key.createdAtMs)))
        let cred = key.credential ?? Data()
        blob.append(DeceiptBytes.u16BE(UInt16(cred.count)))
        blob.append(cred)
        let mid = key.merchantId ?? Data()
        blob.append(DeceiptBytes.u16BE(UInt16(mid.count)))
        blob.append(mid)
        try storeRaw(blob)
    }

    public func delete() {
        deleteRaw()
    }

    public func privateKey(_ key: StoredKey) -> Curve25519.Signing.PrivateKey? {
        try? Curve25519.Signing.PrivateKey(rawRepresentation: key.seed)
    }

    public func publicKeyBytes(_ key: StoredKey) -> Data? {
        privateKey(key)?.publicKey.rawRepresentation
    }

    // MARK: Blob codec

    private func decodeBlob(_ blob: Data) throws -> StoredKey {
        var p = 0
        func take(_ n: Int) throws -> Data {
            guard p + n <= blob.count else { throw DeceiptFailure("STORAGE_FAILED", phase: BridgePhase.keys, detail: "truncated key blob") }
            let d = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + n))
            p += n
            return d
        }
        func u16() throws -> Int {
            let d = try take(2)
            return Int((UInt16(d[d.startIndex]) << 8) | UInt16(d[d.startIndex + 1]))
        }
        guard try take(1).first == 0x01 else { throw DeceiptFailure("STORAGE_FAILED", phase: BridgePhase.keys, detail: "key blob version") }
        let seed = try take(try u16())
        let keyId = try take(try u16())
        let createdAt = Int64(bitPattern: DeceiptBytes.readU64BE(try take(8), 0) ?? 0)
        let cred = try take(try u16())
        let mid = try take(try u16())
        return StoredKey(seed: seed, deviceKeyId: keyId, createdAtMs: createdAt,
                         credential: cred.isEmpty ? nil : cred, merchantId: mid.isEmpty ? nil : mid)
    }
}
