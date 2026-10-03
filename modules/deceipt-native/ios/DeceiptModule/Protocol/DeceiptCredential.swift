//
//  DeceiptCredential.swift
//  Deceipt iOS native adapter (A4)
//
//  Pass B credential verification (trust.md §4). This is the trust split that
//  yields the three peer session types (handshake.md §9):
//
//    * anchor present  + valid           -> SessionAuthenticated
//    * anchor absent   + well-formed     -> SessionUnverifiedPeer
//    * anything else                     -> fail closed
//
//  A supplied public key plus a valid signature does NOT prove merchant
//  identity: the anchor lookup (step 7) is the identity gate.
//

import Foundation

public struct CredentialVerificationResult {
    public enum Trust: String {
        case authenticated
        case unknownIssuer = "unknown_issuer"
    }

    public var trust: Trust
    public var signatureValid: Bool
    public var temporallyAcceptable: Bool
    public var merchantId: Data?
    public var deviceKeyId: Data?
    public var devicePublicKey: Data?
    public var issuerId: Data?
    public var capabilities: Int64?
    public var merchantReference: String?
    public var displayName: String?
    public var error: BridgeErrorShape?

    /// Public-only bridge projection (A3 `CredentialVerification`).
    public func asDictionary() -> [String: Any] {
        var d: [String: Any] = [
            "trust": trust.rawValue,
            "signatureValid": signatureValid,
            "temporallyAcceptable": temporallyAcceptable,
        ]
        if let v = merchantId { d["merchantIdHex"] = DeceiptBytes.hex(v) }
        if let v = deviceKeyId { d["deviceKeyIdHex"] = DeceiptBytes.hex(v) }
        if let v = devicePublicKey { d["devicePublicKeyB64"] = DeceiptBytes.base64(v) }
        if let v = issuerId { d["issuerIdHex"] = DeceiptBytes.hex(v) }
        if let v = capabilities { d["capabilities"] = NSNumber(value: v) }
        if let v = merchantReference { d["merchantReference"] = v }
        if let v = displayName { d["displayName"] = v }
        if let e = error { d["error"] = e.asDictionary }
        return d
    }
}

public enum DeceiptCredential {
    /// Trust anchors supplied by the app: anchor_id(16) -> Ed25519 public key(32).
    public struct AnchorSet {
        public var byId: [String: Data]
        public init(_ anchors: [(id: Data, publicKey: Data)]) {
            var m: [String: Data] = [:]
            for a in anchors { m[DeceiptBytes.hex(a.id)] = a.publicKey }
            byId = m
        }
        public func lookup(_ id: Data) -> Data? { byId[DeceiptBytes.hex(id)] }
    }

    public static func verify(credentialBytes: Data, anchors: AnchorSet, nowUnix: Int64) throws -> CredentialVerificationResult {
        // 1. size
        guard credentialBytes.count <= DeceiptBounds.maxCredentialBytes else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: ">1024 bytes")
        }
        // 2. container
        let sign1 = try DeceiptCose.parseSign1(credentialBytes, maxBytes: DeceiptBounds.maxCredentialBytes, requireCanonicalReencode: true, phase: BridgePhase.credential)
        let header = try DeceiptCose.parseProtectedHeader(
            sign1.protectedMap,
            expectedContentType: DeceiptProto.credentialContentType,
            unknownHeaderError: "CREDENTIAL_MALFORMED",
            unsupportedAlgError: "CREDENTIAL_MALFORMED"
        )
        guard let kid = header.kid else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "missing kid")
        }
        // 3. payload
        let payload = try CborDecoder.decode(sign1.payload)
        guard case .map = payload.kind, payload.field(1)?.asInt == 1 else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "credential_version")
        }
        // unknown payload labels are rejected (strict v1).
        guard let keys = payload.mapKeysAsInts(), keys.allSatisfy({ (1...11).contains($0) }) else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "unknown payload label")
        }
        // 4. kid == issuer_id
        guard let issuerId = payload.field(2)?.asData, issuerId.count == 16, issuerId == kid else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "kid != issuer_id")
        }
        // 5. fixed lengths
        guard let merchantId = payload.field(3)?.asData, merchantId.count == 16,
              let deviceKeyId = payload.field(4)?.asData, deviceKeyId.count == 16,
              let devicePub = payload.field(5)?.asData, devicePub.count == 32,
              let validFrom = payload.field(6)?.asInt,
              let validUntil = payload.field(7)?.asInt,
              let capabilities = payload.field(8)?.asInt,
              validUntil > validFrom else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "fixed-length fields")
        }
        // 6. text checks
        guard let merchantReference = payload.field(9)?.asText, isSafeCredentialText(merchantReference, max: DeceiptBounds.maxTextDisplayNameBytes),
              let displayName = payload.field(10)?.asText, isSafeCredentialText(displayName, max: DeceiptBounds.maxTextDisplayNameBytes),
              payload.field(11)?.asInt != nil else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "text fields")
        }

        var result = CredentialVerificationResult(
            trust: .unknownIssuer, signatureValid: false, temporallyAcceptable: false,
            merchantId: merchantId, deviceKeyId: deviceKeyId, devicePublicKey: devicePub,
            issuerId: issuerId, capabilities: capabilities,
            merchantReference: merchantReference, displayName: displayName
        )

        // 7. anchor lookup — the trust split.
        guard let anchorKey = anchors.lookup(issuerId) else {
            // Non-fatal: the session may continue as SessionUnverifiedPeer, but
            // the key is never authorized and no receipt can ever be TRUSTED.
            result.error = BridgeErrorShape(name: "CREDENTIAL_UNKNOWN_ISSUER", phase: BridgePhase.credential)
            return result
        }

        // 8. signature over the exact received bytes
        let sigStructure = DeceiptCose.sigStructure(protectedRaw: sign1.protectedRaw, payload: sign1.payload)
        guard DeceiptCrypto.ed25519Verify(publicKey: anchorKey, signature: sign1.signature, message: sigStructure) else {
            throw DeceiptFailure("CREDENTIAL_SIGNATURE_INVALID", phase: BridgePhase.credential)
        }
        result.signatureValid = true

        // 9–10. temporal window with skew
        let skew = Int64(DeceiptProto.clockSkewMaxS)
        if nowUnix < validFrom - skew {
            throw DeceiptFailure("CREDENTIAL_NOT_YET_VALID", phase: BridgePhase.credential)
        }
        if nowUnix >= validUntil + skew {
            throw DeceiptFailure("CREDENTIAL_EXPIRED", phase: BridgePhase.credential)
        }
        result.temporallyAcceptable = true

        // 11. authenticated
        result.trust = .authenticated
        return result
    }

    /// NFC + length + control/bidi checks for credential text (trust.md §4 step 6).
    static func isSafeCredentialText(_ s: String, max: Int) -> Bool {
        let bytes = Data(s.utf8)
        guard bytes.count <= max else { return false }
        guard s == s.precomposedStringWithCanonicalMapping else { return false }
        return !DeceiptText.containsForbidden(s)
    }
}

/// Shared text-safety checks (receipt-v1.md §8) — UTF-8, NFC, no C0/C1
/// controls, surrogates or bidi controls.
public enum DeceiptText {
    static let forbiddenScalars: Set<UInt32> = [
        0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2066, 0x2067, 0x2068, 0x2069,
    ]

    public static func containsForbidden(_ s: String) -> Bool {
        for scalar in s.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || (0x7F...0x9F).contains(v) { return true }
            if (0xD800...0xDFFF).contains(v) { return true }
            if forbiddenScalars.contains(v) { return true }
        }
        return false
    }
}
