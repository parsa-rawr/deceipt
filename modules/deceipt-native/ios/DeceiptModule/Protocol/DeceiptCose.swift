//
//  DeceiptCose.swift
//  Deceipt iOS native adapter (A4)
//
//  COSE_Sign1 (RFC 9052) container handling for Pass A receipts and Pass B
//  credentials. Native builds `Sig_structure`; TS never reconstructs or
//  re-encodes it (invariant 3, exact-bytes rule).
//
//  Verification is ALWAYS over the exact received bytes: we parse the array,
//  extract the raw `protected` bstr and raw `payload` bstr as received, and
//  build `CBOR(["Signature1", protected_bstr, h'', payload_bstr])`.
//

import Foundation

public enum DeceiptCose {
    public struct Sign1 {
        public var protectedRaw: Data   // exact protected bstr bytes (as received)
        public var payload: Data        // exact payload bstr bytes (as received)
        public var signature: Data      // 64 bytes
        public var protectedMap: CborValue
        /// The exact container bytes, for byte-equality checks.
        public var containerBytes: Data
    }

    /// `Sig_structure = CBOR(["Signature1", protected_bstr, h'', payload_bstr])`.
    public static func sigStructure(protectedRaw: Data, payload: Data) -> Data {
        let arr = CborValue.array([
            .text("Signature1"),
            .bytes(protectedRaw),
            .bytes(Data()),
            .bytes(payload),
        ])
        return (try? CborEncoder.encode(arr)) ?? Data()
    }

    /// Parses a COSE_Sign1 4-element array with strict container rules.
    /// `requireCanonicalReencode` enforces receipt-v1.md §2's canonicality rule.
    public static func parseSign1(_ bytes: Data, maxBytes: Int, requireCanonicalReencode: Bool, phase: String) throws -> Sign1 {
        guard bytes.count <= maxBytes else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_SIZE_EXCEEDED" : "CREDENTIAL_MALFORMED", phase: phase, detail: "container too large")
        }
        let decoded = try CborDecoder.decode(bytes)
        guard case .array(let arr) = decoded.kind, arr.count == 4 else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_CONTAINER_MALFORMED" : "CREDENTIAL_MALFORMED", phase: phase, detail: "not a 4-element array")
        }
        guard let protectedRaw = arr[0].asData else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_CONTAINER_MALFORMED" : "CREDENTIAL_MALFORMED", phase: phase, detail: "protected not bstr")
        }
        guard case .map(let unprotectedPairs) = arr[1].kind, unprotectedPairs.isEmpty else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_UNKNOWN_HEADER" : "CREDENTIAL_MALFORMED", phase: phase, detail: "unprotected must be empty")
        }
        guard let payload = arr[2].asData else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_CONTAINER_MALFORMED" : "CREDENTIAL_MALFORMED", phase: phase, detail: "payload must be attached bstr")
        }
        guard let signature = arr[3].asData, signature.count == 64 else {
            throw DeceiptFailure(phase == BridgePhase.receipt ? "RECEIPT_CONTAINER_MALFORMED" : "CREDENTIAL_MALFORMED", phase: phase, detail: "signature must be 64 bytes")
        }
        if requireCanonicalReencode {
            let reencoded = try CborEncoder.encode(decoded)
            guard reencoded == bytes else {
                throw DeceiptFailure("RECEIPT_NONCANONICAL", phase: phase, detail: "container re-encode mismatch")
            }
        }
        let protectedMap = try CborDecoder.decode(protectedRaw)
        return Sign1(protectedRaw: protectedRaw, payload: payload, signature: signature, protectedMap: protectedMap, containerBytes: bytes)
    }

    public struct ProtectedHeader {
        public var alg: Int64?
        public var contentType: String?
        public var kid: Data?
    }

    /// Parses the protected header for a specific expected content type.
    /// Unknown labels or a `crit` header are rejected.
    public static func parseProtectedHeader(
        _ map: CborValue,
        expectedContentType: String,
        unknownHeaderError: String,
        unsupportedAlgError: String
    ) throws -> ProtectedHeader {
        guard case .map(let pairs) = map.kind else {
            throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "protected not a map")
        }
        var header = ProtectedHeader()
        for (k, v) in pairs {
            guard let label = k.asInt else {
                throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "non-integer header label")
            }
            switch label {
            case 1: // alg
                guard let alg = v.asInt else { throw DeceiptFailure(unsupportedAlgError, phase: BridgePhase.receipt, detail: "alg not int") }
                header.alg = alg
            case 2: // crit — MUST be absent
                throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "crit present")
            case 3: // content type
                guard let ct = v.asText else { throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "content type not tstr") }
                header.contentType = ct
            case 4: // kid
                guard let kid = v.asData else { throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "kid not bstr") }
                header.kid = kid
            default:
                throw DeceiptFailure(unknownHeaderError, phase: BridgePhase.receipt, detail: "unknown protected label \(label)")
            }
        }
        if let alg = header.alg, alg != DeceiptProto.coseAlgEdDSA {
            throw DeceiptFailure(unsupportedAlgError, phase: BridgePhase.receipt, detail: "unsupported alg")
        }
        if let ct = header.contentType, ct != expectedContentType {
            throw DeceiptFailure(unsupportedAlgError, phase: BridgePhase.receipt, detail: "unexpected content type")
        }
        return header
    }

    /// Builds a COSE_Sign1 container from an already-computed signature.
    public static func buildSign1(protectedRaw: Data, payload: Data, signature: Data) -> Data {
        let arr = CborValue.array([
            .bytes(protectedRaw),
            .map([]),
            .bytes(payload),
            .bytes(signature),
        ])
        return (try? CborEncoder.encode(arr)) ?? Data()
    }
}
