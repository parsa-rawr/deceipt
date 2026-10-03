//
//  DeceiptReceiptVerify.swift
//  Deceipt iOS native adapter (A4)
//
//  Ed25519 verification over the EXACT received COSE_Sign1 bytes (Pass A,
//  invariant 3). Native builds `Sig_structure`; a re-encoded container must
//  fail rather than be accepted.
//
//  This returns ONE sub-state (`signatureValid`) plus the parsed `kid`. It is
//  never the trust decision — the shared app owns steps 8–15.
//

import Foundation

public struct ReceiptVerificationResult {
    public var signatureValid: Bool
    public var deviceKeyId: Data?
    public var error: BridgeErrorShape?

    public func asDictionary() -> [String: Any] {
        var d: [String: Any] = ["signatureValid": signatureValid]
        if let k = deviceKeyId { d["deviceKeyIdHex"] = DeceiptBytes.hex(k) }
        if let e = error { d["error"] = e.asDictionary }
        return d
    }
}

public enum DeceiptReceipt {
    public static func verifyContainer(coseSign1: Data, devicePublicKey: Data) throws -> ReceiptVerificationResult {
        guard coseSign1.count <= DeceiptBounds.maxReceiptBytes else {
            throw DeceiptFailure("RECEIPT_SIZE_EXCEEDED", phase: BridgePhase.receipt)
        }
        let sign1: DeceiptCose.Sign1
        do {
            sign1 = try DeceiptCose.parseSign1(coseSign1, maxBytes: DeceiptBounds.maxReceiptBytes, requireCanonicalReencode: true, phase: BridgePhase.receipt)
        } catch let f as DeceiptFailure {
            // Container-level failures are reported as a verification sub-state,
            // not thrown (A3's `ReceiptSignatureVerification.error`).
            return ReceiptVerificationResult(signatureValid: false, deviceKeyId: nil, error: f.bridge)
        }
        let header: DeceiptCose.ProtectedHeader
        do {
            header = try DeceiptCose.parseProtectedHeader(
                sign1.protectedMap,
                expectedContentType: DeceiptProto.receiptContentType,
                unknownHeaderError: "RECEIPT_UNKNOWN_HEADER",
                unsupportedAlgError: "RECEIPT_UNSUPPORTED_ALGORITHM"
            )
        } catch let f as DeceiptFailure {
            return ReceiptVerificationResult(signatureValid: false, deviceKeyId: nil, error: f.bridge)
        }
        guard devicePublicKey.count == 32 else {
            return ReceiptVerificationResult(signatureValid: false, deviceKeyId: header.kid,
                                             error: BridgeErrorShape(name: "RECEIPT_SIGNATURE_INVALID", phase: BridgePhase.receipt, detail: "device key not 32 bytes"))
        }
        // Build Sig_structure over the EXACT received protected/payload bstrs.
        let sigStructure = DeceiptCose.sigStructure(protectedRaw: sign1.protectedRaw, payload: sign1.payload)
        let valid = DeceiptCrypto.ed25519Verify(publicKey: devicePublicKey, signature: sign1.signature, message: sigStructure)
        return ReceiptVerificationResult(signatureValid: valid, deviceKeyId: header.kid,
                                         error: valid ? nil : BridgeErrorShape(name: "RECEIPT_SIGNATURE_INVALID", phase: BridgePhase.receipt))
    }
}
