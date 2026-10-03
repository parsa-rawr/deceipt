//
//  DeceiptBinding.swift
//  Deceipt iOS native adapter (A4)
//
//  A2 transaction binding, adopted verbatim by A1 (handshake.md §10).
//  Session binding is NOT merchant-key trust: passing every check here says
//  only "this session, this transaction" (A2 §3.9).
//
//  The SBT (session binding token) never crosses the bridge and is never
//  logged; only the QR *payload* string does.
//

import Foundation

public enum DeceiptBinding {
    public static let qrPrefix = "deceipt1:"
    public static let qrFormatVersion: Int64 = 1
    public static let bindingFormatVersion: Int64 = 1

    public struct QrPayload {
        public var qrFormatVersion: Int64
        public var sessionId: Data          // 16
        public var sessionBindingToken: Data // 16 — SECRET
        public var offerHash: Data          // 32
        public var expiresAtUnix: Int64

        public func zeroize() {
            var sbt = sessionBindingToken
            DeceiptBytes.zeroize(&sbt)
        }
    }

    // MARK: QR

    public static func encodeQr(sessionId: Data, sessionBindingToken: Data, offerHash: Data, expiresAtUnix: Int64) -> String {
        let map = CborValue.map([
            (.int(1), .int(qrFormatVersion)),
            (.int(2), .bytes(sessionId)),
            (.int(3), .bytes(sessionBindingToken)),
            (.int(4), .bytes(offerHash)),
            (.int(5), .int(expiresAtUnix)),
        ])
        let bytes = (try? CborEncoder.encode(map)) ?? Data()
        return qrPrefix + DeceiptBytes.base64URLNoPad(bytes)
    }

    public static func parseQr(_ qrPayload: String) throws -> QrPayload {
        guard qrPayload.hasPrefix(qrPrefix) else {
            throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding, detail: "no deceipt1: prefix")
        }
        let encoded = String(qrPayload.dropFirst(qrPrefix.count))
        guard let bytes = DeceiptBytes.fromBase64URLNoPad(encoded) else {
            throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.binding, detail: "bad base64url")
        }
        let decoded = try CborDecoder.decode(bytes)
        guard case .map(let pairs) = decoded.kind else {
            throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.binding, detail: "QR not a map")
        }
        for (k, _) in pairs {
            guard let key = k.asInt, (1...5).contains(key) else {
                throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding, detail: "unknown QR label")
            }
        }
        guard decoded.field(1)?.asInt == qrFormatVersion else {
            throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding, detail: "qr_format_version")
        }
        guard let sessionId = decoded.field(2)?.asData, sessionId.count == 16 else {
            throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding, detail: "session_id must be 16 bytes")
        }
        guard let sbt = decoded.field(3)?.asData, sbt.count == 16 else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "SBT must be 16 bytes")
        }
        guard let offerHash = decoded.field(4)?.asData, offerHash.count == 32 else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "offer_hash must be 32 bytes")
        }
        guard let expires = decoded.field(5)?.asInt, expires >= 0 else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "expires_at_unix")
        }
        return QrPayload(qrFormatVersion: qrFormatVersion, sessionId: sessionId, sessionBindingToken: sbt, offerHash: offerHash, expiresAtUnix: expires)
    }

    public static func assertFresh(_ payload: QrPayload, nowUnix: Int64) throws {
        if nowUnix >= payload.expiresAtUnix {
            throw DeceiptFailure("BINDING_STALE", phase: BridgePhase.binding, detail: "checkout code expired")
        }
    }

    // MARK: Offer hash

    public struct OfferFields {
        public var sessionId: Data
        public var transferId: Data
        public var receiptId: Data
        public var merchantReference: String
        public var totalAmountMinor: Int64
        public var currency: String
        public var issuedAtUnix: Int64
    }

    public static func offerHashPreimage(_ f: OfferFields) -> Data {
        let arr = CborValue.array([
            .bytes(f.sessionId),
            .bytes(f.transferId),
            .bytes(f.receiptId),
            .text(f.merchantReference),
            .int(f.totalAmountMinor),
            .text(f.currency),
            .int(f.issuedAtUnix),
        ])
        return (try? CborEncoder.encode(arr)) ?? Data()
    }

    public static func computeOfferHash(_ f: OfferFields) -> Data {
        DeceiptCrypto.sha256(Data(DeceiptProto.offerHashDomain.utf8) + Data([0x00]) + offerHashPreimage(f))
    }

    // MARK: Binding tuple

    public static func encodeBindingTuple(sessionId: Data, transferId: Data, receiptId: Data, offerHash: Data) -> Data {
        let arr = CborValue.array([
            .int(bindingFormatVersion),
            .bytes(sessionId),
            .bytes(transferId),
            .bytes(receiptId),
            .bytes(offerHash),
        ])
        return (try? CborEncoder.encode(arr)) ?? Data()
    }

    public static func bindingTupleDigest(_ tuple: Data) -> Data {
        DeceiptCrypto.sha256(Data(DeceiptProto.bindingTupleDomain.utf8) + Data([0x00]) + tuple)
    }

    /// Parses the authoritative binding tuple (SERVER_HELLO label 10):
    /// `[1, session_id(16), transfer_id(16), receipt_id(16), offer_hash(32)]`.
    public struct ParsedTuple {
        public var sessionId: Data
        public var transferId: Data
        public var receiptId: Data
        public var offerHash: Data
    }

    public static func parseBindingTuple(_ tuple: Data) throws -> ParsedTuple {
        let v = try CborDecoder.decode(tuple)
        guard case .array(let arr) = v.kind, arr.count == 5, arr[0].asInt == bindingFormatVersion else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "binding tuple shape")
        }
        guard let sessionId = arr[1].asData, sessionId.count == 16,
              let transferId = arr[2].asData, transferId.count == 16,
              let receiptId = arr[3].asData, receiptId.count == 16,
              let offerHash = arr[4].asData, offerHash.count == 32 else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "binding tuple lengths")
        }
        return ParsedTuple(sessionId: sessionId, transferId: transferId, receiptId: receiptId, offerHash: offerHash)
    }

    // MARK: Binding proof

    public static func bindingProofMessage(clientNonce: Data, clientEphemeralPubkey: Data) throws -> Data {
        guard clientNonce.count == 32 else {
            throw DeceiptFailure("BINDING_PROOF_INVALID", phase: BridgePhase.binding, detail: "client_nonce must be 32 bytes")
        }
        guard clientEphemeralPubkey.count == 65 else {
            throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.binding, detail: "client_ephemeral_pubkey must be 65 bytes")
        }
        return Data(DeceiptProto.bindingProofDomain.utf8) + Data([0x00]) + clientNonce + clientEphemeralPubkey
    }

    public static func bindingProof(sbt: Data, clientNonce: Data, clientEphemeralPubkey: Data) throws -> Data {
        let msg = try bindingProofMessage(clientNonce: clientNonce, clientEphemeralPubkey: clientEphemeralPubkey)
        return DeceiptCrypto.hmacSha256(key: sbt, message: msg)
    }
}
