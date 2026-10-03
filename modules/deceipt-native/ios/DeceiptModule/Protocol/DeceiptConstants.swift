//
//  DeceiptConstants.swift
//  Deceipt iOS native adapter (A4)
//
//  Frozen values from docs/protocol/wire.md, framing.md, handshake.md and
//  protocol/schema/bounds-v1.json (revision deceipt-proto-r2).
//

import Foundation

public enum DeceiptProto {
    public static let protocolVersion: UInt16 = 1
    public static let suiteId: UInt16 = 1

    /// `TRANSCRIPT_LEN` — handshake.md §3.
    public static let transcriptLen = 372
    public static let domainLabel = "deceipt-handshake-v1"
    public static let transferKdfPrefix = "deceipt-transfer-v1"
    public static let bindingTupleDomain = "deceipt-binding-tuple-v1"
    public static let bindingProofDomain = "deceipt-binding-proof-v1"
    public static let offerHashDomain = "deceipt-offer-hash-v1"
    public static let receiptContentType = "application/deceipt-receipt+cbor"
    public static let credentialContentType = "application/deceipt-credential+cbor"
    public static let coseAlgEdDSA: Int = -8
    public static let clockSkewMaxS: UInt64 = 300
}

/// GATT identifiers (wire.md §1). Changing these is a revision break.
public enum DeceiptGatt {
    public static let serviceUuid = "8decc0de-1e57-4000-8000-000000000001"
    public static let commandUuid = "8decc0de-1e57-4000-8000-000000000002" // B→A WriteRequest
    public static let eventUuid = "8decc0de-1e57-4000-8000-000000000003"   // A→B Indicate
    public static let dataUuid = "8decc0de-1e57-4000-8000-000000000004"    // A→B Notify
}

/// Message type IDs (wire.md §2).
public enum DeceiptMessageType {
    public static let clientHello: UInt64 = 0x01
    public static let accept: UInt64 = 0x02
    public static let ack: UInt64 = 0x03
    public static let receiptAck: UInt64 = 0x04
    public static let cancel: UInt64 = 0x05
    public static let retry: UInt64 = 0x06
    public static let serverHello: UInt64 = 0x11
    public static let receiptOffer: UInt64 = 0x12
    public static let transferBegin: UInt64 = 0x13
    public static let transferComplete: UInt64 = 0x14
    public static let error: UInt64 = 0x15
}

/// Envelope tags (wire.md §6).
public enum DeceiptEnvelope {
    public static let plaintext: UInt8 = 0x00
    public static let aead: UInt8 = 0x01
}

/// Direction byte inside the control AAD (handshake.md §6.2).
public enum DeceiptDirection: UInt8 {
    case c2m = 0
    case m2c = 1
}

/// Bounds (protocol/schema/bounds-v1.json).
public enum DeceiptBounds {
    // CBOR
    public static let cborMaxDepth = 12
    public static let cborMaxItems = 8192
    public static let cborMaxArray = 1024
    public static let cborMaxMap = 256
    public static let cborMaxTextBytes = 4096
    public static let cborMaxBytes = 65536
    public static let cborMaxMapKey: Int64 = 255

    // Receipt
    public static let maxReceiptBytes = 65536
    public static let maxLines = 256
    public static let maxDiscounts = 64
    public static let maxTaxes = 64
    public static let maxTenders = 32
    public static let maxExtensions = 32
    public static let maxModifiers = 16
    public static let maxAddressLines = 8
    public static let maxTextDescriptionBytes = 512
    public static let maxTextDisplayNameBytes = 128
    public static let maxTextShortBytes = 64
    public static let maxTextUnitBytes = 16
    public static let maxMonetaryAbs: Int64 = 1_000_000_000_000_000
    public static let maxUnitPriceAbs: Int64 = 1_000_000_000_000
    public static let maxQtyValueAbs: Int64 = 1_000_000
    public static let maxQtyScale = 9
    public static let maxArithProduct: Int64 = 4_611_686_018_427_387_904
    public static let maxTaxRatePpm: Int64 = 999_999
    public static let minIssuedAt: Int64 = 1_577_836_800
    public static let maxIssuedAt: Int64 = 4_102_444_800

    // Credential
    public static let maxCredentialBytes = 1024
    public static let capIssueSale: Int64 = 1
    public static let capIssueRefund: Int64 = 2
    public static let capIssueVoid: Int64 = 4
    public static let capReceiveTransfer: Int64 = 8
    public static let capEmbedCredential: Int64 = 16

    // Wire
    public static let maxControlPdu = 2048
    public static let maxLpduFragments = 512
    public static let maxLpduFragBytes = 512
    public static let lpduHeaderBytes = 4
    public static let maxAttPayload = 512
    public static let maxFramePayload = 512
    public static let minFramePayload = 16
    public static let finalFrameMinPayload = 1
    public static let dataframeHeaderBytes = 20
    public static let maxTransferCiphertext = 65552
    public static let maxFrames = 32768
    public static let aeadTagBytes = 16
    public static let aeadNonceBytes = 12
    public static let ackEveryFrames = 32
    public static let windowFrames = 64
    public static let maxFrameRetries = 5
    public static let maxControlMessagesPerDirection = 4096

    // Handshake
    public static let nonceBytes = 32
    public static let maxBindingBytes = 128
    public static let maxSessionIdHistory = 32

    /// `att_payload_max(att_mtu) = min(att_mtu − 3, 512)` (framing.md §1).
    public static func attPayloadMax(_ attMtu: Int) -> Int {
        min(max(attMtu - 3, 0), maxAttPayload)
    }

    /// `max_frame_payload_for_mtu(m) = min(att_payload_max(m) − 20, 512)`.
    public static func maxFramePayloadForMtu(_ attMtu: Int) -> Int {
        min(DeceiptBounds.attPayloadMax(attMtu) - DeceiptBounds.dataframeHeaderBytes, maxFramePayload)
    }
}

/// Timeout names and defaults (framing.md/handshake.md §7).
public enum DeceiptTimeout {
    public static let defaults: [String: Int] = [
        "T_ADVERTISE": 60_000,
        "T_CONNECT": 15_000,
        "T_HELLO_RESPONSE": 5_000,
        "T_ACCEPT": 10_000,
        "T_CONTROL_FRAG": 5_000,
        "T_ACK_WAIT": 3_000,
        "T_ACK_INTERVAL": 500,
        "T_TRANSFER_IDLE": 10_000,
        "T_VERIFY_BUDGET": 5_000,
        "T_SESSION": 120_000,
        "T_CLOSE": 2_000,
        "T_BINDING_QR": 300_000,
    ]
}
