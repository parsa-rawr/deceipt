//
//  DeceiptError.swift
//  Deceipt iOS native adapter (A4)
//
//  The frozen typed-error taxonomy from protocol/vectors/errors.json
//  (91 errors, stable u16 codes). `name`/`code`/`fatal`/`retryable` MUST be
//  identical on both platforms so A6's conformance runner can assert on
//  identifiers alone (verification.md §4).
//
//  Semantics are transport-independent; Swift type names may differ but the
//  emitted name/code/fatal/retryable may not.
//

import Foundation

/// The frozen identifier used in vectors and on the bridge.
public typealias ProtocolErrorName = String

public struct ProtocolErrorSpec {
    public let code: UInt16
    public let fatal: Bool
    public let retryable: Bool
    public let category: String

    init(_ code: UInt16, _ fatal: Bool, _ retryable: Bool, _ category: String) {
        self.code = code
        self.fatal = fatal
        self.retryable = retryable
        self.category = category
    }
}

/// Generated from protocol/vectors/errors.json (r2). Keys are the frozen
/// identifiers; values are the frozen (code, fatal, retryable, category).
public enum DeceiptErrors {
    public static let table: [ProtocolErrorName: ProtocolErrorSpec] = [
        "CBOR_MALFORMED": .init(257, true, false, "encoding"),
        "CBOR_NONCANONICAL": .init(258, true, false, "encoding"),
        "CBOR_DUPLICATE_KEY": .init(259, true, false, "encoding"),
        "CBOR_DEPTH_EXCEEDED": .init(260, true, false, "encoding"),
        "CBOR_SIZE_EXCEEDED": .init(261, true, false, "encoding"),
        "CBOR_UNSUPPORTED_TYPE": .init(262, true, false, "encoding"),
        "MESSAGE_UNKNOWN_TYPE": .init(263, true, false, "message"),
        "MESSAGE_UNKNOWN_FIELD": .init(264, true, false, "message"),
        "MESSAGE_MISSING_FIELD": .init(265, true, false, "message"),
        "MESSAGE_FIELD_TYPE": .init(266, true, false, "message"),
        "MESSAGE_FIELD_RANGE": .init(267, true, false, "message"),
        "MESSAGE_TOO_LARGE": .init(268, true, false, "message"),
        "MESSAGE_WRONG_STATE": .init(269, true, false, "message"),
        "MESSAGE_WRONG_DIRECTION": .init(270, true, false, "message"),
        "LPDU_FRAGMENT_INVALID": .init(513, true, false, "transport"),
        "LPDU_SEQUENCE_ERROR": .init(514, true, false, "transport"),
        "LPDU_CONFLICT": .init(515, true, false, "transport"),
        "LPDU_REASSEMBLY_TIMEOUT": .init(516, true, true, "transport"),
        "LPDU_MESSAGE_TOO_LARGE": .init(517, true, false, "transport"),
        "TRANSPORT_MTU_TOO_SMALL": .init(518, true, false, "transport"),
        "TRANSPORT_LINK_LOST": .init(519, true, true, "transport"),
        "TRANSPORT_WRITE_FAILED": .init(520, true, true, "transport"),
        "TRANSPORT_PERMISSION_DENIED": .init(521, true, false, "transport"),
        "TRANSPORT_BLUETOOTH_OFF": .init(522, true, true, "transport"),
        "TRANSPORT_PEER_AMBIGUOUS": .init(523, true, false, "transport"),
        "TRANSPORT_CONNECT_TIMEOUT": .init(524, true, true, "transport"),
        "HANDSHAKE_UNSUPPORTED_VERSION": .init(769, true, false, "handshake"),
        "HANDSHAKE_NO_COMMON_SUITE": .init(770, true, false, "handshake"),
        "HANDSHAKE_ECDH_INVALID_POINT": .init(771, true, false, "handshake"),
        "HANDSHAKE_SIGNATURE_INVALID": .init(772, true, false, "handshake"),
        "HANDSHAKE_TRANSCRIPT_MISMATCH": .init(773, true, false, "handshake"),
        "HANDSHAKE_SUITE_MISMATCH": .init(774, true, false, "handshake"),
        "HANDSHAKE_NONCE_REPLAYED": .init(775, true, false, "handshake"),
        "CREDENTIAL_MALFORMED": .init(776, true, false, "handshake"),
        "CREDENTIAL_SIGNATURE_INVALID": .init(777, true, false, "handshake"),
        "CREDENTIAL_UNKNOWN_ISSUER": .init(778, false, false, "handshake"),
        "CREDENTIAL_NOT_YET_VALID": .init(779, true, false, "handshake"),
        "CREDENTIAL_EXPIRED": .init(780, true, false, "handshake"),
        "CREDENTIAL_CAPABILITY_MISSING": .init(781, true, false, "handshake"),
        "HANDSHAKE_TIMEOUT": .init(784, true, true, "handshake"),
        "PEER_NOT_AUTHENTICATED": .init(785, true, false, "handshake"),
        "BINDING_UNKNOWN_SESSION": .init(786, true, false, "binding"),
        "BINDING_PROOF_INVALID": .init(787, true, false, "binding"),
        "BINDING_REQUIRED": .init(788, true, false, "binding"),
        "BINDING_STALE": .init(789, true, true, "binding"),
        "BINDING_CONSUMED": .init(790, true, false, "binding"),
        "SESSION_EXPIRED": .init(791, true, false, "handshake"),
        "AEAD_AUTH_FAILED": .init(1025, true, false, "session"),
        "AEAD_COUNTER_MISMATCH": .init(1026, true, false, "session"),
        "AEAD_REPLAY_DETECTED": .init(1027, true, false, "session"),
        "AEAD_NONCE_EXHAUSTED": .init(1028, true, false, "session"),
        "SESSION_TORN_DOWN": .init(1029, true, false, "session"),
        "TRANSFER_SIZE_EXCEEDED": .init(1281, true, false, "framing"),
        "FRAME_SIZE_INVALID": .init(1282, true, false, "framing"),
        "FRAME_SEQUENCE_OUT_OF_RANGE": .init(1283, true, false, "framing"),
        "FRAME_SEQUENCE_REPLAYED": .init(1284, false, false, "framing"),
        "FRAME_CONFLICT": .init(1285, true, false, "framing"),
        "FRAME_BUFFER_EXCEEDED": .init(1286, true, false, "framing"),
        "TRANSFER_INCOMPLETE": .init(1287, true, true, "framing"),
        "TRANSFER_HASH_MISMATCH": .init(1288, true, false, "framing"),
        "TRANSFER_TIMEOUT": .init(1289, true, true, "framing"),
        "TRANSFER_RETRY_EXHAUSTED": .init(1290, true, false, "framing"),
        "TRANSFER_CANCELLED": .init(1291, true, false, "framing"),
        "TRANSFER_ABORTED": .init(1292, true, false, "framing"),
        "TRANSFER_BEGIN_MISMATCH": .init(1293, true, false, "framing"),
        "TRANSFER_ID_MISMATCH": .init(1294, true, false, "framing"),
        "RECEIPT_CONTAINER_MALFORMED": .init(1537, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_VERSION": .init(1538, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_ALGORITHM": .init(1539, true, false, "receipt"),
        "RECEIPT_UNKNOWN_HEADER": .init(1540, true, false, "receipt"),
        "RECEIPT_UNKNOWN_FIELD": .init(1541, true, false, "receipt"),
        "RECEIPT_SIZE_EXCEEDED": .init(1542, true, false, "receipt"),
        "RECEIPT_SIGNATURE_INVALID": .init(1543, true, false, "receipt"),
        "RECEIPT_KEY_NOT_AUTHORIZED": .init(1544, true, false, "receipt"),
        "RECEIPT_SEMANTIC_INVALID": .init(1545, true, false, "receipt"),
        "RECEIPT_ARITHMETIC_MISMATCH": .init(1546, true, false, "receipt"),
        "RECEIPT_MONETARY_RANGE": .init(1547, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_CURRENCY": .init(1548, true, false, "receipt"),
        "RECEIPT_DUPLICATE_CONFLICT": .init(1549, true, false, "receipt"),
        "RECEIPT_OUTSIDE_KEY_VALIDITY": .init(1550, true, false, "receipt"),
        "RECEIPT_CREDENTIAL_MISMATCH": .init(1551, true, false, "receipt"),
        "RECEIPT_TEXT_INVALID": .init(1553, true, false, "receipt"),
        "RECEIPT_UNKNOWN_CRITICAL_EXTENSION": .init(1554, true, false, "receipt"),
        "RECEIPT_ISSUED_IN_FUTURE": .init(1555, true, false, "receipt"),
        "WRONG_TRANSACTION": .init(1556, true, false, "receipt"),
        "RECEIPT_NONCANONICAL": .init(1557, true, false, "receipt"),
        "STORAGE_FAILED": .init(1793, true, true, "local"),
        "USER_CANCELLED": .init(1794, true, false, "local"),
        "VERIFY_BUDGET_EXCEEDED": .init(1795, true, false, "local"),
        "CAPABILITY_UNAVAILABLE": .init(1796, true, false, "local"),
        "INTERNAL_ERROR": .init(1797, true, true, "local"),
    ]

    public static func spec(_ name: ProtocolErrorName) -> ProtocolErrorSpec {
        table[name] ?? ProtocolErrorSpec(1797, true, true, "local")
    }
}

/// The bridge-facing error shape. Mirrors A3's `BridgeError`.
public struct BridgeErrorShape {
    public var name: ProtocolErrorName
    public var code: UInt16
    public var fatal: Bool
    public var retryable: Bool
    public var phase: String?
    public var detail: String?

    public init(name: ProtocolErrorName, phase: String? = nil, detail: String? = nil) {
        let s = DeceiptErrors.spec(name)
        self.name = name
        self.code = s.code
        self.fatal = s.fatal
        self.retryable = s.retryable
        self.phase = phase
        self.detail = detail.map { $0.count > 64 ? String($0.prefix(64)) : $0 }
    }

    public var asDictionary: [String: Any] {
        var d: [String: Any] = [
            "name": name,
            "code": NSNumber(value: code),
            "fatal": fatal,
            "retryable": retryable,
        ]
        if let p = phase { d["phase"] = p }
        if let de = detail { d["detail"] = String(de.prefix(64)) }
        return d
    }
}

/// Internal throwable used throughout the protocol engine. Carries a
/// `BridgeErrorShape`; `DeceiptBridgeError` (the JS-visible class) is raised
/// only at the bridge boundary.
public struct DeceiptFailure: Error {
    public let bridge: BridgeErrorShape
    public init(_ name: ProtocolErrorName, phase: String? = nil, detail: String? = nil) {
        self.bridge = BridgeErrorShape(name: name, phase: phase, detail: detail)
    }
    public init(bridge: BridgeErrorShape) { self.bridge = bridge }
}

/// Phase identifiers from A3's `BridgePhase`.
public enum BridgePhase {
    public static let permission = "permission"
    public static let scan = "scan"
    public static let advertising = "advertising"
    public static let connect = "connect"
    public static let handshake = "handshake"
    public static let credential = "credential"
    public static let binding = "binding"
    public static let transfer = "transfer"
    public static let receipt = "receipt"
    public static let keys = "keys"
    public static let teardown = "teardown"
    public static let `internal` = "internal"
}
