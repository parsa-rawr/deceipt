package com.deceipt.adapter.protocol

/**
 * GENERATED from protocol/vectors/errors.json — do not edit by hand.
 * Revision: deceipt-proto-r3 (aggregate c974e832708774dcfe4910307b913914b47b8496bd3271b65a16eb27f8a266fa)
 *
 * The frozen typed-error taxonomy. A4/A5 MUST emit the same
 * name/code/fatal/retryable for the same condition so A6's conformance runner
 * can assert on identifiers alone (docs/protocol/verification.md 4).
 */
object Errors {

    data class Descriptor(
        val name: String,
        val code: Int,
        val fatal: Boolean,
        val retryable: Boolean,
        val category: String,
    )

    const val REVISION = "deceipt-proto-r3"
    const val AGGREGATE_SHA256 = "c974e832708774dcfe4910307b913914b47b8496bd3271b65a16eb27f8a266fa"

    /** Policy outcomes (errors.json#outcomes). */
    object Outcome {
        const val TRUSTED = 1
        const val UNVERIFIED_UNKNOWN_ISSUER = 2
        const val ALREADY_IMPORTED_IDENTICAL = 3
        const val REJECTED = 4
        const val PENDING = 5
    }

    val ALL: Map<String, Descriptor> = mapOf(
        "CBOR_MALFORMED" to Descriptor("CBOR_MALFORMED", 257, true, false, "encoding"),
        "CBOR_NONCANONICAL" to Descriptor("CBOR_NONCANONICAL", 258, true, false, "encoding"),
        "CBOR_DUPLICATE_KEY" to Descriptor("CBOR_DUPLICATE_KEY", 259, true, false, "encoding"),
        "CBOR_DEPTH_EXCEEDED" to Descriptor("CBOR_DEPTH_EXCEEDED", 260, true, false, "encoding"),
        "CBOR_SIZE_EXCEEDED" to Descriptor("CBOR_SIZE_EXCEEDED", 261, true, false, "encoding"),
        "CBOR_UNSUPPORTED_TYPE" to Descriptor("CBOR_UNSUPPORTED_TYPE", 262, true, false, "encoding"),
        "MESSAGE_UNKNOWN_TYPE" to Descriptor("MESSAGE_UNKNOWN_TYPE", 263, true, false, "message"),
        "MESSAGE_UNKNOWN_FIELD" to Descriptor("MESSAGE_UNKNOWN_FIELD", 264, true, false, "message"),
        "MESSAGE_MISSING_FIELD" to Descriptor("MESSAGE_MISSING_FIELD", 265, true, false, "message"),
        "MESSAGE_FIELD_TYPE" to Descriptor("MESSAGE_FIELD_TYPE", 266, true, false, "message"),
        "MESSAGE_FIELD_RANGE" to Descriptor("MESSAGE_FIELD_RANGE", 267, true, false, "message"),
        "MESSAGE_TOO_LARGE" to Descriptor("MESSAGE_TOO_LARGE", 268, true, false, "message"),
        "MESSAGE_WRONG_STATE" to Descriptor("MESSAGE_WRONG_STATE", 269, true, false, "message"),
        "MESSAGE_WRONG_DIRECTION" to Descriptor("MESSAGE_WRONG_DIRECTION", 270, true, false, "message"),
        "LPDU_FRAGMENT_INVALID" to Descriptor("LPDU_FRAGMENT_INVALID", 513, true, false, "transport"),
        "LPDU_SEQUENCE_ERROR" to Descriptor("LPDU_SEQUENCE_ERROR", 514, true, false, "transport"),
        "LPDU_CONFLICT" to Descriptor("LPDU_CONFLICT", 515, true, false, "transport"),
        "LPDU_REASSEMBLY_TIMEOUT" to Descriptor("LPDU_REASSEMBLY_TIMEOUT", 516, true, true, "transport"),
        "LPDU_MESSAGE_TOO_LARGE" to Descriptor("LPDU_MESSAGE_TOO_LARGE", 517, true, false, "transport"),
        "TRANSPORT_MTU_TOO_SMALL" to Descriptor("TRANSPORT_MTU_TOO_SMALL", 518, true, false, "transport"),
        "TRANSPORT_LINK_LOST" to Descriptor("TRANSPORT_LINK_LOST", 519, true, true, "transport"),
        "TRANSPORT_WRITE_FAILED" to Descriptor("TRANSPORT_WRITE_FAILED", 520, true, true, "transport"),
        "TRANSPORT_PERMISSION_DENIED" to Descriptor("TRANSPORT_PERMISSION_DENIED", 521, true, false, "transport"),
        "TRANSPORT_BLUETOOTH_OFF" to Descriptor("TRANSPORT_BLUETOOTH_OFF", 522, true, true, "transport"),
        "TRANSPORT_PEER_AMBIGUOUS" to Descriptor("TRANSPORT_PEER_AMBIGUOUS", 523, true, false, "transport"),
        "TRANSPORT_CONNECT_TIMEOUT" to Descriptor("TRANSPORT_CONNECT_TIMEOUT", 524, true, true, "transport"),
        "HANDSHAKE_UNSUPPORTED_VERSION" to Descriptor("HANDSHAKE_UNSUPPORTED_VERSION", 769, true, false, "handshake"),
        "HANDSHAKE_NO_COMMON_SUITE" to Descriptor("HANDSHAKE_NO_COMMON_SUITE", 770, true, false, "handshake"),
        "HANDSHAKE_ECDH_INVALID_POINT" to Descriptor("HANDSHAKE_ECDH_INVALID_POINT", 771, true, false, "handshake"),
        "HANDSHAKE_SIGNATURE_INVALID" to Descriptor("HANDSHAKE_SIGNATURE_INVALID", 772, true, false, "handshake"),
        "HANDSHAKE_TRANSCRIPT_MISMATCH" to Descriptor("HANDSHAKE_TRANSCRIPT_MISMATCH", 773, true, false, "handshake"),
        "HANDSHAKE_SUITE_MISMATCH" to Descriptor("HANDSHAKE_SUITE_MISMATCH", 774, true, false, "handshake"),
        "HANDSHAKE_NONCE_REPLAYED" to Descriptor("HANDSHAKE_NONCE_REPLAYED", 775, true, false, "handshake"),
        "CREDENTIAL_MALFORMED" to Descriptor("CREDENTIAL_MALFORMED", 776, true, false, "handshake"),
        "CREDENTIAL_SIGNATURE_INVALID" to Descriptor("CREDENTIAL_SIGNATURE_INVALID", 777, true, false, "handshake"),
        "CREDENTIAL_UNKNOWN_ISSUER" to Descriptor("CREDENTIAL_UNKNOWN_ISSUER", 778, false, false, "handshake"),
        "CREDENTIAL_NOT_YET_VALID" to Descriptor("CREDENTIAL_NOT_YET_VALID", 779, true, false, "handshake"),
        "CREDENTIAL_EXPIRED" to Descriptor("CREDENTIAL_EXPIRED", 780, true, false, "handshake"),
        "CREDENTIAL_CAPABILITY_MISSING" to Descriptor("CREDENTIAL_CAPABILITY_MISSING", 781, true, false, "handshake"),
        "HANDSHAKE_TIMEOUT" to Descriptor("HANDSHAKE_TIMEOUT", 784, true, true, "handshake"),
        "PEER_NOT_AUTHENTICATED" to Descriptor("PEER_NOT_AUTHENTICATED", 785, true, false, "handshake"),
        "BINDING_UNKNOWN_SESSION" to Descriptor("BINDING_UNKNOWN_SESSION", 786, true, false, "binding"),
        "BINDING_PROOF_INVALID" to Descriptor("BINDING_PROOF_INVALID", 787, true, false, "binding"),
        "BINDING_REQUIRED" to Descriptor("BINDING_REQUIRED", 788, true, false, "binding"),
        "BINDING_STALE" to Descriptor("BINDING_STALE", 789, true, true, "binding"),
        "BINDING_CONSUMED" to Descriptor("BINDING_CONSUMED", 790, true, false, "binding"),
        "SESSION_EXPIRED" to Descriptor("SESSION_EXPIRED", 791, true, false, "handshake"),
        "AEAD_AUTH_FAILED" to Descriptor("AEAD_AUTH_FAILED", 1025, true, false, "session"),
        "AEAD_COUNTER_MISMATCH" to Descriptor("AEAD_COUNTER_MISMATCH", 1026, true, false, "session"),
        "AEAD_REPLAY_DETECTED" to Descriptor("AEAD_REPLAY_DETECTED", 1027, true, false, "session"),
        "AEAD_NONCE_EXHAUSTED" to Descriptor("AEAD_NONCE_EXHAUSTED", 1028, true, false, "session"),
        "SESSION_TORN_DOWN" to Descriptor("SESSION_TORN_DOWN", 1029, true, false, "session"),
        "TRANSFER_SIZE_EXCEEDED" to Descriptor("TRANSFER_SIZE_EXCEEDED", 1281, true, false, "framing"),
        "FRAME_SIZE_INVALID" to Descriptor("FRAME_SIZE_INVALID", 1282, true, false, "framing"),
        "FRAME_SEQUENCE_OUT_OF_RANGE" to Descriptor("FRAME_SEQUENCE_OUT_OF_RANGE", 1283, true, false, "framing"),
        "FRAME_SEQUENCE_REPLAYED" to Descriptor("FRAME_SEQUENCE_REPLAYED", 1284, false, false, "framing"),
        "FRAME_CONFLICT" to Descriptor("FRAME_CONFLICT", 1285, true, false, "framing"),
        "FRAME_BUFFER_EXCEEDED" to Descriptor("FRAME_BUFFER_EXCEEDED", 1286, true, false, "framing"),
        "TRANSFER_INCOMPLETE" to Descriptor("TRANSFER_INCOMPLETE", 1287, true, true, "framing"),
        "TRANSFER_HASH_MISMATCH" to Descriptor("TRANSFER_HASH_MISMATCH", 1288, true, false, "framing"),
        "TRANSFER_TIMEOUT" to Descriptor("TRANSFER_TIMEOUT", 1289, true, true, "framing"),
        "TRANSFER_RETRY_EXHAUSTED" to Descriptor("TRANSFER_RETRY_EXHAUSTED", 1290, true, false, "framing"),
        "TRANSFER_CANCELLED" to Descriptor("TRANSFER_CANCELLED", 1291, true, false, "framing"),
        "TRANSFER_ABORTED" to Descriptor("TRANSFER_ABORTED", 1292, true, false, "framing"),
        "TRANSFER_BEGIN_MISMATCH" to Descriptor("TRANSFER_BEGIN_MISMATCH", 1293, true, false, "framing"),
        "TRANSFER_ID_MISMATCH" to Descriptor("TRANSFER_ID_MISMATCH", 1294, true, false, "framing"),
        "RECEIPT_CONTAINER_MALFORMED" to Descriptor("RECEIPT_CONTAINER_MALFORMED", 1537, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_VERSION" to Descriptor("RECEIPT_UNSUPPORTED_VERSION", 1538, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_ALGORITHM" to Descriptor("RECEIPT_UNSUPPORTED_ALGORITHM", 1539, true, false, "receipt"),
        "RECEIPT_UNKNOWN_HEADER" to Descriptor("RECEIPT_UNKNOWN_HEADER", 1540, true, false, "receipt"),
        "RECEIPT_UNKNOWN_FIELD" to Descriptor("RECEIPT_UNKNOWN_FIELD", 1541, true, false, "receipt"),
        "RECEIPT_SIZE_EXCEEDED" to Descriptor("RECEIPT_SIZE_EXCEEDED", 1542, true, false, "receipt"),
        "RECEIPT_SIGNATURE_INVALID" to Descriptor("RECEIPT_SIGNATURE_INVALID", 1543, true, false, "receipt"),
        "RECEIPT_KEY_NOT_AUTHORIZED" to Descriptor("RECEIPT_KEY_NOT_AUTHORIZED", 1544, true, false, "receipt"),
        "RECEIPT_SEMANTIC_INVALID" to Descriptor("RECEIPT_SEMANTIC_INVALID", 1545, true, false, "receipt"),
        "RECEIPT_ARITHMETIC_MISMATCH" to Descriptor("RECEIPT_ARITHMETIC_MISMATCH", 1546, true, false, "receipt"),
        "RECEIPT_MONETARY_RANGE" to Descriptor("RECEIPT_MONETARY_RANGE", 1547, true, false, "receipt"),
        "RECEIPT_UNSUPPORTED_CURRENCY" to Descriptor("RECEIPT_UNSUPPORTED_CURRENCY", 1548, true, false, "receipt"),
        "RECEIPT_DUPLICATE_CONFLICT" to Descriptor("RECEIPT_DUPLICATE_CONFLICT", 1549, true, false, "receipt"),
        "RECEIPT_OUTSIDE_KEY_VALIDITY" to Descriptor("RECEIPT_OUTSIDE_KEY_VALIDITY", 1550, true, false, "receipt"),
        "RECEIPT_CREDENTIAL_MISMATCH" to Descriptor("RECEIPT_CREDENTIAL_MISMATCH", 1551, true, false, "receipt"),
        "RECEIPT_TEXT_INVALID" to Descriptor("RECEIPT_TEXT_INVALID", 1553, true, false, "receipt"),
        "RECEIPT_UNKNOWN_CRITICAL_EXTENSION" to Descriptor("RECEIPT_UNKNOWN_CRITICAL_EXTENSION", 1554, true, false, "receipt"),
        "RECEIPT_ISSUED_IN_FUTURE" to Descriptor("RECEIPT_ISSUED_IN_FUTURE", 1555, true, false, "receipt"),
        "WRONG_TRANSACTION" to Descriptor("WRONG_TRANSACTION", 1556, true, false, "receipt"),
        "RECEIPT_NONCANONICAL" to Descriptor("RECEIPT_NONCANONICAL", 1557, true, false, "receipt"),
        "STORAGE_FAILED" to Descriptor("STORAGE_FAILED", 1793, true, true, "local"),
        "USER_CANCELLED" to Descriptor("USER_CANCELLED", 1794, true, false, "local"),
        "VERIFY_BUDGET_EXCEEDED" to Descriptor("VERIFY_BUDGET_EXCEEDED", 1795, true, false, "local"),
        "CAPABILITY_UNAVAILABLE" to Descriptor("CAPABILITY_UNAVAILABLE", 1796, true, false, "local"),
        "INTERNAL_ERROR" to Descriptor("INTERNAL_ERROR", 1797, true, true, "local"),
    )

    fun descriptor(name: String): Descriptor =
        ALL[name] ?: error("unknown frozen error name: " + name)
}

/**
 * A typed protocol failure carrying the frozen identifiers. Native code throws
 * this; the module boundary converts it to the `BridgeError` wire shape.
 */
class ProtocolError(
    val errorName: String,
    val detail: String? = null,
    cause: Throwable? = null,
) : Exception(detail ?: errorName, cause) {

    val descriptor: Errors.Descriptor get() = Errors.descriptor(errorName)
    val code: Int get() = descriptor.code
    val fatal: Boolean get() = descriptor.fatal
    val retryable: Boolean get() = descriptor.retryable

    /** The `BridgeError` JSON shape (DeceiptNative.ts). `detail` is bounded, no secrets. */
    fun toBridge(phase: String? = null): Map<String, Any?> {
        val m = HashMap<String, Any?>()
        m["name"] = descriptor.name
        m["code"] = descriptor.code
        m["fatal"] = descriptor.fatal
        m["retryable"] = descriptor.retryable
        if (phase != null) m["phase"] = phase
        val d = detail
        if (d != null) m["detail"] = d.take(64)
        return m
    }
}

/** Narrow a throwable to a typed protocol failure. */
fun asProtocolError(t: Throwable): ProtocolError? = t as? ProtocolError
