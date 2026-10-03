package com.deceipt.adapter.protocol

/**
 * GENERATED from protocol/schema/bounds-v1.json — do not edit by hand.
 * Revision: deceipt-proto-r3
 *
 * Parser and allocation bounds are SECURITY requirements (DESIGN.md 13.11):
 * never allocate from a peer-declared length before checking it against a cap.
 */
object Bounds {
    const val REVISION = "deceipt-proto-r3"
    const val PROTOCOL_VERSION = 1
    const val SUITE_ID = 1
    const val CLOCK_SKEW_MAX_S = 300

    // --- CBOR ---
    const val CBOR_MAX_DEPTH = 12
    const val CBOR_MAX_ITEMS = 8192
    const val CBOR_MAX_ARRAY = 1024
    const val CBOR_MAX_MAP = 256
    const val CBOR_MAX_TEXT_BYTES = 4096
    const val CBOR_MAX_BYTES = 65536

    // --- wire ---
    const val MAX_CONTROL_PDU = 2048
    const val MAX_LPDU_FRAGMENTS = 512
    const val MAX_LPDU_FRAG_BYTES = 512
    const val LPDU_HEADER_BYTES = 4
    const val MAX_ATT_PAYLOAD = 512
    const val MAX_FRAME_PAYLOAD = 512
    const val MIN_FRAME_PAYLOAD = 16
    const val FINAL_FRAME_MIN_PAYLOAD = 1
    const val DATAFRAME_HEADER_BYTES = 20
    const val MAX_TRANSFER_CIPHERTEXT = 65552
    const val MAX_FRAMES = 32768
    const val AEAD_TAG_BYTES = 16
    const val AEAD_NONCE_BYTES = 12
    const val AEAD_CTRL_ENVELOPE_OVERHEAD = 25
    const val ACK_EVERY_FRAMES = 32
    const val WINDOW_FRAMES = 64
    const val MAX_FRAME_RETRIES = 5
    const val MAX_CONTROL_MESSAGES_PER_DIRECTION = 4096

    const val MESSAGE_TYPES_CLIENT_HELLO = 0x01
    const val MESSAGE_TYPES_ACCEPT = 0x02
    const val MESSAGE_TYPES_ACK = 0x03
    const val MESSAGE_TYPES_RECEIPT_ACK = 0x04
    const val MESSAGE_TYPES_CANCEL = 0x05
    const val MESSAGE_TYPES_RETRY = 0x06
    const val MESSAGE_TYPES_SERVER_HELLO = 0x11
    const val MESSAGE_TYPES_RECEIPT_OFFER = 0x12
    const val MESSAGE_TYPES_TRANSFER_BEGIN = 0x13
    const val MESSAGE_TYPES_TRANSFER_COMPLETE = 0x14
    const val MESSAGE_TYPES_ERROR = 0x15

    const val ENVELOPE_PLAINTEXT = 0x00
    const val ENVELOPE_AEAD = 0x01

    // --- handshake ---
    const val NONCE_BYTES = 32
    const val TRANSCRIPT_LEN = 372
    const val MAX_BINDING_BYTES = 128
    const val MAX_SESSION_ID_HISTORY = 32

    // --- receipt / credential ---
    const val MAX_RECEIPT_BYTES = 65536
    const val MAX_CREDENTIAL_BYTES = 1024

    /** `att_payload_max(att_mtu) = min(att_mtu - 3, 512)` (wire.md 5). */
    fun attPayloadMax(attMtu: Int): Int = minOf(attMtu - 3, MAX_ATT_PAYLOAD)

    /** `max_frame_payload_for_mtu(m) = min(att_payload_max(m) - 20, 512)`. */
    fun maxFramePayloadForMtu(attMtu: Int): Int =
        minOf(attPayloadMax(attMtu) - DATAFRAME_HEADER_BYTES, MAX_FRAME_PAYLOAD)

    /** Frozen timeout values, keyed by TimeoutName. */
    val TIMEOUTS_MS: Map<String, Long> = mapOf(
        "T_ADVERTISE" to 60000L,
        "T_CONNECT" to 15000L,
        "T_HELLO_RESPONSE" to 5000L,
        "T_ACCEPT" to 10000L,
        "T_CONTROL_FRAG" to 5000L,
        "T_ACK_WAIT" to 3000L,
        "T_ACK_INTERVAL" to 500L,
        "T_TRANSFER_IDLE" to 10000L,
        "T_VERIFY_BUDGET" to 5000L,
        "T_SESSION" to 120000L,
        "T_CLOSE" to 2000L,
        "T_BINDING_QR" to 300000L,
    )
}
