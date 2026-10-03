package com.deceipt.adapter.protocol

/** Maps the contract's `RECEIPT_ACK_OUTCOME` keys to the frozen wire codes. */
object OutcomeCodes {
    const val TRUSTED = 1
    const val UNKNOWN_ISSUER = 2
    const val ALREADY_IMPORTED = 3
    const val REJECTED = 4

    fun of(key: String): Int = when (key) {
        "trusted" -> TRUSTED
        "unknown_issuer" -> UNKNOWN_ISSUER
        "already_imported" -> ALREADY_IMPORTED
        "rejected" -> REJECTED
        else -> throw ProtocolError("MESSAGE_FIELD_RANGE", "unknown RECEIPT_ACK outcome $key")
    }
}
