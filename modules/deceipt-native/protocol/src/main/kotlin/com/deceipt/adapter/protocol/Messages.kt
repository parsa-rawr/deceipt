package com.deceipt.adapter.protocol

/**
 * Control messages (wire.md 2, deceipt-proto-r3). `DataFrame` is NOT here — it
 * has its own layout (Frame.kt). Unknown labels are fatal `MESSAGE_UNKNOWN_FIELD`.
 */
object Messages {

    data class Accept(val transferId: ByteArray, val protocolVersion: Long, val suiteId: Long)
    data class Ack(val transferId: ByteArray, val highestContiguousSequence: Long)
    data class ReceiptAck(val transferId: ByteArray, val receiptId: ByteArray, val outcome: Long)
    data class Cancel(val transferId: ByteArray?, val errorCode: Long?)
    data class Retry(val transferId: ByteArray, val fromSequence: Long)
    data class Error(val errorCode: Long, val fatal: Boolean, val transferId: ByteArray?, val detail: String?)

    data class ReceiptOffer(
        val transferId: ByteArray,
        val receiptId: ByteArray,
        val merchantReference: String,
        val totalAmountMinor: Long,
        val currency: String,
        val issuedAt: Long,
        val kind: Long,
        val ciphertextLength: Long,
        val merchantId: ByteArray,
        val credentialHash: ByteArray,
        val sessionId: ByteArray,
    )

    data class TransferBegin(
        val transferId: ByteArray,
        val ciphertextLength: Long,
        val payloadHash: ByteArray,
        val frameSize: Long,
        val frameCount: Long,
    )

    data class TransferComplete(val transferId: ByteArray, val frameCount: Long, val payloadHash: ByteArray)

    // -- helpers -------------------------------------------------------------

    private fun entries(bytes: ByteArray): Map<Long, Cbor> {
        if (bytes.size > Bounds.MAX_CONTROL_PDU) throw ProtocolError("MESSAGE_TOO_LARGE")
        val m = CborCodec.decode(bytes) as? Cbor.Map ?: throw ProtocolError("CBOR_MALFORMED", "message must be a map")
        return m.entries
    }

    private fun req(m: Map<Long, Cbor>, label: Long, name: String): Cbor =
        m[label] ?: throw ProtocolError("MESSAGE_MISSING_FIELD", name)

    private fun uint(m: Map<Long, Cbor>, label: Long, name: String): Long =
        (req(m, label, name) as? Cbor.UInt)?.value ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)

    private fun bstr(m: Map<Long, Cbor>, label: Long, name: String, len: Int?): ByteArray {
        val b = req(m, label, name) as? Cbor.BStr ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)
        if (len != null && b.value.size != len) throw ProtocolError("MESSAGE_FIELD_RANGE", name)
        return b.value
    }

    private fun tstr(m: Map<Long, Cbor>, label: Long, name: String): String =
        (req(m, label, name) as? Cbor.TStr)?.value ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)

    private fun checkNoUnknown(m: Map<Long, Cbor>, allowed: Set<Long>) {
        for (k in m.keys) if (k !in allowed) throw ProtocolError("MESSAGE_UNKNOWN_FIELD", "label $k")
    }

    private fun expectType(m: Map<Long, Cbor>, type: Long) {
        if (uint(m, 1L, "type") != type) throw ProtocolError("MESSAGE_UNKNOWN_TYPE")
    }

    // -- encoders ------------------------------------------------------------

    fun encodeAccept(a: Accept): ByteArray = CborCodec.encode(
        Cbor.Map(linkedMapOf(1L to Cbor.of(2L), 2L to Cbor.BStr(a.transferId), 3L to Cbor.of(a.protocolVersion), 4L to Cbor.of(a.suiteId))),
    )

    fun encodeAck(a: Ack): ByteArray = CborCodec.encode(
        Cbor.Map(linkedMapOf(1L to Cbor.of(3L), 2L to Cbor.BStr(a.transferId), 3L to Cbor.of(a.highestContiguousSequence))),
    )

    fun encodeReceiptAck(a: ReceiptAck): ByteArray = CborCodec.encode(
        Cbor.Map(linkedMapOf(1L to Cbor.of(4L), 2L to Cbor.BStr(a.transferId), 3L to Cbor.BStr(a.receiptId), 4L to Cbor.of(a.outcome))),
    )

    fun encodeCancel(c: Cancel): ByteArray {
        val m = linkedMapOf<Long, Cbor>(1L to Cbor.of(5L))
        c.transferId?.let { m[2L] = Cbor.BStr(it) }
        c.errorCode?.let { m[3L] = Cbor.of(it) }
        return CborCodec.encode(Cbor.Map(m))
    }

    fun encodeRetry(r: Retry): ByteArray = CborCodec.encode(
        Cbor.Map(linkedMapOf(1L to Cbor.of(6L), 2L to Cbor.BStr(r.transferId), 3L to Cbor.of(r.fromSequence))),
    )

    fun encodeError(e: Error): ByteArray {
        val m = linkedMapOf<Long, Cbor>(1L to Cbor.of(21L), 2L to Cbor.of(e.errorCode), 3L to Cbor.of(e.fatal))
        e.transferId?.let { m[4L] = Cbor.BStr(it) }
        e.detail?.let { m[5L] = Cbor.TStr(it.take(64)) }
        return CborCodec.encode(Cbor.Map(m))
    }

    fun encodeReceiptOffer(o: ReceiptOffer): ByteArray = CborCodec.encode(
        Cbor.Map(
            linkedMapOf(
                1L to Cbor.of(18L),
                2L to Cbor.BStr(o.transferId),
                3L to Cbor.BStr(o.receiptId),
                4L to Cbor.TStr(o.merchantReference),
                5L to Cbor.of(o.totalAmountMinor),
                6L to Cbor.TStr(o.currency),
                7L to Cbor.of(o.issuedAt),
                8L to Cbor.of(o.kind),
                9L to Cbor.of(o.ciphertextLength),
                10L to Cbor.BStr(o.merchantId),
                11L to Cbor.BStr(o.credentialHash),
                12L to Cbor.BStr(o.sessionId),
            ),
        ),
    )

    fun encodeTransferBegin(t: TransferBegin): ByteArray = CborCodec.encode(
        Cbor.Map(
            linkedMapOf(
                1L to Cbor.of(19L),
                2L to Cbor.BStr(t.transferId),
                3L to Cbor.of(t.ciphertextLength),
                4L to Cbor.BStr(t.payloadHash),
                5L to Cbor.of(t.frameSize),
                6L to Cbor.of(t.frameCount),
            ),
        ),
    )

    fun encodeTransferComplete(t: TransferComplete): ByteArray = CborCodec.encode(
        Cbor.Map(linkedMapOf(1L to Cbor.of(20L), 2L to Cbor.BStr(t.transferId), 3L to Cbor.of(t.frameCount), 4L to Cbor.BStr(t.payloadHash))),
    )

    // -- parsers -------------------------------------------------------------

    fun parseAccept(bytes: ByteArray): Accept {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L, 4L)); expectType(m, 2L)
        return Accept(bstr(m, 2L, "transfer_id", 16), uint(m, 3L, "protocol_version"), uint(m, 4L, "suite_id"))
    }

    fun parseAck(bytes: ByteArray): Ack {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L)); expectType(m, 3L)
        return Ack(bstr(m, 2L, "transfer_id", 16), uint(m, 3L, "highest_contiguous_sequence"))
    }

    fun parseReceiptAck(bytes: ByteArray): ReceiptAck {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L, 4L)); expectType(m, 4L)
        return ReceiptAck(bstr(m, 2L, "transfer_id", 16), bstr(m, 3L, "receipt_id", 16), uint(m, 4L, "outcome"))
    }

    fun parseCancel(bytes: ByteArray): Cancel {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L)); expectType(m, 5L)
        val tid = (m[2L] as? Cbor.BStr)?.value
        val code = (m[3L] as? Cbor.UInt)?.value
        return Cancel(tid, code)
    }

    fun parseRetry(bytes: ByteArray): Retry {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L)); expectType(m, 6L)
        return Retry(bstr(m, 2L, "transfer_id", 16), uint(m, 3L, "from_sequence"))
    }

    fun parseError(bytes: ByteArray): Error {
        val m = entries(bytes)
        checkNoUnknown(m, setOf(1L, 2L, 3L, 4L, 5L)); expectType(m, 21L)
        val fatal = (req(m, 3L, "fatal") as? Cbor.Bool)?.value ?: throw ProtocolError("MESSAGE_FIELD_TYPE", "fatal")
        val tid = (m[4L] as? Cbor.BStr)?.value
        val detail = (m[5L] as? Cbor.TStr)?.value
        return Error(uint(m, 2L, "error_code"), fatal, tid, detail)
    }

    fun parseReceiptOffer(bytes: ByteArray): ReceiptOffer {
        val m = entries(bytes)
        checkNoUnknown(m, setOf(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L, 11L, 12L)); expectType(m, 18L)
        val kind = uint(m, 8L, "kind")
        if (kind !in 1L..3L) throw ProtocolError("MESSAGE_FIELD_RANGE", "kind")
        val ciphertextLength = uint(m, 9L, "ciphertext_length")
        if (ciphertextLength > Bounds.MAX_TRANSFER_CIPHERTEXT.toLong()) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
        return ReceiptOffer(
            transferId = bstr(m, 2L, "transfer_id", 16),
            receiptId = bstr(m, 3L, "receipt_id", 16),
            merchantReference = tstr(m, 4L, "merchant_reference"),
            totalAmountMinor = uint(m, 5L, "total_amount_minor"),
            currency = tstr(m, 6L, "currency"),
            issuedAt = uint(m, 7L, "issued_at"),
            kind = kind,
            ciphertextLength = ciphertextLength,
            merchantId = bstr(m, 10L, "merchant_id", 16),
            credentialHash = bstr(m, 11L, "credential_hash", 32),
            sessionId = bstr(m, 12L, "session_id", 16),
        )
    }

    fun parseTransferBegin(bytes: ByteArray): TransferBegin {
        val m = entries(bytes)
        checkNoUnknown(m, setOf(1L, 2L, 3L, 4L, 5L, 6L)); expectType(m, 19L)
        val len = uint(m, 3L, "ciphertext_length")
        if (len > Bounds.MAX_TRANSFER_CIPHERTEXT.toLong()) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
        val frameSize = uint(m, 5L, "frame_size")
        if (frameSize < Bounds.MIN_FRAME_PAYLOAD || frameSize > Bounds.MAX_FRAME_PAYLOAD) {
            throw ProtocolError("FRAME_SIZE_INVALID", "frame_size")
        }
        val frameCount = uint(m, 6L, "frame_count")
        if (frameCount > Bounds.MAX_FRAMES.toLong()) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
        if (frameCount != ((len + frameSize - 1) / frameSize)) {
            throw ProtocolError("TRANSFER_BEGIN_MISMATCH", "frame_count != ceil(ciphertext_length/frame_size)")
        }
        return TransferBegin(bstr(m, 2L, "transfer_id", 16), len, bstr(m, 4L, "payload_hash", 32), frameSize, frameCount)
    }

    fun parseTransferComplete(bytes: ByteArray): TransferComplete {
        val m = entries(bytes); checkNoUnknown(m, setOf(1L, 2L, 3L, 4L)); expectType(m, 20L)
        return TransferComplete(bstr(m, 2L, "transfer_id", 16), uint(m, 3L, "frame_count"), bstr(m, 4L, "payload_hash", 32))
    }

    /** The `type` of a control message without full parsing. */
    fun peekType(bytes: ByteArray): Long = uint(entries(bytes), 1L, "type")
}
