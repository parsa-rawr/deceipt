package com.deceipt.adapter.protocol

/**
 * Reads the offer-relevant fields out of an exact signed receipt
 * (`DeceiptReceiptV1`, docs/protocol/receipt-v1.md 3–4). Native needs these to
 * build `RECEIPT_OFFER` without re-encoding the receipt: the offer is display
 * metadata that commits to the transaction, and the receipt itself travels
 * unchanged.
 *
 * This reads the payload bytes as received; it never re-encodes or re-signs.
 */
object Receipt {

    data class OfferFields(
        val receiptId: ByteArray,
        val issuedAt: Long,
        val merchantId: ByteArray,
        val merchantReference: String,
        val currency: String,
        val totalAmountMinor: Long,
        val kind: Long,
    )

    fun extractOfferFields(coseSign1: ByteArray): OfferFields {
        val sign1 = Cose.parse(coseSign1, Bounds.MAX_RECEIPT_BYTES)
        val body = CborCodec.decode(sign1.payload) as? Cbor.Map
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "receipt payload must be a map")
        val m = body.entries

        fun bstr(label: Long): ByteArray =
            (m[label] as? Cbor.BStr)?.value ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "label $label")
        fun uint(label: Long): Long =
            (m[label] as? Cbor.UInt)?.value ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "label $label")
        fun tstr(label: Long): String =
            (m[label] as? Cbor.TStr)?.value ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "label $label")
        fun map(label: Long): Map<Long, Cbor> =
            (m[label] as? Cbor.Map)?.entries ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "label $label")

        val receiptId = bstr(3L)
        if (receiptId.size != 16) throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "receipt_id length")
        val issuedAt = uint(4L)
        val merchant = map(6L)
        val merchantId = (merchant[1L] as? Cbor.BStr)?.value
            ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "merchant_id")
        val merchantReference = (merchant[3L] as? Cbor.TStr)?.value
            ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "merchant_reference")
        val currency = tstr(8L)
        val kind = uint(2L)
        val totals = map(15L)
        val total = (totals[4L] as? Cbor.UInt)?.value
            ?: throw ProtocolError("RECEIPT_SEMANTIC_INVALID", "totals.total_minor")

        return OfferFields(receiptId, issuedAt, merchantId, merchantReference, currency, total, kind)
    }

    /** `SHA-256(exact credential bytes)` — RECEIPT_OFFER label 11. */
    fun credentialHash(credentialBytes: ByteArray): ByteArray = Cose.sha256(credentialBytes)
}
