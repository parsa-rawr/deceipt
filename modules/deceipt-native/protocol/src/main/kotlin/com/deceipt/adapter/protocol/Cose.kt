package com.deceipt.adapter.protocol

import com.deceipt.adapter.crypto.Crypto
import com.deceipt.adapter.crypto.Ed25519

/**
 * COSE_Sign1 (RFC 9052) container handling for the Deceipt v1 profile.
 *
 * `COSE_Sign1 = [ protected : bstr .cbor protected-map, unprotected : {}, payload : bstr, signature : bstr(64) ]`
 *
 * The container MUST be canonical: re-encoding the parsed array MUST reproduce
 * the received bytes, else `RECEIPT_NONCANONICAL` (receipt-v1.md 2).
 *
 * Signature verification is ALWAYS over `Sig_structure` built from the payload
 * bytes AS RECEIVED. Decoding, modifying and re-encoding is prohibited
 * (DESIGN.md 4.1) — never re-encode-then-verify.
 */
object Cose {

    const val ALG_EDDSA = -8
    const val CONTENT_TYPE_RECEIPT = "application/deceipt-receipt+cbor"
    const val CONTENT_TYPE_CREDENTIAL = "application/deceipt-credential+cbor"

    data class Sign1(
        val protectedBytes: ByteArray,
        val protectedMap: Map<Long, Cbor>,
        val unprotected: Cbor.Map,
        val payload: ByteArray,
        val signature: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is Sign1 &&
            protectedBytes.contentEquals(other.protectedBytes) &&
            payload.contentEquals(other.payload) && signature.contentEquals(other.signature)
        override fun hashCode(): Int = payload.contentHashCode()
    }

    /** `Sig_structure = CBOR(["Signature1", protected_bstr, h'', payload_bstr])`. */
    fun sigStructure(protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        CborCodec.encodeBytes(
            Cbor.Arr(
                listOf(
                    Cbor.TStr("Signature1"),
                    Cbor.BStr(protectedBytes),
                    Cbor.BStr(ByteArray(0)),
                    Cbor.BStr(payload),
                ),
            ),
        )

    /**
     * Parse and structurally validate a COSE_Sign1 container.
     * `maxBytes` bounds the container (receipt vs credential).
     */
    fun parse(bytes: ByteArray, maxBytes: Int): Sign1 {
        if (bytes.size > maxBytes) throw ProtocolError("RECEIPT_SIZE_EXCEEDED")
        val top = CborCodec.decode(bytes)
        val arr = top as? Cbor.Arr ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "not a 4-element array")
        if (arr.items.size != 4) throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "expected 4 elements")
        // Canonicality: the received bytes must be reproduced exactly.
        if (!CborCodec.encode(top).contentEquals(bytes)) throw ProtocolError("RECEIPT_NONCANONICAL")

        val protectedBstr = arr.items[0] as? Cbor.BStr
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "protected header must be a bstr")
        val unprotected = arr.items[1] as? Cbor.Map
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "unprotected header must be a map")
        val payload = arr.items[2] as? Cbor.BStr
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "payload must be an attached bstr")
        val signature = arr.items[3] as? Cbor.BStr
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "signature must be a bstr")

        if (signature.value.size != Ed25519.SIGNATURE_BYTES) {
            throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "signature must be 64 bytes")
        }
        val protectedMap = CborCodec.decode(protectedBstr.value) as? Cbor.Map
            ?: throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "protected header must be a CBOR map")
        return Sign1(protectedBstr.value, protectedMap.entries, unprotected, payload.value, signature.value)
    }

    /** `kid` (label 4) of the protected header, or null when absent/mis-typed. */
    fun kidHex(sign1: Sign1): String? {
        val kid = sign1.protectedMap[4L] as? Cbor.BStr ?: return null
        if (kid.value.size != 16) return null
        return Bytes.toHex(kid.value)
    }

    fun alg(sign1: Sign1): Long? = (sign1.protectedMap[1L] as? Cbor.NInt)?.value

    fun contentType(sign1: Sign1): String? = (sign1.protectedMap[3L] as? Cbor.TStr)?.value

    /** Validate the protected header against a content type; unknown labels are fatal. */
    fun validateProtected(sign1: Sign1, expectedContentType: String) {
        if (sign1.unprotected.entries.isNotEmpty()) {
            throw ProtocolError("RECEIPT_UNKNOWN_HEADER", "unprotected header must be empty")
        }
        if (sign1.protectedMap.containsKey(2L)) {
            throw ProtocolError("RECEIPT_UNKNOWN_HEADER", "crit header must be absent")
        }
        for (label in sign1.protectedMap.keys) {
            if (label !in setOf(1L, 3L, 4L)) {
                throw ProtocolError("RECEIPT_UNKNOWN_HEADER", "unknown protected header label $label")
            }
        }
        val alg = sign1.protectedMap[1L]
        if (alg !is Cbor.NInt || alg.value != ALG_EDDSA.toLong()) {
            throw ProtocolError("RECEIPT_UNSUPPORTED_ALGORITHM", "alg must be EdDSA (-8)")
        }
        val ctype = sign1.protectedMap[3L]
        if (ctype !is Cbor.TStr || ctype.value != expectedContentType) {
            throw ProtocolError("RECEIPT_UNSUPPORTED_ALGORITHM", "unexpected content type")
        }
        val kid = sign1.protectedMap[4L]
        if (kid !is Cbor.BStr || kid.value.size != 16) {
            throw ProtocolError("RECEIPT_CONTAINER_MALFORMED", "kid must be a 16-byte bstr")
        }
    }

    /**
     * Build a canonical COSE_Sign1 container from a protected header, payload and
     * signature. Used on the merchant side to produce the exact signable bytes.
     */
    fun build(protectedBytes: ByteArray, payload: ByteArray, signature: ByteArray): ByteArray {
        val container = Cbor.Arr(
            listOf(
                Cbor.BStr(protectedBytes),
                Cbor.Map(emptyMap()),
                Cbor.BStr(payload),
                Cbor.BStr(signature),
            ),
        )
        return CborCodec.encode(container)
    }

    /**
     * Build the protected header bytes for a receipt:
     * `{1:-8, 3:"application/deceipt-receipt+cbor", 4:kid}`.
     */
    fun receiptProtectedHeader(kid: ByteArray): ByteArray {
        require(kid.size == 16) { "kid must be 16 bytes" }
        return CborCodec.encode(
            Cbor.Map(
                linkedMapOf(
                    1L to Cbor.of(-8L),
                    3L to Cbor.TStr(CONTENT_TYPE_RECEIPT),
                    4L to Cbor.BStr(kid),
                ),
            ),
        )
    }

    /** Ed25519 sign over Sig_structure; returns the 64-byte signature. */
    fun sign(seed: ByteArray, protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        Ed25519.sign(seed, sigStructure(protectedBytes, payload))

    /** Ed25519 verify over Sig_structure of the exact received bytes. */
    fun verify(publicKey: ByteArray, sign1: Sign1): Boolean =
        Ed25519.verify(publicKey, sigStructure(sign1.protectedBytes, sign1.payload), sign1.signature)

    /** SHA-256 over an arbitrary number of parts. */
    fun sha256(vararg parts: ByteArray): ByteArray = Crypto.sha256(*parts)
}
