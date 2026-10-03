package com.deceipt.native.protocol

import com.deceipt.native.crypto.Crypto
import com.deceipt.native.crypto.Ed25519

/**
 * Credential verification (docs/protocol/trust.md 4) and receipt container
 * verification (docs/protocol/receipt-v1.md 2, verification.md 8–14).
 *
 * Trust model, stated plainly: a valid signature proves integrity and
 * possession of a key, NOT merchant identity. Identity requires a credential
 * chaining to a pinned anchor. This object never collapses the sub-states into
 * one boolean.
 */
object Credential {

    data class Anchor(val anchorId: ByteArray, val publicKey: ByteArray, val label: String?)

    /** An `unknown_issuer` credential is NON-FATAL; the key is never authorized. */
    data class Verification(
        val trust: String, // "authenticated" | "unknown_issuer"
        val signatureValid: Boolean,
        val temporallyAcceptable: Boolean,
        val merchantId: ByteArray?,
        val deviceKeyId: ByteArray?,
        val devicePublicKey: ByteArray?,
        val issuerId: ByteArray?,
        val capabilities: Long?,
        val merchantReference: String?,
        val displayName: String?,
        val validFrom: Long?,
        val validUntil: Long?,
        val errorName: String?,
    )

    data class Fields(
        val issuerId: ByteArray,
        val merchantId: ByteArray,
        val deviceKeyId: ByteArray,
        val devicePublicKey: ByteArray,
        val validFrom: Long,
        val validUntil: Long,
        val capabilities: Long,
        val merchantReference: String,
        val displayName: String,
        val issuedAt: Long,
    )

    fun parseFields(credentialBytes: ByteArray): Fields {
        if (credentialBytes.size > Bounds.MAX_CREDENTIAL_BYTES) throw ProtocolError("CREDENTIAL_MALFORMED")
        val sign1 = Cose.parse(credentialBytes, Bounds.MAX_CREDENTIAL_BYTES)
        Cose.validateProtected(sign1, Cose.CONTENT_TYPE_CREDENTIAL)
        val payload = CborCodec.decode(sign1.payload) as? Cbor.Map ?: throw ProtocolError("CREDENTIAL_MALFORMED")
        val m = payload.entries
        for (k in m.keys) if (k !in 1L..11L) throw ProtocolError("CREDENTIAL_MALFORMED", "unknown field $k")
        fun u(l: Long): Long = (m[l] as? Cbor.UInt)?.value ?: throw ProtocolError("CREDENTIAL_MALFORMED", "field $l")
        fun b(l: Long, n: Int): ByteArray {
            val v = (m[l] as? Cbor.BStr)?.value ?: throw ProtocolError("CREDENTIAL_MALFORMED", "field $l")
            if (v.size != n) throw ProtocolError("CREDENTIAL_MALFORMED", "field $l length")
            return v
        }
        fun t(l: Long): String = (m[l] as? Cbor.TStr)?.value ?: throw ProtocolError("CREDENTIAL_MALFORMED", "field $l")
        if (u(1L) != 1L) throw ProtocolError("CREDENTIAL_MALFORMED", "credential_version")
        val issuerId = b(2L, 16)
        val merchantId = b(3L, 16)
        val deviceKeyId = b(4L, 16)
        val devicePublicKey = b(5L, 32)
        val validFrom = u(6L)
        val validUntil = u(7L)
        if (validUntil <= validFrom) throw ProtocolError("CREDENTIAL_MALFORMED", "validity window")
        val capabilities = u(8L)
        val merchantReference = t(9L)
        val displayName = t(10L)
        val issuedAt = u(11L)
        // protected.kid MUST equal payload.issuer_id
        val kid = sign1.protectedMap[4L] as? Cbor.BStr ?: throw ProtocolError("CREDENTIAL_MALFORMED")
        if (!Bytes.constantTimeEquals(kid.value, issuerId)) throw ProtocolError("CREDENTIAL_MALFORMED", "kid != issuer_id")
        return Fields(issuerId, merchantId, deviceKeyId, devicePublicKey, validFrom, validUntil, capabilities, merchantReference, displayName, issuedAt)
    }

    /**
     * trust.md 4 step order. `CREDENTIAL_UNKNOWN_ISSUER` is non-fatal here: it
     * yields `trust = unknown_issuer` so the app can display it, and the caller
     * must then verify the transcript signature against the credential's
     * SELF-ASSERTED device key (internal consistency only).
     */
    fun verify(credentialBytes: ByteArray, anchors: List<Anchor>, nowUnix: Long): Verification {
        val f = try {
            parseFields(credentialBytes)
        } catch (e: ProtocolError) {
            return Verification("unknown_issuer", false, false, null, null, null, null, null, null, null, null, null, e.errorName)
        }
        val anchor = anchors.firstOrNull { Bytes.constantTimeEquals(it.anchorId, f.issuerId) }
        val skew = Bounds.CLOCK_SKEW_MAX_S.toLong()
        val temporallyAcceptable = nowUnix >= f.validFrom - skew && nowUnix < f.validUntil + skew

        if (anchor == null) {
            // Unknown issuer (trust.md 4 step 7): the credential is well-formed but
            // no anchor authorizes it. Signature is NOT verifiable against a pinned
            // anchor, so `signatureValid` is false and trust is not established.
            return Verification(
                trust = "unknown_issuer", signatureValid = false, temporallyAcceptable = temporallyAcceptable,
                merchantId = f.merchantId, deviceKeyId = f.deviceKeyId, devicePublicKey = f.devicePublicKey,
                issuerId = f.issuerId, capabilities = f.capabilities, merchantReference = f.merchantReference,
                displayName = f.displayName, validFrom = f.validFrom, validUntil = f.validUntil,
                errorName = "CREDENTIAL_UNKNOWN_ISSUER",
            )
        }

        val sign1 = Cose.parse(credentialBytes, Bounds.MAX_CREDENTIAL_BYTES)
        val sigOk = Ed25519.verify(anchor.publicKey, Cose.sigStructure(sign1.protectedBytes, sign1.payload), sign1.signature)
        if (!sigOk) {
            return Verification("authenticated", false, temporallyAcceptable, f.merchantId, f.deviceKeyId, f.devicePublicKey,
                f.issuerId, f.capabilities, f.merchantReference, f.displayName, f.validFrom, f.validUntil, "CREDENTIAL_SIGNATURE_INVALID")
        }
        if (nowUnix < f.validFrom - skew) {
            return Verification("authenticated", true, false, f.merchantId, f.deviceKeyId, f.devicePublicKey,
                f.issuerId, f.capabilities, f.merchantReference, f.displayName, f.validFrom, f.validUntil, "CREDENTIAL_NOT_YET_VALID")
        }
        if (nowUnix >= f.validUntil + skew) {
            return Verification("authenticated", true, false, f.merchantId, f.deviceKeyId, f.devicePublicKey,
                f.issuerId, f.capabilities, f.merchantReference, f.displayName, f.validFrom, f.validUntil, "CREDENTIAL_EXPIRED")
        }
        return Verification("authenticated", true, true, f.merchantId, f.deviceKeyId, f.devicePublicKey,
            f.issuerId, f.capabilities, f.merchantReference, f.displayName, f.validFrom, f.validUntil, null)
    }
}

/**
 * Receipt container verification. Steps 8–10 only: structural validation plus
 * Ed25519 over the EXACT received bytes. Steps 11–14 (authorization, schema,
 * dedup, policy) live in the shared app for the receipt body; native exposes the
 * exact bytes and the signature sub-state.
 */
object ReceiptVerify {

    data class Result(val signatureValid: Boolean, val deviceKeyIdHex: String?, val errorName: String?)

    fun parseAndVerify(coseSign1Bytes: ByteArray, devicePublicKey: ByteArray): Result {
        val sign1 = try {
            Cose.parse(coseSign1Bytes, Bounds.MAX_RECEIPT_BYTES)
        } catch (e: ProtocolError) {
            return Result(false, null, e.errorName)
        }
        try {
            Cose.validateProtected(sign1, Cose.CONTENT_TYPE_RECEIPT)
        } catch (e: ProtocolError) {
            return Result(false, Cose.kidHex(sign1), e.errorName)
        }
        val kidHex = Cose.kidHex(sign1)
        // The receipt body's own schema/semantic checks are A3's; native returns
        // the signature sub-state over the exact received bytes.
        val ok = Ed25519.verify(devicePublicKey, Cose.sigStructure(sign1.protectedBytes, sign1.payload), sign1.signature)
        return Result(ok, kidHex, if (ok) null else "RECEIPT_SIGNATURE_INVALID")
    }

    /** SHA-256 of the AEAD ciphertext, a transport-integrity checkpoint only. */
    fun payloadHash(ciphertext: ByteArray): ByteArray = Crypto.sha256(ciphertext)
}
