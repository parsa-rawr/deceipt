package com.deceipt.adapter.protocol

/**
 * A2 transaction-binding QR payload
 * (docs/flows/transaction-binding-and-checkout-v1.md 3.3, deceipt-proto-r3).
 *
 * `qr_payload = "deceipt1:" || base64url_nopad(CBOR map(5))`
 * `{1: qr_format_version=1, 2: session_id(16), 3: session_binding_token(16),
 *   4: offer_hash(32), 5: expires_at_unix}`
 *
 * The QR is a selection/bootstrap channel only: it carries no merchant name,
 * amount, receipt id or credential. The SBT is a secret and never crosses the
 * JS bridge as a field.
 */
object Qr {

    const val PREFIX = "deceipt1:"

    data class Payload(
        val sessionId: ByteArray,
        val sessionBindingToken: ByteArray,
        val offerHash: ByteArray,
        val expiresAtUnix: Long,
    )

    fun parse(payload: String): Payload {
        if (!payload.startsWith(PREFIX)) throw ProtocolError("BINDING_PROOF_INVALID", "missing deceipt1: prefix")
        val b64 = payload.substring(PREFIX.length)
        val bytes = try {
            Bytes.fromBase64UrlNoPad(b64)
        } catch (e: Exception) {
            throw ProtocolError("BINDING_PROOF_INVALID", "malformed base64url")
        }
        val map = CborCodec.decode(bytes) as? Cbor.Map ?: throw ProtocolError("BINDING_PROOF_INVALID", "QR must be a map")
        val m = map.entries
        for (k in m.keys) if (k !in 1L..5L) throw ProtocolError("BINDING_PROOF_INVALID", "unknown QR field $k")
        val version = (m[1L] as? Cbor.UInt)?.value ?: throw ProtocolError("BINDING_PROOF_INVALID", "qr_format_version")
        if (version != 1L) throw ProtocolError("BINDING_PROOF_INVALID", "unsupported qr_format_version")
        fun b(l: Long, n: Int): ByteArray {
            val v = (m[l] as? Cbor.BStr)?.value ?: throw ProtocolError("BINDING_PROOF_INVALID", "QR field $l")
            if (v.size != n) throw ProtocolError("BINDING_PROOF_INVALID", "QR field $l length")
            return v
        }
        val expires = (m[5L] as? Cbor.UInt)?.value ?: throw ProtocolError("BINDING_PROOF_INVALID", "expires_at_unix")
        return Payload(b(2L, 16), b(3L, 16), b(4L, 32), expires)
    }

    fun mint(sessionId: ByteArray, sbt: ByteArray, offerHash: ByteArray, expiresAtUnix: Long): String {
        require(sessionId.size == 16 && sbt.size == 16 && offerHash.size == 32)
        val bytes = CborCodec.encode(
            Cbor.Map(
                linkedMapOf(
                    1L to Cbor.of(1L),
                    2L to Cbor.BStr(sessionId),
                    3L to Cbor.BStr(sbt),
                    4L to Cbor.BStr(offerHash),
                    5L to Cbor.of(expiresAtUnix),
                ),
            ),
        )
        return PREFIX + Bytes.toBase64UrlNoPad(bytes)
    }

    /** Freshness check: a QR at or past its expiry is `BINDING_STALE`. */
    fun checkFresh(p: Payload, nowUnix: Long) {
        if (nowUnix >= p.expiresAtUnix) throw ProtocolError("BINDING_STALE", "expired at ${p.expiresAtUnix}")
    }
}

/**
 * Merchant-side session-binding store. The SBT never crosses the JS bridge and
 * is destroyed on consumption or expiry (A2 3.4/3.8).
 */
class BindingStore {

    private class Entry(
        val sbt: ByteArray,
        val offerHash: ByteArray,
        val expiresAtUnix: Long,
        var consumed: Boolean = false,
    )

    private val entries = LinkedHashMap<String, Entry>()

    fun put(sessionId: ByteArray, sbt: ByteArray, offerHash: ByteArray, expiresAtUnix: Long) {
        entries[Bytes.toHex(sessionId)] = Entry(sbt.copyOf(), offerHash.copyOf(), expiresAtUnix)
    }

    /** Resolve an unconsumed, unexpired session; throws the frozen binding errors. */
    fun claim(sessionId: ByteArray, nowUnix: Long): ByteArray {
        val e = entries[Bytes.toHex(sessionId)]
            ?: throw ProtocolError("BINDING_UNKNOWN_SESSION")
        if (e.consumed) throw ProtocolError("BINDING_CONSUMED")
        if (nowUnix >= e.expiresAtUnix) throw ProtocolError("BINDING_STALE", "expired at ${e.expiresAtUnix}")
        return e.sbt
    }

    fun markConsumed(sessionId: ByteArray) {
        entries[Bytes.toHex(sessionId)]?.consumed = true
    }

    fun isConsumed(sessionId: ByteArray): Boolean = entries[Bytes.toHex(sessionId)]?.consumed == true

    fun offerHash(sessionId: ByteArray): ByteArray? = entries[Bytes.toHex(sessionId)]?.offerHash

    /** Zeroize and drop expired/consumed entries (best-effort in a managed runtime). */
    fun prune(nowUnix: Long) {
        val it = entries.entries.iterator()
        while (it.hasNext()) {
            val e = it.next().value
            if (e.consumed || nowUnix >= e.expiresAtUnix) {
                Bytes.zeroize(e.sbt)
                it.remove()
            }
        }
    }

    fun clear() {
        for (e in entries.values) Bytes.zeroize(e.sbt)
        entries.clear()
    }
}

/** Session-identifier history for replay answers (handshake.md 6.4). */
class SessionIdHistory(private val maxSize: Int = Bounds.MAX_SESSION_ID_HISTORY) {
    private val seen = ArrayDeque<String>()

    fun remember(sessionId: ByteArray): Boolean {
        val hex = Bytes.toHex(sessionId)
        if (seen.contains(hex)) return false
        seen.addLast(hex)
        while (seen.size > maxSize) seen.removeFirst()
        return true
    }

    fun contains(sessionId: ByteArray): Boolean = seen.contains(Bytes.toHex(sessionId))
}
