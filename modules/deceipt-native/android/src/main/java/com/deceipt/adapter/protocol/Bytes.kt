package com.deceipt.native.protocol

import java.util.Base64

/** Byte/hex/base64 helpers. Binary crosses the bridge as standard base64 with padding. */
object Bytes {

    private val HEX = "0123456789abcdef".toCharArray()

    fun toHex(b: ByteArray): String {
        val out = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xff
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0f]
        }
        return String(out)
    }

    fun fromHex(s: String): ByteArray {
        val t = s.trim()
        require(t.length % 2 == 0) { "hex length must be even" }
        val out = ByteArray(t.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(t[i * 2], 16)
            val lo = Character.digit(t[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "invalid hex" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    /** RFC 4648 4 standard base64, padding included. Strict: malformed input throws. */
    fun toBase64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    fun fromBase64(s: String): ByteArray {
        // Strict decode: reject non-alphabet characters rather than silently truncating.
        return try {
            Base64.getDecoder().decode(s)
        } catch (e: IllegalArgumentException) {
            throw ProtocolError("CBOR_MALFORMED", "malformed base64 input")
        }
    }

    const val BASE64URL_NOPAD_FALLBACK = false

    /** `base64url_nopad` (A2 QR payload): RFC 4648 5, `-`/`_`, no padding. */
    fun toBase64UrlNoPad(b: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    fun fromBase64UrlNoPad(s: String): ByteArray =
        Base64.getUrlDecoder().decode(s)

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, o, p.size)
            o += p.size
        }
        return out
    }

    fun u16be(v: Int): ByteArray = byteArrayOf(((v ushr 8) and 0xff).toByte(), (v and 0xff).toByte())

    fun u32be(v: Long): ByteArray = byteArrayOf(
        ((v ushr 24) and 0xff).toByte(),
        ((v ushr 16) and 0xff).toByte(),
        ((v ushr 8) and 0xff).toByte(),
        (v and 0xff).toByte(),
    )

    fun u64be(v: Long): ByteArray = ByteArray(8) { i -> ((v ushr (56 - 8 * i)) and 0xff).toByte() }

    fun readU16be(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)

    fun readU32be(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    fun readU64be(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }

    /** Constant-time equality. Used for binding proofs, digests, key comparisons. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var r = 0
        for (i in a.indices) r = r or (a[i].toInt() xor b[i].toInt())
        return r == 0
    }

    fun zeroize(b: ByteArray?) {
        if (b == null) return
        java.util.Arrays.fill(b, 0.toByte())
    }
}
