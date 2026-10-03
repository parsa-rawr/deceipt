package com.deceipt.adapter.protocol

/**
 * Byte/hex/base64 helpers. Binary crosses the bridge as standard base64 with padding.
 *
 * Base64 is implemented here rather than via `java.util.Base64`, which does not
 * exist below API 26; the PoC floor is minSdk 24.
 */
object Bytes {

    private val HEX = "0123456789abcdef".toCharArray()
    private val B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray()
    private val B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray()
    private val B64_REV_STD = IntArray(128) { -1 }.also { for (i in B64_STD.indices) it[B64_STD[i].code] = i }
    private val B64_REV_URL = IntArray(128) { -1 }.also { for (i in B64_URL.indices) it[B64_URL[i].code] = i }

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

    /** RFC 4648 4 standard base64, padding included. */
    fun toBase64(b: ByteArray): String = encode(b, B64_STD, pad = true)

    /** Strict decode: rejects malformed base64 rather than silently truncating. */
    fun fromBase64(s: String): ByteArray {
        val out = decode(s, B64_REV_STD, allowUrlAlphabet = false, requirePad = false)
            ?: throw ProtocolError("CBOR_MALFORMED", "malformed base64 input")
        return out
    }

    /** `base64url_nopad` (A2 QR payload): RFC 4648 5, `-`/`_`, no padding. */
    fun toBase64UrlNoPad(b: ByteArray): String = encode(b, B64_URL, pad = false)

    fun fromBase64UrlNoPad(s: String): ByteArray =
        decode(s, B64_REV_URL, allowUrlAlphabet = true, requirePad = false)
            ?: throw ProtocolError("CBOR_MALFORMED", "malformed base64url input")

    private fun encode(bytes: ByteArray, alphabet: CharArray, pad: Boolean): String {
        val sb = StringBuilder(((bytes.size + 2) / 3) * 4)
        var i = 0
        while (i + 2 < bytes.size) {
            val n = ((bytes[i].toInt() and 0xff) shl 16) or
                ((bytes[i + 1].toInt() and 0xff) shl 8) or (bytes[i + 2].toInt() and 0xff)
            sb.append(alphabet[(n ushr 18) and 0x3f])
            sb.append(alphabet[(n ushr 12) and 0x3f])
            sb.append(alphabet[(n ushr 6) and 0x3f])
            sb.append(alphabet[n and 0x3f])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = (bytes[i].toInt() and 0xff) shl 16
                sb.append(alphabet[(n ushr 18) and 0x3f])
                sb.append(alphabet[(n ushr 12) and 0x3f])
                if (pad) sb.append("==")
            }
            2 -> {
                val n = ((bytes[i].toInt() and 0xff) shl 16) or ((bytes[i + 1].toInt() and 0xff) shl 8)
                sb.append(alphabet[(n ushr 18) and 0x3f])
                sb.append(alphabet[(n ushr 12) and 0x3f])
                sb.append(alphabet[(n ushr 6) and 0x3f])
                if (pad) sb.append('=')
            }
        }
        return sb.toString()
    }

    /**
     * Strict decoder. Returns null on any malformed input (bad character, bad
     * length, bad padding). `requirePad=false` accepts both padded and unpadded.
     */
    private fun decode(s: String, rev: IntArray, allowUrlAlphabet: Boolean, requirePad: Boolean): ByteArray? {
        val cleaned = s.trim()
        var end = cleaned.length
        while (end > 0 && cleaned[end - 1] == '=') end--
        val padding = cleaned.length - end
        if (padding > 2) return null
        if (requirePad && padding != 0) return null
        if (end == 0) return ByteArray(0)
        // A single leftover character cannot encode a byte.
        if (end % 4 == 1) return null

        val out = ByteArray((end * 3) / 4)
        var o = 0
        var i = 0
        while (i + 4 <= end) {
            val a = ch(cleaned[i], rev); val b = ch(cleaned[i + 1], rev)
            val c = ch(cleaned[i + 2], rev); val d = ch(cleaned[i + 3], rev)
            if (a < 0 || b < 0 || c < 0 || d < 0) return null
            val n = (a shl 18) or (b shl 12) or (c shl 6) or d
            out[o++] = ((n ushr 16) and 0xff).toByte()
            out[o++] = ((n ushr 8) and 0xff).toByte()
            out[o++] = (n and 0xff).toByte()
            i += 4
        }
        when (end - i) {
            0 -> {}
            2 -> {
                val a = ch(cleaned[i], rev); val b = ch(cleaned[i + 1], rev)
                if (a < 0 || b < 0) return null
                // The discarded 4 bits MUST be zero (canonical), else reject.
                if ((b and 0x0f) != 0) return null
                out[o++] = (((a shl 2) or (b ushr 4)) and 0xff).toByte()
            }
            3 -> {
                val a = ch(cleaned[i], rev); val b = ch(cleaned[i + 1], rev); val c = ch(cleaned[i + 2], rev)
                if (a < 0 || b < 0 || c < 0) return null
                if ((c and 0x03) != 0) return null
                out[o++] = (((a shl 2) or (b ushr 4)) and 0xff).toByte()
                out[o++] = (((b shl 4) or (c ushr 2)) and 0xff).toByte()
            }
            else -> return null
        }
        return if (o == out.size) out else out.copyOf(o)
    }

    private fun ch(c: Char, rev: IntArray): Int {
        val code = c.code
        if (code >= rev.size) return -1
        return rev[code]
    }

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
