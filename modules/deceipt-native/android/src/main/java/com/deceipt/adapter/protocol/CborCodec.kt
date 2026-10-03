package com.deceipt.native.protocol

import java.io.ByteArrayOutputStream

/**
 * CBOR value model. Only the subset the Deceipt profile admits is representable;
 * every value is deterministic-encodable (RFC 8949 4.2.1 core deterministic
 * encoding), which is a hard requirement for signed bytes (receipt-v1.md 1).
 *
 * Floats, tags, indefinite lengths, `null`, `undefined` and other simple values
 * are NOT representable — the profile forbids them, and the parser never
 * constructs them (receipt-v1.md 1, CBOR_UNSUPPORTED_TYPE).
 */
sealed class Cbor {

    data class UInt(val value: Long) : Cbor() {
        init { require(value >= 0) { "UInt must be non-negative" } }
    }

    /** A negative integer (major type 1). `value` is the mathematical value (< 0). */
    data class NInt(val value: Long) : Cbor() {
        init { require(value < 0) { "NInt must be negative" } }
    }

    data class BStr(val value: ByteArray) : Cbor() {
        override fun equals(other: Any?): Boolean = other is BStr && value.contentEquals(other.value)
        override fun hashCode(): Int = value.contentHashCode()
    }

    data class TStr(val value: String) : Cbor()

    data class Arr(val items: List<Cbor>) : Cbor()

    data class Map(val entries: Map<Long, Cbor>) : Cbor()

    data class Bool(val value: Boolean) : Cbor()

    companion object {
        fun of(v: Long): Cbor = if (v >= 0) UInt(v) else NInt(v)
        fun of(v: Int): Cbor = of(v.toLong())
        fun of(v: Boolean): Cbor = Bool(v)
        fun of(v: String): Cbor = TStr(v)
        fun of(v: ByteArray): Cbor = BStr(v)
        fun bytes(vararg v: Int): BStr = BStr(ByteArray(v.size) { v[it].toByte() })
    }
}

/**
 * Deterministic CBOR codec for the Deceipt v1 profile.
 *
 * Encoder emits RFC 8949 4.2.1 core deterministic encoding: minimal-length
 * arguments, definite lengths, ascending encoded-key map order, no floats/tags.
 *
 * Decoder enforces the SAME profile and additionally rejects: trailing bytes,
 * duplicate keys, non-minimal arguments, indefinite lengths, floats, tags,
 * simple values other than false/true, and depth/item/size bound violations.
 * It never allocates from a peer-declared length before checking that length
 * against the frozen caps (Bounds) — parser bounds are security requirements.
 */
object CborCodec {

    private const val MT_UINT = 0
    private const val MT_NINT = 1
    private const val MT_BSTR = 2
    private const val MT_TSTR = 3
    private const val MT_ARR = 4
    private const val MT_MAP = 5
    private const val MT_SIMPLE = 7

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    fun encode(v: Cbor): ByteArray {
        val out = ByteArrayOutputStream(64)
        write(out, v)
        return out.toByteArray()
    }

    fun encodeBytes(vararg v: Cbor): ByteArray {
        val out = ByteArrayOutputStream(64)
        for (x in v) write(out, x)
        return out.toByteArray()
    }

    private fun write(out: ByteArrayOutputStream, v: Cbor) {
        when (v) {
            is Cbor.UInt -> head(out, MT_UINT, v.value)
            is Cbor.NInt -> head(out, MT_NINT, -(v.value + 1))
            is Cbor.BStr -> {
                head(out, MT_BSTR, v.value.size.toLong())
                out.write(v.value)
            }
            is Cbor.TStr -> {
                val b = v.value.toByteArray(Charsets.UTF_8)
                head(out, MT_TSTR, b.size.toLong())
                out.write(b)
            }
            is Cbor.Arr -> {
                head(out, MT_ARR, v.items.size.toLong())
                for (i in v.items) write(out, i)
            }
            is Cbor.Map -> {
                // Ascending by encoded key bytes == ascending numeric order for
                // integer keys 0..255 (receipt-v1.md 1).
                val keys = v.entries.keys.sorted()
                head(out, MT_MAP, keys.size.toLong())
                for (k in keys) {
                    write(out, Cbor.UInt(k))
                    write(out, v.entries.getValue(k))
                }
            }
            is Cbor.Bool -> out.write(if (v.value) 0xf5 else 0xf4)
        }
    }

    private fun head(out: ByteArrayOutputStream, major: Int, arg: Long) {
        val mt = major shl 5
        when {
            arg < 24 -> out.write(mt or arg.toInt())
            arg <= 0xff -> {
                out.write(mt or 24); out.write(arg.toInt() and 0xff)
            }
            arg <= 0xffff -> {
                out.write(mt or 25)
                out.write(((arg ushr 8) and 0xff).toInt())
                out.write((arg and 0xff).toInt())
            }
            arg <= 0xffffffffL -> {
                out.write(mt or 26)
                for (i in 3 downTo 0) out.write(((arg ushr (8 * i)) and 0xff).toInt())
            }
            else -> {
                out.write(mt or 27)
                for (i in 7 downTo 0) out.write(((arg ushr (8 * i)) and 0xff).toInt())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decoding
    // -----------------------------------------------------------------------

    /** Decode exactly one item; trailing bytes are `CBOR_MALFORMED`. */
    fun decode(b: ByteArray): Cbor {
        val r = Reader(b)
        val v = r.readValue(0)
        if (r.pos != b.size) throw ProtocolError("CBOR_MALFORMED", "trailing bytes after top-level item")
        return v
    }

    private class Reader(private val b: ByteArray) {
        var pos = 0
        private var items = 0

        fun readValue(depth: Int): Cbor {
            if (depth > Bounds.CBOR_MAX_DEPTH) throw ProtocolError("CBOR_DEPTH_EXCEEDED")
            items += 1
            if (items > Bounds.CBOR_MAX_ITEMS) throw ProtocolError("CBOR_SIZE_EXCEEDED", "item count")
            val ib = u8()
            val major = ib ushr 5
            val addl = ib and 0x1f
            if (major == 7) return readSimple(addl)
            val arg = readArg(addl, major)
            return when (major) {
                MT_UINT -> Cbor.UInt(arg)
                MT_NINT -> {
                    if (arg < 0) throw ProtocolError("CBOR_MALFORMED", "negative major-1 argument overflow")
                    Cbor.NInt(-(arg + 1))
                }
                MT_BSTR -> Cbor.BStr(takeBounded(arg))
                MT_TSTR -> Cbor.TStr(decodeUtf8(takeBounded(arg)))
                MT_ARR -> {
                    if (arg > Bounds.CBOR_MAX_ARRAY) throw ProtocolError("CBOR_SIZE_EXCEEDED", "array length")
                    val n = arg.toInt()
                    val out = ArrayList<Cbor>(minOf(n, 64))
                    for (i in 0 until n) out.add(readValue(depth + 1))
                    Cbor.Arr(out)
                }
                MT_MAP -> {
                    if (arg > Bounds.CBOR_MAX_MAP) throw ProtocolError("CBOR_SIZE_EXCEEDED", "map length")
                    val n = arg.toInt()
                    val out = LinkedHashMap<Long, Cbor>(minOf(n, 32))
                    var prev = -1L
                    for (i in 0 until n) {
                        val k = readValue(depth + 1)
                        val key = (k as? Cbor.UInt)?.value
                            ?: throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "map key must be a non-negative integer")
                        if (out.containsKey(key)) throw ProtocolError("CBOR_DUPLICATE_KEY")
                        if (key <= prev) throw ProtocolError("CBOR_NONCANONICAL", "map keys not ascending")
                        prev = key
                        out[key] = readValue(depth + 1)
                    }
                    Cbor.Map(out)
                }
                else -> throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "unsupported major type $major")
            }
        }

        private fun readSimple(addl: Int): Cbor = when (addl) {
            20 -> Cbor.Bool(false)
            21 -> Cbor.Bool(true)
            22, 23 -> throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "null/undefined forbidden")
            24, 25, 26, 27 -> throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "floats/simple values forbidden")
            31 -> throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "indefinite length forbidden")
            else -> throw ProtocolError("CBOR_UNSUPPORTED_TYPE", "simple value $addl forbidden")
        }

        private fun readArg(addl: Int, major: Int): Long = when {
            addl < 24 -> addl.toLong()
            addl == 24 -> {
                val v = u8().toLong()
                if (v < 24) throw ProtocolError("CBOR_NONCANONICAL", "non-minimal argument")
                v
            }
            addl == 25 -> {
                val v = (u8().toLong() shl 8) or u8().toLong()
                if (v <= 0xff) throw ProtocolError("CBOR_NONCANONICAL", "non-minimal argument")
                v
            }
            addl == 26 -> {
                var v = 0L
                for (i in 0 until 4) v = (v shl 8) or u8().toLong()
                if (v <= 0xffffL) throw ProtocolError("CBOR_NONCANONICAL", "non-minimal argument")
                v
            }
            addl == 27 -> {
                var v = 0L
                for (i in 0 until 8) v = (v shl 8) or u8().toLong()
                if (v >= 0 && v <= 0xffffffffL) throw ProtocolError("CBOR_NONCANONICAL", "non-minimal argument")
                v
            }
            else -> throw ProtocolError(
                if (major == MT_BSTR || major == MT_TSTR || major == MT_ARR || major == MT_MAP)
                    "CBOR_UNSUPPORTED_TYPE" else "CBOR_MALFORMED",
                "indefinite/reserved additional information $addl",
            )
        }

        /** Read `n` bytes, but never allocate from an unchecked peer length. */
        private fun takeBounded(n: Long): ByteArray {
            if (n < 0) throw ProtocolError("CBOR_MALFORMED", "negative length")
            if (n > Bounds.CBOR_MAX_BYTES) throw ProtocolError("CBOR_SIZE_EXCEEDED", "byte string length")
            if (n > remaining()) throw ProtocolError("CBOR_MALFORMED", "truncated input")
            val out = ByteArray(n.toInt())
            System.arraycopy(b, pos, out, 0, out.size)
            pos += out.size
            return out
        }

        private fun decodeUtf8(bytes: ByteArray): String {
            if (bytes.size > Bounds.CBOR_MAX_TEXT_BYTES) throw ProtocolError("CBOR_SIZE_EXCEEDED", "text length")
            return try {
                val s = String(bytes, Charsets.UTF_8)
                // Reject invalid UTF-8: round-trip must be byte-identical.
                if (!s.toByteArray(Charsets.UTF_8).contentEquals(bytes)) throw ProtocolError("CBOR_MALFORMED", "invalid UTF-8")
                s
            } catch (e: ProtocolError) {
                throw e
            } catch (e: Exception) {
                throw ProtocolError("CBOR_MALFORMED", "invalid UTF-8")
            }
        }

        private fun u8(): Int {
            if (pos >= b.size) throw ProtocolError("CBOR_MALFORMED", "truncated input")
            return b[pos++].toInt() and 0xff
        }

        private fun remaining(): Int = b.size - pos
    }
}
