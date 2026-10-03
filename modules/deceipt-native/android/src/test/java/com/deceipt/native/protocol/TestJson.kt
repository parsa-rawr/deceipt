package com.deceipt.native.protocol

/**
 * Minimal JSON reader for the frozen vector fixtures. Deliberately dependency-free
 * so the JVM test path is hermetic (no network, no Gradle fetch of a JSON library).
 */
object TestJson {

    fun parse(text: String): Any? {
        val p = P(text)
        p.ws()
        val v = p.value()
        p.ws()
        return v
    }

    @Suppress("UNCHECKED_CAST")
    fun obj(v: Any?): Map<String, Any?> = v as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    fun arr(v: Any?): List<Any?> = v as List<Any?>

    fun str(v: Any?): String = v as String

    fun num(v: Any?): Long = when (v) {
        is Double -> v.toLong()
        is Long -> v
        is Int -> v.toLong()
        else -> error("not a number: $v")
    }

    private class P(val s: String) {
        var i = 0

        fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(): Any? {
            ws()
            return when (val c = s[i]) {
                '{' -> obj()
                '[' -> array()
                '"' -> string()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> if (c == '-' || c.isDigit()) number() else error("unexpected '$c' at $i")
            }
        }

        fun expect(word: String) {
            if (!s.startsWith(word, i)) error("expected $word at $i")
            i += word.length
        }

        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++ // {
            ws()
            if (s[i] == '}') { i++; return m }
            while (true) {
                ws()
                val k = string()
                ws()
                if (s[i] != ':') error("expected ':' at $i")
                i++
                m[k] = value()
                ws()
                when (s[i]) {
                    ',' -> { i++; continue }
                    '}' -> { i++; return m }
                    else -> error("expected ',' or '}' at $i")
                }
            }
        }

        fun array(): List<Any?> {
            val out = ArrayList<Any?>()
            i++ // [
            ws()
            if (s[i] == ']') { i++; return out }
            while (true) {
                out.add(value())
                ws()
                when (s[i]) {
                    ',' -> { i++; continue }
                    ']' -> { i++; return out }
                    else -> error("expected ',' or ']' at $i")
                }
            }
        }

        fun string(): String {
            if (s[i] != '"') error("expected string at $i")
            i++
            val sb = StringBuilder()
            while (true) {
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> when (val e = s[i++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i, i + 4)
                            i += 4
                            sb.append(hex.toInt(16).toChar())
                        }
                        else -> error("bad escape \\$e")
                    }
                    else -> sb.append(c)
                }
            }
        }

        fun number(): Double {
            val start = i
            if (s[i] == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) i++
            return s.substring(start, i).toDouble()
        }
    }
}
