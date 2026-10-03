package com.deceipt.adapter.crypto

import com.deceipt.adapter.protocol.Bytes
import com.deceipt.adapter.protocol.ProtocolError
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigInteger
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Ed25519 (EdDSA). Backed by BouncyCastle so behaviour is identical from API 24
 * through current (java.security `Ed25519` only exists from API 33, and its
 * availability there is itself reported inconsistent). The keys are software
 * keys on Android; see `modules/deceipt-native/android/ANDROID-KEY-STORAGE.md` — the PoC does
 * NOT claim hardware-backed non-exportability.
 */
object Ed25519 {
    const val SEED_BYTES = 32
    const val PUBLIC_KEY_BYTES = 32
    const val SIGNATURE_BYTES = 64

    /** Derive the public key for a 32-byte seed (RFC 8032 key derivation). */
    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == SEED_BYTES) { "Ed25519 seed must be 32 bytes" }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == SEED_BYTES) { "Ed25519 seed must be 32 bytes" }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /** Verify over the EXACT bytes. Returns false on any malformed input, never throws. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PUBLIC_KEY_BYTES || signature.size != SIGNATURE_BYTES) return false
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    fun generateSeed(random: SecureRandom = SecureRandom()): ByteArray =
        ByteArray(SEED_BYTES).also { random.nextBytes(it) }
}

/**
 * P-256 (secp256r1) point validation and ECDH.
 *
 * Point decoding is done against the curve equation explicitly so a substituted
 * or compressed point is rejected with HANDSHAKE_ECDH_INVALID_POINT *before* any
 * ECDH or binding work (binding-contract 3.7).
 */
object P256 {
    const val UNCOMPRESSED_BYTES = 65
    const val SCALAR_BYTES = 32
    const val COORD_BYTES = 32

    private val P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val A = P.subtract(BigInteger.valueOf(3))
    private val B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    private val N = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    /** The named curve, from BouncyCastle (the same provider used for Ed25519). */
    private val domain = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256r1")

    /** True iff `pub` is a valid uncompressed P-256 point. */
    fun isValidPoint(pub: ByteArray): Boolean {
        if (pub.size != UNCOMPRESSED_BYTES || pub[0] != 0x04.toByte()) return false
        val x = BigInteger(1, pub.copyOfRange(1, 33))
        val y = BigInteger(1, pub.copyOfRange(33, 65))
        if (x >= P || y >= P) return false
        // y^2 == x^3 - 3x + b (mod p)
        val lhs = y.multiply(y).mod(P)
        val rhs = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P)
        return lhs == rhs
    }

    /** Validate an uncompressed point, throwing the frozen error when invalid. */
    fun decodePoint(pub: ByteArray) {
        if (!isValidPoint(pub)) throw ProtocolError("HANDSHAKE_ECDH_INVALID_POINT")
    }

    /** Decode a 32-byte big-endian scalar (1..n-1), throwing on out-of-range. */
    fun decodeScalar(scalar: ByteArray): BigInteger {
        require(scalar.size == SCALAR_BYTES) { "P-256 scalar must be 32 bytes" }
        val v = BigInteger(1, scalar)
        if (v.signum() <= 0 || v >= N) throw ProtocolError("HANDSHAKE_ECDH_INVALID_POINT", "scalar out of range")
        return v
    }

    /** A fresh uniform scalar in [1, n-1]. */
    fun generateScalar(random: SecureRandom = SecureRandom()): ByteArray {
        while (true) {
            val candidate = ByteArray(SCALAR_BYTES).also { random.nextBytes(it) }
            val v = BigInteger(1, candidate)
            if (v.signum() > 0 && v < N) return candidate
        }
    }

    /** The uncompressed public point for a raw scalar (`s * G`). */
    fun publicKeyFromScalar(scalar: ByteArray): ByteArray {
        val d = decodeScalar(scalar)
        val p = domain.g.multiply(d).normalize()
        return Bytes.concat(
            byteArrayOf(0x04),
            toFixed(p.affineXCoord.toBigInteger(), COORD_BYTES),
            toFixed(p.affineYCoord.toBigInteger(), COORD_BYTES),
        )
    }

    /** ECDH: 32-byte X coordinate of `scalar * peerPoint`. */
    fun sharedSecret(scalar: ByteArray, peerPoint: ByteArray): ByteArray {
        val d = decodeScalar(scalar)
        decodePoint(peerPoint)
        val q = domain.curve.decodePoint(peerPoint).normalize()
        val shared = q.multiply(d).normalize()
        return toFixed(shared.affineXCoord.toBigInteger(), COORD_BYTES)
    }

    private fun toFixed(v: BigInteger, len: Int): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(len)
        if (raw.size > len) {
            System.arraycopy(raw, raw.size - len, out, 0, len)
        } else {
            System.arraycopy(raw, 0, out, len - raw.size, raw.size)
        }
        return out
    }
}

/** HKDF-SHA-256 (RFC 5869), SHA-256, HMAC-SHA-256, AES-256-GCM. */
object Crypto {

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /** HKDF-Extract(salt, ikm) = HMAC-SHA-256(salt, ikm). */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray = hmacSha256(salt, ikm)

    /** HKDF-Expand(prk, info, length). */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    /** `nonce = 00000000 || u64_be(counter)` (handshake.md 6.1). */
    fun aeadNonce(counter: Long): ByteArray = Bytes.concat(ByteArray(4), Bytes.u64be(counter))

    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /**
     * AES-256-GCM open. Returns null when the tag does not verify (the caller
     * maps that to AEAD_AUTH_FAILED); malformed key/nonce throw.
     */
    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (e: javax.crypto.AEADBadTagException) {
            null
        } catch (e: Exception) {
            null
        }
    }
}
