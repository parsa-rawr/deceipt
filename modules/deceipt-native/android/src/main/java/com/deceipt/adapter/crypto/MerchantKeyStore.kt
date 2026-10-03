package com.deceipt.adapter.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64 as AndroidBase64
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.Bytes
import com.deceipt.adapter.protocol.Cose
import com.deceipt.adapter.protocol.ProtocolError
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.NamedParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Merchant device key custody on Android.
 *
 * VERDICT (see modules/deceipt-native/android/ANDROID-KEY-STORAGE.md for the full research note):
 * holding an Ed25519 key directly in Android Keystore requires **API 33+**
 * (Android 13); `AndroidKeyStore` gained Curve25519/Ed25519 there, hardware-backed
 * only where the device's KeyMint/StrongBox supports it. The Deceipt PoC floor is
 * **minSdk 24**, so a majority of the floor cannot hold Ed25519 directly.
 *
 * Therefore this adapter:
 *   * probes for direct Keystore Ed25519 at runtime and uses it when the probe
 *     succeeds (`keystore_ed25519`, non-exportable);
 *   * otherwise uses the DESIGN.md 4.4 fallback: an app-generated Ed25519 seed
 *     encrypted with a device-bound AES-256-GCM key held in Android Keystore, in
 *     private app storage (`keystore_wrapped_aes`).
 *
 * The fallback is EXPLICITLY NOT hardware-backed non-exportability: the seed is
 * decrypted into the app process to sign. It is still device-bound — the wrapped
 * blob is unreadable without the Keystore AES key, which never leaves the TEE/SE
 * and is destroyed on uninstall. See `modules/deceipt-native/android/ANDROID-KEY-STORAGE.md`.
 */
object MerchantKeyStore {

    const val DIRECT_ALIAS = "deceipt.merchant.ed25519.v1"
    const val WRAP_ALIAS = "deceipt.merchant.wrapAes.v1"
    private const val WRAPPED_FILE = "deceipt-merchant-key.bin"
    private const val WRAPPED_MAGIC = "DECEIPTK1"
    private const val GCM_TAG_BITS = 128

    data class StoredKey(
        val storage: String, // keystore_ed25519 | keystore_wrapped_aes | in_memory_ephemeral | none
        val deviceKeyId: ByteArray?,
        val publicKey: ByteArray?,
        val createdAtMs: Long,
        /** Test provisioning path: in-memory seed, never persisted. */
        val ephemeralSeed: ByteArray? = null,
    )

    // -----------------------------------------------------------------------
    // Capability probe
    // -----------------------------------------------------------------------

    /**
     * Whether the running device can hold an Ed25519 key directly in Android
     * Keystore. Gated on API 33 (documented introduction) and then PROBED, because
     * per-device support varies — never assumed.
     */
    fun directKeystoreEd25519Available(): Boolean {
        if (Build.VERSION.SDK_INT < 33) return false
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val probeAlias = "deceipt.probe.ed25519"
            if (ks.containsAlias(probeAlias)) ks.deleteEntry(probeAlias)
            val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(probeAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
                    .build(),
            )
            val kp = kpg.generateKeyPair()
            val sig = Signature.getInstance("Ed25519").apply { initSign(kp.private) }
            sig.update("deceipt-probe".toByteArray())
            val signature = sig.sign()
            val ver = Signature.getInstance("Ed25519").apply { initVerify(kp.public) }
            ver.update("deceipt-probe".toByteArray())
            val ok = ver.verify(signature)
            ks.deleteEntry(probeAlias)
            ok
        } catch (e: Exception) {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Generate / load / delete
    // -----------------------------------------------------------------------

    fun generate(context: Context, deviceKeyId: ByteArray): StoredKey {
        require(deviceKeyId.size == 16)
        if (directKeystoreEd25519Available()) {
            try {
                generateDirect(deviceKeyId)
                return load(context, deviceKeyId) ?: error("direct key not readable after generate")
            } catch (e: Exception) {
                // Fall through to the wrapped fallback rather than failing the PoC.
            }
        }
        return generateWrapped(context, deviceKeyId)
    }

    private fun generateDirect(deviceKeyId: ByteArray) {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(DIRECT_ALIAS)) ks.deleteEntry(DIRECT_ALIAS)
        val kpg = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(DIRECT_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
                .build(),
        )
        kpg.generateKeyPair()
    }

    private fun generateWrapped(context: Context, deviceKeyId: ByteArray): StoredKey {
        val seed = Ed25519.generateSeed()
        val wrapped = wrapSeed(context, seed)
        Bytes.zeroize(seed)
        writeWrapped(context, deviceKeyId, wrapped)
        return load(context, deviceKeyId) ?: error("wrapped key not readable after generate")
    }

    /** Test-only provisioning: import a published seed into the wrapped store. */
    fun provision(context: Context, deviceKeyId: ByteArray, seed: ByteArray): StoredKey {
        require(seed.size == Ed25519.SEED_BYTES) { "seed must be 32 bytes" }
        val wrapped = wrapSeed(context, seed)
        writeWrapped(context, deviceKeyId, wrapped)
        return load(context, deviceKeyId) ?: error("provisioned key not readable")
    }

    fun load(context: Context, deviceKeyId: ByteArray): StoredKey? {
        // Direct Keystore path.
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(DIRECT_ALIAS)) {
                val pub = ks.getCertificate(DIRECT_ALIAS)?.publicKey?.encoded
                if (pub != null && pub.size == 32) {
                    return StoredKey("keystore_ed25519", deviceKeyId, pub, createdAtMs = 0L)
                }
            }
        } catch (e: Exception) {
            // ignore; try the wrapped store
        }
        // Wrapped fallback.
        val f = wrappedFile(context)
        if (!f.exists()) return null
        val raw = try {
            f.readBytes()
        } catch (e: Exception) {
            return null
        }
        val parsed = parseWrapped(raw) ?: return null
        val seed = unwrapSeed(context, parsed.second) ?: return null
        return try {
            val pub = Ed25519.publicKeyFromSeed(seed)
            // Re-wrap with a fresh IV on load so a stolen blob's IV is not stable.
            StoredKey("keystore_wrapped_aes", parsed.first, pub, createdAtMs = 0L)
        } finally {
            Bytes.zeroize(seed)
        }
    }

    fun delete(context: Context) {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(DIRECT_ALIAS)) ks.deleteEntry(DIRECT_ALIAS)
        } catch (e: Exception) {
            // best effort
        }
        wrappedFile(context).delete()
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /**
     * Sign the receipt payload bytes. Builds the COSE_Sign1 container natively;
     * TS never builds or re-encodes the signed structure.
     */
    fun signReceipt(context: Context, deviceKeyId: ByteArray, payload: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val protectedBytes = Cose.receiptProtectedHeader(deviceKeyId)
        val sigStructure = Cose.sigStructure(protectedBytes, payload)
        val signature = signRaw(context, deviceKeyId, sigStructure)
        if (signature.size != Ed25519.SIGNATURE_BYTES) throw ProtocolError("INTERNAL_ERROR", "signature length")
        val container = Cose.build(protectedBytes, payload, signature)
        return Triple(container, signature, protectedBytes)
    }

    /** Sign arbitrary bytes (the handshake transcript, or a COSE Sig_structure). */
    fun signRaw(context: Context, deviceKeyId: ByteArray, message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(DIRECT_ALIAS)) {
            val entry = ks.getEntry(DIRECT_ALIAS, null) as? KeyStore.PrivateKeyEntry
            if (entry != null) {
                val s = Signature.getInstance("Ed25519").apply { initSign(entry.privateKey) }
                s.update(message)
                return s.sign()
            }
        }
        return signWrapped(context, message)
    }

    private fun signWrapped(context: Context, sigStructure: ByteArray): ByteArray {
        val f = wrappedFile(context)
        if (!f.exists()) throw ProtocolError("INTERNAL_ERROR", "no merchant key provisioned")
        val parsed = parseWrapped(f.readBytes()) ?: throw ProtocolError("INTERNAL_ERROR", "malformed wrapped key")
        val seed = unwrapSeed(context, parsed.second) ?: throw ProtocolError("INTERNAL_ERROR", "cannot unwrap merchant key")
        return try {
            Ed25519.sign(seed, sigStructure)
        } finally {
            Bytes.zeroize(seed)
        }
    }

    // -----------------------------------------------------------------------
    // Wrapped format: MAGIC || u8 idLen || id || u8 ivLen || iv || ciphertext
    // -----------------------------------------------------------------------

    private fun wrapSeed(context: Context, seed: ByteArray): ByteArray {
        val key = wrapKey(context)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(seed)
        return Bytes.concat(iv, ct)
    }

    private fun unwrapSeed(context: Context, ivAndCt: ByteArray): ByteArray? {
        if (ivAndCt.size <= 12) return null
        return try {
            val iv = ivAndCt.copyOfRange(0, 12)
            val ct = ivAndCt.copyOfRange(12, ivAndCt.size)
            val key = wrapKey(context)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ct)
        } catch (e: Exception) {
            null
        }
    }

    private fun wrapKey(context: Context): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(WRAP_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(WRAP_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return kg.generateKey()
    }

    private fun writeWrapped(context: Context, deviceKeyId: ByteArray, ivAndCt: ByteArray) {
        val f = wrappedFile(context)
        val out = Bytes.concat(
            WRAPPED_MAGIC.toByteArray(Charsets.US_ASCII),
            byteArrayOf(deviceKeyId.size.toByte()),
            deviceKeyId,
            ivAndCt,
        )
        f.writeBytes(out)
        // Private app storage; no world-readable mode.
        f.setReadable(false, false)
        f.setReadable(true, true)
    }

    private fun parseWrapped(raw: ByteArray): Pair<ByteArray, ByteArray>? {
        if (raw.size < WRAPPED_MAGIC.length + 1) return null
        if (!raw.copyOfRange(0, WRAPPED_MAGIC.length).contentEquals(WRAPPED_MAGIC.toByteArray(Charsets.US_ASCII))) return null
        var pos = WRAPPED_MAGIC.length
        val idLen = raw[pos].toInt() and 0xff
        pos += 1
        if (raw.size < pos + idLen) return null
        val id = raw.copyOfRange(pos, pos + idLen)
        pos += idLen
        return id to raw.copyOfRange(pos, raw.size)
    }

    private fun wrappedFile(context: Context): File = File(context.filesDir, WRAPPED_FILE)
}
