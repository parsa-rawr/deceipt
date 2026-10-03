package com.deceipt.adapter.bridge

import com.deceipt.adapter.crypto.MerchantKeyStore
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.Bytes
import com.deceipt.adapter.protocol.Cose
import com.deceipt.adapter.protocol.Credential
import com.deceipt.adapter.protocol.Handshake
import com.deceipt.adapter.protocol.ProtocolError
import com.deceipt.adapter.protocol.Qr
import com.deceipt.adapter.session.Session
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Owns the live sessions, the merchant binding store and the batched event
 * queue. Kept free of RN types so the protocol path stays unit-testable; the
 * module adapts its maps to `WritableMap`.
 */
class SessionManager(private val merchantContext: android.content.Context?) {

    private val sessions = ConcurrentHashMap<String, Session>()
    private val random = SecureRandom()
    val bindingStore: com.deceipt.adapter.protocol.BindingStore = com.deceipt.adapter.protocol.BindingStore()
    val sessionHistory: com.deceipt.adapter.protocol.SessionIdHistory = com.deceipt.adapter.protocol.SessionIdHistory()

    /** Latest merchant key identity (device key id + public key), if provisioned. */
    @Volatile var merchantDeviceKeyId: ByteArray? = null
    @Volatile var merchantPublicKey: ByteArray? = null
    @Volatile var merchantStorage: String = "none"
    @Volatile var merchantCreatedAtMs: Long = 0L
    @Volatile var merchantCredential: ByteArray? = null
    @Volatile var merchantId: ByteArray? = null

    fun handle(explicit: String? = null): String = explicit ?: ("s" + Bytes.toHex(ByteArray(8).also { random.nextBytes(it) }))

    fun put(session: Session) {
        sessions[session.handle] = session
    }

    fun get(handle: String): Session? = sessions[handle]

    fun remove(handle: String) {
        sessions.remove(handle)
    }

    fun all(): Collection<Session> = sessions.values

    fun closeAll(reason: String) {
        for (s in sessions.values) s.stop(reason)
        sessions.clear()
    }

    // -- merchant key operations --------------------------------------------

    fun generateMerchantKey(): MerchantKeyStore.StoredKey {
        val ctx = requireNotNull(merchantContext) { "no android context" }
        val deviceKeyId = ByteArray(16).also { random.nextBytes(it) }
        val stored = MerchantKeyStore.generate(ctx, deviceKeyId)
        merchantDeviceKeyId = stored.deviceKeyId
        merchantPublicKey = stored.publicKey
        merchantStorage = stored.storage
        merchantCreatedAtMs = System.currentTimeMillis()
        return stored
    }

    /**
     * Reload the persisted merchant identity. This is called on every status read,
     * so a COLD START (process death, app restart) re-hydrates the in-memory
     * identity from disk; without it a persisted key would look unprovisioned.
     */
    fun loadMerchantKey(): MerchantKeyStore.StoredKey? {
        val ctx = merchantContext ?: return null
        val stored = MerchantKeyStore.load(ctx) ?: return null
        merchantDeviceKeyId = stored.deviceKeyId
        merchantPublicKey = stored.publicKey
        merchantStorage = stored.storage
        if (merchantCredential == null) {
            merchantCredential = MerchantKeyStore.loadCredential(ctx)
            merchantId = merchantCredential?.let {
                try {
                    Credential.parseFields(it).merchantId
                } catch (e: ProtocolError) {
                    null
                }
            }
        }
        return stored
    }

    fun deleteMerchantKey() {
        val ctx = merchantContext ?: return
        MerchantKeyStore.delete(ctx)
        merchantDeviceKeyId = null
        merchantPublicKey = null
        merchantStorage = "none"
        merchantCredential = null
        merchantId = null
    }

    fun provisionTestMerchant(seed: ByteArray, deviceKeyId: ByteArray, credential: ByteArray) {
        val ctx = requireNotNull(merchantContext)
        val stored = MerchantKeyStore.provision(ctx, deviceKeyId, seed, credential)
        merchantDeviceKeyId = stored.deviceKeyId
        merchantPublicKey = stored.publicKey
        merchantStorage = stored.storage
        merchantCredential = credential
        merchantId = try {
            Credential.parseFields(credential).merchantId
        } catch (e: ProtocolError) {
            null
        }
    }

    fun merchantKeyOrNull(): ByteArray? = merchantDeviceKeyId

    /** Sign a receipt payload and return the full COSE_Sign1 container. */
    fun signReceipt(payload: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val ctx = requireNotNull(merchantContext)
        // Hydrate first so a cold start does not depend on call order.
        loadMerchantKey()
        val deviceKeyId = merchantDeviceKeyId ?: throw ProtocolError("CAPABILITY_UNAVAILABLE", "no merchant key")
        return MerchantKeyStore.signReceipt(ctx, deviceKeyId, payload)
    }

    fun signer(): com.deceipt.adapter.session.MerchantSigner? {
        val ctx = merchantContext ?: return null
        loadMerchantKey()
        val deviceKeyId = merchantDeviceKeyId ?: return null
        val pub = merchantPublicKey ?: return null
        return object : com.deceipt.adapter.session.MerchantSigner {
            override fun deviceKeyId(): ByteArray = deviceKeyId
            override fun devicePublicKey(): ByteArray = pub
            override fun sign(sigStructure: ByteArray): ByteArray {
                // Sign the transcript bytes directly (handshake.md 3).
                return MerchantKeyStore.signRaw(ctx, deviceKeyId, sigStructure)
            }
        }
    }
}
