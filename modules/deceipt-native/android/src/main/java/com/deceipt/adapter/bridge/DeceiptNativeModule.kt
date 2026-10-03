package com.deceipt.adapter.bridge

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.deceipt.adapter.ble.BlePermissions
import com.deceipt.adapter.crypto.Ed25519
import com.deceipt.adapter.crypto.Crypto
import com.deceipt.adapter.crypto.MerchantKeyStore
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.Bytes
import com.deceipt.adapter.protocol.Cose
import com.deceipt.adapter.protocol.Credential
import com.deceipt.adapter.protocol.Errors
import com.deceipt.adapter.protocol.Handshake
import com.deceipt.adapter.protocol.Messages
import com.deceipt.adapter.protocol.ProtocolError
import com.deceipt.adapter.protocol.Qr
import com.deceipt.adapter.protocol.ReceiptVerify
import com.deceipt.adapter.session.Events
import com.deceipt.adapter.session.Session
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import java.util.concurrent.Executors

/**
 * The legacy `DeceiptNative` module (modules/deceipt-native/index.ts
 * `NATIVE_MODULE_NAME`). Implements every method of
 * `app/src/native/DeceiptNative.ts` exactly; no method is added or renamed.
 *
 * Byte encoding: standard base64 WITH padding (RFC 4648 4), decoded strictly.
 * Events are batched (at most once per 16 ms) and ONE byte-carrying event is
 * emitted per logical protocol object — never one bridge call per BLE fragment.
 */
class DeceiptNativeModule(
    private val reactContext: ReactApplicationContext,
) : ReactContextBaseJavaModule(reactContext) {

    private val manager = SessionManager(reactContext.applicationContext)
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "deceipt-native") }
    private val eventQueue = ArrayDeque<WritableMap>()
    private var flushScheduled = false
    private var listenerAttached = false

    override fun getName(): String = DeceiptPackage.MODULE_NAME

    // -----------------------------------------------------------------------
    // Event batching
    // -----------------------------------------------------------------------

    private fun emit(map: Map<String, Any?>) {
        synchronized(eventQueue) {
            eventQueue.addLast(toWritable(map))
            if (!flushScheduled) {
                flushScheduled = true
                reactContext.runOnUiQueueThread { flushBatch() }
            }
        }
    }

    private fun flushNow() {
        synchronized(eventQueue) { flushScheduled = true }
        reactContext.runOnUiQueueThread { flushBatch() }
    }

    /** Drain the queue into ONE batched emitter delivery. */
    private fun flushBatch() {
        val batch = Arguments.createArray()
        synchronized(eventQueue) {
            while (eventQueue.isNotEmpty()) batch.pushMap(eventQueue.removeFirst())
            flushScheduled = false
        }
        if (batch.size() == 0) return
        // A3's adapterShim subscribes to this exact channel (EVENT_CHANNEL).
        reactContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
            .emit(EVENT_CHANNEL, batch)
    }

    private fun toWritable(value: Any?): WritableMap {
        val map = Arguments.createMap()
        @Suppress("UNCHECKED_CAST")
        when (value) {
            is Map<*, *> -> for ((k, v) in value) putAny(map, k as String, v)
            else -> {}
        }
        return map
    }

    private fun putAny(map: WritableMap, key: String, value: Any?) {
        when (value) {
            null -> map.putNull(key)
            is Boolean -> map.putBoolean(key, value)
            is Int -> map.putInt(key, value)
            is Long -> map.putDouble(key, value.toDouble())
            is Double -> map.putDouble(key, value)
            is String -> map.putString(key, value)
            is Map<*, *> -> map.putMap(key, toWritable(value))
            is List<*> -> {
                val arr = Arguments.createArray()
                for (item in value) {
                    when (item) {
                        null -> arr.pushNull()
                        is Boolean -> arr.pushBoolean(item)
                        is Int -> arr.pushInt(item)
                        is Long -> arr.pushDouble(item.toDouble())
                        is Double -> arr.pushDouble(item)
                        is String -> arr.pushString(item)
                        else -> arr.pushString(item.toString())
                    }
                }
                map.putArray(key, arr)
            }
            else -> map.putString(key, value.toString())
        }
    }

    private fun ok(promise: Promise, value: Any?) {
        promise.resolve(if (value == null) null else toWritable(value))
    }

    private fun fail(promise: Promise, e: Throwable, phase: String? = null) {
        val pe = e as? ProtocolError
            ?: ProtocolError("INTERNAL_ERROR", e.message?.take(64) ?: e.javaClass.simpleName)
        promise.reject(pe.errorName, pe.message, pe.toBridge(phase).let { b -> toWritable(b) })
    }

    private fun <T> onWorker(promise: Promise, block: () -> T) {
        executor.execute {
            try {
                val r = block()
                reactContext.runOnUiQueueThread { ok(promise, r) }
            } catch (t: Throwable) {
                reactContext.runOnUiQueueThread { fail(promise, t) }
            }
        }
    }

    /**
     * Worker path for a SCALAR result (e.g. a base64 string). The map-shaped
     * [ok] would coerce it to an empty WritableMap, so this resolves the raw
     * value directly.
     */
    private fun <T> onWorkerRaw(promise: Promise, block: () -> T) {
        executor.execute {
            try {
                val r = block()
                reactContext.runOnUiQueueThread { promise.resolve(r) }
            } catch (t: Throwable) {
                reactContext.runOnUiQueueThread { fail(promise, t) }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capabilities & permissions
    // -----------------------------------------------------------------------

    @ReactMethod
    fun capabilities(promise: Promise) {
        onWorker(promise) {
            val report = BlePermissions.report(reactContext)
            val adapter = BlePermissions.adapter(reactContext)
            val advertisingSupported = adapter != null && (adapter.isMultipleAdvertisementSupported || adapter.isOffloadedAdvertisementsSupportedCompat())
            linkedMapOf<String, Any?>(
                "platform" to "android",
                "bleCentral" to (adapter != null),
                "blePeripheral" to (adapter != null),
                "bleAdvertising" to advertisingSupported,
                "protocolVersion" to Bounds.PROTOCOL_VERSION,
                "suiteIds" to listOf(Bounds.SUITE_ID),
                "ed25519" to true,
                "ed25519Keystore" to true,
                "ed25519HardwareBacked" to (manager.merchantStorage == "keystore_ed25519"),
                "keyPersistence" to true,
                "cameraQrScan" to BlePermissions.hasCamera(reactContext),
                "testProvisioningEnabled" to TEST_PROVISIONING_ENABLED,
                "adapterBuild" to "a5-android-0.1.0",
                "bluetoothState" to report.bluetoothState,
            )
        }
    }

    private fun android.bluetooth.BluetoothAdapter.isOffloadedAdvertisementsSupportedCompat(): Boolean =
        this.isMultipleAdvertisementSupported

    @ReactMethod
    fun permissionState(promise: Promise) {
        onWorker(promise) { BlePermissions.report(reactContext).toBridgeMap() }
    }

    @ReactMethod
    fun requestPermissions(kinds: ReadableArray, promise: Promise) {
        onWorker(promise) {
            val requested = (0 until kinds.size()).mapNotNull { kinds.getString(it) }
            val includeCamera = requested.contains("camera")
            if (requested.contains("bluetooth")) {
                val role = if (manager.merchantKeyOrNull() != null) BlePermissions.Role.MERCHANT else BlePermissions.Role.CUSTOMER
                val needed = BlePermissions.requestablePermissions(role, includeCamera)
                reactContext.currentActivity?.requestPermissions(needed.toTypedArray(), REQ_BLE)
            } else if (includeCamera) {
                reactContext.currentActivity?.requestPermissions(arrayOf(BlePermissions.cameraPermission()), REQ_BLE)
            }
            BlePermissions.report(reactContext).toBridgeMap()
        }
    }

    @ReactMethod
    fun openSettings(target: String, promise: Promise) {
        onWorker(promise) {
            val activity = reactContext.currentActivity
            if (activity == null) {
                throw ProtocolError("CAPABILITY_UNAVAILABLE", "no foreground activity")
            }
            val intent = if (target == "bluetooth") {
                Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
            } else {
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + reactContext.packageName))
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
            null
        }
    }

    // -----------------------------------------------------------------------
    // Merchant keys & signing
    // -----------------------------------------------------------------------

    @ReactMethod
    fun merchantKeyStatus(promise: Promise) {
        onWorker(promise) {
            val stored = manager.loadMerchantKey() ?: manager.merchantPublicKey?.let {
                MerchantKeyStore.StoredKey(manager.merchantStorage, manager.merchantDeviceKeyId, it, manager.merchantCreatedAtMs)
            }
            val identity = stored?.let { s ->
                linkedMapOf<String, Any?>(
                    "deviceKeyIdHex" to Bytes.toHex(s.deviceKeyId ?: ByteArray(0)),
                    "devicePublicKeyB64" to Bytes.toBase64(s.publicKey ?: ByteArray(0)),
                    "storage" to s.storage,
                    "createdAtMs" to s.createdAtMs,
                )
            }
            val m = linkedMapOf<String, Any?>("provisioned" to (identity != null))
            if (identity != null) m["identity"] = identity
            manager.merchantCredential?.let { m["credentialB64"] = Bytes.toBase64(it) }
            manager.merchantId?.let { m["merchantIdHex"] = Bytes.toHex(it) }
            m
        }
    }

    @ReactMethod
    fun merchantKeyGenerate(promise: Promise) {
        onWorker(promise) {
            val stored = manager.generateMerchantKey()
            linkedMapOf<String, Any?>(
                "deviceKeyIdHex" to Bytes.toHex(stored.deviceKeyId ?: ByteArray(0)),
                "devicePublicKeyB64" to Bytes.toBase64(stored.publicKey ?: ByteArray(0)),
                "storage" to stored.storage,
                "createdAtMs" to stored.createdAtMs,
            )
        }
    }

    @ReactMethod
    fun merchantKeyDelete(promise: Promise) {
        onWorker(promise) { manager.deleteMerchantKey(); null }
    }

    @ReactMethod
    fun merchantPublicIdentity(promise: Promise) {
        onWorker(promise) {
            val stored = manager.loadMerchantKey() ?: return@onWorker null
            linkedMapOf<String, Any?>(
                "deviceKeyIdHex" to Bytes.toHex(stored.deviceKeyId ?: ByteArray(0)),
                "devicePublicKeyB64" to Bytes.toBase64(stored.publicKey ?: ByteArray(0)),
                "storage" to stored.storage,
                "createdAtMs" to stored.createdAtMs,
            )
        }
    }

    @ReactMethod
    fun merchantSignReceipt(payloadB64: String, promise: Promise) {
        onWorker(promise) {
            val payload = Bytes.fromBase64(payloadB64)
            val (container, signature, protectedBytes) = manager.signReceipt(payload)
            linkedMapOf<String, Any?>(
                "coseSign1B64" to Bytes.toBase64(container),
                "signatureB64" to Bytes.toBase64(signature),
                "protectedB64" to Bytes.toBase64(protectedBytes),
                "deviceKeyIdHex" to Bytes.toHex(manager.merchantDeviceKeyId ?: ByteArray(0)),
            )
        }
    }

    @ReactMethod
    fun verifyReceiptContainer(coseSign1B64: String, devicePublicKeyB64: String, promise: Promise) {
        onWorker(promise) {
            val cose = Bytes.fromBase64(coseSign1B64)
            val pub = Bytes.fromBase64(devicePublicKeyB64)
            val r = ReceiptVerify.parseAndVerify(cose, pub)
            val m = linkedMapOf<String, Any?>("signatureValid" to r.signatureValid)
            r.deviceKeyIdHex?.let { m["deviceKeyIdHex"] = it }
            val errName = r.errorName
            if (errName != null) m["error"] = Errors.descriptor(errName).let {
                linkedMapOf<String, Any?>("name" to it.name, "code" to it.code, "fatal" to it.fatal, "retryable" to it.retryable)
            }
            m
        }
    }

    @ReactMethod
    fun verifyCredential(credentialB64: String, anchors: ReadableArray, nowUnix: Double?, promise: Promise) {
        onWorker(promise) {
            val credential = Bytes.fromBase64(credentialB64)
            val anchorList = (0 until anchors.size()).mapNotNull { anchors.getMap(it)?.let { m ->
                Credential.Anchor(
                    Bytes.fromHex(m.getString("anchorIdHex") ?: ""),
                    Bytes.fromBase64(m.getString("publicKeyB64") ?: ""),
                    if (m.hasKey("label")) m.getString("label") else null,
                )
            } }
            val now = nowUnix?.toLong() ?: (System.currentTimeMillis() / 1000L)
            val v = Credential.verify(credential, anchorList, now)
            Events.credentialMap(v)
        }
    }

    // -----------------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------------

    @ReactMethod
    fun mintBindingQr(request: ReadableMap, promise: Promise) {
        onWorker(promise) {
            val sessionId = Bytes.fromHex(request.getString("sessionIdHex")!!)
            val offerHashHex = request.getString("offerHashHex")!!
            val offerHash = Bytes.fromHex(offerHashHex)
            val expires = request.getDouble("expiresAtUnix").toLong()
            val sbt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            manager.bindingStore.put(sessionId, sbt, offerHash, expires)
            val qr = Qr.mint(sessionId, sbt, offerHash, expires)
            pendingBindingRef = Bytes.toHex(sessionId)
            linkedMapOf<String, Any?>(
                "bindingRef" to Bytes.toHex(sessionId),
                "qrPayload" to qr,
                "sessionIdHex" to Bytes.toHex(sessionId),
                "expiresAtUnix" to expires,
            )
        }
    }

    private var pendingBindingRef: String? = null

    @ReactMethod
    fun startMerchantSession(request: ReadableMap, promise: Promise) {
        onWorker(promise) {
            val sessionIdHex = request.getString("sessionIdHex")!!
            val sessionId = Bytes.fromHex(sessionIdHex)
            manager.sessionHistory.remember(sessionId)
            val handle = manager.handle()
            val ble = MerchantBleSession(reactContext.applicationContext, ::emit)
            val session = Session(
                handle, Session.Role.MERCHANT, ble, ::emit,
                random = java.security.SecureRandom(),
            )
            ble.attach(session)
            session.setMerchantCredential(manager.merchantCredential ?: throw ProtocolError("CREDENTIAL_MALFORMED", "merchant not provisioned"))
            session.startMerchant(
                manager.bindingStore,
                request.getString("receiptCose1B64")!!,
                request.getString("transferIdHex")!!,
                sessionIdHex,
                request.getString("receiptIdHex")!!,
                request.getString("offerHashHex")!!,
                if (request.hasKey("frameSize")) request.getDouble("frameSize").toInt() else null,
                manager.signer() ?: throw ProtocolError("CAPABILITY_UNAVAILABLE", "no merchant key"),
            )
            // Bring up the GATT server + advertiser now that the session is armed.
            ble.open()
            manager.put(session)
            session.snapshot()
        }
    }

    @ReactMethod
    fun beginTransfer(sessionHandle: String, session: ReadableMap?, promise: Promise) {
        onWorker(promise) {
            val s = require(sessionHandle)
            requireTransferable(session)
            s.beginTransfer()
            null
        }
    }

    @ReactMethod
    fun startScan(promise: Promise) {
        onWorker(promise) { emit(Events.scanStarted()); null }
    }

    @ReactMethod
    fun stopScan(promise: Promise) {
        onWorker(promise) { emit(Events.scanStopped("user_cancelled")); null }
    }

    @ReactMethod
    fun startCustomerSession(request: ReadableMap, promise: Promise) {
        onWorker(promise) {
            val selection = request.getMap("selection") ?: throw ProtocolError("BINDING_REQUIRED", "no selection")
            if (selection.getString("kind") != "qr") throw ProtocolError("BINDING_REQUIRED", "qr selection is mandatory")
            val qrPayload = selection.getString("qrPayload") ?: throw ProtocolError("BINDING_REQUIRED", "no qr payload")
            val qr = Qr.parse(qrPayload)
            Qr.checkFresh(qr, System.currentTimeMillis() / 1000L)
            if (!manager.sessionHistory.remember(qr.sessionId)) {
                throw ProtocolError("BINDING_CONSUMED")
            }
            if (manager.bindingStore.isConsumed(qr.sessionId)) throw ProtocolError("BINDING_CONSUMED")

            val anchors = parseAnchors(request.getArray("anchors"))
            val handle = manager.handle()
            val ble = CustomerBleSession(reactContext.applicationContext, ::emit)
            val session = Session(
                handle, Session.Role.CUSTOMER, ble, ::emit,
                random = java.security.SecureRandom(), anchors = anchors,
            )
            ble.attach(session)
            // The QR names the session; the first candidate advertising the service
            // is the connect target. 2+ candidates fail closed inside the transport.
            ble.awaitFirstCandidate { peripheralId ->
                try {
                    ble.connectSelected(peripheralId)
                } catch (e: ProtocolError) {
                    emit(Events.error(handle, e.toBridge("connect")))
                }
            }
            val clientMax = if (request.hasKey("clientMaxFramePayload")) request.getDouble("clientMaxFramePayload").toInt() else null
            ble.startScan()
            session.startCustomer(
                Bytes.toHex(qr.sessionId), qr.sessionBindingToken, Bytes.toHex(qr.offerHash), clientMax, manager.bindingStore,
            )
            manager.put(session)
            session.snapshot()
        }
    }

    @ReactMethod
    fun acceptOffer(session: ReadableMap, promise: Promise) {
        onWorker(promise) {
            requireTransferable(session)
            val handle = sessionHandleOf(session)
            require(handle).acceptOffer()
            null
        }
    }

    @ReactMethod
    fun retryTransfer(sessionHandle: String, fromSequence: Double, promise: Promise) {
        onWorker(promise) { require(sessionHandle).retryFrom(fromSequence.toLong()); null }
    }

    @ReactMethod
    fun sendReceiptAck(session: ReadableMap, receiptIdHex: String, outcome: String, promise: Promise) {
        onWorker(promise) {
            requireTransferable(session)
            val code = com.deceipt.adapter.protocol.OutcomeCodes.of(outcome)
            require(sessionHandleOf(session)).sendReceiptAck(receiptIdHex, code)
            null
        }
    }

    @ReactMethod
    fun cancelSession(sessionHandle: String, reason: String?, promise: Promise) {
        onWorker(promise) {
            manager.get(sessionHandle)?.cancel(reason ?: "user_cancelled")
            manager.remove(sessionHandle)
            null
        }
    }

    @ReactMethod
    fun stopSession(sessionHandle: String, promise: Promise) {
        onWorker(promise) {
            manager.get(sessionHandle)?.stop("user_cancelled")
            manager.remove(sessionHandle)
            null
        }
    }

    @ReactMethod
    fun sessionSnapshot(sessionHandle: String, promise: Promise) {
        onWorker(promise) {
            val s = manager.get(sessionHandle) ?: throw ProtocolError("SESSION_TORN_DOWN")
            s.snapshot()
        }
    }

    /**
     * Readiness probe. A3's contract is satisfied on the JS side by
     * `adaptNativeModule` / `subscribeViaEmitter`: the emitter pattern is the
     * agreed Android mechanism (a legacy bridge method cannot RETURN the
     * `unsubscribe` closure the contract declares). Events are emitted BATCHED on
     * [EVENT_CHANNEL] and delivered via `addListener`/`removeListeners`.
     */
    @ReactMethod
    fun subscribe(promise: Promise) {
        onWorker(promise) {
            listenerAttached = true
            null
        }
    }

    /** Standard emitter contract: the shim builds a NativeEventEmitter over this. */
    @ReactMethod
    fun addListener(eventName: String) {
        listenerAttached = true
    }

    @ReactMethod
    fun removeListeners(count: Double) {
        listenerAttached = false
    }

    /**
     * Cryptographically strong random bytes for protocol secrets
     * (session_id / client_nonce / SBT) when the JS runtime has no WebCrypto —
     * Hermes does not expose `globalThis.crypto`. Backed by `SecureRandom`; a JS
     * PRNG is never acceptable for these values.
     *
     * `count` is validated against `Crypto.MIN/MAX_RANDOM_BYTES` BEFORE allocating.
     * Runs on the worker path; the output is never logged or persisted.
     */
    @ReactMethod
    fun randomBytes(count: Double, promise: Promise) {
        // Scalar result: must resolve the Base64 STRING, not a WritableMap.
        onWorkerRaw(promise) { Bytes.toBase64(Crypto.randomBytes(count.toInt())) }
    }

    // -- test-only provisioning (gated) ------------------------------------

    @ReactMethod
    fun provisionTestMerchant(request: ReadableMap, promise: Promise) {
        onWorker(promise) {
            if (!TEST_PROVISIONING_ENABLED) {
                throw ProtocolError("CAPABILITY_UNAVAILABLE", "test provisioning disabled in this build")
            }
            val seed = Bytes.fromBase64(request.getString("deviceSeedB64")!!)
            val deviceKeyId = Bytes.fromHex(request.getString("deviceKeyIdHex")!!)
            val credential = Bytes.fromBase64(request.getString("credentialB64")!!)
            manager.provisionTestMerchant(seed, deviceKeyId, credential)
            merchantKeyStatusMap()
        }
    }

    @ReactMethod
    fun clearTestProvisioning(promise: Promise) {
        onWorker(promise) {
            if (!TEST_PROVISIONING_ENABLED) {
                throw ProtocolError("CAPABILITY_UNAVAILABLE", "test provisioning disabled in this build")
            }
            manager.deleteMerchantKey()
            null
        }
    }

    private fun merchantKeyStatusMap(): Map<String, Any?> =
        manager.merchantPublicKey?.let { pub ->
            linkedMapOf<String, Any?>(
                "provisioned" to true,
                "identity" to linkedMapOf<String, Any?>(
                    "deviceKeyIdHex" to Bytes.toHex(manager.merchantDeviceKeyId ?: ByteArray(0)),
                    "devicePublicKeyB64" to Bytes.toBase64(pub),
                    "storage" to manager.merchantStorage,
                    "createdAtMs" to manager.merchantCreatedAtMs,
                ),
            )
        } ?: linkedMapOf("provisioned" to false)

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun require(handle: String): Session =
        manager.get(handle) ?: throw ProtocolError("SESSION_TORN_DOWN", "unknown session handle")

    private fun sessionHandleOf(map: ReadableMap): String =
        map.getString("sessionHandle") ?: throw ProtocolError("SESSION_TORN_DOWN", "no session handle")

    /** Refuse a `SessionKeysOnly` handle at RUNTIME too (contract: PEER_NOT_AUTHENTICATED). */
    private fun requireTransferable(map: ReadableMap?) {
        if (map == null) return
        val kind = map.getString("kind")
        if (kind == "SessionKeysOnly") {
            throw ProtocolError("PEER_NOT_AUTHENTICATED", "a SessionKeysOnly session may not accept or transfer a receipt")
        }
    }

    private fun parseAnchors(anchors: ReadableArray?): List<Credential.Anchor> {
        if (anchors == null) return emptyList()
        return (0 until anchors.size()).mapNotNull { i ->
            anchors.getMap(i)?.let {
                Credential.Anchor(
                    Bytes.fromHex(it.getString("anchorIdHex") ?: return@let null),
                    Bytes.fromBase64(it.getString("publicKeyB64") ?: return@let null),
                    if (it.hasKey("label")) it.getString("label") else null,
                )
            }
        }
    }

    override fun invalidate() {
        // RN reload / unmount / app shutdown: no stale callbacks, no half-sessions.
        manager.closeAll("app_shutdown")
        flushNow()
        executor.shutdownNow()
        super.invalidate()
    }

    companion object {
        /**
         * Emitter channel for BATCHED event arrays. Must match A3's
         * `adapterShim.EVENT_CHANNEL` exactly.
         */
        private const val EVENT_CHANNEL = "DeceiptEvent"
        private const val REQ_BLE = 0x0DEC

        /** `BlePermissions.PermissionReport` -> the contract's `PermissionReport` shape. */
        fun BlePermissions.PermissionReport.toBridgeMap(): Map<String, Any?> = linkedMapOf(
            "bluetooth" to bluetoothStatus.wire,
            "camera" to cameraStatus.wire,
            "bluetoothState" to bluetoothState,
        )

        /**
         * `testProvisioningEnabled`. A release build MUST ship `false`
         * (trust.md 3, conformance B9). Set from the library's own DEBUG flag:
         * only debug/dev builds may import published test key material.
         */
        var TEST_PROVISIONING_ENABLED: Boolean = false

        init {
            TEST_PROVISIONING_ENABLED = com.deceipt.adapter.BuildConfig.DEBUG
        }
    }
}
