package com.deceipt.adapter.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelUuid
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.ProtocolError
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Merchant side: GATT server + advertiser (peripheral). `wire.md` 1.
 *
 *  * One service, three characteristics (COMMAND write-with-response, EVENT
 *    indicate, DATA notify). The service is OPEN — no pairing, no link
 *    encryption, no link authentication; trust comes from the handshake and the
 *    receipt signature, never from the link.
 *  * The advertisement carries the service UUID and nothing else.
 *  * Advertising support is DEVICE-DEPENDENT: `AdvertiseCallback.onStartFailure`
 *    is surfaced through `PeripheralCallback.onAdvertisingFailed` (frozen
 *    `CAPABILITY_UNAVAILABLE`), never a crash.
 *  * Outbound traffic is bounded per characteristic (default 64 entries). A full
 *    queue DROPS the item and signals `onQueueOverflow`; it never grows
 *    unbounded and never allocates from a peer-declared length.
 *  * At most one central is served: a second subscriber is reported through
 *    `onSubscriberLimitReached` and is never trusted or targeted.
 *
 * Threading: all bookkeeping runs on one `HandlerThread`; GATT/Binder callbacks
 * are marshalled onto it. `close()` flips an `AtomicBoolean`, stops advertising,
 * unregisters the server callback, clears the queues and stops the thread, so no
 * stale callback survives teardown.
 */
class GattServerSession(
    context: Context,
    private val callback: PeripheralCallback,
    private val queueCapacity: Int = DEFAULT_QUEUE_CAPACITY,
    private val autoAdvertise: Boolean = true,
) : BleLink {

    private val appContext: Context = context.applicationContext
    private val thread = HandlerThread(THREAD_NAME).apply { start() }
    private val handler = Handler(thread.looper)
    private val closed = AtomicBoolean(false)

    private val eventQueue = BoundedQueue(EVENT_NAME, queueCapacity) { n, c -> callback.onQueueOverflow(n, c) }
    private val dataQueue = BoundedQueue(DATA_NAME, queueCapacity) { n, c -> callback.onQueueOverflow(n, c) }

    private val advertising = AtomicBoolean(false)
    private val advertiseAttempted = AtomicBoolean(false)
    private val serviceAdded = AtomicBoolean(false)
    private val retryScheduled = AtomicBoolean(false)
    private val indicationsSent = AtomicInteger(0)

    private val subscriber = AtomicReference<BluetoothDevice?>(null)
    private val subscriberMtu = AtomicInteger(DEFAULT_ATT_MTU)

    private val lock = Any()

    @Volatile
    private var server: BluetoothGattServer? = null

    @Volatile
    private var advertiser: BluetoothLeAdvertiser? = null

    @Volatile
    private var commandCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var eventCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var dataCharacteristic: BluetoothGattCharacteristic? = null

    /** Set by the module: one COMMAND fragment (an LPdu fragment), exactly as written. */
    @Volatile
    var onCommandWrite: ((ByteArray) -> Unit)? = null

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            if (closed.get()) {
                stopAdvertisingInternal(BleReasons.APP_SHUTDOWN)
                return
            }
            advertising.set(true)
            dispatch { callback.onAdvertisingStarted() }
        }

        override fun onStartFailure(errorCode: Int) {
            if (closed.get()) return
            advertising.set(false)
            dispatch {
                callback.onAdvertisingFailed(FROZEN_CAPABILITY_UNAVAILABLE, advertiseFailureDetail(errorCode))
            }
        }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (closed.get()) return
            if (status != BluetoothGatt.GATT_SUCCESS || service.uuid != GattUuids.SERVICE) {
                dispatch { callback.onError(FROZEN_CAPABILITY_UNAVAILABLE, "gatt service add status=$status") }
                return
            }
            serviceAdded.set(true)
            if (autoAdvertise) startAdvertisingInternal(includeTxPowerLevel = false)
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (closed.get()) return
            if (newState == BluetoothGatt.STATE_DISCONNECTED && device.address == currentAddress()) {
                subscriber.set(null)
                subscriberMtu.set(DEFAULT_ATT_MTU)
                dispatch {
                    callback.onLinkDown(BleReasons.LINK_LOST)
                    callback.onCapabilityChanged(BlePermissions.report(appContext))
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            if (closed.get()) return
            if (device.address != currentAddress()) return
            subscriberMtu.set(if (mtu > 0) mtu else DEFAULT_ATT_MTU)
            dispatch { callback.onMtuChanged(BleDiagnostics.mtuInfo(subscriberMtu.get())) }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            dispatch {
                handleCommandWrite(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            dispatch { handleDescriptorWrite(device, requestId, descriptor, responseNeeded, value) }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor,
        ) {
            dispatch { respond(device, requestId, BluetoothGatt.GATT_SUCCESS, descriptor.value) }
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    val role: BleRole get() = BleRole.MERCHANT

    val isClosed: Boolean get() = closed.get()

    val isAdvertising: Boolean get() = advertising.get()

    val isServiceAdded: Boolean get() = serviceAdded.get()

    /** Address of the one subscriber currently served, or null. */
    val subscriberId: String? get() = currentAddress()

    /** Create the GATT server and register its callback. Advertising is not started. */
    fun openServer() {
        requireOpen()
        requireRolePermission()
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: throw ProtocolError("CAPABILITY_UNAVAILABLE", "no bluetooth service")
        val opened = try {
            manager.openGattServer(appContext, serverCallback)
        } catch (se: SecurityException) {
            throw ProtocolError(FROZEN_PERMISSION_DENIED, "openGattServer: ${se.message}")
        } ?: throw ProtocolError("CAPABILITY_UNAVAILABLE", "openGattServer returned null")
        synchronized(lock) { server = opened }
    }

    /** Register the one service and its three characteristics. */
    fun addService() {
        requireOpen()
        requireRolePermission()
        val s = synchronized(lock) { server } ?: throw ProtocolError("CAPABILITY_UNAVAILABLE", "server not open")

        val command = BluetoothGattCharacteristic(
            GattUuids.COMMAND,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val event = BluetoothGattCharacteristic(
            GattUuids.EVENT,
            BluetoothGattCharacteristic.PROPERTY_INDICATE,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        val data = BluetoothGattCharacteristic(
            GattUuids.DATA,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        for (c in listOf(command, event, data)) {
            c.addDescriptor(
                BluetoothGattDescriptor(
                    GattUuids.CCCD,
                    BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                ),
            )
        }
        val service = BluetoothGattService(GattUuids.SERVICE, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(command)
        service.addCharacteristic(event)
        service.addCharacteristic(data)

        commandCharacteristic = command
        eventCharacteristic = event
        dataCharacteristic = data

        val ok = try {
            s.addService(service)
        } catch (se: SecurityException) {
            throw ProtocolError(FROZEN_PERMISSION_DENIED, "addService: ${se.message}")
        }
        if (!ok) throw ProtocolError("CAPABILITY_UNAVAILABLE", "GATT addService rejected")
    }

    /** `openServer` + `addService`; advertising follows on service-added. */
    fun serve() {
        openServer()
        addService()
    }

    /**
     * Start advertising the service UUID and nothing else. `onAdvertisingFailed`
     * reports device-dependent advertising unsupported-ness.
     */
    fun startAdvertising(includeTxPowerLevel: Boolean = false) {
        requireOpen()
        startAdvertisingInternal(includeTxPowerLevel)
    }

    fun stopAdvertising() {
        stopAdvertisingInternal(BleReasons.USER_CANCELLED)
    }

    private fun startAdvertisingInternal(includeTxPowerLevel: Boolean) {
        requireOpen()
        if (advertising.get()) return
        advertiseAttempted.set(true)
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val le = manager?.adapter?.bluetoothLeAdvertiser
        if (le == null) {
            advertising.set(false)
            dispatch { callback.onAdvertisingFailed(FROZEN_CAPABILITY_UNAVAILABLE, "device has no BLE advertiser") }
            return
        }
        advertiser = le
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(includeTxPowerLevel)
            .addServiceUuid(ParcelUuid(GattUuids.SERVICE))
            .build()
        try {
            le.startAdvertising(settings, data, advertiseCallback)
        } catch (se: SecurityException) {
            advertising.set(false)
            dispatch { callback.onAdvertisingFailed(FROZEN_PERMISSION_DENIED, "startAdvertising: ${se.message}") }
        }
    }

    private fun stopAdvertisingInternal(reason: String) {
        val le = advertiser
        if (le != null && advertiseAttempted.get()) {
            try {
                le.stopAdvertising(advertiseCallback)
            } catch (t: Throwable) {
                // Best effort: the radio may already be down.
            }
        }
        advertiseAttempted.set(false)
        if (advertising.getAndSet(false)) {
            dispatch { callback.onAdvertisingStopped(reason) }
        }
    }

    /** Re-probe the permission/radio state and report it (after a prompt, say). */
    fun refreshCapability(): PermissionReport {
        val report = BlePermissions.report(appContext)
        callback.onCapabilityChanged(report)
        return report
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    /** Queue one EVENT fragment; delivered as an indication. */
    fun notifyEvent(bytes: ByteArray): Boolean {
        if (closed.get()) return false
        if (currentAddress() == null) return false
        if (!eventQueue.offer(bytes)) return false
        handler.post { drainEvents() }
        return true
    }

    /** Queue one DATA frame; delivered as a notify (no confirmation). */
    fun notifyData(bytes: ByteArray): Boolean {
        if (closed.get()) return false
        if (currentAddress() == null) return false
        if (!dataQueue.offer(bytes)) return false
        handler.post { drainEvents(); drainData() }
        return true
    }

    /** `send` = "one already-framed unit": EVENT fragments first, then DATA frames. */
    override fun send(pdu: ByteArray) {
        notifyEvent(pdu)
    }

    private fun drainEvents() {
        if (closed.get()) return
        val next = eventQueue.peek() ?: return
        if (next.size > maxOutboundPayload()) {
            dropOversized(eventQueue, EVENT_NAME)
            return
        }
        val s = synchronized(lock) { server } ?: return
        val device = subscriber.get() ?: return
        val characteristic = eventCharacteristic ?: return
        val accepted = try {
            sendNotification(s, device, characteristic, true, next)
        } catch (se: SecurityException) {
            callback.onError(FROZEN_PERMISSION_DENIED, "indicate: ${se.message}")
            return
        } catch (t: Throwable) {
            callback.onError("TRANSPORT_WRITE_FAILED", "indicate: ${t.message}")
            return
        }
        if (accepted) {
            eventQueue.poll()
            indicationsSent.incrementAndGet()
        } else {
            scheduleRetry()
        }
    }

    private fun drainData() {
        if (closed.get()) return
        val s = synchronized(lock) { server } ?: return
        val device = subscriber.get() ?: return
        val characteristic = dataCharacteristic ?: return
        while (!closed.get()) {
            val next = dataQueue.peek() ?: return
            if (next.size > maxOutboundPayload()) {
                dropOversized(dataQueue, DATA_NAME)
                continue
            }
            val accepted = try {
                sendNotification(s, device, characteristic, false, next)
            } catch (se: SecurityException) {
                callback.onError(FROZEN_PERMISSION_DENIED, "notify: ${se.message}")
                return
            } catch (t: Throwable) {
                callback.onError("TRANSPORT_WRITE_FAILED", "notify: ${t.message}")
                return
            }
            if (!accepted) {
                scheduleRetry()
                return
            }
            dataQueue.poll()
        }
    }

    /**
     * The GATT stack refused a value because its buffer was full. Retry once the
     * stack has had a chance to drain; never spin.
     */
    private fun scheduleRetry() {
        if (!retryScheduled.compareAndSet(false, true)) return
        handler.postDelayed(
            {
                retryScheduled.set(false)
                if (closed.get()) return@postDelayed
                drainEvents()
                drainData()
            },
            RETRY_DELAY_MS,
        )
    }

    // -----------------------------------------------------------------------
    // Inbound (GATT server callbacks)
    // -----------------------------------------------------------------------

    private fun handleCommandWrite(
        device: BluetoothDevice,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?,
    ) {
        if (!GattUuids.isCommand(characteristic.uuid)) {
            if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, null)
            return
        }
        // Fragments are ATT-write independent; long/prepared writes are unsupported.
        if (preparedWrite || offset != 0) {
            if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, null)
            return
        }
        if (value == null || value.isEmpty() || value.size > Bounds.MAX_ATT_PAYLOAD) {
            if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, null)
            return
        }
        if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_SUCCESS, null)
        val handlerFn = onCommandWrite
        if (handlerFn != null) {
            try {
                handlerFn(value)
            } catch (e: ProtocolError) {
                callback.onError(e.errorName, e.detail)
            } catch (t: Throwable) {
                callback.onError("INTERNAL_ERROR", t.message)
            }
        }
    }

    private fun handleDescriptorWrite(
        device: BluetoothDevice,
        requestId: Int,
        descriptor: BluetoothGattDescriptor,
        responseNeeded: Boolean,
        value: ByteArray?,
    ) {
        if (!GattUuids.isCccd(descriptor.uuid)) {
            if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, null)
            return
        }
        if (responseNeeded) respond(device, requestId, BluetoothGatt.GATT_SUCCESS, null)
        val enable = value != null && value.isNotEmpty() && value[0].toInt() != 0
        if (!enable) return
        val characteristic = descriptor.characteristic ?: return
        if (!GattUuids.isEvent(characteristic.uuid) && !GattUuids.isData(characteristic.uuid)) return
        val existing = subscriber.get()
        if (existing != null && existing.address != device.address) {
            // One receiver at a time; the service stays open but the link is not trusted.
            callback.onSubscriberLimitReached(device.address)
            return
        }
        subscriber.set(device)
        callback.onSubscribed(device.address)
    }

    private fun respond(device: BluetoothDevice, requestId: Int, status: Int, value: ByteArray?) {
        val s = synchronized(lock) { server } ?: return
        try {
            s.sendResponse(device, requestId, status, 0, value)
        } catch (t: Throwable) {
            // The link may have dropped between request and response.
        }
    }

    /**
     * Send one notification/indication. The memory-safe
     * `notifyCharacteristicChanged(device, characteristic, confirm, value)`
     * exists only on API 33+; below it the caller must preload the value.
     */
    private fun sendNotification(
        server: BluetoothGattServer,
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        confirm: Boolean,
        value: ByteArray,
    ): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        server.notifyCharacteristicChanged(device, characteristic, confirm, value) == BluetoothStatusCodes.SUCCESS
    } else {
        @Suppress("DEPRECATION")
        characteristic.value = value
        @Suppress("DEPRECATION")
        server.notifyCharacteristicChanged(device, characteristic, confirm)
    }

    /** Drop one already-dequeued item that the negotiated MTU cannot carry, and signal. */
    private fun dropOversized(queue: BoundedQueue, name: String) {
        queue.poll()
        callback.onQueueOverflow(name, queueCapacity)
    }

    /** Largest value the negotiated MTU can carry on this link. */
    private fun maxOutboundPayload(): Int = BleDiagnostics.attPayloadMax(subscriberMtu.get())

    // -----------------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------------

    /** Stop advertising, unregister the server callback, close the server. Idempotent. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        stopAdvertisingInternal(BleReasons.APP_SHUTDOWN)
        eventQueue.clear()
        dataQueue.clear()
        subscriber.set(null)
        subscriberMtu.set(DEFAULT_ATT_MTU)
        val s = synchronized(lock) {
            val current = server
            server = null
            current
        }
        if (s != null) {
            try {
                s.clearServices()
            } catch (t: Throwable) {
                // Device may already be gone.
            }
            try {
                s.close()
            } catch (t: Throwable) {
                // Device may already be gone.
            }
        }
        server = null
        advertiser = null
        commandCharacteristic = null
        eventCharacteristic = null
        dataCharacteristic = null
        onCommandWrite = null
        handler.removeCallbacksAndMessages(null)
        thread.quitSafely()
    }

    // -----------------------------------------------------------------------
    // Introspection
    // -----------------------------------------------------------------------

    fun queueDepth(characteristic: String): Int = when (characteristic) {
        EVENT_NAME -> eventQueue.size
        DATA_NAME -> dataQueue.size
        else -> 0
    }

    fun droppedCount(characteristic: String): Int = when (characteristic) {
        EVENT_NAME -> eventQueue.droppedCount
        DATA_NAME -> dataQueue.droppedCount
        else -> 0
    }

    val indicationsSentCount: Int get() = indicationsSent.get()

    /** ATT MTU as last reported by the subscribed central. */
    val negotiatedAttMtu: Int get() = subscriberMtu.get()

    fun permissionReport(): PermissionReport = BlePermissions.report(appContext)

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private fun requireOpen() {
        if (closed.get()) throw ProtocolError("SESSION_TORN_DOWN", "server session closed")
    }

    private fun requireRolePermission() {
        val failure = BlePermissions.preconditionFailure(appContext, BlePermissions.Role.MERCHANT) ?: return
        throw ProtocolError(failure, "peripheral precondition failed")
    }

    private fun currentAddress(): String? = subscriber.get()?.address

    private fun dispatch(action: () -> Unit) {
        if (closed.get()) return
        if (Handler.myLooper() == handler.looper) {
            action()
        } else {
            handler.post {
                if (!closed.get()) action()
            }
        }
    }

    companion object {
        const val DEFAULT_QUEUE_CAPACITY = 64
        const val DEFAULT_ATT_MTU = 23
        const val THREAD_NAME = "deceipt-ble-peripheral"
        const val EVENT_NAME = "event"
        const val DATA_NAME = "data"
        const val RETRY_DELAY_MS = 20L

        /** Frozen capability error surfaced when advertising is unsupported. */
        const val FROZEN_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"

        /** Frozen permission error name. */
        const val FROZEN_PERMISSION_DENIED = "TRANSPORT_PERMISSION_DENIED"

        /** Map an `AdvertiseCallback` error code to a stable diagnostic string. */
        fun advertiseFailureDetail(errorCode: Int): String = when (errorCode) {
            AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE -> "ADVERTISE_FAILED_DATA_TOO_LARGE"
            AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> "ADVERTISE_FAILED_TOO_MANY_ADVERTISERS"
            AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> "ADVERTISE_FAILED_ALREADY_STARTED"
            AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR -> "ADVERTISE_FAILED_INTERNAL_ERROR"
            AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> "ADVERTISE_FAILED_FEATURE_UNSUPPORTED"
            else -> "ADVERTISE_FAILED_UNKNOWN($errorCode)"
        }
    }
}
