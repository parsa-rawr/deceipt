package com.deceipt.adapter.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelUuid
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.Lpdu
import com.deceipt.adapter.protocol.ProtocolError
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Customer side: GATT client + scanner (central). `wire.md` 1.
 *
 *  * `startScan` filters on the Deceipt Transfer Service UUID. A candidate is
 *    reported with the peripheral id and `rssiDiagnosticsOnly`; RSSI is NEVER an
 *    input to selection, ordering, association or the connect target.
 *  * `connect` targets EXACTLY ONE given peripheral id and never re-targets. A
 *    second connect for a different id fails closed with
 *    `TRANSPORT_PEER_AMBIGUOUS`.
 *  * Connect → discover the service → `setMtu(517)` → `onMtuChanged` →
 *    enable EVENT (indicate) + DATA (notify) notifications → `writeCommand`.
 *    The whole sequence is bounded by `T_CONNECT` (`Bounds.TIMEOUTS_MS`), after
 *    which the link fails with `TRANSPORT_CONNECT_TIMEOUT`.
 *  * If the reported ATT MTU cannot carry a legal frame, the link fails with
 *    `TRANSPORT_MTU_TOO_SMALL` rather than negotiating a zero frame size.
 *  * Outbound COMMAND fragments go through a bounded (default 64) queue drained
 *    one write-with-response at a time; a full queue DROPS and signals.
 *
 * Threading: one `HandlerThread`; every GATT/scan callback is marshalled onto it.
 * `close()` flips an `AtomicBoolean`, cancels the timeout, stops the scan,
 * unregisters the GATT callback and disconnects — no stale callbacks.
 */
class GattClientSession(
    context: Context,
    private val callback: CentralCallback,
    private val queueCapacity: Int = DEFAULT_QUEUE_CAPACITY,
) : BleLink {

    private val appContext: Context = context.applicationContext
    private val thread = HandlerThread(THREAD_NAME).apply { start() }
    private val handler = Handler(thread.looper)
    private val closed = AtomicBoolean(false)

    private val commandQueue = BoundedQueue(COMMAND_NAME, queueCapacity) { n, c -> callback.onQueueOverflow(n, c) }

    private val scanning = AtomicBoolean(false)
    private val notificationsEnabled = AtomicBoolean(false)
    private val pendingDescriptors = AtomicInteger(0)
    private val writeInFlight = AtomicBoolean(false)
    private val retryScheduled = AtomicBoolean(false)
    private val linkUp = AtomicBoolean(false)
    private val connectPending = AtomicBoolean(false)

    private val target = AtomicReference<BluetoothDevice?>(null)
    private val targetId = AtomicReference<String?>(null)
    private val discovered = java.util.concurrent.ConcurrentHashMap<String, BluetoothDevice>()
    private val attMtu = AtomicInteger(MIN_ATT_MTU)

    private val commandReassembler = Lpdu.Reassembler()
    private val eventReassembler = Lpdu.Reassembler()

    /** Rebuilt on every scan so a different service UUID can be requested. */
    private val scanServiceUuid = AtomicReference<UUID>(GattUuids.SERVICE)

    /** Per-scan candidate sink; when null the `CentralCallback.onCandidate` is used. */
    private val candidateSink = AtomicReference<((String, Int) -> Unit)?>(null)

    private val timeout = Runnable {
        if (closed.get()) return@Runnable
        fail("TRANSPORT_CONNECT_TIMEOUT", "no link within T_CONNECT")
        teardownLink(BleReasons.CONNECT_TIMEOUT)
    }

    private val lock = Any()

    @Volatile
    private var scanner: BluetoothLeScanner? = null

    @Volatile
    private var gatt: BluetoothGatt? = null

    @Volatile
    private var commandCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var eventCharacteristic: BluetoothGattCharacteristic? = null

    @Volatile
    private var dataCharacteristic: BluetoothGattCharacteristic? = null

    private val scanCallback = object : ScanCallback() {

        override fun onScanResult(callbackType: Int, result: ScanResult) {
            dispatch { handleScanResult(result) }
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            for (r in results) dispatch { handleScanResult(r) }
        }

        override fun onScanFailed(errorCode: Int) {
            if (closed.get()) return
            scanning.set(false)
            if (errorCode == ScanCallback.SCAN_FAILED_ALREADY_STARTED) {
                scanning.set(true)
                return
            }
            val name = if (scanFailureIsCapability(errorCode)) FROZEN_CAPABILITY_UNAVAILABLE else "TRANSPORT_LINK_LOST"
            dispatch { callback.onError(name, scanFailureDetail(errorCode)) }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            dispatch { handleConnectionStateChange(gatt, status, newState) }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            dispatch { handleServicesDiscovered(gatt, status) }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            dispatch { handleMtuChanged(gatt, mtu, status) }
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            dispatch { handleDescriptorWrite(status) }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            dispatch { handleCharacteristicWrite(characteristic, status) }
        }

        @Deprecated("Deprecated in Java")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION")
            val value = characteristic.value
            dispatch { handleCharacteristicChanged(characteristic.uuid, value) }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            dispatch { handleCharacteristicChanged(characteristic.uuid, value) }
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    val role: BleRole get() = BleRole.CUSTOMER

    val isClosed: Boolean get() = closed.get()

    val isScanning: Boolean get() = scanning.get()

    /** The one peripheral this session may ever connect to, or null before `connect`. */
    val peripheralId: String? get() = targetId.get()

    val isConnected: Boolean get() = gatt != null && target.get() != null && linkUp.get()

    val areNotificationsEnabled: Boolean get() = notificationsEnabled.get()

    val negotiatedAttMtu: Int get() = attMtu.get()

    /** Frame-size ceiling for the negotiated MTU (never a fixed MTU). */
    val frameSizeCeiling: Int get() = BleDiagnostics.frameSizeCeiling(attMtu.get())

    /**
     * Begin a scan filtered on [serviceUuid]. Candidates are delivered to
     * [onCandidate] when supplied, otherwise to `CentralCallback.onCandidate`.
     * No ordering, no ranking, never by RSSI.
     *
     * @return true when the scan was started.
     */
    fun startScan(
        serviceUuid: UUID = GattUuids.SERVICE,
        onCandidate: ((peripheralId: String, rssiDiagnosticsOnly: Int) -> Unit)? = null,
    ): Boolean {
        requireOpen()
        requireRolePermission()
        scanServiceUuid.set(serviceUuid)
        candidateSink.set(onCandidate)
        if (scanning.get()) return true
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter: BluetoothAdapter? = manager?.adapter
        val le: BluetoothLeScanner? = try {
            adapter?.bluetoothLeScanner
        } catch (se: SecurityException) {
            null
        }
        if (adapter == null || le == null) {
            fail(FROZEN_CAPABILITY_UNAVAILABLE, "no BLE scanner on this device")
            return false
        }
        scanner = le
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(serviceUuid))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        return try {
            le.startScan(listOf(filter), settings, scanCallback)
            scanning.set(true)
            callback.onScanStarted()
            true
        } catch (se: SecurityException) {
            fail(FROZEN_PERMISSION_DENIED, "startScan: ${se.message}")
            false
        }
    }

    fun stopScan(reason: String = BleReasons.USER_CANCELLED) {
        stopScanInternal(reason, notify = true)
    }

    private fun stopScanInternal(reason: String, notify: Boolean) {
        val le = scanner
        val wasScanning = scanning.getAndSet(false)
        if (le != null && wasScanning) {
            try {
                le.stopScan(scanCallback)
            } catch (t: Throwable) {
                // Best effort.
            }
        }
        if (wasScanning && notify && !closed.get()) callback.onScanStopped(reason)
    }

    /**
     * Connect to EXACTLY [peripheralId]. Never re-targets: a second connect to a
     * different id fails closed. The whole discovery/MTU/notification sequence
     * is bounded by `T_CONNECT`.
     */
    fun connect(context: Context, peripheralId: String) {
        requireOpen()
        requireRolePermission()
        val currentTarget = targetId.get()
        if (currentTarget != null && currentTarget != peripheralId) {
            throw ProtocolError("TRANSPORT_PEER_AMBIGUOUS", "already targeting $currentTarget; refusing to re-target")
        }
        if (currentTarget == peripheralId && (gatt != null || connectPending.get())) return

        val device = resolveDevice(peripheralId) ?: throw ProtocolError("TRANSPORT_LINK_LOST", "unknown peripheral id")
        stopScan(BleReasons.USER_CANCELLED)
        target.set(device)
        targetId.set(peripheralId)
        connectPending.set(true)
        val connected = try {
            val active = context.applicationContext
            device.connectGatt(active, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        } catch (se: SecurityException) {
            clearTarget()
            throw ProtocolError(FROZEN_PERMISSION_DENIED, "connectGatt: ${se.message}")
        } catch (t: Throwable) {
            clearTarget()
            throw ProtocolError("TRANSPORT_LINK_LOST", "connectGatt: ${t.message}")
        }
        if (connected == null) {
            clearTarget()
            throw ProtocolError("TRANSPORT_LINK_LOST", "connectGatt returned null")
        }
        synchronized(lock) { gatt = connected }
        handler.removeCallbacks(timeout)
        handler.postDelayed(timeout, Bounds.TIMEOUTS_MS["T_CONNECT"] ?: DEFAULT_CONNECT_TIMEOUT_MS)
    }

    /** Explicitly disconnect the single target (reports `link_lost`). */
    fun disconnect(reason: String = BleReasons.USER_CANCELLED) {
        teardownLink(reason)
    }

    /**
     * Request the ATT MTU. 517 is the ceiling the transfer path wants; the
     * peer may grant less and the reported value governs.
     *
     * @return true when the request was accepted by the stack.
     */
    fun setMtu(attMtu: Int = TARGET_ATT_MTU): Boolean {
        requireOpen()
        val g = synchronized(lock) { gatt } ?: return false
        if (attMtu < MIN_ATT_MTU) throw ProtocolError("TRANSPORT_MTU_TOO_SMALL", "requested mtu below 23")
        return try {
            g.requestMtu(attMtu)
        } catch (se: SecurityException) {
            fail(FROZEN_PERMISSION_DENIED, "requestMtu: ${se.message}")
            false
        } catch (t: Throwable) {
            fail("TRANSPORT_LINK_LOST", "requestMtu: ${t.message}")
            false
        }
    }

    /**
     * Enable EVENT (indicate) and DATA (notify) notifications on the target.
     *
     * @return true when both descriptor writes were issued.
     */
    fun enableNotifications(): Boolean {
        requireOpen()
        val g = synchronized(lock) { gatt } ?: return false
        val event = eventCharacteristic ?: return false
        val data = dataCharacteristic ?: return false
        if (notificationsEnabled.get()) return true
        val eventCccd = event.getDescriptor(GattUuids.CCCD)
        val dataCccd = data.getDescriptor(GattUuids.CCCD)
        if (eventCccd == null || dataCccd == null) {
            fail("TRANSPORT_LINK_LOST", "peer characteristic has no CCCD descriptor")
            return false
        }
        return try {
            pendingDescriptors.set(2)
            if (!g.setCharacteristicNotification(event, true) || !g.setCharacteristicNotification(data, true)) {
                pendingDescriptors.set(0)
                fail("TRANSPORT_LINK_LOST", "setCharacteristicNotification rejected")
                return false
            }
            writeCccd(g, eventCccd, BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
            writeCccd(g, dataCccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            true
        } catch (se: SecurityException) {
            pendingDescriptors.set(0)
            fail(FROZEN_PERMISSION_DENIED, "enableNotifications: ${se.message}")
            false
        } catch (t: Throwable) {
            pendingDescriptors.set(0)
            fail("TRANSPORT_LINK_LOST", "enableNotifications: ${t.message}")
            false
        }
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    /**
     * Queue one COMMAND fragment (an LPdu fragment, or one AEAD control
     * envelope already framed). Write-with-response, one at a time.
     *
     * @return true when the fragment was accepted by the bounded queue.
     */
    fun writeCommand(fragment: ByteArray): Boolean {
        if (closed.get()) return false
        if (fragment.isEmpty()) return false
        if (fragment.size > Bounds.MAX_ATT_PAYLOAD) {
            throw ProtocolError("MESSAGE_TOO_LARGE", "command fragment above ${Bounds.MAX_ATT_PAYLOAD} bytes")
        }
        if (!commandQueue.offer(fragment)) return false
        handler.post { flushCommands() }
        return true
    }

    /** Queue every fragment in order. @return the number accepted. */
    fun writeCommand(fragments: List<ByteArray>): Int {
        var accepted = 0
        for (f in fragments) {
            if (!writeCommand(f)) break
            accepted += 1
        }
        return accepted
    }

    /** `send` = "one already-framed unit": COMMAND fragments only (B→A). */
    override fun send(pdu: ByteArray) {
        writeCommand(pdu)
    }

    private fun flushCommands() {
        if (closed.get()) return
        if (!notificationsEnabled.get()) return
        if (writeInFlight.get()) return
        val next = commandQueue.peek() ?: return
        val g = synchronized(lock) { gatt } ?: return
        val characteristic = commandCharacteristic ?: return
        val payloadMax = BleDiagnostics.attPayloadMax(attMtu.get())
        if (next.size > payloadMax) {
            commandQueue.poll()
            callback.onError("TRANSPORT_MTU_TOO_SMALL", "fragment ${next.size}B above att_payload_max=$payloadMax")
            return
        }
        val accepted = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                g.writeCharacteristic(characteristic, next, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothGatt.GATT_SUCCESS
            } else {
                @Suppress("DEPRECATION")
                characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                @Suppress("DEPRECATION")
                characteristic.value = next
                @Suppress("DEPRECATION")
                g.writeCharacteristic(characteristic)
            }
        } catch (se: SecurityException) {
            fail(FROZEN_PERMISSION_DENIED, "writeCharacteristic: ${se.message}")
            return
        } catch (t: Throwable) {
            fail("TRANSPORT_WRITE_FAILED", "writeCharacteristic: ${t.message}")
            return
        }
        if (accepted) {
            writeInFlight.set(true)
        } else {
            scheduleRetry()
        }
    }

    private fun scheduleRetry() {
        if (!retryScheduled.compareAndSet(false, true)) return
        handler.postDelayed(
            {
                retryScheduled.set(false)
                if (closed.get()) return@postDelayed
                flushCommands()
            },
            RETRY_DELAY_MS,
        )
    }

    // -----------------------------------------------------------------------
    // Inbound (scan + GATT callbacks)
    // -----------------------------------------------------------------------

    private fun handleScanResult(result: ScanResult) {
        if (closed.get()) return
        val device = result.device ?: return
        discovered[device.address] = device
        val requested = scanServiceUuid.get()
        val record = result.scanRecord
        val advertised = record?.serviceUuids
        if (advertised != null && advertised.isNotEmpty() && advertised.none { it.uuid == requested }) return
        val sink = candidateSink.get()
        if (sink != null) {
            sink.invoke(device.address, result.rssi)
        } else {
            callback.onCandidate(device.address, result.rssi)
        }
    }

    private fun handleConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
        if (closed.get()) return
        val expected = target.get()
        if (expected == null || g.device.address != expected.address) {
            // Never adopt a link we did not ask for.
            closeGatt(g)
            return
        }
        when (newState) {
            BluetoothProfile.STATE_CONNECTED -> {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    fail("TRANSPORT_LINK_LOST", "connect status=$status")
                    teardownLink(BleReasons.CONNECT_FAILED)
                    return
                }
                try {
                    g.discoverServices()
                } catch (se: SecurityException) {
                    fail(FROZEN_PERMISSION_DENIED, "discoverServices: ${se.message}")
                    teardownLink(BleReasons.PERMISSION_DENIED)
                } catch (t: Throwable) {
                    fail("TRANSPORT_LINK_LOST", "discoverServices: ${t.message}")
                    teardownLink(BleReasons.LINK_LOST)
                }
            }

            BluetoothProfile.STATE_DISCONNECTED -> {
                val wasPending = connectPending.getAndSet(false)
                teardownLink(if (wasPending && !linkUp.get()) BleReasons.CONNECT_FAILED else BleReasons.LINK_LOST)
                if (status != BluetoothGatt.GATT_SUCCESS && !wasPending) {
                    fail("TRANSPORT_LINK_LOST", "gatt disconnect status=$status")
                }
            }

            else -> Unit
        }
    }

    private fun handleServicesDiscovered(g: BluetoothGatt, status: Int) {
        if (closed.get()) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("TRANSPORT_LINK_LOST", "service discovery status=$status")
            teardownLink(BleReasons.LINK_LOST)
            return
        }
        val services: List<BluetoothGattService> = try {
            g.services ?: emptyList()
        } catch (t: Throwable) {
            emptyList()
        }
        val service = services.firstOrNull { it.uuid == scanServiceUuid.get() || it.uuid == GattUuids.SERVICE }
        if (service == null) {
            fail("TRANSPORT_LINK_LOST", "peer does not expose the Deceipt Transfer Service")
            teardownLink(BleReasons.LINK_LOST)
            return
        }
        val chars: List<BluetoothGattCharacteristic> = try {
            service.characteristics ?: emptyList()
        } catch (t: Throwable) {
            emptyList()
        }
        val command = chars.firstOrNull { GattUuids.isCommand(it.uuid) }
        val event = chars.firstOrNull { GattUuids.isEvent(it.uuid) }
        val data = chars.firstOrNull { GattUuids.isData(it.uuid) }
        if (command == null || event == null || data == null) {
            fail("TRANSPORT_LINK_LOST", "peer service is missing COMMAND/EVENT/DATA")
            teardownLink(BleReasons.LINK_LOST)
            return
        }
        commandCharacteristic = command
        eventCharacteristic = event
        dataCharacteristic = data
        callback.onServicesDiscovered(g.device.address)
        // setMtu -> onMtuChanged -> enableNotifications -> writeCommand
        if (!setMtu(TARGET_ATT_MTU)) {
            // The stack refused the request; proceed with the current MTU.
            onLinkEstablished(attMtu.get())
        }
    }

    private fun handleMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
        if (closed.get()) return
        val expected = target.get()
        if (expected == null || g.device.address != expected.address) return
        if (status == BluetoothGatt.GATT_SUCCESS && mtu > 0) {
            attMtu.set(mtu)
        }
        // A peer-initiated MTU change can arrive before service discovery; only a
        // change with the characteristics in hand completes the ordered link
        // sequence (setMtu -> onMtuChanged -> enableNotifications -> writeCommand).
        if (commandCharacteristic == null || eventCharacteristic == null || dataCharacteristic == null) return
        onLinkEstablished(attMtu.get())
    }

    private fun onLinkEstablished(mtu: Int) {
        if (closed.get()) return
        // Idempotent: a peer-initiated MTU change after the link is up must not
        // re-run notification enabling or re-emit the connected event.
        if (linkUp.get()) return
        if (!BleDiagnostics.isUsable(mtu)) {
            fail("TRANSPORT_MTU_TOO_SMALL", "att_mtu=$mtu yields frame_size=${BleDiagnostics.frameSizeCeiling(mtu)}")
            teardownLink(BleReasons.LINK_LOST)
            return
        }
        connectPending.set(false)
        handler.removeCallbacks(timeout)
        val info = BleDiagnostics.mtuInfo(mtu)
        callback.onMtuChanged(info)
        if (enableNotifications()) {
            if (!linkUp.getAndSet(true)) callback.onLinkUp(info)
        } else {
            teardownLink(BleReasons.LINK_LOST)
        }
    }

    private fun handleDescriptorWrite(status: Int) {
        if (closed.get()) return
        // Ignore a CCCD write we did not request (never infer subscriptions).
        if (pendingDescriptors.get() <= 0) return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("TRANSPORT_WRITE_FAILED", "CCCD write status=$status")
            return
        }
        val remaining = pendingDescriptors.decrementAndGet()
        if (remaining > 0) return
        pendingDescriptors.set(0)
        if (notificationsEnabled.getAndSet(true)) return
        callback.onNotificationsEnabled()
        // Only now may COMMAND fragments flow (the ordered link sequence).
        flushCommands()
    }

    private fun handleCharacteristicWrite(characteristic: BluetoothGattCharacteristic, status: Int) {
        if (closed.get()) return
        if (!GattUuids.isCommand(characteristic.uuid)) return
        writeInFlight.set(false)
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("TRANSPORT_WRITE_FAILED", "command write status=$status")
            return
        }
        commandQueue.poll()
        callback.onWriteComplete()
        flushCommands()
    }

    private fun handleCharacteristicChanged(characteristicUuid: UUID, value: ByteArray?) {
        if (closed.get()) return
        if (value == null || value.isEmpty()) return
        if (value.size > Bounds.MAX_ATT_PAYLOAD) {
            callback.onError("MESSAGE_TOO_LARGE", "notification of ${value.size} bytes")
            return
        }
        try {
            when {
                GattUuids.isData(characteristicUuid) -> callback.onDataFrame(value)
                GattUuids.isEvent(characteristicUuid) -> {
                    val pdu = eventReassembler.accept(value)
                    if (pdu != null) callback.onEventPdu(pdu)
                }
            }
        } catch (e: ProtocolError) {
            callback.onError(e.errorName, e.detail)
        } catch (t: Throwable) {
            callback.onError("INTERNAL_ERROR", t.message)
        }
    }

    // -----------------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------------

    /** Disconnect, unregister the GATT callback, close the client. Idempotent. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        handler.removeCallbacks(timeout)
        handler.removeCallbacksAndMessages(null)
        stopScanInternal(BleReasons.APP_SHUTDOWN, notify = false)
        scanning.set(false)
        commandQueue.clear()
        writeInFlight.set(false)
        notificationsEnabled.set(false)
        pendingDescriptors.set(0)
        linkUp.set(false)
        connectPending.set(false)
        val g = synchronized(lock) {
            val current = gatt
            gatt = null
            current
        }
        if (g != null) {
            closeGatt(g)
        }
        commandCharacteristic = null
        eventCharacteristic = null
        dataCharacteristic = null
        candidateSink.set(null)
        discovered.clear()
        commandReassembler.reset()
        eventReassembler.reset()
        target.set(null)
        targetId.set(null)
        thread.quitSafely()
    }

    // -----------------------------------------------------------------------
    // Introspection
    // -----------------------------------------------------------------------

    fun queueDepth(): Int = commandQueue.size

    fun droppedCount(): Int = commandQueue.droppedCount

    fun permissionReport(): PermissionReport = BlePermissions.report(appContext)

    /** Candidate peripheral ids seen since the last `connect`. Diagnostics only. */
    fun discoveredPeripheralIds(): List<String> = discovered.keys.toList()

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private fun requireOpen() {
        if (closed.get()) throw ProtocolError("SESSION_TORN_DOWN", "client session closed")
    }

    private fun requireRolePermission() {
        val failure = BlePermissions.preconditionFailure(appContext, BlePermissions.Role.CUSTOMER) ?: return
        throw ProtocolError(failure, "central precondition failed")
    }

    private fun resolveDevice(peripheralId: String): BluetoothDevice? {
        if (peripheralId.isBlank()) return null
        discovered[peripheralId]?.let { return it }
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = manager?.adapter ?: return null
        return try {
            adapter.getRemoteDevice(peripheralId).also { discovered[peripheralId] = it }
        } catch (t: Throwable) {
            null
        }
    }

    private fun writeCccd(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, value: ByteArray) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeDescriptor(descriptor, value)
        } else {
            @Suppress("DEPRECATION")
            descriptor.value = value
            @Suppress("DEPRECATION")
            g.writeDescriptor(descriptor)
        }
    }

    private fun teardownLink(reason: String) {
        val hadLink = linkUp.getAndSet(false) || gatt != null || connectPending.get()
        connectPending.set(false)
        notificationsEnabled.set(false)
        pendingDescriptors.set(0)
        writeInFlight.set(false)
        handler.removeCallbacks(timeout)
        val g = synchronized(lock) {
            val current = gatt
            gatt = null
            current
        }
        if (g != null) closeGatt(g)
        commandCharacteristic = null
        eventCharacteristic = null
        dataCharacteristic = null
        commandReassembler.reset()
        eventReassembler.reset()
        if (hadLink && !closed.get()) callback.onLinkDown(reason)
    }

    private fun closeGatt(g: BluetoothGatt) {
        try {
            g.disconnect()
        } catch (t: Throwable) {
            // The link may already be gone.
        }
        // `BluetoothGatt` exposes no way to unregister its callback; `close()` is
        // the documented teardown, and every callback is dropped by the `closed`
        // gate in `dispatch`, so no stale callback can reach the session above.
        try {
            g.close()
        } catch (t: Throwable) {
            // The link may already be gone.
        }
    }

    private fun clearTarget() {
        target.set(null)
        targetId.set(null)
        connectPending.set(false)
    }

    private fun fail(errorName: String, detail: String?) {
        callback.onError(errorName, detail)
    }

    private fun dispatch(action: () -> Unit) {
        if (closed.get()) return
        if (android.os.Looper.myLooper() == handler.looper) {
            action()
        } else {
            handler.post {
                if (!closed.get()) action()
            }
        }
    }

    companion object {
        const val DEFAULT_QUEUE_CAPACITY = 64
        const val MIN_ATT_MTU = 23
        const val TARGET_ATT_MTU = 517
        const val DEFAULT_CONNECT_TIMEOUT_MS = 15000L
        const val THREAD_NAME = "deceipt-ble-central"
        const val COMMAND_NAME = "command"
        const val RETRY_DELAY_MS = 20L

        /** Frozen capability error surfaced when scanning is unsupported. */
        const val FROZEN_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"

        /** Frozen permission error name. */
        const val FROZEN_PERMISSION_DENIED = "TRANSPORT_PERMISSION_DENIED"

        fun scanFailureIsCapability(errorCode: Int): Boolean = when (errorCode) {
            ScanCallback.SCAN_FAILED_FEATURE_UNSUPPORTED,
            ScanCallback.SCAN_FAILED_APPLICATION_REGISTRATION_FAILED,
            ScanCallback.SCAN_FAILED_SCANNING_TOO_FREQUENTLY,
            -> true

            else -> false
        }

        fun scanFailureDetail(errorCode: Int): String = when (errorCode) {
            ScanCallback.SCAN_FAILED_ALREADY_STARTED -> "SCAN_FAILED_ALREADY_STARTED"
            ScanCallback.SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "SCAN_FAILED_APPLICATION_REGISTRATION_FAILED"
            ScanCallback.SCAN_FAILED_FEATURE_UNSUPPORTED -> "SCAN_FAILED_FEATURE_UNSUPPORTED"
            ScanCallback.SCAN_FAILED_INTERNAL_ERROR -> "SCAN_FAILED_INTERNAL_ERROR"
            ScanCallback.SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES -> "SCAN_FAILED_OUT_OF_HARDWARE_RESOURCES"
            ScanCallback.SCAN_FAILED_SCANNING_TOO_FREQUENTLY -> "SCAN_FAILED_SCANNING_TOO_FREQUENTLY"
            else -> "SCAN_FAILED_UNKNOWN($errorCode)"
        }
    }
}
