package com.deceipt.adapter.ble

import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.session.SessionTransport
import java.util.ArrayDeque
import java.util.concurrent.locks.ReentrantLock

/** `PermissionReport` lives on [BlePermissions]; this is its package-level name. */
typealias PermissionReport = BlePermissions.PermissionReport

/**
 * Shared BLE transport surface (A5). Everything the session layer needs to talk
 * to the radio, expressed without `android.bluetooth` so the protocol/state
 * machine path stays JVM-testable.
 *
 * Design shape (solutionSpace): ONE callback interface + ONE link interface,
 * with the transport role selected by construction (`BleRole`). GATT callbacks
 * are marshalled onto a single `HandlerThread` by the platform classes; the
 * engine above this seam never sees a radio thread.
 *
 * LPDU reassembly for the control characteristics lives inside the platform
 * session classes, so exactly ONE `onCommandPdu` / `onEventPdu` is delivered per
 * logical protocol message — never one call per GATT fragment. DATA frames are
 * delivered one GATT notification at a time, because the sliding window
 * (`Frame.Receiver`) is defined over frames, not over reassembled transfers.
 *
 * RSSI may appear ONLY in a field named `rssiDiagnosticsOnly` and is never an
 * input to selection, ordering, association, connect target, or trust.
 */
enum class BleRole { MERCHANT, CUSTOMER }

/**
 * Negotiated link budget. `frameSizeCeiling` is derived from the reported ATT
 * MTU and is NEVER a fixed MTU (wire.md 5):
 * `max_frame_payload_for_mtu(m) = min(min(m - 3, 512) - 20, 512)`.
 */
data class MtuInfo(val attMtu: Int, val frameSizeCeiling: Int)

/** The seam the session engine drives (mirrors `SessionTransport`). */
interface BleLink {
    /** Send one already-framed unit: an LPDU fragment, or a DATA frame. */
    fun send(pdu: ByteArray)

    /** Idempotent teardown: stop advertising/scanning, unregister, no stale callbacks. */
    fun close()
}

/** Derives link budgets from an ATT MTU without touching the radio. */
object BleDiagnostics {

    /** ATT payload usable by a write/indication: `min(m - 3, 512)`. */
    fun attPayloadMax(attMtu: Int): Int = Bounds.attPayloadMax(attMtu)

    /** Frame-size ceiling for [attMtu] (never a fixed MTU). */
    fun frameSizeCeiling(attMtu: Int): Int = Bounds.maxFramePayloadForMtu(attMtu)

    fun mtuInfo(attMtu: Int): MtuInfo = MtuInfo(attMtu, frameSizeCeiling(attMtu))

    /** The usable MTU floor: below this no legal DATA frame exists. */
    const val MIN_USABLE_ATT_MTU: Int = Bounds.MIN_FRAME_PAYLOAD + Bounds.DATAFRAME_HEADER_BYTES + 3

    fun isUsable(attMtu: Int): Boolean = frameSizeCeiling(attMtu) >= Bounds.MIN_FRAME_PAYLOAD
}

/**
 * Inbound transport callbacks. Inbound CONTROL arrives reassembled; inbound DATA
 * arrives one frame per GATT notification.
 */
interface Callback {
    /** One reassembled control PDU from COMMAND (merchant side). */
    fun onCommandPdu(pdu: ByteArray) {}

    /** One reassembled control PDU from EVENT (customer side). */
    fun onEventPdu(pdu: ByteArray) {}

    /** One DATA frame from a single notify/indication. */
    fun onDataFrame(frame: ByteArray) {}

    /** The link is usable and the MTU is known. */
    fun onLinkUp(mtu: MtuInfo) {}

    /** The negotiated ATT MTU changed. Frame size is recomputed, never assumed. */
    fun onMtuChanged(mtu: MtuInfo) {}

    /** The link ended. `reason` is a `TeardownReason` string (see [BleReasons]). */
    fun onLinkDown(reason: String) {}

    /** A typed failure. `errorName` is a frozen name from `protocol.Errors`. */
    fun onError(errorName: String, detail: String? = null) {}
}

/** Merchant (peripheral / GATT server) callbacks. */
interface PeripheralCallback : Callback {
    /** Advertising is live; the service UUID is on the air, nothing else. */
    fun onAdvertisingStarted() {}

    fun onAdvertisingStopped(reason: String) {}

    /**
     * Advertising could not start (device-dependent on Android). This is an
     * explicit capability failure, never a crash.
     */
    fun onAdvertisingFailed(errorName: String, detail: String?) {}

    /** A central subscribed to EVENT; the service is nevertheless open/untrusted. */
    fun onSubscribed(centralId: String) {}

    /** The merchant is serving exactly one receiver; further centrals are ignored. */
    fun onSubscriberLimitReached(centralId: String) {}

    /** A runtime permission / Bluetooth state change was observed. */
    fun onCapabilityChanged(report: PermissionReport) {}

    /** An outbound queue hit its cap: the item was DROPPED, never queued unbounded. */
    fun onQueueOverflow(characteristic: String, capacity: Int) {}
}

/** Customer (central / GATT client) callbacks. */
interface CentralCallback : Callback {
    fun onScanStarted() {}

    fun onScanStopped(reason: String) {}

    /** A candidate advertising the Deceipt service UUID. RSSI is diagnostics only. */
    fun onCandidate(peripheralId: String, rssiDiagnosticsOnly: Int) {}

    fun onCandidateLost(peripheralId: String) {}

    fun onServicesDiscovered(peripheralId: String) {}

    override fun onMtuChanged(mtu: MtuInfo) {}

    /** EVENT + DATA notifications are enabled on the target peripheral. */
    fun onNotificationsEnabled() {}

    /** One command fragment was accepted by the peer (write-with-response). */
    fun onWriteComplete() {}

    fun onCapabilityChanged(report: PermissionReport) {}

    fun onQueueOverflow(characteristic: String, capacity: Int) {}
}

/**
 * Frozen reason strings. The first six overlap `TeardownReason` in the shared
 * contract (`app/src/native/DeceiptNative.ts`); the rest are transport-internal
 * and are mapped by the module layer.
 */
object BleReasons {
    const val LINK_LOST = "link_lost"
    const val USER_CANCELLED = "user_cancelled"
    const val PERMISSION_DENIED = "permission_denied"
    const val BLUETOOTH_OFF = "bluetooth_off"
    const val APP_SHUTDOWN = "app_shutdown"
    const val PEER_ERROR = "peer_error"
    const val COMPLETED = "completed"

    /** Transport-internal (not in `TeardownReason`); mapped by the caller. */
    const val CONNECT_FAILED = "connect_failed"
    const val CONNECT_TIMEOUT = "connect_timeout"
    const val CAPABILITY_UNAVAILABLE = "capability_unavailable"
    const val SUBSCRIBER_LIMIT = "subscriber_limit"
}

/**
 * A bounded FIFO. `offer` refuses (and signals) rather than growing without
 * limit; the peer never controls capacity or item size.
 */
internal class BoundedQueue(
    private val name: String,
    private val capacity: Int,
    private val onOverflow: (name: String, capacity: Int) -> Unit,
) {
    private val lock = ReentrantLock()
    private val items = ArrayDeque<ByteArray>()
    private var dropped = 0

    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    fun offer(item: ByteArray): Boolean {
        lock.lock()
        val accepted: Boolean
        try {
            if (items.size >= capacity) {
                dropped += 1
                accepted = false
            } else {
                items.addLast(item)
                accepted = true
            }
        } finally {
            lock.unlock()
        }
        if (!accepted) onOverflow(name, capacity)
        return accepted
    }

    fun peek(): ByteArray? {
        lock.lock()
        try {
            return items.peekFirst()
        } finally {
            lock.unlock()
        }
    }

    fun poll(): ByteArray? {
        lock.lock()
        try {
            return items.pollFirst()
        } finally {
            lock.unlock()
        }
    }

    val size: Int
        get() {
            lock.lock()
            try {
                return items.size
            } finally {
                lock.unlock()
            }
        }

    val droppedCount: Int
        get() {
            lock.lock()
            try {
                return dropped
            } finally {
                lock.unlock()
            }
        }

    fun clear() {
        lock.lock()
        try {
            items.clear()
        } finally {
            lock.unlock()
        }
    }
}

/**
 * Merchant adapter: the `SessionTransport` seam backed by [GattServerSession].
 *
 * `sendEvent` carries LPdu fragments (indicate), `sendDataFrame` DATA frames
 * (notify). `sendCommand` is never used on the peripheral role; a stray call is
 * dropped rather than silently mis-routed. `frameSizeCeiling` and `close`
 * delegate to the server session.
 */
class BlePeripheralTransport(private val session: GattServerSession) : SessionTransport {

    override fun sendEvent(pdu: ByteArray) {
        session.notifyEvent(pdu)
    }

    override fun sendDataFrame(frame: ByteArray) {
        session.notifyData(frame)
    }

    override fun sendCommand(pdu: ByteArray) {
        // B→A COMMAND never originates at the merchant (wire.md 2).
    }

    override fun frameSizeCeiling(): Int =
        BleDiagnostics.frameSizeCeiling(session.negotiatedAttMtu)

    override fun close() {
        session.close()
    }
}

/**
 * Customer adapter: the `SessionTransport` seam backed by [GattClientSession].
 *
 * `sendCommand` carries LPdu fragments (write with response). `sendEvent` and
 * `sendDataFrame` are never used on the central role (A→B); stray calls are
 * dropped rather than silently mis-routed.
 */
class BleCentralTransport(private val session: GattClientSession) : SessionTransport {

    override fun sendEvent(pdu: ByteArray) {
        // A→B EVENT never originates at the customer (wire.md 2).
    }

    override fun sendDataFrame(frame: ByteArray) {
        // A→B DATA never originates at the customer (wire.md 2).
    }

    override fun sendCommand(pdu: ByteArray) {
        session.writeCommand(pdu)
    }

    override fun frameSizeCeiling(): Int = session.frameSizeCeiling

    override fun close() {
        session.close()
    }
}
