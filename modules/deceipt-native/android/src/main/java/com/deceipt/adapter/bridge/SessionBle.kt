package com.deceipt.adapter.bridge

import android.content.Context
import com.deceipt.adapter.ble.BleDiagnostics
import com.deceipt.adapter.ble.CentralCallback
import com.deceipt.adapter.ble.GattClientSession
import com.deceipt.adapter.ble.GattServerSession
import com.deceipt.adapter.ble.MtuInfo
import com.deceipt.adapter.ble.PeripheralCallback
import com.deceipt.adapter.protocol.Bounds
import com.deceipt.adapter.protocol.ProtocolError
import com.deceipt.adapter.session.Events
import com.deceipt.adapter.session.Session
import com.deceipt.adapter.session.SessionTransport

/**
 * Binds the Android GATT objects to a protocol [Session].
 *
 * Exactly one logical object reaches the session per callback: the BLE layer
 * performs LPdu reassembly for control and delivers one DATA frame per
 * notification, so the session never sees a GATT fragment. Outbound units are
 * handed to the GATT layer one at a time and queued there under a bounded cap.
 *
 * Lifecycle: `attach(session)` completes the cycle (the session needs the
 * transport, the callbacks need the session). `close()` is idempotent and stops
 * advertising/scanning so no stale callback survives teardown.
 */
class MerchantBleSession(
    private val context: Context,
    private val emit: (Map<String, Any?>) -> Unit,
) : SessionTransport {

    private var session: Session? = null
    private val commandReassembler = com.deceipt.adapter.protocol.Lpdu.Reassembler()
    var onLinkUp: ((MtuInfo) -> Unit)? = null

    fun attach(s: Session) { session = s }

    val server: GattServerSession by lazy {
        val s = GattServerSession(context, object : PeripheralCallback {
            override fun onAdvertisingStarted() = Unit // the module owns the advertising_* events
            override fun onAdvertisingStopped(reason: String) = Unit
            override fun onAdvertisingFailed(errorName: String, detail: String?) =
                emitError(errorName, detail, "advertising")
            override fun onLinkUp(mtu: MtuInfo) {
                emit(Events.connected(handle(), server.subscriberId ?: "peer", mtu.attMtu))
                emit(Events.mtuChanged(handle(), mtu.attMtu, mtu.frameSizeCeiling))
                onLinkUp?.invoke(mtu)
            }
            override fun onLinkDown(reason: String) = session?.onLinkLost() ?: Unit
            override fun onError(errorName: String, detail: String?) = emitError(errorName, detail, "advertising")
        })
        // COMMAND arrives as LPdu fragments (one ATT write each); reassemble here so
        // exactly one control PDU reaches the session per logical message.
        s.onCommandWrite = { fragment ->
            try {
                commandReassembler.accept(fragment)?.let { session?.onCommandPdu(it) }
            } catch (e: com.deceipt.adapter.protocol.ProtocolError) {
                emit(Events.error(session?.handle, e.toBridge("transfer")))
            }
        }
        s
    }

    fun open() {
        server.openServer()
        server.addService()
        server.serve()
    }

    override fun sendEvent(pdu: ByteArray) { server.notifyEvent(pdu) }
    override fun sendDataFrame(frame: ByteArray) { server.notifyData(frame) }
    override fun sendCommand(pdu: ByteArray) = Unit // merchant has no COMMAND to write

    override fun frameSizeCeiling(): Int =
        if (server.isAdvertising) BleDiagnostics.frameSizeCeiling(server.negotiatedAttMtu)
        else Bounds.MAX_FRAME_PAYLOAD

    override fun controlFragmentCeiling(): Int {
        val mtu = server.negotiatedAttMtu
        // Before the subscriber's MTU is known (default 23) fall back to the
        // hard LPdu cap rather than deriving a zero-size payload budget.
        return if (mtu <= MIN_ATT_MTU) Bounds.MAX_LPDU_FRAG_BYTES else BleDiagnostics.attPayloadMax(mtu)
    }

    override fun close() { server.close() }

    private fun handle(): String = session?.handle ?: "merchant"
    private fun emitError(name: String, detail: String?, phase: String) {
        emit(Events.error(session?.handle, ProtocolError(name, detail).toBridge(phase)))
    }
}

class CustomerBleSession(
    private val context: Context,
    private val emit: (Map<String, Any?>) -> Unit,
) : SessionTransport {

    private var session: Session? = null
    private var onFirstCandidate: ((String) -> Unit)? = null
    private val candidates = LinkedHashSet<String>()
    private var connecting = false
    var onLinkUp: (() -> Unit)? = null

    fun attach(s: Session) { session = s }

    /** Called once, with the first candidate advertising the service UUID. */
    fun awaitFirstCandidate(action: (String) -> Unit) { onFirstCandidate = action }

    val client: GattClientSession by lazy {
        GattClientSession(context, object : CentralCallback {
            override fun onScanStarted() = emit(Events.scanStarted())
            override fun onScanStopped(reason: String) = emit(Events.scanStopped(reason))
            override fun onCandidate(peripheralId: String, rssiDiagnosticsOnly: Int) {
                emit(Events.peerCandidate(peripheralId, GattUuids.SERVICE_STR, null, rssiDiagnosticsOnly))
                synchronized(candidates) {
                    candidates.add(peripheralId)
                    // Ambiguity FAILS CLOSED (DESIGN.md 7.3): never pick by RSSI.
                    if (candidates.size > 1 && !connecting) {
                        emit(
                            Events.error(
                                session?.handle,
                                ProtocolError("TRANSPORT_PEER_AMBIGUOUS", "${candidates.size} candidates advertising the service").toBridge("scan"),
                            ),
                        )
                        return
                    }
                }
                if (!connecting) onFirstCandidate?.invoke(peripheralId)
            }
            override fun onCandidateLost(peripheralId: String) = emit(Events.peerCandidateLost(peripheralId))
            override fun onMtuChanged(mtu: MtuInfo) = emit(Events.mtuChanged(handle(), mtu.attMtu, mtu.frameSizeCeiling))
            override fun onEventPdu(pdu: ByteArray) { session?.onEventPdu(pdu) }
            override fun onDataFrame(frame: ByteArray) { session?.onDataFrame(frame) }
            override fun onLinkUp(mtu: MtuInfo) {
                emit(Events.connected(handle(), client.peripheralId ?: "peer", mtu.attMtu))
                emit(Events.mtuChanged(handle(), mtu.attMtu, mtu.frameSizeCeiling))
                onLinkUp?.invoke()
            }
            override fun onLinkDown(reason: String) { session?.onLinkLost() }
            override fun onError(errorName: String, detail: String?) =
                emit(Events.error(session?.handle, ProtocolError(errorName, detail).toBridge("connect")))
        })
    }

    fun startScan() { client.startScan() }
    fun stopScan() { client.stopScan() }

    /**
     * Connect to the single candidate the user's QR named. The BLE layer refuses
     * to re-target, so a second, different id fails closed
     * (`TRANSPORT_PEER_AMBIGUOUS`) rather than choosing by RSSI.
     */
    fun connectSelected(peripheralId: String) {
        connecting = true
        client.connect(context, peripheralId)
    }

    override fun sendEvent(pdu: ByteArray) = Unit // customer has no EVENT to write
    override fun sendDataFrame(frame: ByteArray) = Unit // customer has no DATA to write
    override fun sendCommand(pdu: ByteArray) { client.writeCommand(pdu) }

    override fun frameSizeCeiling(): Int = client.frameSizeCeiling

    override fun controlFragmentCeiling(): Int {
        val mtu = client.negotiatedAttMtu
        return if (mtu <= MIN_ATT_MTU) Bounds.MAX_LPDU_FRAG_BYTES else BleDiagnostics.attPayloadMax(mtu)
    }

    override fun close() { client.close() }

    private fun handle(): String = session?.handle ?: "customer"
}

/** String form of the frozen service UUID, for the `serviceUuid` event field. */
object GattUuids {
    const val SERVICE_STR = com.deceipt.adapter.ble.GattUuids.SERVICE.toString()

    /** The BLE default ATT MTU (23). Used only to detect "MTU not yet negotiated". */
    const val MIN_ATT_MTU = 23
}
