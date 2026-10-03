package com.deceipt.adapter.bridge

import com.deceipt.adapter.ble.GattClientSession
import com.deceipt.adapter.ble.GattServerSession
import com.deceipt.adapter.session.SessionTransport

/**
 * The seam between the session state machine and the Android GATT objects.
 *
 * The session drives `SessionTransport`; this class forwards outbound units to
 * the GATT server (merchant) or client (customer) and lets the BLE layer feed
 * inbound callbacks straight back into the session. The BLE layer performs LPdu
 * reassembly for control and delivers one DATA frame per notification, so the
 * session sees exactly one logical object per callback — never one per fragment.
 */
class GattTransportAdapter(
    private val server: GattServerSession?,
    private val client: GattClientSession?,
) : SessionTransport {

    override fun sendEvent(pdu: ByteArray) {
        // Merchant -> customer EVENT (indicate).
        server?.notifyEvent(pdu)
    }

    override fun sendDataFrame(frame: ByteArray) {
        // Merchant -> customer DATA (notify).
        server?.notifyData(frame)
    }

    override fun sendCommand(pdu: ByteArray) {
        // Customer -> merchant COMMAND (write with response).
        client?.writeCommand(pdu)
    }

    override fun frameSizeCeiling(): Int {
        client?.let { return it.frameSizeCeiling }
        server?.let {
            return com.deceipt.adapter.ble.BleDiagnostics.frameSizeCeiling(it.negotiatedAttMtu)
        }
        return com.deceipt.adapter.protocol.Bounds.MAX_FRAME_PAYLOAD
    }

    override fun close() {
        server?.close()
        client?.close()
    }
}
