package com.deceipt.adapter.bridge

import com.deceipt.adapter.session.SessionTransport

/**
 * Transport used when no radio is attached: the JVM protocol path, and a device
 * with no usable BLE hardware. It never fabricates success — it simply carries
 * nothing, so the session logic is exercised without a device.
 */
class NoopTransport : SessionTransport {
    override fun sendEvent(pdu: ByteArray) = Unit
    override fun sendDataFrame(frame: ByteArray) = Unit
    override fun sendCommand(pdu: ByteArray) = Unit
    override fun close() = Unit
}
