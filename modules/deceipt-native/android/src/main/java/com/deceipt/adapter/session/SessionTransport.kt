package com.deceipt.native.session

import com.deceipt.native.protocol.Bounds
import com.deceipt.native.protocol.Bytes

/**
 * The seam between the protocol state machine and the BLE transport. The
 * transport implementation (Android GATT server/client) lives in
 * `com.deceipt.native.ble`; the session logic never imports android.bluetooth,
 * which keeps the whole protocol path exercisable on the JVM.
 *
 * RSSI appears ONLY as a diagnostics field and is never an input to selection,
 * ordering, association, connection target, or trust (DESIGN.md 2.5, 7.3).
 */
interface SessionTransport {
    /** Merchant -> customer EVENT characteristic (indicate). */
    fun sendEvent(pdu: ByteArray)

    /** Merchant -> customer DATA characteristic (notify). */
    fun sendDataFrame(frame: ByteArray)

    /** Customer -> merchant COMMAND characteristic (write with response). */
    fun sendCommand(pdu: ByteArray)

    /** Frame-size ceiling derived from the negotiated ATT MTU (never a fixed MTU). */
    fun frameSizeCeiling(): Int = Bounds.MAX_FRAME_PAYLOAD

    /** Stop advertising / scanning and tear the link down. */
    fun close()
}

/** Merchant key custody seam; keeps signing keys out of the session object. */
interface MerchantSigner {
    fun deviceKeyId(): ByteArray
    fun devicePublicKey(): ByteArray
    /** Sign `Sig_structure` bytes with the merchant device key (Ed25519). */
    fun sign(sigStructure: ByteArray): ByteArray
}

/** Wall clock in unix seconds; injectable so timeout logic is testable. */
fun interface Clock {
    fun nowUnix(): Long

    companion object {
        val SYSTEM = Clock { System.currentTimeMillis() / 1000L }
    }
}

/** Schedules timeout callbacks; injectable so the JVM tests are deterministic. */
interface Scheduler {
    /** @return a handle that cancels the pending callback. */
    fun schedule(delayMs: Long, action: Runnable): Cancellable

    fun shutdown()

    fun interface Cancellable {
        fun cancel()
    }

    companion object {
        fun real(): Scheduler = object : Scheduler {
            private val exec = java.util.concurrent.ScheduledThreadPoolExecutor(1) { r ->
                Thread(r, "deceipt-session-timers").apply { isDaemon = true }
            }

            override fun schedule(delayMs: Long, action: Runnable): Cancellable {
                val f = exec.schedule(action, delayMs, java.util.concurrent.TimeUnit.MILLISECONDS)
                return Cancellable { f.cancel(false) }
            }

            override fun shutdown() {
                exec.shutdownNow()
            }
        }
    }
}

/** Builds the JSON-friendly event maps the module forwards across the bridge. */
object Events {

    fun advertisingStarted(handle: String, serviceUuid: String): Map<String, Any?> =
        linkedMapOf("type" to "advertising_started", "sessionHandle" to handle, "serviceUuid" to serviceUuid)

    fun advertisingStopped(handle: String, reason: String): Map<String, Any?> =
        linkedMapOf("type" to "advertising_stopped", "sessionHandle" to handle, "reason" to reason)

    fun scanStarted(): Map<String, Any?> = linkedMapOf("type" to "scan_started")

    fun scanStopped(reason: String): Map<String, Any?> =
        linkedMapOf("type" to "scan_stopped", "reason" to reason)

    fun peerCandidate(peripheralId: String, serviceUuid: String, protocolVersion: Int?, rssi: Int?): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "type" to "peer_candidate",
            "peripheralId" to peripheralId,
            "serviceUuid" to serviceUuid,
            "deterministicLabel" to ("terminal-" + peripheralId.takeLast(6)),
            "diagnostics" to linkedMapOf<String, Any?>("diagnosticsOnly" to true, "rssi" to rssi),
        )
        if (protocolVersion != null) m["protocolVersion"] = protocolVersion
        return m
    }

    fun peerCandidateLost(peripheralId: String): Map<String, Any?> =
        linkedMapOf("type" to "peer_candidate_lost", "peripheralId" to peripheralId)

    fun bluetoothState(state: String): Map<String, Any?> =
        linkedMapOf("type" to "bluetooth_state_changed", "state" to state)

    fun connected(handle: String, peripheralId: String, attMtu: Int): Map<String, Any?> =
        linkedMapOf("type" to "connected", "sessionHandle" to handle, "peripheralId" to peripheralId, "attMtu" to attMtu)

    fun mtuChanged(handle: String, attMtu: Int, frameSizeCeiling: Int): Map<String, Any?> =
        linkedMapOf("type" to "mtu_changed", "sessionHandle" to handle, "attMtu" to attMtu, "frameSizeCeiling" to frameSizeCeiling)

    fun disconnected(handle: String, reason: String, error: Map<String, Any?>? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("type" to "disconnected", "sessionHandle" to handle, "reason" to reason)
        if (error != null) m["error"] = error
        return m
    }

    fun handshakeStarted(handle: String, role: String): Map<String, Any?> =
        linkedMapOf("type" to "handshake_started", "sessionHandle" to handle, "role" to role)

    fun sessionKeysDerived(handle: String): Map<String, Any?> = linkedMapOf(
        "type" to "session_keys_derived",
        "sessionHandle" to handle,
        "sessionKeysOnly" to linkedMapOf<String, Any?>("kind" to "SessionKeysOnly", "sessionHandle" to handle),
    )

    fun sessionUnverifiedPeer(
        handle: String,
        merchantIdHex: String,
        deviceKeyIdHex: String,
        credentialB64: String,
        credential: Map<String, Any?>,
    ): Map<String, Any?> = linkedMapOf(
        "type" to "session_unverified_peer",
        "sessionHandle" to handle,
        "unverifiedPeer" to linkedMapOf<String, Any?>(
            "kind" to "SessionUnverifiedPeer",
            "sessionHandle" to handle,
            "merchantIdHex" to merchantIdHex,
            "deviceKeyIdHex" to deviceKeyIdHex,
            "credentialB64" to credentialB64,
            "credentialTrust" to "unknown_issuer",
            "keyAuthorized" to false,
        ),
        "credential" to credential,
    )

    fun sessionAuthenticated(
        handle: String,
        merchantIdHex: String,
        deviceKeyIdHex: String,
        credentialB64: String,
        temporallyAcceptable: Boolean,
        credential: Map<String, Any?>,
    ): Map<String, Any?> = linkedMapOf(
        "type" to "session_authenticated",
        "sessionHandle" to handle,
        "authenticated" to linkedMapOf<String, Any?>(
            "kind" to "SessionAuthenticated",
            "sessionHandle" to handle,
            "merchantIdHex" to merchantIdHex,
            "deviceKeyIdHex" to deviceKeyIdHex,
            "credentialB64" to credentialB64,
            "credentialTrust" to "authenticated",
            "keyAuthorized" to true,
            "credentialTemporallyAcceptable" to temporallyAcceptable,
        ),
        "credential" to credential,
    )

    fun bindingConsumed(handle: String, sessionIdHex: String): Map<String, Any?> =
        linkedMapOf("type" to "binding_consumed", "sessionHandle" to handle, "sessionIdHex" to sessionIdHex)

    fun bindingStale(handle: String, sessionIdHex: String, expiredAtUnix: Long): Map<String, Any?> =
        linkedMapOf("type" to "binding_stale", "sessionHandle" to handle, "sessionIdHex" to sessionIdHex, "expiredAtUnix" to expiredAtUnix)

    fun offerReceived(handle: String, offer: Map<String, Any?>): Map<String, Any?> =
        linkedMapOf("type" to "offer_received", "sessionHandle" to handle, "offer" to offer)

    fun offerAccepted(handle: String): Map<String, Any?> =
        linkedMapOf("type" to "offer_accepted", "sessionHandle" to handle)

    fun transferStarted(handle: String, ciphertextLength: Int, frameCount: Int, frameSize: Int, payloadHashHex: String): Map<String, Any?> =
        linkedMapOf(
            "type" to "transfer_started", "sessionHandle" to handle,
            "ciphertextLength" to ciphertextLength, "frameCount" to frameCount,
            "frameSize" to frameSize, "payloadHashHex" to payloadHashHex,
        )

    fun transferProgress(handle: String, highestContiguousSequence: Int, frameCount: Int, notices: List<String>): Map<String, Any?> =
        linkedMapOf(
            "type" to "transfer_progress", "sessionHandle" to handle,
            "highestContiguousSequence" to highestContiguousSequence, "frameCount" to frameCount,
            "notices" to notices,
        )

    fun transferComplete(handle: String, frameCount: Int, payloadHashHex: String): Map<String, Any?> =
        linkedMapOf("type" to "transfer_complete", "sessionHandle" to handle, "frameCount" to frameCount, "payloadHashHex" to payloadHashHex)

    fun receiptReceived(handle: String, coseSign1B64: String, payloadSha256Hex: String, ciphertextLength: Int): Map<String, Any?> =
        linkedMapOf(
            "type" to "receipt_received", "sessionHandle" to handle, "state" to "RECEIPT_UNTRUSTED",
            "coseSign1B64" to coseSign1B64, "payloadSha256Hex" to payloadSha256Hex, "ciphertextLength" to ciphertextLength,
        )

    fun receiptAckSent(handle: String, receiptIdHex: String, outcomeCode: Int): Map<String, Any?> =
        linkedMapOf("type" to "receipt_ack_sent", "sessionHandle" to handle, "receiptIdHex" to receiptIdHex, "outcomeCode" to outcomeCode)

    fun sessionTornDown(handle: String, reason: String): Map<String, Any?> =
        linkedMapOf("type" to "session_torn_down", "sessionHandle" to handle, "reason" to reason)

    fun error(handle: String?, bridge: Map<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("type" to "error", "error" to bridge)
        if (handle != null) m["sessionHandle"] = handle
        return m
    }

    fun credentialMap(v: com.deceipt.native.protocol.Credential.Verification): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "trust" to v.trust,
            "signatureValid" to v.signatureValid,
            "temporallyAcceptable" to v.temporallyAcceptable,
        )
        v.merchantId?.let { m["merchantIdHex"] = Bytes.toHex(it) }
        v.deviceKeyId?.let { m["deviceKeyIdHex"] = Bytes.toHex(it) }
        v.devicePublicKey?.let { m["devicePublicKeyB64"] = Bytes.toBase64(it) }
        v.issuerId?.let { m["issuerIdHex"] = Bytes.toHex(it) }
        v.capabilities?.let { m["capabilities"] = it }
        v.merchantReference?.let { m["merchantReference"] = it }
        v.displayName?.let { m["displayName"] = it }
        if (v.errorName != null) {
            val d = com.deceipt.native.protocol.Errors.descriptor(v.errorName)
            m["error"] = linkedMapOf<String, Any?>(
                "name" to d.name, "code" to d.code, "fatal" to d.fatal, "retryable" to d.retryable,
            )
        }
        return m
    }
}
