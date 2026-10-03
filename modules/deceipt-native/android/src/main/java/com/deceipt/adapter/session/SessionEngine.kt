package com.deceipt.native.session

import com.deceipt.native.crypto.Crypto
import com.deceipt.native.crypto.Ed25519
import com.deceipt.native.crypto.P256
import com.deceipt.native.protocol.BindingStore
import com.deceipt.native.protocol.Bounds
import com.deceipt.native.protocol.Bytes
import com.deceipt.native.protocol.Cose
import com.deceipt.native.protocol.Credential
import com.deceipt.native.protocol.Envelope
import com.deceipt.native.protocol.Errors
import com.deceipt.native.protocol.Frame
import com.deceipt.native.protocol.Handshake
import com.deceipt.native.protocol.Lpdu
import com.deceipt.native.protocol.Messages
import com.deceipt.native.protocol.ProtocolError
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Deceipt transfer session state machine, both roles
 * (docs/protocol/handshake.md 2/8/9, docs/protocol/verification.md 1).
 *
 * Invariants enforced here:
 *  * BLE is an untrusted transport; successful AEAD open yields `RECEIPT_UNTRUSTED`,
 *    never a trusted receipt.
 *  * Trust requires the merchant signature over the EXACT received transcript and
 *    a credential chaining to a pinned anchor. Never re-encode-then-verify.
 *  * The merchant's long-lived signing key is never used for session key agreement.
 *  * No failure transition reaches a verified state.
 *
 * Everything here is radio-independent and runs identically on the JVM.
 */
class Session(
    val handle: String,
    val role: Role,
    private val transport: SessionTransport,
    private val emit: (Map<String, Any?>) -> Unit,
    private val clock: Clock = Clock.SYSTEM,
    private val scheduler: Scheduler = Scheduler.real(),
    private val random: SecureRandom = SecureRandom(),
    private val timeouts: Map<String, Long> = Bounds.TIMEOUTS_MS,
    private val anchors: List<Credential.Anchor> = emptyList(),
) {
    enum class Role { MERCHANT, CUSTOMER }

    @Volatile var state: String = "IDLE"
        private set

    private val closed = AtomicBoolean(false)
    private val timerHandles = HashMap<String, Scheduler.Cancellable>()

    // --- handshake material (never crosses the bridge) ---
    private var clientHello: Handshake.ClientHello? = null
    private var serverHello: Handshake.ServerHello? = null
    private var clientEphemeralScalar: ByteArray? = null
    private var serverEphemeralScalar: ByteArray? = null
    private var keys: Handshake.SessionKeys? = null
    private var sessionType: String = "none" // none | SessionKeysOnly | SessionUnverifiedPeer | SessionAuthenticated

    private var c2mAead: Envelope.Receiver? = null
    private var m2cAead: Envelope.Receiver? = null
    private var m2cOutCounter = 0L
    private var c2mOutCounter = 0L
    private var payloadSealed = false

    // --- reassembly ---
    private val commandReassembler = Lpdu.Reassembler()
    private val eventReassembler = Lpdu.Reassembler()
    private var commandMsgSeq = 0
    private var eventMsgSeq = 0

    // --- transfer ---
    private var receiver: Frame.Receiver? = null
    private var outFrames: List<ByteArray> = emptyList()
    private var ackedThrough = -1
    private var retryRounds = 0
    private val pendingNotices = mutableListOf<String>()
    private var ackSinceLast = 0
    private var lastAckAtMs = 0L

    // --- merchant input ---
    var transferId: ByteArray? = null; private set
    var sessionId: ByteArray? = null; private set
    private var receiptCose1: ByteArray? = null
    private var offerHash: ByteArray? = null

    val isClosed: Boolean get() = closed.get()

    // =======================================================================
    // Public lifecycle
    // =======================================================================

    fun startMerchant(
        bindingStore: BindingStore,
        receiptCose1B64: String,
        transferIdHex: String,
        sessionIdHex: String,
        receiptIdHex: String,
        offerHashHex: String,
        frameSize: Int?,
        signer: MerchantSigner,
    ) {
        require(role == Role.MERCHANT)
        transferId = Bytes.fromHex(transferIdHex)
        sessionId = Bytes.fromHex(sessionIdHex)
        receiptCose1 = Bytes.fromBase64(receiptCose1B64)
        offerHash = Bytes.fromHex(offerHashHex)
        this.bindingStore = bindingStore
        this.signer = signer
        this.receiptId = Bytes.fromHex(receiptIdHex)
        this.requestedFrameSize = frameSize ?: Bounds.MAX_FRAME_PAYLOAD

        state = "ADVERTISING"
        emit(Events.advertisingStarted(handle, GattUuids.SERVICE))
        armTimeout("T_ADVERTISE") { fail("SESSION_EXPIRED", "advertise window elapsed") }
        armTimeout("T_SESSION") { fail("SESSION_EXPIRED", "session lifetime elapsed") }
    }

    private var bindingStore: BindingStore? = null
    private var signer: MerchantSigner? = null
    private var receiptId: ByteArray? = null
    private var requestedFrameSize: Int = Bounds.MAX_FRAME_PAYLOAD
    private var negotiatedFrameSize: Int = Bounds.MAX_FRAME_PAYLOAD

    fun startCustomer(
        sessionIdHex: String,
        sbt: ByteArray,
        offerHashHex: String,
        clientMaxFramePayload: Int?,
        bindingStore: BindingStore,
    ) {
        require(role == Role.CUSTOMER)
        this.sessionId = Bytes.fromHex(sessionIdHex)
        this.qrSbt = sbt.copyOf()
        this.offerHash = Bytes.fromHex(offerHashHex)
        this.requestedFrameSize = clientMaxFramePayload ?: Bounds.MAX_FRAME_PAYLOAD
        this.bindingStore = bindingStore
        state = "CONNECTED"
        emit(Events.handshakeStarted(handle, "customer"))

        val nonce = ByteArray(Bounds.NONCE_BYTES).also { random.nextBytes(it) }
        val scalar = P256.generateScalar(random)
        clientEphemeralScalar = scalar
        val eph = P256.publicKeyFromScalar(scalar)
        val proof = Handshake.bindingProof(qrSbt!!, nonce, eph)
        val ch = Handshake.ClientHello(
            protocolVersion = Bounds.PROTOCOL_VERSION.toLong(),
            cryptoSuites = listOf(Bounds.SUITE_ID.toLong()),
            sessionId = this.sessionId!!,
            clientNonce = nonce,
            clientEphemeralPubkey = eph,
            bindingProof = proof,
            maxFramePayload = this.requestedFrameSize.toLong(),
        )
        clientHello = ch
        state = "HANDSHAKE"
        armTimeout("T_HELLO_RESPONSE") { fail("HANDSHAKE_TIMEOUT", "no ServerHello") }
        armTimeout("T_SESSION") { fail("SESSION_EXPIRED", "session lifetime elapsed") }
        sendControl(Envelope.plaintext(Handshake.encodeClientHello(ch)), command = true)
    }

    private var qrSbt: ByteArray? = null

    fun acceptOffer() {
        val k = ensureKeys()
        val offer = requireNotNull(offered) { "no offer to accept" }
        val msg = Messages.encodeAccept(Messages.Accept(offer.transferId, Bounds.PROTOCOL_VERSION.toLong(), Bounds.SUITE_ID.toLong()))
        val env = Envelope.seal(k.kC2mCtrl, c2mOutCounter++, k.sessionContext, byteArrayOf(0x00), msg)
        sendControl(env, command = true)
        emit(Events.offerAccepted(handle))
    }

    fun beginTransfer(receiptAlreadySigned: Boolean = true) {
        // Merchant: seal the payload ONCE (one-shot k_m2c_payload, counter 0) and stream.
        val k = ensureKeys()
        val receipt = requireNotNull(receiptCose1)
        if (payloadSealed) throw ProtocolError("INTERNAL_ERROR", "payload key already used")
        payloadSealed = true
        val ciphertext = Crypto.aesGcmSeal(
            k.kM2cPayload,
            Crypto.aeadNonce(0),
            Handshake.aadPayload(k.sessionContext),
            receipt,
        )
        receiptRequiresCiphertext = ciphertext
        val frameSize = negotiatedFrameSize
        val frameCount = Frame.frameCount(ciphertext.size, frameSize)
        outFrames = Frame.split(transferId!!, ciphertext, frameSize)
        val hash = Crypto.sha256(ciphertext)
        state = "TRANSFER"
        emit(Events.transferStarted(handle, ciphertext.size, frameCount, frameSize, Bytes.toHex(hash)))
        val begin = Messages.encodeTransferBegin(
            Messages.TransferBegin(transferId!!, ciphertext.size.toLong(), hash, frameSize.toLong(), frameCount.toLong()),
        )
        sendControl(Envelope.seal(k.kM2cCtrl, m2cOutCounter++, k.sessionContext, byteArrayOf(0x01), begin), command = false)
        for (f in outFrames) transport.sendDataFrame(f)
        armTimeout("T_ACK_WAIT") { onAckWait() }
        armTimeout("T_TRANSFER_IDLE") { fail("TRANSFER_TIMEOUT", "transfer idle") }
    }

    fun retryFrom(fromSequence: Long) {
        val k = ensureKeys()
        val from = fromSequence.toInt()
        if (from < 0 || from >= outFrames.size) throw ProtocolError("FRAME_SEQUENCE_OUT_OF_RANGE")
        for (i in from until outFrames.size) transport.sendDataFrame(outFrames[i])
    }

    fun sendReceiptAck(receiptIdHex: String, outcomeCode: Int) {
        val k = ensureKeys()
        val msg = Messages.encodeReceiptAck(
            Messages.ReceiptAck(transferId ?: ByteArray(16), Bytes.fromHex(receiptIdHex), outcomeCode.toLong()),
        )
        sendControl(Envelope.seal(k.kC2mCtrl, c2mOutCounter++, k.sessionContext, byteArrayOf(0x00), msg), command = true)
        emit(Events.receiptAckSent(handle, receiptIdHex, outcomeCode))
    }

    fun cancel(reason: String) {
        val k = keys
        if (k != null && sessionType != "SessionKeysOnly") {
            try {
                val msg = Messages.encodeCancel(Messages.Cancel(transferId, Errors.descriptor("TRANSFER_CANCELLED").code.toLong()))
                val dir = if (role == Role.MERCHANT) byteArrayOf(0x01) else byteArrayOf(0x00)
                val counter = if (role == Role.MERCHANT) m2cOutCounter++ else c2mOutCounter++
                val key = if (role == Role.MERCHANT) k.kM2cCtrl else k.kC2mCtrl
                sendControl(Envelope.seal(key, counter, k.sessionContext, dir, msg), command = role == Role.CUSTOMER)
            } catch (e: Exception) {
                // Cancellation is best-effort; teardown still proceeds.
            }
        }
        teardown(reason, emitError = false)
    }

    /** Teardown + zeroize. Idempotent. */
    fun stop(reason: String = "user_cancelled") = teardown(reason, emitError = false)

    fun fail(errorName: String, detail: String? = null) {
        val pe = ProtocolError(errorName, detail)
        emit(Events.error(handle, pe.toBridge(phaseFor(errorName))))
        teardown("aborted", emitError = false)
    }

    private fun phaseFor(name: String): String = when {
        name.startsWith("BINDING") -> "binding"
        name.startsWith("CREDENTIAL") -> "credential"
        name.startsWith("HANDSHAKE") || name.startsWith("AEAD") -> "handshake"
        name.startsWith("FRAME") || name.startsWith("TRANSFER") || name.startsWith("LPDU") -> "transfer"
        name.startsWith("TRANSPORT") -> "connect"
        name.startsWith("SESSION") -> "teardown"
        else -> "internal"
    }

    // =======================================================================
    // Inbound
    // =======================================================================

    /** A reassembled control PDU arrived on COMMAND (merchant side). */
    fun onCommandPdu(pdu: ByteArray) {
        if (closed.get()) return
        try {
            when (role) {
                Role.MERCHANT -> merchantOnCommand(pdu)
                Role.CUSTOMER -> customerOnCommand(pdu)
            }
        } catch (e: ProtocolError) {
            fail(e.errorName, e.detail)
        }
    }

    /** A reassembled control PDU arrived on EVENT (customer side). */
    fun onEventPdu(pdu: ByteArray) {
        if (closed.get()) return
        try {
            if (role == Role.CUSTOMER) customerOnEvent(pdu)
        } catch (e: ProtocolError) {
            fail(e.errorName, e.detail)
        }
    }

    /** A DATA frame arrived (customer side). */
    fun onDataFrame(frame: ByteArray) {
        if (closed.get()) return
        try {
            if (role != Role.CUSTOMER) return
            val r = receiver ?: return
            val replayed = r.add(frame)
            if (replayed) {
                synchronized(pendingNotices) { pendingNotices.add("FRAME_SEQUENCE_REPLAYED") }
            }
            ackSinceLast += 1
            emit(
                Events.transferProgress(
                    handle, r.highestContiguousSequence, r.frameCount,
                    synchronized(pendingNotices) { pendingNotices.toList().also { pendingNotices.clear() } },
                ),
            )
            if (r.isComplete) {
                customerCompleteTransfer(r)
            } else if (ackSinceLast >= Bounds.ACK_EVERY_FRAMES) {
                sendAck(r.highestContiguousSequence)
            }
        } catch (e: ProtocolError) {
            fail(e.errorName, e.detail)
        }
    }

    fun onRawCommandFragment(fragment: ByteArray) {
        commandReassembler.accept(fragment)?.let { onCommandPdu(it) }
    }

    fun onRawEventFragment(fragment: ByteArray) {
        eventReassembler.accept(fragment)?.let { onEventPdu(it) }
    }

    // --- merchant -----------------------------------------------------------

    private fun merchantOnCommand(pdu: ByteArray) {
        val k = keys
        if (k == null) {
            // Pre-key: only the plaintext CLIENT_HELLO (or pre-key ERROR) is legal.
            if (pdu.isEmpty()) throw ProtocolError("CBOR_MALFORMED")
            if ((pdu[0].toInt() and 0xff) == Bounds.ENVELOPE_AEAD) throw ProtocolError("MESSAGE_WRONG_STATE")
            merchantOnClientHello(pdu.copyOfRange(1, pdu.size))
            return
        }
        val msgBytes = c2mAead!!.open(pdu, requireAead = true)
        when (val type = Messages.peekType(msgBytes)) {
            2L -> merchantOnAccept(msgBytes)
            3L -> merchantOnAck(msgBytes)
            4L -> merchantOnReceiptAck(msgBytes)
            5L -> { /* CANCEL */ teardown("user_cancelled", emitError = false) }
            6L -> merchantOnRetry(msgBytes)
            21L -> { val e = Messages.parseError(msgBytes); fail("TRANSFER_ABORTED", e.detail) }
            else -> throw ProtocolError("MESSAGE_UNKNOWN_TYPE", "type $type")
        }
    }

    private fun merchantOnClientHello(body: ByteArray) {
        val ch = Handshake.parseClientHello(body)
        clientHello = ch
        val store = requireNotNull(bindingStore)
        val now = clock.nowUnix()
        val sbt = store.claim(ch.sessionId, now) // BINDING_UNKNOWN_SESSION / BINDING_STALE / BINDING_CONSUMED
        val expected = Handshake.bindingProof(sbt, ch.clientNonce, ch.clientEphemeralPubkey)
        if (!Bytes.constantTimeEquals(expected, ch.bindingProof)) {
            throw ProtocolError("BINDING_PROOF_INVALID")
        }
        store.markConsumed(ch.sessionId)
        emit(Events.bindingConsumed(handle, Bytes.toHex(ch.sessionId)))
        cancelTimersOf("T_ADVERTISE")

        // Build SERVER_HELLO (eleven labels) and sign the transcript.
        val serverNonce = ByteArray(Bounds.NONCE_BYTES).also { random.nextBytes(it) }
        val serverScalar = P256.generateScalar(random)
        serverEphemeralScalar = serverScalar
        val serverEph = P256.publicKeyFromScalar(serverScalar)
        val tupleBytes = store.offerHash(ch.sessionId)?.let { oh ->
            Handshake.encodeBindingTuple(
                Handshake.BindingTuple(ch.sessionId, transferId!!, receiptId!!, oh),
            )
        } ?: throw ProtocolError("BINDING_REQUIRED")
        val tuple = Handshake.parseBindingTuple(tupleBytes)
        val digest = Handshake.bindingTupleDigest(tupleBytes)
        negotiatedFrameSize = minOf(requestedFrameSize, minOf(ch.maxFramePayload.toInt(), transport.frameSizeCeiling()))
        if (negotiatedFrameSize < Bounds.MIN_FRAME_PAYLOAD) {
            throw ProtocolError("FRAME_SIZE_INVALID", "negotiated frame size below minimum")
        }
        val transcript = Handshake.buildTranscript(
            Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID,
            ch.clientNonce, ch.clientEphemeralPubkey, serverNonce, serverEph,
            tuple, tupleBytes, digest, negotiatedFrameSize,
        )
        // handshake.md 3: signature = Ed25519_sign(merchant_device_key, transcript).
        val signature = requireNotNull(signer).sign(transcript)
        val sh = Handshake.ServerHello(
            protocolVersion = Bounds.PROTOCOL_VERSION.toLong(),
            suiteId = Bounds.SUITE_ID.toLong(),
            transferId = transferId!!,
            serverNonce = serverNonce,
            serverEphemeralPubkey = serverEph,
            merchantCredential = requireNotNull(merchantCredential),
            transcriptSignature = signature,
            bindingTupleDigest = digest,
            bindingTuple = tupleBytes,
            maxFramePayload = negotiatedFrameSize.toLong(),
        )
        serverHello = sh
        // Derive keys and derive the shared secret with the client's ephemeral key.
        val shared = P256.sharedSecret(serverScalar, ch.clientEphemeralPubkey)
        val sk = Handshake.deriveKeys(shared, transcript, tuple.transferId)
        Bytes.zeroize(shared)
        installKeys(sk, Role.MERCHANT)
        state = "MERCHANT_SESSION_AUTHENTICATED"
        sendControl(Envelope.plaintext(Handshake.encodeServerHello(sh)), command = false)
        emit(Events.sessionKeysDerived(handle))

        // Offer is untrusted display data; it is sealed with k_m2c_ctrl counter 0.
        val offer = buildOffer()
        offered = offer
        sendControl(Envelope.seal(sk.kM2cCtrl, m2cOutCounter++, sk.sessionContext, byteArrayOf(0x01), Messages.encodeReceiptOffer(offer)), command = false)
        armTimeout("T_ACCEPT") { fail("HANDSHAKE_TIMEOUT", "no ACCEPT") }
    }

    private var merchantCredential: ByteArray? = null
    fun setMerchantCredential(cred: ByteArray) { merchantCredential = cred }

    private var offered: Messages.ReceiptOffer? = null
    private var offerEmitted = false

    private fun buildOffer(): Messages.ReceiptOffer {
        val offer = requireNotNull(merchantOfferFields)
        return offer
    }

    private var merchantOfferFields: Messages.ReceiptOffer? = null
    fun setOfferFields(o: Messages.ReceiptOffer) { merchantOfferFields = o }

    private fun merchantOnAccept(msgBytes: ByteArray) {
        val a = Messages.parseAccept(msgBytes)
        if (a.protocolVersion != Bounds.PROTOCOL_VERSION.toLong()) throw ProtocolError("HANDSHAKE_UNSUPPORTED_VERSION")
        if (a.suiteId != Bounds.SUITE_ID.toLong()) throw ProtocolError("HANDSHAKE_SUITE_MISMATCH")
        if (!Bytes.constantTimeEquals(a.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        cancelTimersOf("T_ACCEPT")
        offerEmitted = true
    }

    private fun merchantOnAck(msgBytes: ByteArray) {
        val ack = Messages.parseAck(msgBytes)
        if (!Bytes.constantTimeEquals(ack.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        val h = ack.highestContiguousSequence.toInt()
        if (h <= ackedThrough) return // stale duplicate, ignored
        ackedThrough = h
        retryRounds = 0
        cancelTimersOf("T_ACK_WAIT")
        val hash = Crypto.sha256(receiptRequiresCiphertext!!)
        if (ackedThrough >= outFrames.size - 1) {
            val complete = Messages.encodeTransferComplete(
                Messages.TransferComplete(transferId!!, outFrames.size.toLong(), hash),
            )
            val k = ensureKeys()
            sendControl(Envelope.seal(k.kM2cCtrl, m2cOutCounter++, k.sessionContext, byteArrayOf(0x01), complete), command = false)
            emit(Events.transferComplete(handle, outFrames.size, Bytes.toHex(hash)))
        } else {
            armTimeout("T_ACK_WAIT") { onAckWait() }
        }
    }

    private var receiptRequiresCiphertext: ByteArray? = null

    private fun onAckWait() {
        if (ackedThrough >= outFrames.size - 1) return
        if (retryRounds >= Bounds.MAX_FRAME_RETRIES) {
            fail("TRANSFER_RETRY_EXHAUSTED")
            return
        }
        retryRounds += 1
        for (i in (ackedThrough + 1) until outFrames.size) transport.sendDataFrame(outFrames[i])
        armTimeout("T_ACK_WAIT") { onAckWait() }
    }

    private fun merchantOnRetry(msgBytes: ByteArray) {
        val r = Messages.parseRetry(msgBytes)
        if (!Bytes.constantTimeEquals(r.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        retryFrom(r.fromSequence)
    }

    private fun merchantOnReceiptAck(msgBytes: ByteArray) {
        val a = Messages.parseReceiptAck(msgBytes)
        state = "ACKED"
        teardown("completed", emitError = false)
    }

    // --- customer -----------------------------------------------------------

    private fun customerOnCommand(pdu: ByteArray) {
        // COMMAND carries only customer->merchant traffic; anything here is wrong.
        throw ProtocolError("MESSAGE_WRONG_DIRECTION")
    }

    private fun customerOnEvent(pdu: ByteArray) {
        val k = keys
        if (k == null) {
            if (pdu.isEmpty()) throw ProtocolError("CBOR_MALFORMED")
            if ((pdu[0].toInt() and 0xff) == Bounds.ENVELOPE_AEAD) throw ProtocolError("MESSAGE_WRONG_STATE")
            customerOnServerHello(pdu.copyOfRange(1, pdu.size))
            return
        }
        val msgBytes = m2cAead!!.open(pdu, requireAead = true)
        when (val type = Messages.peekType(msgBytes)) {
            18L -> customerOnOffer(msgBytes)
            19L -> customerOnTransferBegin(msgBytes)
            20L -> customerOnTransferComplete(msgBytes)
            21L -> { val e = Messages.parseError(msgBytes); fail("TRANSFER_ABORTED", e.detail) }
            else -> throw ProtocolError("MESSAGE_UNKNOWN_TYPE", "type $type")
        }
    }

    private fun customerOnServerHello(body: ByteArray) {
        cancelTimersOf("T_HELLO_RESPONSE")
        val ch = requireNotNull(clientHello)
        val sh = Handshake.parseServerHello(body, ch.cryptoSuites)
        serverHello = sh
        val transcript = Handshake.rebuildFromReceived(Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID, ch, sh)

        // Step 3: credential. An unknown issuer is NON-FATAL.
        val cred = Credential.verify(sh.merchantCredential, anchors, clock.nowUnix())
        val credentialDeviceKey = cred.devicePublicKey
            ?: throw ProtocolError("CREDENTIAL_MALFORMED", "credential has no device key")

        // Step 4: transcript signature. Anchored -> SessionAuthenticated;
        // unknown issuer + self-asserted signature -> SessionUnverifiedPeer;
        // anything else fails closed.
        val sigOk = Ed25519.verify(credentialDeviceKey, transcript, sh.transcriptSignature)
        if (!sigOk) throw ProtocolError("HANDSHAKE_SIGNATURE_INVALID")

        val shared = P256.sharedSecret(clientEphemeralScalar!!, sh.serverEphemeralPubkey)
        val tuple = Handshake.parseBindingTuple(sh.bindingTuple)
        val sk = Handshake.deriveKeys(shared, transcript, tuple.transferId)
        Bytes.zeroize(shared)
        installKeys(sk, Role.CUSTOMER)
        transferId = tuple.transferId
        state = "MERCHANT_SESSION_AUTHENTICATED"
        emit(Events.sessionKeysDerived(handle))

        if (cred.trust == "authenticated" && cred.temporallyAcceptable) {
            sessionType = "SessionAuthenticated"
            emit(
                Events.sessionAuthenticated(
                    handle, Bytes.toHex(cred.merchantId!!), Bytes.toHex(cred.deviceKeyId!!),
                    Bytes.toBase64(sh.merchantCredential), true, Events.credentialMap(cred),
                ),
            )
        } else {
            // Well-formed credential from an unpinned issuer whose transcript
            // signature verified against its SELF-ASSERTED key: internal
            // consistency only, NOT identity. Receipts can never be TRUSTED.
            sessionType = "SessionUnverifiedPeer"
            emit(
                Events.sessionUnverifiedPeer(
                    handle, Bytes.toHex(cred.merchantId!!), Bytes.toHex(cred.deviceKeyId!!),
                    Bytes.toBase64(sh.merchantCredential), Events.credentialMap(cred),
                ),
            )
        }
    }

    private fun customerOnOffer(msgBytes: ByteArray) {
        val offer = Messages.parseReceiptOffer(msgBytes)
        val tuple = Handshake.parseBindingTuple(requireNotNull(serverHello).bindingTuple)
        if (!Bytes.constantTimeEquals(offer.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        // Recomputed offer_hash MUST equal the QR value (wire.md 7).
        val recomputed = Handshake.offerHash(
            offer.sessionId, offer.transferId, offer.receiptId,
            offer.merchantReference, offer.totalAmountMinor, offer.currency, offer.issuedAt,
        )
        if (!Bytes.constantTimeEquals(recomputed, offerHash!!)) throw ProtocolError("WRONG_TRANSACTION", "offer hash vs QR")
        if (!Bytes.constantTimeEquals(recomputed, tuple.offerHash)) throw ProtocolError("WRONG_TRANSACTION", "offer hash vs binding tuple")
        if (!Bytes.constantTimeEquals(offer.sessionId, sessionId!!)) throw ProtocolError("BINDING_UNKNOWN_SESSION")
        offered = offer
        state = "RECEIPT_OFFERED"
        emit(Events.offerReceived(handle, offerMap(offer)))
        cancelTimersOf("T_ACCEPT")
        armTimeout("T_TRANSFER_IDLE") { fail("TRANSFER_TIMEOUT", "no transfer after offer") }
    }

    private fun offerMap(o: Messages.ReceiptOffer): Map<String, Any?> = linkedMapOf(
        "transferIdHex" to Bytes.toHex(o.transferId),
        "receiptIdHex" to Bytes.toHex(o.receiptId),
        "merchantReference" to o.merchantReference,
        "totalAmountMinor" to o.totalAmountMinor,
        "currency" to o.currency,
        "issuedAt" to o.issuedAt,
        "kind" to o.kind,
        "ciphertextLength" to o.ciphertextLength,
        "merchantIdHex" to Bytes.toHex(o.merchantId),
        "credentialHashHex" to Bytes.toHex(o.credentialHash),
        "sessionIdHex" to Bytes.toHex(o.sessionId),
        "offerHashHex" to Bytes.toHex(
            Handshake.offerHash(o.sessionId, o.transferId, o.receiptId, o.merchantReference, o.totalAmountMinor, o.currency, o.issuedAt),
        ),
    )

    private fun customerOnTransferBegin(msgBytes: ByteArray) {
        val tb = Messages.parseTransferBegin(msgBytes)
        val k = ensureKeys()
        if (!Bytes.constantTimeEquals(tb.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        val negotiated = requireNotNull(serverHello).maxFramePayload.toInt()
        if (tb.frameSize > negotiated) throw ProtocolError("FRAME_SIZE_INVALID", "frame_size above transcript value")
        receiver = Frame.Receiver(tb.transferId, tb.ciphertextLength.toInt(), tb.frameCount.toInt(), tb.frameSize.toInt())
        state = "TRANSFER"
        armTimeout("T_TRANSFER_IDLE") { fail("TRANSFER_TIMEOUT", "transfer idle") }
    }

    private fun customerOnTransferComplete(msgBytes: ByteArray) {
        val tc = Messages.parseTransferComplete(msgBytes)
        if (!Bytes.constantTimeEquals(tc.transferId, transferId!!)) throw ProtocolError("TRANSFER_ID_MISMATCH")
        val r = receiver ?: throw ProtocolError("TRANSFER_INCOMPLETE")
        if (!r.isComplete) throw ProtocolError("TRANSFER_INCOMPLETE")
        if (tc.frameCount != r.frameCount.toLong()) throw ProtocolError("TRANSFER_BEGIN_MISMATCH")
        if (!Bytes.constantTimeEquals(tc.payloadHash, r.payloadHash())) throw ProtocolError("TRANSFER_HASH_MISMATCH")
        customerCompleteTransfer(r)
    }

    private var completed = false
    private fun customerCompleteTransfer(r: Frame.Receiver) {
        if (completed) return
        completed = true
        cancelTimersOf("T_TRANSFER_IDLE")
        val ciphertext = r.ciphertext()
        val k = ensureKeys()
        // Step 7: AEAD open with the ONE-SHOT payload key (counter 0).
        val plaintext = Crypto.aesGcmOpen(
            k.kM2cPayload, Crypto.aeadNonce(0), Handshake.aadPayload(k.sessionContext), ciphertext,
        ) ?: throw ProtocolError("AEAD_AUTH_FAILED")
        state = "RECEIPT_UNTRUSTED"
        sendAck(r.frameCount - 1)
        emit(Events.transferComplete(handle, r.frameCount, Bytes.toHex(r.payloadHash())))
        // Decryption success is NOT trust: hand the EXACT bytes to the app.
        emit(
            Events.receiptReceived(
                handle, Bytes.toBase64(plaintext), Bytes.toHex(Crypto.sha256(plaintext)), ciphertext.size,
            ),
        )
    }

    private fun sendAck(highest: Int) {
        val k = ensureKeys()
        val msg = Messages.encodeAck(Messages.Ack(transferId!!, highest.toLong()))
        val env = Envelope.seal(k.kC2mCtrl, c2mOutCounter++, k.sessionContext, byteArrayOf(0x00), msg)
        sendControl(env, command = true)
        ackSinceLast = 0
        lastAckAtMs = clock.nowUnix() * 1000L
    }

    // =======================================================================
    // Internals
    // =======================================================================

    private fun installKeys(k: Handshake.SessionKeys, role: Role) {
        keys = k
        c2mAead = Envelope.Receiver(k.kC2mCtrl, k.sessionContext, byteArrayOf(0x00))
        m2cAead = Envelope.Receiver(k.kM2cCtrl, k.sessionContext, byteArrayOf(0x01))
    }

    private fun ensureKeys(): Handshake.SessionKeys = keys ?: throw ProtocolError("PEER_NOT_AUTHENTICATED", "no session keys")

    private fun sendControl(pdu: ByteArray, command: Boolean) {
        if (closed.get()) return
        val maxFrag = minOf(transport.frameSizeCeiling(), Bounds.MAX_LPDU_FRAG_BYTES)
        val seq = if (command) commandMsgSeq++ else eventMsgSeq++
        for (f in Lpdu.fragment(pdu, seq, maxFrag)) {
            if (command) transport.sendCommand(f) else transport.sendEvent(f)
        }
    }

    private fun armTimeout(name: String, action: () -> Unit) {
        val ms = timeouts[name] ?: return
        synchronized(timerHandles) {
            timerHandles.remove(name)?.cancel()
            timerHandles[name] = scheduler.schedule(ms) {
                if (!closed.get()) action()
            }
        }
    }

    private fun cancelTimersOf(name: String) {
        synchronized(timerHandles) { timerHandles.remove(name)?.cancel() }
    }

    private fun teardown(reason: String, emitError: Boolean) {
        if (!closed.compareAndSet(false, true)) return
        state = "DISCONNECT"
        synchronized(timerHandles) {
            for (t in timerHandles.values) t.cancel()
            timerHandles.clear()
        }
        keys?.zeroize()
        keys = null
        Bytes.zeroize(clientEphemeralScalar)
        Bytes.zeroize(serverEphemeralScalar)
        Bytes.zeroize(qrSbt)
        transport.close()
        emit(Events.sessionTornDown(handle, reason))
    }

    /** Called by the module when the platform disconnects or the app goes away. */
    fun onLinkLost() = teardown("link_lost", emitError = false)
    fun onBluetoothOff() = teardown("bluetooth_off", emitError = false)
    fun onAppShutdown() = teardown("app_shutdown", emitError = false)

    fun snapshot(): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "sessionHandle" to handle,
            "role" to if (role == Role.MERCHANT) "merchant" else "customer",
            "state" to state,
            "authenticated" to (sessionType == "SessionAuthenticated"),
        )
        transferId?.let { m["transferIdHex"] = Bytes.toHex(it) }
        sessionId?.let { m["sessionIdHex"] = Bytes.toHex(it) }
        m["frameSize"] = negotiatedFrameSize
        receiver?.let {
            m["frameCount"] = it.frameCount
            m["highestContiguousSequence"] = it.highestContiguousSequence
        }
        return m
    }

    companion object {
        const val SESSION_TYPE_AUTHENTICATED = "SessionAuthenticated"
        const val SESSION_TYPE_UNVERIFIED_PEER = "SessionUnverifiedPeer"
        const val SESSION_TYPE_KEYS_ONLY = "SessionKeysOnly"
    }
}

/** GATT identifiers shared by the transport implementations. */
object GattUuids {
    const val SERVICE = "8decc0de-1e57-4000-8000-000000000001"
    const val COMMAND = "8decc0de-1e57-4000-8000-000000000002"
    const val EVENT = "8decc0de-1e57-4000-8000-000000000003"
    const val DATA = "8decc0de-1e57-4000-8000-000000000004"
}
