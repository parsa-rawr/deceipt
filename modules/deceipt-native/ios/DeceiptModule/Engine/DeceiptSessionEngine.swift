//
//  DeceiptSessionEngine.swift
//  Deceipt iOS native adapter (A4)
//
//  Role-agnostic session state machine: handshake driving, AEAD control
//  channel, LPdu send/receive, transfer flow control, timeouts and teardown.
//  It talks to a `DeceiptTransport` (CoreBluetooth on device, Loopback in
//  tests) and never touches JSI, so the whole protocol path is unit-testable
//  without a radio.
//
//  Invariants honoured here:
//    * successful AEAD decryption NEVER implies trust — the engine stops at
//      RECEIPT_UNTRUSTED and hands the exact bytes to the app;
//    * session secrets are ephemeral and zeroized on teardown;
//    * every queue/buffer is bounded;
//    * RSSI is never an input to selection or trust.
//

import Foundation

/// The native state projection (A3 `NativeSessionState`).
public enum NativeSessionState: String {
    case idle = "IDLE"
    case receiptSigned = "RECEIPT_SIGNED"
    case advertising = "ADVERTISING"
    case scanning = "SCANNING"
    case connected = "CONNECTED"
    case handshake = "HANDSHAKE"
    case merchantSessionAuthenticated = "MERCHANT_SESSION_AUTHENTICATED"
    case sessionKeysOnly = "SESSION_KEYS_ONLY"
    case receiptOffered = "RECEIPT_OFFERED"
    case transfer = "TRANSFER"
    case ciphertextReassembled = "CIPHERTEXT_REASSEMBLED"
    case sessionDecrypted = "SESSION_DECRYPTED"
    case receiptUntrusted = "RECEIPT_UNTRUSTED"
    case awaitingStore = "AWAITING_STORE"
    case acked = "ACKED"
    case disconnect = "DISCONNECT"
    case aborted = "ABORTED"
}

/// Events emitted by the engine; the bridge maps these to `DeceiptEvent`s.
public enum EngineEvent {
    case connected(peripheralId: String, attMtu: Int)
    case mtuChanged(attMtu: Int, frameSizeCeiling: Int)
    case disconnected(reason: String, error: BridgeErrorShape?)
    case handshakeStarted(role: String)
    case sessionKeysDerived
    /// credential verified to a pinned anchor AND transcript signature verified.
    case sessionAuthenticated(merchantId: Data, deviceKeyId: Data, credentialBytes: Data, credential: CredentialVerificationResult)
    /// credential well-formed, issuer NOT pinned, transcript verified against the
    /// credential's self-asserted device key. Transfer allowed; trust not attainable.
    case sessionUnverifiedPeer(merchantId: Data, deviceKeyId: Data, credentialBytes: Data, credential: CredentialVerificationResult)
    case bindingConsumed(sessionIdHex: String)
    case bindingStale(sessionIdHex: String, expiredAtUnix: Int64)
    case offerReceived(offer: OfferMetadataValue)
    case offerAccepted
    case transferStarted(ciphertextLength: Int, frameCount: Int, frameSize: Int, payloadHashHex: String)
    case transferProgress(highestContiguousSequence: Int64, frameCount: Int, notices: [ProtocolErrorName])
    case transferComplete(frameCount: Int, payloadHashHex: String)
    case receiptReceived(coseSign1: Data, payloadSha256Hex: String, ciphertextLength: Int)
    case receiptAckSent(receiptIdHex: String, outcomeCode: Int)
    case tornDown(reason: String)
    case error(BridgeErrorShape)
}

public struct OfferMetadataValue {
    public var transferIdHex: String
    public var receiptIdHex: String
    public var merchantReference: String
    public var totalAmountMinor: Int64
    public var currency: String
    public var issuedAt: Int64
    public var kind: Int64
    public var ciphertextLength: Int
    public var merchantIdHex: String
    public var credentialHashHex: String
    public var sessionIdHex: String
    public var offerHashHex: String

    public func asDictionary() -> [String: Any] {
        [
            "transferIdHex": transferIdHex,
            "receiptIdHex": receiptIdHex,
            "merchantReference": merchantReference,
            "totalAmountMinor": NSNumber(value: totalAmountMinor),
            "currency": currency,
            "issuedAt": NSNumber(value: issuedAt),
            "kind": NSNumber(value: kind),
            "ciphertextLength": NSNumber(value: ciphertextLength),
            "merchantIdHex": merchantIdHex,
            "credentialHashHex": credentialHashHex,
            "sessionIdHex": sessionIdHex,
            "offerHashHex": offerHashHex,
        ]
    }
}

/// Merchant-side configuration assembled at `startMerchantSession`.
public struct MerchantConfig {
    public var receiptCose1: Data
    public var transferId: Data
    public var sessionId: Data
    public var receiptId: Data
    public var offerHash: Data
    public var bindingTuple: Data
    public var sessionBindingToken: Data
    public var credentialBytes: Data
    public var credentialResult: CredentialVerificationResult
    public var merchantId: Data
    public var deviceKeyId: Data
    public var deviceSigningSeed: Data
    public var offer: MerchantOfferFields
}

public struct MerchantOfferFields {
    public var merchantReference: String
    public var totalAmountMinor: Int64
    public var currency: String
    public var issuedAt: Int64
    public var kind: Int64
}

/// Customer-side configuration assembled at `startCustomerSession`.
public struct CustomerConfig {
    public var qr: DeceiptBinding.QrPayload
    public var anchors: DeceiptCredential.AnchorSet
    public var clientMaxFramePayload: Int
    public var nowUnix: Int64
}

public final class DeceiptSessionEngine {
    public private(set) var handle: String
    public let role: DeceiptRole
    public private(set) var state: NativeSessionState = .idle
    private let transport: DeceiptTransport

    public var onEvent: ((EngineEvent) -> Void)?
    public var onStateChange: ((NativeSessionState) -> Void)?

    // Identity / session
    private var localEphemeral = DeceiptCrypto.EphemeralKeyPair()
    private var keys: SessionKeys?
    private var c2mChannel: ControlChannel?
    private var m2cChannel: ControlChannel?
    private var lpduRx = LpduReceiver()
    private var lpduTxSeq: UInt16 = 0
    private var peerAuthLevel: PeerAuthLevel = .keysOnly

    // Merchant
    private var merchant: MerchantConfig?
    private var frameSender: FrameSender?
    // Customer
    private var customer: CustomerConfig?
    private var frameReceiver: FrameReceiver?
    private var negotiatedFrameSize: Int = 0
    private var expectedTransferId: Data?
    private var payloadHash: Data?

    // Timeouts
    private var sessionTimer: DispatchSourceTimer?
    private var transferIdleTimer: DispatchSourceTimer?
    private var timeouts: [String: Int] = DeceiptTimeout.defaults

    private var teardownReason: String = "aborted"
    private var tornDown = false
    private let lock = NSRecursiveLock()

    public init(handle: String, role: DeceiptRole, transport: DeceiptTransport) {
        self.handle = handle
        self.role = role
        self.transport = transport
        wireTransport()
    }

    public func applyTimeoutOverrides(_ overrides: [String: Int]?) {
        guard let overrides else { return }
        for (k, v) in overrides where timeouts[k] != nil { timeouts[k] = v }
    }

    private func setState(_ s: NativeSessionState) {
        lock.lock(); defer { lock.unlock() }
        guard state != s else { return }
        state = s
        onStateChange?(s)
    }

    private func emit(_ e: EngineEvent) { onEvent?(e) }

    private func fail(_ name: ProtocolErrorName, phase: String, detail: String? = nil, fatal: Bool = true) {
        let err = BridgeErrorShape(name: name, phase: phase, detail: detail)
        emit(.error(err))
        if fatal { abort(reason: "aborted") }
    }

    // MARK: Transport wiring

    private func wireTransport() {
        transport.onCommandFragment = { [weak self] frag in self?.ingestCommand(frag) }
        transport.onEventFragment = { [weak self] frag in self?.ingestEvent(frag) }
        transport.onDataFrame = { [weak self] frame in self?.ingestDataFrame(frame) }
        transport.onConnected = { [weak self] mtu in self?.handleConnected(mtu: mtu) }
        transport.onDisconnected = { [weak self] reason in self?.handleLinkLost(reason: reason) }
        transport.onBluetoothState = { [weak self] state in
            if state != "on" { self?.abort(reason: "bluetooth_off") }
        }
    }

    // MARK: Merchant

    public func configureMerchant(_ config: MerchantConfig) {
        merchant = config
        expectedTransferId = config.transferId
        setState(.receiptSigned)
        startSessionTimer()
    }

    public func startAdvertising() {
        guard merchant != nil else { return }
        transport.startAdvertising()
        setState(.advertising)
        // T_ADVERTISE
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + .milliseconds(timeouts["T_ADVERTISE"] ?? 60_000))
        t.setEventHandler { [weak self] in
            self?.emit(.error(BridgeErrorShape(name: "SESSION_EXPIRED", phase: BridgePhase.advertising)))
            self?.abort(reason: "timeout")
        }
        t.resume()
        advertiseTimer?.cancel()
        advertiseTimer = t
    }
    private var advertiseTimer: DispatchSourceTimer?

    public func beginTransfer() {
        guard let keys, let merchant else { return }
        guard peerAuthLevel != .keysOnly else {
            fail("PEER_NOT_AUTHENTICATED", phase: BridgePhase.transfer, detail: "keys-only session cannot transfer")
            return
        }
        setState(.transfer)
        let ciphertext: Data
        do {
            ciphertext = try DeceiptCrypto.aesGcmSeal(
                key: keys.kM2cPayload,
                nonce: DeceiptCrypto.aeadNonce(counter: 0),
                aad: sessionContext() + Data([0x01]),
                plaintext: merchant.receiptCose1
            )
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer); return }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.transfer); return }

        let frameSize = negotiatedFrameSize > 0 ? negotiatedFrameSize : min(DeceiptBounds.maxFramePayloadForMtu(transport.attMtu), DeceiptBounds.maxFramePayload)
        let frames = FrameCodec.split(ciphertext: ciphertext, transferId: merchant.transferId, frameSize: frameSize)
        let hash = DeceiptCrypto.sha256(ciphertext)

        // TRANSFER_BEGIN (AEAD control)
        let begin = CborValue.map([
            (.int(1), .uint(DeceiptMessageType.transferBegin)),
            (.int(2), .bytes(merchant.transferId)),
            (.int(3), .int(Int64(ciphertext.count))),
            (.int(4), .bytes(hash)),
            (.int(5), .int(Int64(frameSize))),
            (.int(6), .int(Int64(frames.count))),
        ])
        do { try sendControl(CborEncoder.encode(begin), direction: .m2c) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer); return }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.transfer); return }

        emit(.transferStarted(ciphertextLength: ciphertext.count, frameCount: frames.count, frameSize: frameSize, payloadHashHex: DeceiptBytes.hex(hash)))
        frameSender = FrameSender(frames: frames, transport: transport, window: DeceiptBounds.windowFrames,
                                  onProgress: { [weak self] seq, count in
                                      self?.emit(.transferProgress(highestContiguousSequence: seq, frameCount: count, notices: []))
                                  },
                                  onExhausted: { [weak self] in
                                      self?.fail("TRANSFER_RETRY_EXHAUSTED", phase: BridgePhase.transfer)
                                  })
        frameSender?.start { [weak self] in
            guard let self, let merchant = self.merchant else { return }
            // TRANSFER_COMPLETE (AEAD control)
            let complete = CborValue.map([
                (.int(1), .uint(DeceiptMessageType.transferComplete)),
                (.int(2), .bytes(merchant.transferId)),
                (.int(3), .int(Int64(frames.count))),
                (.int(4), .bytes(hash)),
            ])
            try? self.sendControl(CborEncoder.encode(complete), direction: .m2c)
            self.emit(.transferComplete(frameCount: frames.count, payloadHashHex: DeceiptBytes.hex(hash)))
        }
    }

    // MARK: Customer

    public func configureCustomer(_ config: CustomerConfig) {
        customer = config
        startSessionTimer()
    }

    public func startScan() {
        setState(.scanning)
        transport.startScan()
    }

    public func connectCustomer(peripheralId: String) {
        setState(.connected)
        transport.connect(peripheralId: peripheralId)
    }

    private func sendClientHello() {
        guard let customer else { return }
        let qr = customer.qr
        let nonce = DeceiptCrypto.randomBytes(32)
        let proof: Data
        do {
            proof = try DeceiptBinding.bindingProof(sbt: qr.sessionBindingToken, clientNonce: nonce,
                                                    clientEphemeralPubkey: localEphemeral.publicKeyBytes)
        } catch { fail("BINDING_PROOF_INVALID", phase: BridgePhase.binding); return }
        let hello = ClientHelloMsg(protocolVersion: UInt64(DeceiptProto.protocolVersion), cryptoSuites: [UInt64(DeceiptProto.suiteId)],
                                   sessionId: qr.sessionId, clientNonce: nonce,
                                   clientEphemeralPubkey: localEphemeral.publicKeyBytes, bindingProof: proof,
                                   maxFramePayload: UInt64(customer.clientMaxFramePayload))
        setState(.handshake)
        emit(.handshakeStarted(role: "customer"))
        lastClientHello = hello
        do { try sendControl(DeceiptHandshake.encodeClientHello(hello), direction: .c2m, plaintext: true) }
        catch { fail("TRANSPORT_WRITE_FAILED", phase: BridgePhase.handshake) }
    }

    public func acceptOffer() {
        guard peerAuthLevel != .keysOnly else {
            fail("PEER_NOT_AUTHENTICATED", phase: BridgePhase.transfer, detail: "SessionKeysOnly must not send ACCEPT")
            return
        }
        guard let transferId = expectedTransferId else { return }
        let msg = CborValue.map([
            (.int(1), .uint(DeceiptMessageType.accept)),
            (.int(2), .bytes(transferId)),
            (.int(3), .uint(UInt64(DeceiptProto.protocolVersion))),
            (.int(4), .uint(UInt64(DeceiptProto.suiteId))),
        ])
        do { try sendControl(CborEncoder.encode(msg), direction: .c2m) }
        catch { fail("TRANSPORT_WRITE_FAILED", phase: BridgePhase.transfer) }
        setState(.transfer)
    }

    public func requestRetry(fromSequence: Int64) {
        frameSender?.retransmit(from: fromSequence)
    }

    public func sendReceiptAck(receiptId: Data, outcomeCode: Int) {
        guard let transferId = expectedTransferId else { return }
        let msg = CborValue.map([
            (.int(1), .uint(DeceiptMessageType.receiptAck)),
            (.int(2), .bytes(transferId)),
            (.int(3), .bytes(receiptId)),
            (.int(4), .int(Int64(outcomeCode))),
        ])
        do { try sendControl(CborEncoder.encode(msg), direction: .c2m) }
        catch { fail("TRANSPORT_WRITE_FAILED", phase: BridgePhase.receipt) }
        setState(.acked)
        emit(.receiptAckSent(receiptIdHex: DeceiptBytes.hex(receiptId), outcomeCode: outcomeCode))
        teardownReason = "completed"
        stopSession()
    }

    public func cancel() {
        teardownReason = "user_cancelled"
        // Send CANCEL if keys exist; otherwise just disconnect.
        if keys != nil {
            var map: [(CborValue, CborValue)] = [(.int(1), .uint(DeceiptMessageType.cancel))]
            if let tid = expectedTransferId { map.append((.int(2), .bytes(tid))) }
            map.append((.int(3), .int(Int64(DeceiptErrors.spec("USER_CANCELLED").code))))
            if let body = try? CborEncoder.encode(.map(map)) { try? sendControl(body, direction: role == .customer ? .c2m : .m2c) }
        }
        abort(reason: "user_cancelled")
    }

    public func stopSession() {
        teardown(reason: teardownReason)
    }

    // MARK: Inbound control

    private func ingestCommand(_ fragment: Data) {
        guard role == .merchant else { return } // customer receives on EVENT
        guard let pdu = tryFeedLpdu(fragment) else { return }
        handleControl(pdu, from: .c2m)
    }

    private func ingestEvent(_ fragment: Data) {
        guard role == .customer else { return } // merchant receives on COMMAND
        guard let pdu = tryFeedLpdu(fragment) else { return }
        handleControl(pdu, from: .m2c)
    }

    private func tryFeedLpdu(_ fragment: Data) -> Data? {
        do { return try lpduRx.feed(fragment) }
        catch let f as DeceiptFailure {
            if f.bridge.retryable {
                // LPDU reassembly timeout is retryable; surface a non-fatal notice.
                emit(.transferProgress(highestContiguousSequence: -1, frameCount: 0, notices: [f.bridge.name]))
                return nil
            }
            fail(f.bridge.name, phase: BridgePhase.transfer)
            return nil
        } catch { fail("INTERNAL_ERROR", phase: BridgePhase.transfer); return nil }
    }

    private func handleControl(_ pdu: Data, from direction: DeceiptDirection) {
        guard let tag = pdu.first else { return }
        let isPlaintext = tag == DeceiptEnvelope.plaintext
        // ClientHello/ServerHello are plaintext; ERROR may be plaintext pre-key.
        if isPlaintext {
            if role == .merchant, direction == .c2m {
                handleClientHello(pdu)
            } else if role == .customer, direction == .m2c {
                handleServerHello(pdu)
            } else {
                fail("MESSAGE_WRONG_DIRECTION", phase: BridgePhase.handshake)
            }
            return
        }
        // AEAD envelope
        let channel = direction == .c2m ? c2mChannel : m2cChannel
        guard let channel else {
            fail("MESSAGE_WRONG_STATE", phase: BridgePhase.handshake, detail: "AEAD before keys")
            return
        }
        let body: Data
        do { body = try channel.open(pdu) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer); return }
        catch { fail("AEAD_AUTH_FAILED", phase: BridgePhase.transfer); return }
        handleControlMessageBody(body, from: direction)
    }

    private func handleControlMessageBody(_ body: Data, from direction: DeceiptDirection) {
        guard let msg = try? CborDecoder.decode(body), let type = msg.field(1)?.asUInt else {
            fail("CBOR_MALFORMED", phase: BridgePhase.transfer)
            return
        }
        switch UInt64(type) {
        case DeceiptMessageType.accept: handleAccept(msg)
        case DeceiptMessageType.ack: handleAck(msg)
        case DeceiptMessageType.receiptAck: handleReceiptAck(msg)
        case DeceiptMessageType.cancel: abort(reason: "peer_error")
        case DeceiptMessageType.retry: handleRetry(msg)
        case DeceiptMessageType.receiptOffer:
            if role == .merchant { handleReceiptAck(msg) } else { handleReceiptOffer(msg) }
        case DeceiptMessageType.transferBegin: handleTransferBegin(msg)
        case DeceiptMessageType.transferComplete: handleTransferComplete(msg)
        case DeceiptMessageType.error: handlePeerError(msg)
        default:
            fail("MESSAGE_UNKNOWN_TYPE", phase: BridgePhase.transfer)
        }
    }

    // MARK: Merchant handshake

    private func handleClientHello(_ pdu: Data) {
        guard let merchant else { return }
        let ch: ClientHelloMsg
        do { ch = try DeceiptHandshake.parseClientHello(pdu) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.handshake); return }
        catch { fail("CBOR_MALFORMED", phase: BridgePhase.handshake); return }

        // binding: session_id must match; proof must verify with the SBT.
        guard ch.sessionId == merchant.sessionId else {
            fail("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding); return
        }
        let expectedProof = try? DeceiptBinding.bindingProof(sbt: merchant.sessionBindingToken,
                                                             clientNonce: ch.clientNonce,
                                                             clientEphemeralPubkey: ch.clientEphemeralPubkey)
        guard let expectedProof, DeceiptBytes.constantTimeEqual(expectedProof, ch.bindingProof) else {
            fail("BINDING_PROOF_INVALID", phase: BridgePhase.binding); return
        }
        emit(.bindingConsumed(sessionIdHex: DeceiptBytes.hex(ch.sessionId)))

        // Build transcript, sign with the merchant device key.
        let serverEphemeral = localEphemeral.publicKeyBytes
        let serverNonce = DeceiptCrypto.randomBytes(32)
        let digest = DeceiptBinding.bindingTupleDigest(merchant.bindingTuple)
        let frameSize = min(merchantFrameSize(peerMax: Int(ch.maxFramePayload)), Int(ch.maxFramePayload))
        let transcript = DeceiptHandshake.buildTranscript(
            protocolVersion: UInt16(DeceiptProto.protocolVersion), suiteId: UInt16(DeceiptProto.suiteId),
            clientNonce: ch.clientNonce, clientEphemeralPubkey: ch.clientEphemeralPubkey,
            serverNonce: serverNonce, serverEphemeralPubkey: serverEphemeral,
            transferId: merchant.transferId, sessionId: merchant.sessionId,
            bindingTupleDigest: digest, maxFramePayload: UInt16(frameSize), bindingTuple: merchant.bindingTuple)

        let signature: Data
        do { signature = try DeceiptCrypto.ed25519Sign(seed: merchant.deviceSigningSeed, message: transcript) }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.handshake); return }

        let sh = ServerHelloMsg(protocolVersion: UInt64(DeceiptProto.protocolVersion), suiteId: UInt64(DeceiptProto.suiteId),
                                transferId: merchant.transferId, serverNonce: serverNonce,
                                serverEphemeralPubkey: serverEphemeral, merchantCredential: merchant.credentialBytes,
                                transcriptSignature: signature, bindingTupleDigest: digest,
                                bindingTuple: merchant.bindingTuple, maxFramePayload: UInt64(frameSize))
        do { try sendControl(DeceiptHandshake.encodeServerHello(sh), direction: .m2c, plaintext: true) }
        catch { fail("TRANSPORT_WRITE_FAILED", phase: BridgePhase.handshake); return }

        negotiatedFrameSize = frameSize
        // Merchant derives keys immediately (handshake.md §2).
        do {
            keys = try DeceiptHandshake.deriveSessionKeys(localEphemeral: localEphemeral,
                                                          peerEphemeralPubkey: ch.clientEphemeralPubkey,
                                                          transcript: transcript, transferId: merchant.transferId)
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.handshake); return }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.handshake); return }
        makeChannels()
        peerAuthLevel = merchant.credentialResult.trust == .authenticated ? .authenticated : .unverifiedPeer
        emit(.sessionKeysDerived)
        if peerAuthLevel == .authenticated {
            emit(.sessionAuthenticated(merchantId: merchant.merchantId, deviceKeyId: merchant.deviceKeyId,
                                       credentialBytes: merchant.credentialBytes, credential: merchant.credentialResult))
        } else {
            emit(.sessionUnverifiedPeer(merchantId: merchant.merchantId, deviceKeyId: merchant.deviceKeyId,
                                        credentialBytes: merchant.credentialBytes, credential: merchant.credentialResult))
        }
        setState(.merchantSessionAuthenticated)
        emit(.offerAccepted)
        // Send the offer.
        sendReceiptOffer()
    }

    private func merchantFrameSize(peerMax: Int) -> Int {
        min(DeceiptBounds.maxFramePayloadForMtu(transport.attMtu), peerMax)
    }

    private func sendReceiptOffer() {
        guard let merchant else { return }
        let credentialHash = DeceiptCrypto.sha256(merchant.credentialBytes)
        let offerHash = DeceiptBinding.computeOfferHash(.init(
            sessionId: merchant.sessionId, transferId: merchant.transferId, receiptId: merchant.receiptId,
            merchantReference: merchant.offer.merchantReference, totalAmountMinor: merchant.offer.totalAmountMinor,
            currency: merchant.offer.currency, issuedAtUnix: merchant.offer.issuedAt))
        let msg = CborValue.map([
            (.int(1), .uint(DeceiptMessageType.receiptOffer)),
            (.int(2), .bytes(merchant.transferId)),
            (.int(3), .bytes(merchant.receiptId)),
            (.int(4), .text(merchant.offer.merchantReference)),
            (.int(5), .int(merchant.offer.totalAmountMinor)),
            (.int(6), .text(merchant.offer.currency)),
            (.int(7), .int(merchant.offer.issuedAt)),
            (.int(8), .int(merchant.offer.kind)),
            (.int(9), .int(Int64(merchant.receiptCose1.count) + 16)),
            (.int(10), .bytes(merchant.merchantId)),
            (.int(11), .bytes(credentialHash)),
            (.int(12), .bytes(merchant.sessionId)),
        ])
        if (try? sendControl(CborEncoder.encode(msg), direction: .m2c)) != nil {
            setState(.receiptOffered)
            _ = offerHash
        }
    }

    // MARK: Customer handshake

    private func handleServerHello(_ pdu: Data) {
        guard let customer else { return }
        let sh: ServerHelloMsg
        do { sh = try DeceiptHandshake.parseServerHello(pdu, offeredSuites: [UInt64(DeceiptProto.suiteId)]) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.handshake); return }
        catch { fail("CBOR_MALFORMED", phase: BridgePhase.handshake); return }

        // The customer rebuilt CLIENT_HELLO locally when it sent it; keep it.
        guard let ch = lastClientHello else { fail("INTERNAL_ERROR", phase: BridgePhase.handshake); return }
        let rebuild: DeceiptHandshake.TranscriptRebuild
        do { rebuild = try DeceiptHandshake.rebuildTranscript(clientHello: ch, serverHello: sh) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.handshake); return }
        catch { fail("HANDSHAKE_TRANSCRIPT_MISMATCH", phase: BridgePhase.handshake); return }

        // Credential verification: trust split.
        let cred: CredentialVerificationResult
        do { cred = try DeceiptCredential.verify(credentialBytes: sh.merchantCredential, anchors: customer.anchors, nowUnix: customer.nowUnix) }
        catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.credential); return }
        catch { fail("CREDENTIAL_MALFORMED", phase: BridgePhase.credential); return }

        // The transcript signature is checked against the credential's device key
        // (either the anchor-authorized key or the self-asserted one).
        guard let deviceKey = cred.devicePublicKey else {
            fail("CREDENTIAL_MALFORMED", phase: BridgePhase.credential); return
        }
        guard DeceiptCrypto.ed25519Verify(publicKey: deviceKey, signature: sh.transcriptSignature, message: rebuild.transcript) else {
            fail("HANDSHAKE_SIGNATURE_INVALID", phase: BridgePhase.handshake); return
        }
        // The binding tuple's offer_hash must equal the QR value.
        guard rebuild.tuple.offerHash == customer.qr.offerHash else {
            fail("BINDING_PROOF_INVALID", phase: BridgePhase.binding, detail: "offer_hash != QR"); return
        }

        do {
            keys = try DeceiptHandshake.deriveSessionKeys(localEphemeral: localEphemeral, peerEphemeralPubkey: sh.serverEphemeralPubkey,
                                                          transcript: rebuild.transcript, transferId: rebuild.tuple.transferId)
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.handshake); return }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.handshake); return }
        makeChannels()
        expectedTransferId = rebuild.tuple.transferId
        negotiatedFrameSize = Int(sh.maxFramePayload)
        emit(.sessionKeysDerived)

        if cred.trust == .authenticated {
            peerAuthLevel = .authenticated
            guard let mid = cred.merchantId, let did = cred.deviceKeyId else { fail("CREDENTIAL_MALFORMED", phase: BridgePhase.credential); return }
            emit(.sessionAuthenticated(merchantId: mid, deviceKeyId: did, credentialBytes: sh.merchantCredential, credential: cred))
        } else {
            peerAuthLevel = .unverifiedPeer
            guard let mid = cred.merchantId, let did = cred.deviceKeyId else { fail("CREDENTIAL_MALFORMED", phase: BridgePhase.credential); return }
            emit(.sessionUnverifiedPeer(merchantId: mid, deviceKeyId: did, credentialBytes: sh.merchantCredential, credential: cred))
        }
    }

    private var lastClientHello: ClientHelloMsg?

    // MARK: Control handlers

    private func handleAccept(_ msg: CborValue) {
        guard role == .merchant, let tid = msg.field(2)?.asData, tid == expectedTransferId else {
            fail("TRANSFER_ID_MISMATCH", phase: BridgePhase.transfer); return
        }
        emit(.offerAccepted)
        setState(.merchantSessionAuthenticated)
    }

    private func handleAck(_ msg: CborValue) {
        guard let seq = msg.field(3)?.asInt else { return }
        frameSender?.acknowledge(highestContiguous: seq)
    }

    private func handleRetry(_ msg: CborValue) {
        guard let from = msg.field(3)?.asInt else { return }
        frameSender?.retransmit(from: from)
    }

    private func handleReceiptAck(_ msg: CborValue) {
        guard let rid = msg.field(3)?.asData else { return }
        teardownReason = "completed"
        emit(.receiptAckSent(receiptIdHex: DeceiptBytes.hex(rid), outcomeCode: Int(msg.field(4)?.asInt ?? 0)))
        setState(.acked)
        teardown(reason: "completed")
    }

    private func handleReceiptOffer(_ msg: CborValue) {
        guard role == .customer else { return }
        guard let transferId = msg.field(2)?.asData, transferId == expectedTransferId,
              let receiptId = msg.field(3)?.asData,
              let merchantRef = msg.field(4)?.asText,
              let total = msg.field(5)?.asInt,
              let currency = msg.field(6)?.asText,
              let issuedAt = msg.field(7)?.asInt,
              let kind = msg.field(8)?.asInt,
              let ciphertextLength = msg.field(9)?.asInt,
              let merchantId = msg.field(10)?.asData,
              let credentialHash = msg.field(11)?.asData,
              let sessionId = msg.field(12)?.asData else {
            fail("MESSAGE_MISSING_FIELD", phase: BridgePhase.transfer); return
        }
        // Recompute the offer hash from labels 3,4,5,6,7,10 and compare to the QR.
        let recomputed = DeceiptBinding.computeOfferHash(.init(
            sessionId: sessionId, transferId: transferId, receiptId: receiptId,
            merchantReference: merchantRef, totalAmountMinor: total, currency: currency, issuedAtUnix: issuedAt))
        guard let qr = customer?.qr, recomputed == qr.offerHash else {
            fail("WRONG_TRANSACTION", phase: BridgePhase.receipt, detail: "offer_hash mismatch"); return
        }
        setState(.receiptOffered)
        emit(.offerReceived(offer: OfferMetadataValue(
            transferIdHex: DeceiptBytes.hex(transferId), receiptIdHex: DeceiptBytes.hex(receiptId),
            merchantReference: merchantRef, totalAmountMinor: total, currency: currency, issuedAt: issuedAt,
            kind: kind, ciphertextLength: Int(ciphertextLength), merchantIdHex: DeceiptBytes.hex(merchantId),
            credentialHashHex: DeceiptBytes.hex(credentialHash), sessionIdHex: DeceiptBytes.hex(sessionId),
            offerHashHex: DeceiptBytes.hex(recomputed))))
    }

    private func handleTransferBegin(_ msg: CborValue) {
        guard role == .customer else { return }
        guard let transferId = msg.field(2)?.asData, transferId == expectedTransferId,
              let ciphertextLength = msg.field(3)?.asInt,
              let hash = msg.field(4)?.asData,
              let frameSize = msg.field(5)?.asInt,
              let frameCount = msg.field(6)?.asInt else {
            fail("MESSAGE_MISSING_FIELD", phase: BridgePhase.transfer); return
        }
        guard frameSize >= Int64(DeceiptBounds.minFramePayload), frameSize <= Int64(min(negotiatedFrameSize, DeceiptBounds.maxFramePayload)) else {
            fail("FRAME_SIZE_INVALID", phase: BridgePhase.transfer, detail: "frame_size"); return
        }
        payloadHash = hash
        do {
            frameReceiver = try FrameReceiver(transferId: transferId, ciphertextLength: Int(ciphertextLength), frameSize: Int(frameSize), frameCount: Int(frameCount))
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer); return }
        catch { fail("TRANSFER_BEGIN_MISMATCH", phase: BridgePhase.transfer); return }
        setState(.transfer)
        emit(.transferStarted(ciphertextLength: Int(ciphertextLength), frameCount: Int(frameCount), frameSize: Int(frameSize), payloadHashHex: DeceiptBytes.hex(hash)))
        armTransferIdleTimer()
    }

    private func handleTransferComplete(_ msg: CborValue) {
        guard role == .customer else { return }
        guard let frameCount = msg.field(3)?.asInt, let hash = msg.field(4)?.asData else { return }
        guard let receiver = frameReceiver, let ciphertext = receiver.reassembledCiphertext else {
            fail("TRANSFER_INCOMPLETE", phase: BridgePhase.transfer); return
        }
        guard frameCount == Int64(receiver.frameCountValue), hash == DeceiptCrypto.sha256(ciphertext) else {
            fail("TRANSFER_HASH_MISMATCH", phase: BridgePhase.transfer); return
        }
        setState(.ciphertextReassembled)
        emit(.transferComplete(frameCount: Int(frameCount), payloadHashHex: DeceiptBytes.hex(hash)))

        // AEAD open -> RECEIPT_UNTRUSTED. Decryption success is NOT trust.
        guard let keys else { return }
        let plaintext: Data
        do {
            plaintext = try DeceiptCrypto.aesGcmOpen(key: keys.kM2cPayload, nonce: DeceiptCrypto.aeadNonce(counter: 0),
                                                     aad: sessionContext() + Data([0x01]), ciphertextAndTag: ciphertext)
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer); return }
        catch { fail("AEAD_AUTH_FAILED", phase: BridgePhase.transfer); return }
        setState(.sessionDecrypted)
        setState(.receiptUntrusted)
        emit(.receiptReceived(coseSign1: plaintext, payloadSha256Hex: DeceiptBytes.hex(DeceiptCrypto.sha256(plaintext)), ciphertextLength: ciphertext.count))
    }

    private func handlePeerError(_ msg: CborValue) {
        let code = msg.field(2)?.asInt ?? 0
        let name = DeceiptErrors.table.first { $0.value.code == UInt16(truncatingIfNeeded: code) }?.key ?? "INTERNAL_ERROR"
        emit(.error(BridgeErrorShape(name: name, phase: BridgePhase.transfer)))
        abort(reason: "peer_error")
    }

    // MARK: Outbound control

    private func sendControl(_ body: Data, direction: DeceiptDirection, plaintext: Bool = false) throws {
        let channel = direction == .c2m ? c2mChannel : m2cChannel
        let pdu: Data
        if plaintext {
            pdu = body
        } else {
            guard let channel else { throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.transfer, detail: "no keys") }
            pdu = try channel.seal(body)
        }
        let fragments = try Lpdu.segment(pdu: pdu, msgSeq: lpduTxSeq, fragPayloadMax: transport.fragmentPayloadMax)
        lpduTxSeq = lpduTxSeq &+ 1
        for frag in fragments {
            let ok: Bool
            if direction == .c2m {
                ok = transport.sendCommand(frag) // customer → merchant COMMAND
            } else {
                ok = transport.sendEvent(frag)   // merchant → customer EVENT
            }
            if !ok { throw DeceiptFailure("TRANSPORT_WRITE_FAILED", phase: BridgePhase.transfer) }
        }
    }

    private func sessionContext() -> Data {
        (keys?.sessionContext) ?? Data()
    }

    private func makeChannels() {
        guard let keys else { return }
        let ctx = keys.sessionContext
        c2mChannel = ControlChannel(key: keys.kC2mCtrl, direction: .c2m, sessionContext: ctx)
        m2cChannel = ControlChannel(key: keys.kM2cCtrl, direction: .m2c, sessionContext: ctx)
    }

    // MARK: Frames inbound (customer)

    private func ingestDataFrame(_ bytes: Data) {
        guard role == .customer, let receiver = frameReceiver else { return }
        do {
            let frame = try FrameCodec.parse(bytes)
            let progress = try receiver.feed(frame)
            if !progress.notices.isEmpty {
                emit(.transferProgress(highestContiguousSequence: progress.highestContiguousSequence, frameCount: progress.frameCount, notices: progress.notices))
            }
            // ACK policy: every ACK_EVERY_FRAMES, or on a gap stall.
            if progress.highestContiguousSequence >= 0 {
                sendAckIfNeeded(progress)
            }
            armTransferIdleTimer()
        } catch let f as DeceiptFailure { fail(f.bridge.name, phase: BridgePhase.transfer) }
        catch { fail("INTERNAL_ERROR", phase: BridgePhase.transfer) }
    }

    private var lastAcked: Int64 = -1

    private func sendAckIfNeeded(_ progress: FrameReceiver.Progress) {
        if progress.highestContiguousSequence - lastAcked >= Int64(DeceiptBounds.ackEveryFrames) || progress.complete {
            lastAcked = progress.highestContiguousSequence
            guard let tid = expectedTransferId else { return }
            let msg = CborValue.map([
                (.int(1), .uint(DeceiptMessageType.ack)),
                (.int(2), .bytes(tid)),
                (.int(3), .int(progress.highestContiguousSequence)),
            ])
            try? sendControl(CborEncoder.encode(msg), direction: .c2m)
        }
    }

    // MARK: Link / lifecycle

    private func handleConnected(mtu: Int) {
        guard !tornDown else { return }
        setState(.connected)
        emit(.connected(peripheralId: "peer", attMtu: mtu))
        emit(.mtuChanged(attMtu: mtu, frameSizeCeiling: DeceiptBounds.maxFramePayloadForMtu(mtu)))
        if role == .customer {
            sendClientHello()
        }
    }

    private func handleLinkLost(reason: String) {
        guard !tornDown else { return }
        emit(.disconnected(reason: "link_lost", error: nil))
        abort(reason: "link_lost")
    }

    private func armTransferIdleTimer() {
        transferIdleTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + .milliseconds(timeouts["T_TRANSFER_IDLE"] ?? 10_000))
        t.setEventHandler { [weak self] in
            guard let self, self.state == .transfer else { return }
            self.fail("TRANSFER_TIMEOUT", phase: BridgePhase.transfer)
        }
        t.resume()
        transferIdleTimer = t
    }

    private func startSessionTimer() {
        sessionTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + .milliseconds(timeouts["T_SESSION"] ?? 120_000))
        t.setEventHandler { [weak self] in
            guard let self, !self.tornDown else { return }
            self.emit(.error(BridgeErrorShape(name: "SESSION_EXPIRED", phase: BridgePhase.internal)))
            self.abort(reason: "timeout")
        }
        t.resume()
        sessionTimer = t
    }

    private func abort(reason: String) {
        teardownReason = reason
        teardown(reason: reason)
    }

    /// Teardown: stop advertising/scanning, disconnect, zeroize keys and buffers,
    /// drop the session record (handshake.md §8).
    public func teardown(reason: String) {
        lock.lock(); defer { lock.unlock() }
        guard !tornDown else { return }
        tornDown = true
        advertiseTimer?.cancel(); advertiseTimer = nil
        sessionTimer?.cancel(); sessionTimer = nil
        transferIdleTimer?.cancel(); transferIdleTimer = nil
        transport.stopAdvertising()
        transport.stopScan()
        transport.disconnect()
        frameSender?.stop()
        c2mChannel?.zeroize(); c2mChannel = nil
        m2cChannel?.zeroize(); m2cChannel = nil
        keys?.zeroize(); keys = nil
        var receipt = merchant?.receiptCose1 ?? Data()
        DeceiptBytes.zeroize(&receipt)
        var sbt = merchant?.sessionBindingToken ?? Data()
        DeceiptBytes.zeroize(&sbt)
        customer?.qr.zeroize()
        frameReceiver = nil
        frameSender = nil
        setState(state == .aborted || state == .disconnect ? state : (reason == "completed" ? .disconnect : .aborted))
        emit(.tornDown(reason: reason))
    }
}
