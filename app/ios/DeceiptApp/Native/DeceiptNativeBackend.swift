//
//  DeceiptNativeBackend.swift
//  Deceipt iOS native adapter (A4) — app target
//
//  The facade the TurboModule calls. It owns the key store, the capability
//  reporter, the per-session engines/transports and the batched event stream,
//  and it exposes EXACTLY A3's `DeceiptNative` operations.
//
//  Nothing here reorders trust: successful AEAD decryption surfaces
//  `receipt_received` with state RECEIPT_UNTRUSTED and the exact bytes; the
//  engine never decides trust.
//

import Foundation
import UIKit
import CoreBluetooth
import AVFoundation
import CryptoKit

@objc(DeceiptNativeBackend)
public final class DeceiptNativeBackend: NSObject {
    private let keyStore = DeceiptKeyStore()
    private let caps = DeceiptCapabilities()
    private var sessions: [String: SessionRecord] = [:]
    private var pendingBindings: [String: PendingBinding] = [:]
    private var cachedAnchors: DeceiptCredential.AnchorSet?
    private var candidates: [String: PeerCandidate] = [:]
    private var bluetoothState = "unknown"
    private var handleCounter = 0

    /// Batched event sink (installed by the module's `subscribe`).
    private var eventQueue: [[String: Any]] = []
    private let eventLock = NSLock()
    private var flushScheduled = false
    private let flushInterval: TimeInterval = 0.016

    private final class SessionRecord {
        let handle: String
        let role: DeceiptRole
        let engine: DeceiptSessionEngine
        let transport: DeceiptBleTransport
        var merchantId: Data?
        var deviceKeyId: Data?
        var transferId: Data?
        var sessionId: Data?
        var peerLevel: PeerAuthLevel = .keysOnly
        var frameCount: Int?
        var frameSize: Int?
        var highestContiguous: Int64?
        init(handle: String, role: DeceiptRole, engine: DeceiptSessionEngine, transport: DeceiptBleTransport) {
            self.handle = handle; self.role = role; self.engine = engine; self.transport = transport
        }
    }

    private final class PendingBinding {
        let ref: String
        let qr: DeceiptBinding.QrPayload
        init(ref: String, qr: DeceiptBinding.QrPayload) { self.ref = ref; self.qr = qr }
    }

    // MARK: Capabilities & permissions

    public func capabilities() -> [String: Any] { caps.report() }

    public func permissionState() -> [String: Any] { caps.permissionReport(bluetoothState: bluetoothState) }

    public func requestPermissions(kinds: [String], completion: @escaping ([String: Any]) -> Void) {
        let group = DispatchGroup()
        if kinds.contains("bluetooth") {
            group.enter()
            // Instantiating a CBCentralManager triggers the Bluetooth prompt when
            // authorization is notDetermined.
            DispatchQueue.main.async {
                let mgr = CBCentralManager(delegate: nil, queue: .main)
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { _ = mgr; group.leave() }
            }
        }
        if kinds.contains("camera") {
            group.enter()
            AVCaptureDeviceRequest { group.leave() }
        }
        group.notify(queue: .main) { [weak self] in
            completion(self?.permissionState() ?? [:])
        }
    }

    private func AVCaptureDeviceRequest(_ done: @escaping () -> Void) {
        AVCaptureDevice.requestAccess(for: .video) { _ in done() }
    }

    public func openSettings(target: String) {
        DispatchQueue.main.async {
            // iOS has no public deep link to the Bluetooth pane; try the
            // documented settings URL (honest fallback), then the historical
            // App-Prefs route when the platform still honours it.
            var url: URL? = URL(string: UIApplication.openSettingsURLString)
            if target == "bluetooth" {
                if let bt = URL(string: "App-Prefs:root=Bluetooth") { url = bt }
            }
            if let url, UIApplication.shared.canOpenURL(url) {
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
            } else if let fallback = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(fallback, options: [:], completionHandler: nil)
            }
        }
    }

    // MARK: Merchant keys & signing

    public func merchantKeyStatus() -> [String: Any] {
        guard let key = keyStore.load() else { return ["provisioned": false] }
        var d: [String: Any] = [
            "provisioned": true,
            "identity": identityDict(key),
        ]
        if let cred = key.credential {
            d["credentialB64"] = DeceiptBytes.base64(cred)
            if let mid = key.merchantId { d["merchantIdHex"] = DeceiptBytes.hex(mid) }
        }
        return d
    }

    private func identityDict(_ key: DeceiptKeyStore.StoredKey) -> [String: Any] {
        var d: [String: Any] = [
            "deviceKeyIdHex": DeceiptBytes.hex(key.deviceKeyId),
            "devicePublicKeyB64": DeceiptBytes.base64(keyStore.publicKeyBytes(key) ?? Data()),
            "storage": "keychain_software",
        ]
        if key.createdAtMs > 0 { d["createdAtMs"] = NSNumber(value: key.createdAtMs) }
        return d
    }

    public func merchantKeyGenerate() throws -> [String: Any] {
        let key = try keyStore.generate()
        return identityDict(key)
    }

    public func merchantKeyDelete() { keyStore.delete() }

    // MARK: Secure randomness (WebCrypto is absent on RN 0.87 Hermes)

    /// Returns `count` bytes from the platform CSPRNG as padded standard base64.
    /// Bound 1..64 (documented); a JS PRNG is never acceptable for protocol
    /// secrets. The bytes are never logged.
    public func randomBytes(count: Int) throws -> String {
        guard (1...64).contains(count) else {
            throw DeceiptFailure("CAPABILITY_UNAVAILABLE", phase: BridgePhase.internal, detail: "randomBytes count must be 1..64")
        }
        return DeceiptBytes.base64(DeceiptCrypto.randomBytes(count))
    }

    // MARK: Test-only provisioning (gated)

    /// Imports the published PoC test device key + credential. Dev builds only:
    /// refuses with CAPABILITY_UNAVAILABLE unless `testProvisioningEnabled`.
    public func provisionTestMerchant(_ request: [String: Any]) throws -> [String: Any] {
        guard DeceiptCapabilities.testProvisioningEnabled else {
            throw DeceiptFailure("CAPABILITY_UNAVAILABLE", phase: BridgePhase.keys, detail: "test provisioning is disabled in this build")
        }
        guard let seedB64 = request["deviceSeedB64"] as? String, let seed = DeceiptBytes.fromBase64(seedB64), seed.count == 32,
              let keyIdHex = request["deviceKeyIdHex"] as? String, let keyId = DeceiptBytes.fromHex(keyIdHex), keyId.count == 16,
              let credB64 = request["credentialB64"] as? String, let cred = DeceiptBytes.fromBase64(credB64) else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.keys, detail: "provisionTestMerchant request")
        }
        let merchantId = (try? DeceiptCose.parseSign1(cred, maxBytes: DeceiptBounds.maxCredentialBytes, requireCanonicalReencode: true, phase: BridgePhase.credential))
            .flatMap { try? CborDecoder.decode($0.payload) }?.field(3)?.asData
        let stored = DeceiptKeyStore.StoredKey(seed: seed, deviceKeyId: keyId,
                                               createdAtMs: Int64(Date().timeIntervalSince1970 * 1000),
                                               credential: cred, merchantId: merchantId)
        try keyStore.persist(stored)
        return merchantKeyStatus()
    }

    public func clearTestProvisioning() {
        keyStore.delete()
    }

    public func merchantPublicIdentity() -> [String: Any]? {
        guard let key = keyStore.load() else { return nil }
        return identityDict(key)
    }

    public func merchantSignReceipt(payloadB64: String) throws -> [String: Any] {
        guard let key = keyStore.load(), let priv = keyStore.privateKey(key) else {
            throw DeceiptFailure("STORAGE_FAILED", phase: BridgePhase.keys, detail: "no merchant key provisioned")
        }
        guard let payload = DeceiptBytes.fromBase64(payloadB64) else {
            throw DeceiptFailure("CBOR_MALFORMED", phase: BridgePhase.receipt, detail: "bad payload base64")
        }
        // Protected header: {1: -8, 3: receipt content type, 4: kid}
        let protectedMap = CborValue.map([
            (.int(1), .int(Int64(DeceiptProto.coseAlgEdDSA))),
            (.int(3), .text(DeceiptProto.receiptContentType)),
            (.int(4), .bytes(key.deviceKeyId)),
        ])
        let protectedRaw = try CborEncoder.encode(protectedMap)
        let sigStructure = DeceiptCose.sigStructure(protectedRaw: protectedRaw, payload: payload)
        let signature = try DeceiptCrypto.ed25519Sign(privateKey: priv, message: sigStructure)
        let container = DeceiptCose.buildSign1(protectedRaw: protectedRaw, payload: payload, signature: signature)
        return [
            "coseSign1B64": DeceiptBytes.base64(container),
            "signatureB64": DeceiptBytes.base64(signature),
            "protectedB64": DeceiptBytes.base64(protectedRaw),
            "deviceKeyIdHex": DeceiptBytes.hex(key.deviceKeyId),
        ]
    }

    public func verifyReceiptContainer(coseSign1B64: String, devicePublicKeyB64: String) throws -> [String: Any] {
        guard let cose = DeceiptBytes.fromBase64(coseSign1B64) else {
            throw DeceiptFailure("RECEIPT_CONTAINER_MALFORMED", phase: BridgePhase.receipt, detail: "bad base64")
        }
        guard let pub = DeceiptBytes.fromBase64(devicePublicKeyB64) else {
            throw DeceiptFailure("RECEIPT_CONTAINER_MALFORMED", phase: BridgePhase.receipt, detail: "bad key base64")
        }
        return try DeceiptReceipt.verifyContainer(coseSign1: cose, devicePublicKey: pub).asDictionary()
    }

    public func verifyCredential(credentialB64: String, anchors: [[String: Any]], nowUnix: Int64?) throws -> [String: Any] {
        guard let cred = DeceiptBytes.fromBase64(credentialB64) else {
            throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.credential, detail: "bad base64")
        }
        let set = anchorSet(from: anchors)
        let now = nowUnix ?? Int64(Date().timeIntervalSince1970)
        let result = try DeceiptCredential.verify(credentialBytes: cred, anchors: set, nowUnix: now)
        cachedAnchors = set
        return result.asDictionary()
    }

    private func anchorSet(from anchors: [[String: Any]]) -> DeceiptCredential.AnchorSet {
        var list: [(id: Data, publicKey: Data)] = []
        for a in anchors {
            guard let idHex = a["anchorIdHex"] as? String, let id = DeceiptBytes.fromHex(idHex),
                  let pubB64 = a["publicKeyB64"] as? String, let pub = DeceiptBytes.fromBase64(pubB64) else { continue }
            list.append((id: id, publicKey: pub))
        }
        return DeceiptCredential.AnchorSet(list)
    }

    // MARK: Session lifecycle — merchant

    public func mintBindingQr(_ request: [String: Any]) throws -> [String: Any] {
        guard let sessionIdHex = request["sessionIdHex"] as? String, let sessionId = DeceiptBytes.fromHex(sessionIdHex),
              let offerHashHex = request["offerHashHex"] as? String, let offerHash = DeceiptBytes.fromHex(offerHashHex),
              let expires = request["expiresAtUnix"] as? NSNumber else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "mintBindingQr request")
        }
        let sbt = DeceiptCrypto.randomBytes(16)
        let ref = "bind-" + DeceiptBytes.hex(DeceiptCrypto.randomBytes(8))
        let qr = DeceiptBinding.QrPayload(qrFormatVersion: 1, sessionId: sessionId, sessionBindingToken: sbt,
                                          offerHash: offerHash, expiresAtUnix: expires.int64Value)
        pendingBindings[ref] = PendingBinding(ref: ref, qr: qr)
        return [
            "bindingRef": ref,
            "qrPayload": DeceiptBinding.encodeQr(sessionId: sessionId, sessionBindingToken: sbt, offerHash: offerHash, expiresAtUnix: expires.int64Value),
            "sessionIdHex": sessionIdHex,
            "expiresAtUnix": expires,
        ]
    }

    public func startMerchantSession(_ request: [String: Any]) throws -> [String: Any] {
        guard let bindingRef = request["bindingRef"] as? String, let binding = pendingBindings[bindingRef] else {
            throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.binding, detail: "unknown bindingRef")
        }
        guard let key = keyStore.load(), let credential = key.credential else {
            throw DeceiptFailure("STORAGE_FAILED", phase: BridgePhase.keys, detail: "merchant not provisioned with a credential")
        }
        guard let receiptB64 = request["receiptCose1B64"] as? String, let receipt = DeceiptBytes.fromBase64(receiptB64) else {
            throw DeceiptFailure("RECEIPT_CONTAINER_MALFORMED", phase: BridgePhase.receipt, detail: "receiptCose1B64")
        }
        let transferId = try hexField(request, "transferIdHex")
        let sessionId = try hexField(request, "sessionIdHex")
        let receiptId = try hexField(request, "receiptIdHex")
        let offerHash = try hexField(request, "offerHashHex")

        // Offer fields are recomputed from the receipt offer in shared logic;
        // native only needs them for the RECEIPT_OFFER it emits.
        let offer = MerchantOfferFields(
            merchantReference: (request["merchantReference"] as? String) ?? "",
            totalAmountMinor: (request["totalAmountMinor"] as? NSNumber)?.int64Value ?? 0,
            currency: (request["currency"] as? String) ?? "",
            issuedAt: (request["issuedAt"] as? NSNumber)?.int64Value ?? 0,
            kind: (request["kind"] as? NSNumber)?.int64Value ?? 1)

        let credentialResult = verifyOwnCredential(credential, merchantId: key.merchantId)

        let record = try makeSession(role: .merchant)
        record.transferId = transferId; record.sessionId = sessionId
        record.merchantId = key.merchantId; record.deviceKeyId = key.deviceKeyId
        record.frameSize = (request["frameSize"] as? NSNumber)?.intValue
        record.engine.applyTimeoutOverrides(parseTimeouts(request["timeoutOverridesMs"]))

        let bindingTuple = DeceiptBinding.encodeBindingTuple(sessionId: sessionId, transferId: transferId, receiptId: receiptId, offerHash: offerHash)
        let config = MerchantConfig(
            receiptCose1: receipt, transferId: transferId, sessionId: sessionId, receiptId: receiptId,
            offerHash: offerHash, bindingTuple: bindingTuple, sessionBindingToken: binding.qr.sessionBindingToken,
            credentialBytes: credential, credentialResult: credentialResult,
            merchantId: key.merchantId ?? Data(), deviceKeyId: key.deviceKeyId, deviceSigningSeed: key.seed, offer: offer)
        record.engine.configureMerchant(config)
        record.engine.startAdvertising()
        return try snapshot(record)
    }

    private func verifyOwnCredential(_ credential: Data, merchantId: Data?) -> CredentialVerificationResult {
        // The merchant's own credential is verified against whatever pinned
        // anchor set the app has supplied. With none cached, native conservatively
        // reports unknown-issuer (never overclaiming identity).
        guard let anchors = cachedAnchors else {
            return CredentialVerificationResult(trust: .unknownIssuer, signatureValid: false, temporallyAcceptable: false,
                                                merchantId: merchantId, deviceKeyId: nil, devicePublicKey: nil,
                                                issuerId: nil, capabilities: nil, merchantReference: nil, displayName: nil,
                                                error: BridgeErrorShape(name: "CREDENTIAL_UNKNOWN_ISSUER", phase: BridgePhase.credential))
        }
        let now = Int64(Date().timeIntervalSince1970)
        if let r = try? DeceiptCredential.verify(credentialBytes: credential, anchors: anchors, nowUnix: now) { return r }
        return CredentialVerificationResult(trust: .unknownIssuer, signatureValid: false, temporallyAcceptable: false,
                                            merchantId: merchantId, deviceKeyId: nil, devicePublicKey: nil,
                                            issuerId: nil, capabilities: nil, merchantReference: nil, displayName: nil,
                                            error: BridgeErrorShape(name: "CREDENTIAL_MALFORMED", phase: BridgePhase.credential))
    }

    public func beginTransfer(handle: String, session: [String: Any]?) throws {
        guard let record = sessions[handle] else { throw DeceiptFailure("SESSION_TORN_DOWN", phase: BridgePhase.transfer, detail: "unknown handle") }
        if let session {
            let kind = session["kind"] as? String
            if kind == "SessionKeysOnly" {
                throw DeceiptFailure("PEER_NOT_AUTHENTICATED", phase: BridgePhase.transfer, detail: "SessionKeysOnly may not transfer")
            }
        }
        if record.peerLevel == .keysOnly {
            throw DeceiptFailure("PEER_NOT_AUTHENTICATED", phase: BridgePhase.transfer, detail: "peer not authenticated")
        }
        record.engine.beginTransfer()
    }

    // MARK: Session lifecycle — customer

    public func startScan() throws {
        let record = try makeSession(role: .customer)
        scanRecord = record.handle
        record.engine.startScan()
    }
    private var scanRecord: String?

    public func stopScan() throws {
        guard let handle = scanRecord, let record = sessions[handle] else { return }
        record.engine.teardown(reason: "user_cancelled")
        sessions.removeValue(forKey: handle)
        scanRecord = nil
    }

    public func startCustomerSession(_ request: [String: Any]) throws -> [String: Any] {
        guard let selection = request["selection"] as? [String: Any], let kind = selection["kind"] as? String else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "selection")
        }
        let anchors = anchorSet(from: (request["anchors"] as? [[String: Any]]) ?? [])
        cachedAnchors = anchors
        let now = Int64(Date().timeIntervalSince1970)

        var qr: DeceiptBinding.QrPayload?
        var peripheralId: String?
        // r3 is qr_mandatory_v1: the scanned QR is the only selection act.
        guard kind == "qr" else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "selection.kind must be 'qr'")
        }
        guard let payload = selection["qrPayload"] as? String else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: "qrPayload")
        }
        let parsed = try DeceiptBinding.parseQr(payload)
        if now >= parsed.expiresAtUnix {
            emit(["type": "binding_stale", "sessionHandle": "pending", "sessionIdHex": DeceiptBytes.hex(parsed.sessionId),
                  "expiredAtUnix": NSNumber(value: parsed.expiresAtUnix)])
            throw DeceiptFailure("BINDING_STALE", phase: BridgePhase.binding, detail: "checkout code expired")
        }
        qr = parsed
        // Fail closed on ambiguity: exactly one advertising candidate.
        if candidates.count == 0 {
            throw DeceiptFailure("TRANSPORT_CONNECT_TIMEOUT", phase: BridgePhase.scan, detail: "no candidate advertising the service")
        }
        if candidates.count > 1 {
            throw DeceiptFailure("TRANSPORT_PEER_AMBIGUOUS", phase: BridgePhase.scan, detail: "multiple candidates; fail closed")
        }
        peripheralId = candidates.keys.first

        // Reuse the scanning transport so the CoreBluetooth peripheral it
        // discovered is the one we connect to; otherwise the new transport has
        // an empty discovery cache and the connect fails.
        let record: SessionRecord
        if let handle = scanRecord, let existing = sessions[handle] {
            record = existing
            scanRecord = nil
        } else {
            record = try makeSession(role: .customer)
        }
        record.engine.applyTimeoutOverrides(parseTimeouts(request["timeoutOverridesMs"]))
        if let qr {
            record.sessionId = qr.sessionId
            let config = CustomerConfig(qr: qr, anchors: anchors,
                                        clientMaxFramePayload: (request["clientMaxFramePayload"] as? NSNumber)?.intValue ?? DeceiptBounds.maxFramePayload,
                                        nowUnix: now)
            record.engine.configureCustomer(config)
        }
        if let peripheralId {
            record.engine.connectCustomer(peripheralId: peripheralId)
        }
        return try snapshot(record)
    }

    public func acceptOffer(session: [String: Any]) throws {
        guard let handle = session["sessionHandle"] as? String, let record = sessions[handle] else {
            throw DeceiptFailure("SESSION_TORN_DOWN", phase: BridgePhase.transfer, detail: "unknown handle")
        }
        if (session["kind"] as? String) == "SessionKeysOnly" {
            throw DeceiptFailure("PEER_NOT_AUTHENTICATED", phase: BridgePhase.transfer, detail: "SessionKeysOnly must not send ACCEPT")
        }
        record.engine.acceptOffer()
    }

    public func retryTransfer(handle: String, fromSequence: Int) throws {
        guard let record = sessions[handle] else { throw DeceiptFailure("SESSION_TORN_DOWN", phase: BridgePhase.transfer, detail: "unknown handle") }
        record.engine.requestRetry(fromSequence: Int64(fromSequence))
    }

    public func sendReceiptAck(session: [String: Any], receiptIdHex: String, outcome: String) throws {
        guard let handle = session["sessionHandle"] as? String, let record = sessions[handle] else {
            throw DeceiptFailure("SESSION_TORN_DOWN", phase: BridgePhase.receipt, detail: "unknown handle")
        }
        guard let receiptId = DeceiptBytes.fromHex(receiptIdHex) else {
            throw DeceiptFailure("RECEIPT_CONTAINER_MALFORMED", phase: BridgePhase.receipt, detail: "receiptIdHex")
        }
        let outcomeCode: Int
        switch outcome {
        case "trusted": outcomeCode = 1
        case "unknown_issuer": outcomeCode = 2
        case "already_imported": outcomeCode = 3
        case "rejected": outcomeCode = 4
        default: outcomeCode = 4
        }
        record.engine.sendReceiptAck(receiptId: receiptId, outcomeCode: outcomeCode)
        sessions.removeValue(forKey: handle)
    }

    public func cancelSession(handle: String, reason: String?) throws {
        guard let record = sessions[handle] else { return }
        record.engine.cancel()
        sessions.removeValue(forKey: handle)
    }

    public func stopSession(handle: String) throws {
        guard let record = sessions[handle] else { return }
        record.engine.stopSession()
        sessions.removeValue(forKey: handle)
    }

    public func sessionSnapshot(handle: String) throws -> [String: Any] {
        guard let record = sessions[handle] else {
            throw DeceiptFailure("SESSION_TORN_DOWN", phase: BridgePhase.internal, detail: "unknown handle")
        }
        return try snapshot(record)
    }

    // MARK: Session plumbing

    private func makeSession(role: DeceiptRole) throws -> SessionRecord {
        handleCounter += 1
        let handle = "s\(handleCounter)-\(DeceiptBytes.hex(DeceiptCrypto.randomBytes(4)))"
        let transport = DeceiptBleTransport(role: role)
        let engine = DeceiptSessionEngine(handle: handle, role: role, transport: transport)
        let record = SessionRecord(handle: handle, role: role, engine: engine, transport: transport)
        transport.onBluetoothState = { [weak self] state in
            self?.bluetoothState = state
            self?.emit(["type": "bluetooth_state_changed", "state": state])
        }
        transport.onAdvertisingStarted = { [weak self] in
            self?.emit(["type": "advertising_started", "sessionHandle": handle, "serviceUuid": DeceiptGatt.serviceUuid])
        }
        transport.onAdvertisingStopped = { [weak self] reason in
            self?.emit(["type": "advertising_stopped", "sessionHandle": handle, "reason": reason])
        }
        transport.onScanStarted = { [weak self] in
            self?.emit(["type": "scan_started"])
        }
        transport.onScanStopped = { [weak self] reason in
            self?.emit(["type": "scan_stopped", "reason": reason])
        }
        transport.onPeerCandidate = { [weak self] candidate in
            self?.recordCandidate(candidate)
        }
        transport.onPeerCandidateLost = { [weak self] pid in
            self?.candidates.removeValue(forKey: pid)
            self?.emit(["type": "peer_candidate_lost", "peripheralId": pid])
        }
        engine.onEvent = { [weak self] event in self?.forward(event, record: record) }
        sessions[handle] = record
        return record
    }

    private func snapshot(_ record: SessionRecord) throws -> [String: Any] {
        var d: [String: Any] = [
            "sessionHandle": record.handle,
            "role": record.role.rawValue,
            "state": record.engine.state.rawValue,
            "authenticated": record.peerLevel == .authenticated,
        ]
        if let v = record.transferId { d["transferIdHex"] = DeceiptBytes.hex(v) }
        if let v = record.sessionId { d["sessionIdHex"] = DeceiptBytes.hex(v) }
        d["attMtu"] = NSNumber(value: record.transport.attMtu)
        if let v = record.frameSize { d["frameSize"] = NSNumber(value: v) }
        if let v = record.frameCount { d["frameCount"] = NSNumber(value: v) }
        if let v = record.highestContiguous { d["highestContiguousSequence"] = NSNumber(value: v) }
        if let v = record.merchantId { d["merchantIdHex"] = DeceiptBytes.hex(v) }
        if let v = record.deviceKeyId { d["deviceKeyIdHex"] = DeceiptBytes.hex(v) }
        return d
    }

    private func hexField(_ request: [String: Any], _ key: String) throws -> Data {
        guard let s = request[key] as? String, let d = DeceiptBytes.fromHex(s) else {
            throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.binding, detail: key)
        }
        return d
    }

    private func parseTimeouts(_ raw: Any?) -> [String: Int]? {
        guard let m = raw as? [String: Any] else { return nil }
        var out: [String: Int] = [:]
        for (k, v) in m { if let n = v as? NSNumber { out[k] = n.intValue } }
        return out
    }

    // MARK: Event forwarding & batching

    private func forward(_ event: EngineEvent, record: SessionRecord) {
        let handle = record.handle
        switch event {
        case .connected(let pid, let mtu):
            emit(["type": "connected", "sessionHandle": handle, "peripheralId": pid, "attMtu": NSNumber(value: mtu)])
        case .mtuChanged(let mtu, let ceiling):
            emit(["type": "mtu_changed", "sessionHandle": handle, "attMtu": NSNumber(value: mtu), "frameSizeCeiling": NSNumber(value: ceiling)])
        case .disconnected(let reason, let error):
            var d: [String: Any] = ["type": "disconnected", "sessionHandle": handle, "reason": reason]
            if let error { d["error"] = error.asDictionary }
            emit(d)
        case .handshakeStarted(let role):
            emit(["type": "handshake_started", "sessionHandle": handle, "role": role])
        case .sessionKeysDerived:
            emit(["type": "session_keys_derived", "sessionHandle": handle,
                  "sessionKeysOnly": ["kind": "SessionKeysOnly", "sessionHandle": handle]])
        case .sessionAuthenticated(let mid, let did, let credBytes, let cred):
            record.peerLevel = .authenticated
            record.merchantId = mid; record.deviceKeyId = did
            emit(["type": "session_authenticated", "sessionHandle": handle,
                  "authenticated": [
                    "kind": "SessionAuthenticated", "sessionHandle": handle,
                    "merchantIdHex": DeceiptBytes.hex(mid), "deviceKeyIdHex": DeceiptBytes.hex(did),
                    "credentialB64": DeceiptBytes.base64(credBytes),
                    "credentialTrust": "authenticated", "keyAuthorized": true,
                    "credentialTemporallyAcceptable": cred.temporallyAcceptable,
                  ],
                  "credential": cred.asDictionary()])
        case .sessionUnverifiedPeer(let mid, let did, let credBytes, let cred):
            record.peerLevel = .unverifiedPeer
            record.merchantId = mid; record.deviceKeyId = did
            emit(["type": "session_unverified_peer", "sessionHandle": handle,
                  "unverifiedPeer": [
                    "kind": "SessionUnverifiedPeer", "sessionHandle": handle,
                    "merchantIdHex": DeceiptBytes.hex(mid), "deviceKeyIdHex": DeceiptBytes.hex(did),
                    "credentialB64": DeceiptBytes.base64(credBytes),
                    "credentialTrust": "unknown_issuer", "keyAuthorized": false,
                  ],
                  "credential": cred.asDictionary()])
        case .bindingConsumed(let sid):
            emit(["type": "binding_consumed", "sessionHandle": handle, "sessionIdHex": sid])
        case .bindingStale(let sid, let exp):
            emit(["type": "binding_stale", "sessionHandle": handle, "sessionIdHex": sid, "expiredAtUnix": NSNumber(value: exp)])
        case .offerReceived(let offer):
            emit(["type": "offer_received", "sessionHandle": handle, "offer": offer.asDictionary()])
        case .offerAccepted:
            emit(["type": "offer_accepted", "sessionHandle": handle])
        case .transferStarted(let len, let frames, let size, let hash):
            record.frameCount = frames; record.frameSize = size
            emit(["type": "transfer_started", "sessionHandle": handle, "ciphertextLength": NSNumber(value: len),
                  "frameCount": NSNumber(value: frames), "frameSize": NSNumber(value: size), "payloadHashHex": hash])
        case .transferProgress(let seq, let frames, let notices):
            record.highestContiguous = seq
            emit(["type": "transfer_progress", "sessionHandle": handle, "highestContiguousSequence": NSNumber(value: seq),
                  "frameCount": NSNumber(value: frames), "notices": notices])
        case .transferComplete(let frames, let hash):
            emit(["type": "transfer_complete", "sessionHandle": handle, "frameCount": NSNumber(value: frames), "payloadHashHex": hash])
        case .receiptReceived(let cose, let sha, let len):
            emit(["type": "receipt_received", "sessionHandle": handle, "state": "RECEIPT_UNTRUSTED",
                  "coseSign1B64": DeceiptBytes.base64(cose), "payloadSha256Hex": sha, "ciphertextLength": NSNumber(value: len)])
        case .receiptAckSent(let rid, let outcome):
            emit(["type": "receipt_ack_sent", "sessionHandle": handle, "receiptIdHex": rid, "outcomeCode": NSNumber(value: outcome)])
        case .tornDown(let reason):
            emit(["type": "session_torn_down", "sessionHandle": handle, "reason": reason])
        case .error(let err):
            emit(["type": "error", "error": err.asDictionary, "sessionHandle": handle])
        @unknown default:
            break
        }
    }

    // MARK: Events

    public func emit(_ event: [String: Any]) {
        eventLock.lock()
        eventQueue.append(event)
        let alreadyScheduled = flushScheduled
        flushScheduled = true
        eventLock.unlock()
        guard !alreadyScheduled else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + flushInterval) { [weak self] in
            guard let self else { return }
            self.eventLock.lock()
            self.flushScheduled = false
            let batch = self.eventQueue
            self.eventQueue.removeAll(keepingCapacity: true)
            let sink = self.nativeEventSink
            self.eventLock.unlock()
            if !batch.isEmpty { sink?(batch) }
        }
    }

    // MARK: Lifecycle

    /// Called when the RN module is invalidated (reload / unmount). Tears down
    /// every session, zeroizes keys, and drops the event sink.
    @objc public func invalidate() {
        for (_, record) in sessions { record.engine.teardown(reason: "app_shutdown"); record.transport.disconnect() }
        sessions.removeAll()
        pendingBindings.removeAll()
        eventQueue.removeAll()
        nativeEventSink = nil
    }

    /// App background/foreground. The PoC does not support background BLE, so
    /// leaving the foreground tears sessions down cleanly (no half-sessions
    /// across a suspended radio).
    @objc public func handleAppState(_ state: String) {
        guard state == "background" || state == "inactive" else { return }
        for (handle, record) in sessions {
            record.engine.teardown(reason: "app_shutdown")
            sessions.removeValue(forKey: handle)
        }
        candidates.removeAll()
    }

    // MARK: Candidate tracking (customer scan)

    public func recordCandidate(_ candidate: PeerCandidate) {
        candidates[candidate.peripheralId] = candidate
        var d: [String: Any] = [
            "type": "peer_candidate", "peripheralId": candidate.peripheralId,
            "serviceUuid": candidate.serviceUuid, "deterministicLabel": candidate.deterministicLabel,
            "diagnostics": ["diagnosticsOnly": true],
        ]
        if let v = candidate.protocolVersion { d["protocolVersion"] = NSNumber(value: v) }
        if let rssi = candidate.rssi { d["diagnostics"] = ["diagnosticsOnly": true, "rssi": NSNumber(value: rssi)] }
        emit(d)
    }

    // MARK: ObjC-facing dispatch (used by the TurboModule shim)

    /// Raw event sink invoked on the main thread with a JSON-serialisable batch.
    @objc public var nativeEventSink: (([Any]) -> Void)?

    /// Single entry point for the ObjC++ module. `args` is a JSON-safe array.
    /// Returns a JSON-safe value; on failure the `error:` out-parameter carries
    /// the bridge shape under `userInfo["bridge"]`.
    @objc(dispatchMethodName:args:error:)
    public func dispatch(method: String, args: [Any]) throws -> Any {
        do {
            return try dispatchInternal(method: method, args: args)
        } catch let f as DeceiptFailure {
            throw NSError(domain: "DeceiptBridgeError", code: Int(f.bridge.code),
                          userInfo: ["bridge": f.bridge.asDictionary,
                                     NSLocalizedDescriptionKey: f.bridge.detail ?? f.bridge.name])
        }
    }

    private func dispatchInternal(method: String, args: [Any]) throws -> Any {
        switch method {
        case "capabilities":
            return capabilities()
        case "permissionState":
            return permissionState()
        case "requestPermissions":
            return try blocking { done in
                self.requestPermissions(kinds: (args.first as? [String]) ?? [], completion: { done($0) })
            }
        case "openSettings":
            openSettings(target: (args.first as? String) ?? "app_permissions")
            return NSNull()
        case "merchantKeyStatus":
            return merchantKeyStatus()
        case "merchantKeyGenerate":
            return try merchantKeyGenerate()
        case "merchantKeyDelete":
            merchantKeyDelete(); return NSNull()
        case "randomBytes":
            return try randomBytes(count: (args.first as? NSNumber)?.intValue ?? 0)
        case "merchantPublicIdentity":
            return merchantPublicIdentity() ?? NSNull()
        case "merchantSignReceipt":
            return try merchantSignReceipt(payloadB64: try str(args, 0))
        case "verifyReceiptContainer":
            return try verifyReceiptContainer(coseSign1B64: try str(args, 0), devicePublicKeyB64: try str(args, 1))
        case "verifyCredential":
            return try verifyCredential(credentialB64: try str(args, 0),
                                        anchors: (args.count > 1 ? args[1] as? [[String: Any]] : nil) ?? [],
                                        nowUnix: args.count > 2 ? (args[2] as? NSNumber)?.int64Value : nil)
        case "mintBindingQr":
            return try mintBindingQr(try dict(args, 0))
        case "startMerchantSession":
            return try startMerchantSession(try dict(args, 0))
        case "beginTransfer":
            try beginTransfer(handle: try str(args, 0), session: args.count > 1 ? args[1] as? [String: Any] : nil)
            return NSNull()
        case "startScan":
            try startScan(); return NSNull()
        case "stopScan":
            try stopScan(); return NSNull()
        case "startCustomerSession":
            return try startCustomerSession(try dict(args, 0))
        case "acceptOffer":
            try acceptOffer(session: try dict(args, 0)); return NSNull()
        case "retryTransfer":
            try retryTransfer(handle: try str(args, 0), fromSequence: (args[1] as? NSNumber)?.intValue ?? 0)
            return NSNull()
        case "sendReceiptAck":
            try sendReceiptAck(session: try dict(args, 0), receiptIdHex: try str(args, 1), outcome: try str(args, 2))
            return NSNull()
        case "cancelSession":
            try cancelSession(handle: try str(args, 0), reason: args.count > 1 ? args[1] as? String : nil)
            return NSNull()
        case "stopSession":
            try stopSession(handle: try str(args, 0)); return NSNull()
        case "sessionSnapshot":
            return try sessionSnapshot(handle: try str(args, 0))
        case "provisionTestMerchant":
            return try provisionTestMerchant(try dict(args, 0))
        case "clearTestProvisioning":
            clearTestProvisioning(); return NSNull()
        default:
            throw DeceiptFailure("CAPABILITY_UNAVAILABLE", phase: BridgePhase.internal, detail: "unknown method \(method)")
        }
    }

    private func str(_ args: [Any], _ i: Int) throws -> String {
        guard args.count > i, let s = args[i] as? String else {
            throw DeceiptFailure("MESSAGE_MISSING_FIELD", phase: BridgePhase.internal, detail: "arg \(i)")
        }
        return s
    }

    private func dict(_ args: [Any], _ i: Int) throws -> [String: Any] {
        guard args.count > i, let d = args[i] as? [String: Any] else {
            throw DeceiptFailure("MESSAGE_MISSING_FIELD", phase: BridgePhase.internal, detail: "arg \(i)")
        }
        return d
    }

    /// Runs an async completion on the main run loop and returns its value,
    /// for methods the shared contract declares as promises.
    private func blocking<T>(_ body: (@escaping (T) -> Void) -> Void) throws -> T {
        var result: T?
        let sem = DispatchSemaphore(value: 0)
        body { value in result = value; sem.signal() }
        if Thread.isMainThread {
            // Pump the run loop until the completion fires.
            let deadline = Date().addingTimeInterval(10)
            while result == nil, Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
        } else {
            _ = sem.wait(timeout: .now() + 10)
        }
        guard let v = result else {
            throw DeceiptFailure("INTERNAL_ERROR", phase: BridgePhase.permission, detail: "permission request timed out")
        }
        return v
    }
}
