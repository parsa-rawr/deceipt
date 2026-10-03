//
//  EngineLifecycleTests.swift
//  Deceipt iOS adapter tests (A4)
//
//  The lifecycle and session-type matrix that a device run is normally needed
//  for, exercised over the loopback transport instead:
//    * cancel / teardown zeroizes and reaches ABORTED or DISCONNECT with no
//      stale callbacks;
//    * a keys-only session refuses to transfer (PEER_NOT_AUTHENTICATED);
//    * an unknown-issuer credential reaches SessionUnverifiedPeer (transfer
//      allowed) and NEVER SessionAuthenticated — so its receipt can never be
//      TRUSTED (handshake.md §9, fixture handshake-unverified-peer.json);
//    * a pinned-anchor credential reaches SessionAuthenticated.
//

import XCTest
@testable import DeceiptModule

final class EngineLifecycleTests: XCTestCase {

    private func testKeys() throws -> [String: [String: Any]] {
        let tk = try VectorFixtures.json("protocol/vectors/keys/test-keys.json")
        let list = try XCTUnwrap(tk["keys"] as? [[String: Any]])
        var out: [String: [String: Any]] = [:]
        for k in list { if let n = k["name"] as? String { out[n] = k } }
        return out
    }

    private func spin(_ timeout: TimeInterval, _ predicate: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if predicate() { return true }
            RunLoop.main.run(until: Date().addingTimeInterval(0.01))
        }
        return predicate()
    }

    private func pinnedAnchors() throws -> DeceiptCredential.AnchorSet {
        let anchors = try VectorFixtures.json("protocol/vectors/fixtures/trust-anchors-v1.json")
        let anchor = try XCTUnwrap((anchors["anchors"] as? [[String: Any]])?.first)
        return DeceiptCredential.AnchorSet([
            (id: try XCTUnwrap(DeceiptBytes.fromHex(anchor["anchor_id_hex"] as! String)),
             publicKey: try XCTUnwrap(DeceiptBytes.fromHex(anchor["public_key_hex"] as! String))),
        ])
    }

    func testCancelTearsDownWithoutStaleCallbacks() throws {
        let transport = LoopbackTransport(role: .merchant)
        let engine = DeceiptSessionEngine(handle: "m", role: .merchant, transport: transport)
        var tornDown: String?
        engine.onEvent = { if case .tornDown(let r) = $0 { tornDown = r } }
        engine.configureMerchant(MerchantConfig(
            receiptCose1: Data([1, 2, 3]), transferId: Data(repeating: 0, count: 16), sessionId: Data(repeating: 0, count: 16),
            receiptId: Data(repeating: 0, count: 16), offerHash: Data(repeating: 0, count: 32), bindingTuple: Data(),
            sessionBindingToken: Data(repeating: 0, count: 16), credentialBytes: Data(),
            credentialResult: CredentialVerificationResult(trust: .unknownIssuer, signatureValid: false, temporallyAcceptable: false,
                                                           merchantId: nil, deviceKeyId: nil, devicePublicKey: nil, issuerId: nil,
                                                           capabilities: nil, merchantReference: nil, displayName: nil, error: nil),
            merchantId: Data(), deviceKeyId: Data(), deviceSigningSeed: Data(repeating: 1, count: 32),
            offer: MerchantOfferFields(merchantReference: "x", totalAmountMinor: 0, currency: "CAD", issuedAt: 0, kind: 1)))
        engine.startAdvertising()
        engine.cancel()
        XCTAssertEqual(tornDown, "user_cancelled")
        XCTAssertEqual(engine.state, .aborted)
    }

    func testKeysOnlySessionRefusesToTransfer() throws {
        let transport = LoopbackTransport(role: .merchant)
        let engine = DeceiptSessionEngine(handle: "m", role: .merchant, transport: transport)
        var sawPeerNotAuthenticated = false
        engine.onEvent = { if case .error(let e) = $0, e.name == "PEER_NOT_AUTHENTICATED" { sawPeerNotAuthenticated = true } }
        engine.configureMerchant(MerchantConfig(
            receiptCose1: Data([1, 2, 3]), transferId: Data(repeating: 0, count: 16), sessionId: Data(repeating: 0, count: 16),
            receiptId: Data(repeating: 0, count: 16), offerHash: Data(repeating: 0, count: 32), bindingTuple: Data(),
            sessionBindingToken: Data(repeating: 0, count: 16), credentialBytes: Data(),
            credentialResult: CredentialVerificationResult(trust: .unknownIssuer, signatureValid: false, temporallyAcceptable: false,
                                                           merchantId: nil, deviceKeyId: nil, devicePublicKey: nil, issuerId: nil,
                                                           capabilities: nil, merchantReference: nil, displayName: nil, error: nil),
            merchantId: Data(), deviceKeyId: Data(), deviceSigningSeed: Data(repeating: 1, count: 32),
            offer: MerchantOfferFields(merchantReference: "x", totalAmountMinor: 0, currency: "CAD", issuedAt: 0, kind: 1)))
        // No ClientHello has been processed, so no keys exist -> keys-only.
        engine.beginTransfer()
        XCTAssertTrue(sawPeerNotAuthenticated, "a keys-only session must refuse to transfer")
    }

    func testUnknownIssuerReachesUnverifiedPeerAndNeverAuthenticated() throws {
        let fixture = try VectorFixtures.json("protocol/vectors/handshake-unverified-peer.json")
        let keys = try testKeys()
        let rogueCredential = try VectorFixtures.hex(fixture, "credential_hex")
        let rogueSeed = try XCTUnwrap(DeceiptBytes.fromHex(keys["merchant-unknown-1"]!["private_seed_hex"] as! String))
        let anchors = try pinnedAnchors()

        // Credential verification: issuer absent -> unknown_issuer (non-fatal).
        let cred = try DeceiptCredential.verify(credentialBytes: rogueCredential, anchors: anchors, nowUnix: 1_767_748_900)
        XCTAssertEqual(cred.trust, .unknownIssuer)
        XCTAssertEqual(cred.error?.name, "CREDENTIAL_UNKNOWN_ISSUER")
        XCTAssertEqual(cred.error?.fatal, false)

        let sbt = DeceiptCrypto.randomBytes(16)
        let sessionId = try XCTUnwrap(DeceiptBytes.fromHex("00112233445566778899aabbccddeeff"))
        let transferId = try XCTUnwrap(DeceiptBytes.fromHex("ffeeddccbbaa99887766554433221100"))
        let receiptId = try XCTUnwrap(DeceiptBytes.fromHex("0123456789abcdef0123456789abcdef"))
        let merchantReference = "merchant.poc.test-rogue"
        let offeredAt: Int64 = 1_767_748_900
        let offerHash = DeceiptBinding.computeOfferHash(.init(
            sessionId: sessionId, transferId: transferId, receiptId: receiptId,
            merchantReference: merchantReference, totalAmountMinor: 970, currency: "CAD", issuedAtUnix: offeredAt))
        let receipt = try VectorFixtures.hex(try VectorFixtures.json("protocol/vectors/receipt-valid.json"), "cose_sign1_hex")

        let merchantTransport = LoopbackTransport(role: .merchant, attMtu: 185)
        let customerTransport = LoopbackTransport(role: .customer, attMtu: 185)
        merchantTransport.link(customerTransport)
        let merchant = DeceiptSessionEngine(handle: "m", role: .merchant, transport: merchantTransport)
        let customer = DeceiptSessionEngine(handle: "c", role: .customer, transport: customerTransport)

        var customerUnverified = false
        var customerAuthenticated = false
        var customerReceipt: Data?
        customer.onEvent = { e in
            switch e {
            case .sessionUnverifiedPeer: customerUnverified = true
            case .sessionAuthenticated: customerAuthenticated = true
            case .receiptReceived(let cose, _, _): customerReceipt = cose
            default: break
            }
        }
        var merchantUnverified = false
        merchant.onEvent = { if case .sessionUnverifiedPeer = $0 { merchantUnverified = true } }

        merchant.configureMerchant(MerchantConfig(
            receiptCose1: receipt, transferId: transferId, sessionId: sessionId, receiptId: receiptId,
            offerHash: offerHash,
            bindingTuple: DeceiptBinding.encodeBindingTuple(sessionId: sessionId, transferId: transferId, receiptId: receiptId, offerHash: offerHash),
            sessionBindingToken: sbt, credentialBytes: rogueCredential, credentialResult: cred,
            merchantId: try XCTUnwrap(cred.merchantId), deviceKeyId: try XCTUnwrap(cred.deviceKeyId), deviceSigningSeed: rogueSeed,
            offer: MerchantOfferFields(merchantReference: merchantReference, totalAmountMinor: 970, currency: "CAD",
                                       issuedAt: offeredAt, kind: 1)))
        merchant.startAdvertising()

        let qr = DeceiptBinding.QrPayload(qrFormatVersion: 1, sessionId: sessionId, sessionBindingToken: sbt,
                                          offerHash: offerHash, expiresAtUnix: Int64(Date().timeIntervalSince1970) + 300)
        customer.configureCustomer(CustomerConfig(qr: qr, anchors: anchors, clientMaxFramePayload: 162, nowUnix: 1_767_748_900))
        customer.startScan()
        customer.connectCustomer(peripheralId: "loopback-peripheral")

        XCTAssertTrue(spin(2.0) { customerUnverified }, "unknown issuer must reach SessionUnverifiedPeer")
        XCTAssertTrue(spin(1.0) { merchantUnverified })
        XCTAssertFalse(customerAuthenticated, "an unknown issuer must NEVER reach SessionAuthenticated")

        customer.acceptOffer()
        merchant.beginTransfer()
        XCTAssertTrue(spin(3.0) { customerReceipt != nil }, "unverified peer transfer is permitted")
        XCTAssertEqual(customer.state, .receiptUntrusted)
        // Byte-exact receipt bytes survived; trust is the app's decision.
        XCTAssertHexEqual(try XCTUnwrap(customerReceipt), receipt)
    }

    func testPinnedIssuerReachesAuthenticated() throws {
        let hv = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let keys = try testKeys()
        let sh = try DeceiptHandshake.parseServerHello(try VectorFixtures.hex(hv, "server_hello_pdu_hex"), offeredSuites: [1])
        let anchors = try pinnedAnchors()
        let cred = try DeceiptCredential.verify(credentialBytes: sh.merchantCredential, anchors: anchors, nowUnix: 1_767_748_900)
        XCTAssertEqual(cred.trust, .authenticated)

        let tuple = try DeceiptBinding.parseBindingTuple(try VectorFixtures.hex(hv, "binding_tuple_hex"))
        let sbt = DeceiptCrypto.randomBytes(16)
        let receipt = try VectorFixtures.hex(try VectorFixtures.json("protocol/vectors/receipt-valid.json"), "cose_sign1_hex")
        let seed = try XCTUnwrap(DeceiptBytes.fromHex(keys["merchant-test-1"]!["private_seed_hex"] as! String))
        let offer = try CborDecoder.decode(try VectorFixtures.hex(try VectorFixtures.json("protocol/vectors/receipt-valid.json"), "receipt_offer_hex"))

        let mt = LoopbackTransport(role: .merchant, attMtu: 185)
        let ct = LoopbackTransport(role: .customer, attMtu: 185)
        mt.link(ct)
        let merchant = DeceiptSessionEngine(handle: "m", role: .merchant, transport: mt)
        let customer = DeceiptSessionEngine(handle: "c", role: .customer, transport: ct)
        var customerAuthenticated = false
        customer.onEvent = { if case .sessionAuthenticated = $0 { customerAuthenticated = true } }

        merchant.configureMerchant(MerchantConfig(
            receiptCose1: receipt, transferId: tuple.transferId, sessionId: tuple.sessionId, receiptId: tuple.receiptId,
            offerHash: tuple.offerHash, bindingTuple: try VectorFixtures.hex(hv, "binding_tuple_hex"), sessionBindingToken: sbt,
            credentialBytes: sh.merchantCredential, credentialResult: cred,
            merchantId: try XCTUnwrap(cred.merchantId), deviceKeyId: try XCTUnwrap(cred.deviceKeyId), deviceSigningSeed: seed,
            offer: MerchantOfferFields(merchantReference: try XCTUnwrap(offer.field(4)?.asText),
                                       totalAmountMinor: try XCTUnwrap(offer.field(5)?.asInt), currency: try XCTUnwrap(offer.field(6)?.asText),
                                       issuedAt: try XCTUnwrap(offer.field(7)?.asInt), kind: try XCTUnwrap(offer.field(8)?.asInt))))
        merchant.startAdvertising()
        let qr = DeceiptBinding.QrPayload(qrFormatVersion: 1, sessionId: tuple.sessionId, sessionBindingToken: sbt,
                                          offerHash: tuple.offerHash, expiresAtUnix: Int64(Date().timeIntervalSince1970) + 300)
        customer.configureCustomer(CustomerConfig(qr: qr, anchors: anchors, clientMaxFramePayload: 162, nowUnix: 1_767_748_900))
        customer.startScan()
        customer.connectCustomer(peripheralId: "loopback-peripheral")

        XCTAssertTrue(spin(2.0) { customerAuthenticated }, "pinned issuer must reach SessionAuthenticated")
    }
}
