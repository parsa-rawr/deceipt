//
//  EngineLoopbackTests.swift
//  Deceipt iOS adapter tests (A4)
//
//  Drives the full merchant↔customer protocol path over the in-process
//  LoopbackTransport against the frozen vectors, with no radio. This exercises
//  the parts a bare crypto vector cannot: LPdu send/receive, AEAD control
//  channels, the transcript rebuild on the customer side, RECEIPT_OFFER
//  recompute-and-compare, DataFrame flow control, and the final AEAD open into
//  RECEIPT_UNTRUSTED.
//
//  The receipt-bytes assertion proves the exact signed container survived the
//  whole path unmodified (invariant 3).
//

import XCTest
@testable import DeceiptModule

final class EngineLoopbackTests: XCTestCase {

    private func testKeys() throws -> [String: [String: Any]] {
        let tk = try VectorFixtures.json("protocol/vectors/keys/test-keys.json")
        let keys = try XCTUnwrap(tk["keys"] as? [[String: Any]])
        var out: [String: [String: Any]] = [:]
        for k in keys { if let n = k["name"] as? String { out[n] = k } }
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

    func testFullLoopbackTransferReachesReceiptUntrusted() throws {
        let hv = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let rv = try VectorFixtures.json("protocol/vectors/receipt-valid.json")
        let keys = try testKeys()

        let receiptCose = try VectorFixtures.hex(rv, "cose_sign1_hex")
        let tuple = try DeceiptBinding.parseBindingTuple(try VectorFixtures.hex(hv, "binding_tuple_hex"))
        let offerMap = try CborDecoder.decode(try VectorFixtures.hex(rv, "receipt_offer_hex"))

        // Merchant credential + trust result (pinned anchor).
        let sh = try DeceiptHandshake.parseServerHello(try VectorFixtures.hex(hv, "server_hello_pdu_hex"), offeredSuites: [1])
        let anchors = try VectorFixtures.json("protocol/vectors/fixtures/trust-anchors-v1.json")
        let anchor = try XCTUnwrap((anchors["anchors"] as? [[String: Any]])?.first)
        let anchorSet = DeceiptCredential.AnchorSet([
            (id: try XCTUnwrap(DeceiptBytes.fromHex(anchor["anchor_id_hex"] as! String)),
             publicKey: try XCTUnwrap(DeceiptBytes.fromHex(anchor["public_key_hex"] as! String))),
        ])
        let credResult = try DeceiptCredential.verify(credentialBytes: sh.merchantCredential, anchors: anchorSet, nowUnix: 1_767_748_900)

        let offer = MerchantOfferFields(
            merchantReference: try XCTUnwrap(offerMap.field(4)?.asText),
            totalAmountMinor: try XCTUnwrap(offerMap.field(5)?.asInt),
            currency: try XCTUnwrap(offerMap.field(6)?.asText),
            issuedAt: try XCTUnwrap(offerMap.field(7)?.asInt),
            kind: try XCTUnwrap(offerMap.field(8)?.asInt)
        )
        let merchantId = try XCTUnwrap(credResult.merchantId)
        let deviceKeyId = try XCTUnwrap(credResult.deviceKeyId)
        let seed = try XCTUnwrap(DeceiptBytes.fromHex(keys["merchant-test-1"]!["private_seed_hex"] as! String))

        let merchantConfig = MerchantConfig(
            receiptCose1: receiptCose, transferId: tuple.transferId, sessionId: tuple.sessionId,
            receiptId: tuple.receiptId, offerHash: tuple.offerHash, bindingTuple: try VectorFixtures.hex(hv, "binding_tuple_hex"),
            sessionBindingToken: try XCTUnwrap(DeceiptBytes.fromHex("000102030405060708090a0b0c0d0e0f")),
            credentialBytes: sh.merchantCredential, credentialResult: credResult,
            merchantId: merchantId, deviceKeyId: deviceKeyId, deviceSigningSeed: seed, offer: offer)

        // QR: the merchant's QR names the same session/offer with the SBT above.
        let qr = DeceiptBinding.QrPayload(qrFormatVersion: 1, sessionId: tuple.sessionId,
                                          sessionBindingToken: try XCTUnwrap(DeceiptBytes.fromHex("000102030405060708090a0b0c0d0e0f")),
                                          offerHash: tuple.offerHash, expiresAtUnix: Int64(Date().timeIntervalSince1970) + 300)

        let merchantTransport = LoopbackTransport(role: .merchant, attMtu: 185)
        let customerTransport = LoopbackTransport(role: .customer, attMtu: 185)
        merchantTransport.link(customerTransport)

        let merchant = DeceiptSessionEngine(handle: "m1", role: .merchant, transport: merchantTransport)
        let customer = DeceiptSessionEngine(handle: "c1", role: .customer, transport: customerTransport)

        var merchantAuthenticated = false
        var customerOfferReceived = false
        var customerReceipt: Data?
        var customerTornDown: String?
        merchant.onEvent = { e in
            if case .sessionAuthenticated = e { merchantAuthenticated = true }
        }
        customer.onEvent = { e in
            switch e {
            case .offerReceived: customerOfferReceived = true
            case .receiptReceived(let cose, _, _): customerReceipt = cose
            case .tornDown(let r): customerTornDown = r
            default: break
            }
        }

        merchant.configureMerchant(merchantConfig)
        merchant.startAdvertising()
        customer.configureCustomer(CustomerConfig(qr: qr, anchors: anchorSet, clientMaxFramePayload: 162, nowUnix: 1_767_748_900))
        customer.startScan()
        customer.connectCustomer(peripheralId: "loopback-peripheral")

        XCTAssertTrue(spin(2.0) { merchantAuthenticated }, "merchant authenticated the customer")
        XCTAssertTrue(spin(2.0) { customerOfferReceived }, "customer received the offer")
        XCTAssertEqual(customer.state, .receiptOffered)

        // Customer accepts.
        customer.acceptOffer()
        XCTAssertTrue(spin(1.0) { merchant.state == .merchantSessionAuthenticated })

        // Merchant begins the transfer.
        XCTAssertTrue(spin(1.0) { true })
        merchant.beginTransfer()

        XCTAssertTrue(spin(3.0) { customerReceipt != nil }, "customer reached RECEIPT_UNTRUSTED")
        XCTAssertEqual(customer.state, .receiptUntrusted)
        XCTAssertHexEqual(try XCTUnwrap(customerReceipt), receiptCose, "exact signed receipt bytes survived the transfer")

        // Acknowledge and tear down cleanly.
        customer.sendReceiptAck(receiptId: tuple.receiptId, outcomeCode: 1)
        XCTAssertTrue(spin(2.0) { customerTornDown != nil }, "customer tore down after RECEIPT_ACK")
        XCTAssertEqual(customer.state, .disconnect)
    }
}
