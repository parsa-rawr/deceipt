//
//  ProtocolVectorTests.swift
//  Deceipt iOS adapter tests (A4)
//
//  Radio-independent protocol conformance: transcript rebuild (R4-01), the key
//  schedule, LPdu reassembly, DataFrame reassembly, COSE parsing, credential
//  verification (all three trust outcomes), offer-hash binding and the QR
//  payload. These MUST pass without a device.
//

import XCTest
@testable import DeceiptModule

final class ProtocolVectorTests: XCTestCase {

    private func testKey(_ name: String) throws -> Data {
        let tk = try VectorFixtures.json("protocol/vectors/keys/test-keys.json")
        let keys = try XCTUnwrap(tk["keys"] as? [[String: Any]])
        for k in keys where (k["name"] as? String) == name {
            return try XCTUnwrap(DeceiptBytes.fromHex(k["public_key_hex"] as! String))
        }
        throw NSError(domain: "testKey", code: 1)
    }

    // MARK: Transcript rebuild (R4-01)

    func testTranscriptRebuildFromReceivedBytes() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let chPdu = try VectorFixtures.hex(v, "client_hello_pdu_hex")
        let shPdu = try VectorFixtures.hex(v, "server_hello_pdu_hex")

        let ch = try DeceiptHandshake.parseClientHello(chPdu)
        let sh = try DeceiptHandshake.parseServerHello(shPdu, offeredSuites: [1])
        let rebuild = try DeceiptHandshake.rebuildTranscript(clientHello: ch, serverHello: sh)

        XCTAssertHexEqual(rebuild.transcript, try VectorFixtures.hex(v, "transcript_hex"), "372-byte transcript rebuild")
        XCTAssertEqual(rebuild.transcript.count, 372)
        XCTAssertHexEqual(DeceiptCrypto.sha256(rebuild.transcript), try VectorFixtures.hex(v, "transcript_hash_hex"), "transcript_hash")

        // The merchant signs the transcript with its device key.
        XCTAssertTrue(DeceiptCrypto.ed25519Verify(publicKey: try testKey("merchant-test-1"),
                                                  signature: sh.transcriptSignature, message: rebuild.transcript),
                      "transcript signature verifies against the merchant device key")

        // SERVER_HELLO label 11 is the signed max_frame_payload.
        XCTAssertEqual(sh.maxFramePayload, 162)
        XCTAssertEqual(rebuild.tuple.transferId, sh.transferId)
    }

    func testTranscriptRebuildRejectsSubstitutedTupleDigest() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let ch = try DeceiptHandshake.parseClientHello(try VectorFixtures.hex(v, "client_hello_pdu_hex"))
        var sh = try DeceiptHandshake.parseServerHello(try VectorFixtures.hex(v, "server_hello_pdu_hex"), offeredSuites: [1])
        // label 9 no longer matches digest(label 10) => HANDSHAKE_TRANSCRIPT_MISMATCH
        sh.bindingTupleDigest[sh.bindingTupleDigest.startIndex] ^= 0x01
        XCTAssertThrowsError(try DeceiptHandshake.rebuildTranscript(clientHello: ch, serverHello: sh)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "HANDSHAKE_TRANSCRIPT_MISMATCH")
        }
    }

    func testKeyScheduleFromRebuild() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let ch = try DeceiptHandshake.parseClientHello(try VectorFixtures.hex(v, "client_hello_pdu_hex"))
        let sh = try DeceiptHandshake.parseServerHello(try VectorFixtures.hex(v, "server_hello_pdu_hex"), offeredSuites: [1])
        let rebuild = try DeceiptHandshake.rebuildTranscript(clientHello: ch, serverHello: sh)

        // Customer side: client-eph-1 private scalar + server ephemeral pubkey.
        let tk = try VectorFixtures.json("protocol/vectors/keys/test-keys.json")
        let keysList = try XCTUnwrap(tk["keys"] as? [[String: Any]])
        let clientEph = try XCTUnwrap(keysList.first { ($0["name"] as? String) == "client-eph-1" })
        let scalar = try XCTUnwrap(DeceiptBytes.fromHex(clientEph["private_scalar_hex"] as! String))
        let kp = try DeceiptCrypto.EphemeralKeyPair(privateScalar: scalar)

        let keys = try DeceiptHandshake.deriveSessionKeys(localEphemeral: kp, peerEphemeralPubkey: sh.serverEphemeralPubkey,
                                                          transcript: rebuild.transcript, transferId: rebuild.tuple.transferId)
        let expected = try XCTUnwrap(v["keys"] as? [String: Any])
        XCTAssertHexEqual(keys.kC2mCtrl, try XCTUnwrap(DeceiptBytes.fromHex(expected["k_c2m_ctrl"] as! String)), "k_c2m_ctrl")
        XCTAssertHexEqual(keys.kM2cCtrl, try XCTUnwrap(DeceiptBytes.fromHex(expected["k_m2c_ctrl"] as! String)), "k_m2c_ctrl")
        XCTAssertHexEqual(keys.kM2cPayload, try XCTUnwrap(DeceiptBytes.fromHex(expected["k_m2c_payload"] as! String)), "k_m2c_payload")
    }

    // MARK: LPdu

    func testLpduReassembly() throws {
        let v = try VectorFixtures.json("protocol/vectors/lpdu-valid.json")
        let frags = try XCTUnwrap(v["fragments_hex"] as? [String])
        let expected = try VectorFixtures.hex(v, "server_hello_pdu_hex")
        let rx = LpduReceiver()
        var pdu: Data?
        for f in frags {
            let frag = try XCTUnwrap(DeceiptBytes.fromHex(f))
            if let complete = try rx.feed(frag) { pdu = complete }
        }
        XCTAssertHexEqual(try XCTUnwrap(pdu), expected, "LPdu reassembly")
    }

    func testLpduSegmentationRejectsOversize() throws {
        let big = Data(repeating: 0x00, count: DeceiptBounds.maxControlPdu + 1)
        XCTAssertThrowsError(try Lpdu.segment(pdu: big, msgSeq: 0, fragPayloadMax: 182)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "LPDU_MESSAGE_TOO_LARGE")
        }
    }

    // MARK: Frames

    func testFrameSplitMatchesVector() throws {
        let v = try VectorFixtures.json("protocol/vectors/framing-valid.json")
        let aead = try VectorFixtures.json("protocol/vectors/aead-valid.json")
        let seal = try XCTUnwrap(aead["payload_seal"] as? [String: Any])
        let ciphertext = try XCTUnwrap(DeceiptBytes.fromHex(seal["ciphertext_hex"] as! String))
        let transferId = try VectorFixtures.hex(v, "transfer_id_hex")
        let frameSize = (v["frame_size"] as? NSNumber)?.intValue ?? 162

        let frames = FrameCodec.split(ciphertext: ciphertext, transferId: transferId, frameSize: frameSize)
        XCTAssertEqual(frames.count, 6)
        let expectedHex = try XCTUnwrap(v["frames_hex"] as? [String])
        for (i, f) in frames.enumerated() {
            XCTAssertEqual(DeceiptBytes.hex(f.encoded), expectedHex[i], "frame \(i)")
        }
    }

    func testFrameReceiverReassembles() throws {
        let v = try VectorFixtures.json("protocol/vectors/framing-valid.json")
        let expectedHex = try XCTUnwrap(v["frames_hex"] as? [String])
        let transferId = try VectorFixtures.hex(v, "transfer_id_hex")
        let ciphertextLen = (v["ciphertext_len"] as? NSNumber)?.intValue ?? 814
        let frameSize = (v["frame_size"] as? NSNumber)?.intValue ?? 162
        let frameCount = (v["frame_count"] as? NSNumber)?.intValue ?? 6

        let rx = try FrameReceiver(transferId: transferId, ciphertextLength: ciphertextLen, frameSize: frameSize, frameCount: frameCount)
        var last: FrameReceiver.Progress?
        for h in expectedHex {
            let frame = try FrameCodec.parse(try XCTUnwrap(DeceiptBytes.fromHex(h)))
            last = try rx.feed(frame)
        }
        XCTAssertEqual(last?.complete, true)
        XCTAssertEqual(last?.highestContiguousSequence, 5)
        XCTAssertEqual(rx.reassembledCiphertext?.count, ciphertextLen)
    }

    func testFrameReceiverRejectsConflictingDuplicate() throws {
        let v = try VectorFixtures.json("protocol/vectors/framing-valid.json")
        let expectedHex = try XCTUnwrap(v["frames_hex"] as? [String])
        let transferId = try VectorFixtures.hex(v, "transfer_id_hex")
        let rx = try FrameReceiver(transferId: transferId, ciphertextLength: 814, frameSize: 162, frameCount: 6)
        // Feed sequence 1 first (sequence 0 missing, so it is buffered, not contiguous).
        let f1 = try FrameCodec.parse(try XCTUnwrap(DeceiptBytes.fromHex(expectedHex[1])))
        _ = try rx.feed(f1)
        // A byte-identical duplicate is a non-fatal replay notice.
        let replay = try rx.feed(f1)
        XCTAssertTrue(replay.notices.contains("FRAME_SEQUENCE_REPLAYED"))
        // A different body for the same sequence is a fatal conflict.
        var tampered = f1
        tampered.payload[tampered.payload.startIndex] ^= 0x01
        XCTAssertThrowsError(try rx.feed(tampered)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "FRAME_CONFLICT")
        }
    }

    // MARK: COSE receipt

    func testReceiptContainerVerifies() throws {
        let v = try VectorFixtures.json("protocol/vectors/receipt-valid.json")
        let cose = try VectorFixtures.hex(v, "cose_sign1_hex")
        let result = try DeceiptReceipt.verifyContainer(coseSign1: cose, devicePublicKey: try testKey("merchant-test-1"))
        XCTAssertTrue(result.signatureValid, "receipt signature valid over exact bytes")
        XCTAssertEqual(DeceiptBytes.hex(try XCTUnwrap(result.deviceKeyId)), "0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    }

    func testReceiptContainerRejectsWrongKey() throws {
        let v = try VectorFixtures.json("protocol/vectors/receipt-valid.json")
        let cose = try VectorFixtures.hex(v, "cose_sign1_hex")
        let result = try DeceiptReceipt.verifyContainer(coseSign1: cose, devicePublicKey: try testKey("merchant-unknown-1"))
        XCTAssertFalse(result.signatureValid, "unknown key must not verify")
    }

    // MARK: Credential verification

    func testCredentialAuthenticatedAgainstPinnedAnchor() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let sh = try DeceiptHandshake.parseServerHello(try VectorFixtures.hex(v, "server_hello_pdu_hex"), offeredSuites: [1])
        let anchors = try VectorFixtures.json("protocol/vectors/fixtures/trust-anchors-v1.json")
        let anchor = try XCTUnwrap((anchors["anchors"] as? [[String: Any]])?.first)
        let set = DeceiptCredential.AnchorSet([
            (id: try XCTUnwrap(DeceiptBytes.fromHex(anchor["anchor_id_hex"] as! String)),
             publicKey: try XCTUnwrap(DeceiptBytes.fromHex(anchor["public_key_hex"] as! String))),
        ])
        // now inside the credential validity window.
        let payload = try CborDecoder.decode(try DeceiptCose.parseSign1(sh.merchantCredential, maxBytes: 1024, requireCanonicalReencode: true, phase: BridgePhase.credential).payload)
        let validFrom = try XCTUnwrap(payload.field(6)?.asInt)
        let result = try DeceiptCredential.verify(credentialBytes: sh.merchantCredential, anchors: set, nowUnix: validFrom + 1)
        XCTAssertEqual(result.trust, .authenticated)
        XCTAssertTrue(result.signatureValid)
        XCTAssertTrue(result.temporallyAcceptable)
        XCTAssertEqual(DeceiptBytes.hex(try XCTUnwrap(result.merchantId)), "a1b2c3d4e5f60718293a4b5c6d7e8f90")
        XCTAssertEqual(DeceiptBytes.hex(try XCTUnwrap(result.deviceKeyId)), "0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    }

    func testCredentialUnknownIssuerIsNonFatal() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-unverified-peer.json")
        let credential = try VectorFixtures.hex(v, "credential_hex")
        // Only the pinned anchor set; the rogue issuer is absent.
        let anchors = try VectorFixtures.json("protocol/vectors/fixtures/trust-anchors-v1.json")
        let anchor = try XCTUnwrap((anchors["anchors"] as? [[String: Any]])?.first)
        let set = DeceiptCredential.AnchorSet([
            (id: try XCTUnwrap(DeceiptBytes.fromHex(anchor["anchor_id_hex"] as! String)),
             publicKey: try XCTUnwrap(DeceiptBytes.fromHex(anchor["public_key_hex"] as! String))),
        ])
        let result = try DeceiptCredential.verify(credentialBytes: credential, anchors: set, nowUnix: 1_764_634_624)
        XCTAssertEqual(result.trust, .unknownIssuer)
        XCTAssertFalse(result.signatureValid)
        XCTAssertEqual(result.error?.name, "CREDENTIAL_UNKNOWN_ISSUER")
        XCTAssertEqual(result.error?.fatal, false)
    }

    func testUnverifiedPeerTranscriptSignatureVsSelfAssertedKey() throws {
        // handshake.md §9: SessionUnverifiedPeer verifies the transcript against
        // the credential's SELF-ASSERTED device key. Internal consistency only.
        let v = try VectorFixtures.json("protocol/vectors/handshake-unverified-peer.json")
        var chPdu = try VectorFixtures.hex(v, "client_hello_hex")
        chPdu.insert(DeceiptEnvelope.plaintext, at: 0)
        var shPdu = try VectorFixtures.hex(v, "server_hello_hex")
        shPdu.insert(DeceiptEnvelope.plaintext, at: 0)
        let ch = try DeceiptHandshake.parseClientHello(chPdu)
        let sh = try DeceiptHandshake.parseServerHello(shPdu, offeredSuites: [1])
        let rebuild = try DeceiptHandshake.rebuildTranscript(clientHello: ch, serverHello: sh)
        XCTAssertHexEqual(rebuild.transcript, try VectorFixtures.hex(v, "transcript_hex"), "unverified-peer transcript")
        let selfAsserted = try VectorFixtures.hex(v, "credential_device_public_key_hex")
        XCTAssertTrue(DeceiptCrypto.ed25519Verify(publicKey: selfAsserted, signature: sh.transcriptSignature, message: rebuild.transcript),
                      "transcript signature verifies against self-asserted device key")
    }

    // MARK: Offer hash / binding proof / QR

    func testOfferHash() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let tuple = try DeceiptBinding.parseBindingTuple(try VectorFixtures.hex(v, "binding_tuple_hex"))
        // Offer fields come from RECEIPT_OFFER (aead-valid/receipt-valid).
        let offer = try VectorFixtures.json("protocol/vectors/receipt-valid.json")
        let offerHex = try VectorFixtures.hex(offer, "receipt_offer_hex")
        let map = try CborDecoder.decode(offerHex)
        let fields = DeceiptBinding.OfferFields(
            sessionId: try XCTUnwrap(map.field(12)?.asData),
            transferId: try XCTUnwrap(map.field(2)?.asData),
            receiptId: try XCTUnwrap(map.field(3)?.asData),
            merchantReference: try XCTUnwrap(map.field(4)?.asText),
            totalAmountMinor: try XCTUnwrap(map.field(5)?.asInt),
            currency: try XCTUnwrap(map.field(6)?.asText),
            issuedAtUnix: try XCTUnwrap(map.field(7)?.asInt)
        )
        XCTAssertHexEqual(DeceiptBinding.computeOfferHash(fields), tuple.offerHash, "offer_hash recomputed == tuple offer_hash")
    }

    func testBindingTupleDigestAndProof() throws {
        let v = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let tuple = try VectorFixtures.hex(v, "binding_tuple_hex")
        XCTAssertHexEqual(DeceiptBinding.bindingTupleDigest(tuple), try VectorFixtures.hex(v, "binding_tuple_digest_hex"))
        let ch = try DeceiptHandshake.parseClientHello(try VectorFixtures.hex(v, "client_hello_pdu_hex"))
        let sbt = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        XCTAssertHexEqual(try XCTUnwrap(DeceiptBinding.bindingProofMessage(clientNonce: ch.clientNonce, clientEphemeralPubkey: ch.clientEphemeralPubkey)),
                          try VectorFixtures.hex(v, "binding_proof_message_hex"))
        let proof = try DeceiptBinding.bindingProof(sbt: sbt, clientNonce: ch.clientNonce, clientEphemeralPubkey: ch.clientEphemeralPubkey)
        XCTAssertHexEqual(proof, try VectorFixtures.hex(v, "binding_proof_hex"))
    }

    func testQrRoundTrip() throws {
        let x = try VectorFixtures.json("protocol/vectors/binding-crosscheck.json")
        guard let check = (x["a2_checks"] as? [[String: Any]])?.first(where: { ($0["name"] as? String)?.contains("qr_payload") == true }) else {
            throw NSError(domain: "testQr", code: 1)
        }
        let payloadStr = check["derived"] as! String
        let parsed = try DeceiptBinding.parseQr(payloadStr)
        XCTAssertEqual(parsed.sessionId.count, 16)
        XCTAssertEqual(parsed.sessionBindingToken.count, 16)
        XCTAssertEqual(parsed.offerHash.count, 32)
        let reencoded = DeceiptBinding.encodeQr(sessionId: parsed.sessionId, sessionBindingToken: parsed.sessionBindingToken,
                                                offerHash: parsed.offerHash, expiresAtUnix: parsed.expiresAtUnix)
        XCTAssertEqual(reencoded, payloadStr, "QR re-encode is byte-identical")
    }

    // MARK: AEAD control channel semantics

    func testControlChannelStrictCounter() throws {
        let v = try VectorFixtures.json("protocol/vectors/aead-valid.json")
        let handshake = try VectorFixtures.json("protocol/vectors/handshake-valid.json")
        let keys = try XCTUnwrap(handshake["keys"] as? [String: Any])
        let kM2c = try XCTUnwrap(DeceiptBytes.fromHex(keys["k_m2c_ctrl"] as! String))
        let context = try VectorFixtures.hex(v, "session_context_hex")
        let ch = ControlChannel(key: kM2c, direction: .m2c, sessionContext: context)

        // Feed the two known envelopes in order; counters 0 then 1.
        let offerEnv = try XCTUnwrap(DeceiptBytes.fromHex((v["control_offer"] as! [String: Any])["envelope_hex"] as! String))
        let beginEnv = try XCTUnwrap(DeceiptBytes.fromHex((v["control_transfer_begin"] as! [String: Any])["envelope_hex"] as! String))
        _ = try ch.open(offerEnv)
        _ = try ch.open(beginEnv)
        // Replaying counter 0 is a replay.
        XCTAssertThrowsError(try ch.open(offerEnv)) { err in
            XCTAssertEqual((err as? DeceiptFailure)?.bridge.name, "AEAD_REPLAY_DETECTED")
        }
    }
}
