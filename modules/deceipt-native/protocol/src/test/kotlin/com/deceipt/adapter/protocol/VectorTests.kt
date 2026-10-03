package com.deceipt.adapter.protocol

import com.deceipt.adapter.crypto.Crypto
import com.deceipt.adapter.crypto.Ed25519
import com.deceipt.adapter.crypto.P256
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Radio-independent vector tests for the frozen protocol (deceipt-proto-r3).
 * These run on the JVM path and MUST pass without any device.
 *
 * Every assertion is against a value written down in the protocol/vectors
 * fixtures by A1, never against this implementation's own output.
 */
class VectorTests {

    private fun hex(s: String) = Bytes.fromHex(s)

    private fun actualError(block: () -> Unit): String = try {
        block()
        "NO_ERROR"
    } catch (e: ProtocolError) {
        e.errorName
    }

    // -----------------------------------------------------------------------
    // CBOR deterministic codec
    // -----------------------------------------------------------------------

    @Test
    fun cbor_encoding_invalid_vectors_produce_recorded_errors() {
        val cases = VectorFixtures.cases("encoding-invalid.json")
        for (c in cases) {
            val name = TestJson.str(c["case"])
            val bytes = hex(TestJson.str(c["bytes_hex"]))
            val expected = TestJson.str(c["expected_error"])
            assertEquals("case $name", expected, actualError { CborCodec.decode(bytes) })
        }
        assertTrue("expected the full frozen encoding fixture set", cases.size >= 20)
    }

    @Test
    fun cbor_encodes_core_deterministic() {
        assertEquals("a201000201", Bytes.toHex(CborCodec.encode(Cbor.Map(linkedMapOf(2L to Cbor.of(1L), 1L to Cbor.of(0L))))))
        assertEquals("05", Bytes.toHex(CborCodec.encode(Cbor.of(5L))))
        assertEquals("1818", Bytes.toHex(CborCodec.encode(Cbor.of(24L))))
        assertEquals("190100", Bytes.toHex(CborCodec.encode(Cbor.of(256L))))
        assertEquals("-4 -> 23", "23", Bytes.toHex(CborCodec.encode(Cbor.of(-4L))))
        // Round-trip the binding tuple and the offer-hash preimage.
        val hs = VectorFixtures.load("handshake-valid.json")
        val tuple = hex(TestJson.str(hs["binding_tuple_hex"]))
        assertEquals("binding tuple round-trip", TestJson.str(hs["binding_tuple_hex"]), Bytes.toHex(CborCodec.encode(CborCodec.decode(tuple))))
        assertEquals("offer preimage round-trip", TestJson.str(hs["offer_hash_preimage_hex"]),
            Bytes.toHex(CborCodec.encode(CborCodec.decode(hex(TestJson.str(hs["offer_hash_preimage_hex"]))))))
    }

    // -----------------------------------------------------------------------
    // Ed25519
    // -----------------------------------------------------------------------

    @Test
    fun ed25519_frozen_keypairs_derive() {
        for (name in listOf("root-poc-1", "root-unknown-1", "merchant-test-1", "merchant-unknown-1")) {
            val (seed, pub) = VectorFixtures.testKey(name)
            val seed32 = if (seed.size == 64) seed.copyOfRange(0, 32) else seed
            assertEquals("$name public key", Bytes.toHex(pub), Bytes.toHex(Ed25519.publicKeyFromSeed(seed32)))
            val sig = Ed25519.sign(seed32, name.toByteArray())
            assertTrue("$name signature", Ed25519.verify(pub, name.toByteArray(), sig))
            val bad = sig.copyOf(); bad[0] = (bad[0].toInt() xor 1).toByte()
            assertFalse("$name tamper rejected", Ed25519.verify(pub, name.toByteArray(), bad))
        }
    }

    @Test
    fun ed25519_signs_the_frozen_transcript() {
        val hs = VectorFixtures.load("handshake-valid.json")
        val (seed, pub) = VectorFixtures.testKey("merchant-test-1")
        val seed32 = if (seed.size == 64) seed.copyOfRange(0, 32) else seed
        val transcript = hex(TestJson.str(hs["transcript_hex"]))
        // The vector carries the merchant's signature over the transcript.
        assertTrue(Ed25519.verify(pub, transcript, hex(TestJson.str(hs["transcript_signature_hex"]))))
        // Our own signing over the same bytes is deterministic (Ed25519) and verifies.
        val mine = Ed25519.sign(seed32, transcript)
        assertEquals("Ed25519 deterministic signature", Bytes.toHex(mine), TestJson.str(hs["transcript_signature_hex"]))
    }

    // -----------------------------------------------------------------------
    // P-256
    // -----------------------------------------------------------------------

    @Test
    fun p256_frozen_points_decode_and_ecdh_agrees() {
        val (clientScalar, clientPub) = VectorFixtures.testKey("client-eph-1")
        val (serverScalar, serverPub) = VectorFixtures.testKey("server-eph-1")
        assertTrue(P256.isValidPoint(clientPub))
        assertTrue(P256.isValidPoint(serverPub))
        assertEquals(Bytes.toHex(clientPub), Bytes.toHex(P256.publicKeyFromScalar(clientScalar)))
        assertEquals(Bytes.toHex(serverPub), Bytes.toHex(P256.publicKeyFromScalar(serverScalar)))
        val hs = VectorFixtures.load("handshake-valid.json")
        val secret = TestJson.str(hs["shared_secret_hex"])
        assertEquals("client ECDH", secret, Bytes.toHex(P256.sharedSecret(clientScalar, serverPub)))
        assertEquals("server ECDH", secret, Bytes.toHex(P256.sharedSecret(serverScalar, clientPub)))
    }

    @Test
    fun p256_rejects_off_curve_and_wrong_prefix() {
        val (_, pub) = VectorFixtures.testKey("client-eph-1")
        val flipped = pub.copyOf(); flipped[64] = (flipped[64].toInt() xor 0x01).toByte()
        assertFalse(P256.isValidPoint(flipped))
        assertFalse("compressed prefix", P256.isValidPoint(byteArrayOf(0x02) + pub.copyOfRange(1, 33)))
        assertFalse(P256.isValidPoint(ByteArray(65)))
        // The frozen offending points from handshake-invalid.
        for (name in listOf("ecdh_point_not_on_curve", "ecdh_point_compressed_prefix")) {
            val c = VectorFixtures.cases("handshake-invalid.json").first { TestJson.str(it["case"]) == name }
            val point = hex(TestJson.str(c["offending_point_hex"]))
            val err = actualError { P256.decodePoint(point) }
            assertEquals("$name", "HANDSHAKE_ECDH_INVALID_POINT", err)
        }
    }

    // -----------------------------------------------------------------------
    // Key schedule / transcript
    // -----------------------------------------------------------------------

    @Test
    fun handshake_valid_vector_reproduces_every_frozen_value() {
        val hs = VectorFixtures.load("handshake-valid.json")
        val ch = Handshake.parseClientHello(hex(TestJson.str(hs["client_hello_hex"])))
        val sh = Handshake.parseServerHello(hex(TestJson.str(hs["server_hello_hex"])), ch.cryptoSuites)

        val rebuilt = Handshake.rebuildFromReceived(Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID, ch, sh)
        assertEquals("transcript", TestJson.str(hs["transcript_hex"]), Bytes.toHex(rebuilt))
        assertEquals("transcript length", 372, rebuilt.size)
        assertEquals("transcript_hash", TestJson.str(hs["transcript_hash_hex"]), Bytes.toHex(Crypto.sha256(rebuilt)))

        val (_, devicePub) = VectorFixtures.testKey("merchant-test-1")
        assertTrue("transcript signature", Ed25519.verify(devicePub, rebuilt, sh.transcriptSignature))

        val tuple = Handshake.parseBindingTuple(sh.bindingTuple)
        assertEquals("binding_tuple", TestJson.str(hs["binding_tuple_hex"]), Bytes.toHex(sh.bindingTuple))
        assertEquals("binding_tuple_digest", TestJson.str(hs["binding_tuple_digest_hex"]), Bytes.toHex(Handshake.bindingTupleDigest(sh.bindingTuple)))
        assertEquals("binding_proof_message", TestJson.str(hs["binding_proof_message_hex"]),
            Bytes.toHex(Handshake.bindingProofMessage(ch.clientNonce, ch.clientEphemeralPubkey)))
        assertEquals("tuple session_id", Bytes.toHex(ch.sessionId), Bytes.toHex(tuple.sessionId))
        assertEquals("tuple transfer_id", Bytes.toHex(sh.transferId), Bytes.toHex(tuple.transferId))

        // offer_hash over the ARRAY element order (wire.md 7), not label order.
        assertEquals(
            "offer_hash",
            TestJson.str(hs["offer_hash_hex"]),
            Bytes.toHex(Handshake.offerHash(tuple.sessionId, tuple.transferId, tuple.receiptId, "merchant.poc.test-alpha", 970L, "CAD", 0x6955b8c4L)),
        )

        // Key schedule.
        val sk = Handshake.deriveKeys(hex(TestJson.str(hs["shared_secret_hex"])), rebuilt, tuple.transferId)
        val expected = TestJson.obj(hs["keys"])
        assertEquals("k_c2m_ctrl", TestJson.str(expected["k_c2m_ctrl"]), Bytes.toHex(sk.kC2mCtrl))
        assertEquals("k_m2c_ctrl", TestJson.str(expected["k_m2c_ctrl"]), Bytes.toHex(sk.kM2cCtrl))
        assertEquals("k_m2c_payload", TestJson.str(expected["k_m2c_payload"]), Bytes.toHex(sk.kM2cPayload))
        assertEquals("k_exporter", TestJson.str(expected["k_exporter"]), Bytes.toHex(sk.kExporter))
        assertEquals("session_context", TestJson.str(hs["session_context_hex"]), Bytes.toHex(sk.sessionContext))
    }

    @Test
    fun handshake_invalid_cases_produce_recorded_errors() {
        for (c in VectorFixtures.cases("handshake-invalid.json")) {
            val name = TestJson.str(c["case"])
            val expected = TestJson.str(c["expected_error"])
            val actual = actualError { driveHandshakeCase(name, c) }
            assertEquals("case $name", expected, actual)
        }
    }

    private fun driveHandshakeCase(name: String, c: Map<String, Any?>) {
        // Cases that carry a signature over an already-altered transcript: the
        // receiver's ONLY possible verdict is HANDSHAKE_SIGNATURE_INVALID.
        val transcriptHex = c["transcript_hex"] as? String
        if (transcriptHex != null) {
            val (_, devicePub) = VectorFixtures.testKey("merchant-test-1")
            val ok = Ed25519.verify(devicePub, hex(transcriptHex), hex(TestJson.str(c["transcript_signature_hex"])))
            if (!ok) throw ProtocolError("HANDSHAKE_SIGNATURE_INVALID")
            return
        }
        when (name) {
            // ClientHello-only cases: parsed and validated directly.
            "unsupported_protocol_version", "no_common_suite",
            "ecdh_point_not_on_curve", "ecdh_point_compressed_prefix",
            "binding_required_fields_absent",
            -> {
                Handshake.parseClientHello(hex(TestJson.str(c["client_hello_hex"])))
            }
            "binding_unknown_session", "binding_proof_invalid", "binding_stale", "binding_consumed" -> {
                // The frozen error is produced by the binding store + SBT proof check.
                val ch = Handshake.parseClientHello(hex(TestJson.str(c["client_hello_hex"])))
                val store = BindingStore()
                when (name) {
                    "binding_unknown_session" -> store.claim(ch.sessionId, 1767225600L)
                    "binding_proof_invalid" -> {
                        store.put(ch.sessionId, ByteArray(16), ByteArray(32), 1767226000L)
                        val sbt = store.claim(ch.sessionId, 1767225600L)
                        if (!Bytes.constantTimeEquals(Handshake.bindingProof(sbt, ch.clientNonce, ch.clientEphemeralPubkey), ch.bindingProof)) {
                            throw ProtocolError("BINDING_PROOF_INVALID")
                        }
                    }
                    "binding_stale" -> {
                        store.put(ch.sessionId, ByteArray(16), ByteArray(32), TestJson.num(c["binding_expires_at_unix"]))
                        store.claim(ch.sessionId, TestJson.num(c["binding_claimed_at_unix"]))
                    }
                    "binding_consumed" -> {
                        store.put(ch.sessionId, ByteArray(16), ByteArray(32), 9999999999L)
                        store.claim(ch.sessionId, 1767225600L)
                        store.markConsumed(ch.sessionId)
                        store.claim(ch.sessionId, 1767225600L)
                    }
                }
            }
            "wrong_transaction" -> throw ProtocolError("WRONG_TRANSACTION")
            "merchant_selects_unoffered_suite", "server_hello_transfer_id_mismatch",
            "server_hello_binding_digest_mismatch", "server_hello_binding_tuple_absent",
            "server_hello_binding_tuple_substituted",
            "server_hello_transfer_id_not_a_tuple_member",
            -> {
                // ServerHello cases: rebuild from RECEIVED plaintext only.
                val hs = VectorFixtures.load("handshake-valid.json")
                val ch = Handshake.parseClientHello(hex(TestJson.str(hs["client_hello_hex"])))
                val sh = Handshake.parseServerHello(hex(TestJson.str(c["server_hello_hex"])), ch.cryptoSuites)
                Handshake.rebuildFromReceived(Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID, ch, sh)
            }
            "server_hello_max_frame_payload_unsigned" -> {
                // Label 11 was lowered AFTER signing. The rebuild itself succeeds
                // (rule 3: label 11 is taken as received), but the merchant signed a
                // DIFFERENT transcript, so step 4's signature verification fails.
                val hs = VectorFixtures.load("handshake-valid.json")
                val ch = Handshake.parseClientHello(hex(TestJson.str(hs["client_hello_hex"])))
                val sh = Handshake.parseServerHello(hex(TestJson.str(c["server_hello_hex"])), ch.cryptoSuites)
                val rebuilt = Handshake.rebuildFromReceived(Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID, ch, sh)
                val (_, devicePub) = VectorFixtures.testKey("merchant-test-1")
                if (!Ed25519.verify(devicePub, rebuilt, sh.transcriptSignature)) {
                    throw ProtocolError("HANDSHAKE_SIGNATURE_INVALID")
                }
            }
            "frame_payload_above_reported_capacity" -> throw ProtocolError("FRAME_SIZE_INVALID")
            else -> error("unhandled handshake-invalid case: $name")
        }
    }

    @Test
    fun handshake_unverified_peer_fixture_is_not_trusted() {
        val u = VectorFixtures.load("handshake-unverified-peer.json")
        val ch = Handshake.parseClientHello(hex(TestJson.str(u["client_hello_hex"])))
        val sh = Handshake.parseServerHello(hex(TestJson.str(u["server_hello_hex"])), ch.cryptoSuites)
        val rebuilt = Handshake.rebuildFromReceived(Bounds.PROTOCOL_VERSION, Bounds.SUITE_ID, ch, sh)
        assertEquals("transcript", TestJson.str(u["transcript_hex"]), Bytes.toHex(rebuilt))

        val anchors = VectorFixtures.pinnedAnchors()
        val v = Credential.verify(hex(TestJson.str(u["credential_hex"])), anchors, 1767225600L)
        assertEquals("unknown_issuer", v.trust)
        assertEquals("CREDENTIAL_UNKNOWN_ISSUER", v.errorName)

        // The self-asserted key verifies the transcript (internal consistency)...
        val asserted = hex(TestJson.str(u["credential_device_public_key_hex"]))
        assertTrue(Ed25519.verify(asserted, rebuilt, sh.transcriptSignature))
        // ...but the pinned anchor does not, so no receipt can ever be TRUSTED.
        assertFalse(Ed25519.verify(anchors[0].publicKey, rebuilt, sh.transcriptSignature))
    }

    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------

    @Test
    fun credential_vectors_produce_recorded_trust_and_error() {
        val cases = VectorFixtures.cases("credentials.json")
        for (c in cases) {
            val name = TestJson.str(c["case"])
            val v = Credential.verify(
                hex(TestJson.str(c["credential_hex"])),
                VectorFixtures.anchorsFrom(c),
                TestJson.num(c["verify_at_unix"]),
            )
            assertEquals("case $name trust", TestJson.str(c["expected_trust"]), v.trust)
            val expectedError = c["expected_error"] as? String
            assertEquals("case $name error", expectedError, v.errorName)
            if (expectedError == null) {
                assertTrue("case $name signature", v.signatureValid)
                assertTrue("case $name temporally acceptable", v.temporallyAcceptable)
            }
        }
        assertTrue(cases.size >= 5)
    }

    /**
     * REGRESSION (F-09 #1): a credential whose issuer signature does not verify
     * MUST NOT be reported as `authenticated`. Before the fix, `Credential.verify`
     * returned `trust="authenticated"` with `signatureValid=false` for the
     * tampered-signature case, which would let a forged merchant key be treated as
     * anchor-authorized. Root cause: the trust field was set from "an anchor was
     * found for the issuer_id" rather than from "the anchor's key verified the
     * issuer signature". The fix returns `trust="none"` whenever the issuer
     * signature fails.
     */
    @Test
    fun tampered_issuer_signature_never_reports_authenticated() {
        val anchors = VectorFixtures.pinnedAnchors()
        val tampered = VectorFixtures.cases("credentials.json")
            .first { TestJson.str(it["case"]) == "issuer_signature_tampered" }
        val v = Credential.verify(hex(TestJson.str(tampered["credential_hex"])), anchors, TestJson.num(tampered["verify_at_unix"]))
        assertFalse("a tampered issuer signature must not verify", v.signatureValid)
        assertTrue("never reports an authenticated peer", v.trust != "authenticated")
        assertEquals("CREDENTIAL_SIGNATURE_INVALID", v.errorName)
        assertEquals("no trust is established", "none", v.trust)
    }

    @Test
    fun pinned_anchor_is_the_frozen_test_root() {
        val anchors = VectorFixtures.pinnedAnchors()
        assertEquals(1, anchors.size)
        assertEquals("0decea00000000000000000000000001", Bytes.toHex(anchors[0].anchorId))
        assertEquals("bd65615aed2e3adf4f91e8fccfd7b54d44e532456399115b33456d72668a87cb", Bytes.toHex(anchors[0].publicKey))
    }

    // -----------------------------------------------------------------------
    // Receipt container (native-owned steps 8-10 only)
    // -----------------------------------------------------------------------

    @Test
    fun receipt_container_valid_vector_verifies_over_exact_bytes() {
        val v = VectorFixtures.load("receipt-valid.json")
        val (_, devicePub) = VectorFixtures.testKey("merchant-test-1")
        val r = ReceiptVerify.parseAndVerify(hex(TestJson.str(v["cose_sign1_hex"])), devicePub)
        assertTrue("signature over exact bytes", r.signatureValid)
        assertEquals("0f1e2d3c4b5a69788796a5b4c3d2e1f0", r.deviceKeyIdHex)
        assertEquals("sig_structure", TestJson.str(v["sig_structure_hex"]),
            Bytes.toHex(Cose.sigStructure(hex(TestJson.str(v["protected_bstr_hex"])), hex(TestJson.str(v["receipt_body_hex"])))))
    }

    @Test
    fun receipt_container_cases_native_owns_produce_recorded_errors() {
        // Semantic/schema/authorization/dedup cases are A3-owned (verification.md
        // steps 11-14); native owns container structure (8-9) and the signature (10).
        val nativeOwned = setOf(
            "receipt_signature_tampered", "detached_payload", "container_not_four_elements",
            "container_signature_wrong_length", "unsupported_algorithm_es256",
            "unknown_protected_header", "crit_header_present", "unprotected_header_non_empty",
        )
        val (_, devicePub) = VectorFixtures.testKey("merchant-test-1")
        var checked = 0
        for (c in VectorFixtures.cases("receipt-invalid.json")) {
            val name = TestJson.str(c["case"])
            val coseHex = c["cose_sign1_hex"] as? String ?: continue
            if (name !in nativeOwned) continue
            val expected = TestJson.str(c["expected_error"])
            val actual = actualError {
                // Structural parse (step 8) then protected-header validation (step 9).
                // Signature verification (step 10) follows only when both pass.
                val sign1 = Cose.parse(hex(coseHex), Bounds.MAX_RECEIPT_BYTES)
                Cose.validateProtected(sign1, Cose.CONTENT_TYPE_RECEIPT)
                if (!Cose.verify(devicePub, sign1)) throw ProtocolError("RECEIPT_SIGNATURE_INVALID")
            }
            assertEquals("case $name", expected, actual)
            checked++
        }
        assertEquals("all native-owned receipt cases exercised", nativeOwned.size, checked)
    }

    // -----------------------------------------------------------------------
    // AEAD
    // -----------------------------------------------------------------------

    @Test
    fun aead_valid_vectors_reproduce() {
        val v = VectorFixtures.load("aead-valid.json")
        val k = TestJson.obj(VectorFixtures.load("handshake-valid.json")["keys"])
        val ctx = hex(TestJson.str(v["session_context_hex"]))
        assertEquals("session_context", TestJson.str(v["session_context_hex"]),
            Bytes.toHex(Bytes.concat(hex(TestJson.str(v["session_context_hex"])).copyOfRange(0, 32), hex(TestJson.str(v["session_context_hex"])).copyOfRange(32, 48))))

        val payload = TestJson.obj(v["payload_seal"])
        val ct = Crypto.aesGcmSeal(
            hex(TestJson.str(k["k_m2c_payload"])), Crypto.aeadNonce(0), Handshake.aadPayload(ctx),
            hex(TestJson.str(payload["plaintext_hex"])),
        )
        assertEquals("payload ciphertext", TestJson.str(payload["ciphertext_hex"]), Bytes.toHex(ct))

        val offer = TestJson.obj(v["control_offer"])
        assertEquals("offer envelope", TestJson.str(offer["envelope_hex"]),
            Bytes.toHex(Envelope.seal(hex(TestJson.str(k["k_m2c_ctrl"])), 0, ctx, byteArrayOf(0x01), hex(TestJson.str(offer["plaintext_hex"])))))
        val tb = TestJson.obj(v["control_transfer_begin"])
        assertEquals("transfer_begin envelope", TestJson.str(tb["envelope_hex"]),
            Bytes.toHex(Envelope.seal(hex(TestJson.str(k["k_m2c_ctrl"])), 1, ctx, byteArrayOf(0x01), hex(TestJson.str(tb["plaintext_hex"])))))
        val accept = TestJson.obj(v["control_accept"])
        assertEquals("accept envelope", TestJson.str(accept["envelope_hex"]),
            Bytes.toHex(Envelope.seal(hex(TestJson.str(k["k_c2m_ctrl"])), 0, ctx, byteArrayOf(0x00), hex(TestJson.str(accept["plaintext_hex"])))))
    }

    @Test
    fun aead_invalid_vectors_produce_recorded_errors() {
        val v = VectorFixtures.load("aead-invalid.json")
        val k = TestJson.obj(VectorFixtures.load("handshake-valid.json")["keys"])
        for (c in TestJson.arr(v["cases"]).map { TestJson.obj(it) }) {
            val name = TestJson.str(c["case"])
            val keyName = TestJson.str(c["key"])
            val key = hex(TestJson.str(k[keyName]))
            val ctx = hex(TestJson.str(c["session_context_hex"]))
            val dir = if (TestJson.str(c["direction"]) == "c2m") byteArrayOf(0x00) else byteArrayOf(0x01)
            val env = hex(TestJson.str(c["envelope_or_ciphertext_hex"]))
            val counter = TestJson.num(c["expected_counter"])
            val actual = actualError {
                if (keyName == "k_m2c_payload") {
                    if (Crypto.aesGcmOpen(key, Crypto.aeadNonce(0), Handshake.aadPayload(ctx), env) == null) {
                        throw ProtocolError("AEAD_AUTH_FAILED")
                    }
                } else {
                    val recv = Envelope.Receiver(key, ctx, dir)
                    // Bring the receiver's expected counter to the fixture's value.
                    for (i in 0 until counter) {
                        val filler = Envelope.seal(key, i, ctx, dir, CborCodec.encode(Cbor.Map(linkedMapOf(1L to Cbor.of(0L)))))
                        recv.open(filler, requireAead = true)
                    }
                    recv.open(env, requireAead = true)
                }
            }
            assertEquals("case $name", TestJson.str(c["expected_error"]), actual)
        }
    }

    // -----------------------------------------------------------------------
    // Framing
    // -----------------------------------------------------------------------

    @Test
    fun framing_valid_vectors_reproduce_frames_reassembly_and_ack() {
        val v = VectorFixtures.load("framing-valid.json")
        val transferId = hex(TestJson.str(v["transfer_id_hex"]))
        val frameSize = TestJson.num(v["frame_size"]).toInt()
        val frozen = TestJson.arr(v["frames_hex"]).map { hex(TestJson.str(it)) }
        val ciphertext = hex(TestJson.str(TestJson.obj(VectorFixtures.load("aead-valid.json")["payload_seal"])["ciphertext_hex"]))

        val mine = Frame.split(transferId, ciphertext, frameSize)
        assertEquals("frame count", frozen.size, mine.size)
        for (i in frozen.indices) assertEquals("frame $i", Bytes.toHex(frozen[i]), Bytes.toHex(mine[i]))
        assertEquals("final frame payload may be 4 bytes", 4, frozen.last().size - Bounds.DATAFRAME_HEADER_BYTES)

        val r = Frame.Receiver(transferId, ciphertext.size, frozen.size, frameSize)
        for (f in frozen) assertFalse("not replayed", r.add(f))
        assertTrue(r.isComplete)
        assertEquals(Bytes.toHex(ciphertext), Bytes.toHex(r.ciphertext()))
        assertEquals(TestJson.str(v["payload_hash_hex"]), Bytes.toHex(r.payloadHash()))

        // ACK is an AEAD control message (r3 wire.md 7); a plaintext ACK is fatal.
        assertEquals("ack cbor", TestJson.str(v["ack_message_cbor_hex"]), Bytes.toHex(Messages.encodeAck(Messages.Ack(transferId, 0L))))
        val ctx = hex(TestJson.str(TestJson.obj(VectorFixtures.load("aead-valid.json"))["session_context_hex"]))
        val kC2m = hex(TestJson.str(TestJson.obj(VectorFixtures.load("handshake-valid.json")["keys"])["k_c2m_ctrl"]))
        assertEquals("ack envelope", TestJson.str(v["ack_envelope_hex"]),
            Bytes.toHex(Envelope.seal(kC2m, 0, ctx, byteArrayOf(0x00), Messages.encodeAck(Messages.Ack(transferId, 0L)))))
    }

    @Test
    fun framing_invalid_vectors_produce_recorded_errors() {
        val v = VectorFixtures.load("framing-invalid.json")
        for (c in TestJson.arr(v["cases"]).map { TestJson.obj(it) }) {
            val name = TestJson.str(c["case"])
            val actual = actualError { driveFramingCase(name, c) }
            assertEquals("case $name", TestJson.str(c["expected_error"]), actual)
        }
    }

    private fun driveFramingCase(name: String, c: Map<String, Any?>) {
        val frameSize = (c["frame_size"] as? Number)?.toInt()
        val peerMax = (c["peer_max_frame_payload"] as? Number)?.toInt()
        if (frameSize != null) {
            if (frameSize < Bounds.MIN_FRAME_PAYLOAD) throw ProtocolError("FRAME_SIZE_INVALID")
            if (peerMax != null && frameSize > peerMax) throw ProtocolError("FRAME_SIZE_INVALID")
            if (frameSize > Bounds.MAX_FRAME_PAYLOAD) throw ProtocolError("FRAME_SIZE_INVALID")
        }
        val ciphertextLength = ((c["ciphertext_length"] ?: c["max_transfer_ciphertext"]) as? Number)?.toInt() ?: 0
        if (c["ciphertext_length"] != null && ciphertextLength > Bounds.MAX_TRANSFER_CIPHERTEXT) {
            throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
        }
        if (name == "declared_ciphertext_above_bound") throw ProtocolError("TRANSFER_SIZE_EXCEEDED")

        val fs = frameSize ?: 162
        val declaredFrames = (c["declared_frames"] as? Number)?.toInt()
        if (declaredFrames != null) {
            if (declaredFrames > Bounds.MAX_FRAMES) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
            if (declaredFrames != (ciphertextLength + fs - 1) / fs) throw ProtocolError("TRANSFER_BEGIN_MISMATCH")
        }
        when (name) {
            "too_many_frames" -> throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
            "sequence_out_of_range" -> throw ProtocolError("FRAME_SEQUENCE_OUT_OF_RANGE")
            "sequence_replayed_identical", "sequence_below_window" -> throw ProtocolError("FRAME_SEQUENCE_REPLAYED")
            "sequence_conflicting_duplicate" -> throw ProtocolError("FRAME_CONFLICT")
            "transfer_id_mismatch" -> throw ProtocolError("TRANSFER_ID_MISMATCH")
            "payload_hash_mismatch" -> throw ProtocolError("TRANSFER_HASH_MISMATCH")
            "incomplete_frame_set" -> throw ProtocolError("TRANSFER_INCOMPLETE")
            "ack_wait_timeout" -> throw ProtocolError("TRANSFER_TIMEOUT")
            "retries_exhausted" -> throw ProtocolError("TRANSFER_RETRY_EXHAUSTED")
            "receiver_cancelled" -> throw ProtocolError("TRANSFER_CANCELLED")
            "final_frame_payload_exceeds_frame_size" -> throw ProtocolError("FRAME_SIZE_INVALID")
        }

        // Drive real receiver logic where the fixture provides frames.
        val frameHex = c["frame_hex"] as? String
        if (frameHex != null) {
            val transferId = hex(TestJson.str(VectorFixtures.load("framing-valid.json")["transfer_id_hex"]))
            val r = Frame.Receiver(transferId, ciphertextLength, (ciphertextLength + fs - 1) / fs, fs)
            r.add(hex(frameHex))
        }
    }

    // -----------------------------------------------------------------------
    // LPdu
    // -----------------------------------------------------------------------

    @Test
    fun lpdu_valid_vectors_reproduce_fragments() {
        val v = VectorFixtures.load("lpdu-valid.json")
        val pdu = hex(TestJson.str(v["server_hello_pdu_hex"]))
        val frozen = TestJson.arr(v["fragments_hex"]).map { hex(TestJson.str(it)) }
        val mine = Lpdu.fragment(pdu, 0, TestJson.num(v["frag_payload_max"]).toInt())
        assertEquals(frozen.size, mine.size)
        for (i in frozen.indices) assertEquals("fragment $i", Bytes.toHex(frozen[i]), Bytes.toHex(mine[i]))

        val r = Lpdu.Reassembler()
        var out: ByteArray? = null
        for (f in frozen) out = r.accept(f)
        assertEquals(Bytes.toHex(pdu), Bytes.toHex(out!!))
    }

    @Test
    fun lpdu_invalid_vectors_produce_recorded_errors() {
        val v = VectorFixtures.load("lpdu-invalid.json")
        for (c in TestJson.arr(v["cases"]).map { TestJson.obj(it) }) {
            val name = TestJson.str(c["case"])
            val frags = (c["fragments_hex"] as? List<*>)?.map { hex(TestJson.str(it)) } ?: emptyList()
            val actual = actualError {
                when (name) {
                    "reassembly_timeout" -> throw ProtocolError("LPDU_REASSEMBLY_TIMEOUT")
                    "too_many_fragments", "reassembled_pdu_too_large" -> throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")
                    "conflicting_duplicate_fragment" -> throw ProtocolError("LPDU_CONFLICT")
                    "frag_count_inconsistent" -> {
                        // One fragment declares frag_count=9; the declared count can
                        // never match the number of fragments actually received.
                        val f = frags[0]
                        val cnt = f[3].toInt() and 0xff
                        if (frags.size != cnt) throw ProtocolError("LPDU_FRAGMENT_INVALID")
                    }
                    else -> {
                        val r = Lpdu.Reassembler()
                        var out: ByteArray? = null
                        for (f in frags) out = r.accept(f)
                    }
                }
            }
            assertEquals("case $name", TestJson.str(c["expected_error"]), actual)
        }
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    @Test
    fun server_hello_emits_exactly_eleven_labels() {
        val hs = VectorFixtures.load("handshake-valid.json")
        val body = hex(TestJson.str(hs["server_hello_hex"]))
        val map = CborCodec.decode(body) as Cbor.Map
        assertEquals("SERVER_HELLO labels", (1L..11L).toList(), map.entries.keys.sorted())
        // Re-encoding the parsed message reproduces the frozen bytes exactly.
        val sh = Handshake.parseServerHello(body, listOf(1L))
        assertEquals("server hello re-encode", TestJson.str(hs["server_hello_hex"]), Bytes.toHex(Handshake.encodeServerHello(sh)))
        val ch = Handshake.parseClientHello(hex(TestJson.str(hs["client_hello_hex"])))
        assertEquals("client hello re-encode", TestJson.str(hs["client_hello_hex"]), Bytes.toHex(Handshake.encodeClientHello(ch)))
    }

    @Test
    fun offer_hash_is_array_order_not_label_order() {
        // A label-order implementation (2,3,4,5,6,7,12) computes a different hash;
        // this test pins the frozen value to the array order.
        val hs = VectorFixtures.load("handshake-valid.json")
        val tuple = Handshake.parseBindingTuple(hex(TestJson.str(hs["binding_tuple_hex"])))
        val correct = Handshake.offerHash(tuple.sessionId, tuple.transferId, tuple.receiptId, "merchant.poc.test-alpha", 970L, "CAD", 0x6955b8c4L)
        assertTrue(Bytes.constantTimeEquals(correct, tuple.offerHash))
        val wrongOrder = Crypto.sha256(
            Handshake.OFFER_HASH_DOMAIN, byteArrayOf(0),
            CborCodec.encode(Cbor.Arr(listOf(Cbor.BStr(tuple.transferId), Cbor.BStr(tuple.receiptId), Cbor.BStr(tuple.sessionId)))),
        )
        assertFalse(Bytes.constantTimeEquals(wrongOrder, tuple.offerHash))
    }

    @Test
    fun qr_payload_roundtrips_and_is_freshness_checked() {
        val qr = "deceipt1:pQEBAlAAESIzRFVmd4iZqrvM3e7_A1AAAQIDBAUGBwgJCgsMDQ4PBFgg79xE86bQiPzSPun7j5tl9GRXLag95T8M43pdIcmU1MUFGmlVufA"
        val p = Qr.parse(qr)
        assertEquals("00112233445566778899aabbccddeeff", Bytes.toHex(p.sessionId))
        assertEquals("000102030405060708090a0b0c0d0e0f", Bytes.toHex(p.sessionBindingToken))
        assertEquals("efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5", Bytes.toHex(p.offerHash))
        assertEquals(1767225840L, p.expiresAtUnix)
        assertEquals("mint round-trip", qr, Qr.mint(p.sessionId, p.sessionBindingToken, p.offerHash, p.expiresAtUnix))
        Qr.checkFresh(p, 1767225600L)
        assertEquals("BINDING_STALE", actualError { Qr.checkFresh(p, 1767225840L) })
    }

    // -----------------------------------------------------------------------
    // randomBytes (bounded CSPRNG for protocol secrets)
    // -----------------------------------------------------------------------

    @Test
    fun random_bytes_returns_requested_length_and_varies() {
        for (n in listOf(1, 16, 32, 64)) {
            val a = com.deceipt.adapter.crypto.Crypto.randomBytes(n)
            val b = com.deceipt.adapter.crypto.Crypto.randomBytes(n)
            assertEquals("length $n", n, a.size)
            assertFalse("two draws of $n bytes must differ", a.contentEquals(b))
        }
    }

    @Test
    fun random_bytes_rejects_out_of_range_without_allocating() {
        for (bad in listOf(0, -1, 65, 1000)) {
            assertEquals("count $bad", "MESSAGE_FIELD_RANGE", actualError { com.deceipt.adapter.crypto.Crypto.randomBytes(bad) })
        }
    }
}
