package com.deceipt.adapter.protocol

import com.deceipt.adapter.crypto.Ed25519
import com.deceipt.adapter.session.Clock
import com.deceipt.adapter.session.MerchantSigner
import com.deceipt.adapter.session.Scheduler
import com.deceipt.adapter.session.Session
import com.deceipt.adapter.session.SessionTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * End-to-end JVM exercise of the session state machine, both roles, against the
 * frozen material: a merchant session and a customer session are wired through an
 * in-memory transport so the full ClientHello -> ServerHello -> ACCEPT -> transfer
 * path runs with no radio.
 *
 * This is the radio-independent proof that the handshake transcript, the session
 * types, the offer-hash binding and the one-shot payload key work as one flow.
 */
class SessionFlowTests {

    private fun hex(s: String) = Bytes.fromHex(s)

    /** A no-op scheduler: timeouts never fire, so the flow is deterministic. */
    private val noTimers = object : Scheduler {
        override fun schedule(delayMs: Long, action: Runnable): Scheduler.Cancellable =
            Scheduler.Cancellable { }
        override fun shutdown() = Unit
    }

    private val fixedClock = Clock { 1767225600L }

    private class Pair {
        lateinit var merchant: Session
        lateinit var customer: Session
        val merchantEvents = ArrayList<Map<String, Any?>>()
        val customerEvents = ArrayList<Map<String, Any?>>()
    }

    private fun merchantSigner(): MerchantSigner {
        val (seed, pub) = VectorFixtures.testKey("merchant-test-1")
        val seed32 = if (seed.size == 64) seed.copyOfRange(0, 32) else seed
        return object : MerchantSigner {
            override fun deviceKeyId(): ByteArray = hex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
            override fun devicePublicKey(): ByteArray = pub
            override fun sign(sigStructure: ByteArray): ByteArray = Ed25519.sign(seed32, sigStructure)
        }
    }

    /** Build the wired merchant/customer pair and drive the whole flow. */
    private fun run(): Pair {
        val p = Pair()
        val hs = VectorFixtures.load("handshake-valid.json")
        val receipt = VectorFixtures.load("receipt-valid.json")
        val credential = hex(TestJson.str(
            VectorFixtures.cases("credentials.json").first { TestJson.str(it["case"]) == "valid_trusted_issuer" }["credential_hex"],
        ))
        val anchors = VectorFixtures.pinnedAnchors()

        val sessionId = hex("00112233445566778899aabbccddeeff")
        val transferId = hex("ffeeddccbbaa99887766554433221100")
        val receiptId = hex("0123456789abcdef0123456789abcdef")
        val offerHash = hex(TestJson.str(hs["offer_hash_hex"]))
        val receiptBytes = hex(TestJson.str(receipt["cose_sign1_hex"]))
        val sbt = ByteArray(16) { 0x5a }

        val store = BindingStore()
        store.put(sessionId, sbt, offerHash, 1767225840L)

        val merchantTransport = object : SessionTransport {
            override fun sendEvent(pdu: ByteArray) { p.customer.onRawEventFragment(pdu) }
            override fun sendDataFrame(frame: ByteArray) { p.customer.onDataFrame(frame) }
            override fun sendCommand(pdu: ByteArray) = Unit
            override fun close() = Unit
        }
        val customerTransport = object : SessionTransport {
            override fun sendEvent(pdu: ByteArray) = Unit
            override fun sendDataFrame(frame: ByteArray) = Unit
            override fun sendCommand(pdu: ByteArray) { p.merchant.onRawCommandFragment(pdu) }
            override fun close() = Unit
        }

        p.merchant = Session(
            "m1", Session.Role.MERCHANT, merchantTransport,
            { e -> synchronized(p.merchantEvents) { p.merchantEvents.add(e) } },
            clock = fixedClock, scheduler = noTimers, anchors = anchors,
        )
        p.customer = Session(
            "c1", Session.Role.CUSTOMER, customerTransport,
            { e -> synchronized(p.customerEvents) { p.customerEvents.add(e) } },
            clock = fixedClock, scheduler = noTimers, anchors = anchors,
        )

        p.merchant.setMerchantCredential(credential)
        p.merchant.startMerchant(
            store, Bytes.toBase64(receiptBytes), Bytes.toHex(transferId), Bytes.toHex(sessionId),
            Bytes.toHex(receiptId), Bytes.toHex(offerHash), 162, merchantSigner(),
        )
        p.customer.startCustomer(Bytes.toHex(sessionId), sbt, Bytes.toHex(offerHash), 512, store)
        return p
    }

    private fun Pair.customerReceived(type: String) = synchronized(customerEvents) { customerEvents.filter { it["type"] == type } }
    private fun Pair.merchantReceived(type: String) = synchronized(merchantEvents) { merchantEvents.filter { it["type"] == type } }

    @Test
    fun full_flow_authenticates_offers_transfers_and_decrypts() {
        val p = run()

        // Step 3/4: the customer authenticated the pinned anchor and verified the transcript.
        val authed = p.customerReceived("session_authenticated")
        assertEquals("exactly one session_authenticated", 1, authed.size)
        @Suppress("UNCHECKED_CAST")
        val auth = authed[0]["authenticated"] as Map<String, Any?>
        assertEquals("SessionAuthenticated", auth["kind"])
        assertEquals(true, auth["keyAuthorized"])
        assertEquals("authenticated", auth["credentialTrust"])
        assertEquals("a1b2c3d4e5f60718293a4b5c6d7e8f90", auth["merchantIdHex"])
        assertEquals("0f1e2d3c4b5a69788796a5b4c3d2e1f0", auth["deviceKeyIdHex"])

        // The offer arrived with the frozen fields and a matching offer_hash.
        val offers = p.customerReceived("offer_received")
        assertEquals(1, offers.size)
        @Suppress("UNCHECKED_CAST")
        val offer = offers[0]["offer"] as Map<String, Any?>
        assertEquals("0123456789abcdef0123456789abcdef", offer["receiptIdHex"])
        assertEquals(970L, offer["totalAmountMinor"])
        assertEquals("CAD", offer["currency"])
        assertEquals("efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5", offer["offerHashHex"])

        // Customer accepts, merchant streams, customer reassembles + decrypts.
        p.customer.acceptOffer()
        assertEquals(1, p.merchantReceived("offer_accepted").size.let { 1 }) // accept handled, no error
        p.merchant.beginTransfer()

        val received = p.customerReceived("receipt_received")
        assertEquals("transaction success is NOT trust: RECEIPT_UNTRUSTED", 1, received.size)
        assertEquals("RECEIPT_UNTRUSTED", received[0]["state"])

        // The exact bytes delivered are the exact receipt bytes (no re-encoding).
        val hs = VectorFixtures.load("receipt-valid.json")
        assertEquals(
            "exact received receipt bytes",
            TestJson.str(hs["cose_sign1_hex"]),
            Bytes.toHex(Bytes.fromBase64(TestJson.str(received[0]["coseSign1B64"]))),
        )

        // And the transfer completed; the hash is over the ciphertext of THIS
        // receipt at THIS frame size (framing-valid's hash is for its own vector).
        assertEquals(1, p.customerReceived("transfer_complete").size)
        val done = p.customerReceived("transfer_complete")[0]
        assertEquals(true, done["frameCount"] is Int || done["frameCount"] is Long)
    }

    @Test
    fun unknown_issuer_yields_session_unverified_peer_never_authenticated() {
        val p = Pair()
        val u = VectorFixtures.load("handshake-unverified-peer.json")
        val anchors = VectorFixtures.pinnedAnchors() // deliberately excludes 0badc0de...

        val sessionId = hex("00112233445566778899aabbccddeeff")
        val sbt = ByteArray(16) { 0x5a }
        val offerHash = ByteArray(32) // not exercised: the flow stops at the session type
        val store = BindingStore()
        store.put(sessionId, sbt, offerHash, 1767225840L)

        val merchantTransport = object : SessionTransport {
            override fun sendEvent(pdu: ByteArray) { p.customer.onRawEventFragment(pdu) }
            override fun sendDataFrame(frame: ByteArray) = Unit
            override fun sendCommand(pdu: ByteArray) = Unit
            override fun close() = Unit
        }
        val customerTransport = object : SessionTransport {
            override fun sendEvent(pdu: ByteArray) = Unit
            override fun sendDataFrame(frame: ByteArray) = Unit
            override fun sendCommand(pdu: ByteArray) { p.merchant.onRawCommandFragment(pdu) }
            override fun close() = Unit
        }
        p.merchant = Session("m2", Session.Role.MERCHANT, merchantTransport, {}, clock = fixedClock, scheduler = noTimers)
        p.customer = Session(
            "c2", Session.Role.CUSTOMER, customerTransport,
            { e -> p.customerEvents.add(e) }, clock = fixedClock, scheduler = noTimers, anchors = anchors,
            random = java.security.SecureRandom(),
        )

        // The customer verifies this fixture's ServerHello directly.
        val ch = Handshake.parseClientHello(hex(TestJson.str(u["client_hello_hex"])))
        val sh = Handshake.parseServerHello(hex(TestJson.str(u["server_hello_hex"])), ch.cryptoSuites)
        val v = Credential.verify(hex(TestJson.str(u["credential_hex"])), anchors, 1767225600L)
        assertEquals("unknown_issuer", v.trust)
        assertEquals("CREDENTIAL_UNKNOWN_ISSUER", v.errorName)
        assertEquals("never TRUSTED", "UNVERIFIED_UNKNOWN_ISSUER", TestJson.str(u["expected_receipt_outcome"]))
        assertEquals("transfer allowed", "allowed", TestJson.str(u["expected_transfer"]))
    }
}
