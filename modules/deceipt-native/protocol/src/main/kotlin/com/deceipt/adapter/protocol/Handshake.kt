package com.deceipt.adapter.protocol

import com.deceipt.adapter.crypto.Crypto
import com.deceipt.adapter.crypto.P256

/**
 * Handshake pass C (docs/protocol/handshake.md, deceipt-proto-r3): canonical
 * transcript, key schedule, AEAD nonces/AAD, and the hello message shapes.
 *
 * Every value here is frozen; alternatives are not permitted.
 */
object Handshake {

    val TRANSCRIPT_LABEL = "deceipt-handshake-v1".toByteArray(Charsets.US_ASCII) // 20 bytes
    val HKDF_INFO_PREFIX = "deceipt-transfer-v1".toByteArray(Charsets.US_ASCII)
    val BINDING_TUPLE_DOMAIN = "deceipt-binding-tuple-v1".toByteArray(Charsets.US_ASCII)
    val OFFER_HASH_DOMAIN = "deceipt-offer-hash-v1".toByteArray(Charsets.US_ASCII)
    val BINDING_PROOF_DOMAIN = "deceipt-binding-proof-v1".toByteArray(Charsets.US_ASCII)

    const val OKM_LENGTH = 128

    // -----------------------------------------------------------------------
    // A2 binding tuple / offer hash / binding proof
    // -----------------------------------------------------------------------

    data class BindingTuple(
        val sessionId: ByteArray,
        val transferId: ByteArray,
        val receiptId: ByteArray,
        val offerHash: ByteArray,
    )

    /** Parse the exact A2 `binding_tuple` bytes: `[1, session_id, transfer_id, receipt_id, offer_hash]`. */
    fun parseBindingTuple(bytes: ByteArray): BindingTuple {
        if (bytes.isEmpty()) throw ProtocolError("BINDING_REQUIRED", "binding tuple absent")
        if (bytes.size > Bounds.MAX_BINDING_BYTES) throw ProtocolError("BINDING_REQUIRED", "binding tuple too large")
        val arr = CborCodec.decode(bytes) as? Cbor.Arr
            ?: throw ProtocolError("BINDING_PROOF_INVALID", "binding tuple must be an array")
        if (arr.items.size != 5) throw ProtocolError("BINDING_PROOF_INVALID", "binding tuple must have 5 elements")
        val version = (arr.items[0] as? Cbor.UInt)?.value
            ?: throw ProtocolError("BINDING_PROOF_INVALID", "binding version must be a uint")
        if (version != 1L) throw ProtocolError("BINDING_PROOF_INVALID", "unsupported binding version")
        fun bstr(i: Int, n: Int): ByteArray {
            val b = arr.items[i] as? Cbor.BStr ?: throw ProtocolError("BINDING_PROOF_INVALID", "binding element $i must be a bstr")
            if (b.value.size != n) throw ProtocolError("BINDING_PROOF_INVALID", "binding element $i wrong length")
            return b.value
        }
        return BindingTuple(bstr(1, 16), bstr(2, 16), bstr(3, 16), bstr(4, 32))
    }

    fun encodeBindingTuple(t: BindingTuple): ByteArray = CborCodec.encode(
        Cbor.Arr(
            listOf(
                Cbor.of(1L),
                Cbor.BStr(t.sessionId),
                Cbor.BStr(t.transferId),
                Cbor.BStr(t.receiptId),
                Cbor.BStr(t.offerHash),
            ),
        ),
    )

    fun bindingTupleDigest(bindingTuple: ByteArray): ByteArray =
        Crypto.sha256(BINDING_TUPLE_DOMAIN, byteArrayOf(0), bindingTuple)

    /** `offer_hash`, over the array element order (wire.md 7, NOT the label order). */
    fun offerHash(
        sessionId: ByteArray,
        transferId: ByteArray,
        receiptId: ByteArray,
        merchantReference: String,
        totalAmountMinor: Long,
        currency: String,
        issuedAtUnix: Long,
    ): ByteArray {
        val preimage = CborCodec.encode(
            Cbor.Arr(
                listOf(
                    Cbor.BStr(sessionId),
                    Cbor.BStr(transferId),
                    Cbor.BStr(receiptId),
                    Cbor.TStr(merchantReference),
                    Cbor.UInt(totalAmountMinor),
                    Cbor.TStr(currency),
                    Cbor.UInt(issuedAtUnix),
                ),
            ),
        )
        return Crypto.sha256(OFFER_HASH_DOMAIN, byteArrayOf(0), preimage)
    }

    /** `proof_message = "deceipt-binding-proof-v1" || 0x00 || client_nonce || client_ephemeral_pubkey`. */
    fun bindingProofMessage(clientNonce: ByteArray, clientEphemeralPub: ByteArray): ByteArray =
        Bytes.concat(BINDING_PROOF_DOMAIN, byteArrayOf(0), clientNonce, clientEphemeralPub)

    fun bindingProof(sbt: ByteArray, clientNonce: ByteArray, clientEphemeralPub: ByteArray): ByteArray =
        Crypto.hmacSha256(sbt, bindingProofMessage(clientNonce, clientEphemeralPub))

    // -----------------------------------------------------------------------
    // Canonical transcript
    // -----------------------------------------------------------------------

    fun buildTranscript(
        protocolVersion: Int,
        suiteId: Int,
        clientNonce: ByteArray,
        clientEphemeralPub: ByteArray,
        serverNonce: ByteArray,
        serverEphemeralPub: ByteArray,
        tuple: BindingTuple,
        bindingTuple: ByteArray,
        bindingTupleDigest: ByteArray,
        maxFramePayload: Int,
    ): ByteArray {
        require(clientNonce.size == Bounds.NONCE_BYTES)
        require(serverNonce.size == Bounds.NONCE_BYTES)
        require(clientEphemeralPub.size == P256.UNCOMPRESSED_BYTES)
        require(serverEphemeralPub.size == P256.UNCOMPRESSED_BYTES)
        require(bindingTuple.size <= Bounds.MAX_BINDING_BYTES)
        // Frozen layout (handshake.md 3): transfer_id at 218, session_id at 234,
        // digest at 250, max_frame_payload at 282, binding_len at 284, tuple at 285.
        val t = Bytes.concat(
            TRANSCRIPT_LABEL,
            Bytes.u16be(protocolVersion),
            Bytes.u16be(suiteId),
            clientNonce,
            clientEphemeralPub,
            serverNonce,
            serverEphemeralPub,
            tuple.transferId,
            tuple.sessionId,
            bindingTupleDigest,
            Bytes.u16be(maxFramePayload),
            byteArrayOf(bindingTuple.size.toByte()),
            bindingTuple,
        )
        if (t.size != Bounds.TRANSCRIPT_LEN) throw ProtocolError("HANDSHAKE_TRANSCRIPT_MISMATCH", "transcript length ${t.size}")
        return t
    }

    /**
     * Rebuild the transcript from received plaintext (handshake.md 3.1, R4-01).
     * Uses SERVER_HELLO label 10 as the authoritative binding tuple and the
     * received max_frame_payload (label 11), never a client-side assumption.
     *
     * Rule 3 enforcement: label 11 is the value the merchant SIGNED. If it is
     * below the client's own declared ceiling that is legal; if it is above it,
     * the merchant signed a frame size the client never offered, so the rebuilt
     * transcript cannot match the signature -> `HANDSHAKE_SIGNATURE_INVALID`
     * (vector `server_hello_max_frame_payload_unsigned`).
     */
    fun rebuildFromReceived(
        protocolVersion: Int,
        suiteId: Int,
        clientHello: ClientHello,
        serverHello: ServerHello,
    ): ByteArray {
        val tuple = parseBindingTuple(serverHello.bindingTuple)
        if (!Bytes.constantTimeEquals(serverHello.bindingTupleDigest, bindingTupleDigest(serverHello.bindingTuple))) {
            throw ProtocolError("HANDSHAKE_TRANSCRIPT_MISMATCH", "binding_tuple_digest mismatch")
        }
        if (!Bytes.constantTimeEquals(serverHello.transferId, tuple.transferId)) {
            throw ProtocolError("TRANSFER_ID_MISMATCH")
        }
        if (!Bytes.constantTimeEquals(tuple.sessionId, clientHello.sessionId)) {
            throw ProtocolError("BINDING_UNKNOWN_SESSION")
        }
        if (serverHello.maxFramePayload > clientHello.maxFramePayload) {
            throw ProtocolError("HANDSHAKE_SIGNATURE_INVALID", "signed max_frame_payload above the client's declared ceiling")
        }
        return buildTranscript(
            protocolVersion, suiteId,
            clientHello.clientNonce, clientHello.clientEphemeralPubkey,
            serverHello.serverNonce, serverHello.serverEphemeralPubkey,
            tuple, serverHello.bindingTuple, serverHello.bindingTupleDigest, serverHello.maxFramePayload.toInt(),
        )
    }

    // -----------------------------------------------------------------------
    // Key schedule
    // -----------------------------------------------------------------------

    data class SessionKeys(
        val transcriptHash: ByteArray,
        val kC2mCtrl: ByteArray,
        val kM2cCtrl: ByteArray,
        val kM2cPayload: ByteArray,
        val kExporter: ByteArray,
        val sessionContext: ByteArray,
    ) {
        fun zeroize() {
            Bytes.zeroize(kC2mCtrl); Bytes.zeroize(kM2cCtrl)
            Bytes.zeroize(kM2cPayload); Bytes.zeroize(kExporter)
        }
    }

    fun deriveKeys(sharedSecret: ByteArray, transcript: ByteArray, transferId: ByteArray): SessionKeys {
        require(transferId.size == 16)
        val transcriptHash = Crypto.sha256(transcript)
        val prk = Crypto.hkdfExtract(transcriptHash, sharedSecret)
        val info = Bytes.concat(HKDF_INFO_PREFIX, transcriptHash)
        val okm = Crypto.hkdfExpand(prk, info, OKM_LENGTH)
        Bytes.zeroize(prk)
        val sessionContext = Bytes.concat(transcriptHash, transferId)
        return SessionKeys(
            transcriptHash = transcriptHash,
            kC2mCtrl = okm.copyOfRange(0, 32),
            kM2cCtrl = okm.copyOfRange(32, 64),
            kM2cPayload = okm.copyOfRange(64, 96),
            kExporter = okm.copyOfRange(96, 128),
            sessionContext = sessionContext,
        )
    }

    // -----------------------------------------------------------------------
    // AAD
    // -----------------------------------------------------------------------

    fun aadPayload(sessionContext: ByteArray): ByteArray = Bytes.concat(sessionContext, byteArrayOf(0x01))
    fun aadControlC2m(sessionContext: ByteArray): ByteArray = Bytes.concat(sessionContext, byteArrayOf(0x02, 0x00))
    fun aadControlM2c(sessionContext: ByteArray): ByteArray = Bytes.concat(sessionContext, byteArrayOf(0x02, 0x01))

    // -----------------------------------------------------------------------
    // Hello messages
    // -----------------------------------------------------------------------

    data class ClientHello(
        val protocolVersion: Long,
        val cryptoSuites: List<Long>,
        val sessionId: ByteArray,
        val clientNonce: ByteArray,
        val clientEphemeralPubkey: ByteArray,
        val bindingProof: ByteArray,
        val maxFramePayload: Long,
    )

    data class ServerHello(
        val protocolVersion: Long,
        val suiteId: Long,
        val transferId: ByteArray,
        val serverNonce: ByteArray,
        val serverEphemeralPubkey: ByteArray,
        val merchantCredential: ByteArray,
        val transcriptSignature: ByteArray,
        val bindingTupleDigest: ByteArray,
        val bindingTuple: ByteArray,
        val maxFramePayload: Long,
    )

    private fun mapOf(bytes: ByteArray): Map<Long, Cbor> {
        val m = CborCodec.decode(bytes) as? Cbor.Map
            ?: throw ProtocolError("CBOR_MALFORMED", "message must be a map")
        return m.entries
    }

    private fun required(m: Map<Long, Cbor>, label: Long, name: String): Cbor =
        m[label] ?: throw ProtocolError("MESSAGE_MISSING_FIELD", name)

    private fun checkNoUnknown(m: Map<Long, Cbor>, allowed: Set<Long>) {
        for (k in m.keys) if (k !in allowed) throw ProtocolError("MESSAGE_UNKNOWN_FIELD", "label $k")
    }

    private fun uint(m: Map<Long, Cbor>, label: Long, name: String): Long =
        (required(m, label, name) as? Cbor.UInt)?.value ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)

    private fun bstr(m: Map<Long, Cbor>, label: Long, name: String, len: Int?): ByteArray {
        val b = required(m, label, name) as? Cbor.BStr ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)
        if (len != null && b.value.size != len) throw ProtocolError("MESSAGE_FIELD_RANGE", name)
        return b.value
    }

    /** Absence of a binding field is the frozen `BINDING_REQUIRED`, not a generic missing-field. */
    private fun bstrOrBindingRequired(m: Map<Long, Cbor>, label: Long, name: String, len: Int?): ByteArray {
        val v = m[label] ?: throw ProtocolError("BINDING_REQUIRED", name)
        val b = v as? Cbor.BStr ?: throw ProtocolError("MESSAGE_FIELD_TYPE", name)
        if (len != null && b.value.size != len) throw ProtocolError("MESSAGE_FIELD_RANGE", name)
        return b.value
    }

    /** Parse and validate a CLIENT_HELLO (plaintext PDU body, without the 0x00 envelope tag). */
    fun parseClientHello(bytes: ByteArray): ClientHello {
        if (bytes.size > Bounds.MAX_CONTROL_PDU) throw ProtocolError("MESSAGE_TOO_LARGE")
        val m = mapOf(bytes)
        checkNoUnknown(m, setOf(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L))
        if (uint(m, 1L, "type") != 1L) throw ProtocolError("MESSAGE_UNKNOWN_TYPE")
        val version = uint(m, 2L, "protocol_version")
        if (version != Bounds.PROTOCOL_VERSION.toLong()) throw ProtocolError("HANDSHAKE_UNSUPPORTED_VERSION")
        val suites = (required(m, 3L, "crypto_suites") as? Cbor.Arr)
            ?: throw ProtocolError("MESSAGE_FIELD_TYPE", "crypto_suites")
        val suiteIds = suites.items.map {
            (it as? Cbor.UInt)?.value ?: throw ProtocolError("MESSAGE_FIELD_TYPE", "crypto_suites")
        }
        if (suiteIds.isEmpty()) throw ProtocolError("HANDSHAKE_NO_COMMON_SUITE")
        if (!suiteIds.contains(Bounds.SUITE_ID.toLong())) throw ProtocolError("HANDSHAKE_NO_COMMON_SUITE")
        val sessionId = bstrOrBindingRequired(m, 4L, "session_id", 16)
        val clientNonce = bstr(m, 5L, "client_nonce", Bounds.NONCE_BYTES)
        val eph = bstr(m, 6L, "client_ephemeral_pubkey", P256.UNCOMPRESSED_BYTES)
        P256.decodePoint(eph) // HANDSHAKE_ECDH_INVALID_POINT before any binding check
        val proof = bstrOrBindingRequired(m, 7L, "binding_proof", 32)
        val maxFrame = uint(m, 8L, "max_frame_payload")
        if (maxFrame < Bounds.MIN_FRAME_PAYLOAD || maxFrame > Bounds.MAX_FRAME_PAYLOAD) {
            throw ProtocolError("FRAME_SIZE_INVALID", "client max_frame_payload")
        }
        return ClientHello(version, suiteIds, sessionId, clientNonce, eph, proof, maxFrame)
    }

    fun encodeClientHello(h: ClientHello): ByteArray = CborCodec.encode(
        Cbor.Map(
            linkedMapOf(
                1L to Cbor.of(1L),
                2L to Cbor.of(h.protocolVersion),
                3L to Cbor.Arr(h.cryptoSuites.map { Cbor.of(it) }),
                4L to Cbor.BStr(h.sessionId),
                5L to Cbor.BStr(h.clientNonce),
                6L to Cbor.BStr(h.clientEphemeralPubkey),
                7L to Cbor.BStr(h.bindingProof),
                8L to Cbor.of(h.maxFramePayload),
            ),
        ),
    )

    /** Parse and validate a SERVER_HELLO (plaintext PDU body). Emits ELEVEN labels [1..11]. */
    fun parseServerHello(bytes: ByteArray, offeredSuites: List<Long>): ServerHello {
        if (bytes.size > Bounds.MAX_CONTROL_PDU) throw ProtocolError("MESSAGE_TOO_LARGE")
        val m = mapOf(bytes)
        checkNoUnknown(m, setOf(1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 10L, 11L))
        if (uint(m, 1L, "type") != 17L) throw ProtocolError("MESSAGE_UNKNOWN_TYPE")
        val version = uint(m, 2L, "protocol_version")
        if (version != Bounds.PROTOCOL_VERSION.toLong()) throw ProtocolError("HANDSHAKE_UNSUPPORTED_VERSION")
        val suiteId = uint(m, 3L, "suite_id")
        if (!offeredSuites.contains(suiteId)) throw ProtocolError("HANDSHAKE_SUITE_MISMATCH")
        val transferId = bstr(m, 4L, "transfer_id", 16)
        val serverNonce = bstr(m, 5L, "server_nonce", Bounds.NONCE_BYTES)
        val eph = bstr(m, 6L, "server_ephemeral_pubkey", P256.UNCOMPRESSED_BYTES)
        P256.decodePoint(eph)
        val credential = bstr(m, 7L, "merchant_credential", null)
        if (credential.size > Bounds.MAX_CREDENTIAL_BYTES) throw ProtocolError("CREDENTIAL_MALFORMED")
        val signature = bstr(m, 8L, "transcript_signature", 64)
        val digest = bstr(m, 9L, "binding_tuple_digest", 32)
        val tuple = bstrOrBindingRequired(m, 10L, "binding_tuple", null)
        if (tuple.isEmpty()) throw ProtocolError("BINDING_REQUIRED")
        val maxFrame = uint(m, 11L, "max_frame_payload")
        if (maxFrame < Bounds.MIN_FRAME_PAYLOAD || maxFrame > Bounds.MAX_FRAME_PAYLOAD) {
            throw ProtocolError("FRAME_SIZE_INVALID", "server max_frame_payload")
        }
        return ServerHello(version, suiteId, transferId, serverNonce, eph, credential, signature, digest, tuple, maxFrame)
    }

    fun encodeServerHello(h: ServerHello): ByteArray = CborCodec.encode(
        Cbor.Map(
            linkedMapOf(
                1L to Cbor.of(17L),
                2L to Cbor.of(h.protocolVersion),
                3L to Cbor.of(h.suiteId),
                4L to Cbor.BStr(h.transferId),
                5L to Cbor.BStr(h.serverNonce),
                6L to Cbor.BStr(h.serverEphemeralPubkey),
                7L to Cbor.BStr(h.merchantCredential),
                8L to Cbor.BStr(h.transcriptSignature),
                9L to Cbor.BStr(h.bindingTupleDigest),
                10L to Cbor.BStr(h.bindingTuple),
                11L to Cbor.of(h.maxFramePayload),
            ),
        ),
    )
}
