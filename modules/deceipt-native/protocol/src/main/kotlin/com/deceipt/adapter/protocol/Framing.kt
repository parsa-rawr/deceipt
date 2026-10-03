package com.deceipt.adapter.protocol

import com.deceipt.adapter.crypto.Crypto

/**
 * Framing, LPdu segmentation and AEAD control envelopes
 * (docs/protocol/framing.md, docs/protocol/wire.md, deceipt-proto-r3).
 *
 * Frames are fragments of ONE ciphertext, reassembled before AEAD open; BLE
 * packet boundaries NEVER influence cryptographic object boundaries.
 */
object Frame {

    /** `DataFrame = transfer_id(16) || u32_be(sequence_number) || payload_bytes`. */
    fun encode(transferId: ByteArray, sequence: Long, payload: ByteArray): ByteArray {
        require(transferId.size == 16)
        return Bytes.concat(transferId, Bytes.u32be(sequence), payload)
    }

    data class Decoded(val transferId: ByteArray, val sequence: Long, val payload: ByteArray)

    fun decode(frame: ByteArray, frameSize: Int, frameCount: Int): Decoded {
        if (frame.size < Bounds.DATAFRAME_HEADER_BYTES) throw ProtocolError("FRAME_SIZE_INVALID", "frame shorter than header")
        val transferId = frame.copyOfRange(0, 16)
        val seq = Bytes.readU32be(frame, 16)
        val payload = frame.copyOfRange(20, frame.size)
        // Final-frame rule (r3): non-final 16..frame_size, final 1..frame_size.
        val isFinal = seq == (frameCount - 1).toLong()
        if (payload.size > frameSize) throw ProtocolError("FRAME_SIZE_INVALID", "frame payload above frame_size")
        if (isFinal) {
            if (payload.size < Bounds.FINAL_FRAME_MIN_PAYLOAD) throw ProtocolError("FRAME_SIZE_INVALID", "final frame empty")
        } else {
            if (payload.size < Bounds.MIN_FRAME_PAYLOAD) throw ProtocolError("FRAME_SIZE_INVALID", "non-final frame below minimum")
        }
        return Decoded(transferId, seq, payload)
    }

    /** Split a ciphertext into `frameCount` frames of `frameSize` (final frame may be short). */
    fun split(transferId: ByteArray, ciphertext: ByteArray, frameSize: Int): List<ByteArray> {
        val count = frameCount(ciphertext.size, frameSize)
        val out = ArrayList<ByteArray>(count)
        for (i in 0 until count) {
            val from = i * frameSize
            val to = minOf(from + frameSize, ciphertext.size)
            out.add(encode(transferId, i.toLong(), ciphertext.copyOfRange(from, to)))
        }
        return out
    }

    fun frameCount(ciphertextLength: Int, frameSize: Int): Int {
        require(frameSize in Bounds.MIN_FRAME_PAYLOAD..Bounds.MAX_FRAME_PAYLOAD)
        return (ciphertextLength + frameSize - 1) / frameSize
    }

    /**
     * Bounded sliding-window receiver (framing.md 3). Allocates the ciphertext
     * buffer only after checking the peer-declared length against the cap.
     */
    class Receiver(
        val transferId: ByteArray,
        val ciphertextLength: Int,
        val frameCount: Int,
        val frameSize: Int,
    ) {
        init {
            if (ciphertextLength > Bounds.MAX_TRANSFER_CIPHERTEXT) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
            if (frameCount > Bounds.MAX_FRAMES) throw ProtocolError("TRANSFER_SIZE_EXCEEDED")
            if (frameCount != ((ciphertextLength + frameSize - 1) / frameSize)) {
                throw ProtocolError("TRANSFER_BEGIN_MISMATCH", "frame_count != ceil(ciphertext_length/frame_size)")
            }
        }

        private val buffer = ByteArray(ciphertextLength)
        private val present = BooleanArray(frameCount)
        /** Distinct un-acked slots above the contiguous prefix; bounded by WINDOW_FRAMES. */
        private var outOfOrderSlots = 0

        var highestContiguousSequence: Int = -1
            private set

        /** @return true when `FRAME_SEQUENCE_REPLAYED` (ignored), false otherwise. */
        fun add(frame: ByteArray): Boolean {
            val d = decode(frame, frameSize, frameCount)
            if (!Bytes.constantTimeEquals(d.transferId, transferId)) throw ProtocolError("TRANSFER_ID_MISMATCH")
            if (d.sequence >= frameCount) throw ProtocolError("FRAME_SEQUENCE_OUT_OF_RANGE")
            val seq = d.sequence.toInt()

            if (present[seq]) {
                val existing = buffer.copyOfRange(offset(seq), offset(seq) + expectedPayloadLen(seq))
                if (existing.contentEquals(d.payload)) return true
                throw ProtocolError("FRAME_CONFLICT")
            }
            // Below the window floor: a stale duplicate, ignored.
            if (seq <= highestContiguousSequence - Bounds.WINDOW_FRAMES) return true
            if (seq > highestContiguousSequence) {
                outOfOrderSlots += 1
                if (outOfOrderSlots > Bounds.WINDOW_FRAMES) throw ProtocolError("FRAME_BUFFER_EXCEEDED")
            }
            System.arraycopy(d.payload, 0, buffer, offset(seq), d.payload.size)
            present[seq] = true
            while (highestContiguousSequence + 1 < frameCount && present[highestContiguousSequence + 1]) {
                highestContiguousSequence += 1
                if (highestContiguousSequence <= seq + 0) outOfOrderSlots = maxOf(0, outOfOrderSlots - 1)
            }
            return false
        }

        val isComplete: Boolean get() = highestContiguousSequence == frameCount - 1

        /** The reassembled ciphertext. Only valid once `isComplete`. */
        fun ciphertext(): ByteArray {
            if (!isComplete) throw ProtocolError("TRANSFER_INCOMPLETE")
            return buffer
        }

        fun payloadHash(): ByteArray = Crypto.sha256(buffer)

        private fun offset(seq: Int): Int = seq * frameSize
        private fun expectedPayloadLen(seq: Int): Int =
            if (seq == frameCount - 1) ciphertextLength - frameSize * (frameCount - 1) else frameSize
    }
}

/**
 * LPdu segmentation for control messages (wire.md 3).
 * `fragment = u16_be(msg_seq) || u8(frag_index) || u8(frag_count) || fragment_bytes`
 */
object Lpdu {

    fun fragment(pdu: ByteArray, msgSeq: Int, maxFragmentBytes: Int): List<ByteArray> {
        if (pdu.size > Bounds.MAX_CONTROL_PDU) throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")
        val fragBytes = minOf(maxFragmentBytes, Bounds.MAX_LPDU_FRAG_BYTES)
        if (fragBytes <= 0) throw ProtocolError("TRANSPORT_MTU_TOO_SMALL")
        val count = (pdu.size + fragBytes - 1) / fragBytes
        if (count > Bounds.MAX_LPDU_FRAGMENTS) throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")
        val out = ArrayList<ByteArray>(count)
        for (i in 0 until count) {
            val from = i * fragBytes
            val to = minOf(from + fragBytes, pdu.size)
            out.add(
                Bytes.concat(
                    Bytes.u16be(msgSeq),
                    byteArrayOf(i.toByte(), count.toByte()),
                    pdu.copyOfRange(from, to),
                ),
            )
        }
        return out
    }

    /** Bounded reassembler: never allocates from a peer-declared fragment count. */
    class Reassembler {
        private var msgSeq = -1
        private var expectedNext = 0
        private var fragCount = -1
        private var acc: ByteArray? = null
        private var filled = 0

        fun reset() {
            msgSeq = -1; expectedNext = 0; fragCount = -1; acc = null; filled = 0
        }

        /** @return the reassembled PDU when a message completes, else null. */
        fun accept(fragment: ByteArray, firstFragmentExpected: Boolean = false): ByteArray? {
            if (fragment.size < Bounds.LPDU_HEADER_BYTES) throw ProtocolError("LPDU_FRAGMENT_INVALID", "short fragment")
            val seq = Bytes.readU16be(fragment, 0)
            val index = fragment[2].toInt() and 0xff
            val count = fragment[3].toInt() and 0xff
            val body = fragment.copyOfRange(4, fragment.size)
            if (count < 1) throw ProtocolError("LPDU_FRAGMENT_INVALID", "frag_count zero")
            if (count > Bounds.MAX_LPDU_FRAGMENTS) throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")
            if (body.size > Bounds.MAX_LPDU_FRAG_BYTES) throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")

            if (msgSeq == -1) {
                if (index != 0) throw ProtocolError("LPDU_FRAGMENT_INVALID", "first fragment index not zero")
                msgSeq = seq; expectedNext = 0; fragCount = count
                acc = ByteArray(0)
            } else if (seq != msgSeq) {
                throw ProtocolError("LPDU_SEQUENCE_ERROR", "message interleave or msg_seq reuse")
            } else if (count != fragCount) {
                throw ProtocolError("LPDU_FRAGMENT_INVALID", "frag_count inconsistent")
            }
            if (index != expectedNext) {
                if (index < expectedNext) throw ProtocolError("LPDU_SEQUENCE_ERROR", "repeated fragment index")
                throw ProtocolError("LPDU_SEQUENCE_ERROR", "fragment index skipped")
            }
            if (filled + body.size > Bounds.MAX_CONTROL_PDU) throw ProtocolError("LPDU_MESSAGE_TOO_LARGE")
            acc = Bytes.concat(acc!!, body)
            filled += body.size
            expectedNext += 1
            if (expectedNext == fragCount) {
                val pdu = acc!!
                val result = pdu
                reset()
                return result
            }
            return null
        }
    }
}

/**
 * AEAD control envelopes (handshake.md 6.3, wire.md 6).
 *
 * `plaintext = 0x00 || CBOR`; `aead = 0x01 || u64_be(counter) || AES-256-GCM(key, nonce(counter), aad, CBOR)`.
 * Only ClientHello/ServerHello (and pre-key ERROR) may be plaintext.
 */
object Envelope {

    fun plaintext(messageCbor: ByteArray): ByteArray = Bytes.concat(byteArrayOf(0x00), messageCbor)

    fun seal(key: ByteArray, counter: Long, sessionContext: ByteArray, dirTag: ByteArray, messageCbor: ByteArray): ByteArray {
        val nonce = Crypto.aeadNonce(counter)
        val ciphertext = Crypto.aesGcmSeal(key, nonce, aadControl(sessionContext, dirTag), messageCbor)
        return Bytes.concat(byteArrayOf(0x01), Bytes.u64be(counter), ciphertext)
    }

    private fun aadControl(sessionContext: ByteArray, dirTag: ByteArray): ByteArray =
        Bytes.concat(sessionContext, byteArrayOf(0x02), dirTag)

    /** Strict in-order AEAD control receiver for one direction. */
    class Receiver(
        private val key: ByteArray,
        private val sessionContext: ByteArray,
        private val dirTag: ByteArray, // 0x00 = c2m, 0x01 = m2c
    ) {
        private var expectedCounter = 0L

        /**
         * @param requireAead false only while no keys exist (plaintext ERROR allowed).
         * @return the decrypted CBOR message bytes.
         */
        fun open(envelope: ByteArray, requireAead: Boolean = true): ByteArray {
            if (envelope.isEmpty()) throw ProtocolError("CBOR_MALFORMED", "empty envelope")
            val tag = envelope[0].toInt() and 0xff
            if (tag == Bounds.ENVELOPE_PLAINTEXT) {
                if (requireAead) throw ProtocolError("MESSAGE_WRONG_STATE", "plaintext envelope where AEAD is required")
                return envelope.copyOfRange(1, envelope.size)
            }
            if (tag != Bounds.ENVELOPE_AEAD) throw ProtocolError("MESSAGE_UNKNOWN_TYPE", "unknown envelope tag")
            if (envelope.size < 9 + Bounds.AEAD_TAG_BYTES) throw ProtocolError("CBOR_MALFORMED", "short AEAD envelope")
            val counter = Bytes.readU64be(envelope, 1)
            if (counter < expectedCounter) throw ProtocolError("AEAD_REPLAY_DETECTED")
            if (counter > expectedCounter) throw ProtocolError("AEAD_COUNTER_MISMATCH")
            val nonce = Crypto.aeadNonce(counter)
            val aad = aadControl(sessionContext, dirTag)
            val plaintext = Crypto.aesGcmOpen(key, nonce, aad, envelope.copyOfRange(9, envelope.size))
                ?: throw ProtocolError("AEAD_AUTH_FAILED")
            expectedCounter += 1
            return plaintext
        }
    }
}
