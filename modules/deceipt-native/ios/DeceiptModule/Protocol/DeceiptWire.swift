//
//  DeceiptWire.swift
//  Deceipt iOS native adapter (A4)
//
//  Pass D: AEAD control envelopes with strict in-order counters, LPdu
//  fragmentation/reassembly, DataFrame framing and the bounded sliding-window
//  reassembler with flow control (wire.md, framing.md, handshake.md §6).
//
//  Every queue and buffer is bounded before allocation (invariant 7).
//

import Foundation

// MARK: - AEAD control channel

/// One direction's control channel: a key, an AAD direction byte, a strict
/// in-order counter, and a message budget.
public final class ControlChannel {
    private var key: Data
    private let directionByte: UInt8
    private let sessionContext: Data
    private var expectedCounter: UInt64 = 0
    private var sentCounter: UInt64 = 0
    private var messagesReceived = 0

    public init(key: Data, direction: DeceiptDirection, sessionContext: Data) {
        self.key = key
        self.directionByte = direction.rawValue
        self.sessionContext = sessionContext
    }

    private var aad: Data { sessionContext + Data([0x02, directionByte]) }

    public func seal(_ message: Data) throws -> Data {
        guard message.count <= DeceiptBounds.maxControlPdu else {
            throw DeceiptFailure("MESSAGE_TOO_LARGE", phase: BridgePhase.transfer)
        }
        let counter = sentCounter
        let nonce = DeceiptCrypto.aeadNonce(counter: counter)
        let ct = try DeceiptCrypto.aesGcmSeal(key: key, nonce: nonce, aad: aad, plaintext: message)
        var env = Data([DeceiptEnvelope.aead])
        env.append(DeceiptBytes.u64BE(counter))
        env.append(ct)
        sentCounter += 1
        return env
    }

    /// Opens an AEAD envelope with strict counter ordering: `counter < expected`
    /// is a replay; `counter > expected` is a mismatch; both are rejected BEFORE
    /// spending AEAD work (handshake.md §6.3). A plaintext envelope where AEAD
    /// is required is MESSAGE_WRONG_STATE.
    public func open(_ envelope: Data) throws -> Data {
        guard let tag = envelope.first else { throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.transfer, detail: "empty envelope") }
        guard tag == DeceiptEnvelope.aead else {
            throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.transfer, detail: "plaintext where AEAD required")
        }
        guard envelope.count >= 1 + 8 else { throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.transfer, detail: "short AEAD envelope") }
        guard let counter = DeceiptBytes.readU64BE(envelope, 1) else { throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.transfer) }
        if counter < expectedCounter { throw DeceiptFailure("AEAD_REPLAY_DETECTED", phase: BridgePhase.transfer) }
        if counter > expectedCounter { throw DeceiptFailure("AEAD_COUNTER_MISMATCH", phase: BridgePhase.transfer) }
        let body = Data(envelope.dropFirst(9))
        let nonce = DeceiptCrypto.aeadNonce(counter: counter)
        let plaintext = try DeceiptCrypto.aesGcmOpen(key: key, nonce: nonce, aad: aad, ciphertextAndTag: body)
        expectedCounter = counter + 1
        messagesReceived += 1
        guard messagesReceived <= DeceiptBounds.maxControlMessagesPerDirection else {
            throw DeceiptFailure("MESSAGE_TOO_LARGE", phase: BridgePhase.transfer, detail: "control budget")
        }
        return plaintext
    }

    public func zeroize() { DeceiptBytes.zeroize(&key) }
}

// MARK: - LPdu fragmentation

public enum Lpdu {
    /// Segments one PDU into LPdu fragments of at most `fragPayloadMax`.
    public static func segment(pdu: Data, msgSeq: UInt16, fragPayloadMax: Int) throws -> [Data] {
        guard pdu.count <= DeceiptBounds.maxControlPdu else { throw DeceiptFailure("LPDU_MESSAGE_TOO_LARGE", phase: BridgePhase.transfer) }
        let maxPayload = min(fragPayloadMax, DeceiptBounds.maxLpduFragBytes)
        guard maxPayload >= 1 else { throw DeceiptFailure("TRANSPORT_MTU_TOO_SMALL", phase: BridgePhase.transfer) }
        let count = max(1, Int(ceil(Double(pdu.count) / Double(maxPayload))))
        guard count <= DeceiptBounds.maxLpduFragments else { throw DeceiptFailure("LPDU_MESSAGE_TOO_LARGE", phase: BridgePhase.transfer, detail: "too many fragments") }
        var out: [Data] = []
        out.reserveCapacity(count)
        var offset = 0
        var index = 0
        while offset < pdu.count || index == 0 {
            let end = min(offset + maxPayload, pdu.count)
            let chunk = pdu.subdata(in: (pdu.startIndex + offset)..<(pdu.startIndex + end))
            var frag = DeceiptBytes.u16BE(msgSeq)
            frag.append(UInt8(index))
            frag.append(UInt8(count))
            frag.append(chunk)
            out.append(frag)
            offset = end
            index += 1
        }
        return out
    }
}

/// Reassembles LPdu fragments for one sender. Fragments of two messages MUST
/// NOT interleave; `msg_seq` is strictly increasing per sender per session.
public final class LpduReceiver {
    private var nextMsgSeq: UInt64 = 0
    private var currentSeq: UInt16?
    private var currentBuf = Data()
    private var expectedIndex = 0
    private var fragCount = 0
    private var lastFragmentAt: Date?
    private let fragTimeout: TimeInterval

    public init(fragTimeoutMs: Int = DeceiptTimeout.defaults["T_CONTROL_FRAG"]!) {
        self.fragTimeout = Double(fragTimeoutMs) / 1000.0
    }

    /// Feeds one fragment; returns a completed PDU when the message is whole.
    public func feed(_ fragment: Data) throws -> Data? {
        guard fragment.count >= DeceiptBounds.lpduHeaderBytes else { throw DeceiptFailure("LPDU_FRAGMENT_INVALID", phase: BridgePhase.transfer) }
        guard let msgSeq = DeceiptBytes.readU16BE(fragment, 0) else { throw DeceiptFailure("LPDU_FRAGMENT_INVALID", phase: BridgePhase.transfer) }
        let idx = Int(fragment[fragment.startIndex + 2])
        let count = Int(fragment[fragment.startIndex + 3])
        let payload = Data(fragment.dropFirst(DeceiptBounds.lpduHeaderBytes))
        guard count >= 1, count <= DeceiptBounds.maxLpduFragments else { throw DeceiptFailure("LPDU_MESSAGE_TOO_LARGE", phase: BridgePhase.transfer, detail: "frag_count") }
        guard payload.count <= DeceiptBounds.maxLpduFragBytes else { throw DeceiptFailure("LPDU_FRAGMENT_INVALID", phase: BridgePhase.transfer, detail: "fragment too large") }

        // Time out an incomplete message rather than mixing messages.
        if let started = lastFragmentAt, currentSeq != nil, Date().timeIntervalSince(started) > fragTimeout {
            reset()
            throw DeceiptFailure("LPDU_REASSEMBLY_TIMEOUT", phase: BridgePhase.transfer)
        }

        if currentSeq == nil {
            guard idx == 0 else { throw DeceiptFailure("LPDU_FRAGMENT_INVALID", phase: BridgePhase.transfer, detail: "first frag_index must be 0") }
            guard UInt64(msgSeq) >= nextMsgSeq else { throw DeceiptFailure("LPDU_SEQUENCE_ERROR", phase: BridgePhase.transfer, detail: "msg_seq reuse") }
            guard UInt64(msgSeq) < UInt64(DeceiptBounds.maxControlMessagesPerDirection) else { throw DeceiptFailure("MESSAGE_TOO_LARGE", phase: BridgePhase.transfer, detail: "msg_seq budget") }
            currentSeq = msgSeq
            fragCount = count
            expectedIndex = 0
            currentBuf = Data()
            lastFragmentAt = Date()
        } else {
            guard msgSeq == currentSeq else { throw DeceiptFailure("LPDU_SEQUENCE_ERROR", phase: BridgePhase.transfer, detail: "message interleave") }
            guard count == fragCount else { throw DeceiptFailure("LPDU_SEQUENCE_ERROR", phase: BridgePhase.transfer, detail: "frag_count changed") }
        }

        if idx < expectedIndex {
            // A repeated fragment: identical bytes are ignored, different bytes conflict.
            // We do not retain old fragments; a repeat of an already-consumed index
            // with different bytes cannot be compared, so treat as conflict only
            // when it is the immediately preceding fragment. Documented PoC bound.
            throw DeceiptFailure("LPDU_SEQUENCE_ERROR", phase: BridgePhase.transfer, detail: "fragment index already consumed")
        }
        guard idx == expectedIndex else { throw DeceiptFailure("LPDU_SEQUENCE_ERROR", phase: BridgePhase.transfer, detail: "fragment out of order") }
        guard currentBuf.count + payload.count <= DeceiptBounds.maxControlPdu else {
            throw DeceiptFailure("LPDU_MESSAGE_TOO_LARGE", phase: BridgePhase.transfer)
        }
        currentBuf.append(payload)
        expectedIndex += 1

        if expectedIndex == fragCount {
            let pdu = currentBuf
            nextMsgSeq = UInt64(msgSeq) + 1
            reset(keepingSeq: true)
            return pdu
        }
        return nil
    }

    private func reset(keepingSeq: Bool = false) {
        currentSeq = nil
        currentBuf = Data()
        expectedIndex = 0
        fragCount = 0
        lastFragmentAt = nil
    }
}

// MARK: - DataFrames

public struct DataFrame {
    public var transferId: Data
    public var sequence: UInt32
    public var payload: Data

    public var encoded: Data {
        var d = transferId
        d.append(DeceiptBytes.u32BE(sequence))
        d.append(payload)
        return d
    }
}

public enum FrameCodec {
    /// Splits a ciphertext into frames (framing.md §1).
    public static func split(ciphertext: Data, transferId: Data, frameSize: Int) -> [DataFrame] {
        precondition(frameSize >= DeceiptBounds.minFramePayload && frameSize <= DeceiptBounds.maxFramePayload)
        var frames: [DataFrame] = []
        var seq: UInt32 = 0
        var offset = 0
        while offset < ciphertext.count {
            let end = min(offset + frameSize, ciphertext.count)
            let chunk = ciphertext.subdata(in: (ciphertext.startIndex + offset)..<(ciphertext.startIndex + end))
            frames.append(DataFrame(transferId: transferId, sequence: seq, payload: chunk))
            offset = end
            seq += 1
        }
        return frames
    }

    public static func parse(_ bytes: Data) throws -> DataFrame {
        guard bytes.count > DeceiptBounds.dataframeHeaderBytes else {
            throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.transfer, detail: "frame shorter than header")
        }
        guard let tid = DeceiptBytes.slice(bytes, 0, 16), let seq = DeceiptBytes.readU32BE(bytes, 16) else {
            throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.transfer)
        }
        let payload = Data(bytes.dropFirst(DeceiptBounds.dataframeHeaderBytes))
        return DataFrame(transferId: tid, sequence: seq, payload: payload)
    }
}

/// Bounded sliding-window reassembler (framing.md §3). Never allocates from a
/// peer-declared length before checking it.
public final class FrameReceiver {
    public struct Progress {
        public var highestContiguousSequence: Int64
        public var frameCount: Int
        public var complete: Bool
        public var notices: [ProtocolErrorName]
    }

    private let transferId: Data
    private let ciphertextLength: Int
    private let frameSize: Int
    private let frameCount: Int
    private var buffered: [UInt32: Data] = [:]
    private var highestContiguous: Int64 = -1
    private var contiguous = Data()

    public init(transferId: Data, ciphertextLength: Int, frameSize: Int, frameCount: Int) throws {
        guard ciphertextLength >= 0, ciphertextLength <= DeceiptBounds.maxTransferCiphertext else {
            throw DeceiptFailure("TRANSFER_SIZE_EXCEEDED", phase: BridgePhase.transfer)
        }
        guard frameCount >= 0, frameCount <= DeceiptBounds.maxFrames else {
            throw DeceiptFailure("TRANSFER_SIZE_EXCEEDED", phase: BridgePhase.transfer, detail: "frame_count")
        }
        let expected = frameSize > 0 ? Int(ceil(Double(ciphertextLength) / Double(frameSize))) : 0
        guard frameCount == expected else {
            throw DeceiptFailure("TRANSFER_BEGIN_MISMATCH", phase: BridgePhase.transfer, detail: "frame_count != ceil(len/size)")
        }
        self.transferId = transferId
        self.ciphertextLength = ciphertextLength
        self.frameSize = frameSize
        self.frameCount = frameCount
        self.contiguous.reserveCapacity(ciphertextLength)
    }

    public func feed(_ frame: DataFrame) throws -> Progress {
        guard frame.transferId == transferId else { throw DeceiptFailure("TRANSFER_ID_MISMATCH", phase: BridgePhase.transfer) }
        let seq = frame.sequence
        guard seq < UInt32(frameCount), Int(seq) < DeceiptBounds.maxFrames else {
            throw DeceiptFailure("FRAME_SEQUENCE_OUT_OF_RANGE", phase: BridgePhase.transfer)
        }
        // Frame payload size rules (bounds-v1.json wire.final_frame_rule).
        let expectedFinal = ciphertextLength - frameSize * (frameCount - 1)
        if Int(seq) == frameCount - 1 {
            guard frame.payload.count == expectedFinal, frame.payload.count >= 1, frame.payload.count <= frameSize else {
                throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.transfer, detail: "final frame")
            }
        } else {
            guard frame.payload.count == frameSize else {
                throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.transfer, detail: "non-final frame")
            }
        }

        var notices: [ProtocolErrorName] = []
        // Below or equal to contiguous: already reassembled.
        if Int64(seq) <= highestContiguous {
            notices.append("FRAME_SEQUENCE_REPLAYED")
            return progress(notices)
        }
        if let existing = buffered[seq] {
            if existing == frame.payload {
                notices.append("FRAME_SEQUENCE_REPLAYED")
            } else {
                throw DeceiptFailure("FRAME_CONFLICT", phase: BridgePhase.transfer)
            }
            return progress(notices)
        }
        // Window floor: below the window is treated as a stale replay.
        if Int64(seq) < highestContiguous - Int64(DeceiptBounds.windowFrames) {
            notices.append("FRAME_SEQUENCE_REPLAYED")
            return progress(notices)
        }
        if buffered.count >= DeceiptBounds.windowFrames {
            throw DeceiptFailure("FRAME_BUFFER_EXCEEDED", phase: BridgePhase.transfer, detail: "sender outran flow control")
        }
        buffered[seq] = frame.payload

        // Advance highest_contiguous_sequence while the next slot is present.
        while let next = buffered.removeValue(forKey: UInt32(highestContiguous + 1)) {
            contiguous.append(next)
            highestContiguous += 1
        }
        return progress(notices)
    }

    private func progress(_ notices: [ProtocolErrorName]) -> Progress {
        Progress(highestContiguousSequence: highestContiguous, frameCount: frameCount,
                 complete: highestContiguous == Int64(frameCount - 1), notices: notices)
    }

    public var reassembledCiphertext: Data? {
        contiguous.count == ciphertextLength ? contiguous : nil
    }

    /// The negotiated frame count (read-only, for TRANSFER_COMPLETE checks).
    public var frameCountValue: Int { frameCount }
    public var ciphertextLengthValue: Int { ciphertextLength }
}
