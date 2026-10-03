//
//  DeceiptHandshake.swift
//  Deceipt iOS native adapter (A4)
//
//  Pass C: CLIENT_HELLO / SERVER_HELLO, the canonical 372-byte transcript,
//  the R4-01 rebuild rule (handshake.md §3.1), the key schedule (§5), and the
//  three nominal session types (§9).
//
//  The transcript is built from *received plaintext only*; the receiver never
//  trusts a client-side assumption about max_frame_payload or the tuple.
//

import Foundation

public struct ClientHelloMsg {
    public var protocolVersion: UInt64
    public var cryptoSuites: [UInt64]
    public var sessionId: Data
    public var clientNonce: Data
    public var clientEphemeralPubkey: Data
    public var bindingProof: Data
    public var maxFramePayload: UInt64
}

public struct ServerHelloMsg {
    public var protocolVersion: UInt64
    public var suiteId: UInt64
    public var transferId: Data
    public var serverNonce: Data
    public var serverEphemeralPubkey: Data
    public var merchantCredential: Data
    public var transcriptSignature: Data
    public var bindingTupleDigest: Data
    public var bindingTuple: Data
    public var maxFramePayload: UInt64
}

/// The four directional keys plus the transcript-derived session context.
public struct SessionKeys {
    public var kC2mCtrl: Data
    public var kM2cCtrl: Data
    public var kM2cPayload: Data
    public var kExporter: Data
    public var transcriptHash: Data
    public var transferId: Data

    public var sessionContext: Data { transcriptHash + transferId }

    public mutating func zeroize() {
        DeceiptBytes.zeroize(&kC2mCtrl)
        DeceiptBytes.zeroize(&kM2cCtrl)
        DeceiptBytes.zeroize(&kM2cPayload)
        DeceiptBytes.zeroize(&kExporter)
    }
}

public enum DeceiptHandshake {
    // MARK: Encode

    public static func encodeClientHello(_ h: ClientHelloMsg) -> Data {
        let map = CborValue.map([
            (.int(1), .int(DeceiptMessageType.clientHello == 1 ? 1 : 1)),
            (.int(2), .uint(h.protocolVersion)),
            (.int(3), .array(h.cryptoSuites.map { CborValue.uint($0) })),
            (.int(4), .bytes(h.sessionId)),
            (.int(5), .bytes(h.clientNonce)),
            (.int(6), .bytes(h.clientEphemeralPubkey)),
            (.int(7), .bytes(h.bindingProof)),
            (.int(8), .uint(h.maxFramePayload)),
        ])
        return Data([DeceiptEnvelope.plaintext]) + ((try? CborEncoder.encode(map)) ?? Data())
    }

    public static func encodeServerHello(_ h: ServerHelloMsg) -> Data {
        let map = CborValue.map([
            (.int(1), .uint(DeceiptMessageType.serverHello)),
            (.int(2), .uint(h.protocolVersion)),
            (.int(3), .uint(h.suiteId)),
            (.int(4), .bytes(h.transferId)),
            (.int(5), .bytes(h.serverNonce)),
            (.int(6), .bytes(h.serverEphemeralPubkey)),
            (.int(7), .bytes(h.merchantCredential)),
            (.int(8), .bytes(h.transcriptSignature)),
            (.int(9), .bytes(h.bindingTupleDigest)),
            (.int(10), .bytes(h.bindingTuple)),
            (.int(11), .uint(h.maxFramePayload)),
        ])
        return Data([DeceiptEnvelope.plaintext]) + ((try? CborEncoder.encode(map)) ?? Data())
    }

    // MARK: Parse

    private static func plaintextBody(_ pdu: Data) throws -> CborValue {
        guard pdu.count >= 1, pdu[pdu.startIndex] == DeceiptEnvelope.plaintext else {
            throw DeceiptFailure("MESSAGE_WRONG_STATE", phase: BridgePhase.handshake, detail: "expected plaintext envelope")
        }
        return try CborDecoder.decode(Data(pdu.dropFirst()))
    }

    public static func parseClientHello(_ pdu: Data) throws -> ClientHelloMsg {
        let v = try plaintextBody(pdu)
        guard v.field(1)?.asUInt == DeceiptMessageType.clientHello, let keys = v.mapKeysAsInts(), keys.allSatisfy({ (1...8).contains($0) }) else {
            throw DeceiptFailure("MESSAGE_UNKNOWN_TYPE", phase: BridgePhase.handshake)
        }
        guard let pv = v.field(2)?.asUInt else { throw DeceiptFailure("MESSAGE_MISSING_FIELD", phase: BridgePhase.handshake, detail: "protocol_version") }
        guard pv == UInt64(DeceiptProto.protocolVersion) else { throw DeceiptFailure("HANDSHAKE_UNSUPPORTED_VERSION", phase: BridgePhase.handshake) }
        guard let suites = v.field(3)?.asArray, !suites.isEmpty else {
            throw DeceiptFailure("HANDSHAKE_NO_COMMON_SUITE", phase: BridgePhase.handshake, detail: "empty suites")
        }
        let suiteIds = suites.compactMap { $0.asUInt }
        guard suiteIds.contains(UInt64(DeceiptProto.suiteId)) else {
            throw DeceiptFailure("HANDSHAKE_NO_COMMON_SUITE", phase: BridgePhase.handshake)
        }
        guard let sessionId = v.field(4)?.asData, sessionId.count == 16 else { throw DeceiptFailure("MESSAGE_FIELD_TYPE", phase: BridgePhase.handshake, detail: "session_id") }
        guard let nonce = v.field(5)?.asData, nonce.count == 32 else { throw DeceiptFailure("MESSAGE_FIELD_TYPE", phase: BridgePhase.handshake, detail: "client_nonce") }
        guard let eph = v.field(6)?.asData, eph.count == 65 else { throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.handshake, detail: "client_ephemeral_pubkey length") }
        _ = try DeceiptCrypto.decodeP256PublicKey(eph) // on-curve check
        guard let proof = v.field(7)?.asData, proof.count == 32 else { throw DeceiptFailure("BINDING_PROOF_INVALID", phase: BridgePhase.handshake) }
        guard let mfp = v.field(8)?.asUInt, (UInt64(DeceiptBounds.minFramePayload)...UInt64(DeceiptBounds.maxFramePayload)).contains(mfp) else {
            throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.handshake, detail: "max_frame_payload")
        }
        return ClientHelloMsg(protocolVersion: pv, cryptoSuites: suiteIds, sessionId: sessionId, clientNonce: nonce,
                              clientEphemeralPubkey: eph, bindingProof: proof, maxFramePayload: mfp)
    }

    public static func parseServerHello(_ pdu: Data, offeredSuites: [UInt64]) throws -> ServerHelloMsg {
        let v = try plaintextBody(pdu)
        guard v.field(1)?.asUInt == DeceiptMessageType.serverHello, let keys = v.mapKeysAsInts(), keys.allSatisfy({ (1...11).contains($0) }) else {
            throw DeceiptFailure("MESSAGE_UNKNOWN_TYPE", phase: BridgePhase.handshake)
        }
        guard let pv = v.field(2)?.asUInt, pv == UInt64(DeceiptProto.protocolVersion) else {
            throw DeceiptFailure("HANDSHAKE_UNSUPPORTED_VERSION", phase: BridgePhase.handshake)
        }
        guard let suite = v.field(3)?.asUInt, offeredSuites.contains(suite) else {
            throw DeceiptFailure("HANDSHAKE_SUITE_MISMATCH", phase: BridgePhase.handshake)
        }
        guard let transferId = v.field(4)?.asData, transferId.count == 16 else { throw DeceiptFailure("MESSAGE_FIELD_TYPE", phase: BridgePhase.handshake, detail: "transfer_id") }
        guard let nonce = v.field(5)?.asData, nonce.count == 32 else { throw DeceiptFailure("MESSAGE_FIELD_TYPE", phase: BridgePhase.handshake, detail: "server_nonce") }
        guard let eph = v.field(6)?.asData, eph.count == 65 else { throw DeceiptFailure("HANDSHAKE_ECDH_INVALID_POINT", phase: BridgePhase.handshake, detail: "server_ephemeral_pubkey length") }
        _ = try DeceiptCrypto.decodeP256PublicKey(eph)
        guard let cred = v.field(7)?.asData, cred.count <= DeceiptBounds.maxCredentialBytes else { throw DeceiptFailure("CREDENTIAL_MALFORMED", phase: BridgePhase.handshake, detail: "credential size") }
        guard let sig = v.field(8)?.asData, sig.count == 64 else { throw DeceiptFailure("HANDSHAKE_SIGNATURE_INVALID", phase: BridgePhase.handshake, detail: "signature length") }
        guard let digest = v.field(9)?.asData, digest.count == 32 else { throw DeceiptFailure("HANDSHAKE_TRANSCRIPT_MISMATCH", phase: BridgePhase.handshake, detail: "digest length") }
        guard let tuple = v.field(10)?.asData, !tuple.isEmpty else { throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.handshake) }
        guard tuple.count <= DeceiptBounds.maxBindingBytes else { throw DeceiptFailure("BINDING_REQUIRED", phase: BridgePhase.handshake, detail: "tuple too large") }
        guard let mfp = v.field(11)?.asUInt, (UInt64(DeceiptBounds.minFramePayload)...UInt64(DeceiptBounds.maxFramePayload)).contains(mfp) else {
            throw DeceiptFailure("FRAME_SIZE_INVALID", phase: BridgePhase.handshake, detail: "max_frame_payload")
        }
        return ServerHelloMsg(protocolVersion: pv, suiteId: suite, transferId: transferId, serverNonce: nonce,
                              serverEphemeralPubkey: eph, merchantCredential: cred, transcriptSignature: sig,
                              bindingTupleDigest: digest, bindingTuple: tuple, maxFramePayload: mfp)
    }

    // MARK: Transcript

    /// Builds the canonical 372-byte transcript (handshake.md §3).
    public static func buildTranscript(
        protocolVersion: UInt16,
        suiteId: UInt16,
        clientNonce: Data,
        clientEphemeralPubkey: Data,
        serverNonce: Data,
        serverEphemeralPubkey: Data,
        transferId: Data,
        sessionId: Data,
        bindingTupleDigest: Data,
        maxFramePayload: UInt16,
        bindingTuple: Data
    ) -> Data {
        var t = Data()
        t.append(Data(DeceiptProto.domainLabel.utf8))          // 20
        t.append(DeceiptBytes.u16BE(protocolVersion))          // 2
        t.append(DeceiptBytes.u16BE(suiteId))                  // 2
        t.append(clientNonce)                                  // 32
        t.append(clientEphemeralPubkey)                        // 65
        t.append(serverNonce)                                  // 32
        t.append(serverEphemeralPubkey)                        // 65
        t.append(transferId)                                   // 16
        t.append(sessionId)                                    // 16
        t.append(bindingTupleDigest)                           // 32
        t.append(DeceiptBytes.u16BE(maxFramePayload))          // 2
        t.append(Data([UInt8(bindingTuple.count & 0xff)]))     // 1
        t.append(bindingTuple)                                 // var
        return t
    }

    public struct TranscriptRebuild {
        public var transcript: Data
        public var tuple: DeceiptBinding.ParsedTuple
    }

    /// R4-01 rebuild: the receiver rebuilds the signed transcript from received
    /// plaintext only. SERVER_HELLO label 10 is authoritative over label 9.
    public static func rebuildTranscript(clientHello: ClientHelloMsg, serverHello: ServerHelloMsg) throws -> TranscriptRebuild {
        let tuple = try DeceiptBinding.parseBindingTuple(serverHello.bindingTuple)
        // 1. label 10 authoritative: recompute the digest and compare to label 9.
        let recomputed = DeceiptBinding.bindingTupleDigest(serverHello.bindingTuple)
        guard recomputed == serverHello.bindingTupleDigest else {
            throw DeceiptFailure("HANDSHAKE_TRANSCRIPT_MISMATCH", phase: BridgePhase.handshake, detail: "label 9 != digest(label 10)")
        }
        // 2. label 4 transfer_id == tuple[2]
        guard serverHello.transferId == tuple.transferId else {
            throw DeceiptFailure("TRANSFER_ID_MISMATCH", phase: BridgePhase.handshake)
        }
        // 4. tuple[1] session_id == CLIENT_HELLO label 4
        guard tuple.sessionId == clientHello.sessionId else {
            throw DeceiptFailure("BINDING_UNKNOWN_SESSION", phase: BridgePhase.handshake)
        }
        let transcript = buildTranscript(
            protocolVersion: UInt16(DeceiptProto.protocolVersion),
            suiteId: UInt16(serverHello.suiteId),
            clientNonce: clientHello.clientNonce,
            clientEphemeralPubkey: clientHello.clientEphemeralPubkey,
            serverNonce: serverHello.serverNonce,
            serverEphemeralPubkey: serverHello.serverEphemeralPubkey,
            transferId: tuple.transferId,
            sessionId: tuple.sessionId,
            bindingTupleDigest: serverHello.bindingTupleDigest,
            maxFramePayload: UInt16(serverHello.maxFramePayload),
            bindingTuple: serverHello.bindingTuple
        )
        return TranscriptRebuild(transcript: transcript, tuple: tuple)
    }

    // MARK: Key schedule (handshake.md §5)

    public static func deriveKeys(sharedSecret: Data, transcriptHash: Data, transferId: Data) -> SessionKeys {
        let prk = DeceiptCrypto.hkdfExtract(salt: transcriptHash, ikm: sharedSecret)
        var info = Data(DeceiptProto.transferKdfPrefix.utf8)
        info.append(transcriptHash)
        let okm = DeceiptCrypto.hkdfExpand(prk: prk, info: info, outputLength: 128)
        return SessionKeys(
            kC2mCtrl: okm.subdata(in: 0..<32),
            kM2cCtrl: okm.subdata(in: 32..<64),
            kM2cPayload: okm.subdata(in: 64..<96),
            kExporter: okm.subdata(in: 96..<128),
            transcriptHash: transcriptHash,
            transferId: transferId
        )
    }

    /// Full key derivation given local ephemeral private and the rebuild.
    public static func deriveSessionKeys(
        localEphemeral: DeceiptCrypto.EphemeralKeyPair,
        peerEphemeralPubkey: Data,
        transcript: Data,
        transferId: Data
    ) throws -> SessionKeys {
        let peer = try DeceiptCrypto.decodeP256PublicKey(peerEphemeralPubkey)
        let shared = DeceiptCrypto.ecdhSharedSecretX(privateKey: localEphemeral.privateKey, peerPublicKey: peer)
        let transcriptHash = DeceiptCrypto.sha256(transcript)
        return deriveKeys(sharedSecret: shared, transcriptHash: transcriptHash, transferId: transferId)
    }
}

/// Three nominal peer authentication levels (handshake.md §9).
public enum PeerAuthLevel {
    case keysOnly             // no verified ServerHello — diagnostics only, MUST NOT transfer
    case unverifiedPeer       // credential unknown-issuer, transcript verified vs self-asserted device key
    case authenticated        // credential chained to a pinned anchor AND transcript verified
}
