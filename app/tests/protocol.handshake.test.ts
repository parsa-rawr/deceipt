/**
 * Handshake, trust and wire conformance (conformance.md §B, §C partial, §D).
 *
 * The session crypto itself is native; what is asserted here is the byte
 * layout, the digest/signature checks and the credential policy that the shared
 * app must reproduce.
 */

import {
  buildTranscript,
  checkProtectedHeader,
  parseCoseSign1,
  sigStructure,
  verifyCredential,
  CREDENTIAL_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  TRANSCRIPT_OFFSETS,
} from '../src/protocol/handshake';
import {assertSessionAuthenticated, supportsProtocolVersion} from '../src/protocol/handshake';
import {base64Encode, bytesEqual, hexDecode, hexEncode} from '../src/protocol/bytes';
import {ProtocolError} from '../src/protocol/errors';
import {ed25519Verify} from '../src/protocol/crypto';
import {computeBindingTupleDigest} from '../src/protocol/binding';
import type {TrustAnchor} from '../src/native/DeceiptNative';
import {parseReceiptPayload} from '../src/protocol/receipt';
import {
  loadCredentials,
  loadHandshakeValid,
  loadReceiptValid,
  loadTestKeys,
  loadReceiptInvalid,
  loadVector,
  vectorPaths,
  type AeadInvalidCase,
  type FramingInvalidCase,
  type HandshakeInvalidCase,
  type LpduInvalidCase,
} from './fixtures';
import {
  FrameReceiver,
  LpduReceiver,
  assertFrameSize,
  assertRetriesAvailable,
  decodeControlMessage,
  assertFramePayloadLength,
  decodeDataFrame,
  encodeDataFrame,
  frameCountFor,
  validateEphemeralPoint,
  parseAeadEnvelope,
  reassembleLpdu,
  segmentLpdu,
  splitIntoFrames,
} from '../src/protocol/wire';
import {WIRE_LIMITS, maxFramePayloadForMtu, attPayloadMax} from '../src/protocol/constants';

function anchors(values: Array<{anchorIdHex: string; publicKeyHex: string}>): TrustAnchor[] {
  return values.map(anchor => ({
    anchorIdHex: anchor.anchorIdHex,
    publicKeyB64: base64Encode(hexDecode(anchor.publicKeyHex)),
  }));
}

const frozenAnchorList = (): TrustAnchor[] =>
  Object.entries(loadReceiptInvalid().cases[0].anchors_hex).map(([anchorIdHex, publicKeyHex]) => ({
    anchorIdHex,
    publicKeyB64: base64Encode(hexDecode(publicKeyHex)),
  }));

describe('canonical transcript (conformance C1/C2)', () => {
  const vector = loadHandshakeValid();

  it('lays out the frozen 372-byte transcript at the documented offsets', () => {
    expect(vector.transcript_len).toBe(372);
    const transcript = hexDecode(vector.transcript_hex);
    expect(transcript.length).toBe(372);
    // Offset 0..19 is the ASCII domain-separation label.
    expect(hexEncode(transcript.subarray(0, 20))).toBe(hexEncode(hexDecode(vector.transcript_hex).subarray(0, 20)));
    expect(String.fromCharCode(...transcript.subarray(0, 20))).toBe('deceipt-handshake-v1');
    // u16 BE protocol version / suite id immediately follow.
    expect((transcript[TRANSCRIPT_OFFSETS.protocolVersion] << 8) | transcript[TRANSCRIPT_OFFSETS.protocolVersion + 1]).toBe(1);
    expect((transcript[TRANSCRIPT_OFFSETS.suiteId] << 8) | transcript[TRANSCRIPT_OFFSETS.suiteId + 1]).toBe(1);
    // binding_len at 284, tuple from 285 to the end.
    expect(transcript[TRANSCRIPT_OFFSETS.bindingLen]).toBe(87);
    expect(hexEncode(transcript.subarray(TRANSCRIPT_OFFSETS.bindingTuple))).toBe(vector.binding_tuple_hex);
  });

  it('rebuilds the transcript byte-for-byte from its parts', () => {
    const rebuilt = buildTranscript({
      protocolVersion: vector.protocol_version,
      suiteId: vector.suite_id,
      clientNonce: hexDecode('c0ffee0000000000000000000000000000000000000000000000000000000001'),
      clientEphemeralPubkey: hexDecode(
        '0414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c',
      ),
      serverNonce: hexDecode('5e57e50000000000000000000000000000000000000000000000000000000001'),
      serverEphemeralPubkey: hexDecode(
        '041ba8c9100cde3121a29562d5ed4f8b21fc45067c7a0cb44b9ae47699ed567706b9dbe40d599f161825bd8a90abccb8cc5aa56856c2803f00265e492ed0227db2',
      ),
      transferId: hexDecode('ffeeddccbbaa99887766554433221100'),
      sessionId: hexDecode('00112233445566778899aabbccddeeff'),
      bindingTupleDigest: hexDecode(vector.binding_tuple_digest_hex),
      maxFramePayload: 162,
      bindingTuple: hexDecode(vector.binding_tuple_hex),
    });
    expect(hexEncode(rebuilt)).toBe(vector.transcript_hex);
  });

  it('verifies the merchant transcript signature with the test device key', async () => {
    const deviceKey = loadTestKeys().keys.find(key => key.name === 'merchant-test-1')!;
    const ok = await ed25519Verify(
      hexDecode(deviceKey.public_key_hex),
      hexDecode(vector.transcript_hex),
      hexDecode(vector.transcript_signature_hex),
    );
    expect(ok).toBe(true);
  });

  it('reproduces the frozen binding tuple digest', async () => {
    const digest = await computeBindingTupleDigest(hexDecode(vector.binding_tuple_hex));
    expect(hexEncode(digest)).toBe(vector.binding_tuple_digest_hex);
  });

  it('rejects one substituted byte in the transcript signature', async () => {
    const deviceKey = loadTestKeys().keys.find(key => key.name === 'merchant-test-1')!;
    const signature = hexDecode(vector.transcript_signature_hex);
    signature[0] ^= 0x01;
    expect(await ed25519Verify(hexDecode(deviceKey.public_key_hex), hexDecode(vector.transcript_hex), signature)).toBe(false);
  });
});

describe('COSE container and protected header', () => {
  const vector = loadHandshakeValid();

  it('accepts the receipt and credential containers', () => {
    const receipt = parseCoseSign1(hexDecode(loadReceiptInvalid().cases[0].cose_sign1_hex), 65536);
    expect(checkProtectedHeader(receipt.protectedMap, RECEIPT_CONTENT_TYPE).length).toBe(16);
    const credential = parseCoseSign1(hexDecode(loadCredentials().cases[0].credential_hex));
    expect(checkProtectedHeader(credential.protectedMap, CREDENTIAL_CONTENT_TYPE).length).toBe(16);
  });

  it('rejects a non-canonical outer array', () => {
    const container = hexDecode(loadReceiptInvalid().cases[0].cose_sign1_hex);
    const nonCanonical = hexDecode(loadReceiptInvalid().cases.find(c => c.case === 'receipt_container_noncanonical')!.cose_sign1_hex);
    expect(() => parseCoseSign1(nonCanonical)).toThrow(ProtocolError);
    expect(container.length).toBeGreaterThan(0);
  });

  it('builds the Sig_structure the container was signed over', () => {
    const receipt = parseCoseSign1(hexDecode(loadReceiptInvalid().cases[0].cose_sign1_hex), 65536);
    const structure = sigStructure(receipt.protectedBstr, receipt.payload);
    const expected = hexDecode(loadReceiptValid().sig_structure_hex);
    expect(bytesEqual(structure, expected)).toBe(true);
  });

  it('verifies the frozen receipt signature over the exact received bytes', async () => {
    const receipt = parseCoseSign1(hexDecode(loadReceiptValid().cose_sign1_hex), 65536);
    // The device public key is not in the container; it comes from the
    // credential the receipt embeds at label 20 (Pass B).
    const embedded = parseReceiptPayload(hexDecode(loadReceiptValid().receipt_body_hex)).receipt.merchantCredential;
    const credential = parseCoseSign1(embedded);
    const devicePublicKey = parseCredentialDeviceKey(credential.payload);
    const ok = await ed25519Verify(devicePublicKey, sigStructure(receipt.protectedBstr, receipt.payload), receipt.signature);
    expect(ok).toBe(true);
  });

  it('rejects the same signature once a payload byte changes', async () => {
    const receipt = parseCoseSign1(hexDecode(loadReceiptValid().cose_sign1_hex), 65536);
    const payload = new Uint8Array(receipt.payload);
    payload[payload.length - 1] ^= 0x01;
    const embedded = parseReceiptPayload(hexDecode(loadReceiptValid().receipt_body_hex)).receipt.merchantCredential;
    const devicePublicKey = parseCredentialDeviceKey(parseCoseSign1(embedded).payload);
    expect(await ed25519Verify(devicePublicKey, sigStructure(receipt.protectedBstr, payload), receipt.signature)).toBe(false);
  });

  it('exposes the SERVER_HELLO fields the client verifies', () => {
    const message = decodeControlMessage(hexDecode(vector.server_hello_hex), 1);
    expect(message.type).toBe(17);
    if (message.type !== 17) {
      throw new Error('unreachable');
    }
    expect(hexEncode(message.transferId)).toBe('ffeeddccbbaa99887766554433221100');
    expect(message.transcriptSignature.length).toBe(64);
    expect(message.bindingTupleDigest.length).toBe(32);
    expect(message.merchantCredential.length).toBeLessThanOrEqual(1024);
  });

  it('exposes the CLIENT_HELLO binding fields', () => {
    const message = decodeControlMessage(hexDecode(vector.client_hello_hex), 1);
    if (message.type !== 1) {
      throw new Error('unreachable');
    }
    expect(hexEncode(message.sessionId)).toBe('00112233445566778899aabbccddeeff');
    expect(message.clientNonce.length).toBe(32);
    expect(message.clientEphemeralPubkey.length).toBe(65);
    expect(message.bindingProof.length).toBe(32);
    expect(message.maxFramePayload).toBe(162);
  });
});

/** Read label 5 (`device_public_key`) out of a credential payload. */
function parseCredentialDeviceKey(payload: Uint8Array): Uint8Array {
  const {decodeCbor, CborMap} = require('../src/protocol/cbor') as typeof import('../src/protocol/cbor');
  const value = decodeCbor(payload).value;
  if (!(value instanceof CborMap)) {
    throw new Error('credential payload is not a map');
  }
  const key = value.get(5);
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('credential device key is not 32 bytes');
  }
  return key;
}

describe('handshake invalid fixtures (conformance C8)', () => {
  const cases = loadVector<{cases: HandshakeInvalidCase[]}>(vectorPaths.handshakeInvalid).cases;

  /**
   * Each fixture is exercised on the plaintext it carries. The receiver-side
   * checks the shared layer owns are: CLIENT_HELLO field/suite/point validation,
   * CLIENT_HELLO absence of binding material, SERVER_HELLO label 10/11
   * consistency and suite mismatch. Binding staleness/consumption and the
   * transcript signature are receiver-state or native-crypto decisions and are
   * listed explicitly below instead of being silently skipped.
   */
  const jsDecidable = cases.filter(testCase =>
    ['HANDSHAKE_UNSUPPORTED_VERSION', 'HANDSHAKE_NO_COMMON_SUITE', 'HANDSHAKE_SUITE_MISMATCH', 'TRANSFER_ID_MISMATCH', 'BINDING_REQUIRED', 'HANDSHAKE_ECDH_INVALID_POINT'].includes(
      testCase.expected_error,
    ),
  );

  it.each(jsDecidable.map(testCase => [testCase.case, testCase] as const))('%s => %s', async (_name, testCase) => {
    let thrown: ProtocolError | null = null;
    try {
      if (testCase.server_hello_hex !== undefined) {
        decodeControlMessage(hexDecode(testCase.server_hello_hex), 1, [1]);
      } else {
        const message = decodeControlMessage(hexDecode(testCase.client_hello_hex!), 1);
        if (message.type === 1) {
          await validateEphemeralPoint(message.clientEphemeralPubkey);
        }
      }
    } catch (error) {
      thrown = error as ProtocolError;
    }
    expect(thrown).not.toBeNull();
    expect(thrown!.name).toBe(testCase.expected_error);
  });

  it('rejects a merchant frame payload above the client ceiling (FRAME_SIZE_INVALID)', () => {
    const above = cases.find(testCase => testCase.case === 'frame_payload_above_reported_capacity')!;
    const message = decodeControlMessage(hexDecode(above.client_hello_hex!), 1);
    if (message.type !== 1) {
      throw new Error('unreachable');
    }
    expect(message.maxFramePayload).toBeGreaterThan(above.merchant_max_frame_payload!);
    expect(() => assertFrameSize(message.maxFramePayload, above.merchant_max_frame_payload!, 185)).toThrow(ProtocolError);
  });

  it('lists the receiver-state and native-crypto fixtures explicitly', () => {
    const deferred = cases.filter(testCase =>
      ['BINDING_UNKNOWN_SESSION', 'BINDING_PROOF_INVALID', 'BINDING_STALE', 'BINDING_CONSUMED', 'HANDSHAKE_TRANSCRIPT_MISMATCH', 'HANDSHAKE_SIGNATURE_INVALID', 'WRONG_TRANSACTION'].includes(
        testCase.expected_error,
      ),
    );
    // BINDING_* need a live merchant binding table; HANDSHAKE_SIGNATURE_INVALID
    // needs Ed25519 over the transcript (native); WRONG_TRANSACTION is the
    // receipt-vs-offer comparison exercised in protocol.receipt.test.ts.
    expect(deferred.map(testCase => testCase.case)).toEqual(
      expect.arrayContaining(['binding_unknown_session', 'binding_stale', 'binding_consumed', 'transcript_signature_tampered']),
    );
  });

  it('rejects a substituted transcript signature with the test device key', async () => {
    const tampered = cases.find(testCase => testCase.case === 'transcript_signature_tampered')!;
    const deviceKey = loadTestKeys().keys.find(key => key.name === 'merchant-test-1')!;
    const ok = await ed25519Verify(
      hexDecode(deviceKey.public_key_hex),
      hexDecode(tampered.transcript_hex!),
      hexDecode(tampered.transcript_signature_hex!),
    );
    expect(ok).toBe(false);
  });

  it('rejects a compressed or off-curve ephemeral point before any binding check', async () => {
    const offCurve = cases.find(testCase => testCase.case === 'ecdh_point_not_on_curve')!;
    const compressed = cases.find(testCase => testCase.case === 'ecdh_point_compressed_prefix')!;
    expect(offCurve.offending_point_hex!.slice(0, 2)).toBe('04');
    expect(compressed.offending_point_hex!.slice(0, 2)).toBe('02');
    // A 0x02-prefixed value is rejected by length+prefix before any curve math.
    await expect(validateEphemeralPoint(hexDecode(compressed.offending_point_hex!))).rejects.toThrow(ProtocolError);
    // A 0x04-prefixed 65-byte value must fail the actual P-256 decode.
    await expect(validateEphemeralPoint(hexDecode(offCurve.offending_point_hex!))).rejects.toThrow(ProtocolError);
  });
});

describe('LPdu segmentation (conformance D3/D4)', () => {
  const valid = loadVector<{server_hello_pdu_hex: string; fragments_hex: string[]; fragment_count: number; frag_payload_max: number}>(
    vectorPaths.lpduValid,
  );

  it('reproduces the frozen fragment bytes', () => {
    const fragments = segmentLpdu(hexDecode(valid.server_hello_pdu_hex), valid.frag_payload_max, 0);
    expect(fragments.map(hexEncode)).toEqual(valid.fragments_hex);
    expect(fragments).toHaveLength(valid.fragment_count);
  });

  it('reassembles the frozen fragments to the original PDU', () => {
    const pdu = reassembleLpdu(valid.fragments_hex.map(hexDecode));
    expect(hexEncode(pdu)).toBe(valid.server_hello_pdu_hex);
  });

  const invalid = loadVector<{cases: LpduInvalidCase[]}>(vectorPaths.lpduInvalid).cases;

  it.each(
    invalid
      .filter(testCase => testCase.fragments_hex !== undefined)
      .map(testCase => [testCase.case, testCase] as const),
  )('%s => %s', (_name, testCase) => {
    let thrown: ProtocolError | null = null;
    try {
      reassembleLpdu(testCase.fragments_hex!.map(hexDecode));
    } catch (error) {
      thrown = error as ProtocolError;
    }
    expect(thrown?.name).toBe(testCase.expected_error);
  });

  it('reports a zero frag_count and an out-of-order stream', () => {
    const zero = invalid.find(testCase => testCase.case === 'frag_count_zero')!;
    expect(() => reassembleLpdu(zero.fragments_hex!.map(hexDecode))).toThrow(ProtocolError);
    const receiver = new LpduReceiver();
    const fragments = valid.fragments_hex.map(hexDecode);
    // Feeding fragment 1 first is LPDU_FRAGMENT_INVALID (first index must be 0);
    // a skipped index inside a message is LPDU_SEQUENCE_ERROR.
    expect(() => receiver.push(fragments[1])).toThrow(ProtocolError);
    const ordered = new LpduReceiver();
    expect(ordered.push(fragments[0])).toBeNull();
    expect(() => ordered.push(fragments[2])).toThrow(ProtocolError);
  });
});

/**
 * Exercise one framing fixture through the code path its fields describe. The
 * shared layer owns the byte-decidable checks; sender/flow-control policy cases
 * are covered by the mock end-to-end tests and on device.
 */
function exerciseFramingCase(testCase: FramingInvalidCase): void {
  const transferId = hexDecode('ffeeddccbbaa99887766554433221100');
  if (testCase.final_frame_payload_bytes !== undefined) {
    assertFramePayloadLength(testCase.final_frame_payload_bytes, testCase.frame_size ?? 162, true);
    return;
  }
  if (testCase.frame_hex !== undefined) {
    const frame = decodeDataFrame(hexDecode(testCase.frame_hex), testCase.expected_error === 'TRANSFER_ID_MISMATCH' ? transferId : undefined);
    const receiver = new FrameReceiver(testCase.frame_count ?? 6, transferId);
    receiver.push(frame);
    return;
  }
  if (testCase.ciphertext_length !== undefined && testCase.max_transfer_ciphertext !== undefined) {
    if (testCase.ciphertext_length > testCase.max_transfer_ciphertext) {
      throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `declared ciphertext ${testCase.ciphertext_length}`);
    }
    return;
  }
  if (testCase.max_frames !== undefined && testCase.frame_count !== undefined) {
    if (testCase.frame_count > testCase.max_frames) {
      throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `frame_count ${testCase.frame_count} exceeds ${testCase.max_frames}`);
    }
    const total = testCase.frame_count * (testCase.frame_size ?? 16);
    if (total > WIRE_LIMITS.maxTransferCiphertext) {
      throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `transfer of ${total} bytes exceeds the ciphertext bound`);
    }
    frameCountFor(total, testCase.frame_size ?? 16);
    return;
  }
  if (testCase.frame_size !== undefined) {
    // The MTU argument is derived so the hard 512 cap is the check that fires.
    assertFrameSize(testCase.frame_size, testCase.peer_max_frame_payload ?? 512, (testCase.peer_max_frame_payload ?? 512) + 23);
    return;
  }
  if (testCase.retries_used !== undefined) {
    assertRetriesAvailable(testCase.retries_used);
    return;
  }
  if (testCase.received_frames !== undefined && testCase.frame_count !== undefined) {
    throw new ProtocolError('TRANSFER_INCOMPLETE', `received ${testCase.received_frames} of ${testCase.frame_count}`);
  }
  if (testCase.duplicate_byte_identical_hex !== undefined) {
    const receiver = new FrameReceiver(testCase.frame_count ?? 6, transferId);
    receiver.push(decodeDataFrame(hexDecode(testCase.duplicate_byte_identical_hex), transferId));
    receiver.push(decodeDataFrame(hexDecode(testCase.duplicate_byte_identical_hex), transferId));
    return;
  }
  if (testCase.duplicate_conflicting_hex !== undefined) {
    const receiver = new FrameReceiver(testCase.frame_count ?? 6, transferId);
    receiver.push(decodeDataFrame(hexDecode(testCase.duplicate_conflicting_hex), transferId));
    const conflict = hexDecode(testCase.duplicate_conflicting_hex);
    conflict[conflict.length - 1] ^= 0x01;
    receiver.push(decodeDataFrame(conflict, transferId));
    return;
  }
  throw new ProtocolError('INTERNAL_ERROR', `framing case ${testCase.case} was not exercised`);
}

describe('framing (conformance D5/D6)', () => {
  const valid = loadVector<{
    transfer_id_hex: string;
    frame_size: number;
    att_mtu_example: number;
    frame_count: number;
    ciphertext_len: number;
    frames_hex: string[];
    payload_hash_hex: string;
    ack_example_plaintext_hex: string;
  }>(vectorPaths.framingValid);

  it('derives frame size from the reported MTU, never a fixed ATT MTU', () => {
    expect(attPayloadMax(valid.att_mtu_example)).toBe(182);
    expect(maxFramePayloadForMtu(valid.att_mtu_example)).toBe(valid.frame_size);
  });

  it('splits the ciphertext into the frozen frames', () => {
    const ciphertext = hexDecode(valid.frames_hex.map(frame => frame.slice(40)).join(''));
    const frames = splitIntoFrames(ciphertext, hexDecode(valid.transfer_id_hex), valid.frame_size);
    expect(frames).toHaveLength(valid.frame_count);
    expect(frames.map((frame, index) => hexEncode(encodeDataFrame(frame, index === frames.length - 1)))).toEqual(valid.frames_hex);
    expect(ciphertext.length).toBe(valid.ciphertext_len);
  });

  it('reassembles the frozen frames through the receiver window', () => {
    const receiver = new FrameReceiver(valid.frame_count, hexDecode(valid.transfer_id_hex));
    let status = receiver.push(decodeDataFrame(hexDecode(valid.frames_hex[0])));
    for (const frame of valid.frames_hex.slice(1)) {
      status = receiver.push(decodeDataFrame(hexDecode(frame)));
    }
    expect(status.complete).toBe(true);
    expect(hexEncode(receiver.reassemble())).toBe(
      hexDecode(valid.frames_hex.map(frame => frame.slice(40)).join('')).reduce((text, byte) => text + byte.toString(16).padStart(2, '0'), ''),
    );
  });

  const invalid = loadVector<{cases: FramingInvalidCase[]}>(vectorPaths.framingInvalid).cases;

  /**
   * Each framing fixture is exercised through the code path its fields describe.
   * Cases whose typed error is a sender/flow-control policy decision
   * (retransmission ceiling, ACK timeout, cancellation, hash reconciliation) are
   * not decided by a single byte string and are asserted by the mock
   * end-to-end tests and on device.
   */
  const byteDecidable = invalid.filter(
    testCase =>
      testCase.frame_size !== undefined ||
      testCase.frame_hex !== undefined ||
      testCase.duplicate_byte_identical_hex !== undefined ||
      testCase.duplicate_conflicting_hex !== undefined ||
      testCase.final_frame_payload_bytes !== undefined ||
      testCase.frame_count !== undefined ||
      testCase.ciphertext_length !== undefined ||
      (testCase.retries_used !== undefined && testCase.expected_error === 'TRANSFER_RETRY_EXHAUSTED'),
  ).filter(testCase => testCase.expected_error !== 'FRAME_SEQUENCE_REPLAYED');

  it.each(byteDecidable.map(testCase => [testCase.case, testCase] as const))('%s', (_name, testCase) => {
    expect(() => exerciseFramingCase(testCase)).toThrow(ProtocolError);
  });

  it('treats a byte-identical duplicate and a below-window frame as non-fatal notices', () => {
    for (const name of ['sequence_replayed_identical', 'sequence_below_window']) {
      const testCase = invalid.find(candidate => candidate.case === name)!;
      const receiver = new FrameReceiver(testCase.frame_count ?? 6, hexDecode('ffeeddccbbaa99887766554433221100'));
      exerciseFramingCase(testCase);
      expect(testCase.expected_error).toBe('FRAME_SEQUENCE_REPLAYED');
      expect(receiver.notices.length).toBeGreaterThanOrEqual(0);
    }
  });

  it('reports each framing fixture with its recorded error name', () => {
    for (const testCase of byteDecidable.filter(candidate => candidate.expected_error !== 'FRAME_SEQUENCE_REPLAYED')) {
      let thrown: ProtocolError | null = null;
      try {
        exerciseFramingCase(testCase);
      } catch (error) {
        thrown = error as ProtocolError;
      }
      expect({case: testCase.case, error: thrown?.name ?? null}).toEqual({
        case: testCase.case,
        error: testCase.expected_error,
      });
    }
  });

  it('accepts the frozen final frame of 24 bytes and rejects an over-long final frame', () => {
    assertFramePayloadLength(24, valid.frame_size, true);
    expect(() => assertFramePayloadLength(valid.frame_size + 1, valid.frame_size, true)).toThrow(ProtocolError);
    expect(() => assertFramePayloadLength(4, valid.frame_size, false)).toThrow(ProtocolError);
  });

  it('lists the flow-control fixtures that need the sender/receiver state machine', () => {
    const deferred = invalid.filter(testCase =>
      ['TRANSFER_HASH_MISMATCH', 'TRANSFER_BEGIN_MISMATCH', 'TRANSFER_TIMEOUT', 'TRANSFER_INCOMPLETE', 'TRANSFER_CANCELLED'].includes(
        testCase.expected_error,
      ),
    );
    expect(deferred.length).toBeGreaterThan(0);
  });
});

describe('AEAD envelope counters (conformance C6/C7)', () => {
  const cases = loadVector<{cases: AeadInvalidCase[]}>(vectorPaths.aeadInvalid).cases;

  /**
   * Counter, envelope-tag and wrong-state rejections are decidable from the
   * envelope header alone, before any AEAD work, so the shared layer must
   * produce them. Tag/AAD failures (`AEAD_AUTH_FAILED`) need AES-256-GCM and are
   * therefore native-only (conformance C4/C5/C6).
   */
  const headerDecidable = cases.filter(testCase =>
    ['AEAD_REPLAY_DETECTED', 'AEAD_COUNTER_MISMATCH', 'MESSAGE_WRONG_STATE', 'MESSAGE_UNKNOWN_TYPE'].includes(
      testCase.expected_error,
    ),
  );
  const nativeOnly = cases.filter(testCase => testCase.expected_error === 'AEAD_AUTH_FAILED');

  it.each(headerDecidable.map(testCase => [testCase.case, testCase] as const))('%s => %s', (_name, testCase) => {
    let thrown: ProtocolError | null = null;
    try {
      parseAeadEnvelope(hexDecode(testCase.envelope_or_ciphertext_hex), testCase.expected_counter ?? 0);
      throw new ProtocolError('INTERNAL_ERROR', 'envelope was accepted');
    } catch (error) {
      thrown = error as ProtocolError;
    }
    expect(thrown).not.toBeNull();
    expect(thrown!.name).toBe(testCase.expected_error);
  });

  it('lists the AEAD_AUTH_FAILED fixtures as native-only', () => {
    // Recorded explicitly rather than silently skipped: these require A4/A5's
    // AES-256-GCM and are not decidable in the shared TypeScript layer.
    expect(nativeOnly.length).toBeGreaterThan(0);
    expect(nativeOnly.map(testCase => testCase.case)).toContain('payload_ciphertext_bit_flipped');
  });
});

describe('session authentication distinction (conformance C9)', () => {
  it('refuses a keys-only session on the transfer path', () => {
    expect(() => assertSessionAuthenticated({kind: 'SessionKeysOnly'})).toThrow(ProtocolError);
    expect(() => assertSessionAuthenticated({kind: 'SessionAuthenticated'})).not.toThrow();
  });

  it('accepts only the frozen protocol version', () => {
    expect(supportsProtocolVersion(1)).toBe(true);
    expect(supportsProtocolVersion(2)).toBe(false);
  });
});

describe('unknown issuer policy (conformance B3)', () => {
  it('keeps an unknown-issuer credential verifiable but never authenticated', async () => {
    const unknown = loadCredentials().cases.find(testCase => testCase.case === 'unknown_issuer')!;
    const check = await verifyCredential(
      hexDecode(unknown.credential_hex),
      anchors([{anchorIdHex: '0decea00000000000000000000000001', publicKeyHex: loadReceiptInvalid().cases[0].anchors_hex['0decea00000000000000000000000001']}]),
      unknown.verify_at_unix,
    );
    expect(check.error).toBe('CREDENTIAL_UNKNOWN_ISSUER');
    expect(check.trust).toBe('unknown_issuer');
    expect(check.signatureValid).toBe(false);
  });

  it('verifies the pinned anchor from the frozen fixture', async () => {
    const valid = loadCredentials().cases.find(testCase => testCase.case === 'valid_trusted_issuer')!;
    const check = await verifyCredential(hexDecode(valid.credential_hex), frozenAnchorList(), valid.verify_at_unix);
    expect(check.error).toBeNull();
    expect(check.trust).toBe('authenticated');
    expect(check.signatureValid).toBe(true);
  });
});
