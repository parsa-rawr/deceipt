/**
 * Wire layer: control messages, LPdu segmentation, DataFrame framing, AEAD
 * envelope open/seal and flow control.
 *
 * Implements docs/protocol/wire.md (Pass D), docs/protocol/framing.md and the
 * envelope rules of docs/protocol/handshake.md §6. Native adapters own the BLE
 * callbacks and the real crypto; this module is the *specification in code*
 * that (a) the shared app uses for message models and offer/ack bookkeeping,
 * (b) the mock adapters use to run the whole flow in tests, and (c) A4/A5 can
 * mirror method-for-method.
 *
 * Every byte-level rejection here carries the frozen error identifier from
 * `protocol/vectors/errors.json` so the same fixture produces the same name on
 * every platform.
 */

import {CborMap, CborValue, decodeCbor, encodeCbor} from './cbor';
import {ProtocolError} from './errors';
import {bytesEqual, concatBytes, hexEncode} from './bytes';
import {SUPPORTED_SUITE_IDS, WIRE_LIMITS, MESSAGE_TYPES, ENVELOPE_TAGS, maxFramePayloadForMtu} from './constants';

// ---------------------------------------------------------------------------
// Control message model (wire-v1.messages.json)
// ---------------------------------------------------------------------------

export interface ClientHello {
  type: 1;
  protocolVersion: number;
  cryptosuites: number[];
  sessionId: Uint8Array;
  clientNonce: Uint8Array;
  clientEphemeralPubkey: Uint8Array;
  bindingProof: Uint8Array;
  maxFramePayload: number;
}

export interface ServerHello {
  type: 17;
  protocolVersion: number;
  suiteId: number;
  transferId: Uint8Array;
  serverNonce: Uint8Array;
  serverEphemeralPubkey: Uint8Array;
  merchantCredential: Uint8Array;
  transcriptSignature: Uint8Array;
  bindingTupleDigest: Uint8Array;
  /**
   * The exact A2 binding tuple (87 B in v1). **Authoritative** over
   * `bindingTupleDigest`: the receiver recomputes the digest from these bytes
   * and requires agreement, and takes `session_id`/`transfer_id` from here
   * (handshake.md §3.1). Absence is `BINDING_REQUIRED`.
   */
  bindingTuple: Uint8Array;
  /**
   * The merchant's **signed** frame size. It MAY be lower than the client's
   * `CLIENT_HELLO` label 8; the client rebuilds the transcript with this value,
   * never with its own (handshake.md §3.1 rule 3).
   */
  maxFramePayload: number;
}

export interface AcceptMessage {
  type: 2;
  transferId: Uint8Array;
  protocolVersion: number;
  suiteId: number;
}

export interface AckMessage {
  type: 3;
  transferId: Uint8Array;
  highestContiguousSequence: number;
}

export interface ReceiptAckMessage {
  type: 4;
  transferId: Uint8Array;
  receiptId: Uint8Array;
  outcome: number;
}

export interface CancelMessage {
  type: 5;
  transferId?: Uint8Array;
  errorCode?: number;
}

export interface RetryMessage {
  type: 6;
  transferId: Uint8Array;
  fromSequence: number;
}

export interface ReceiptOffer {
  type: 18;
  transferId: Uint8Array;
  receiptId: Uint8Array;
  merchantReference: string;
  totalAmountMinor: number;
  currency: string;
  issuedAt: number;
  kind: 1 | 2 | 3;
  ciphertextLength: number;
  merchantId: Uint8Array;
  credentialHash: Uint8Array;
  sessionId: Uint8Array;
}

export interface TransferBegin {
  type: 19;
  transferId: Uint8Array;
  ciphertextLength: number;
  payloadHash: Uint8Array;
  frameSize: number;
  frameCount: number;
}

export interface TransferComplete {
  type: 20;
  transferId: Uint8Array;
  frameCount: number;
  payloadHash: Uint8Array;
}

export interface ErrorMessage {
  type: 21;
  errorCode: number;
  fatal: boolean;
  transferId?: Uint8Array;
  detail?: string;
}

export type ControlMessage =
  | ClientHello
  | ServerHello
  | AcceptMessage
  | AckMessage
  | ReceiptAckMessage
  | CancelMessage
  | RetryMessage
  | ReceiptOffer
  | TransferBegin
  | TransferComplete
  | ErrorMessage;

export function encodeControlMessage(message: ControlMessage): Uint8Array {
  const map = CborMap.of([[1, message.type]]);
  switch (message.type) {
    case 1:
      map.set(2, message.protocolVersion);
      map.set(3, message.cryptosuites);
      map.set(4, message.sessionId);
      map.set(5, message.clientNonce);
      map.set(6, message.clientEphemeralPubkey);
      map.set(7, message.bindingProof);
      map.set(8, message.maxFramePayload);
      break;
    case 17:
      map.set(2, message.protocolVersion);
      map.set(3, message.suiteId);
      map.set(4, message.transferId);
      map.set(5, message.serverNonce);
      map.set(6, message.serverEphemeralPubkey);
      map.set(7, message.merchantCredential);
      map.set(8, message.transcriptSignature);
      map.set(9, message.bindingTupleDigest);
      map.set(10, message.bindingTuple);
      map.set(11, message.maxFramePayload);
      break;
    case 2:
      map.set(2, message.transferId);
      map.set(3, message.protocolVersion);
      map.set(4, message.suiteId);
      break;
    case 3:
      map.set(2, message.transferId);
      map.set(3, message.highestContiguousSequence);
      break;
    case 4:
      map.set(2, message.transferId);
      map.set(3, message.receiptId);
      map.set(4, message.outcome);
      break;
    case 5:
      if (message.transferId !== undefined) {
        map.set(2, message.transferId);
      }
      if (message.errorCode !== undefined) {
        map.set(3, message.errorCode);
      }
      break;
    case 6:
      map.set(2, message.transferId);
      map.set(3, message.fromSequence);
      break;
    case 18:
      map.set(2, message.transferId);
      map.set(3, message.receiptId);
      map.set(4, message.merchantReference);
      map.set(5, message.totalAmountMinor);
      map.set(6, message.currency);
      map.set(7, message.issuedAt);
      map.set(8, message.kind);
      map.set(9, message.ciphertextLength);
      map.set(10, message.merchantId);
      map.set(11, message.credentialHash);
      map.set(12, message.sessionId);
      break;
    case 19:
      map.set(2, message.transferId);
      map.set(3, message.ciphertextLength);
      map.set(4, message.payloadHash);
      map.set(5, message.frameSize);
      map.set(6, message.frameCount);
      break;
    case 20:
      map.set(2, message.transferId);
      map.set(3, message.frameCount);
      map.set(4, message.payloadHash);
      break;
    case 21:
      map.set(2, message.errorCode);
      map.set(3, message.fatal);
      if (message.transferId !== undefined) {
        map.set(4, message.transferId);
      }
      if (message.detail !== undefined) {
        map.set(5, message.detail);
      }
      break;
    default:
      throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `cannot encode type ${String((message as {type: number}).type)}`);
  }
  return encodeCbor(map);
}

const REQUIRED_LABELS: Record<number, number[]> = {
  1: [1, 2, 3, 4, 5, 6, 7, 8],
  17: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
  2: [1, 2, 3, 4],
  3: [1, 2, 3],
  4: [1, 2, 3, 4],
  5: [1],
  6: [1, 2, 3],
  18: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
  19: [1, 2, 3, 4, 5, 6],
  20: [1, 2, 3, 4],
  21: [1, 2, 3],
};

/** Decode a control message, enforcing the message tables' labels and types. */
export function decodeControlMessage(
  bytes: Uint8Array,
  protocolVersion: number,
  offeredSuites?: readonly number[],
): ControlMessage {
  if (bytes.length > WIRE_LIMITS.maxControlPdu) {
    throw new ProtocolError('MESSAGE_TOO_LARGE', `control message is ${bytes.length} bytes`);
  }
  const value = decodeCbor(bytes).value;
  if (!(value instanceof CborMap)) {
    throw new ProtocolError('MESSAGE_FIELD_TYPE', 'control message must be a CBOR map');
  }
  const type = value.get(1);
  if (typeof type !== 'number' || type === 0) {
    throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', 'control message has no valid type label');
  }
  const required = REQUIRED_LABELS[type];
  if (required === undefined) {
    throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `unknown message type ${type}`);
  }
  for (const label of value.keys()) {
    const permitted = type === 5 || type === 21 ? required.concat([2, 3, 4, 5]) : required;
    if (!permitted.includes(label)) {
      throw new ProtocolError('MESSAGE_UNKNOWN_FIELD', `type ${type} has unknown label ${label}`);
    }
  }
  for (const label of required) {
    // The binding material has its own frozen identifier: a CLIENT_HELLO without
    // session_id/binding_proof, or a SERVER_HELLO without label 10, is
    // BINDING_REQUIRED rather than a generic missing-field error.
    if (type === 1 && (label === 4 || label === 7)) {
      continue;
    }
    if (type === 17 && label === 10) {
      continue;
    }
    if (!value.has(label)) {
      throw new ProtocolError('MESSAGE_MISSING_FIELD', `type ${type} lacks required label ${label}`);
    }
  }
  return readControlMessage(type, value, protocolVersion, offeredSuites);
}

function requireBytesField(map: CborMap, label: number, length: number | null, message: string): Uint8Array {
  const value = map.get(label);
  if (!(value instanceof Uint8Array)) {
    throw new ProtocolError('MESSAGE_FIELD_TYPE', `${message} label ${label} must be a byte string`);
  }
  if (length !== null && value.length !== length) {
    throw new ProtocolError('MESSAGE_FIELD_TYPE', `${message} label ${label} must be ${length} bytes`);
  }
  return value;
}

function requireUintField(map: CborMap, label: number, message: string): number {
  const value = map.get(label);
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new ProtocolError('MESSAGE_FIELD_TYPE', `${message} label ${label} must be a non-negative integer`);
  }
  return value;
}

function requireTextField(map: CborMap, label: number, message: string): string {
  const value = map.get(label);
  if (typeof value !== 'string') {
    throw new ProtocolError('MESSAGE_FIELD_TYPE', `${message} label ${label} must be a text string`);
  }
  return value;
}

function readControlMessage(
  type: number,
  map: CborMap,
  protocolVersion: number,
  offeredSuites?: readonly number[],
): ControlMessage {
  switch (type) {
    case 1: {
      if (!map.has(4) || !map.has(7)) {
        // The binding material is mandatory for the v1 (QR) flow; absence is
        // BINDING_REQUIRED rather than a generic missing-field error.
        throw new ProtocolError('BINDING_REQUIRED', 'CLIENT_HELLO lacks session_id and/or binding_proof');
      }
      const suites = map.get(3);
      if (!Array.isArray(suites) || suites.length === 0 || suites.some(entry => typeof entry !== 'number')) {
        throw new ProtocolError('MESSAGE_FIELD_TYPE', 'CLIENT_HELLO crypto_suites must be a non-empty uint array');
      }
      if (!(suites as number[]).some(suite => SUPPORTED_SUITE_IDS.includes(suite))) {
        throw new ProtocolError('HANDSHAKE_NO_COMMON_SUITE', `client offers ${suites.join(',')}; v1 supports ${SUPPORTED_SUITE_IDS.join(',')}`);
      }
      const declaredVersion = requireUintField(map, 2, 'CLIENT_HELLO');
      if (declaredVersion !== protocolVersion) {
        throw new ProtocolError('HANDSHAKE_UNSUPPORTED_VERSION', `client protocol_version ${declaredVersion}`);
      }
      const maxFramePayload = requireUintField(map, 8, 'CLIENT_HELLO');
      if (maxFramePayload < WIRE_LIMITS.minFramePayload || maxFramePayload > WIRE_LIMITS.maxFramePayload) {
        throw new ProtocolError('FRAME_SIZE_INVALID', `CLIENT_HELLO max_frame_payload ${maxFramePayload}`);
      }
      return {
        type: 1,
        protocolVersion: declaredVersion,
        cryptosuites: suites as number[],
        sessionId: requireBytesField(map, 4, 16, 'CLIENT_HELLO'),
        clientNonce: requireBytesField(map, 5, 32, 'CLIENT_HELLO'),
        clientEphemeralPubkey: requireBytesField(map, 6, 65, 'CLIENT_HELLO'),
        bindingProof: requireBytesField(map, 7, 32, 'CLIENT_HELLO'),
        maxFramePayload,
      };
    }
    case 17: {
      const declaredVersion = requireUintField(map, 2, 'SERVER_HELLO');
      if (declaredVersion !== protocolVersion) {
        throw new ProtocolError('HANDSHAKE_UNSUPPORTED_VERSION', `server protocol_version ${declaredVersion}`);
      }
      const transferId = requireBytesField(map, 4, 16, 'SERVER_HELLO');
      if (!map.has(10)) {
        throw new ProtocolError('BINDING_REQUIRED', 'SERVER_HELLO has no binding tuple (label 10)');
      }
      const bindingTupleBytes = requireBytesField(map, 10, null, 'SERVER_HELLO');
      const tuple = decodeBindingTuple(bindingTupleBytes);
      // Rule 2: transfer_id MUST equal binding_tuple[2].
      if (!bytesEqual(transferId, tuple.transferId)) {
        throw new ProtocolError('TRANSFER_ID_MISMATCH', 'SERVER_HELLO transfer_id is not binding_tuple[2]');
      }
      if (!map.has(11)) {
        throw new ProtocolError('FRAME_SIZE_INVALID', 'SERVER_HELLO has no signed max_frame_payload (label 11)');
      }
      const maxFramePayload = requireUintField(map, 11, 'SERVER_HELLO');
      if (maxFramePayload < WIRE_LIMITS.minFramePayload || maxFramePayload > WIRE_LIMITS.maxFramePayload) {
        throw new ProtocolError('FRAME_SIZE_INVALID', `SERVER_HELLO max_frame_payload ${maxFramePayload}`);
      }
      const suiteId = requireUintField(map, 3, 'SERVER_HELLO');
      if (offeredSuites !== undefined && !offeredSuites.includes(suiteId)) {
        throw new ProtocolError('HANDSHAKE_SUITE_MISMATCH', `merchant selected suite ${suiteId}, which was not offered`);
      }
      return {
        type: 17,
        protocolVersion: declaredVersion,
        suiteId,
        transferId,
        serverNonce: requireBytesField(map, 5, 32, 'SERVER_HELLO'),
        serverEphemeralPubkey: requireBytesField(map, 6, 65, 'SERVER_HELLO'),
        merchantCredential: requireBytesField(map, 7, null, 'SERVER_HELLO'),
        transcriptSignature: requireBytesField(map, 8, 64, 'SERVER_HELLO'),
        bindingTupleDigest: requireBytesField(map, 9, 32, 'SERVER_HELLO'),
        bindingTuple: bindingTupleBytes,
        maxFramePayload,
      };
    }
    case 2:
      return {
        type: 2,
        transferId: requireBytesField(map, 2, 16, 'ACCEPT'),
        protocolVersion: requireUintField(map, 3, 'ACCEPT'),
        suiteId: requireUintField(map, 4, 'ACCEPT'),
      };
    case 3:
      return {
        type: 3,
        transferId: requireBytesField(map, 2, 16, 'ACK'),
        highestContiguousSequence: requireUintField(map, 3, 'ACK'),
      };
    case 4:
      return {
        type: 4,
        transferId: requireBytesField(map, 2, 16, 'RECEIPT_ACK'),
        receiptId: requireBytesField(map, 3, 16, 'RECEIPT_ACK'),
        outcome: requireUintField(map, 4, 'RECEIPT_ACK'),
      };
    case 5: {
      const message: CancelMessage = {type: 5};
      if (map.has(2)) {
        message.transferId = requireBytesField(map, 2, 16, 'CANCEL');
      }
      if (map.has(3)) {
        message.errorCode = requireUintField(map, 3, 'CANCEL');
      }
      return message;
    }
    case 6:
      return {
        type: 6,
        transferId: requireBytesField(map, 2, 16, 'RETRY'),
        fromSequence: requireUintField(map, 3, 'RETRY'),
      };
    case 18: {
      const kind = requireUintField(map, 8, 'RECEIPT_OFFER');
      if (kind !== 1 && kind !== 2 && kind !== 3) {
        throw new ProtocolError('MESSAGE_FIELD_RANGE', `RECEIPT_OFFER kind ${kind}`);
      }
      return {
        type: 18,
        transferId: requireBytesField(map, 2, 16, 'RECEIPT_OFFER'),
        receiptId: requireBytesField(map, 3, 16, 'RECEIPT_OFFER'),
        merchantReference: requireTextField(map, 4, 'RECEIPT_OFFER'),
        totalAmountMinor: requireUintField(map, 5, 'RECEIPT_OFFER'),
        currency: requireTextField(map, 6, 'RECEIPT_OFFER'),
        issuedAt: requireUintField(map, 7, 'RECEIPT_OFFER'),
        kind,
        ciphertextLength: requireUintField(map, 9, 'RECEIPT_OFFER'),
        merchantId: requireBytesField(map, 10, 16, 'RECEIPT_OFFER'),
        credentialHash: requireBytesField(map, 11, 32, 'RECEIPT_OFFER'),
        sessionId: requireBytesField(map, 12, 16, 'RECEIPT_OFFER'),
      };
    }
    case 19: {
      const begin: TransferBegin = {
        type: 19,
        transferId: requireBytesField(map, 2, 16, 'TRANSFER_BEGIN'),
        ciphertextLength: requireUintField(map, 3, 'TRANSFER_BEGIN'),
        payloadHash: requireBytesField(map, 4, 32, 'TRANSFER_BEGIN'),
        frameSize: requireUintField(map, 5, 'TRANSFER_BEGIN'),
        frameCount: requireUintField(map, 6, 'TRANSFER_BEGIN'),
      };
      if (begin.ciphertextLength > WIRE_LIMITS.maxTransferCiphertext) {
        throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `declared ciphertext ${begin.ciphertextLength}`);
      }
      if (begin.frameCount > WIRE_LIMITS.maxFrames) {
        throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `declared frame_count ${begin.frameCount}`);
      }
      return begin;
    }
    case 20:
      return {
        type: 20,
        transferId: requireBytesField(map, 2, 16, 'TRANSFER_COMPLETE'),
        frameCount: requireUintField(map, 3, 'TRANSFER_COMPLETE'),
        payloadHash: requireBytesField(map, 4, 32, 'TRANSFER_COMPLETE'),
      };
    case 21: {
      const fatal = map.get(3);
      if (typeof fatal !== 'boolean') {
        throw new ProtocolError('MESSAGE_FIELD_TYPE', 'ERROR label 3 must be a boolean');
      }
      const message: ErrorMessage = {
        type: 21,
        errorCode: requireUintField(map, 2, 'ERROR'),
        fatal,
      };
      if (map.has(4)) {
        message.transferId = requireBytesField(map, 4, 16, 'ERROR');
      }
      if (map.has(5)) {
        message.detail = requireTextField(map, 5, 'ERROR');
        if (message.detail.length > 64) {
          throw new ProtocolError('MESSAGE_FIELD_RANGE', 'ERROR detail is longer than 64 bytes');
        }
      }
      return message;
    }
    default:
      throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `unknown message type ${type}`);
  }
}

/** Direction rule: `0x0_` is customer->merchant, `0x1_` is merchant->customer. */
export function messageDirection(messageType: number): 'c2m' | 'm2c' {
  const table: Record<number, 'c2m' | 'm2c'> = {
    [MESSAGE_TYPES.CLIENT_HELLO]: 'c2m',
    [MESSAGE_TYPES.ACCEPT]: 'c2m',
    [MESSAGE_TYPES.ACK]: 'c2m',
    [MESSAGE_TYPES.RECEIPT_ACK]: 'c2m',
    [MESSAGE_TYPES.CANCEL]: 'c2m',
    [MESSAGE_TYPES.RETRY]: 'c2m',
    [MESSAGE_TYPES.SERVER_HELLO]: 'm2c',
    [MESSAGE_TYPES.RECEIPT_OFFER]: 'm2c',
    [MESSAGE_TYPES.TRANSFER_BEGIN]: 'm2c',
    [MESSAGE_TYPES.TRANSFER_COMPLETE]: 'm2c',
    [MESSAGE_TYPES.ERROR]: 'm2c',
  };
  const direction = table[messageType];
  if (direction === undefined) {
    throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `no direction for message type ${messageType}`);
  }
  return direction;
}

export interface DecodedBindingTuple {
  bindingFormatVersion: number;
  sessionId: Uint8Array;
  transferId: Uint8Array;
  receiptId: Uint8Array;
  offerHash: Uint8Array;
}

/**
 * Decode the A2 binding tuple `[1, session_id(16), transfer_id(16),
 * receipt_id(16), offer_hash(32)]` (A2 §3.6). A malformed tuple is
 * `BINDING_REQUIRED`, since the receiver cannot rebuild the transcript without
 * it.
 */
export function decodeBindingTuple(bytes: Uint8Array): DecodedBindingTuple {
  let value: CborValue;
  try {
    value = decodeCbor(bytes).value;
  } catch {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple is not canonical CBOR');
  }
  if (!Array.isArray(value) || value.length !== 5) {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple must be a 5-element array');
  }
  const [version, sessionId, transferId, receiptId, offerHash] = value;
  if (version !== 1) {
    throw new ProtocolError('BINDING_REQUIRED', `binding format version ${String(version)} is not 1`);
  }
  if (!(sessionId instanceof Uint8Array) || sessionId.length !== 16) {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple session_id must be 16 bytes');
  }
  if (!(transferId instanceof Uint8Array) || transferId.length !== 16) {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple transfer_id must be 16 bytes');
  }
  if (!(receiptId instanceof Uint8Array) || receiptId.length !== 16) {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple receipt_id must be 16 bytes');
  }
  if (!(offerHash instanceof Uint8Array) || offerHash.length !== 32) {
    throw new ProtocolError('BINDING_REQUIRED', 'binding tuple offer_hash must be 32 bytes');
  }
  return {bindingFormatVersion: 1, sessionId, transferId, receiptId, offerHash};
}

export function assertDirection(messageType: number, expected: 'c2m' | 'm2c'): void {
  if (messageDirection(messageType) !== expected) {
    throw new ProtocolError('MESSAGE_WRONG_DIRECTION', `type ${messageType} is not ${expected}`);
  }
}

/**
 * Validate a CLIENT_HELLO's ephemeral public key by asking WebCrypto to import
 * it as a P-256 ECDH key. An off-curve point, a compressed prefix, or a
 * wrong-length value all fail import, which is the frozen
 * `HANDSHAKE_ECDH_INVALID_POINT` condition (A2 §3.7 checks this **before** the
 * binding proof). Native adapters do the same check with their own EC library.
 */
export async function validateEphemeralPoint(point: Uint8Array): Promise<void> {
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'the ephemeral key must be 65 uncompressed bytes');
  }
  const subtle = (globalThis as {crypto?: {subtle?: {importKey(...args: unknown[]): Promise<unknown>}}}).crypto?.subtle;
  if (subtle === undefined || typeof subtle.importKey !== 'function') {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'ECDH point validation needs WebCrypto');
  }
  try {
    await subtle.importKey('raw', point, {name: 'ECDH', namedCurve: 'P-256'}, false, []);
  } catch {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'the ephemeral key does not decode on secp256r1');
  }
}

// ---------------------------------------------------------------------------
// LPdu segmentation (wire.md §3)
// ---------------------------------------------------------------------------

export interface LpduFragment {
  msgSeq: number;
  fragIndex: number;
  fragCount: number;
  bytes: Uint8Array;
}

export function encodeLpduFragment(fragment: LpduFragment): Uint8Array {
  if (fragment.fragCount < 1 || fragment.fragCount > WIRE_LIMITS.maxLpduFragments) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', `frag_count ${fragment.fragCount}`);
  }
  if (fragment.fragIndex < 0 || fragment.fragIndex >= fragment.fragCount) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', `frag_index ${fragment.fragIndex}`);
  }
  if (fragment.bytes.length > WIRE_LIMITS.maxLpduFragBytes) {
    throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `fragment payload ${fragment.bytes.length}`);
  }
  const header = new Uint8Array(WIRE_LIMITS.lpduHeaderBytes);
  header[0] = (fragment.msgSeq >> 8) & 0xff;
  header[1] = fragment.msgSeq & 0xff;
  header[2] = fragment.fragIndex;
  header[3] = fragment.fragCount;
  return concatBytes(header, fragment.bytes);
}

/** Segment one logical PDU into LPdu fragments. */
export function segmentLpdu(pdu: Uint8Array, fragPayloadMax: number, msgSeq: number): Uint8Array[] {
  if (pdu.length > WIRE_LIMITS.maxControlPdu) {
    throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `PDU is ${pdu.length} bytes`);
  }
  if (fragPayloadMax < 1 || fragPayloadMax > WIRE_LIMITS.maxLpduFragBytes) {
    throw new ProtocolError('TRANSPORT_MTU_TOO_SMALL', `fragment payload cap ${fragPayloadMax}`);
  }
  const count = Math.max(1, Math.ceil(pdu.length / fragPayloadMax));
  if (count > WIRE_LIMITS.maxLpduFragments) {
    throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `needs ${count} fragments`);
  }
  const fragments: Uint8Array[] = [];
  for (let index = 0; index < count; index += 1) {
    const start = index * fragPayloadMax;
    fragments.push(
      encodeLpduFragment({
        msgSeq,
        fragIndex: index,
        fragCount: count,
        bytes: pdu.subarray(start, Math.min(start + fragPayloadMax, pdu.length)),
      }),
    );
  }
  return fragments;
}

function readLpduHeader(bytes: Uint8Array): {msgSeq: number; fragIndex: number; fragCount: number} {
  if (bytes.length < WIRE_LIMITS.lpduHeaderBytes) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', 'fragment is shorter than its 4-byte header');
  }
  return {
    msgSeq: (bytes[0] << 8) | bytes[1],
    fragIndex: bytes[2],
    fragCount: bytes[3],
  };
}

export interface LpduReassemblerOptions {
  /** Message sequence of the previous complete message; -1 before the first. */
  initialMsgSeq?: number;
  fragPayloadMax?: number;
}

/** Reassemble one message's fragments in order, enforcing every LPdu rule. */
export function reassembleLpdu(fragments: Uint8Array[], options: LpduReassemblerOptions = {}): Uint8Array {
  if (fragments.length === 0) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', 'no fragments');
  }
  const first = readLpduHeader(fragments[0]);
  if (first.fragCount < 1) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', 'frag_count is zero');
  }
  if (first.fragCount > WIRE_LIMITS.maxLpduFragments) {
    throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `frag_count ${first.fragCount}`);
  }
  if (first.fragIndex !== 0) {
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', `first fragment index is ${first.fragIndex}`);
  }
  if (fragments.length !== first.fragCount) {
    // A set handed to the reassembler that does not match its own frag_count is
    // malformed; `LPDU_REASSEMBLY_TIMEOUT` is the receiver's in-flight timeout.
    throw new ProtocolError('LPDU_FRAGMENT_INVALID', `received ${fragments.length} of ${first.fragCount} fragments`);
  }
  if (options.initialMsgSeq !== undefined && first.msgSeq <= options.initialMsgSeq) {
    throw new ProtocolError('LPDU_SEQUENCE_ERROR', `msg_seq ${first.msgSeq} is not above ${options.initialMsgSeq}`);
  }
  let total = 0;
  const parts: Uint8Array[] = [];
  for (const [index, fragment] of fragments.entries()) {
    const header = readLpduHeader(fragment);
    if (header.msgSeq !== first.msgSeq) {
      throw new ProtocolError('LPDU_SEQUENCE_ERROR', 'fragments carry different msg_seq');
    }
    if (header.fragCount !== first.fragCount) {
      throw new ProtocolError('LPDU_FRAGMENT_INVALID', 'fragments disagree on frag_count');
    }
    if (header.fragIndex !== index) {
      throw new ProtocolError('LPDU_SEQUENCE_ERROR', `fragment ${index} has frag_index ${header.fragIndex}`);
    }
    const payload = fragment.subarray(WIRE_LIMITS.lpduHeaderBytes);
    total += payload.length;
    parts.push(payload);
  }
  if (total > WIRE_LIMITS.maxControlPdu) {
    throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `reassembled PDU is ${total} bytes`);
  }
  return concatBytes(...parts);
}

/**
 * Stateful reassembler. Enforces ordering, conflict and repeat rules across a
 * stream of fragments (wire.md §3), including the `LPDU_CONFLICT` case where
 * the same index arrives twice with different bytes in *different* messages.
 */
export class LpduReceiver {
  private currentSeq = -1;
  private expectedIndex = 0;
  private fragCount = -1;
  private parts: Uint8Array[] = [];
  private lastCompleteSeq = -1;
  private readonly seen = new Map<number, Map<number, Uint8Array>>();

  /** Feed one fragment; returns the reassembled PDU when the message completes. */
  push(fragment: Uint8Array): Uint8Array | null {
    const header = readLpduHeader(fragment);
    if (header.fragCount < 1 || header.fragCount > WIRE_LIMITS.maxLpduFragments) {
      throw new ProtocolError(header.fragCount < 1 ? 'LPDU_FRAGMENT_INVALID' : 'LPDU_MESSAGE_TOO_LARGE', `frag_count ${header.fragCount}`);
    }
    const payload = fragment.subarray(WIRE_LIMITS.lpduHeaderBytes);
    const priorMessage = this.seen.get(header.msgSeq);
    if (this.currentSeq === -1) {
      if (header.msgSeq <= this.lastCompleteSeq) {
        throw new ProtocolError('LPDU_SEQUENCE_ERROR', `msg_seq ${header.msgSeq} is not above ${this.lastCompleteSeq}`);
      }
      if (header.fragIndex !== 0) {
        throw new ProtocolError('LPDU_FRAGMENT_INVALID', `first fragment index is ${header.fragIndex}`);
      }
      this.currentSeq = header.msgSeq;
      this.fragCount = header.fragCount;
      this.expectedIndex = 0;
      this.parts = [];
    }
    if (header.msgSeq !== this.currentSeq) {
      throw new ProtocolError('LPDU_SEQUENCE_ERROR', `msg_seq ${header.msgSeq} interleaves with ${this.currentSeq}`);
    }
    if (header.fragCount !== this.fragCount) {
      throw new ProtocolError('LPDU_FRAGMENT_INVALID', 'frag_count changed mid-message');
    }
    const recorded = priorMessage?.get(header.fragIndex);
    if (recorded !== undefined) {
      if (recorded.length !== payload.length) {
        throw new ProtocolError('LPDU_CONFLICT', `fragment ${header.fragIndex} repeated with different bytes`);
      }
      for (let i = 0; i < recorded.length; i += 1) {
        if (recorded[i] !== payload[i]) {
          throw new ProtocolError('LPDU_CONFLICT', `fragment ${header.fragIndex} repeated with different bytes`);
        }
      }
      return null;
    }
    if (header.fragIndex !== this.expectedIndex) {
      throw new ProtocolError('LPDU_SEQUENCE_ERROR', `expected fragment ${this.expectedIndex}, got ${header.fragIndex}`);
    }
    const perMessage = priorMessage ?? new Map<number, Uint8Array>();
    perMessage.set(header.fragIndex, new Uint8Array(payload));
    this.seen.set(header.msgSeq, perMessage);
    for (const seq of this.seen.keys()) {
      if (seq < header.msgSeq - 1) {
        this.seen.delete(seq);
      }
    }
    this.parts.push(new Uint8Array(payload));
    this.expectedIndex += 1;
    if (this.expectedIndex === this.fragCount) {
      const total = this.parts.reduce((sum, part) => sum + part.length, 0);
      if (total > WIRE_LIMITS.maxControlPdu) {
        throw new ProtocolError('LPDU_MESSAGE_TOO_LARGE', `reassembled PDU is ${total} bytes`);
      }
      const pdu = concatBytes(...this.parts);
      this.lastCompleteSeq = this.currentSeq;
      this.currentSeq = -1;
      this.fragCount = -1;
      this.expectedIndex = 0;
      this.parts = [];
      return pdu;
    }
    return null;
  }

  /** Timeout guard: an incomplete message within `T_CONTROL_FRAG` is retryable. */
  assertComplete(): void {
    if (this.currentSeq !== -1) {
      throw new ProtocolError('LPDU_REASSEMBLY_TIMEOUT', `incomplete message ${this.currentSeq}`);
    }
  }
}

// ---------------------------------------------------------------------------
// DataFrame (framing.md §1)
// ---------------------------------------------------------------------------

export interface DataFrame {
  transferId: Uint8Array;
  sequence: number;
  payload: Uint8Array;
}

/**
 * Encode a DataFrame. `isFinal` (or the absence of a known frame count) is what
 * permits a short final frame: r2/r3 fix the payload bounds as
 * non-final `16..frame_size`, final `1..frame_size`, so a 4-byte last frame is
 * valid while a non-final frame under 16 bytes is `FRAME_SIZE_INVALID`
 * (docs/protocol/framing.md §1).
 */
export function encodeDataFrame(frame: DataFrame, isFinal = false): Uint8Array {
  if (frame.transferId.length !== 16) {
    throw new ProtocolError('TRANSFER_ID_MISMATCH', 'DataFrame transfer_id must be 16 bytes');
  }
  if (frame.sequence < 0 || frame.sequence > 0xffffffff) {
    throw new ProtocolError('FRAME_SEQUENCE_OUT_OF_RANGE', `sequence ${frame.sequence}`);
  }
  if (frame.payload.length > WIRE_LIMITS.maxFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `payload ${frame.payload.length} bytes exceeds the frame size`);
  }
  if (!isFinal && frame.payload.length < WIRE_LIMITS.minFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `non-final payload ${frame.payload.length} bytes is below the minimum`);
  }
  if (frame.payload.length < 1) {
    throw new ProtocolError('FRAME_SIZE_INVALID', 'a frame payload may not be empty');
  }
  const header = new Uint8Array(WIRE_LIMITS.dataframeHeaderBytes);
  header.set(frame.transferId, 0);
  header[16] = (frame.sequence >>> 24) & 0xff;
  header[17] = (frame.sequence >>> 16) & 0xff;
  header[18] = (frame.sequence >>> 8) & 0xff;
  header[19] = frame.sequence & 0xff;
  return concatBytes(header, frame.payload);
}

export function decodeDataFrame(bytes: Uint8Array, expectedTransferId?: Uint8Array): DataFrame {
  if (bytes.length < WIRE_LIMITS.dataframeHeaderBytes) {
    throw new ProtocolError('FRAME_SIZE_INVALID', 'DataFrame is shorter than its 20-byte header');
  }
  const transferId = new Uint8Array(bytes.subarray(0, 16));
  const sequence = ((bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19]) >>> 0;
  const payload = new Uint8Array(bytes.subarray(20));
  if (expectedTransferId !== undefined) {
    for (let i = 0; i < 16; i += 1) {
      if (transferId[i] !== expectedTransferId[i]) {
        throw new ProtocolError('TRANSFER_ID_MISMATCH', 'DataFrame transfer_id does not match the session');
      }
    }
  }
  if (bytes.length > WIRE_LIMITS.maxAttPayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `DataFrame is ${bytes.length} bytes`);
  }
  return {transferId, sequence, payload};
}

export function frameCountFor(ciphertextLength: number, frameSize: number): number {
  if (frameSize < WIRE_LIMITS.minFramePayload || frameSize > WIRE_LIMITS.maxFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `frame_size ${frameSize}`);
  }
  return Math.ceil(ciphertextLength / frameSize);
}

/**
 * Validate an already-parsed frame's payload length against its position. This
 * is the r2/r3 rule stated positively: only the final frame may be shorter than
 * the 16-byte minimum, and no frame may exceed `frame_size`.
 */
export function assertFramePayloadLength(payloadLength: number, frameSize: number, isFinal: boolean): void {
  if (payloadLength > frameSize || payloadLength > WIRE_LIMITS.maxFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `payload ${payloadLength} exceeds frame_size ${frameSize}`);
  }
  if (!isFinal && payloadLength < WIRE_LIMITS.minFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `non-final payload ${payloadLength} is below the minimum`);
  }
  if (payloadLength < 1) {
    throw new ProtocolError('FRAME_SIZE_INVALID', 'a frame payload may not be empty');
  }
}

/** Split a ciphertext into frames; the last frame may be short but never under 16 bytes. */
export function splitIntoFrames(ciphertext: Uint8Array, transferId: Uint8Array, frameSize: number): DataFrame[] {
  if (ciphertext.length === 0) {
    throw new ProtocolError('FRAME_SIZE_INVALID', 'a transfer must carry at least one byte');
  }
  if (ciphertext.length > WIRE_LIMITS.maxTransferCiphertext) {
    throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `ciphertext is ${ciphertext.length} bytes`);
  }
  const count = frameCountFor(ciphertext.length, frameSize);
  if (count > WIRE_LIMITS.maxFrames) {
    throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `frame_count ${count}`);
  }
  const frames: DataFrame[] = [];
  for (let index = 0; index < count; index += 1) {
    const start = index * frameSize;
    frames.push({transferId, sequence: index, payload: ciphertext.subarray(start, Math.min(start + frameSize, ciphertext.length))});
  }
  return frames;
}

export function assertFrameSize(frameSize: number, peerMaxFramePayload: number, attMtu: number): void {
  if (!Number.isInteger(frameSize) || frameSize < WIRE_LIMITS.minFramePayload || frameSize > WIRE_LIMITS.maxFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `frame_size ${frameSize} is outside 16..512`);
  }
  if (frameSize > peerMaxFramePayload) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `frame_size ${frameSize} exceeds the peer's ${peerMaxFramePayload}`);
  }
  const ceiling = maxFramePayloadForMtu(attMtu);
  if (frameSize > ceiling) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `frame_size ${frameSize} exceeds the MTU ceiling ${ceiling}`);
  }
}

// ---------------------------------------------------------------------------
// Envelope (wire.md §6, handshake.md §6)
// ---------------------------------------------------------------------------

export function encodePlaintextEnvelope(message: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([ENVELOPE_TAGS.PLAINTEXT]), message);
}

export interface PlaintextEnvelopeResult {
  message: Uint8Array;
}

export function decodePlaintextEnvelope(envelope: Uint8Array): PlaintextEnvelopeResult {
  if (envelope.length < 1) {
    throw new ProtocolError('CBOR_MALFORMED', 'empty PDU');
  }
  if (envelope[0] === ENVELOPE_TAGS.AEAD) {
    throw new ProtocolError('MESSAGE_WRONG_STATE', 'an AEAD envelope arrived where a plaintext one was required');
  }
  if (envelope[0] !== ENVELOPE_TAGS.PLAINTEXT) {
    throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `unknown envelope tag ${envelope[0]}`);
  }
  return {message: new Uint8Array(envelope.subarray(1))};
}

export interface AeadEnvelope {
  counter: number;
  ciphertext: Uint8Array;
}

export function encodeAeadEnvelope(envelope: AeadEnvelope): Uint8Array {
  const header = new Uint8Array(9);
  header[0] = ENVELOPE_TAGS.AEAD;
  let counter = BigInt(envelope.counter);
  for (let index = 8; index >= 1; index -= 1) {
    header[index] = Number(counter & 0xffn);
    counter >>= 8n;
  }
  return concatBytes(header, envelope.ciphertext);
}

/**
 * Parse an AEAD envelope and apply the counter rules *before* any decryption:
 * `counter < expected` => replay, `> expected` => gap. The tag check happens
 * after, and its failure is `AEAD_AUTH_FAILED` (handshake.md §6.3).
 */
export function parseAeadEnvelope(envelope: Uint8Array, expectedCounter: number): AeadEnvelope {
  if (envelope.length < 1) {
    throw new ProtocolError('CBOR_MALFORMED', 'empty PDU');
  }
  if (envelope[0] === ENVELOPE_TAGS.PLAINTEXT) {
    throw new ProtocolError('MESSAGE_WRONG_STATE', 'plaintext control message after the handshake');
  }
  if (envelope[0] !== ENVELOPE_TAGS.AEAD) {
    throw new ProtocolError('MESSAGE_UNKNOWN_TYPE', `unknown envelope tag ${envelope[0]}`);
  }
  if (envelope.length < 9 + WIRE_LIMITS.aeadTagBytes) {
    throw new ProtocolError('CBOR_MALFORMED', 'AEAD envelope is too short');
  }
  let counter = 0n;
  for (let index = 1; index <= 8; index += 1) {
    counter = (counter << 8n) | BigInt(envelope[index]);
  }
  if (counter < BigInt(expectedCounter)) {
    throw new ProtocolError('AEAD_REPLAY_DETECTED', `counter ${counter.toString()} < expected ${expectedCounter}`);
  }
  if (counter > BigInt(expectedCounter)) {
    throw new ProtocolError('AEAD_COUNTER_MISMATCH', `counter ${counter.toString()} > expected ${expectedCounter}`);
  }
  return {counter: Number(counter), ciphertext: new Uint8Array(envelope.subarray(9))};
}

/** `nonce = 00000000 ‖ u64_be(counter)`. */
export function aeadNonce(counter: number): Uint8Array {
  const nonce = new Uint8Array(WIRE_LIMITS.aeadNonceBytes);
  let value = BigInt(counter);
  for (let index = 11; index >= 4; index -= 1) {
    nonce[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return nonce;
}

export type AeadDirection = 'm2c' | 'c2m';
export type EnvelopeUsage = 'payload' | 'control';

/** AAD tables of handshake.md §6.2. */
export function aeadAdditionalData(sessionContext: Uint8Array, usage: EnvelopeUsage, direction?: AeadDirection): Uint8Array {
  if (usage === 'payload') {
    return concatBytes(sessionContext, new Uint8Array([0x01]));
  }
  if (direction === undefined) {
    throw new ProtocolError('INTERNAL_ERROR', 'control AAD requires a direction');
  }
  return concatBytes(sessionContext, new Uint8Array([0x02, direction === 'c2m' ? 0x00 : 0x01]));
}

// ---------------------------------------------------------------------------
// Flow control (framing.md §3–§4)
// ---------------------------------------------------------------------------

export interface FrameBufferStatus {
  highestContiguousSequence: number;
  buffered: number;
  complete: boolean;
}

/**
 * Receiver-side reassembly with the 64-frame sliding window, duplicate and
 * conflict rules, and the `FRAME_BUFFER_EXCEEDED` backpressure guard.
 */
export class FrameReceiver {
  private readonly slots: Array<Uint8Array | null>;
  private highestContiguous = -1;
  private buffered = 0;

  constructor(
    private readonly frameCount: number,
    private readonly transferId: Uint8Array,
  ) {
    if (frameCount < 0 || frameCount > WIRE_LIMITS.maxFrames) {
      throw new ProtocolError('TRANSFER_SIZE_EXCEEDED', `frame_count ${frameCount}`);
    }
    // Bounded allocation: never allocate from a peer-declared length unchecked.
    this.slots = new Array<Uint8Array | null>(Math.min(frameCount, WIRE_LIMITS.maxFrames)).fill(null);
  }

  /** Non-fatal replay/duplicate notices observed while receiving. */
  readonly notices: string[] = [];

  push(frame: DataFrame): FrameBufferStatus {
    if (frame.transferId.length !== 16) {
      throw new ProtocolError('TRANSFER_ID_MISMATCH', 'frame has no transfer_id');
    }
    for (let i = 0; i < 16; i += 1) {
      if (frame.transferId[i] !== this.transferId[i]) {
        throw new ProtocolError('TRANSFER_ID_MISMATCH', 'frame belongs to another transfer');
      }
    }
    if (frame.sequence >= this.frameCount) {
      throw new ProtocolError('FRAME_SEQUENCE_OUT_OF_RANGE', `sequence ${frame.sequence} >= frame_count ${this.frameCount}`);
    }
    const existing = this.slots[frame.sequence];
    if (existing !== null) {
      if (existing.length === frame.payload.length) {
        let identical = true;
        for (let i = 0; i < existing.length; i += 1) {
          if (existing[i] !== frame.payload[i]) {
            identical = false;
            break;
          }
        }
        if (identical) {
          this.notices.push('FRAME_SEQUENCE_REPLAYED');
          return this.status();
        }
      }
      throw new ProtocolError('FRAME_CONFLICT', `sequence ${frame.sequence} arrived twice with different bytes`);
    }
    const windowFloor = Math.max(0, this.highestContiguous + 1 - WIRE_LIMITS.windowFrames);
    if (frame.sequence < windowFloor) {
      this.notices.push('FRAME_SEQUENCE_REPLAYED');
      return this.status();
    }
    this.slots[frame.sequence] = new Uint8Array(frame.payload);
    this.buffered += 1;
    if (this.buffered > WIRE_LIMITS.windowFrames) {
      throw new ProtocolError('FRAME_BUFFER_EXCEEDED', 'sender outran the 64-frame window');
    }
    while (this.highestContiguous + 1 < this.frameCount && this.slots[this.highestContiguous + 1] !== null) {
      this.highestContiguous += 1;
    }
    return this.status();
  }

  private status(): FrameBufferStatus {
    return {
      highestContiguousSequence: this.highestContiguous,
      buffered: this.buffered,
      complete: this.highestContiguous === this.frameCount - 1,
    };
  }

  /** Reassemble the ciphertext. Incomplete sets are `TRANSFER_INCOMPLETE`. */
  reassemble(): Uint8Array {
    if (this.highestContiguous !== this.frameCount - 1) {
      throw new ProtocolError('TRANSFER_INCOMPLETE', `missing frames above ${this.highestContiguous}`);
    }
    const parts: Uint8Array[] = [];
    for (let index = 0; index < this.frameCount; index += 1) {
      const slot = this.slots[index];
      if (slot === null) {
        throw new ProtocolError('TRANSFER_INCOMPLETE', `frame ${index} is absent`);
      }
      parts.push(slot);
    }
    return concatBytes(...parts);
  }
}

/** Sender-side retry ceiling (framing.md §4). */
export function assertRetriesAvailable(retriesUsed: number): void {
  if (retriesUsed > WIRE_LIMITS.maxFrameRetries) {
    throw new ProtocolError('TRANSFER_RETRY_EXHAUSTED', `${retriesUsed} retransmission rounds used`);
  }
}

export function shouldSendAck(highestContiguousSequence: number, lastAckedSequence: number, unackedForMs: number, ackIntervalMs: number): boolean {
  return (
    highestContiguousSequence - lastAckedSequence >= WIRE_LIMITS.ackEveryFrames ||
    unackedForMs >= ackIntervalMs
  );
}

export function describeTransferId(transferId: Uint8Array): string {
  return hexEncode(transferId);
}

export function controlMessageTypeName(type: number): string {
  const entry = Object.entries(MESSAGE_TYPES).find(([, value]) => value === type);
  return entry === undefined ? `UNKNOWN_${type}` : entry[0];
}

