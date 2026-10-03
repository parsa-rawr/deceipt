/**
 * A2 transaction-binding bytes — adopted verbatim into `deceipt-proto-r1`
 * (docs/flows/transaction-binding-and-checkout-v1.md §3; A1 adoption in
 * docs/protocol/handshake.md §10).
 *
 * The app computes the *public* binding values so it can compare what the
 * merchant sent against what the QR named:
 *
 *   * `offer_hash`            — recomputed from `RECEIPT_OFFER` labels 3,4,5,6,7,10
 *   * `binding_tuple_digest`  — recomputed from the binding tuple and compared
 *                               against `SERVER_HELLO` label 9
 *   * `binding_proof_message` — the exact 122-byte message the merchant's HMAC
 *                               covers (the HMAC itself is native-side, because
 *                               the key is the session-binding token)
 *
 * Session binding is NOT merchant-key trust: passing every check here says only
 * "this session, this transaction" (A2 §3.9).
 */

import {CborMap, CborValue, decodeCbor, encodeCbor} from './cbor';
import {ProtocolError} from './errors';
import {base64UrlDecode, base64UrlEncode, bytesEqual, concatBytes, hexEncode, utf8Encode} from './bytes';
import {domainSeparatedSha256} from './crypto';

export const QR_PREFIX = 'deceipt1:';
export const QR_FORMAT_VERSION = 1;
export const BINDING_FORMAT_VERSION = 1;
export const OFFER_HASH_DOMAIN = 'deceipt-offer-hash-v1';
export const BINDING_TUPLE_DOMAIN = 'deceipt-binding-tuple-v1';
export const BINDING_PROOF_DOMAIN = 'deceipt-binding-proof-v1';

// ---------------------------------------------------------------------------
// QR payload (A2 §3.3)
// ---------------------------------------------------------------------------

export interface BindingQrPayload {
  qrFormatVersion: 1;
  sessionId: Uint8Array;
  /**
   * SECRET. Present only in merchant-side code and inside the native adapter's
   * QR parse. Never logged, never persisted, never rendered (A2 §3.4).
   */
  sessionBindingToken: Uint8Array;
  offerHash: Uint8Array;
  expiresAtUnix: number;
}

/** Encode the QR string the merchant renders at the terminal. */
export function encodeBindingQr(payload: BindingQrPayload): string {
  const map = CborMap.of([
    [1, payload.qrFormatVersion],
    [2, payload.sessionId],
    [3, payload.sessionBindingToken],
    [4, payload.offerHash],
    [5, payload.expiresAtUnix],
  ]);
  return QR_PREFIX + base64UrlEncode(encodeCbor(map));
}

/**
 * Parse a scanned QR payload. Rejects a wrong prefix, a wrong format version,
 * and any payload whose declared lengths differ from the fixed sizes.
 */
export function parseBindingQr(qrPayload: string): BindingQrPayload {
  if (!qrPayload.startsWith(QR_PREFIX)) {
    throw new ProtocolError('BINDING_UNKNOWN_SESSION', 'QR payload lacks the deceipt1: prefix');
  }
  const encoded = qrPayload.slice(QR_PREFIX.length);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(encoded);
  } catch {
    throw new ProtocolError('CBOR_MALFORMED', 'QR payload is not valid base64url');
  }
  let decoded: CborValue;
  try {
    decoded = decodeCbor(bytes).value;
  } catch (error) {
    throw error instanceof ProtocolError ? error : new ProtocolError('CBOR_MALFORMED', 'QR payload is not canonical CBOR');
  }
  if (!(decoded instanceof CborMap)) {
    throw new ProtocolError('CBOR_MALFORMED', 'QR payload must be a CBOR map');
  }
  const map = decoded;
  for (const key of map.keys()) {
    if (key < 1 || key > 5) {
      throw new ProtocolError('BINDING_UNKNOWN_SESSION', `QR payload has unknown label ${key}`);
    }
  }
  const version = map.get(1);
  if (version !== QR_FORMAT_VERSION) {
    throw new ProtocolError('BINDING_UNKNOWN_SESSION', `qr_format_version ${String(version)} is not supported`);
  }
  const sessionId = map.get(2);
  const bindingToken = map.get(3);
  const offerHash = map.get(4);
  const expiresAt = map.get(5);
  if (!(sessionId instanceof Uint8Array) || sessionId.length !== 16) {
    throw new ProtocolError('BINDING_UNKNOWN_SESSION', 'QR session_id must be 16 bytes');
  }
  if (!(bindingToken instanceof Uint8Array) || bindingToken.length !== 16) {
    throw new ProtocolError('BINDING_REQUIRED', 'QR session binding token must be 16 bytes');
  }
  if (!(offerHash instanceof Uint8Array) || offerHash.length !== 32) {
    throw new ProtocolError('BINDING_REQUIRED', 'QR offer_hash must be 32 bytes');
  }
  if (typeof expiresAt !== 'number' || !Number.isInteger(expiresAt) || expiresAt < 0) {
    throw new ProtocolError('BINDING_REQUIRED', 'QR expires_at_unix must be a non-negative integer');
  }
  return {
    qrFormatVersion: 1,
    sessionId,
    sessionBindingToken: bindingToken,
    offerHash,
    expiresAtUnix: expiresAt,
  };
}

/** Freshness gate before any session work (A2 §3.8, `T_BINDING_QR`). */
export function assertQrFresh(payload: BindingQrPayload, nowUnix: number): void {
  if (nowUnix >= payload.expiresAtUnix) {
    throw new ProtocolError('BINDING_STALE', `checkout code expired at ${payload.expiresAtUnix}`);
  }
}

// ---------------------------------------------------------------------------
// Offer hash (A2 §3.5)
// ---------------------------------------------------------------------------

export interface OfferFields {
  sessionId: Uint8Array;
  transferId: Uint8Array;
  receiptId: Uint8Array;
  merchantReference: string;
  totalAmountMinor: number;
  currency: string;
  issuedAtUnix: number;
}

/** Exact 7-element CBOR array the offer hash covers. */
export function offerHashPreimage(fields: OfferFields): Uint8Array {
  return encodeCbor([
    fields.sessionId,
    fields.transferId,
    fields.receiptId,
    fields.merchantReference,
    fields.totalAmountMinor,
    fields.currency,
    fields.issuedAtUnix,
  ]);
}

export async function computeOfferHash(fields: OfferFields): Promise<Uint8Array> {
  return domainSeparatedSha256(OFFER_HASH_DOMAIN, offerHashPreimage(fields));
}

// ---------------------------------------------------------------------------
// Binding tuple and digest (A2 §3.6)
// ---------------------------------------------------------------------------

export interface BindingTupleFields extends OfferFields {
  offerHash: Uint8Array;
}

export function encodeBindingTuple(fields: BindingTupleFields): Uint8Array {
  return encodeCbor([
    BINDING_FORMAT_VERSION,
    fields.sessionId,
    fields.transferId,
    fields.receiptId,
    fields.offerHash,
  ]);
}

export async function computeBindingTupleDigest(bindingTuple: Uint8Array): Promise<Uint8Array> {
  return domainSeparatedSha256(BINDING_TUPLE_DOMAIN, bindingTuple);
}

// ---------------------------------------------------------------------------
// Binding proof message (A2 §3.7)
// ---------------------------------------------------------------------------

/**
 * `"deceipt-binding-proof-v1" || 0x00 || client_nonce(32) || client_ephemeral_pubkey(65)`
 * — exactly 122 bytes for P-256. The HMAC over these bytes is computed natively
 * with the SBT as key; this function only builds the message.
 */
export function bindingProofMessage(clientNonce: Uint8Array, clientEphemeralPubkey: Uint8Array): Uint8Array {
  if (clientNonce.length !== 32) {
    throw new ProtocolError('BINDING_PROOF_INVALID', 'client_nonce must be 32 bytes');
  }
  if (clientEphemeralPubkey.length !== 65) {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'client_ephemeral_pubkey must be 65 uncompressed bytes');
  }
  return concatBytes(utf8Encode(BINDING_PROOF_DOMAIN), new Uint8Array([0x00]), clientNonce, clientEphemeralPubkey);
}

// ---------------------------------------------------------------------------
// Comparisons (fail closed)
// ---------------------------------------------------------------------------

export function offerHashMatches(expected: Uint8Array, actual: Uint8Array): boolean {
  return bytesEqual(expected, actual);
}

export function bindingTupleDigestMatches(expected: Uint8Array, actual: Uint8Array): boolean {
  return bytesEqual(expected, actual);
}

export function bindingFingerprint(sessionId: Uint8Array): string {
  return hexEncode(sessionId);
}
