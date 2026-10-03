/**
 * Handshake-layer types and checks: the canonical 372-byte transcript, the COSE
 * container reader shared by receipts and credentials, Pass B credential
 * verification, and the nominal `SessionKeysOnly` / `SessionAuthenticated`
 * distinction of handshake.md §9.
 *
 * The session crypto itself (P-256 ECDH, HKDF-SHA-256, AES-256-GCM) lives in
 * native code on both platforms. This module reproduces the *bytes* so the app
 * can (a) recompute the transcript digest the merchant signed and (b) run the
 * whole protocol in tests against mock adapters.
 */

import {CborMap, CborValue, checkCanonical, decodeCbor, encodeCbor} from './cbor';
import {ProtocolError} from './errors';
import {base64Decode, bytesEqual, concatBytes, hexDecode, hexEncode, utf8Encode} from './bytes';
import {ed25519Verify, sha256} from './crypto';
import {CLOCK_SKEW_MAX_S, CREDENTIAL_LIMITS, HANDSHAKE_LIMITS, PROTOCOL_VERSION} from './constants';
import type {TrustAnchor} from '../native/DeceiptNative';

export const HANDSHAKE_LABEL = 'deceipt-handshake-v1';
export const RECEIPT_CONTENT_TYPE = 'application/deceipt-receipt+cbor';
export const CREDENTIAL_CONTENT_TYPE = 'application/deceipt-credential+cbor';
export const COSE_ALG_EDDSA = -8;

export const COSE_LABEL_ALG = 1;
export const COSE_LABEL_CRIT = 2;
export const COSE_LABEL_CONTENT_TYPE = 3;
export const COSE_LABEL_KID = 4;

// ---------------------------------------------------------------------------
// COSE_Sign1 container (receipt-v1.md §2)
// ---------------------------------------------------------------------------

export interface CoseSign1 {
  protectedBstr: Uint8Array;
  protectedMap: CborMap;
  unprotected: CborMap;
  payload: Uint8Array;
  signature: Uint8Array;
}

/**
 * Parse a COSE_Sign1 with Pass A's container rules. Any CBOR-level deviation
 * maps through `mapCborToReceipt` exactly as the reference does, so
 * `encoding-invalid.json` and the non-canonical containers reproduce the
 * recorded receipt-level codes.
 */
export function parseCoseSign1(blob: Uint8Array, maxBytes: number = CREDENTIAL_LIMITS.maxCredentialBytes * 64): CoseSign1 {
  if (blob.length > maxBytes) {
    throw new ProtocolError('RECEIPT_SIZE_EXCEEDED', `container is ${blob.length} bytes, above ${maxBytes}`);
  }
  let decoded: CborValue;
  try {
    decoded = checkCanonicalChecked(blob);
  } catch (error) {
    throw error;
  }
  if (!Array.isArray(decoded)) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'COSE_Sign1 must be a 4-element array');
  }
  if (decoded.length !== 4) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', `COSE_Sign1 has ${decoded.length} elements, not 4`);
  }
  const [protectedValue, unprotectedValue, payloadValue, signatureValue] = decoded;
  if (!(protectedValue instanceof Uint8Array)) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'protected header must be a byte string');
  }
  if (!(unprotectedValue instanceof CborMap)) {
    throw new ProtocolError('RECEIPT_UNKNOWN_HEADER', 'unprotected header must be a map');
  }
  if (unprotectedValue.size !== 0) {
    throw new ProtocolError('RECEIPT_UNKNOWN_HEADER', 'unprotected header must be empty');
  }
  if (!(payloadValue instanceof Uint8Array)) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'detached payload is not permitted');
  }
  if (!(signatureValue instanceof Uint8Array) || signatureValue.length !== 64) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'signature must be exactly 64 bytes');
  }
  const protectedValue2 = decodeCbor(protectedValue).value;
  if (!(protectedValue2 instanceof CborMap)) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'protected header must be a CBOR map');
  }
  return {
    protectedBstr: new Uint8Array(protectedValue),
    protectedMap: protectedValue2,
    unprotected: unprotectedValue,
    payload: new Uint8Array(payloadValue),
    signature: new Uint8Array(signatureValue),
  };
}

function checkCanonicalChecked(blob: Uint8Array): CborValue {
  let decoded: CborValue;
  try {
    decoded = decodeCbor(blob).value;
  } catch (error) {
    throw mapCborError(error);
  }
  const reencoded = encodeCbor(decoded);
  if (!bytesEqual(reencoded, blob)) {
    throw new ProtocolError('RECEIPT_NONCANONICAL', 'container does not re-encode to itself');
  }
  return decoded;
}

/** `CBOR_*` -> the receipt-level identifiers the reference uses. */
function mapCborError(error: unknown): ProtocolError {
  if (!(error instanceof ProtocolError)) {
    return new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'container could not be decoded');
  }
  if (error.name === 'CBOR_NONCANONICAL') {
    return new ProtocolError('RECEIPT_NONCANONICAL', error.message);
  }
  if (error.name === 'CBOR_SIZE_EXCEEDED') {
    return new ProtocolError('RECEIPT_SIZE_EXCEEDED', error.message);
  }
  if (error.name === 'CBOR_UNSUPPORTED_TYPE') {
    return new ProtocolError('RECEIPT_CONTAINER_MALFORMED', error.message);
  }
  if (error.name === 'CBOR_DEPTH_EXCEEDED' || error.name === 'CBOR_DUPLICATE_KEY') {
    return new ProtocolError('RECEIPT_NONCANONICAL', error.message);
  }
  return new ProtocolError('RECEIPT_CONTAINER_MALFORMED', error.message);
}

/** Protected-header checks: alg, content type, kid; `crit` and unknown labels fatal. */
export function checkProtectedHeader(protectedMap: CborMap, contentType: string): Uint8Array {
  if (protectedMap.has(COSE_LABEL_CRIT)) {
    throw new ProtocolError('RECEIPT_UNKNOWN_HEADER', 'crit header is not permitted');
  }
  for (const label of protectedMap.keys()) {
    if (label !== COSE_LABEL_ALG && label !== COSE_LABEL_CONTENT_TYPE && label !== COSE_LABEL_KID) {
      throw new ProtocolError('RECEIPT_UNKNOWN_HEADER', `unknown protected header label ${label}`);
    }
  }
  if (protectedMap.get(COSE_LABEL_ALG) !== COSE_ALG_EDDSA) {
    throw new ProtocolError('RECEIPT_UNSUPPORTED_ALGORITHM', 'protected alg is not EdDSA (-8)');
  }
  if (protectedMap.get(COSE_LABEL_CONTENT_TYPE) !== contentType) {
    throw new ProtocolError('RECEIPT_UNSUPPORTED_ALGORITHM', `protected content type is not ${contentType}`);
  }
  const kid = protectedMap.get(COSE_LABEL_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== 16) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'protected kid must be a 16-byte string');
  }
  return kid;
}

/**
 * `Sig_structure = CBOR(["Signature1", protected_bstr, h'', payload_bstr])`
 * (RFC 9052 §4.4). Built here only for verification of *exact received bytes*;
 * nothing in the app re-encodes a signed structure.
 */
export function sigStructure(protectedBstr: Uint8Array, payload: Uint8Array, externalAad: Uint8Array = new Uint8Array(0)): Uint8Array {
  return encodeCbor(['Signature1', protectedBstr, externalAad, payload]);
}

// ---------------------------------------------------------------------------
// Canonical transcript (handshake.md §3)
// ---------------------------------------------------------------------------

export interface TranscriptInputs {
  protocolVersion: number;
  suiteId: number;
  clientNonce: Uint8Array;
  clientEphemeralPubkey: Uint8Array;
  serverNonce: Uint8Array;
  serverEphemeralPubkey: Uint8Array;
  transferId: Uint8Array;
  sessionId: Uint8Array;
  bindingTupleDigest: Uint8Array;
  maxFramePayload: number;
  bindingTuple: Uint8Array;
}

/** Offsets of the frozen 372-byte layout, for conformance assertions. */
export const TRANSCRIPT_OFFSETS = {
  /** ASCII "deceipt-handshake-v1" — 20 bytes (handshake.md §3). */
  label: 0,
  protocolVersion: 20,
  suiteId: 22,
  clientNonce: 24,
  clientEphemeralPubkey: 56,
  serverNonce: 121,
  serverEphemeralPubkey: 153,
  transferId: 218,
  sessionId: 234,
  bindingTupleDigest: 250,
  maxFramePayload: 282,
  bindingLen: 284,
  bindingTuple: 285,
} as const;

const TRANSCRIPT_LABEL_BYTES = utf8Encode(HANDSHAKE_LABEL);

export function buildTranscript(inputs: TranscriptInputs): Uint8Array {
  if (inputs.clientNonce.length !== HANDSHAKE_LIMITS.nonceBytes || inputs.serverNonce.length !== HANDSHAKE_LIMITS.nonceBytes) {
    throw new ProtocolError('HANDSHAKE_TRANSCRIPT_MISMATCH', 'nonces must be 32 bytes');
  }
  if (inputs.clientEphemeralPubkey.length !== 65 || inputs.serverEphemeralPubkey.length !== 65) {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'ephemeral public keys must be 65 uncompressed bytes');
  }
  if (inputs.bindingTuple.length > HANDSHAKE_LIMITS.maxBindingBytes) {
    throw new ProtocolError('HANDSHAKE_TRANSCRIPT_MISMATCH', `binding_tuple is ${inputs.bindingTuple.length} bytes`);
  }
  if (!Number.isInteger(inputs.maxFramePayload) || inputs.maxFramePayload < 1 || inputs.maxFramePayload > 0xffff) {
    throw new ProtocolError('FRAME_SIZE_INVALID', `max_frame_payload ${inputs.maxFramePayload}`);
  }
  // Header is offsets 0..284 inclusive; the length byte is the last of them,
  // and the binding tuple itself occupies 285..371 for the frozen 87-byte tuple.
  const header = new Uint8Array(TRANSCRIPT_OFFSETS.bindingLen + 1);
  header.set(TRANSCRIPT_LABEL_BYTES, TRANSCRIPT_OFFSETS.label);
  header[TRANSCRIPT_OFFSETS.protocolVersion] = (inputs.protocolVersion >> 8) & 0xff;
  header[TRANSCRIPT_OFFSETS.protocolVersion + 1] = inputs.protocolVersion & 0xff;
  header[TRANSCRIPT_OFFSETS.suiteId] = (inputs.suiteId >> 8) & 0xff;
  header[TRANSCRIPT_OFFSETS.suiteId + 1] = inputs.suiteId & 0xff;
  header.set(inputs.clientNonce, TRANSCRIPT_OFFSETS.clientNonce);
  header.set(inputs.clientEphemeralPubkey, TRANSCRIPT_OFFSETS.clientEphemeralPubkey);
  header.set(inputs.serverNonce, TRANSCRIPT_OFFSETS.serverNonce);
  header.set(inputs.serverEphemeralPubkey, TRANSCRIPT_OFFSETS.serverEphemeralPubkey);
  header.set(inputs.transferId, TRANSCRIPT_OFFSETS.transferId);
  header.set(inputs.sessionId, TRANSCRIPT_OFFSETS.sessionId);
  header.set(inputs.bindingTupleDigest, TRANSCRIPT_OFFSETS.bindingTupleDigest);
  header[TRANSCRIPT_OFFSETS.maxFramePayload] = (inputs.maxFramePayload >> 8) & 0xff;
  header[TRANSCRIPT_OFFSETS.maxFramePayload + 1] = inputs.maxFramePayload & 0xff;
  header[TRANSCRIPT_OFFSETS.bindingLen] = inputs.bindingTuple.length;
  const transcript = concatBytes(header, inputs.bindingTuple);
  if (transcript.length !== HANDSHAKE_LIMITS.transcriptLen && inputs.bindingTuple.length === 87) {
    throw new ProtocolError('HANDSHAKE_TRANSCRIPT_MISMATCH', `transcript is ${transcript.length} bytes, expected ${HANDSHAKE_LIMITS.transcriptLen}`);
  }
  return transcript;
}

export async function transcriptHash(transcript: Uint8Array): Promise<Uint8Array> {
  return sha256(transcript);
}

/** Verify the merchant's `SERVER_HELLO` signature over the exact transcript. */
export async function verifyTranscriptSignature(
  devicePublicKey: Uint8Array,
  transcript: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  return ed25519Verify(devicePublicKey, transcript, signature);
}

// ---------------------------------------------------------------------------
// Pass B credential verification (trust.md §4)
// ---------------------------------------------------------------------------

export interface CredentialBody {
  credentialVersion: number;
  issuerId: Uint8Array;
  merchantId: Uint8Array;
  deviceKeyId: Uint8Array;
  devicePublicKey: Uint8Array;
  validFrom: number;
  validUntil: number;
  capabilities: number;
  merchantReference: string;
  displayName: string;
  issuedAt: number;
}

export type CredentialTrust = 'authenticated' | 'unknown_issuer' | 'none';

export interface CredentialCheck {
  /** `null` for success, or the frozen error name. */
  error: string | null;
  body: CredentialBody | null;
  trust: CredentialTrust;
  /** Ed25519 verified against a pinned anchor (false without one). */
  signatureValid: boolean;
  /** `valid_from - skew <= now < valid_until + skew`. */
  temporallyAcceptable: boolean;
}

const CREDENTIAL_LABELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

function parseCredentialBody(payload: Uint8Array): CredentialBody {
  const decoded = decodeCbor(payload).value;
  if (!(decoded instanceof CborMap)) {
    throw new ProtocolError('CREDENTIAL_MALFORMED', 'credential payload must be a CBOR map');
  }
  const map = decoded;
  for (const label of map.keys()) {
    if (!CREDENTIAL_LABELS.includes(label)) {
      throw new ProtocolError('CREDENTIAL_MALFORMED', `credential has unknown label ${label}`);
    }
  }
  for (const label of CREDENTIAL_LABELS) {
    if (!map.has(label)) {
      throw new ProtocolError('CREDENTIAL_MALFORMED', `credential lacks label ${label}`);
    }
  }
  const bytes = (label: number, length: number): Uint8Array => {
    const value = map.get(label);
    if (!(value instanceof Uint8Array) || value.length !== length) {
      throw new ProtocolError('CREDENTIAL_MALFORMED', `credential label ${label} must be ${length} bytes`);
    }
    return value;
  };
  const uint = (label: number): number => {
    const value = map.get(label);
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new ProtocolError('CREDENTIAL_MALFORMED', `credential label ${label} must be a non-negative integer`);
    }
    return value;
  };
  const text = (label: number): string => {
    const value = map.get(label);
    if (typeof value !== 'string') {
      throw new ProtocolError('CREDENTIAL_MALFORMED', `credential label ${label} must be a text string`);
    }
    return value;
  };
  return {
    credentialVersion: map.get(1) as number,
    issuerId: bytes(2, 16),
    merchantId: bytes(3, 16),
    deviceKeyId: bytes(4, 16),
    devicePublicKey: bytes(5, 32),
    validFrom: uint(6),
    validUntil: uint(7),
    capabilities: uint(8),
    merchantReference: text(9),
    displayName: text(10),
    issuedAt: uint(11),
  };
}

/**
 * `verify_credential(credential_bytes, anchor_set, now)` — trust.md §4, in the
 * reference's order. An unknown issuer is NOT a malformed credential: the error
 * is returned with `trust = 'unknown_issuer'` and the caller decides whether the
 * session may continue for diagnostics.
 */
export async function verifyCredential(
  credentialBytes: Uint8Array,
  anchors: TrustAnchor[],
  nowUnix: number,
  verifier: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => Promise<boolean> = ed25519Verify,
): Promise<CredentialCheck> {
  const failure = (error: string, trust: CredentialTrust = 'none'): CredentialCheck => ({
    error,
    body: null,
    trust,
    signatureValid: false,
    temporallyAcceptable: false,
  });
  if (credentialBytes.length > CREDENTIAL_LIMITS.maxCredentialBytes) {
    return failure('CREDENTIAL_MALFORMED');
  }
  let container: CoseSign1;
  try {
    container = parseCoseSign1(credentialBytes);
    checkProtectedHeader(container.protectedMap, CREDENTIAL_CONTENT_TYPE);
  } catch {
    return failure('CREDENTIAL_MALFORMED');
  }
  let body: CredentialBody;
  try {
    body = parseCredentialBody(container.payload);
  } catch {
    return failure('CREDENTIAL_MALFORMED');
  }
  if (body.credentialVersion !== 1) {
    return failure('CREDENTIAL_MALFORMED');
  }
  const kid = container.protectedMap.get(COSE_LABEL_KID);
  if (!(kid instanceof Uint8Array) || !bytesEqual(kid, body.issuerId)) {
    return failure('CREDENTIAL_MALFORMED');
  }
  const anchor = anchors.find(candidate => hexEncode(hexDecode(candidate.anchorIdHex)) === hexEncode(body.issuerId));
  const signatureValid =
    anchor === undefined
      ? false
      : await verifier(
          base64Decode(anchor.publicKeyB64),
          sigStructure(container.protectedBstr, container.payload),
          container.signature,
        );
  if (anchor === undefined) {
    return {error: 'CREDENTIAL_UNKNOWN_ISSUER', body, trust: 'unknown_issuer', signatureValid: false, temporallyAcceptable: false};
  }
  if (!signatureValid) {
    return {error: 'CREDENTIAL_SIGNATURE_INVALID', body, trust: 'none', signatureValid: false, temporallyAcceptable: false};
  }
  const temporallyAcceptable = isValidAt(body, nowUnix);
  if (nowUnix < body.validFrom - CLOCK_SKEW_MAX_S) {
    return {error: 'CREDENTIAL_NOT_YET_VALID', body, trust: 'authenticated', signatureValid, temporallyAcceptable: false};
  }
  if (nowUnix >= body.validUntil + CLOCK_SKEW_MAX_S) {
    return {error: 'CREDENTIAL_EXPIRED', body, trust: 'authenticated', signatureValid, temporallyAcceptable: false};
  }
  return {error: null, body, trust: 'authenticated', signatureValid, temporallyAcceptable};
}

function isValidAt(body: CredentialBody, nowUnix: number): boolean {
  return nowUnix >= body.validFrom - CLOCK_SKEW_MAX_S && nowUnix < body.validUntil + CLOCK_SKEW_MAX_S;
}

export function requiredCapabilityForKind(kind: number): number {
  const table: Record<number, number> = {1: 0x0001, 2: 0x0002, 3: 0x0004};
  const capability = table[kind];
  if (capability === undefined) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `kind ${kind} has no capability`);
  }
  return capability;
}

// ---------------------------------------------------------------------------
// Session authentication distinction (handshake.md §9)
// ---------------------------------------------------------------------------

/**
 * Runtime guard mirroring the type-level split in `DeceiptNative.ts`: only an
 * authenticated session may reach the transfer path. A receiver that derived
 * keys without verifying `SERVER_HELLO` holds `SessionKeysOnly` and MUST NOT
 * send `ACCEPT`.
 */
export function assertSessionAuthenticated(session: {kind: 'SessionKeysOnly' | 'SessionAuthenticated'}): void {
  if (session.kind !== 'SessionAuthenticated') {
    throw new ProtocolError('PEER_NOT_AUTHENTICATED', 'the session has keys but no verified merchant identity');
  }
}

export function supportsProtocolVersion(version: number): boolean {
  return version === PROTOCOL_VERSION;
}
