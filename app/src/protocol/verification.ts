/**
 * Receipt verification: the frozen 16-step order of
 * docs/protocol/verification.md §1, the §5.3 sub-states preserved separately,
 * the policy outcomes of §3, and the dedup rules of receipt-v1.md §9.
 *
 * Two properties this module exists to guarantee:
 *
 *  1. **No failure path reaches a verified state.** Every gate throws or
 *     returns `REJECTED`; nothing falls through (DESIGN.md §9).
 *  2. **Decryption success is not trust.** The caller enters
 *     `RECEIPT_UNTRUSTED` with exact received bytes; only this module moves a
 *     receipt to `TRUSTED`, and only when every applicable sub-state passes.
 *
 * The signature sub-state is produced by native over the exact received bytes
 * (`signatureVerifier`); TS never rebuilds the signed structure.
 */

import {ProtocolError, type PolicyOutcome, type ProtocolErrorName} from './errors';
import {bytesEqual, hexEncode} from './bytes';
import {RECEIPT_LIMITS} from './constants';
import {CborMap, checkCanonical, decodeCbor} from './cbor';
import {ed25519Verify} from './crypto';
import {
  parseCoseSign1,
  checkProtectedHeader,
  verifyCredential,
  requiredCapabilityForKind,
  sigStructure,
  RECEIPT_CONTENT_TYPE,
} from './handshake';
import type {CredentialBody, CredentialCheck} from './handshake';
import {parseReceiptMap, recomputeTotals, type Receipt} from './receipt';
import type {OfferMetadata} from '../native/DeceiptNative';
import type {TrustAnchor} from '../native/DeceiptNative';

// ---------------------------------------------------------------------------
// States and sub-states
// ---------------------------------------------------------------------------

/**
 * The receipt state as it exists in this app. `RECEIPT_UNTRUSTED` is a real
 * state: the payload is decrypted, its provenance is unproven, and it lives in
 * memory only as untrusted bytes (DESIGN.md §8.1).
 */
export type ReceiptState = 'RECEIPT_UNTRUSTED' | 'VERIFYING' | 'VERIFIED' | 'REJECTED' | 'UNVERIFIED_UNKNOWN_ISSUER' | 'SAVED';

/**
 * The §5.3 sub-states. They are NEVER collapsed into a boolean before policy
 * combines them, and they are persisted so a later policy change or the arrival
 * of revocation data can re-evaluate without re-transferring the receipt
 * (verification.md §2).
 */
export interface VerificationSubStates {
  /** Step 10: Ed25519 over the exact received COSE_Sign1 bytes. */
  signatureValid: boolean;
  /** Step 11: the signing key is authorized for the claimed merchant. */
  keyAuthorized: boolean;
  /** Steps 3/14: the credential's validity window accepts this receipt. */
  credentialTemporallyAcceptable: boolean;
  /** Step 14: revocation status known and acceptable. NOT implemented in the PoC. */
  revocationKnown: boolean;
  /** Step 12: schema, semantics and arithmetic all hold. */
  semanticallyValid: boolean;
  /** Step 13: no conflicting prior receipt under this `receipt_id`. */
  uniqueLocally: boolean;
}

/** Machine-readable explanation of the sub-states the PoC cannot evaluate. */
export const REVOCATION_UNSUPPORTED_REASON =
  'no revocation distribution exists in the PoC; a revoked-in-production key is indistinguishable (trust.md §7)';

export interface VerificationResult {
  outcome: PolicyOutcome;
  subStates: VerificationSubStates;
  /** The first fatal error, or `null`. Never present alongside `TRUSTED`. */
  error: ProtocolError | null;
  /** Set when the credential is structurally valid but its issuer is not pinned. */
  credentialTrust: 'authenticated' | 'unknown_issuer' | 'none';
  merchantDisplayName?: string;
  merchantIdHex?: string;
  deviceKeyIdHex?: string;
  /** Present when the receipt parsed; display fields for the UI. */
  receipt?: Receipt;
  /** The exact signed payload bytes, for storage and dedup. */
  payloadBytes: Uint8Array;
  /**
   * The exact COSE_Sign1 container as received. Stored verbatim as evidence;
   * it is never re-serialized from the parsed model.
   */
  coseSign1Bytes: Uint8Array;
  /** The exact credential bytes the receipt embedded (label 20). */
  credentialBytes?: Uint8Array;
}

export interface VerificationContext {
  /** The exact COSE_Sign1 bytes as received over the wire. */
  coseSign1Bytes: Uint8Array;
  /** Pinned public anchors (public material only). */
  anchors: TrustAnchor[];
  /** Verification clock, unix seconds. */
  nowUnix: number;
  /**
   * The credential presented in `SERVER_HELLO`, if this receipt arrived over a
   * session. Byte equality with the receipt's embedded credential is required.
   */
  sessionCredentialBytes?: Uint8Array;
  /** The offer the user accepted, if any (A2 binding / WRONG_TRANSACTION). */
  offer?: OfferMetadata;
  /** Locally stored receipt payloads keyed by `receipt_id` hex. */
  seenReceipts?: Map<string, Uint8Array>;
  /**
   * Native signature verification over the exact received bytes. Defaults to
   * the shared WebCrypto implementation, which the mock adapters and tests use;
   * on device this is A4/A5's native call.
   */
  signatureVerifier?: (
    devicePublicKey: Uint8Array,
    coseSign1Bytes: Uint8Array,
  ) => Promise<{signatureValid: boolean; deviceKeyIdHex?: string}>;
}

const UNVERIFIED_SUB_STATES: VerificationSubStates = {
  signatureValid: false,
  keyAuthorized: false,
  credentialTemporallyAcceptable: false,
  revocationKnown: false,
  semanticallyValid: false,
  uniqueLocally: true,
};

function rejection(
  error: ProtocolError,
  subStates: VerificationSubStates,
  containerBytes: Uint8Array,
  extra: Partial<VerificationResult> = {},
): VerificationResult {
  return {
    outcome: 'REJECTED',
    subStates,
    error,
    credentialTrust: extra.credentialTrust ?? 'none',
    // With no parsed payload the container bytes stand in, so a rejected
    // receipt is still stored with the exact bytes that were received.
    payloadBytes: extra.payloadBytes ?? containerBytes,
    coseSign1Bytes: containerBytes,
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// The 16-step order (verification.md §1)
// ---------------------------------------------------------------------------

/**
 * Run steps 8–15 over untrusted receipt bytes. Steps 1–7 (transport, handshake,
 * credential/transcript, key derivation, reassembly, AEAD open) happen before
 * this call and are native's responsibility.
 *
 * Step 16 (`RECEIPT_ACK`) is the caller's, once this returns.
 */
export async function verifyReceipt(context: VerificationContext): Promise<VerificationResult> {
  const subStates: VerificationSubStates = {...UNVERIFIED_SUB_STATES};
  const bytes = context.coseSign1Bytes;

  // Step 8: parse the signed container as untrusted input.
  if (bytes.length > RECEIPT_LIMITS.maxReceiptBytes) {
    return rejection(new ProtocolError('RECEIPT_SIZE_EXCEEDED', `${bytes.length} bytes`), subStates, bytes);
  }
  let container;
  try {
    container = parseCoseSign1(bytes, RECEIPT_LIMITS.maxReceiptBytes);
  } catch (error) {
    return rejection(asFatal(error, 'RECEIPT_CONTAINER_MALFORMED'), subStates, bytes);
  }

  // Step 9: supported COSE suite and critical headers.
  let deviceKeyId: Uint8Array;
  try {
    deviceKeyId = checkProtectedHeader(container.protectedMap, RECEIPT_CONTENT_TYPE);
  } catch (error) {
    return rejection(asFatal(error, 'RECEIPT_UNKNOWN_HEADER'), subStates, bytes);
  }

  // Step 8/12 hand-off: the payload must be a canonical receipt map. A
  // non-canonical *payload* is RECEIPT_NONCANONICAL, checked before semantics.
  let receipt: Receipt;
  let ignoredExtensions: string[];
  try {
    const parsed = parseReceiptMap(requireMap(container.payload));
    receipt = parsed.receipt;
    ignoredExtensions = parsed.ignoredNonCriticalExtensionKeys;
  } catch (error) {
    return rejection(asFatal(error, 'RECEIPT_SEMANTIC_INVALID'), subStates, bytes, {});
  }
  void ignoredExtensions;

  // Step 11 (part 1): the receipt must embed the exact credential bytes.
  const embeddedCredential = receipt.merchantCredential;
  if (embeddedCredential.length === 0) {
    return rejection(new ProtocolError('RECEIPT_CREDENTIAL_MISMATCH', 'receipt does not embed a credential'), subStates, bytes, {
      receipt,
    });
  }
  if (context.sessionCredentialBytes !== undefined && !bytesEqual(embeddedCredential, context.sessionCredentialBytes)) {
    return rejection(
      new ProtocolError('RECEIPT_CREDENTIAL_MISMATCH', 'receipt credential differs from the session credential'),
      subStates,
      bytes,
      {receipt},
    );
  }

  // Steps 3 + 11: verify the credential and its authorization of this key.
  let credential: CredentialCheck;
  try {
    credential = await verifyCredential(embeddedCredential, context.anchors, context.nowUnix);
  } catch {
    return rejection(new ProtocolError('CREDENTIAL_MALFORMED', 'credential could not be verified'), subStates, bytes, {receipt});
  }
  const credentialBody: CredentialBody | null = credential.body;
  const credentialTrust = credential.trust;
  if (credential.error !== null && credential.error !== 'CREDENTIAL_UNKNOWN_ISSUER') {
    return rejection(new ProtocolError(errorName(credential.error), 'credential rejected'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody?.displayName,
    });
  }
  if (credentialBody === null) {
    return rejection(new ProtocolError('CREDENTIAL_MALFORMED', 'credential payload could not be read'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
    });
  }
  subStates.credentialTemporallyAcceptable = isValidWindow(credentialBody, context.nowUnix);

  // Step 11 (part 2): the credential must authorize this exact device key and merchant.
  if (!bytesEqual(credentialBody.deviceKeyId, deviceKeyId)) {
    return rejection(new ProtocolError('RECEIPT_KEY_NOT_AUTHORIZED', 'receipt kid differs from the credential device key id'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }
  if (!bytesEqual(credentialBody.merchantId, receipt.merchant.merchantId)) {
    return rejection(new ProtocolError('RECEIPT_KEY_NOT_AUTHORIZED', 'receipt merchant_id differs from the credential'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }

  // Step 10: Ed25519 over the EXACT received bytes (native in production).
  const verifier = context.signatureVerifier ?? defaultSignatureVerifier;
  let signatureValid: boolean;
  try {
    const verification = await verifier(credentialBody.devicePublicKey, bytes);
    signatureValid = verification.signatureValid;
  } catch {
    signatureValid = false;
  }
  subStates.signatureValid = signatureValid;
  if (!signatureValid) {
    return rejection(new ProtocolError('RECEIPT_SIGNATURE_INVALID', 'Ed25519 verification failed'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }

  // Step 12: schema, semantics and arithmetic (already enforced during parse).
  subStates.semanticallyValid = true;

  // Step 14: validity policy inside the key's window.
  const policy = checkIssuedAtPolicy(receipt.issuedAt, context.nowUnix, credentialBody.validFrom, credentialBody.validUntil);
  if (policy !== null) {
    return rejection(new ProtocolError(errorName(policy), 'receipt issued_at is outside the key validity policy'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }
  // Revocation is deliberately not evaluated; recorded as a known unknown.
  subStates.revocationKnown = false;

  // Step 13 (part 1): the receipt must be the transaction the user accepted.
  if (context.offer !== undefined) {
    const mismatch = receiptMatchesOffer(receipt, context.offer);
    if (mismatch !== null) {
      return rejection(new ProtocolError('WRONG_TRANSACTION', mismatch), subStates, bytes, {
        receipt,
        credentialTrust,
        credentialBytes: embeddedCredential,
        merchantDisplayName: credentialBody.displayName,
      });
    }
  }

  // Step 11 (part 3): an unknown issuer may never authorize a key.
  if (credentialTrust !== 'authenticated') {
    return {
      outcome: 'UNVERIFIED_UNKNOWN_ISSUER',
      subStates,
      error: new ProtocolError('CREDENTIAL_UNKNOWN_ISSUER', 'issuer is not pinned'),
      credentialTrust,
      merchantDisplayName: credentialBody.displayName,
      merchantIdHex: hexEncode(credentialBody.merchantId),
      deviceKeyIdHex: hexEncode(deviceKeyId),
      receipt,
      payloadBytes: container.payload,
      coseSign1Bytes: bytes,
      credentialBytes: embeddedCredential,
    };
  }

  // Step 11 (part 4): the credential must carry the capability for this kind.
  const required = requiredCapabilityForKind(receipt.kind);
  if ((credentialBody.capabilities & required) === 0) {
    return rejection(new ProtocolError('CREDENTIAL_CAPABILITY_MISSING', `capability 0x${required.toString(16)} is absent`), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }
  subStates.keyAuthorized = true;

  // Step 13 (part 2): dedup, after signature and authorization.
  const seen = context.seenReceipts?.get(hexEncode(receipt.receiptId));
  if (seen !== undefined) {
    subStates.uniqueLocally = false;
    if (bytesEqual(seen, container.payload)) {
      return {
        outcome: 'ALREADY_IMPORTED_IDENTICAL',
        subStates,
        error: null,
        credentialTrust,
        merchantDisplayName: credentialBody.displayName,
        merchantIdHex: hexEncode(credentialBody.merchantId),
        deviceKeyIdHex: hexEncode(deviceKeyId),
        receipt,
        payloadBytes: container.payload,
        coseSign1Bytes: bytes,
        credentialBytes: embeddedCredential,
      };
    }
    return rejection(new ProtocolError('RECEIPT_DUPLICATE_CONFLICT', 'same receipt_id, different signed bytes'), subStates, bytes, {
      receipt,
      credentialTrust,
      credentialBytes: embeddedCredential,
      merchantDisplayName: credentialBody.displayName,
    });
  }

  // Step 15: every applicable sub-state passed.
  return {
    outcome: 'TRUSTED',
    subStates,
    error: null,
    credentialTrust,
    merchantDisplayName: credentialBody.displayName,
    merchantIdHex: hexEncode(credentialBody.merchantId),
    deviceKeyIdHex: hexEncode(deviceKeyId),
    receipt,
    payloadBytes: container.payload,
    coseSign1Bytes: bytes,
    credentialBytes: embeddedCredential,
  };
}

function isValidWindow(body: CredentialBody, nowUnix: number): boolean {
  return nowUnix >= body.validFrom - 300 && nowUnix < body.validUntil + 300;
}

/** `RECEIPT_ISSUED_IN_FUTURE` / `RECEIPT_OUTSIDE_KEY_VALIDITY` (trust.md §6). */
export function checkIssuedAtPolicy(issuedAt: number, nowUnix: number, validFrom: number, validUntil: number): string | null {
  if (issuedAt > nowUnix + 300) {
    return 'RECEIPT_ISSUED_IN_FUTURE';
  }
  if (!(issuedAt >= validFrom && issuedAt < validUntil)) {
    return 'RECEIPT_OUTSIDE_KEY_VALIDITY';
  }
  return null;
}

/** The seven identity fields the receipt must share with the accepted offer. */
export function receiptMatchesOffer(receipt: Receipt, offer: OfferMetadata): string | null {
  if (hexEncode(receipt.receiptId) !== offer.receiptIdHex) {
    return 'receipt_id differs from the accepted offer';
  }
  if (receipt.currency !== offer.currency) {
    return 'currency differs from the accepted offer';
  }
  if (receipt.totals.totalMinor !== offer.totalAmountMinor) {
    return 'total differs from the accepted offer';
  }
  if (receipt.issuedAt !== offer.issuedAt) {
    return 'issued_at differs from the accepted offer';
  }
  if (receipt.kind !== offer.kind) {
    return 'kind differs from the accepted offer';
  }
  if (hexEncode(receipt.merchant.merchantId) !== offer.merchantIdHex) {
    return 'merchant_id differs from the accepted offer';
  }
  if (receipt.merchant.merchantReference !== offer.merchantReference) {
    return 'merchant_reference differs from the accepted offer';
  }
  return null;
}

/**
 * Verify Ed25519 over the exact received container. On device this is A4/A5's
 * native call; the shared implementation exists so mocks and tests can run the
 * identical ordering.
 */
async function defaultSignatureVerifier(
  devicePublicKey: Uint8Array,
  coseSign1Bytes: Uint8Array,
): Promise<{signatureValid: boolean}> {
  const container = parseCoseSign1(coseSign1Bytes, RECEIPT_LIMITS.maxReceiptBytes);
  const ok = await ed25519Verify(devicePublicKey, sigStructure(container.protectedBstr, container.payload), container.signature);
  return {signatureValid: ok};
}

/**
 * Payload canonicality is checked before semantics, as the reference does.
 * Payload-level CBOR failures map to the receipt identifiers: the reference
 * maps CBOR_NONCANONICAL -> RECEIPT_NONCANONICAL and CBOR_SIZE_EXCEEDED ->
 * RECEIPT_SIZE_EXCEEDED, and everything else to RECEIPT_CONTAINER_MALFORMED.
 */
function requireMap(payload: Uint8Array): CborMap {
  let canonical;
  try {
    canonical = checkCanonical(payload);
  } catch (error) {
    throw mapPayloadCborError(error);
  }
  if (!canonical.canonical) {
    throw new ProtocolError('RECEIPT_NONCANONICAL', 'receipt payload does not re-encode to itself');
  }
  const value = decodeCbor(payload).value;
  if (!(value instanceof CborMap)) {
    throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'receipt payload must be a CBOR map');
  }
  return value;
}

function mapPayloadCborError(error: unknown): ProtocolError {
  if (!(error instanceof ProtocolError)) {
    return new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'receipt payload could not be decoded');
  }
  const mapping: Record<string, ProtocolErrorName> = {
    CBOR_NONCANONICAL: 'RECEIPT_NONCANONICAL',
    CBOR_SIZE_EXCEEDED: 'RECEIPT_SIZE_EXCEEDED',
    CBOR_DEPTH_EXCEEDED: 'RECEIPT_NONCANONICAL',
    CBOR_DUPLICATE_KEY: 'RECEIPT_NONCANONICAL',
  };
  return new ProtocolError(mapping[error.name] ?? 'RECEIPT_CONTAINER_MALFORMED', error.message);
}

function asFatal(error: unknown, fallback: string): ProtocolError {
  if (error instanceof ProtocolError) {
    return error;
  }
  return new ProtocolError(errorName(fallback), 'verification aborted');
}

function errorName(name: string): ProtocolErrorName {
  return name as ProtocolErrorName;
}

// ---------------------------------------------------------------------------
// Persistence-facing helpers
// ---------------------------------------------------------------------------

export interface StoredVerification {
  outcome: PolicyOutcome;
  subStates: VerificationSubStates;
  errorName: string | null;
  errorCode: number | null;
  credentialTrust: 'authenticated' | 'unknown_issuer' | 'none';
  verifiedAtUnix: number;
  /** Explicitly recorded so the UI can never imply revocation was evaluated. */
  revocationNote: string;
}

/**
 * The verification record as it is persisted. Trust is *never* inferred from
 * transport success: this record is written only by `verifyReceipt`, and
 * `outcome` is the policy layer's decision.
 */
export function toStoredVerification(result: VerificationResult, verifiedAtUnix: number): StoredVerification {
  return {
    outcome: result.outcome,
    subStates: result.subStates,
    errorName: result.error?.name ?? null,
    errorCode: result.error?.code ?? null,
    credentialTrust: result.credentialTrust,
    verifiedAtUnix,
    revocationNote: REVOCATION_UNSUPPORTED_REASON,
  };
}

/** The trust affordance the UI may show, derived strictly from the outcome. */
export function trustLabel(outcome: PolicyOutcome): 'trusted' | 'unknown_key' | 'rejected' | 'pending' {
  switch (outcome) {
    case 'TRUSTED':
      return 'trusted';
    case 'UNVERIFIED_UNKNOWN_ISSUER':
      return 'unknown_key';
    case 'PENDING':
      return 'pending';
    default:
      return 'rejected';
  }
}

export function summarizeTotals(receipt: Receipt): {totalMinor: number; subtotalMinor: number; currency: string} {
  const recomputed = recomputeTotals(receipt);
  return {totalMinor: recomputed.totalMinor, subtotalMinor: recomputed.subtotalMinor, currency: receipt.currency};
}
