/**
 * The frozen typed-error taxonomy, transcribed from
 * `protocol/vectors/errors.json` at revision `deceipt-proto-r2` (91 codes).
 *
 * r2 removed `RECEIPT_OFFER_MISMATCH`; the offer mismatch case is reported as
 * `WRONG_TRANSACTION` (0x0614) alone.
 *
 * `name` / `code` / `fatal` / `retryable` MUST match that table exactly on
 * every platform and in every layer. The reference implementation in native
 * code and the shared app agree on identifiers alone (verification.md §4).
 *
 * Do not edit by hand: regenerate from the vector table when A1 bumps the
 * revision.
 */

export type ProtocolErrorName =
  | 'CBOR_MALFORMED'
  | 'CBOR_NONCANONICAL'
  | 'CBOR_DUPLICATE_KEY'
  | 'CBOR_DEPTH_EXCEEDED'
  | 'CBOR_SIZE_EXCEEDED'
  | 'CBOR_UNSUPPORTED_TYPE'
  | 'MESSAGE_UNKNOWN_TYPE'
  | 'MESSAGE_UNKNOWN_FIELD'
  | 'MESSAGE_MISSING_FIELD'
  | 'MESSAGE_FIELD_TYPE'
  | 'MESSAGE_FIELD_RANGE'
  | 'MESSAGE_TOO_LARGE'
  | 'MESSAGE_WRONG_STATE'
  | 'MESSAGE_WRONG_DIRECTION'
  | 'LPDU_FRAGMENT_INVALID'
  | 'LPDU_SEQUENCE_ERROR'
  | 'LPDU_CONFLICT'
  | 'LPDU_REASSEMBLY_TIMEOUT'
  | 'LPDU_MESSAGE_TOO_LARGE'
  | 'TRANSPORT_MTU_TOO_SMALL'
  | 'TRANSPORT_LINK_LOST'
  | 'TRANSPORT_WRITE_FAILED'
  | 'TRANSPORT_PERMISSION_DENIED'
  | 'TRANSPORT_BLUETOOTH_OFF'
  | 'TRANSPORT_PEER_AMBIGUOUS'
  | 'TRANSPORT_CONNECT_TIMEOUT'
  | 'HANDSHAKE_UNSUPPORTED_VERSION'
  | 'HANDSHAKE_NO_COMMON_SUITE'
  | 'HANDSHAKE_ECDH_INVALID_POINT'
  | 'HANDSHAKE_SIGNATURE_INVALID'
  | 'HANDSHAKE_TRANSCRIPT_MISMATCH'
  | 'HANDSHAKE_SUITE_MISMATCH'
  | 'HANDSHAKE_NONCE_REPLAYED'
  | 'CREDENTIAL_MALFORMED'
  | 'CREDENTIAL_SIGNATURE_INVALID'
  | 'CREDENTIAL_UNKNOWN_ISSUER'
  | 'CREDENTIAL_NOT_YET_VALID'
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_CAPABILITY_MISSING'
  | 'HANDSHAKE_TIMEOUT'
  | 'PEER_NOT_AUTHENTICATED'
  | 'BINDING_UNKNOWN_SESSION'
  | 'BINDING_PROOF_INVALID'
  | 'BINDING_REQUIRED'
  | 'BINDING_STALE'
  | 'BINDING_CONSUMED'
  | 'SESSION_EXPIRED'
  | 'AEAD_AUTH_FAILED'
  | 'AEAD_COUNTER_MISMATCH'
  | 'AEAD_REPLAY_DETECTED'
  | 'AEAD_NONCE_EXHAUSTED'
  | 'SESSION_TORN_DOWN'
  | 'TRANSFER_SIZE_EXCEEDED'
  | 'FRAME_SIZE_INVALID'
  | 'FRAME_SEQUENCE_OUT_OF_RANGE'
  | 'FRAME_SEQUENCE_REPLAYED'
  | 'FRAME_CONFLICT'
  | 'FRAME_BUFFER_EXCEEDED'
  | 'TRANSFER_INCOMPLETE'
  | 'TRANSFER_HASH_MISMATCH'
  | 'TRANSFER_TIMEOUT'
  | 'TRANSFER_RETRY_EXHAUSTED'
  | 'TRANSFER_CANCELLED'
  | 'TRANSFER_ABORTED'
  | 'TRANSFER_BEGIN_MISMATCH'
  | 'TRANSFER_ID_MISMATCH'
  | 'RECEIPT_CONTAINER_MALFORMED'
  | 'RECEIPT_UNSUPPORTED_VERSION'
  | 'RECEIPT_UNSUPPORTED_ALGORITHM'
  | 'RECEIPT_UNKNOWN_HEADER'
  | 'RECEIPT_UNKNOWN_FIELD'
  | 'RECEIPT_SIZE_EXCEEDED'
  | 'RECEIPT_SIGNATURE_INVALID'
  | 'RECEIPT_KEY_NOT_AUTHORIZED'
  | 'RECEIPT_SEMANTIC_INVALID'
  | 'RECEIPT_ARITHMETIC_MISMATCH'
  | 'RECEIPT_MONETARY_RANGE'
  | 'RECEIPT_UNSUPPORTED_CURRENCY'
  | 'RECEIPT_DUPLICATE_CONFLICT'
  | 'RECEIPT_OUTSIDE_KEY_VALIDITY'
  | 'RECEIPT_CREDENTIAL_MISMATCH'
  | 'RECEIPT_TEXT_INVALID'
  | 'RECEIPT_UNKNOWN_CRITICAL_EXTENSION'
  | 'RECEIPT_ISSUED_IN_FUTURE'
  | 'WRONG_TRANSACTION'
  | 'RECEIPT_NONCANONICAL'
  | 'STORAGE_FAILED'
  | 'USER_CANCELLED'
  | 'VERIFY_BUDGET_EXCEEDED'
  | 'CAPABILITY_UNAVAILABLE'
  | 'INTERNAL_ERROR'
;

export type ErrorCategory =
  | 'encoding'
  | 'message'
  | 'transport'
  | 'handshake'
  | 'binding'
  | 'session'
  | 'framing'
  | 'receipt'
  | 'local';

export interface ErrorDescriptor {
  code: number;
  fatal: boolean;
  retryable: boolean;
  category: ErrorCategory;
}

/** The 92 stable codes of `protocol/vectors/errors.json`. */
export const PROTOCOL_ERRORS: Record<ProtocolErrorName, ErrorDescriptor> = {
  CBOR_MALFORMED: {code: 0x0101, fatal: true, retryable: false, category: 'encoding'},
  CBOR_NONCANONICAL: {code: 0x0102, fatal: true, retryable: false, category: 'encoding'},
  CBOR_DUPLICATE_KEY: {code: 0x0103, fatal: true, retryable: false, category: 'encoding'},
  CBOR_DEPTH_EXCEEDED: {code: 0x0104, fatal: true, retryable: false, category: 'encoding'},
  CBOR_SIZE_EXCEEDED: {code: 0x0105, fatal: true, retryable: false, category: 'encoding'},
  CBOR_UNSUPPORTED_TYPE: {code: 0x0106, fatal: true, retryable: false, category: 'encoding'},
  MESSAGE_UNKNOWN_TYPE: {code: 0x0107, fatal: true, retryable: false, category: 'message'},
  MESSAGE_UNKNOWN_FIELD: {code: 0x0108, fatal: true, retryable: false, category: 'message'},
  MESSAGE_MISSING_FIELD: {code: 0x0109, fatal: true, retryable: false, category: 'message'},
  MESSAGE_FIELD_TYPE: {code: 0x010a, fatal: true, retryable: false, category: 'message'},
  MESSAGE_FIELD_RANGE: {code: 0x010b, fatal: true, retryable: false, category: 'message'},
  MESSAGE_TOO_LARGE: {code: 0x010c, fatal: true, retryable: false, category: 'message'},
  MESSAGE_WRONG_STATE: {code: 0x010d, fatal: true, retryable: false, category: 'message'},
  MESSAGE_WRONG_DIRECTION: {code: 0x010e, fatal: true, retryable: false, category: 'message'},
  LPDU_FRAGMENT_INVALID: {code: 0x0201, fatal: true, retryable: false, category: 'transport'},
  LPDU_SEQUENCE_ERROR: {code: 0x0202, fatal: true, retryable: false, category: 'transport'},
  LPDU_CONFLICT: {code: 0x0203, fatal: true, retryable: false, category: 'transport'},
  LPDU_REASSEMBLY_TIMEOUT: {code: 0x0204, fatal: true, retryable: true, category: 'transport'},
  LPDU_MESSAGE_TOO_LARGE: {code: 0x0205, fatal: true, retryable: false, category: 'transport'},
  TRANSPORT_MTU_TOO_SMALL: {code: 0x0206, fatal: true, retryable: false, category: 'transport'},
  TRANSPORT_LINK_LOST: {code: 0x0207, fatal: true, retryable: true, category: 'transport'},
  TRANSPORT_WRITE_FAILED: {code: 0x0208, fatal: true, retryable: true, category: 'transport'},
  TRANSPORT_PERMISSION_DENIED: {code: 0x0209, fatal: true, retryable: false, category: 'transport'},
  TRANSPORT_BLUETOOTH_OFF: {code: 0x020a, fatal: true, retryable: true, category: 'transport'},
  TRANSPORT_PEER_AMBIGUOUS: {code: 0x020b, fatal: true, retryable: false, category: 'transport'},
  TRANSPORT_CONNECT_TIMEOUT: {code: 0x020c, fatal: true, retryable: true, category: 'transport'},
  HANDSHAKE_UNSUPPORTED_VERSION: {code: 0x0301, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_NO_COMMON_SUITE: {code: 0x0302, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_ECDH_INVALID_POINT: {code: 0x0303, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_SIGNATURE_INVALID: {code: 0x0304, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_TRANSCRIPT_MISMATCH: {code: 0x0305, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_SUITE_MISMATCH: {code: 0x0306, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_NONCE_REPLAYED: {code: 0x0307, fatal: true, retryable: false, category: 'handshake'},
  CREDENTIAL_MALFORMED: {code: 0x0308, fatal: true, retryable: false, category: 'handshake'},
  CREDENTIAL_SIGNATURE_INVALID: {code: 0x0309, fatal: true, retryable: false, category: 'handshake'},
  CREDENTIAL_UNKNOWN_ISSUER: {code: 0x030a, fatal: false, retryable: false, category: 'handshake'},
  CREDENTIAL_NOT_YET_VALID: {code: 0x030b, fatal: true, retryable: false, category: 'handshake'},
  CREDENTIAL_EXPIRED: {code: 0x030c, fatal: true, retryable: false, category: 'handshake'},
  CREDENTIAL_CAPABILITY_MISSING: {code: 0x030d, fatal: true, retryable: false, category: 'handshake'},
  HANDSHAKE_TIMEOUT: {code: 0x0310, fatal: true, retryable: true, category: 'handshake'},
  PEER_NOT_AUTHENTICATED: {code: 0x0311, fatal: true, retryable: false, category: 'handshake'},
  BINDING_UNKNOWN_SESSION: {code: 0x0312, fatal: true, retryable: false, category: 'binding'},
  BINDING_PROOF_INVALID: {code: 0x0313, fatal: true, retryable: false, category: 'binding'},
  BINDING_REQUIRED: {code: 0x0314, fatal: true, retryable: false, category: 'binding'},
  BINDING_STALE: {code: 0x0315, fatal: true, retryable: true, category: 'binding'},
  BINDING_CONSUMED: {code: 0x0316, fatal: true, retryable: false, category: 'binding'},
  SESSION_EXPIRED: {code: 0x0317, fatal: true, retryable: false, category: 'handshake'},
  AEAD_AUTH_FAILED: {code: 0x0401, fatal: true, retryable: false, category: 'session'},
  AEAD_COUNTER_MISMATCH: {code: 0x0402, fatal: true, retryable: false, category: 'session'},
  AEAD_REPLAY_DETECTED: {code: 0x0403, fatal: true, retryable: false, category: 'session'},
  AEAD_NONCE_EXHAUSTED: {code: 0x0404, fatal: true, retryable: false, category: 'session'},
  SESSION_TORN_DOWN: {code: 0x0405, fatal: true, retryable: false, category: 'session'},
  TRANSFER_SIZE_EXCEEDED: {code: 0x0501, fatal: true, retryable: false, category: 'framing'},
  FRAME_SIZE_INVALID: {code: 0x0502, fatal: true, retryable: false, category: 'framing'},
  FRAME_SEQUENCE_OUT_OF_RANGE: {code: 0x0503, fatal: true, retryable: false, category: 'framing'},
  FRAME_SEQUENCE_REPLAYED: {code: 0x0504, fatal: false, retryable: false, category: 'framing'},
  FRAME_CONFLICT: {code: 0x0505, fatal: true, retryable: false, category: 'framing'},
  FRAME_BUFFER_EXCEEDED: {code: 0x0506, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_INCOMPLETE: {code: 0x0507, fatal: true, retryable: true, category: 'framing'},
  TRANSFER_HASH_MISMATCH: {code: 0x0508, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_TIMEOUT: {code: 0x0509, fatal: true, retryable: true, category: 'framing'},
  TRANSFER_RETRY_EXHAUSTED: {code: 0x050a, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_CANCELLED: {code: 0x050b, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_ABORTED: {code: 0x050c, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_BEGIN_MISMATCH: {code: 0x050d, fatal: true, retryable: false, category: 'framing'},
  TRANSFER_ID_MISMATCH: {code: 0x050e, fatal: true, retryable: false, category: 'framing'},
  RECEIPT_CONTAINER_MALFORMED: {code: 0x0601, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNSUPPORTED_VERSION: {code: 0x0602, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNSUPPORTED_ALGORITHM: {code: 0x0603, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNKNOWN_HEADER: {code: 0x0604, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNKNOWN_FIELD: {code: 0x0605, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_SIZE_EXCEEDED: {code: 0x0606, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_SIGNATURE_INVALID: {code: 0x0607, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_KEY_NOT_AUTHORIZED: {code: 0x0608, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_SEMANTIC_INVALID: {code: 0x0609, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_ARITHMETIC_MISMATCH: {code: 0x060a, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_MONETARY_RANGE: {code: 0x060b, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNSUPPORTED_CURRENCY: {code: 0x060c, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_DUPLICATE_CONFLICT: {code: 0x060d, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_OUTSIDE_KEY_VALIDITY: {code: 0x060e, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_CREDENTIAL_MISMATCH: {code: 0x060f, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_TEXT_INVALID: {code: 0x0611, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_UNKNOWN_CRITICAL_EXTENSION: {code: 0x0612, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_ISSUED_IN_FUTURE: {code: 0x0613, fatal: true, retryable: false, category: 'receipt'},
  WRONG_TRANSACTION: {code: 0x0614, fatal: true, retryable: false, category: 'receipt'},
  RECEIPT_NONCANONICAL: {code: 0x0615, fatal: true, retryable: false, category: 'receipt'},
  STORAGE_FAILED: {code: 0x0701, fatal: true, retryable: true, category: 'local'},
  USER_CANCELLED: {code: 0x0702, fatal: true, retryable: false, category: 'local'},
  VERIFY_BUDGET_EXCEEDED: {code: 0x0703, fatal: true, retryable: false, category: 'local'},
  CAPABILITY_UNAVAILABLE: {code: 0x0704, fatal: true, retryable: false, category: 'local'},
  INTERNAL_ERROR: {code: 0x0705, fatal: true, retryable: true, category: 'local'},
};

/** Policy outcomes (verification.md §3, errors.json#outcomes). */
export const OUTCOMES = {
  TRUSTED: 0x0001,
  UNVERIFIED_UNKNOWN_ISSUER: 0x0002,
  ALREADY_IMPORTED_IDENTICAL: 0x0003,
  REJECTED: 0x0004,
  PENDING: 0x0005,
} as const;

export type OutcomeName = keyof typeof OUTCOMES;

/**
 * The user- and storage-facing outcome names. A2 §3.9 and verification.md §3
 * fix `trusted` / `unknown_key` / `rejected` as the UI vocabulary; the wire
 * names are the four above.
 */
export type PolicyOutcome = 'TRUSTED' | 'UNVERIFIED_UNKNOWN_ISSUER' | 'ALREADY_IMPORTED_IDENTICAL' | 'REJECTED' | 'PENDING';

/** A typed protocol failure carrying the frozen identifiers. */
export class ProtocolError extends Error {
  readonly name: ProtocolErrorName;
  readonly code: number;
  readonly fatal: boolean;
  readonly retryable: boolean;
  readonly category: ErrorCategory;
  readonly detail?: string;

  constructor(name: ProtocolErrorName, detail?: string) {
    super(detail === undefined ? name : `${name}: ${detail}`);
    const descriptor = PROTOCOL_ERRORS[name];
    this.name = name;
    this.code = descriptor.code;
    this.fatal = descriptor.fatal;
    this.retryable = descriptor.retryable;
    this.category = descriptor.category;
    this.detail = detail;
  }
}

/** Narrow an unknown throwable to a typed protocol failure. */
export function asProtocolError(value: unknown): ProtocolError | null {
  if (value instanceof ProtocolError) {
    return value;
  }
  if (typeof value === 'object' && value !== null) {
    const candidate = value as {name?: unknown; code?: unknown; fatal?: unknown};
    if (typeof candidate.name === 'string' && candidate.name in PROTOCOL_ERRORS && typeof candidate.code === 'number') {
      return new ProtocolError(candidate.name as ProtocolErrorName);
    }
  }
  return null;
}
