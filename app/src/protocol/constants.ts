/**
 * Frozen numeric bounds, currency exponents, message type ids, envelope tags
 * and timeouts, transcribed from `protocol/schema/bounds-v1.json` at revision
 * `deceipt-proto-r1`.
 *
 * These are security-relevant limits (DESIGN.md §13.11): every parser MUST
 * check them *before* allocating, not after reading a peer-declared length.
 * The shared app enforces them in validation; A4/A5 enforce them in native.
 */

export const PROTOCOL_VERSION = 1;
export const SUITE_ID = 1;
export const SUPPORTED_SUITE_IDS: readonly number[] = [1];
export const CLOCK_SKEW_MAX_S = 300;

/** RFC 8949 core deterministic encoding limits. */
export const CBOR_LIMITS = {
  maxDepth: 12,
  maxItems: 8192,
  maxArray: 1024,
  maxMap: 256,
  maxTextBytes: 4096,
  maxBytes: 65536,
  maxMapKey: 255,
} as const;

/** Receipt parser and allocation bounds. */
export const RECEIPT_LIMITS = {
  maxReceiptBytes: 65536,
  maxLines: 256,
  maxDiscounts: 64,
  maxTaxes: 64,
  maxTenders: 32,
  maxExtensions: 32,
  maxModifiers: 16,
  maxAddressLines: 8,
  maxTextDescriptionBytes: 512,
  maxTextDisplayNameBytes: 128,
  maxTextShortBytes: 64,
  maxTextUnitBytes: 16,
  maxMonetaryAbs: 1000000000000000,
  maxUnitPriceAbs: 1000000000000,
  maxQtyValueAbs: 1000000,
  maxQtyScale: 9,
  maxTaxRatePpm: 999999,
  minIssuedAt: 1577836800,
  maxIssuedAt: 4102444800,
} as const;

export const CREDENTIAL_LIMITS = {
  maxCredentialBytes: 1024,
} as const;

/**
 * Overflow guard for the exact quantity computation (receipt-v1.md §5.2):
 * `|unit_price_minor * qty_value| > 2^62` => `RECEIPT_MONETARY_RANGE`, checked
 * *before* the division. Kept as a BigInt because the bound is exactly 2^62 and
 * a Number literal would silently round it upward.
 */
export const MAX_ARITH_PRODUCT = 1n << 62n;

/** Credential capability bits (trust.md §2.1). */
export const CAPABILITIES = {
  CAP_ISSUE_SALE: 1,
  CAP_ISSUE_REFUND: 2,
  CAP_ISSUE_VOID: 4,
  CAP_RECEIVE_TRANSFER: 8,
  CAP_EMBED_CREDENTIAL: 16,
} as const;

/** GATT / framing / flow-control bounds. */
export const WIRE_LIMITS = {
  maxControlPdu: 2048,
  maxLpduFragments: 512,
  maxLpduFragBytes: 512,
  lpduHeaderBytes: 4,
  maxAttPayload: 512,
  maxFramePayload: 512,
  minFramePayload: 16,
  dataframeHeaderBytes: 20,
  maxTransferCiphertext: 65552,
  maxFrames: 32768,
  aeadTagBytes: 16,
  aeadNonceBytes: 12,
  aeadCtrlEnvelopeOverhead: 25,
  ackEveryFrames: 32,
  windowFrames: 64,
  maxFrameRetries: 5,
  maxControlMessagesPerDirection: 4096,
} as const;

export const HANDSHAKE_LIMITS = {
  nonceBytes: 32,
  transcriptLen: 372,
  maxBindingBytes: 128,
  maxSessionIdHistory: 32,
} as const;

/** Frozen timeouts in milliseconds (handshake.md §7). */
export const TIMEOUTS_MS = {
  T_ADVERTISE: 60000,
  T_CONNECT: 15000,
  T_HELLO_RESPONSE: 5000,
  T_ACCEPT: 10000,
  T_CONTROL_FRAG: 5000,
  T_ACK_WAIT: 3000,
  T_ACK_INTERVAL: 500,
  T_TRANSFER_IDLE: 10000,
  T_VERIFY_BUDGET: 5000,
  T_SESSION: 120000,
  T_CLOSE: 2000,
  T_BINDING_QR: 300000,
} as const;

export type TimeoutName = keyof typeof TIMEOUTS_MS;

/** Control message type ids (wire.md §2). Label 1 of every control message. */
export const MESSAGE_TYPES = {
  CLIENT_HELLO: 1,
  ACCEPT: 2,
  ACK: 3,
  RECEIPT_ACK: 4,
  CANCEL: 5,
  RETRY: 6,
  SERVER_HELLO: 17,
  RECEIPT_OFFER: 18,
  TRANSFER_BEGIN: 19,
  TRANSFER_COMPLETE: 20,
  ERROR: 21,
} as const;

export type MessageTypeName = keyof typeof MESSAGE_TYPES;

/** Direction nibble rule: 0x0_ = B->A (customer to merchant), 0x1_ = A->B. */
export const DIRECTION_NIBBLE = {c2m: 0x00, m2c: 0x10} as const;

/** Envelope tags (wire.md §6). */
export const ENVELOPE_TAGS = {PLAINTEXT: 0, AEAD: 1} as const;

/** GATT service and characteristic UUIDs (wire.md §1, Pass D). */
export const GATT = {
  serviceUuid: '8decc0de-1e57-4000-8000-000000000001',
  commandUuid: '8decc0de-1e57-4000-8000-000000000002',
  eventUuid: '8decc0de-1e57-4000-8000-000000000003',
  dataUuid: '8decc0de-1e57-4000-8000-000000000004',
} as const;

/** ISO 4217 minor-unit exponents present in the v1 table (receipt-v1.md §5.1). */
export const CURRENCY_MINOR_UNIT_EXPONENT: Readonly<Record<string, number>> = {
  CAD: 2,
  USD: 2,
  EUR: 2,
  GBP: 2,
  AUD: 2,
  NZD: 2,
  CHF: 2,
  MXN: 2,
  BRL: 2,
  SGD: 2,
  HKD: 2,
  SEK: 2,
  NOK: 2,
  DKK: 2,
  PLN: 2,
  CZK: 2,
  TRY: 2,
  ZAR: 2,
  INR: 2,
  CNY: 2,
  JPY: 0,
  KRW: 0,
  VND: 0,
  CLP: 0,
  ISK: 0,
  HUF: 2,
  KWD: 3,
  BHD: 3,
  OMR: 3,
  JOD: 3,
  TND: 3,
  IQD: 3,
  LYD: 3,
};

/**
 * Frame sizing from the *reported* MTU, never a fixed ATT MTU
 * (framing.md §1). Both formulas cap at the hard 512-byte limit.
 */
export function attPayloadMax(attMtu: number): number {
  return Math.min(attMtu - 3, WIRE_LIMITS.maxAttPayload);
}

export function maxFramePayloadForMtu(attMtu: number): number {
  return Math.min(attPayloadMax(attMtu) - WIRE_LIMITS.dataframeHeaderBytes, WIRE_LIMITS.maxFramePayload);
}
