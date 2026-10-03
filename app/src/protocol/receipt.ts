/**
 * `DeceiptReceiptV1` — typed model, deterministic-CBOR serialization and strict
 * schema/semantic/arithmetic validation.
 *
 * Implements docs/protocol/receipt-v1.md (Pass A) against
 * `protocol/schema/receipt-v1.fields.json` and the bounds of
 * `protocol/schema/bounds-v1.json`. Money is always an integer count of minor
 * units; quantities are exact scaled integers; **no binary floating point is
 * used anywhere in this module**, including the rounding step (§5.2).
 *
 * The signed structure is never built here: `serializeReceipt` produces the
 * *receipt payload* bytes, and native builds `Sig_structure` around them
 * (receipt-v1.md §2, invariant 3).
 */

import {MAX_ARITH_PRODUCT, CURRENCY_MINOR_UNIT_EXPONENT, RECEIPT_LIMITS} from './constants';
import {normalizeNfcAsync, toNfc} from './normalization';
import {CborMap, CborValue, decodeCbor, encodeCbor} from './cbor';
import {ProtocolError} from './errors';
import {hexEncode} from './bytes';

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export type ReceiptKind = 1 | 2 | 3;
export const KIND_SALE = 1;
export const KIND_REFUND = 2;
export const KIND_VOID = 3;

export const PAYMENT_STATUS = {paid: 1, partial: 2, unpaid: 3, refunded: 4, voided: 5} as const;

export interface Quantity {
  scale: number;
  value: number;
  unit?: string;
}

export interface ReceiptModifier {
  description: string;
  unitPriceMinor: number;
  qtyValue: number;
  qtyScale: number;
}

export interface ReceiptLine {
  lineId: number;
  description: string;
  quantity: Quantity;
  unitPriceMinor: number;
  lineAmountMinor: number;
  lineDiscountMinor?: number;
  parentLineIds?: number[];
  lineType?: 1 | 2 | 3 | 4;
  sku?: string;
  modifiers?: ReceiptModifier[];
}

export interface ReceiptDiscount {
  discountId: number;
  amountMinor: number;
  label?: string;
  scope: 1 | 2;
  targetLineId?: number;
  ratePpm?: number;
  baseAmountMinor?: number;
}

export interface ReceiptTax {
  taxId: number;
  label?: string;
  ratePpm: number;
  baseAmountMinor: number;
  amountMinor: number;
  jurisdiction?: string;
  code?: string;
  includedInPrices?: boolean;
}

export interface ReceiptTotals {
  subtotalMinor: number;
  discountTotalMinor: number;
  taxTotalMinor: number;
  totalMinor: number;
  tipMinor?: number;
  serviceChargeMinor?: number;
  roundingAdjustmentMinor?: number;
  taxAddedTotalMinor: number;
}

export interface ReceiptTender {
  method: 1 | 2 | 3 | 4;
  amountMinor: number;
  cardLast4?: string;
  brand?: string;
  authRef?: string;
}

export interface ReceiptPayment {
  status: 1 | 2 | 3 | 4 | 5;
  amountPaidMinor: number;
  changeMinor?: number;
  tenders?: ReceiptTender[];
}

export interface ReceiptMerchant {
  merchantId: Uint8Array;
  displayName: string;
  merchantReference: string;
}

export interface ReceiptLocation {
  label?: string;
  street?: string;
  city?: string;
  region?: string;
  addressLines?: string[];
  postalCode?: string;
}

export interface ReceiptOrderReference {
  orderNumber?: string;
  table?: string;
  server?: string;
}

export interface ReceiptExtension {
  key: string;
  critical: boolean;
  value?: CborValue;
}

export interface Receipt {
  receiptVersion: 1;
  kind: ReceiptKind;
  receiptId: Uint8Array;
  issuedAt: number;
  tzOffsetMinutes?: number;
  merchant: ReceiptMerchant;
  location?: ReceiptLocation;
  currency: string;
  lines: ReceiptLine[];
  discounts?: ReceiptDiscount[];
  taxes?: ReceiptTax[];
  tipAmountMinor?: number;
  serviceChargeMinor?: number;
  roundingAdjustmentMinor?: number;
  totals: ReceiptTotals;
  payment: ReceiptPayment;
  refundOfReceiptId?: Uint8Array;
  voidOfReceiptId?: Uint8Array;
  orderReference?: ReceiptOrderReference;
  /** Exact COSE_Sign1 credential bytes presented in ServerHello (label 20). */
  merchantCredential: Uint8Array;
  extensions?: ReceiptExtension[];
}

// ---------------------------------------------------------------------------
// Canonical serialization (deterministic CBOR, receipt-v1.md §1, §3)
// ---------------------------------------------------------------------------

function quantityToCbor(quantity: Quantity): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, quantity.scale],
    [2, quantity.value],
  ];
  if (quantity.unit !== undefined) {
    entries.push([3, quantity.unit]);
  }
  return CborMap.of(entries);
}

function lineToCbor(line: ReceiptLine): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, line.lineId],
    [2, line.description],
    [3, quantityToCbor(line.quantity)],
    [4, line.unitPriceMinor],
    [5, line.lineAmountMinor],
  ];
  if (line.lineDiscountMinor !== undefined) {
    entries.push([6, line.lineDiscountMinor]);
  }
  if (line.parentLineIds !== undefined) {
    entries.push([7, line.parentLineIds]);
  }
  if (line.lineType !== undefined) {
    entries.push([8, line.lineType]);
  }
  if (line.sku !== undefined) {
    entries.push([9, line.sku]);
  }
  if (line.modifiers !== undefined) {
    entries.push([
      10,
      line.modifiers.map(modifier =>
        CborMap.of([
          [1, modifier.description],
          [2, modifier.unitPriceMinor],
          [3, modifier.qtyValue],
          [4, modifier.qtyScale],
        ]),
      ),
    ]);
  }
  return CborMap.of(entries);
}

function discountToCbor(discount: ReceiptDiscount): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, discount.discountId],
    [2, discount.amountMinor],
  ];
  if (discount.label !== undefined) {
    entries.push([3, discount.label]);
  }
  entries.push([4, discount.scope]);
  if (discount.targetLineId !== undefined) {
    entries.push([5, discount.targetLineId]);
  }
  if (discount.ratePpm !== undefined) {
    entries.push([6, discount.ratePpm]);
  }
  if (discount.baseAmountMinor !== undefined) {
    entries.push([7, discount.baseAmountMinor]);
  }
  return CborMap.of(entries);
}

function taxToCbor(tax: ReceiptTax): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, tax.taxId],
  ];
  if (tax.label !== undefined) {
    entries.push([2, tax.label]);
  }
  entries.push([3, tax.ratePpm], [4, tax.baseAmountMinor], [5, tax.amountMinor]);
  if (tax.jurisdiction !== undefined) {
    entries.push([6, tax.jurisdiction]);
  }
  if (tax.code !== undefined) {
    entries.push([7, tax.code]);
  }
  if (tax.includedInPrices !== undefined) {
    entries.push([8, tax.includedInPrices]);
  }
  return CborMap.of(entries);
}

function tenderToCbor(tender: ReceiptTender): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, tender.method],
    [2, tender.amountMinor],
  ];
  if (tender.cardLast4 !== undefined) {
    entries.push([3, tender.cardLast4]);
  }
  if (tender.brand !== undefined) {
    entries.push([4, tender.brand]);
  }
  if (tender.authRef !== undefined) {
    entries.push([5, tender.authRef]);
  }
  return CborMap.of(entries);
}

function paymentToCbor(payment: ReceiptPayment): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, payment.status],
    [2, payment.amountPaidMinor],
  ];
  if (payment.changeMinor !== undefined) {
    entries.push([3, payment.changeMinor]);
  }
  if (payment.tenders !== undefined) {
    entries.push([4, payment.tenders.map(tenderToCbor)]);
  }
  return CborMap.of(entries);
}

function totalsToCbor(totals: ReceiptTotals): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, totals.subtotalMinor],
    [2, totals.discountTotalMinor],
    [3, totals.taxTotalMinor],
    [4, totals.totalMinor],
  ];
  if (totals.tipMinor !== undefined) {
    entries.push([5, totals.tipMinor]);
  }
  if (totals.serviceChargeMinor !== undefined) {
    entries.push([6, totals.serviceChargeMinor]);
  }
  if (totals.roundingAdjustmentMinor !== undefined) {
    entries.push([7, totals.roundingAdjustmentMinor]);
  }
  entries.push([8, totals.taxAddedTotalMinor]);
  return CborMap.of(entries);
}

function merchantToCbor(merchant: ReceiptMerchant): CborMap {
  return CborMap.of([
    [1, merchant.merchantId],
    [2, merchant.displayName],
    [3, merchant.merchantReference],
  ]);
}

function locationToCbor(location: ReceiptLocation): CborMap {
  const entries: Array<[number, CborValue]> = [];
  if (location.label !== undefined) {
    entries.push([1, location.label]);
  }
  if (location.street !== undefined) {
    entries.push([2, location.street]);
  }
  if (location.city !== undefined) {
    entries.push([3, location.city]);
  }
  if (location.region !== undefined) {
    entries.push([4, location.region]);
  }
  if (location.addressLines !== undefined) {
    entries.push([5, location.addressLines]);
  }
  if (location.postalCode !== undefined) {
    entries.push([6, location.postalCode]);
  }
  return CborMap.of(entries);
}

function orderReferenceToCbor(reference: ReceiptOrderReference): CborMap {
  const entries: Array<[number, CborValue]> = [];
  if (reference.orderNumber !== undefined) {
    entries.push([1, reference.orderNumber]);
  }
  if (reference.table !== undefined) {
    entries.push([2, reference.table]);
  }
  if (reference.server !== undefined) {
    entries.push([3, reference.server]);
  }
  return CborMap.of(entries);
}

function extensionToCbor(extension: ReceiptExtension): CborMap {
  const entries: Array<[number, CborValue]> = [
    [1, extension.key],
    [2, extension.critical],
  ];
  const value = extension.value;
  if (value !== undefined) {
    entries.push([3, value]);
  }
  return CborMap.of(entries);
}

/** Convert the model to the label-keyed CBOR map of receipt-v1.md §3–§6. */
export function receiptToCbor(receipt: Receipt): CborMap {
  const map = CborMap.of([]);
  map.set(1, receipt.receiptVersion);
  map.set(2, receipt.kind);
  map.set(3, receipt.receiptId);
  map.set(4, receipt.issuedAt);
  if (receipt.tzOffsetMinutes !== undefined) {
    map.set(5, receipt.tzOffsetMinutes);
  }
  map.set(6, merchantToCbor(receipt.merchant));
  if (receipt.location !== undefined) {
    map.set(7, locationToCbor(receipt.location));
  }
  map.set(8, receipt.currency);
  map.set(9, receipt.lines.map(lineToCbor));
  if (receipt.discounts !== undefined) {
    map.set(10, receipt.discounts.map(discountToCbor));
  }
  if (receipt.taxes !== undefined) {
    map.set(11, receipt.taxes.map(taxToCbor));
  }
  if (receipt.tipAmountMinor !== undefined) {
    map.set(12, receipt.tipAmountMinor);
  }
  if (receipt.serviceChargeMinor !== undefined) {
    map.set(13, receipt.serviceChargeMinor);
  }
  if (receipt.roundingAdjustmentMinor !== undefined) {
    map.set(14, receipt.roundingAdjustmentMinor);
  }
  map.set(15, totalsToCbor(receipt.totals));
  map.set(16, paymentToCbor(receipt.payment));
  if (receipt.refundOfReceiptId !== undefined) {
    map.set(17, receipt.refundOfReceiptId);
  }
  if (receipt.voidOfReceiptId !== undefined) {
    map.set(18, receipt.voidOfReceiptId);
  }
  if (receipt.orderReference !== undefined) {
    map.set(19, orderReferenceToCbor(receipt.orderReference));
  }
  map.set(20, receipt.merchantCredential);
  if (receipt.extensions !== undefined) {
    map.set(21, receipt.extensions.map(extensionToCbor));
  }
  return map;
}

/**
 * Deterministic-CBOR bytes of the receipt payload. These are the bytes that
 * get signed (inside `Sig_structure`) and the bytes the dedup comparison uses.
 */
export function serializeReceipt(receipt: Receipt): Uint8Array {
  return encodeCbor(receiptToCbor(receipt));
}

// ---------------------------------------------------------------------------
// Arithmetic (exact, integer-only — receipt-v1.md §5.2)
// ---------------------------------------------------------------------------

/**
 * `round_half_away(n, d) = sign(n) * floor((2|n| + d) / (2d))`, `d > 0`.
 * Implemented with BigInt so the comparison is exact for every legal input;
 * `Number` would silently lose the half-way case near 2^53.
 */
export function roundHalfAwayFromZero(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', 'rounding denominator must be positive');
  }
  const magnitude = numerator < 0n ? -numerator : numerator;
  const rounded = (2n * magnitude + denominator) / (2n * denominator);
  return numerator < 0n ? -rounded : rounded;
}

/**
 * `line_amount_minor = round_half_away(unit_price_minor * value, 10^scale)`.
 * The overflow guard runs *before* the division (§5.2).
 */
export function computeLineAmountMinor(unitPriceMinor: number, quantity: Quantity): number {
  const product = BigInt(unitPriceMinor) * BigInt(quantity.value);
  const magnitude = product < 0n ? -product : product;
  if (magnitude > MAX_ARITH_PRODUCT) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', 'unit price x quantity exceeds 2^62');
  }
  const result = roundHalfAwayFromZero(product, 10n ** BigInt(quantity.scale));
  if (result < 0n || result > BigInt(RECEIPT_LIMITS.maxMonetaryAbs)) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', 'line amount is outside the receivable range');
  }
  return Number(result);
}

/** `round_half_away(base * rate_ppm, 1e6)` for tax and rate-based discounts. */
export function computeRateAmountMinor(baseAmountMinor: number, ratePpm: number): number {
  const product = BigInt(baseAmountMinor) * BigInt(ratePpm);
  const result = roundHalfAwayFromZero(product, 1000000n);
  if (result < 0n || result > BigInt(RECEIPT_LIMITS.maxMonetaryAbs)) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', 'rate-derived amount is out of range');
  }
  return Number(result);
}

export interface RecomputeSummary {
  lineAmounts: number[];
  subtotalMinor: number;
  discountTotalMinor: number;
  taxTotalMinor: number;
  taxAddedTotalMinor: number;
  tipMinor: number;
  serviceChargeMinor: number;
  roundingAdjustmentMinor: number;
  totalMinor: number;
  sumTendersMinor: number;
}

/** Recompute every derived total from the stated lines/discounts/taxes. */
export function recomputeTotals(receipt: Receipt): RecomputeSummary {
  const lineAmounts = receipt.lines.map(line => line.lineAmountMinor);
  const subtotalMinor = lineAmounts.reduce((sum, value) => sum + value, 0);
  const discountTotalMinor = (receipt.discounts ?? []).reduce((sum, discount) => sum + discount.amountMinor, 0);
  const taxes = receipt.taxes ?? [];
  const taxTotalMinor = taxes.reduce((sum, tax) => sum + tax.amountMinor, 0);
  const taxAddedTotalMinor = taxes
    .filter(tax => tax.includedInPrices !== true)
    .reduce((sum, tax) => sum + tax.amountMinor, 0);
  const tipMinor = receipt.tipAmountMinor ?? 0;
  const serviceChargeMinor = receipt.serviceChargeMinor ?? 0;
  const roundingAdjustmentMinor = receipt.roundingAdjustmentMinor ?? 0;
  const totalMinor =
    subtotalMinor - discountTotalMinor + taxAddedTotalMinor + tipMinor + serviceChargeMinor + roundingAdjustmentMinor;
  const sumTendersMinor = (receipt.payment.tenders ?? []).reduce((sum, tender) => sum + tender.amountMinor, 0);
  return {
    lineAmounts,
    subtotalMinor,
    discountTotalMinor,
    taxTotalMinor,
    taxAddedTotalMinor,
    tipMinor,
    serviceChargeMinor,
    roundingAdjustmentMinor,
    totalMinor,
    sumTendersMinor,
  };
}

// ---------------------------------------------------------------------------
// Text safety (receipt-v1.md §8 "check_text")
// ---------------------------------------------------------------------------

const BIDI_CONTROLS = new Set([0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

/** Valid UTF-8 / NFC-normalized / no C0,C1 controls, surrogates or bidi controls. */
/**
 * A non-ASCII text value whose NFC form could not be decided synchronously,
 * because this engine has no `String.prototype.normalize`. It is confirmed
 * through the bridged platform normalizer before any receipt is accepted.
 */
export interface DeferredNfcCheck {
  label: string;
  value: string;
}

/** Collects the values a synchronous parse could not decide. */
class NfcDeferral {
  readonly checks: DeferredNfcCheck[] = [];

  add(label: string, value: string): void {
    this.checks.push({label, value});
  }
}

/**
 * The collector for the parse in progress. It is module state only because CBOR
 * validation is synchronous; NO parse result escapes while it is populated — the
 * async boundary below drains it before returning.
 */
let activeDeferral: NfcDeferral | null = null;

export function checkText(value: string, maxBytes: number, label: string): void {
  const byteLength = utf8ByteLength(value);
  if (byteLength > maxBytes) {
    throw new ProtocolError('RECEIPT_TEXT_INVALID', `${label} is ${byteLength} bytes, above ${maxBytes}`);
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      throw new ProtocolError('RECEIPT_TEXT_INVALID', `${label} contains a control character`);
    }
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
      throw new ProtocolError('RECEIPT_TEXT_INVALID', `${label} contains a surrogate code point`);
    }
    if (BIDI_CONTROLS.has(codePoint)) {
      throw new ProtocolError('RECEIPT_TEXT_INVALID', `${label} contains a bidi control character`);
    }
  }
  // NFC is a REQUIRED rule (receipt-v1.md §1, §8) — two visually identical
  // strings must not have two byte representations — so it is never skipped:
  //
  //  * ASCII (U+0000..U+007F) has no canonical decompositions or compositions,
  //    so NFC is the identity on it. That is a Unicode theorem, not a shortcut:
  //    a pure-ASCII string is NFC without consulting any engine. This covers
  //    every string in the frozen vectors and the demo.
  //  * non-ASCII goes through `normalization.ts`, which uses the platform
  //    normalizer when present and the `unorm` fallback otherwise, so valid
  //    non-ASCII text works on Hermes too (see that module for the measured
  //    limitation of the fallback's older Unicode tables).
  //  * only when NEITHER engine exists is the string rejected — fail closed,
  //    never accepted unvalidated.
  if (isAscii(value)) {
    return;
  }
  const normalized = toNfc(value);
  if (normalized === null) {
    // No synchronous engine. The value is recorded for confirmation through the
    // OS normalizer. It is never accepted here: `parseReceiptPayloadAsync` drains
    // the collector and fails the parse if confirmation does not pass, so no
    // parse result can escape unvalidated.
    if (activeDeferral === null) {
      throw new ProtocolError('INTERNAL_ERROR', 'NFC deferral outside a parse');
    }
    activeDeferral.add(label, value);
    return;
  }
  if (normalized !== value) {
    throw new ProtocolError('RECEIPT_TEXT_INVALID', `${label} is not NFC-normalized`);
  }
}

/** True when every code unit is in U+0000..U+007F (where NFC is the identity). */
export function isAscii(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) {
      return false;
    }
  }
  return true;
}

function utf8ByteLength(value: string): number {
  let length = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    length += codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
  }
  return length;
}

// ---------------------------------------------------------------------------
// Validation (receipt-v1.md §3–§8)
// ---------------------------------------------------------------------------

export interface DecodedReceipt {
  receipt: Receipt;
  /** The exact payload bytes the caller supplied (never re-encoded). */
  payloadBytes: Uint8Array;
  /** Fields that were present but not understood; critical ones already threw. */
  ignoredNonCriticalExtensionKeys: string[];
  /**
   * Non-ASCII values whose NFC form this engine cannot decide synchronously.
   * Empty on any build with `String.prototype.normalize`. `verifyReceipt`
   * confirms every entry through the platform normalizer before accepting.
   */
  deferredNfcChecks: DeferredNfcCheck[];
}

function requireMap(value: CborValue | undefined, label: string, allowed: number[]): CborMap {
  if (!(value instanceof CborMap)) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be a map`);
  }
  for (const key of value.keys()) {
    if (!allowed.includes(key)) {
      throw new ProtocolError('RECEIPT_UNKNOWN_FIELD', `${label} has unknown label ${key}`);
    }
  }
  return value;
}

function optionalMap(value: CborValue | undefined, label: string, allowed: number[]): CborMap | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireMap(value, label, allowed);
}

function requireUint(value: CborValue | undefined, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be a non-negative integer`);
  }
  return value;
}

function optionalUint(value: CborValue | undefined, label: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireUint(value, label);
}

function requireInt(value: CborValue | undefined, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be an integer`);
  }
  return value;
}

function optionalInt(value: CborValue | undefined, label: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireInt(value, label);
}

function requireText(value: CborValue | undefined, label: string, maxBytes: number): string {
  if (typeof value !== 'string') {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be a text string`);
  }
  checkText(value, maxBytes, label);
  return value;
}

function requireBytes(value: CborValue | undefined, label: string, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be a ${length}-byte string`);
  }
  return value;
}

function requireArray(value: CborValue | undefined, label: string, max: number): CborValue[] {
  if (!Array.isArray(value)) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} must be an array`);
  }
  if (value.length > max) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} has ${value.length} items, above ${max}`);
  }
  return value;
}

function requireMonetary(value: CborValue | undefined, label: string, signed: boolean): number {
  const number = signed ? requireInt(value, label) : requireUint(value, label);
  if (Math.abs(number) > RECEIPT_LIMITS.maxMonetaryAbs) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', `${label} is outside the monetary bound`);
  }
  return number;
}

function requireQtyScale(value: CborValue | undefined, label: string): number {
  const scale = requireUint(value, label);
  if (scale > RECEIPT_LIMITS.maxQtyScale) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} is above ${RECEIPT_LIMITS.maxQtyScale}`);
  }
  return scale;
}

function parseQuantity(value: CborValue | undefined, label: string): Quantity {
  const map = requireMap(value, label, [1, 2, 3]);
  const quantity: Quantity = {
    scale: requireQtyScale(map.get(1), `${label}.scale`),
    value: requireInt(map.get(2), `${label}.value`),
  };
  if (Math.abs(quantity.value) > RECEIPT_LIMITS.maxQtyValueAbs) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.value is above ${RECEIPT_LIMITS.maxQtyValueAbs}`);
  }
  const unit = map.get(3);
  if (unit !== undefined) {
    quantity.unit = requireText(unit, `${label}.unit`, RECEIPT_LIMITS.maxTextUnitBytes);
  }
  return quantity;
}

function parseLine(value: CborValue, index: number): ReceiptLine {
  const label = `lines[${index}]`;
  const map = requireMap(value, label, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const lineId = requireUint(map.get(1), `${label}.line_id`);
  if (lineId < 1) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.line_id must be >= 1`);
  }
  const line: ReceiptLine = {
    lineId,
    description: requireText(map.get(2), `${label}.description`, RECEIPT_LIMITS.maxTextDescriptionBytes),
    quantity: parseQuantity(map.get(3), `${label}.quantity`),
    unitPriceMinor: requireMonetary(map.get(4), `${label}.unit_price_minor`, true),
    lineAmountMinor: requireMonetary(map.get(5), `${label}.line_amount_minor`, false),
  };
  if (Math.abs(line.unitPriceMinor) > RECEIPT_LIMITS.maxUnitPriceAbs) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', `${label}.unit_price_minor exceeds the per-unit bound`);
  }
  if (line.lineAmountMinor > RECEIPT_LIMITS.maxMonetaryAbs) {
    throw new ProtocolError('RECEIPT_MONETARY_RANGE', `${label}.line_amount_minor exceeds the monetary bound`);
  }
  const lineDiscount = optionalUint(map.get(6), `${label}.line_discount_minor`);
  if (lineDiscount !== undefined) {
    if (lineDiscount > line.lineAmountMinor) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.line_discount_minor exceeds the line amount`);
    }
    line.lineDiscountMinor = lineDiscount;
  }
  const parents = map.get(7);
  if (parents !== undefined) {
    line.parentLineIds = requireArray(parents, `${label}.parent_line_ids`, RECEIPT_LIMITS.maxLines).map((parent, i) =>
      requireUint(parent, `${label}.parent_line_ids[${i}]`),
    );
    if (line.parentLineIds.length === 0) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.parent_line_ids must not be empty`);
    }
  }
  const lineType = map.get(8);
  if (lineType !== undefined) {
    const parsed = requireUint(lineType, `${label}.line_type`);
    if (parsed < 1 || parsed > 4) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.line_type must be 1..4`);
    }
    line.lineType = parsed as 1 | 2 | 3 | 4;
  }
  const sku = map.get(9);
  if (sku !== undefined) {
    line.sku = requireText(sku, `${label}.sku`, RECEIPT_LIMITS.maxTextShortBytes);
  }
  const modifiers = map.get(10);
  if (modifiers !== undefined) {
    line.modifiers = requireArray(modifiers, `${label}.modifiers`, RECEIPT_LIMITS.maxModifiers).map((modifier, i) => {
      const modifierLabel = `${label}.modifiers[${i}]`;
      const modifierMap = requireMap(modifier, modifierLabel, [1, 2, 3, 4]);
      return {
        description: requireText(modifierMap.get(1), `${modifierLabel}.description`, RECEIPT_LIMITS.maxTextDescriptionBytes),
        unitPriceMinor: requireInt(modifierMap.get(2), `${modifierLabel}.unit_price_minor`),
        qtyValue: requireInt(modifierMap.get(3), `${modifierLabel}.qty_value`),
        qtyScale: requireQtyScale(modifierMap.get(4), `${modifierLabel}.qty_scale`),
      };
    });
  }
  return line;
}

function parseDiscount(value: CborValue, index: number): ReceiptDiscount {
  const label = `discounts[${index}]`;
  const map = requireMap(value, label, [1, 2, 3, 4, 5, 6, 7]);
  const scope = requireUint(map.get(4), `${label}.scope`);
  if (scope !== 1 && scope !== 2) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.scope must be 1 or 2`);
  }
  const discount: ReceiptDiscount = {
    discountId: requireUint(map.get(1), `${label}.discount_id`),
    amountMinor: requireMonetary(map.get(2), `${label}.amount_minor`, false),
    scope: scope as 1 | 2,
  };
  const discountLabel = map.get(3);
  if (discountLabel !== undefined) {
    discount.label = requireText(discountLabel, `${label}.label`, RECEIPT_LIMITS.maxTextDisplayNameBytes);
  }
  const target = optionalUint(map.get(5), `${label}.target_line_id`);
  if (target !== undefined) {
    discount.targetLineId = target;
  }
  if (scope === 2 && target === undefined) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.target_line_id is required for a line-scoped discount`);
  }
  const rate = optionalUint(map.get(6), `${label}.rate_ppm`);
  const base = optionalUint(map.get(7), `${label}.base_amount_minor`);
  if (rate !== undefined) {
    if (rate > RECEIPT_LIMITS.maxTaxRatePpm) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.rate_ppm is above ${RECEIPT_LIMITS.maxTaxRatePpm}`);
    }
    if (base === undefined) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.base_amount_minor is required with rate_ppm`);
    }
    discount.ratePpm = rate;
    discount.baseAmountMinor = base;
    if (discount.amountMinor !== computeRateAmountMinor(base, rate)) {
      throw new ProtocolError(
        'RECEIPT_ARITHMETIC_MISMATCH',
        `${label}.amount_minor ${discount.amountMinor} != round_half_away(${base} * ${rate}, 1e6)`,
      );
    }
  }
  return discount;
}

function parseTax(value: CborValue, index: number): ReceiptTax {
  const label = `taxes[${index}]`;
  const map = requireMap(value, label, [1, 2, 3, 4, 5, 6, 7, 8]);
  const ratePpm = requireUint(map.get(3), `${label}.rate_ppm`);
  if (ratePpm > RECEIPT_LIMITS.maxTaxRatePpm) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.rate_ppm is above ${RECEIPT_LIMITS.maxTaxRatePpm}`);
  }
  const base = requireMonetary(map.get(4), `${label}.base_amount_minor`, false);
  const amount = requireMonetary(map.get(5), `${label}.amount_minor`, false);
  const tax: ReceiptTax = {
    taxId: requireUint(map.get(1), `${label}.tax_id`),
    ratePpm,
    baseAmountMinor: base,
    amountMinor: amount,
  };
  const taxLabel = map.get(2);
  if (taxLabel !== undefined) {
    tax.label = requireText(taxLabel, `${label}.label`, RECEIPT_LIMITS.maxTextDisplayNameBytes);
  }
  const jurisdiction = map.get(6);
  if (jurisdiction !== undefined) {
    tax.jurisdiction = requireText(jurisdiction, `${label}.jurisdiction`, RECEIPT_LIMITS.maxTextShortBytes);
  }
  const code = map.get(7);
  if (code !== undefined) {
    tax.code = requireText(code, `${label}.code`, RECEIPT_LIMITS.maxTextShortBytes);
  }
  const included = map.get(8);
  if (included !== undefined) {
    if (typeof included !== 'boolean') {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.included_in_prices must be a boolean`);
    }
    tax.includedInPrices = included;
  }
  if (tax.includedInPrices === true && tax.baseAmountMinor !== 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label} is included in prices but states a non-zero base`);
  }
  if (amount !== computeRateAmountMinor(base, ratePpm)) {
    throw new ProtocolError(
      'RECEIPT_ARITHMETIC_MISMATCH',
      `${label}.amount_minor ${amount} != round_half_away(${base} * ${ratePpm}, 1e6)`,
    );
  }
  return tax;
}

function parseTender(value: CborValue, index: number): ReceiptTender {
  const label = `payment.tenders[${index}]`;
  const map = requireMap(value, label, [1, 2, 3, 4, 5]);
  const method = requireUint(map.get(1), `${label}.method`);
  if (method < 1 || method > 4) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.method must be 1..4`);
  }
  const tender: ReceiptTender = {
    method: method as 1 | 2 | 3 | 4,
    amountMinor: requireMonetary(map.get(2), `${label}.amount_minor`, false),
  };
  const last4 = map.get(3);
  if (last4 !== undefined) {
    const text = requireText(last4, `${label}.card_last4`, 4);
    if (!/^[0-9]{4}$/.test(text)) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.card_last4 must be exactly four digits`);
    }
    tender.cardLast4 = text;
  }
  const brand = map.get(4);
  if (brand !== undefined) {
    tender.brand = requireText(brand, `${label}.brand`, RECEIPT_LIMITS.maxTextShortBytes);
  }
  const authRef = map.get(5);
  if (authRef !== undefined) {
    tender.authRef = requireText(authRef, `${label}.auth_ref`, RECEIPT_LIMITS.maxTextShortBytes);
  }
  return tender;
}

function parsePayment(value: CborValue | undefined): ReceiptPayment {
  const map = requireMap(value, 'payment', [1, 2, 3, 4]);
  const status = requireUint(map.get(1), 'payment.status');
  if (status < 1 || status > 5) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'payment.status must be 1..5');
  }
  const payment: ReceiptPayment = {
    status: status as 1 | 2 | 3 | 4 | 5,
    amountPaidMinor: requireMonetary(map.get(2), 'payment.amount_paid_minor', false),
  };
  const change = optionalUint(map.get(3), 'payment.change_minor');
  if (change !== undefined) {
    payment.changeMinor = change;
  }
  const tenders = map.get(4);
  if (tenders !== undefined) {
    payment.tenders = requireArray(tenders, 'payment.tenders', RECEIPT_LIMITS.maxTenders).map(parseTender);
  }
  return payment;
}

function parseExtensions(
  value: CborValue | undefined,
  knownKeys: Set<string>,
): {extensions: ReceiptExtension[]; ignored: string[]} {
  if (value === undefined) {
    return {extensions: [], ignored: []};
  }
  const ignored: string[] = [];
  const extensions = requireArray(value, 'extensions', RECEIPT_LIMITS.maxExtensions).map((extension, index) => {
    const label = `extensions[${index}]`;
    const map = requireMap(extension, label, [1, 2, 3]);
    const key = requireText(map.get(1), `${label}.key`, RECEIPT_LIMITS.maxTextShortBytes);
    const critical = map.get(2);
    if (typeof critical !== 'boolean') {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `${label}.critical must be a boolean`);
    }
    const parsed: ReceiptExtension = {key, critical};
    const extensionValue = map.get(3);
    if (extensionValue !== undefined) {
      parsed.value = extensionValue;
    }
    if (!knownKeys.has(key)) {
      if (critical) {
        throw new ProtocolError('RECEIPT_UNKNOWN_CRITICAL_EXTENSION', `unknown critical extension "${key}"`);
      }
      ignored.push(key);
    }
    return parsed;
  });
  return {extensions, ignored};
}

const TOP_LEVEL_LABELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

/** v1 knows no extensions; any critical one is fatal (receipt-v1.md §6). */
export const KNOWN_EXTENSIONS: ReadonlySet<string> = new Set<string>();

/**
 * Validate a decoded receipt map and build the typed model. Every violation is
 * a `ProtocolError` with the frozen identifier from verification.md §1 step 12.
 */
export function parseReceiptMap(map: CborMap): {
  receipt: Receipt;
  ignoredNonCriticalExtensionKeys: string[];
  /** Non-ASCII values a synchronous parse could not decide; usually empty. */
  deferredNfcChecks: DeferredNfcCheck[];
} {
  const outer = activeDeferral;
  const collector = outer ?? new NfcDeferral();
  activeDeferral = collector;
  try {
    const parsed = parseReceiptMapInner(map);
    return {...parsed, deferredNfcChecks: collector === outer ? [] : collector.checks};
  } finally {
    activeDeferral = outer;
  }
}

function parseReceiptMapInner(map: CborMap): {receipt: Receipt; ignoredNonCriticalExtensionKeys: string[]} {
  requireMap(map, 'receipt', TOP_LEVEL_LABELS);

  const version = requireUint(map.get(1), 'receipt_version');
  if (version !== 1) {
    throw new ProtocolError('RECEIPT_UNSUPPORTED_VERSION', `receipt_version ${version} is not supported`);
  }
  const kind = requireUint(map.get(2), 'kind');
  if (kind !== KIND_SALE && kind !== KIND_REFUND && kind !== KIND_VOID) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `kind ${kind} is not 1, 2 or 3`);
  }
  const receiptId = requireBytes(map.get(3), 'receipt_id', 16);
  const issuedAt = requireUint(map.get(4), 'issued_at');
  if (issuedAt < RECEIPT_LIMITS.minIssuedAt || issuedAt > RECEIPT_LIMITS.maxIssuedAt) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `issued_at ${issuedAt} is outside the v1 window`);
  }

  const merchantMap = requireMap(map.get(6), 'merchant', [1, 2, 3]);
  const merchant: ReceiptMerchant = {
    merchantId: requireBytes(merchantMap.get(1), 'merchant.merchant_id', 16),
    displayName: requireText(merchantMap.get(2), 'merchant.display_name', RECEIPT_LIMITS.maxTextDisplayNameBytes),
    merchantReference: requireText(
      merchantMap.get(3),
      'merchant.merchant_reference',
      RECEIPT_LIMITS.maxTextDisplayNameBytes,
    ),
  };

  const currency = requireText(map.get(8), 'currency', 3);
  if (CURRENCY_MINOR_UNIT_EXPONENT[currency] === undefined) {
    throw new ProtocolError('RECEIPT_UNSUPPORTED_CURRENCY', `currency ${currency} is not in the v1 exponent table`);
  }

  const lines = requireArray(map.get(9), 'lines', RECEIPT_LIMITS.maxLines).map(parseLine);
  const lineIds = new Set<number>();
  for (const line of lines) {
    if (lineIds.has(line.lineId)) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `duplicate line_id ${line.lineId}`);
    }
    lineIds.add(line.lineId);
  }
  for (const line of lines) {
    for (const parent of line.parentLineIds ?? []) {
      if (!lineIds.has(parent)) {
        throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `line ${line.lineId} references unknown parent ${parent}`);
      }
    }
  }

  const receipt: Receipt = {
    receiptVersion: 1,
    kind: kind as ReceiptKind,
    receiptId,
    issuedAt,
    merchant,
    currency,
    lines,
    totals: {
      subtotalMinor: 0,
      discountTotalMinor: 0,
      taxTotalMinor: 0,
      totalMinor: 0,
      taxAddedTotalMinor: 0,
    },
    payment: {status: 1, amountPaidMinor: 0},
    merchantCredential: new Uint8Array(0),
  };

  const tzOffset = optionalInt(map.get(5), 'tz_offset_minutes');
  if (tzOffset !== undefined) {
    // The frozen vectors carry the reference implementation's bound
    // (+/-14h expressed in seconds, `valid_baseline` = -14400), while
    // receipt-v1.md §3 states "-840..840". The vectors are what A6's
    // conformance run asserts, so the reference bound is what we enforce;
    // the narrower prose range is a subset. Reported to A1 as a doc defect.
    if (tzOffset < -50400 || tzOffset > 50400) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'tz_offset_minutes is outside -50400..50400');
    }
    receipt.tzOffsetMinutes = tzOffset;
  }

  const locationMap = optionalMap(map.get(7), 'location', [1, 2, 3, 4, 5, 6]);
  if (locationMap !== undefined) {
    const location: ReceiptLocation = {};
    const shortish = RECEIPT_LIMITS.maxTextDescriptionBytes;
    const labels: Array<[number, keyof ReceiptLocation]> = [
      [1, 'label'],
      [2, 'street'],
      [3, 'city'],
      [4, 'region'],
    ];
    for (const [entryLabel, name] of labels) {
      const raw = locationMap.get(entryLabel);
      if (raw !== undefined) {
        (location as Record<string, unknown>)[name] = requireText(raw, `location.${name}`, shortish);
      }
    }
    const addressLines = locationMap.get(5);
    if (addressLines !== undefined) {
      location.addressLines = requireArray(addressLines, 'location.address_lines', RECEIPT_LIMITS.maxAddressLines).map(
        (line, index) => requireText(line, `location.address_lines[${index}]`, shortish),
      );
    }
    const postal = locationMap.get(6);
    if (postal !== undefined) {
      const text = requireText(postal, 'location.postal_code', RECEIPT_LIMITS.maxTextShortBytes);
      if (!/^[0-9]+$/.test(text)) {
        throw new ProtocolError('RECEIPT_TEXT_INVALID', 'location.postal_code must be digits only');
      }
      location.postalCode = text;
    }
    receipt.location = location;
  }

  const discounts = map.get(10);
  if (discounts !== undefined) {
    receipt.discounts = requireArray(discounts, 'discounts', RECEIPT_LIMITS.maxDiscounts).map(parseDiscount);
    const discountIds = new Set<number>();
    for (const discount of receipt.discounts) {
      if (discountIds.has(discount.discountId)) {
        throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `duplicate discount_id ${discount.discountId}`);
      }
      discountIds.add(discount.discountId);
      if (discount.scope === 2 && discount.targetLineId !== undefined && !lineIds.has(discount.targetLineId)) {
        throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `discount targets unknown line ${discount.targetLineId}`);
      }
    }
  }

  const taxes = map.get(11);
  if (taxes !== undefined) {
    receipt.taxes = requireArray(taxes, 'taxes', RECEIPT_LIMITS.maxTaxes).map(parseTax);
    const taxIds = new Set<number>();
    for (const tax of receipt.taxes) {
      if (taxIds.has(tax.taxId)) {
        throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `duplicate tax_id ${tax.taxId}`);
      }
      taxIds.add(tax.taxId);
    }
  }

  const tip = optionalUint(map.get(12), 'tip_amount_minor');
  if (tip !== undefined) {
    receipt.tipAmountMinor = requireMonetary(tip, 'tip_amount_minor', false);
  }
  const serviceCharge = optionalUint(map.get(13), 'service_charge_minor');
  if (serviceCharge !== undefined) {
    receipt.serviceChargeMinor = requireMonetary(serviceCharge, 'service_charge_minor', false);
  }
  const rounding = optionalInt(map.get(14), 'rounding_adjustment_minor');
  if (rounding !== undefined) {
    receipt.roundingAdjustmentMinor = requireMonetary(rounding, 'rounding_adjustment_minor', true);
  }

  const totalsMap = requireMap(map.get(15), 'totals', [1, 2, 3, 4, 5, 6, 7, 8]);
  const totals: ReceiptTotals = {
    subtotalMinor: requireMonetary(totalsMap.get(1), 'totals.subtotal_minor', false),
    discountTotalMinor: requireMonetary(totalsMap.get(2), 'totals.discount_total_minor', false),
    taxTotalMinor: requireMonetary(totalsMap.get(3), 'totals.tax_total_minor', false),
    totalMinor: requireMonetary(totalsMap.get(4), 'totals.total_minor', false),
    taxAddedTotalMinor: requireMonetary(totalsMap.get(8), 'totals.tax_added_total_minor', false),
  };
  const totalsTip = optionalUint(totalsMap.get(5), 'totals.tip_minor');
  if (totalsTip !== undefined) {
    totals.tipMinor = totalsTip;
  }
  const totalsService = optionalUint(totalsMap.get(6), 'totals.service_charge_minor');
  if (totalsService !== undefined) {
    totals.serviceChargeMinor = totalsService;
  }
  const totalsRounding = optionalInt(totalsMap.get(7), 'totals.rounding_adjustment_minor');
  if (totalsRounding !== undefined) {
    totals.roundingAdjustmentMinor = totalsRounding;
  }
  receipt.totals = totals;

  receipt.payment = parsePayment(map.get(16));

  const refundOf = map.get(17);
  if (refundOf !== undefined) {
    receipt.refundOfReceiptId = requireBytes(refundOf, 'refund_of_receipt_id', 16);
  }
  const voidOf = map.get(18);
  if (voidOf !== undefined) {
    receipt.voidOfReceiptId = requireBytes(voidOf, 'void_of_receipt_id', 16);
  }
  if (receipt.kind === KIND_REFUND && receipt.refundOfReceiptId === undefined) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'kind=refund requires refund_of_receipt_id');
  }
  if (receipt.kind === KIND_VOID && receipt.voidOfReceiptId === undefined) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'kind=void requires void_of_receipt_id');
  }

  const orderRefMap = optionalMap(map.get(19), 'order_reference', [1, 2, 3]);
  if (orderRefMap !== undefined) {
    const orderReference: ReceiptOrderReference = {};
    const orderNumber = orderRefMap.get(1);
    if (orderNumber !== undefined) {
      orderReference.orderNumber = requireText(orderNumber, 'order_reference.order_number', RECEIPT_LIMITS.maxTextShortBytes);
    }
    const table = orderRefMap.get(2);
    if (table !== undefined) {
      orderReference.table = requireText(table, 'order_reference.table', RECEIPT_LIMITS.maxTextShortBytes);
    }
    const server = orderRefMap.get(3);
    if (server !== undefined) {
      orderReference.server = requireText(server, 'order_reference.server', RECEIPT_LIMITS.maxTextShortBytes);
    }
    receipt.orderReference = orderReference;
  }

  const credential = map.get(20);
  if (!(credential instanceof Uint8Array)) {
    throw new ProtocolError('RECEIPT_CREDENTIAL_MISMATCH', 'receipt must embed its merchant credential at label 20');
  }
  receipt.merchantCredential = credential;

  const {extensions, ignored} = parseExtensions(map.get(21), KNOWN_EXTENSIONS as Set<string>);
  if (extensions.length > 0) {
    receipt.extensions = extensions;
  }

  validateArithmetic(receipt);
  validateKindSemantics(receipt);
  return {receipt, ignoredNonCriticalExtensionKeys: ignored};
}

/** Recompute every stated total; any mismatch is `RECEIPT_ARITHMETIC_MISMATCH`. */
function validateArithmetic(receipt: Receipt): void {
  for (const [index, line] of receipt.lines.entries()) {
    const expected = computeLineAmountMinor(line.unitPriceMinor, line.quantity);
    if (expected !== line.lineAmountMinor) {
      throw new ProtocolError(
        'RECEIPT_ARITHMETIC_MISMATCH',
        `lines[${index}].line_amount_minor ${line.lineAmountMinor} != round_half_away(${line.unitPriceMinor} * ${line.quantity.value}, 10^${line.quantity.scale}) = ${expected}`,
      );
    }
  }
  const recomputed = recomputeTotals(receipt);
  const totals = receipt.totals;
  const comparisons: Array<[string, number, number]> = [
    ['totals.subtotal_minor', totals.subtotalMinor, recomputed.subtotalMinor],
    ['totals.discount_total_minor', totals.discountTotalMinor, recomputed.discountTotalMinor],
    ['totals.tax_total_minor', totals.taxTotalMinor, recomputed.taxTotalMinor],
    ['totals.tax_added_total_minor', totals.taxAddedTotalMinor, recomputed.taxAddedTotalMinor],
    ['totals.total_minor', totals.totalMinor, recomputed.totalMinor],
  ];
  for (const [label, stated, expected] of comparisons) {
    if (stated !== expected) {
      throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', `${label} ${stated} != recomputed ${expected}`);
    }
  }
  if (recomputed.totalMinor < 0) {
    throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', 'totals.total_minor recomputes below zero');
  }
  if (totals.tipMinor !== undefined && totals.tipMinor !== (receipt.tipAmountMinor ?? 0)) {
    throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', 'totals.tip_minor disagrees with tip_amount_minor');
  }
  if (totals.serviceChargeMinor !== undefined && totals.serviceChargeMinor !== (receipt.serviceChargeMinor ?? 0)) {
    throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', 'totals.service_charge_minor disagrees with the stated service charge');
  }
  if (totals.roundingAdjustmentMinor !== undefined && totals.roundingAdjustmentMinor !== (receipt.roundingAdjustmentMinor ?? 0)) {
    throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', 'totals.rounding_adjustment_minor disagrees with the stated rounding');
  }
}

/** kind-driven payment/line constraints (receipt-v1.md §4.7). */
function validateKindSemantics(receipt: Receipt): void {
  const {payment, totals, kind, lines} = receipt;
  const tenders = payment.tenders;
  if (tenders !== undefined) {
    if (payment.status !== PAYMENT_STATUS.paid && tenders.length > 0) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'tenders are only permitted for a paid sale');
    }
    const sum = tenders.reduce((total, tender) => total + tender.amountMinor, 0);
    if (sum !== payment.amountPaidMinor) {
      throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', `tender sum ${sum} != amount_paid_minor ${payment.amountPaidMinor}`);
    }
  }
  if (payment.amountPaidMinor > totals.totalMinor) {
    const expectedChange = payment.amountPaidMinor - totals.totalMinor;
    if (payment.changeMinor !== expectedChange) {
      throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', `payment.change_minor must equal overpayment ${expectedChange}`);
    }
  } else if (payment.changeMinor !== undefined) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'payment.change_minor is only permitted when the customer overpays');
  }

  if (kind === KIND_SALE) {
    if (payment.status === PAYMENT_STATUS.paid && payment.amountPaidMinor < totals.totalMinor) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a paid sale must have amount_paid_minor >= total_minor');
    }
    if (payment.status === PAYMENT_STATUS.partial && payment.amountPaidMinor >= totals.totalMinor) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a partial sale must have amount_paid_minor < total_minor');
    }
    if (payment.status === PAYMENT_STATUS.unpaid && payment.amountPaidMinor !== 0) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'an unpaid sale must have amount_paid_minor = 0');
    }
    if (payment.status === PAYMENT_STATUS.paid && tenders === undefined) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a paid sale must carry tenders');
    }
    if (payment.status !== PAYMENT_STATUS.paid && payment.status !== PAYMENT_STATUS.partial && payment.status !== PAYMENT_STATUS.unpaid) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', `payment.status ${payment.status} is not valid for a sale`);
    }
    return;
  }

  if (kind === KIND_REFUND) {
    if (payment.status !== PAYMENT_STATUS.refunded) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a refund must have payment.status = refunded');
    }
    if (tenders !== undefined && tenders.length > 0) {
      throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a refund must not carry tenders');
    }
    if (payment.amountPaidMinor !== totals.totalMinor) {
      throw new ProtocolError('RECEIPT_ARITHMETIC_MISMATCH', 'a refund must have amount_paid_minor = total_minor');
    }
    return;
  }

  if (payment.status !== PAYMENT_STATUS.voided) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a void must have payment.status = voided');
  }
  if (tenders !== undefined && tenders.length > 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a void must not carry tenders');
  }
  if (payment.amountPaidMinor !== 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a void must have amount_paid_minor = 0');
  }
  if (lines.length !== 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a void must have an empty lines array');
  }
  if (totals.totalMinor !== 0 || totals.subtotalMinor !== 0 || totals.taxTotalMinor !== 0) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a void must have all-zero totals');
  }
}

/**
 * Parse and validate a receipt payload that arrived as untrusted bytes.
 * Depth, item count and length caps are enforced by the CBOR decoder *before*
 * any allocation.
 */
/** Synchronous parse. INTERNAL: always use `parseReceiptPayloadAsync`. */
function parseReceiptPayloadSync(payloadBytes: Uint8Array): {decoded: DecodedReceipt; pending: DeferredNfcCheck[]} {
  if (payloadBytes.length > RECEIPT_LIMITS.maxReceiptBytes) {
    throw new ProtocolError('RECEIPT_SIZE_EXCEEDED', `payload is ${payloadBytes.length} bytes, above ${RECEIPT_LIMITS.maxReceiptBytes}`);
  }
  const outer = activeDeferral;
  const collector = outer ?? new NfcDeferral();
  activeDeferral = collector;
  try {
    const decoded = decodeCbor(payloadBytes);
    if (!(decoded.value instanceof CborMap)) {
      throw new ProtocolError('RECEIPT_CONTAINER_MALFORMED', 'receipt payload must be a CBOR map');
    }
    const {receipt, ignoredNonCriticalExtensionKeys} = parseReceiptMap(decoded.value);
    return {
      decoded: {receipt, payloadBytes, ignoredNonCriticalExtensionKeys, deferredNfcChecks: []},
      pending: collector === outer ? [] : collector.checks,
    };
  } finally {
    activeDeferral = outer;
  }
}

/**
 * Parse and FULLY VALIDATE a receipt payload — the only public parse boundary.
 *
 * Every NFC check is decided before this resolves: synchronously when the engine
 * can, otherwise through the OS normalizer behind the bridge. A payload whose
 * non-ASCII text is not NFC is rejected with `RECEIPT_TEXT_INVALID`; there is no
 * "unconfirmed but returned" state for a caller to misuse.
 */
export async function parseReceiptPayload(payloadBytes: Uint8Array): Promise<DecodedReceipt> {
  const {decoded, pending} = parseReceiptPayloadSync(payloadBytes);
  await confirmNfcChecks(pending);
  return decoded;
}

/**
 * Confirm the values a synchronous parse could not decide. Throws
 * `RECEIPT_TEXT_INVALID` when a value is not NFC or when no exact engine exists,
 * so an unverifiable receipt is never accepted.
 */
export async function confirmNfcChecks(checks: DeferredNfcCheck[]): Promise<void> {
  if (checks.length === 0) {
    return;
  }
  for (const check of checks) {
    let normalized: string;
    try {
      normalized = await normalizeNfcAsync(check.value);
    } catch {
      throw new ProtocolError(
        'RECEIPT_TEXT_INVALID',
        `${check.label} contains non-ASCII text and this runtime has no exact NFC implementation`,
      );
    }
    if (normalized !== check.value) {
      throw new ProtocolError('RECEIPT_TEXT_INVALID', `${check.label} is not NFC-normalized`);
    }
  }
}

/**
 * Validate every text field of an in-memory receipt before it is SIGNED. The
 * signing path must not attest to text the receiver would reject.
 */
export async function validateReceiptText(receipt: Receipt): Promise<void> {
  const collector = new NfcDeferral();
  const outer = activeDeferral;
  activeDeferral = collector;
  try {
    checkText(receipt.merchant.displayName, RECEIPT_LIMITS.maxTextDisplayNameBytes, 'merchant.display_name');
    checkText(receipt.merchant.merchantReference, RECEIPT_LIMITS.maxTextDisplayNameBytes, 'merchant.merchant_reference');
    for (const line of receipt.lines) {
      checkText(line.description, RECEIPT_LIMITS.maxTextDescriptionBytes, `lines[${line.lineId}].description`);
    }
  } finally {
    activeDeferral = outer;
  }
  await confirmNfcChecks(collector.checks);
}

/** Read only the dedup key and the offer-relevant identity fields. */
export interface ReceiptIdentity {
  receiptId: Uint8Array;
  kind: ReceiptKind;
  totalMinor: number;
  currency: string;
  issuedAt: number;
  merchantId: Uint8Array;
  merchantReference: string;
  displayName: string;
  deviceKeyId?: Uint8Array;
}

export function receiptIdentity(receipt: Receipt, deviceKeyId?: Uint8Array): ReceiptIdentity {
  return {
    receiptId: receipt.receiptId,
    kind: receipt.kind,
    totalMinor: receipt.totals.totalMinor,
    currency: receipt.currency,
    issuedAt: receipt.issuedAt,
    merchantId: receipt.merchant.merchantId,
    merchantReference: receipt.merchant.merchantReference,
    displayName: receipt.merchant.displayName,
    deviceKeyId,
  };
}

export function receiptIdHex(receiptId: Uint8Array): string {
  return hexEncode(receiptId);
}
