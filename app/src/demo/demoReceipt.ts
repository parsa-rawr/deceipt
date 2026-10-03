/**
 * The merchant demo receipt.
 *
 * The PoC demo uses the SAME transaction as A1's frozen `receipt-valid.json`:
 * Maple & Vine Cafe, CAD 9.70 total, the Latte / Croissant / Oat milk lines and
 * the same tax and tip. That makes the two-phone run directly comparable with
 * the recorded vector — a customer that trusts the pinned anchor reports
 * `TRUSTED`, and divergence is obvious.
 *
 * The structure is TRANSCRIBED here rather than loaded from
 * `protocol/vectors/receipt-valid.json`, for two reasons:
 *
 *  1. a shipped app bundle cannot read the repository tree at runtime, and must
 *     not depend on test fixtures (conformance B9);
 *  2. the receipt identifier and `issued_at` MUST be fresh per checkout
 *     (receipt-v1.md §3 label 3 requires a random, globally unique id), so the
 *     payload is necessarily re-issued — the signature is over new bytes.
 *
 * Trust comes from the PINNED ANCHOR and the merchant device signature, never
 * from matching the fixture bytes, so a fresh signature still verifies.
 */

import {computeLineAmountMinor, type Receipt} from '../protocol/receipt';
import type {ProtocolError} from '../protocol/errors';
import {secureRandomBytes} from '../protocol/crypto';

/** Fixed instant inside the frozen credential's validity window. */
export const DEMO_ISSUED_AT_UNIX = 1767225540;
export const DEMO_CURRENCY = 'CAD';
export const DEMO_MERCHANT_REFERENCE = 'merchant.poc.test-alpha';
export const DEMO_MERCHANT_DISPLAY_NAME = 'Maple & Vine Cafe';

export interface DemoReceiptInputs {
  /** 16 bytes, must equal the credential's `merchant_id` (label 3). */
  merchantId: Uint8Array;
  /** The exact COSE_Sign1 credential bytes to embed at label 20. */
  credentialBytes: Uint8Array;
  /** Overrides for tests; defaults to the frozen demo instant. */
  issuedAtUnix?: number;
  /** Overrides for tests; defaults to 16 CSPRNG bytes. */
  receiptId?: Uint8Array;
}

interface DemoLine {
  lineId: number;
  description: string;
  qtyScale: number;
  qtyValue: number;
  unit: string;
  unitPriceMinor: number;
  sku: string;
}

/**
 * The three frozen lines, in the order and with the values of
 * `receipt-valid.json#arithmetic.lines`:
 *   [1, 475, 1, 0, 475], [2, 360, 75, 2, 270], [3, 75, 1, 0, 75]
 */
const DEMO_LINES: readonly DemoLine[] = [
  {lineId: 1, description: 'Latte, 16oz', qtyScale: 0, qtyValue: 1, unit: 'ea', unitPriceMinor: 475, sku: 'SKU-LATTE-1'},
  {lineId: 2, description: 'Croissant', qtyScale: 2, qtyValue: 75, unit: 'kg', unitPriceMinor: 360, sku: 'SKU-CROISSANT'},
  {lineId: 3, description: 'Oat milk substitution', qtyScale: 0, qtyValue: 1, unit: 'ea', unitPriceMinor: 75, sku: 'SKU-OATMILK'},
];

const DEMO_DISCOUNT_MINOR = 50;
/**
 * Chosen so the demo reproduces the frozen receipt's tax exactly:
 * `round_half_away(770 * 129870, 1e6) = 100` minor, which is what
 * `receipt-valid.json#arithmetic.tax_total_minor` records. The rate is a demo
 * input, not a protocol constant.
 */
const DEMO_TAX_RATE_PPM = 129870;
const DEMO_TIP_MINOR = 100;

/**
 * Build the demo sale. Line amounts are computed with the shared exact-integer
 * rule, then the totals are recomputed from what was stated, so the receipt
 * this returns always satisfies the arithmetic validation it will face.
 */
export async function buildDemoReceipt(inputs: DemoReceiptInputs): Promise<Receipt> {
  if (inputs.merchantId.length !== 16) {
    throw new Error('the demo receipt needs the credential\'s 16-byte merchant_id');
  }
  // A fresh identifier per checkout is a protocol requirement (receipt-v1.md §3
  // label 3), and it is a secret-bearing value, so it comes from the CSPRNG.
  const receiptId = inputs.receiptId ?? (await secureRandomBytes(16));
  const lines = DEMO_LINES.map(line => {
    const quantity = {scale: line.qtyScale, value: line.qtyValue, unit: line.unit};
    return {
      lineId: line.lineId,
      description: line.description,
      quantity,
      unitPriceMinor: line.unitPriceMinor,
      lineAmountMinor: computeLineAmountMinor(line.unitPriceMinor, quantity),
      lineType: 1 as const,
      sku: line.sku,
    };
  });
  const subtotalMinor = lines.reduce((sum, line) => sum + line.lineAmountMinor, 0);
  // Tax is stated over the discounted base, as the frozen receipt does.
  const taxBase = subtotalMinor - DEMO_DISCOUNT_MINOR;
  const taxAmountMinor = rateAmount(taxBase, DEMO_TAX_RATE_PPM);
  const totalMinor = subtotalMinor - DEMO_DISCOUNT_MINOR + taxAmountMinor + DEMO_TIP_MINOR;
  return {
    receiptVersion: 1,
    kind: 1,
    receiptId,
    issuedAt: inputs.issuedAtUnix ?? DEMO_ISSUED_AT_UNIX,
    tzOffsetMinutes: -14400,
    merchant: {
      merchantId: inputs.merchantId,
      displayName: DEMO_MERCHANT_DISPLAY_NAME,
      merchantReference: DEMO_MERCHANT_REFERENCE,
    },
    currency: DEMO_CURRENCY,
    lines,
    discounts: [
      {
        discountId: 1,
        amountMinor: DEMO_DISCOUNT_MINOR,
        label: 'Loyalty',
        scope: 1,
      },
    ],
    taxes: [
      {
        taxId: 1,
        label: 'GST',
        ratePpm: DEMO_TAX_RATE_PPM,
        baseAmountMinor: taxBase,
        amountMinor: taxAmountMinor,
        jurisdiction: 'CA',
      },
    ],
    tipAmountMinor: DEMO_TIP_MINOR,
    totals: {
      subtotalMinor,
      discountTotalMinor: DEMO_DISCOUNT_MINOR,
      taxTotalMinor: taxAmountMinor,
      totalMinor,
      tipMinor: DEMO_TIP_MINOR,
      taxAddedTotalMinor: taxAmountMinor,
    },
    payment: {
      status: 1,
      amountPaidMinor: totalMinor,
      tenders: [{method: 3, amountMinor: totalMinor, cardLast4: '4242', brand: 'Visa'}],
    },
    merchantCredential: inputs.credentialBytes,
  };
}

/** Round half away from zero, integer-only (receipt-v1.md §5.2). */
function rateAmount(baseMinor: number, ratePpm: number): number {
  const product = baseMinor * ratePpm;
  return Math.floor((2 * product + 1000000) / 2000000);
}

/** Re-exported so the UI can surface a typed failure without importing errors. */
export type DemoError = ProtocolError;
