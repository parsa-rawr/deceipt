/**
 * Receipt conformance (conformance.md §A): the frozen valid/invalid cases, the
 * exact-bytes reconstruction, the arithmetic rules and the text-safety rules.
 *
 * Every expectation is read from `protocol/vectors/**`; none is derived from
 * this implementation.
 */

import {bytesEqual, hexDecode, hexEncode, base64Encode} from '../src/protocol/bytes';
import {computeLineAmountMinor, parseReceiptPayload, roundHalfAwayFromZero, serializeReceipt} from '../src/protocol/receipt';
import {ProtocolError} from '../src/protocol/errors';
import {verifyReceipt} from '../src/protocol/verification';
import {decodeControlMessage, type ReceiptOffer} from '../src/protocol/wire';
import {verifyCredential} from '../src/protocol/handshake';
import type {OfferMetadata, TrustAnchor} from '../src/native/DeceiptNative';
import {
  loadCredentials,
  loadReceiptInvalid,
  loadReceiptValid,
  loadVector,
  vectorPaths,
  type ReceiptInvalidCase,
} from './fixtures';

interface ArithmeticVector {
  rounding_mode: string;
  cases: Array<{
    case: string;
    note: string;
    lines: Array<Record<string, unknown>>;
    subtotal_minor: number;
    total_minor: number;
    receipt_body_hex: string;
    cose_sign1_hex: string;
    expected_verification: {outcome: string; error: string | null};
  }>;
}

function anchorsFrom(anchorsHex: Record<string, string>): TrustAnchor[] {
  return Object.entries(anchorsHex).map(([anchorIdHex, publicKeyHex]) => ({
    anchorIdHex,
    publicKeyB64: base64Encode(hexDecode(publicKeyHex)),
  }));
}

function offerFrom(hex: string | null): OfferMetadata | undefined {
  if (hex === null) {
    return undefined;
  }
  const message = decodeControlMessage(hexDecode(hex), 1) as ReceiptOffer;
  return {
    transferIdHex: hexEncode(message.transferId),
    receiptIdHex: hexEncode(message.receiptId),
    merchantReference: message.merchantReference,
    totalAmountMinor: message.totalAmountMinor,
    currency: message.currency,
    issuedAt: message.issuedAt,
    kind: message.kind,
    ciphertextLength: message.ciphertextLength,
    merchantIdHex: hexEncode(message.merchantId),
    credentialHashHex: hexEncode(message.credentialHash),
    sessionIdHex: hexEncode(message.sessionId),
    offerHashHex: '',
  };
}

describe('receipt body reconstruction (conformance A1/A2/A3)', () => {
  const vector = loadReceiptValid();

  it('parses the frozen body and re-serializes it byte-identically', () => {
    const payload = hexDecode(vector.receipt_body_hex);
    const parsed = parseReceiptPayload(payload);
    const reencoded = serializeReceipt(parsed.receipt);
    expect(reencoded.length).toBe(vector.receipt_body_len);
    expect(bytesEqual(reencoded, payload)).toBe(true);
    expect(hexEncode(reencoded)).toBe(vector.receipt_body_hex);
  });

  it('reproduces the stated arithmetic from the field tables', () => {
    const parsed = parseReceiptPayload(hexDecode(vector.receipt_body_hex));
    const arithmetic = vector.arithmetic;
    expect(parsed.receipt.totals.subtotalMinor).toBe(arithmetic.subtotal_minor);
    expect(parsed.receipt.totals.discountTotalMinor).toBe(arithmetic.discount_total_minor);
    expect(parsed.receipt.totals.taxTotalMinor).toBe(arithmetic.tax_total_minor);
    expect(parsed.receipt.totals.taxAddedTotalMinor).toBe(arithmetic.tax_added_total_minor);
    expect(parsed.receipt.totals.totalMinor).toBe(arithmetic.total_minor);
    expect(parsed.receipt.currency).toBe(arithmetic.currency);
    expect(parsed.receipt.tipAmountMinor).toBe(arithmetic.tip_minor);
    for (const [index, line] of parsed.receipt.lines.entries()) {
      expect(line.lineAmountMinor).toBe(arithmetic.line_gross_minor[index]);
    }
  });

  it('parses the 256-line long receipt', () => {
    const parsed = parseReceiptPayload(hexDecode(vector.long_receipt.receipt_body_hex));
    expect(parsed.receipt.lines).toHaveLength(vector.long_receipt.lines);
    expect(parsed.receipt.totals.totalMinor).toBe(vector.long_receipt.total_minor);
    expect(hexEncode(serializeReceipt(parsed.receipt))).toBe(vector.long_receipt.receipt_body_hex);
  });
});

describe('receipt verification against the frozen invalid fixtures (conformance A5–A14, B3, B7–B8, E7)', () => {
  const cases: ReceiptInvalidCase[] = loadReceiptInvalid().cases;

  it.each(cases.map(testCase => [testCase.case, testCase]))('%s', async (_name, testCase) => {
    const seen = new Map<string, Uint8Array>();
    for (const [id, payload] of Object.entries(testCase.seen_receipt_ids_hex ?? {})) {
      seen.set(id, hexDecode(payload));
    }
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(testCase.cose_sign1_hex),
      anchors: anchorsFrom(testCase.anchors_hex),
      nowUnix: testCase.verify_at_unix,
      sessionCredentialBytes: testCase.session_credential_hex === null ? undefined : hexDecode(testCase.session_credential_hex),
      offer: offerFrom(testCase.receipt_offer_hex),
      seenReceipts: seen,
    });
    expect({outcome: result.outcome, error: result.error?.name ?? null}).toEqual({
      outcome: testCase.expected_outcome,
      error: testCase.expected_error,
    });
    // No path to a trusted receipt on a fatal case.
    if (testCase.expected_outcome !== 'TRUSTED') {
      expect(result.outcome).not.toBe('TRUSTED');
    }
  });

  it('the oversize case is rejected before signature verification', async () => {
    const oversize = cases.find(testCase => testCase.case === 'receipt_oversize_placeholder' || testCase.expected_error === 'RECEIPT_SIZE_EXCEEDED');
    expect(oversize).toBeDefined();
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(oversize!.cose_sign1_hex),
      anchors: anchorsFrom(oversize!.anchors_hex),
      nowUnix: oversize!.verify_at_unix,
    });
    expect(result.error?.name).toBe('RECEIPT_SIZE_EXCEEDED');
    expect(result.subStates.signatureValid).toBe(false);
  });

  it('the valid baseline reports every expected sub-state separately', async () => {
    const baseline = cases.find(testCase => testCase.case === 'valid_baseline')!;
    const vector = loadReceiptValid();
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(vector.cose_sign1_hex),
      anchors: anchorsFrom(baseline.anchors_hex),
      nowUnix: baseline.verify_at_unix,
      offer: offerFrom(vector.receipt_offer_hex),
    });
    expect(result.outcome).toBe(vector.expected_verification.outcome);
    expect(result.error).toBeNull();
    expect(result.subStates.signatureValid).toBe(vector.expected_verification.signature_valid);
    expect(result.subStates.keyAuthorized).toBe(vector.expected_verification.key_authorized);
    expect(result.subStates.credentialTemporallyAcceptable).toBe(vector.expected_verification.credential_temporally_acceptable);
    expect(result.subStates.semanticallyValid).toBe(vector.expected_verification.semantically_valid);
    expect(result.subStates.uniqueLocally).toBe(vector.expected_verification.unique_locally);
    // Revocation is explicitly not evaluated in the PoC.
    expect(result.subStates.revocationKnown).toBe(false);
  });

  it('an unknown issuer is never authorized even though the signature is valid', async () => {
    const unknown = cases.find(testCase => testCase.case === 'unknown_issuer_credential')!;
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(unknown.cose_sign1_hex),
      anchors: anchorsFrom(unknown.anchors_hex),
      nowUnix: unknown.verify_at_unix,
    });
    expect(result.outcome).toBe('UNVERIFIED_UNKNOWN_ISSUER');
    expect(result.subStates.signatureValid).toBe(true);
    expect(result.subStates.keyAuthorized).toBe(false);
  });
});

describe('arithmetic (conformance A11/A12)', () => {
  const arithmetic = loadVector<ArithmeticVector>(vectorPaths.arithmeticValid);

  it('declares integer-only round-half-away-from-zero', () => {
    expect(arithmetic.rounding_mode).toContain('round-half-away-from-zero');
  });

  it.each([
    [1n, 1n, 1n],
    [5n, 2n, 3n],
    [-5n, 2n, -3n],
    [1n, 2n, 1n],
    [3n, 2n, 2n],
  ])('round_half_away(%s, %s) = %s', (numerator, denominator, expected) => {
    expect(roundHalfAwayFromZero(numerator, denominator)).toBe(expected);
  });

  it('computes each frozen quantity exactly, without a float path', () => {
    expect(computeLineAmountMinor(360, {scale: 2, value: 75})).toBe(270);
    expect(computeLineAmountMinor(1, {scale: 3, value: 1005})).toBe(1);
    expect(computeLineAmountMinor(3, {scale: 1, value: 5})).toBe(2);
    expect(computeLineAmountMinor(7, {scale: 2, value: 25})).toBe(2);
  });

  it('rejects an over-large product before dividing', () => {
    expect(() => computeLineAmountMinor(1_000_000_000_000, {scale: 0, value: 1_000_000})).toThrow(ProtocolError);
  });

  it('signs and verifies each frozen arithmetic fixture', async () => {
    const baseline = loadReceiptInvalid().cases[0];
    for (const testCase of arithmetic.cases) {
      const result = await verifyReceipt({
        coseSign1Bytes: hexDecode(testCase.cose_sign1_hex),
        anchors: anchorsFrom(baseline.anchors_hex),
        nowUnix: baseline.verify_at_unix,
      });
      expect({case: testCase.case, outcome: result.outcome, error: result.error?.name ?? null}).toEqual({
        case: testCase.case,
        outcome: testCase.expected_verification.outcome,
        error: testCase.expected_verification.error,
      });
    }
  });
});

describe('credential verification (conformance B1–B6)', () => {
  const cases = loadCredentials().cases;

  it.each(cases.map(testCase => [testCase.case, testCase]))('%s', async (_name, testCase) => {
    const check = await verifyCredential(
      hexDecode(testCase.credential_hex),
      anchorsFrom(testCase.anchors_hex),
      testCase.verify_at_unix,
    );
    expect(check.error).toBe(testCase.expected_error);
    expect(check.trust).toBe(testCase.expected_trust);
  });
});
