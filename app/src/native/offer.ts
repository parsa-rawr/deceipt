/**
 * Offer-hash helpers shared by the app and the mock adapter.
 *
 * The offer fields are the exact A2 members (`RECEIPT_OFFER` labels 3,4,5,6,7,10
 * plus `transfer_id`/`session_id`), and `offerHash` is recomputed from them so
 * the QR, the offer and the receipt cannot disagree (framing.md §7).
 */

import {hexDecode, hexEncode, base64Decode} from '../protocol/bytes';
import {computeOfferHash, encodeBindingTuple, computeBindingTupleDigest, type OfferFields} from '../protocol/binding';
import {parseCoseSign1} from '../protocol/handshake';
import {parseReceiptPayload} from '../protocol/receipt';
import type {OfferMetadata} from './DeceiptNative';

export interface OfferIdentity {
  merchantReference: string;
  totalAmountMinor: number;
  currency: string;
  issuedAt: number;
  kind: 1 | 2 | 3;
}

/** Read the offer identity fields directly out of the exact signed bytes. */
export function buildReceiptOfferFromReceipt(coseSign1Bytes: Uint8Array): OfferIdentity {
  const parsed = parseReceiptPayload(parseCoseSign1(coseSign1Bytes).payload);
  return {
    merchantReference: parsed.receipt.merchant.merchantReference,
    totalAmountMinor: parsed.receipt.totals.totalMinor,
    currency: parsed.receipt.currency,
    issuedAt: parsed.receipt.issuedAt,
    kind: parsed.receipt.kind,
  };
}

export interface BindingValues {
  offerHashHex: string;
  bindingTupleHex: string;
  bindingTupleDigestHex: string;
}

/** The three A2 binding values every party must agree on for one checkout. */
export async function computeBindingValues(input: {
  sessionIdHex: string;
  transferIdHex: string;
  receiptIdHex: string;
  merchantReference: string;
  totalAmountMinor: number;
  currency: string;
  issuedAtUnix: number;
}): Promise<BindingValues> {
  const fields: OfferFields = {
    sessionId: hexDecode(input.sessionIdHex),
    transferId: hexDecode(input.transferIdHex),
    receiptId: hexDecode(input.receiptIdHex),
    merchantReference: input.merchantReference,
    totalAmountMinor: input.totalAmountMinor,
    currency: input.currency,
    issuedAtUnix: input.issuedAtUnix,
  };
  const offerHash = await computeOfferHash(fields);
  const tuple = encodeBindingTuple({...fields, offerHash});
  const digest = await computeBindingTupleDigest(tuple);
  return {
    offerHashHex: hexEncode(offerHash),
    bindingTupleHex: hexEncode(tuple),
    bindingTupleDigestHex: hexEncode(digest),
  };
}

/** Recompute an offer's `offer_hash` from its own fields (framing.md §7). */
export async function offerHashFromOfferMetadata(offer: OfferMetadata): Promise<string> {
  const fields: OfferFields = {
    sessionId: hexDecode(offer.sessionIdHex),
    transferId: hexDecode(offer.transferIdHex),
    receiptId: hexDecode(offer.receiptIdHex),
    merchantReference: offer.merchantReference,
    totalAmountMinor: offer.totalAmountMinor,
    currency: offer.currency,
    issuedAtUnix: offer.issuedAt,
  };
  return hexEncode(await computeOfferHash(fields));
}

export function decodeCosePayload(coseSign1B64: string): Uint8Array {
  return parseCoseSign1(base64Decode(coseSign1B64)).payload;
}
