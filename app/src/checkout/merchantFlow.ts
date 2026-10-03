/**
 * Merchant mode: mint a synthetic receipt, compute the A2 binding bytes, render
 * the QR, and serve the transfer through the bridge.
 *
 * This is the demo path of A2 §7: the merchant signs the receipt ONCE, before
 * any BLE session, over exact canonical bytes; the transfer never re-encodes it.
 */

import {base64Decode, base64Encode, hexEncode} from '../protocol/bytes';
import {secureRandomBytes} from '../protocol/crypto';
import {serializeReceipt, validateReceiptText, type Receipt} from '../protocol/receipt';
import {computeBindingValues, buildReceiptOfferFromReceipt} from '../native/offer';
import {TIMEOUTS_MS} from '../protocol/constants';
import type {DeceiptNative, MerchantKeyStatus, MintBindingQrResponse, SessionHandle, StartMerchantSessionRequest} from '../native/DeceiptNative';
import {ProtocolError} from '../protocol/errors';

export interface SyntheticReceiptOptions {
  merchantReference: string;
  displayName: string;
  merchantId: Uint8Array;
  deviceKeyId: Uint8Array;
  credentialBytes: Uint8Array;
  currency: string;
  lines: Array<{lineId: number; description: string; quantity: {scale: number; value: number; unit?: string}; unitPriceMinor: number; lineAmountMinor: number}>;
  tipAmountMinor?: number;
  nowUnix: number;
}

/** Build a well-formed, arithmetic-consistent sale receipt to sign. */
export function buildSyntheticSale(options: SyntheticReceiptOptions, receiptId: Uint8Array): Receipt {
  if (receiptId.length !== 16) {
    throw new ProtocolError('RECEIPT_SEMANTIC_INVALID', 'a receipt id is 16 bytes');
  }
  const subtotal = options.lines.reduce((sum, line) => sum + line.lineAmountMinor, 0);
  const tip = options.tipAmountMinor ?? 0;
  const taxBase = subtotal;
  const taxRatePpm = 12190;
  const taxAmount = Math.round((taxBase * taxRatePpm) / 1_000_000);
  return {
    receiptVersion: 1,
    kind: 1,
    receiptId,
    issuedAt: options.nowUnix,
    merchant: {
      merchantId: options.merchantId,
      displayName: options.displayName,
      merchantReference: options.merchantReference,
    },
    currency: options.currency,
    lines: options.lines,
    taxes: [
      {
        taxId: 1,
        label: 'GST',
        ratePpm: taxRatePpm,
        baseAmountMinor: taxBase,
        amountMinor: taxAmount,
        jurisdiction: 'CA',
      },
    ],
    tipAmountMinor: tip,
    totals: {
      subtotalMinor: subtotal,
      discountTotalMinor: 0,
      taxTotalMinor: taxAmount,
      totalMinor: subtotal + taxAmount + tip,
      tipMinor: tip,
      taxAddedTotalMinor: taxAmount,
    },
    payment: {
      status: 1,
      amountPaidMinor: subtotal + taxAmount + tip,
      tenders: [{method: 3, amountMinor: subtotal + taxAmount + tip, cardLast4: '4242', brand: 'Visa'}],
    },
    merchantCredential: options.credentialBytes,
  };
}

/**
 * TEMPORARY DIAGNOSTIC. Names the step a merchant preparation is in, so a stall
 * can be attributed to a specific bridged call from a screenshot or a Metro log.
 *
 * This is NOT protocol policy: no contract deadline covers these local
 * operations (the frozen timeouts are session/handshake/transfer deadlines).
 * Remove it, and the `onProgress` parameter, once the stall's cause is fixed.
 */
export type MerchantPrepareStep =
  | 'checking_capabilities'
  | 'provisioning'
  | 'reading_key_status'
  | 'minting_receipt_id'
  | 'signing_receipt'
  | 'deriving_offer'
  | 'minting_qr'
  | 'done';

export interface MerchantPrepareProgress {
  step: MerchantPrepareStep;
  /** Milliseconds since preparation began. */
  elapsedMs: number;
}

export interface PreparedMerchantOffer {
  receipt: Receipt;
  coseSign1B64: string;
  sessionIdHex: string;
  transferIdHex: string;
  receiptIdHex: string;
  offerHashHex: string;
  bindingTupleDigestHex: string;
  qr: MintBindingQrResponse;
  expiresAtUnix: number;
}

/**
 * Prepare one checkout: sign the receipt, derive the binding bytes and mint the
 * QR. The receipt is signed before the session exists (A2 §7 step 6).
 */
export async function prepareMerchantOffer(
  native: DeceiptNative,
  receipt: Receipt,
  nowUnix: number,
  onProgress?: (progress: MerchantPrepareProgress) => void,
): Promise<PreparedMerchantOffer> {
  const startedAt = Date.now();
  const report = (step: MerchantPrepareStep): void => {
    onProgress?.({step, elapsedMs: Date.now() - startedAt});
  };
  // The receipt's text must be fully validated (including NFC through the OS
  // normalizer when needed) BEFORE it is signed: signing attests to bytes the
  // receiver would reject otherwise, and the failure would surface only as a
  // rejected transfer.
  await validateReceiptText(receipt);
  const payload = serializeReceipt(receipt);
  report('signing_receipt');
  const signed = await native.merchantSignReceipt(base64Encode(payload));
  report('deriving_offer');
  const identity = await buildReceiptOfferFromReceipt(base64Decode(signed.coseSign1B64));
  const sessionIdHex = hexEncode(await secureRandomBytes(16));
  const transferIdHex = hexEncode(await secureRandomBytes(16));
  const receiptIdHex = hexEncode(receipt.receiptId);
  const binding = await computeBindingValues({
    sessionIdHex,
    transferIdHex,
    receiptIdHex,
    merchantReference: identity.merchantReference,
    totalAmountMinor: identity.totalAmountMinor,
    currency: identity.currency,
    issuedAtUnix: identity.issuedAt,
  });
  const expiresAtUnix = nowUnix + Math.floor(TIMEOUTS_MS.T_BINDING_QR / 1000);
  report('minting_qr');
  const qr = await native.mintBindingQr({sessionIdHex, offerHashHex: binding.offerHashHex, expiresAtUnix});
  report('done');
  return {
    receipt,
    coseSign1B64: signed.coseSign1B64,
    sessionIdHex,
    transferIdHex,
    receiptIdHex,
    offerHashHex: binding.offerHashHex,
    bindingTupleDigestHex: binding.bindingTupleDigestHex,
    qr,
    expiresAtUnix,
  };
}

/** Start advertising the prepared offer and return the session handle. */
export async function startMerchantServing(
  native: DeceiptNative,
  prepared: PreparedMerchantOffer,
): Promise<{sessionHandle: SessionHandle; snapshot: Awaited<ReturnType<DeceiptNative['startMerchantSession']>>}> {
  const request: StartMerchantSessionRequest = {
    bindingRef: prepared.qr.bindingRef,
    receiptCose1B64: prepared.coseSign1B64,
    transferIdHex: prepared.transferIdHex,
    sessionIdHex: prepared.sessionIdHex,
    receiptIdHex: prepared.receiptIdHex,
    offerHashHex: prepared.offerHashHex,
  };
  const snapshot = await native.startMerchantSession(request);
  return {sessionHandle: snapshot.sessionHandle, snapshot};
}

/** Guard the merchant capability before entering merchant mode. */
export async function assertMerchantReady(native: DeceiptNative): Promise<MerchantKeyStatus> {
  const capabilities = await native.capabilities();
  if (!capabilities.blePeripheral || !capabilities.bleAdvertising) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'this device cannot advertise the Deceipt service');
  }
  if (!capabilities.ed25519) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'this device cannot sign receipts');
  }
  const status = await native.merchantKeyStatus();
  if (!status.provisioned) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'merchant mode needs a provisioned signing key');
  }
  return status;
}
