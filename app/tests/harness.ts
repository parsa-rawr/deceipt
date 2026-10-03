/**
 * Shared test utilities: build a merchant/customer pair against the frozen
 * vectors, with no hardware.
 *
 * Every fixture here comes from `protocol/vectors/**` or
 * `protocol/flows/vectors/**`; nothing is derived from the implementation
 * under test (conformance.md §F).
 */

import {base64Encode, bytesEqual, hexDecode, hexEncode} from '../src/protocol/bytes';
import {TRUST_ANCHORS} from '../src/config/trustAnchors';
import {InMemoryDeceiptNative, linkMockPeers, type MockMerchantProvision, type MockRadio} from '../src/native/mock/InMemoryDeceiptNative';
import {MemoryKeyValueStore, ReceiptStore} from '../src/storage/receiptStore';
import type {TrustAnchor} from '../src/native/DeceiptNative';
import {loadReceiptValid, loadTestKeys, loadTrustAnchors, loadBytes, vectorPaths} from './fixtures';

/** The pre-provisioned test merchant material (trust.md §3). */
export async function testMerchantProvision(): Promise<MockMerchantProvision> {
  const merchantKey = loadTestKeys().keys.find(key => key.name === 'merchant-test-1');
  if (merchantKey === undefined || merchantKey.private_seed_hex === undefined) {
    throw new Error('merchant-test-1 is missing from the test key vector');
  }
  return {
    deviceSeed: hexDecode(merchantKey.private_seed_hex),
    deviceKeyId: hexDecode('0f1e2d3c4b5a69788796a5b4c3d2e1f0'),
    credentialBytes: loadBytes(vectorPaths.validCredential),
    merchantId: hexDecode('a1b2c3d4e5f60718293a4b5c6d7e8f90'),
    devicePublicKey: hexDecode(merchantKey.public_key_hex),
  };
}

/** The pinned anchors from the frozen vector, as the bridge consumes them. */
export function frozenAnchors(): TrustAnchor[] {
  return loadTrustAnchors().anchors.map(anchor => ({
    anchorIdHex: anchor.anchor_id_hex,
    publicKeyB64: base64Encode(hexDecode(anchor.public_key_hex)),
    label: anchor.label,
  }));
}

/** Assert the shipped anchor constant matches the frozen vector. */
export function assertShippedAnchorsMatchVector(): void {
  const frozen = frozenAnchors();
  if (frozen.length !== TRUST_ANCHORS.length) {
    throw new Error('shipped anchor count differs from the frozen vector');
  }
  for (const anchor of TRUST_ANCHORS) {
    const match = frozen.find(candidate => candidate.anchorIdHex === anchor.anchorIdHex);
    if (match === undefined) {
      throw new Error(`shipped anchor ${anchor.anchorIdHex} is not in the frozen vector`);
    }
    if (match.publicKeyB64 !== anchor.publicKeyB64) {
      throw new Error(`shipped anchor ${anchor.anchorIdHex} key differs from the frozen vector`);
    }
  }
}

/** The exact valid baseline receipt bytes from `receipt-valid.json`. */
export function baselineReceiptBytes(): Uint8Array {
  return hexDecode(loadReceiptValid().cose_sign1_hex);
}

export interface MockPair {
  merchant: InMemoryDeceiptNative;
  customer: InMemoryDeceiptNative;
  merchantStore: ReceiptStore;
  customerStore: ReceiptStore;
  provision: MockMerchantProvision;
}

/** The frozen verification instant used by `receipt-valid.json`. */
export const VECTOR_NOW_UNIX = 1767225600;

export async function buildMockPair(radio: MockRadio | null = null, nowUnix = VECTOR_NOW_UNIX): Promise<MockPair> {
  const provision = await testMerchantProvision();
  const clock = () => nowUnix;
  const merchant = new InMemoryDeceiptNative({platform: 'ios', provision, now: clock});
  const customer = new InMemoryDeceiptNative({platform: 'android', now: clock});
  customer.setAnchors(frozenAnchors());
  linkMockPeers(merchant, customer, radio);
  const storeFor = (): ReceiptStore => new ReceiptStore(new MemoryKeyValueStore());
  return {merchant, customer, merchantStore: storeFor(), customerStore: storeFor(), provision};
}

/** Hex equality assertion helper with a readable failure. */
export function expectBytesEqual(actual: Uint8Array, expectedHex: string, label: string): void {
  const expected = hexDecode(expectedHex);
  if (!bytesEqual(actual, expected)) {
    throw new Error(`${label}: expected ${expectedHex}, got ${hexEncode(actual)}`);
  }
}
