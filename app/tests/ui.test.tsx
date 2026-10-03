/**
 * UI tests: the accessibility contract the operator drives through, the
 * merchant→customer handoff as the screens actually perform it, and the copy
 * rules of docs/flows/transaction-binding-and-checkout-v1.md §8.
 */

import React from 'react';
import {create, act} from 'react-test-renderer';
import {AppContent} from '../src/App';
import {MerchantScreen} from '../src/ui/MerchantScreen';
import {CustomerScreen} from '../src/ui/CustomerScreen';
import {formatMoney, verificationStatusCopy} from '../src/ui/primitives';
import {MemoryKeyValueStore, ReceiptStore} from '../src/storage/receiptStore';
import {prepareMerchantOffer, startMerchantServing} from '../src/checkout/merchantFlow';
import {InMemoryDeceiptNative} from '../src/native/mock/InMemoryDeceiptNative';
import {buildDemoReceipt} from '../src/demo/demoReceipt';
import {parseBindingQr} from '../src/protocol/binding';
import {OUTCOMES} from '../src/protocol/errors';
import {buildMockPair, frozenAnchors, VECTOR_NOW_UNIX} from './harness';

const NOW = VECTOR_NOW_UNIX;
const DEMO_MERCHANT_NAME = 'Maple & Vine Cafe';

type Tree = ReturnType<typeof create>;

/**
 * React 19's test renderer must be mounted inside `act`, and the tree is only
 * addressable while it stays mounted; both helpers below are called from test
 * bodies that keep the returned tree alive.
 */
function render(element: React.ReactElement): Tree {
  let tree!: Tree;
  act(() => {
    tree = create(element);
  });
  return tree;
}

function byId(root: Tree, testID: string) {
  return root.root.findByProps({testID});
}

/** Flatten a subtree's text so a test can assert on rendered copy. */
function collectText(node: {children: unknown[]}): string {
  const parts: string[] = [];
  const walk = (value: unknown): void => {
    if (typeof value === 'string') {
      parts.push(value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(walk);
      return;
    }
    if (typeof value === 'object' && value !== null && 'children' in value) {
      walk((value as {children: unknown[]}).children);
    }
  };
  walk(node.children);
  return parts.join(' ');
}

/** Let the component's promises and the mock's microtask batching resolve. */
async function settle(times = 6): Promise<void> {
  for (let index = 0; index < times; index += 1) {
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 5));
    });
  }
}

describe('app shell', () => {
  it('offers both modes behind stable accessibility handles', () => {
    const root = render(<AppContent store={new ReceiptStore(new MemoryKeyValueStore())} now={() => NOW} />);
    expect(byId(root, 'app-root')).toBeTruthy();
    expect(byId(root, 'mode-merchant')).toBeTruthy();
    expect(byId(root, 'mode-customer')).toBeTruthy();
  });

  it('names the adapter in use rather than choosing silently', () => {
    const root = render(<AppContent store={new ReceiptStore(new MemoryKeyValueStore())} now={() => NOW} />);
    // Jest registers no native module, so the mock stands in and says so.
    const adapterText = collectText(byId(root, 'adapter-card'));
    expect(adapterText).toContain('Mock adapter');
  });

  it('switches into customer mode and back', async () => {
    const root = render(<AppContent store={new ReceiptStore(new MemoryKeyValueStore())} now={() => NOW} />);
    await act(async () => {
      byId(root, 'mode-customer').props.onPress();
    });
    expect(byId(root, 'customer-screen')).toBeTruthy();
    await act(async () => {
      byId(root, 'back-to-menu').props.onPress();
    });
    expect(byId(root, 'mode-merchant')).toBeTruthy();
  });
});

describe('merchant screen', () => {
  it('renders the checkout code as selectable text', async () => {
    const pair = await buildMockPair();
    const root = render(<MerchantScreen native={pair.merchant} now={() => NOW} />);
    await act(async () => {
      await byId(root, 'prepare-checkout').props.onPress();
    });
    await settle();
    const payload = byId(root, 'qr-payload-text');
    expect(payload.props.selectable).toBe(true);
    expect(payload.props.children as string).toMatch(/^deceipt1:/);
  });

  it('reports a missing signing key instead of pretending to serve', async () => {
    const bare = new InMemoryDeceiptNative({platform: 'ios'});
    const root = render(<MerchantScreen native={bare} now={() => NOW} />);
    await settle(2);
    expect(byId(root, 'merchant-key-missing')).toBeTruthy();
  });
});

describe('customer screen drive', () => {
  it('shows the offer read from the merchant code, then verifies and stores it', async () => {
    const pair = await buildMockPair();
    const store = new ReceiptStore(new MemoryKeyValueStore());

    // Merchant side: prepare and advertise through the same helpers the screen
    // uses, so the handoff exercised here is the real one.
    const receipt = buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    const serving = await startMerchantServing(pair.merchant, prepared);

    const root = render(
      <CustomerScreen native={pair.customer} store={store} anchors={frozenAnchors()} now={() => NOW} />,
    );
    await settle(2);

    await act(async () => {
      byId(root, 'qr-payload-input').props.onChangeText(prepared.qr.qrPayload);
    });
    await act(async () => {
      await byId(root, 'scan-qr').props.onPress();
    });
    await settle(10);

    expect(byId(root, 'offer-card')).toBeTruthy();
    const offerText = collectText(byId(root, 'offer-card'));
    // Before verification only the merchant's own claim is shown: its reference.
    // The display name arrives with the credential, i.e. after verification.
    expect(offerText).toContain('merchant.poc.test-alpha');
    expect(offerText).toContain('CAD 9.70');

    await act(async () => {
      await byId(root, 'accept-offer').props.onPress();
    });
    await act(async () => {
      await pair.merchant.beginTransfer(serving.sessionHandle);
    });
    await settle(12);

    expect(byId(root, 'receipt-result')).toBeTruthy();
    expect(byId(root, 'receipt-status-text').props.children as string).toContain('Verified');
    // The display name is shown once the credential has been verified.
    expect(collectText(byId(root, 'receipt-result'))).toContain(DEMO_MERCHANT_NAME);
    const rows = await store.list();
    expect(rows).toHaveLength(1);
    expect(rows[0].trustLabel).toBe('trusted');
    // The §5.3 sub-states survive into storage, so the UI can render them later.
    expect(rows[0].verification.subStates.signatureValid).toBe(true);
    expect(rows[0].verification.subStates.keyAuthorized).toBe(true);
  });

  it('never trusts a receipt whose signature was tampered in flight', async () => {
    const pair = await buildMockPair({tamperFinalFrameByte: true});
    const store = new ReceiptStore(new MemoryKeyValueStore());
    const receipt = buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    const serving = await startMerchantServing(pair.merchant, prepared);
    const root = render(
      <CustomerScreen native={pair.customer} store={store} anchors={frozenAnchors()} now={() => NOW} />,
    );
    await settle(2);
    await act(async () => {
      byId(root, 'qr-payload-input').props.onChangeText(prepared.qr.qrPayload);
    });
    await act(async () => {
      await byId(root, 'scan-qr').props.onPress();
    });
    await settle(8);
    await act(async () => {
      await byId(root, 'accept-offer').props.onPress();
    });
    await act(async () => {
      await pair.merchant.beginTransfer(serving.sessionHandle);
    });
    await settle(12);

    // No trusted result, and no trusted row.
    expect(() => byId(root, 'receipt-result')).toThrow();
    expect(byId(root, 'checkout-state').props.text).toBe('recoverable_failure');
    for (const row of await store.list()) {
      expect(row.trustLabel).not.toBe('trusted');
    }
  });

  it('surfaces a malformed code as a typed failure, never as a connection', async () => {
    const pair = await buildMockPair();
    const root = render(
      <CustomerScreen native={pair.customer} store={new ReceiptStore(new MemoryKeyValueStore())} anchors={frozenAnchors()} now={() => NOW} />,
    );
    await act(async () => {
      byId(root, 'qr-payload-input').props.onChangeText('deceipt1:not-a-real-code');
    });
    await act(async () => {
      await byId(root, 'scan-qr').props.onPress();
    });
    await settle(4);
    expect(byId(root, 'checkout-state').props.text).toBe('recoverable_failure');
    expect(byId(root, 'checkout-error')).toBeTruthy();
  });
});

describe('customer code round-trips into the selection', () => {
  it('accepts the exact merchant payload as startCustomerSession input', async () => {
    const pair = await buildMockPair();
    const receipt = buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    const parsed = parseBindingQr(prepared.qr.qrPayload);
    expect(parsed.expiresAtUnix).toBe(prepared.qr.expiresAtUnix);
    expect(parsed.offerHash.length).toBe(32);
    expect(prepared.qr.qrPayload).not.toContain(DEMO_MERCHANT_NAME);
    const snapshot = await pair.customer.startCustomerSession({
      selection: {kind: 'qr', qrPayload: prepared.qr.qrPayload},
      anchors: frozenAnchors(),
    });
    expect(snapshot.role).toBe('customer');
    expect(snapshot.sessionHandle.length).toBeGreaterThan(0);
  });
});

describe('copy rules (A2 §8)', () => {
  it('renders three distinct outcomes, never one boolean', () => {
    const trusted = verificationStatusCopy('TRUSTED');
    const unknown = verificationStatusCopy('UNVERIFIED_UNKNOWN_ISSUER');
    const rejected = verificationStatusCopy('REJECTED');
    expect([trusted.label, unknown.label, rejected.label]).toEqual(['verified', 'unverified', 'rejected']);
    expect(unknown.text).not.toContain('Verified');
    expect(unknown.color).not.toBe(trusted.color);
    for (const copy of [trusted, unknown, rejected]) {
      // Transport success is never described as verification.
      expect(copy.text).not.toMatch(/delivered|encrypted|connected/i);
    }
  });

  it('matches the frozen outcome codes', () => {
    expect(OUTCOMES).toEqual({
      TRUSTED: 1,
      UNVERIFIED_UNKNOWN_ISSUER: 2,
      ALREADY_IMPORTED_IDENTICAL: 3,
      REJECTED: 4,
      PENDING: 5,
    });
  });

  it('formats minor units per the currency exponent', () => {
    expect(formatMoney(970, 'CAD')).toBe('CAD 9.70');
    expect(formatMoney(525, 'JPY')).toBe('JPY 525');
    expect(formatMoney(1000, 'KWD')).toBe('KWD 1.000');
    expect(formatMoney(-250, 'USD')).toBe('-USD 2.50');
  });
});
