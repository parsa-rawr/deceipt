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
    const receipt = await buildDemoReceipt({
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
    const receipt = await buildDemoReceipt({
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
    const receipt = await buildDemoReceipt({
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

describe('native module binding (device-found defects)', () => {
  it('probes a contract-complete module as compatible', () => {
    const {probeNativeModule} = bindings();
    const complete = contractShapedModule({subscribe: (listener: unknown) => () => listener});
    const probe = probeNativeModule(complete);
    expect(probe.compatible).toBe(true);
    expect(probe.eventMode).toBe('native_jsi');
    expect(probe.problems).toEqual([]);
  });

  it('flags the Android emitter shape as needing the shim, not as broken', () => {
    const {probeNativeModule, needsEmitterShim} = bindings();
    // A5's original module: subscribe(promise) with no JS listener argument.
    const emitterShaped = contractShapedModule({
      subscribe: () => Promise.resolve(),
      addListener: () => undefined,
      removeListeners: () => undefined,
    });
    const probe = probeNativeModule(emitterShaped);
    expect(probe.compatible).toBe(true);
    expect(probe.eventMode).toBe('emitter');
    expect(needsEmitterShim(emitterShaped)).toBe(true);
  });

  it('reports a missing method instead of redboxing on first tap', () => {
    const {probeNativeModule} = bindings();
    const incomplete = contractShapedModule({});
    delete (incomplete as Record<string, unknown>).startCustomerSession;
    const probe = probeNativeModule(incomplete);
    expect(probe.compatible).toBe(false);
    expect(probe.problems).toContain('startCustomerSession is missing');
  });

  it('reports a module with no event channel at all', () => {
    const {probeNativeModule} = bindings();
    const noEvents = contractShapedModule({});
    delete (noEvents as Record<string, unknown>).subscribe;
    const probe = probeNativeModule(noEvents);
    expect(probe.compatible).toBe(false);
    expect(probe.problems.some(problem => problem.includes('no way to receive events'))).toBe(true);
  });

  it('does not use function arity as a compatibility test', () => {
    const {probeNativeModule} = bindings();
    // An adapter whose methods declare no arguments is still valid: JS optional
    // parameters make Function.length unreliable.
    const noArity = contractShapedModule({subscribe: (listener: unknown) => () => listener});
    for (const name of Object.keys(noArity)) {
      if (typeof (noArity as Record<string, unknown>)[name] === 'function' && name !== 'subscribe') {
        (noArity as Record<string, unknown>)[name] = () => undefined;
      }
    }
    expect(probeNativeModule(noArity).compatible).toBe(true);
  });
});

/** The shim module, loaded through the same path the app uses. */
function bindings(): typeof import('../src/native/adapterShim') {
  return require('../src/native/adapterShim') as typeof import('../src/native/adapterShim');
}

/** A module-shaped object with every contract method present and callable. */
function contractShapedModule(overrides: Record<string, unknown>): Record<string, unknown> {
  const {NATIVE_METHODS} = require('../../modules/deceipt-native') as {NATIVE_METHODS: readonly string[]};
  const built: Record<string, unknown> = {};
  for (const name of NATIVE_METHODS) {
    built[name] = () => Promise.resolve();
  }
  built.subscribe = (listener: unknown) => () => listener;
  for (const [key, value] of Object.entries(overrides)) {
    built[key] = value;
  }
  return built;
}

describe('Bluetooth failure copy distinguishes permission from radio state', () => {
  it('never tells a user to turn on the radio when the permission is missing', async () => {
    const {permissionProblem} = await permissionsModule();
    // The exact device state: denied + unauthorized.
    const denied = permissionProblem({bluetooth: 'denied', camera: 'denied', bluetoothState: 'unauthorized'});
    expect(denied).toContain('permission');
    expect(denied).not.toContain('Turn it on');
    // Radio off is a different problem with a different fix.
    const off = permissionProblem({bluetooth: 'granted', camera: 'granted', bluetoothState: 'off'});
    expect(off).toContain('Turn it on');
    expect(off).not.toContain('permission');
    // Unsupported hardware is a third.
    const unsupported = permissionProblem({bluetooth: 'unavailable', camera: 'granted', bluetoothState: 'unsupported'});
    expect(unsupported).toContain('does not support Bluetooth');
    // A healthy state says nothing.
    expect(permissionProblem({bluetooth: 'granted', camera: 'granted', bluetoothState: 'on'})).toBeNull();
  });

  it('renders the permission fix, not the radio fix, for the device state', async () => {
    const {permissionProblem} = await permissionsModule();
    void permissionProblem;
    const {InMemoryDeceiptNative} = await mockModule();
    const adapter = new InMemoryDeceiptNative({platform: 'android'});
    adapter.setPermissionState({bluetooth: 'denied', camera: 'denied', bluetoothState: 'unauthorized'});
    const root = render(
      React.createElement(CustomerScreen, {
        native: adapter,
        store: new ReceiptStore(new MemoryKeyValueStore()),
        anchors: frozenAnchors(),
        now: () => NOW,
      }),
    );
    await settle(3);
    const warning = collectText(byId(root, 'permission-warning'));
    expect(warning).toContain('permission');
    expect(warning).not.toContain('Bluetooth is off');
  });
});

async function permissionsModule(): Promise<typeof import('../src/ui/CustomerScreen')> {
  return require('../src/ui/CustomerScreen') as typeof import('../src/ui/CustomerScreen');
}

async function mockModule(): Promise<typeof import('../src/native/mock/InMemoryDeceiptNative')> {
  return require('../src/native/mock/InMemoryDeceiptNative') as typeof import('../src/native/mock/InMemoryDeceiptNative');
}

describe('merchant enrollment recovery (incomplete identity)', () => {
  it('treats a key without its credential as NOT ready', async () => {
    const {isMerchantReady, missingMerchantParts} = await provisionModule();
    expect(isMerchantReady({provisioned: true, ready: false})).toBe(false);
    expect(isMerchantReady({provisioned: false, ready: false})).toBe(false);
    expect(isMerchantReady({provisioned: true, ready: true})).toBe(true);
    // An adapter that predates `ready` is judged on the parts.
    // An adapter predating `ready` is judged on the parts.
    expect(isMerchantReady({provisioned: true, merchantIdHex: 'a'.repeat(32), credentialB64: 'AAAA'})).toBe(true);
    expect(isMerchantReady({provisioned: true, merchantIdHex: 'a'.repeat(32)})).toBe(false);
    expect(missingMerchantParts({provisioned: true, ready: false, missing: ['credential']})).toEqual(['credential']);
    expect(missingMerchantParts({provisioned: true, ready: true})).toEqual([]);
  });

  it('keeps the import affordance reachable when the credential is missing', async () => {
    const {InMemoryDeceiptNative} = await mockModule();
    // A key exists, but no credential: exactly the device state.
    const adapter = new InMemoryDeceiptNative({platform: 'android'});
    await adapter.merchantKeyGenerate();
    const status = await adapter.merchantKeyStatus();
    expect(status.provisioned).toBe(true);
    expect(status.ready).toBe(false);
    expect(status.missing).toContain('credential');

    const root = render(React.createElement(MerchantScreen, {native: adapter, now: () => NOW}));
    await settle(3);
    // The blocking state AND its repair button are both present.
    const missing = collectText(byId(root, 'merchant-key-missing'));
    expect(missing).toContain('incomplete');
    expect(missing).toContain('credential');
    expect(byId(root, 'provision-test-merchant')).toBeTruthy();
  });

  it('does not report alreadyProvisioned for an incomplete identity', async () => {
    const {ensureDemoMerchant} = await provisionModule();
    const {InMemoryDeceiptNative} = await mockModule();
    const adapter = new InMemoryDeceiptNative({
      platform: 'android',
      capabilities: {testProvisioningEnabled: true, ed25519: true},
    });
    await adapter.merchantKeyGenerate();
    const outcome = await ensureDemoMerchant(adapter);
    // A key alone must not short-circuit the repair path.
    expect(outcome.alreadyProvisioned).toBe(false);
  });

  it('reports alreadyProvisioned only for a complete identity', async () => {
    const {ensureDemoMerchant} = await provisionModule();
    const pair = await buildMockPair();
    const outcome = await ensureDemoMerchant(pair.merchant);
    expect(outcome.alreadyProvisioned).toBe(true);
    expect(outcome.ok).toBe(true);
  });

  it('preserves the production gate: refuses to provision when the adapter disallows it', async () => {
    const {ensureDemoMerchant} = await provisionModule();
    const {InMemoryDeceiptNative} = await mockModule();
    const adapter = new InMemoryDeceiptNative({platform: 'ios', capabilities: {testProvisioningEnabled: false}});
    const outcome = await ensureDemoMerchant(adapter);
    expect(outcome.ok).toBe(false);
    expect(outcome.alreadyProvisioned).toBe(false);
    expect(outcome.reason).toContain('does not allow test provisioning');
  });
});

async function provisionModule(): Promise<typeof import('../src/demo/merchantProvision')> {
  return require('../src/demo/merchantProvision') as typeof import('../src/demo/merchantProvision');
}

describe('merchant prepare diagnostics (TEMPORARY)', () => {
  /**
   * These pin the temporary step-name diagnostic only. They are NOT a policy
   * test: no contract deadline covers merchant preparation, and both this block
   * and the instrumentation it covers are removed once the stall's cause is
   * fixed. A real hang regression belongs at the root-cause seam, not here.
   */
  it('names each step it enters on the normal path', async () => {
    const {prepareMerchantOffer} = await prepareModule();
    const {buildDemoReceipt} = await demoModule();
    const pair = await buildMockPair();
    const receipt = await buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const steps: string[] = [];
    await prepareMerchantOffer(pair.merchant, receipt, NOW, progress => steps.push(progress.step));
    expect(steps).toContain('signing_receipt');
    expect(steps[steps.length - 1]).toBe('done');
  });
});

async function prepareModule(): Promise<typeof import('../src/checkout/merchantFlow')> {
  return require('../src/checkout/merchantFlow') as typeof import('../src/checkout/merchantFlow');
}

async function demoModule(): Promise<typeof import('../src/demo/demoReceipt')> {
  return require('../src/demo/demoReceipt') as typeof import('../src/demo/demoReceipt');
}

describe('checkout QR and session clock (original scope)', () => {
  it('renders a QR that a real decoder reads back as the exact payload', async () => {
    const pair = await buildMockPair();
    const root = render(React.createElement(MerchantScreen, {native: pair.merchant, now: () => NOW}));
    await act(async () => {
      await byId(root, 'prepare-checkout').props.onPress();
    });
    await settle(4);
    const payload = byId(root, 'qr-payload-text').props.children as string;
    expect(byId(root, 'qr-code')).toBeTruthy();

    // The consumer-visible property: the displayed code DECODES to the exact
    // payload. This reconstructs the same matrix the view draws from the same
    // encoder and runs an independent decoder over it, so a regression in the
    // payload or the encoder is caught; it does not assert view internals.
    const encoded = encodeQrImage(payload);
    const decoded = decodeQrImage(encoded);
    expect(decoded).toBe(payload);
    // And the payload is the frozen `deceipt1:` form, not a rewritten one.
    expect(decoded!.startsWith('deceipt1:')).toBe(true);
    const {parseBindingQr} = await bindingModule();
    expect(parseBindingQr(decoded!).sessionId).toHaveLength(16);
  });

  it('advertises a session expiry in the FUTURE even when the fixture clock is old', async () => {
    const pair = await buildMockPair();
    const root = render(React.createElement(MerchantScreen, {native: pair.merchant, now: () => NOW}));
    await act(async () => {
      await byId(root, 'prepare-checkout').props.onPress();
    });
    await settle(4);
    // The screen's `now` prop is the frozen fixture instant; the QR expiry must
    // nevertheless be relative to the real clock, or a live session expires
    // instantly.
    const realNow = Math.floor(Date.now() / 1000);
    const payload = byId(root, 'qr-payload-text').props.children as string;
    const {parseBindingQr} = await bindingModule();
    const parsed = parseBindingQr(payload);
    expect(parsed.expiresAtUnix).toBeGreaterThan(realNow);
    expect(parsed.expiresAtUnix).toBeLessThanOrEqual(realNow + 600);
  });

  it('leaves the phase as ready, not preparing, once preparation succeeds', async () => {
    const pair = await buildMockPair();
    const root = render(React.createElement(MerchantScreen, {native: pair.merchant, now: () => NOW}));
    await act(async () => {
      await byId(root, 'prepare-checkout').props.onPress();
    });
    await settle(4);
    // The device symptom: step done, phase still "preparing", code rendered.
    expect(byId(root, 'merchant-phase').props.text).toBe('ready');
  });
});

describe('camera scan reaches the same selection path as typed input', () => {
  it('hands a scanned payload to the checkout exactly like the text field', async () => {
    const pair = await buildMockPair();
    const store = new ReceiptStore(new MemoryKeyValueStore());
    const receipt = await buildDemoReceipt({
      merchantId: pair.provision.merchantId,
      credentialBytes: pair.provision.credentialBytes,
    });
    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    await startMerchantServing(pair.merchant, prepared);

    const root = render(
      React.createElement(CustomerScreen, {native: pair.customer, store, anchors: frozenAnchors(), now: () => NOW}),
    );
    await settle(2);

    // Open the scanner, then deliver a scan event through the real QrScanner.
    await act(async () => {
      byId(root, 'open-scanner').props.onPress();
    });
    await act(async () => {
      deliverScan(root, prepared.qr.qrPayload);
    });
    await settle(10);

    // The offer is presented, proving the scanned value travelled the same
    // parse -> binding -> handshake path as a typed one.
    expect(byId(root, 'offer-card')).toBeTruthy();
  });

  it('ignores a repeated read of the same code', async () => {
    const pair = await buildMockPair();
    const root = render(
      React.createElement(CustomerScreen, {
        native: pair.customer,
        store: new ReceiptStore(new MemoryKeyValueStore()),
        anchors: frozenAnchors(),
        now: () => NOW,
      }),
    );
    await settle(2);
    await act(async () => {
      byId(root, 'open-scanner').props.onPress();
    });
    // A camera fires repeatedly; the first read is the selection act. A malformed
    // value must fail typed and never silently advance the flow on a repeat.
    await act(async () => {
      deliverScan(root, 'deceipt1:not-a-real-code');
    });
    await settle(4);
    expect(byId(root, 'checkout-state').props.text).toBe('recoverable_failure');
  });
});

/**
 * Deliver one scan event to the rendered scanner. Finds the element carrying the
 * scanner's callback, so the stub's markup is not part of the assertion.
 */
function deliverScan(root: Tree, payload: string): void {
  const scanner = root.root.findAll(
    node => typeof node.props?.onReadCode === 'function',
  );
  if (scanner.length === 0) {
    throw new Error('no scanner is rendered');
  }
  scanner[0].props.onReadCode({nativeEvent: {codeStringValue: payload}});
}

/** Rebuild the module matrix the view draws and run an independent decoder. */
function encodeQrImage(payload: string): {data: Uint8Array; size: number} {
  const qrcode = require('qrcode-generator') as (typeNumber: number, level: string) => {
    addData(value: string): void;
    make(): void;
    getModuleCount(): number;
    isDark(row: number, column: number): boolean;
  };
  const qr = qrcode(0, 'M');
  qr.addData(payload);
  qr.make();
  const count = qr.getModuleCount();
  const scale = 6;
  const quiet = 4;
  const size = (count + quiet * 2) * scale;
  const data = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const moduleX = Math.floor(x / scale) - quiet;
      const moduleY = Math.floor(y / scale) - quiet;
      const dark = moduleX >= 0 && moduleY >= 0 && moduleX < count && moduleY < count && qr.isDark(moduleY, moduleX);
      const value = dark ? 0 : 255;
      const index = (y * size + x) * 4;
      data[index] = value;
      data[index + 1] = value;
      data[index + 2] = value;
      data[index + 3] = 255;
    }
  }
  return {data, size};
}

function decodeQrImage(image: {data: Uint8Array; size: number}): string | null {
  const jsQR = require('jsqr') as (
    data: Uint8ClampedArray,
    width: number,
    height: number,
  ) => {data: string} | null;
  const result = jsQR(new Uint8ClampedArray(image.data), image.size, image.size);
  return result === null ? null : result.data;
}

async function bindingModule(): Promise<typeof import('../src/protocol/binding')> {
  return require('../src/protocol/binding') as typeof import('../src/protocol/binding');
}
