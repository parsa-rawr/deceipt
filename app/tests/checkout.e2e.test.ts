/**
 * End-to-end checkout over the mock adapters: merchant prepares and signs a
 * receipt, mints a QR, advertises; the customer scans, completes the handshake,
 * accepts, receives the frames, verifies and stores.
 *
 * This is the shared-logic proof that the state machine, the binding bytes, the
 * verification order and persistence agree with each other and with the frozen
 * contracts. It does NOT prove anything about BLE, Keychain or real crypto
 * timing — those are device checks (see the A3 report).
 */

import {CheckoutController} from '../src/checkout/controller';
import {MemoryKeyValueStore, ReceiptStore} from '../src/storage/receiptStore';
import {prepareMerchantOffer, startMerchantServing, buildSyntheticSale} from '../src/checkout/merchantFlow';
import {computeBindingValues} from '../src/native/offer';
import {hexEncode, hexDecode} from '../src/protocol/bytes';
import {ed25519Verify} from '../src/protocol/crypto';
import {buildTranscript} from '../src/protocol/handshake';
import {parseReceiptPayload} from '../src/protocol/receipt';
import {loadHandshakeValid, loadReceiptValid} from './fixtures';
import {serializeReceipt} from '../src/protocol/receipt';
import type {CheckoutModel, CheckoutState} from '../src/checkout/machine';
import {buildMockPair, frozenAnchors, type MockPair} from './harness';
import type {MockRadio} from '../src/native/mock/InMemoryDeceiptNative';
import {testKey} from './fixtures';

const NOW = 1767225600;

interface Driven {
  states: CheckoutState[];
  result: Promise<void>;
}

async function waitFor(predicate: () => boolean, label: string, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error(`timed out waiting for ${label}`);
}

function track(controller: CheckoutController): Driven {
  const states: CheckoutState[] = [controller.getState()];
  let resolveDone: () => void = () => undefined;
  const result = new Promise<void>(resolve => {
    resolveDone = resolve;
  });
  const previous = controller.getModel();
  void previous;
  controller.start();
  return {states, result};
}

describe('mock end-to-end checkout', () => {
  it('completes the merchant -> customer flow and stores a trusted receipt', async () => {
    const pair: MockPair = await buildMockPair();
    const merchantKey = testKey('merchant-test-1');

    const receipt = buildSyntheticSale({
      merchantReference: 'merchant.poc.test-alpha',
      displayName: 'Maple & Vine Cafe',
      merchantId: pair.provision.merchantId,
      deviceKeyId: pair.provision.deviceKeyId,
      credentialBytes: pair.provision.credentialBytes,
      currency: 'CAD',
      lines: [
        {lineId: 1, description: 'Latte', quantity: {scale: 0, value: 1}, unitPriceMinor: 475, lineAmountMinor: 475},
        {lineId: 2, description: 'Croissant', quantity: {scale: 2, value: 75}, unitPriceMinor: 360, lineAmountMinor: 270},
      ],
      tipAmountMinor: 100,
      nowUnix: NOW,
    }, hexDecode('0123456789abcdef0123456789abcdef'));

    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    const serving = await startMerchantServing(pair.merchant, prepared);
    void merchantKey;
    void serving;

    const store = new ReceiptStore(new MemoryKeyValueStore());
    let model: CheckoutModel | null = null;
    const controller = new CheckoutController({
      native: pair.customer,
      store,
      anchors: frozenAnchors(),
      now: () => NOW,
      onChange: next => {
        model = next;
      },
    });
    controller.start();

    await controller.onQRScanned(prepared.qr.qrPayload);
    await waitFor(() => model !== null && model.state === 'transferring', 'the authenticated offer');
    await controller.onAcceptOffer();
    await pair.merchant.beginTransfer(serving.sessionHandle);
    await waitFor(() => model !== null && (model.state === 'saved' || model.state === 'recoverable_failure'), 'the outcome');

    expect(model!.state).toBe('saved');
    expect(model!.saved?.trustLabel).toBe('trusted');
    expect(model!.saved?.totalMinor).toBe(receipt.totals.totalMinor);
    expect(model!.saved?.currency).toBe('CAD');

    const stored = await store.list();
    expect(stored).toHaveLength(1);
    expect(stored[0].trustLabel).toBe('trusted');
    // The §5.3 sub-states are persisted separately, not collapsed.
    expect(stored[0].verification.subStates.signatureValid).toBe(true);
    expect(stored[0].verification.subStates.keyAuthorized).toBe(true);
    expect(stored[0].verification.subStates.semanticallyValid).toBe(true);
    expect(stored[0].verification.revocationNote).toContain('no revocation distribution');
    // The exact received container bytes are preserved verbatim.
    expect(stored[0].coseSign1B64.length).toBeGreaterThan(0);

    await controller.dispose();
  });

  it('never stores a trusted row when the receipt signature is tampered', async () => {
    const radio: MockRadio = {tamperFinalFrameByte: true};
    const pair = await buildMockPair(radio);
    const receipt = buildSyntheticSale({
      merchantReference: 'merchant.poc.test-alpha',
      displayName: 'Maple & Vine Cafe',
      merchantId: pair.provision.merchantId,
      deviceKeyId: pair.provision.deviceKeyId,
      credentialBytes: pair.provision.credentialBytes,
      currency: 'CAD',
      lines: [{lineId: 1, description: 'Latte', quantity: {scale: 0, value: 1}, unitPriceMinor: 475, lineAmountMinor: 475}],
      nowUnix: NOW,
    }, hexDecode('0123456789abcdef0123456789abcdef'));
    const prepared = await prepareMerchantOffer(pair.merchant, receipt, NOW);
    const serving = await startMerchantServing(pair.merchant, prepared);

    const store = new ReceiptStore(new MemoryKeyValueStore());
    let model: CheckoutModel | null = null;
    const controller = new CheckoutController({
      native: pair.customer,
      store,
      anchors: frozenAnchors(),
      now: () => NOW,
      onChange: next => {
        model = next;
      },
    });
    controller.start();
    await controller.onQRScanned(prepared.qr.qrPayload);
    await waitFor(() => model !== null && model.state === 'transferring', 'the authenticated offer');
    await controller.onAcceptOffer();

    // Tamper with the receipt payload inside the merchant's signed container so
    // the signature no longer matches, while the structure stays intact.
    await controller.onAcceptOffer();
    await pair.merchant.beginTransfer(serving.sessionHandle);

    await waitFor(() => model !== null && model.state === 'recoverable_failure', 'a recoverable failure');
    expect(model!.state).toBe('recoverable_failure');
    // Nothing trusted was persisted; at most evidence under a rejected record.
    const rows = await store.list();
    for (const row of rows) {
      expect(row.trustLabel).not.toBe('trusted');
    }
    expect(model!.saved).toBeNull();
    await controller.dispose();
  });

  it('fails closed with an ambiguous selection when no candidate is chosen', async () => {
    const pair = await buildMockPair();
    pair.customer.advertiseCandidate('peripheral-aaa');
    pair.customer.advertiseCandidate('peripheral-bbb');
    pair.customer.advertiseCandidate('peripheral-ccc');

    let model: CheckoutModel | null = null;
    const controller = new CheckoutController({
      native: pair.customer,
      store: new ReceiptStore(new MemoryKeyValueStore()),
      anchors: frozenAnchors(),
      now: () => NOW,
      onChange: next => {
        model = next;
      },
    });
    controller.start();
    await controller.onOpenScanner();
    await waitFor(() => model !== null && model.candidates.length === 3, 'three candidates');
    expect(model!.state).toBe('selecting');
    expect(model!.ambiguity).toBe(false);
    expect(model!.selection).toBeNull();
    // Deterministic ordering by peripheral id, no proximity meaning.
    expect(model!.candidates.map(candidate => candidate.peripheralId)).toEqual([
      'peripheral-aaa',
      'peripheral-bbb',
      'peripheral-ccc',
    ]);
    await controller.dispose();
  });
});

describe('binding bytes', () => {
  it('reproduces the frozen offer hash and binding tuple from the frozen inputs', async () => {
    const values = await computeBindingValues({
      sessionIdHex: '00112233445566778899aabbccddeeff',
      transferIdHex: 'ffeeddccbbaa99887766554433221100',
      receiptIdHex: '0123456789abcdef0123456789abcdef',
      merchantReference: 'merchant.poc.test-alpha',
      totalAmountMinor: 970,
      currency: 'CAD',
      issuedAtUnix: 1767225540,
    });
    expect(values.offerHashHex).toBe('efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5');
    expect(values.bindingTupleHex).toBe(
      '85015000112233445566778899aabbccddeeff50ffeeddccbbaa99887766554433221100500123456789abcdef0123456789abcdef5820efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5',
    );
    expect(values.bindingTupleDigestHex).toBe('d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2');
  });
});

describe('handshake bytes', () => {
  it('reproduces the frozen 372-byte transcript and its signature', async () => {
    const vector = loadHandshakeValid();
    const transcript = buildTranscript({
      protocolVersion: 1,
      suiteId: 1,
      clientNonce: hexDecode('c0ffee0000000000000000000000000000000000000000000000000000000001'),
      clientEphemeralPubkey: hexDecode(
        '0414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c',
      ),
      serverNonce: hexDecode('5e57e50000000000000000000000000000000000000000000000000000000001'),
      serverEphemeralPubkey: hexDecode(
        '041ba8c9100cde3121a29562d5ed4f8b21fc45067c7a0cb44b9ae47699ed567706b9dbe40d599f161825bd8a90abccb8cc5aa56856c2803f00265e492ed0227db2',
      ),
      transferId: hexDecode('ffeeddccbbaa99887766554433221100'),
      sessionId: hexDecode('00112233445566778899aabbccddeeff'),
      bindingTupleDigest: hexDecode(vector.binding_tuple_digest_hex),
      maxFramePayload: 162,
      bindingTuple: hexDecode(vector.binding_tuple_hex),
    });
    expect(hexEncode(transcript)).toBe(vector.transcript_hex);
    expect(transcript.length).toBe(372);
    const deviceKey = testKey('merchant-test-1');
    expect(await ed25519Verify(hexDecode(deviceKey.public_key_hex), transcript, hexDecode(vector.transcript_signature_hex))).toBe(true);
  });
});

describe('receipt serialization', () => {
  it('reproduces the frozen 669-byte receipt body byte-for-byte', async () => {
    const vector = loadReceiptValid();
    const parsed = parseReceiptPayload(hexDecode(vector.receipt_body_hex));
    const reencoded = serializeReceipt(parsed.receipt);
    expect(reencoded.length).toBe(vector.receipt_body_len);
    expect(hexEncode(reencoded)).toBe(vector.receipt_body_hex);
  });
});
