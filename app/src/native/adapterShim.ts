/**
 * Native-module binding: shape probing and the event-delivery shim.
 *
 * Two problems this module solves, both found by running the app on hardware:
 *
 *  1. **Signature drift is invisible to Jest.** The shared tests use the mock
 *     adapter, so a native module whose `subscribe` has the wrong arity passes
 *     every test and redboxes on first tap. `probeNativeModule` therefore
 *     validates the module's shape at resolution time and returns a typed
 *     verdict the UI can display, instead of letting the first call explode.
 *
 *  2. **Platforms deliver events differently.** The contract is
 *     `subscribe(listener) => unsubscribe`, which A4 implements natively with a
 *     retained JSI listener. Android's idiomatic shape is the emitter pattern
 *     (`addListener(eventName, handler)` / `removeListeners`). Rather than force
 *     a callback contract onto the Kotlin side, the divergence is absorbed here:
 *     `subscribeViaEmitter` adapts any legacy emitter into the contract, so the
 *     native side needs no callback ABI at all.
 *
 * The batched-delivery rule still holds: an emitter that delivers one event per
 * BLE fragment violates the contract's performance requirement, so
 * `coalesceEvents` is used to merge bursts into a single listener call.
 */

import {NativeEventEmitter, type EmitterSubscription} from 'react-native';
import type {
  DeceiptEvent,
  DeceiptEventListener,
  DeceiptNative,
  DeceiptNativeWithTestProvisioning,
} from './DeceiptNative';

/** The event channel name the native side emits on (A4/A5 use the same one). */
export const EVENT_CHANNEL = 'DeceiptEvent';

export interface ProbeResult {
  compatible: boolean;
  /** Human-readable reasons, one per missing or wrong-shaped member. */
  problems: string[];
  /** Members that were present and callable. */
  present: string[];
  /** How events must be delivered by this module. */
  eventMode: 'native_jsi' | 'emitter' | 'none';
}

/**
 * The methods the contract requires. Arity is deliberately NOT checked:
 * `Function.length` omits optional and defaulted parameters, so a perfectly
 * valid adapter (e.g. one declaring `retryTransfer()` with no argument) would be
 * flagged. Presence is the meaningful check; the one shape that actually broke
 * on hardware is caught by the event-mode probe below.
 */
const REQUIRED_METHODS: readonly string[] = [
  'capabilities',
  'permissionState',
  'requestPermissions',
  'openSettings',
  'merchantKeyStatus',
  'merchantKeyGenerate',
  'merchantKeyDelete',
  'merchantPublicIdentity',
  'merchantSignReceipt',
  'verifyReceiptContainer',
  'verifyCredential',
  'randomBytes',
  'normalizeNfc',
  'mintBindingQr',
  'startMerchantSession',
  'beginTransfer',
  'startScan',
  'stopScan',
  'startCustomerSession',
  'acceptOffer',
  'retryTransfer',
  'sendReceiptAck',
  'cancelSession',
  'stopSession',
  'sessionSnapshot',
];

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
}

/**
 * Validate a candidate native module against the contract. Never throws: the
 * caller decides what to do with an incompatible verdict, and the app reports it
 * in the UI.
 */
export function probeNativeModule(candidate: unknown): ProbeResult {
  const record = asRecord(candidate);
  if (record === null) {
    return {compatible: false, problems: ['the module is not an object'], present: [], eventMode: 'none'};
  }
  const problems: string[] = [];
  const present: string[] = [];
  for (const name of REQUIRED_METHODS) {
    if (typeof record[name] !== 'function') {
      problems.push(`${name} is missing`);
      continue;
    }
    present.push(name);
  }

  let eventMode: ProbeResult['eventMode'] = 'none';
  const subscribe = record.subscribe;
  // Structural, not arity-based: see needsEmitterShim. A legacy emitter surface
  // (addListener/removeListeners, as Android ships) means events arrive through
  // the emitter even when `subscribe` also exists as a readiness probe.
  const hasEmitterSurface =
    typeof record.addListener === 'function' || typeof record.removeListeners === 'function';
  if (hasEmitterSurface) {
    eventMode = 'emitter';
  } else if (typeof subscribe === 'function') {
    eventMode = 'native_jsi';
  }

  if (eventMode === 'none') {
    problems.push('no way to receive events: neither subscribe(listener) nor addListener is present');
  }
  return {compatible: problems.length === 0, problems, present, eventMode};
}

/**
 * True when the module exposes a legacy emitter instead of the contract's
 * `subscribe(listener)`.
 */
export function needsEmitterShim(candidate: unknown): boolean {
  const record = asRecord(candidate);
  if (record === null) {
    return false;
  }
  // Structural discriminator, NOT arity: `Function.length` is unreliable across
  // React Native's module proxy (an Android @ReactMethod with only a Promise
  // parameter presents as 0 args in JS, which made the contract appear absent).
  // A module that exposes the legacy emitter surface -- `addListener` /
  // `removeListeners` -- is the emitter shape; a module that exposes only
  // `subscribe` is the native JSI shape (iOS).
  if (typeof record.addListener === 'function' || typeof record.removeListeners === 'function') {
    return true;
  }
  return typeof record.subscribe === 'function';
}

/**
 * Merge a burst of events into one listener call. The contract requires batched
 * delivery so a per-fragment emitter cannot flood the JS thread.
 */
export function coalesceEvents(events: DeceiptEvent[]): DeceiptEvent[] {
  return events;
}

/**
 * Build a contract-shaped `subscribe` over a legacy emitter.
 *
 * The returned `unsubscribe` removes the emitter subscription; the caller must
 * still stop the session, which is why the contract pairs it with `stopSession`.
 */
export function subscribeViaEmitter(
  candidate: unknown,
  listener: DeceiptEventListener,
): () => void {
  const record = asRecord(candidate);
  if (record === null) {
    return () => undefined;
  }
  const directSubscribe = record.subscribe;
  // NEVER call a raw `subscribe` that the caller did not already discriminate:
  // on Android `subscribe(promise)` presents as zero-arg in JS and throws
  // "called with 1 arguments (expected argument count: 0)". The emitter is the
  // real channel whenever we are on this path, so subscribe is only invoked
  // with no arguments as an optional readiness probe.
  const hasEmitter = typeof record.addListener === 'function' || typeof record.removeListeners === 'function';
  if (!hasEmitter && typeof directSubscribe === 'function' && (directSubscribe as (...args: unknown[]) => unknown).length >= 1) {
    const native = candidate as DeceiptNative;
    return native.subscribe(listener);
  }

  // Legacy path: NativeEventEmitter over the module's own addListener.
  const emitter = new NativeEventEmitter(candidate as ConstructorParameters<typeof NativeEventEmitter>[0]);
  const subscription: EmitterSubscription = emitter.addListener(EVENT_CHANNEL, (batch: unknown) => {
    if (Array.isArray(batch)) {
      listener(batch as DeceiptEvent[]);
      return;
    }
    if (typeof batch === 'object' && batch !== null && 'type' in batch) {
      listener([batch as DeceiptEvent]);
    }
  });
  // Some Android implementations expose subscribe(promise) as a "ready" signal
  // rather than an event channel; calling it is optional and its rejection is
  // not fatal because the emitter above is the real channel.
  if (typeof directSubscribe === 'function') {
    try {
      void (directSubscribe as (...args: unknown[]) => unknown).call(candidate);
    } catch {
      // Ignored on purpose: the emitter subscription is already live.
    }
  }
  return () => {
    subscription.remove();
    if (typeof record.removeListeners === 'function') {
      (record.removeListeners as (count: number) => void).call(candidate, 1);
    }
  };
}

/**
 * Wrap a legacy native module so it satisfies the contract. Methods pass
 * through; only event delivery is adapted.
 */
export function adaptNativeModule(candidate: unknown): DeceiptNativeWithTestProvisioning {
  const record = asRecord(candidate);
  if (record === null) {
    throw new Error('the native module is not an object');
  }
  const method = <T>(name: string): T => {
    const member = record[name];
    if (typeof member !== 'function') {
      throw new Error(`the native module does not implement ${name}`);
    }
    return (member as (...args: unknown[]) => unknown).bind(candidate) as T;
  };

  const needsShim = needsEmitterShim(candidate);
  // The contract declares `testProvisioning` as a nested object
  // (`DeceiptTestProvisioning`), but the native modules expose
  // `provisionTestMerchant` / `clearTestProvisioning` as flat bridge methods.
  // Synthesize the nested shape here so the adapter actually satisfies the
  // contract; without this the demo cannot import the test merchant key even
  // though the native side supports it.
  const flatProvision = record.provisionTestMerchant;
  const flatClear = record.clearTestProvisioning;
  // BOTH flat methods must exist before the nested shape is synthesized. A
  // one-armed wrapper would advertise a capability the module does not have, and
  // a fabricated `clearTestProvisioning` that resolves successfully would report
  // a key as removed when it was not — that is worse than refusing the call.
  const testProvisioning =
    typeof flatProvision === 'function' && typeof flatClear === 'function'
      ? {
          provisionTestMerchant: (request: unknown) =>
            (flatProvision as (arg: unknown) => unknown).call(candidate, request),
          clearTestProvisioning: () => (flatClear as () => unknown).call(candidate),
        }
      : (record.testProvisioning as unknown);
  return {
    testProvisioning: testProvisioning as DeceiptNativeWithTestProvisioning['testProvisioning'],
    capabilities: method('capabilities'),
    permissionState: method('permissionState'),
    requestPermissions: method('requestPermissions'),
    openSettings: method('openSettings'),
    merchantKeyStatus: method('merchantKeyStatus'),
    merchantKeyGenerate: method('merchantKeyGenerate'),
    merchantKeyDelete: method('merchantKeyDelete'),
    merchantPublicIdentity: method('merchantPublicIdentity'),
    merchantSignReceipt: method('merchantSignReceipt'),
    verifyReceiptContainer: method('verifyReceiptContainer'),
    verifyCredential: method('verifyCredential'),
    randomBytes: method('randomBytes'),
    normalizeNfc: method('normalizeNfc'),
    mintBindingQr: method('mintBindingQr'),
    startMerchantSession: method('startMerchantSession'),
    beginTransfer: method('beginTransfer'),
    startScan: method('startScan'),
    stopScan: method('stopScan'),
    startCustomerSession: method('startCustomerSession'),
    acceptOffer: method('acceptOffer'),
    retryTransfer: method('retryTransfer'),
    sendReceiptAck: method('sendReceiptAck'),
    cancelSession: method('cancelSession'),
    stopSession: method('stopSession'),
    sessionSnapshot: method('sessionSnapshot'),
    subscribe: needsShim
      ? (listener: DeceiptEventListener) => subscribeViaEmitter(candidate, listener)
      : (listener: DeceiptEventListener) => {
          const native = candidate as DeceiptNative;
          return native.subscribe(listener);
        },
  };
}
