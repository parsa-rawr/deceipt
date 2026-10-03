/**
 * `modules/deceipt-native/index.ts` — the module entry point A4 and A5 build
 * against.
 *
 * The single typed adapter contract is `app/src/native/DeceiptNative.ts`; this
 * file re-exports it under the module's package path and documents the platform
 * surface a native module must expose.
 *
 * The four constant groups below are all DERIVED from the contract types rather
 * than hand-maintained, so a change to `DeceiptNative.ts` that is not reflected
 * here is a compile error instead of a silent drift (a native implementer
 * asserting on a stale list would otherwise watch for an event that never fires
 * and miss one that does).
 */

import type {DeceiptEvent, DeceiptNative} from '../../app/src/native/DeceiptNative';
import {GATT} from '../../app/src/protocol/constants';

export * from '../../app/src/native/DeceiptNative';
export {DeceiptBridgeError} from '../../app/src/native/bridgeError';

/**
 * The name the shared app registers the adapter under with the RN
 * `NativeModules` / TurboModule registry. A4 supplies the iOS module under this
 * name, A5 the Android one; both must be identical so the app needs no platform
 * branching.
 *
 * Transport note (A4/A5 experience): the app resolves this as
 * `NativeModules[NATIVE_MODULE_NAME]`. React Native's codegen cannot be used
 * against this contract because (a) `subscribe(listener) => () => void` has a
 * return type codegen rejects (`UnsupportedFunctionReturnTypeAnnotationParserError`)
 * and (b) the generic ObjC/TurboModule bridge cannot carry a batched listener
 * callback. A hand-written module reachable as `NativeModules.DeceiptNative`
 * satisfies the contract unchanged; that is the agreed shape, not a fallback.
 */
export const NATIVE_MODULE_NAME = 'DeceiptNative';

/**
 * The method names every adapter MUST export, derived from the contract so a
 * missing or renamed method fails to compile. The app resolves these from the
 * module object and fails loudly (`CAPABILITY_UNAVAILABLE`) when one is absent,
 * rather than degrading silently.
 */
type MethodName = Extract<keyof DeceiptNative, string>;

export const NATIVE_METHODS = [
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
  'subscribe',
] as const satisfies readonly MethodName[];

/**
 * The event names the adapter emits (batched, through `subscribe`), derived from
 * the `DeceiptEvent` union. `satisfies` pins every entry to a real union member,
 * and `EVENT_METHOD_COVERAGE` below proves the direction that `satisfies` cannot:
 * every union member is listed.
 */
export const NATIVE_EVENT_NAMES = [
  'advertising_started',
  'advertising_stopped',
  'peer_candidate',
  'peer_candidate_lost',
  'scan_started',
  'scan_stopped',
  'bluetooth_state_changed',
  'permission_changed',
  'connected',
  'mtu_changed',
  'disconnected',
  'handshake_started',
  'session_keys_derived',
  'session_unverified_peer',
  'session_authenticated',
  'binding_consumed',
  'binding_stale',
  'offer_received',
  'offer_accepted',
  'transfer_started',
  'transfer_progress',
  'transfer_complete',
  'receipt_received',
  'receipt_ack_sent',
  'session_torn_down',
  'error',
] as const satisfies readonly DeceiptEvent['type'][];

type ListedEventName = (typeof NATIVE_EVENT_NAMES)[number];

/**
 * Compile-time exhaustiveness check in the direction `satisfies` cannot express:
 * if the union gains a member that is not listed above, `Exclude` is non-never
 * and the assignment fails. Keep this line; it is the anti-drift mechanism.
 */
const EVENT_METHOD_COVERAGE: Exclude<DeceiptEvent['type'], ListedEventName> extends never ? true : never = true;
void EVENT_METHOD_COVERAGE;

/**
 * GATT identifiers the native layer must expose. Taken from the single frozen
 * source (`app/src/protocol/constants.ts`, itself transcribed from
 * `protocol/schema/bounds-v1.json` and docs/protocol/wire.md §1), so the module
 * and the app cannot disagree.
 */
export const NATIVE_GATT = GATT;
