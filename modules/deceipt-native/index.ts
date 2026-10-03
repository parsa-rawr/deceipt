/**
 * `modules/deceipt-native/index.ts` — the module entry point A4 and A5 build
 * against.
 *
 * The single typed adapter contract is `app/src/native/DeceiptNative.ts`; this
 * file re-exports it under the module's package path and documents the two
 * things an implementer must know: the platform surface a native module has to
 * expose, and the runtime guards the adapters must enforce.
 */

export * from '../../app/src/native/DeceiptNative';
export {DeceiptBridgeError} from '../../app/src/native/bridgeError';

/**
 * The name the shared app registers the adapter under with the RN
 * `NativeModules` / TurboModule registry. A4 supplies the iOS module under this
 * name, A5 the Android one; both must be identical so the app needs no
 * platform branching.
 */
export const NATIVE_MODULE_NAME = 'DeceiptNative';

/**
 * The JSON-RPC style method names every adapter MUST export. The app resolves
 * these from the module object and fails loudly (CAPABILITY_UNAVAILABLE) when
 * one is missing, rather than degrading silently.
 */
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
] as const;

/**
 * The event names the adapter emits (batched, through `subscribe`). The union is
 * `DeceiptEvent['type']`; it is restated here so the native side can assert it
 * at build time without importing TypeScript.
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
  'session_authenticated',
  'credential_unknown_issuer',
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
] as const;

/**
 * GATT identifiers the native layer must expose. Restated as constants for the
 * native builds; the frozen source is `protocol/schema/bounds-v1.json` and
 * docs/protocol/wire.md §1.
 */
export const NATIVE_GATT = {
  serviceUuid: '8decc0de-1e57-4000-8000-000000000001',
  commandUuid: '8decc0de-1e57-4000-8000-000000000002',
  eventUuid: '8decc0de-1e57-4000-8000-000000000003',
  dataUuid: '8decc0de-1e57-4000-8000-000000000004',
} as const;
