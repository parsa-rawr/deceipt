/**
 * DeceiptNative — the single typed adapter contract between the shared React
 * Native app (A3) and the platform adapters (A4 iOS / A5 Android).
 *
 * Revision: `deceipt-proto-r1` (protocol/REVISION.json).
 *
 * THIS FILE IS FROZEN. A4 and A5 implement it identically; neither may extend
 * it unilaterally (Deceipt_Subagent_Delegation_Plan.md §1, §2/A3). Every
 * operation and every event an implementation must provide is enumerated here;
 * there is no "reasonable judgment" left open. Changing this file is a
 * revision break coordinated through A0.
 *
 * ---------------------------------------------------------------------------
 * WHERE THE SECRETS LIVE (invariants 3, 8 of the delegation plan)
 * ---------------------------------------------------------------------------
 *   * Native owns: merchant long-lived signing keys (Keychain / Keystore),
 *     session-binding tokens, ephemeral ECDH private keys, session keys
 *     (k_c2m_ctrl / k_m2c_ctrl / k_m2c_payload / k_exporter), AEAD counters,
 *     BLE callbacks, LPdu fragmentation, DataFrame buffering, flow control,
 *     parser/allocation bounds.
 *   * JS receives ONLY: public identifiers, signatures, verification results,
 *     bounded receipt bytes, and bounded non-secret control metadata.
 *   * The merchant private key and every session secret NEVER cross this
 *     bridge. The one exception is the *test-only* provisioning entry point
 *     (`provisionTestMerchant`), which is gated behind a capability the app
 *     must never enable in a production build (see `DeceiptTestProvisioning`).
 *   * NEVER one bridge call per BLE fragment: bytes arrive as *batches* of
 *     typed events (`subscribe`), and every byte-carrying event is delivered
 *     once per logical protocol object (a reassembled receipt payload, a
 *     reassembled control message), never per ATT write/notification.
 *
 * ---------------------------------------------------------------------------
 * BYTE ENCODING ACROSS THE BRIDGE
 * ---------------------------------------------------------------------------
 * Binary values cross as `Base64` = RFC 4648 §4 standard alphabet, padding
 * included. Rationale: it is UTF-8 safe in every RN transport (legacy bridge,
 * TurboModules, JSI), and a receipt is at most 65536 bytes. Decoders MUST
 * reject malformed base64 rather than silently truncating. Text values are
 * UTF-8 `string`; no binary is ever smuggled through a text field.
 *
 * ---------------------------------------------------------------------------
 * EXACT-BYTES RULE (invariant 3)
 * ---------------------------------------------------------------------------
 * Signature verification is performed by native over the *exact bytes
 * received on the wire*. JS MUST hand native the identical buffer it received
 * in `receipt_received`; native MUST NOT accept a re-encoded container. The
 * `Sig_structure` of RFC 9052 §4.4 is built by native only — TS never
 * reconstructs or re-encodes it.
 *
 * No implementation may substitute a boolean for a verification sub-state:
 * `ReceiptSignatureVerification` carries `signatureValid` alone, and the
 * separate sub-state fields live in the shared verification result (see
 * `app/src/protocol/verification.ts`). Native MUST NOT return anything that
 * collapses signature-valid / key-authorized / temporally-acceptable /
 * revocation-known / semantically-valid / locally-unique into one flag.
 */

import type {ProtocolErrorName} from '../protocol/errors';

/** RFC 4648 §4 base64, padding included. */
export type Base64 = string;

/** Opaque handle for a native session. Never encodes key material. */
export type SessionHandle = string;

/** Opaque identifier of a BLE peripheral as reported by the platform. */
export type PeripheralId = string;

/** 16 random bytes, hex encoded (transfer_id / session_id / receipt_id). */
export type Id16Hex = string;

// ---------------------------------------------------------------------------
// Typed errors (protocol/vectors/errors.json, verification.md §4)
// ---------------------------------------------------------------------------

/**
 * The wire shape of every bridge failure. `name`/`code`/`fatal`/`retryable`
 * MUST be identical to `protocol/vectors/errors.json` on both platforms so
 * A6's conformance runner can assert on identifiers alone (verification.md §4
 * "Semantics are transport-independent").
 */
export interface BridgeError {
  /** Frozen identifier from `protocol/vectors/errors.json#errors[].name`. */
  name: ProtocolErrorName;
  /** Stable u16 wire code from the same table. */
  code: number;
  fatal: boolean;
  retryable: boolean;
  /** Where in the flow the failure happened; diagnostic only. */
  phase?: BridgePhase;
  /** ≤64 bytes, no secrets. Rendered to the user only after mapping. */
  detail?: string;
}

export type BridgePhase =
  | 'permission'
  | 'scan'
  | 'advertising'
  | 'connect'
  | 'handshake'
  | 'credential'
  | 'binding'
  | 'transfer'
  | 'receipt'
  | 'keys'
  | 'teardown'
  | 'internal';

/** Error thrown by every promise in this contract. */
export declare class DeceiptBridgeError extends Error {
  readonly bridge: BridgeError;
  constructor(bridge: BridgeError);
}

// ---------------------------------------------------------------------------
// Capabilities and permissions
// ---------------------------------------------------------------------------

/**
 * What the platform adapter can actually do. A capability that is `false` MUST
 * cause the shared UI to show an explicit capability failure rather than
 * silently degrading (delegation plan §2/A4.2, A5.2).
 */
export interface CapabilityReport {
  platform: 'ios' | 'android';
  /** GATT client / scanning. */
  bleCentral: boolean;
  /** GATT server. */
  blePeripheral: boolean;
  /** Advertising the Deceipt Transfer Service UUID (device dependent on Android). */
  bleAdvertising: boolean;
  /** Advertised `protocol_version` (1 for r1). */
  protocolVersion: number;
  /** Supported `suite_id`s; r1 = [1]. */
  suiteIds: number[];
  /** Ed25519 signing available. */
  ed25519: boolean;
  /** `true` = platform-keystore-held, non-exportable-or-wrapped; see A4/A5 notes. */
  ed25519Keystore: boolean;
  /** `false` on Android means the documented Keystore-AES-wrapped fallback (§4.4). */
  ed25519HardwareBacked: boolean;
  /** Merchant keys survive process restart. */
  keyPersistence: boolean;
  /** Camera QR acquisition is available to the app. */
  cameraQrScan: boolean;
  /**
   * `true` only in explicitly flagged test/dev builds. When `true`, the
   * `DeceiptTestProvisioning` entry points are callable. Production builds
   * MUST report `false` (docs/protocol/trust.md §3, conformance B9).
   */
  testProvisioningEnabled: boolean;
  /** Native module build identifier, diagnostic only (e.g. "a4-ios-0.1.0"). */
  adapterBuild: string;
}

export type PermissionStatus = 'granted' | 'denied' | 'restricted' | 'undetermined' | 'unavailable';
export type BluetoothState = 'on' | 'off' | 'unauthorized' | 'unsupported' | 'unknown';

export interface PermissionReport {
  bluetooth: PermissionStatus;
  camera: PermissionStatus;
  bluetoothState: BluetoothState;
}

export type PermissionKind = 'bluetooth' | 'camera';

// ---------------------------------------------------------------------------
// Merchant key operations and signing (native-side key custody)
// ---------------------------------------------------------------------------

/**
 * Storage class of the merchant device key. Reported honestly: the PoC does
 * NOT claim hardware-backed non-exportability where the platform lacks it
 * (DESIGN.md §4.4).
 */
export type KeyStorageKind =
  | 'keychain_software'
  | 'keystore_ed25519'
  | 'keystore_wrapped_aes'
  | 'in_memory_ephemeral'
  | 'none';

/** Public identifiers only — never key material. */
export interface MerchantKeyIdentity {
  /** 16-byte `device_key_id`; equal to the receipt's COSE protected `kid`. */
  deviceKeyIdHex: Id16Hex;
  /** 32-byte Ed25519 public key of the device signing key. */
  devicePublicKeyB64: Base64;
  storage: KeyStorageKind;
  /** Milliseconds since epoch; diagnostic. */
  createdAtMs?: number;
}

export interface MerchantKeyStatus {
  /** A signing key exists in platform storage. NOT sufficient for merchant mode. */
  provisioned: boolean;
  /**
   * The merchant identity is COMPLETE: a signing key AND the credential that
   * authorizes it AND the merchant id that credential asserts.
   *
   * `provisioned` alone is not enough to serve a receipt — a device can hold a
   * key whose credential import failed (observed on device after a cold start),
   * and such a device cannot build a `ServerHello` or embed a credential at
   * receipt label 20. Callers must gate on `ready`, not on `provisioned`, and
   * adapters MUST report `ready: false` whenever any of the three parts is
   * missing.
   *
   * Optional so an adapter built before this field existed still type-checks; the
   * shared layer then decides readiness from `provisioned`, `credentialB64` and
   * `merchantIdHex` together (see `isMerchantReady`).
   */
  ready?: boolean;
  /** Present only when `ready` is true. */
  identity?: MerchantKeyIdentity;
  /**
   * The exact COSE_Sign1 credential bytes provisioned for this device, if any.
   * Public material (an issuer-signed credential). Held natively so the
   * `ServerHello` can be built without a round trip through JS.
   */
  /** Present only when `ready` is true. */
  credentialB64?: Base64;
  /** 16-byte merchant_id from that credential; present only when `ready`. */
  merchantIdHex?: Id16Hex;
  /**
   * Which parts are missing when `ready` is false, so the UI can say what to do
   * instead of showing a generic failure.
   */
  missing?: Array<'signing_key' | 'credential' | 'merchant_id'>;
}

/** Result of signing a receipt payload. */
export interface SignedReceipt {
  /** The complete COSE_Sign1 bytes (protected ‖ unprotected ‖ payload ‖ sig). */
  coseSign1B64: Base64;
  /** The 64-byte Ed25519 signature, for the conformance vector check. */
  signatureB64: Base64;
  /** The protected header bytes actually signed (bstr), public. */
  protectedB64: Base64;
  deviceKeyIdHex: Id16Hex;
}

// ---------------------------------------------------------------------------
// Verification results (sub-states preserved; trust.md §4, verification.md §2)
// ---------------------------------------------------------------------------

/**
 * Result of Ed25519 verification over the exact received COSE_Sign1 bytes.
 * This is ONE sub-state, never the trust decision.
 */
export interface ReceiptSignatureVerification {
  /** True iff Ed25519 verified over `Sig_structure` of the exact received bytes. */
  signatureValid: boolean;
  /** The protected-header `kid` parsed from the container, if parseable. */
  deviceKeyIdHex?: Id16Hex;
  /** Set when the container could not even be parsed for verification. */
  error?: BridgeError;
}

export type CredentialTrust = 'authenticated' | 'unknown_issuer';

/**
 * Result of `verifyCredential`. `trust = 'unknown_issuer'` is NON-FATAL
 * (trust.md §4 step 7): the session may continue for diagnostics, but the key
 * is never authorized and no receipt from it can ever be TRUSTED.
 */
export interface CredentialVerification {
  trust: CredentialTrust;
  /** Ed25519 verified against an anchor in the supplied anchor set. */
  signatureValid: boolean;
  /** `valid_from - skew <= now < valid_until + skew`, skew = CLOCK_SKEW_MAX_S. */
  temporallyAcceptable: boolean;
  /** Present when parsed; all are public values from the credential payload. */
  merchantIdHex?: Id16Hex;
  deviceKeyIdHex?: Id16Hex;
  devicePublicKeyB64?: Base64;
  issuerIdHex?: Id16Hex;
  capabilities?: number;
  merchantReference?: string;
  displayName?: string;
  /** Non-fatal failures carried explicitly (e.g. CREDENTIAL_UNKNOWN_ISSUER). */
  error?: BridgeError;
}

/** Anchor entry handed to native by the app (public material only). */
export interface TrustAnchor {
  anchorIdHex: Id16Hex;
  /** 32-byte Ed25519 public key. */
  publicKeyB64: Base64;
  label?: string;
}

// ---------------------------------------------------------------------------
// Session configuration and binding (A2 contract bytes, frozen)
// ---------------------------------------------------------------------------

/**
 * The customer's selection: the exact scanned QR string. Native parses
 * `deceipt1:` + base64url + canonical CBOR, checks freshness
 * (`T_BINDING_QR`), and keeps the SBT natively. JS never handles the SBT as a
 * field. Scanning is the ONLY way `connecting` is entered (r3).
 */
export interface QrBindingSelection {
  kind: 'qr';
  /** The exact scanned payload, e.g. `deceipt1:pQEBAlAAESIz…`. */
  qrPayload: string;
}

/**
 * The only customer selection. r3 removed the binding-less P0 path:
 * `CLIENT_HELLO` requires `session_id` (label 4) and `binding_proof` (label 7),
 * and the binding material (SBT) exists only in the QR, so a connect path
 * without a scan would be permanently `BINDING_REQUIRED`
 * (`protocol/flows/checkout-flow-v1.json#selection_model = qr_mandatory_v1`,
 * `qr_less_path: removed`).
 */
export type CustomerSelection = QrBindingSelection;

/**
 * What the customer asks native to do. `anchors` is the pinned public anchor
 * set; a build MUST NOT bundle test private keys, and MUST NOT trust the
 * test-only anchors in a production build (conformance B9).
 */
export interface StartCustomerSessionRequest {
  selection: CustomerSelection;
  anchors: TrustAnchor[];
  /** Client's declared `max_frame_payload`, 16..512. Default 512 (capped by MTU). */
  clientMaxFramePayload?: number;
  /** Overrides for the frozen timeouts (tests only; defaults from bounds-v1.json). */
  timeoutOverridesMs?: Partial<Record<TimeoutName, number>>;
}

/**
 * What the merchant asks native to do after minting its QR.
 * `receiptCose1B64` is the exact signed receipt the merchant already produced;
 * the transfer never re-encodes it (DESIGN.md §4.1).
 */
export interface StartMerchantSessionRequest {
  /** Handle from `mintBindingQr`. The SBT itself never crosses the bridge. */
  bindingRef: string;
  /** Exact COSE_Sign1 bytes of the receipt. */
  receiptCose1B64: Base64;
  transferIdHex: Id16Hex;
  sessionIdHex: Id16Hex;
  receiptIdHex: Id16Hex;
  offerHashHex: string;
  /** Negotiated frame size (≤ peer declared and ≤ MTU ceiling); omitted = maximum the MTU allows. */
  frameSize?: number;
  timeoutOverridesMs?: Partial<Record<TimeoutName, number>>;
}

export interface MintBindingQrRequest {
  sessionIdHex: Id16Hex;
  offerHashHex: string;
  /** `expires_at_unix`, seconds. MUST be now + T_BINDING_QR unless overridden by a test. */
  expiresAtUnix: number;
}

export interface MintBindingQrResponse {
  /** Opaque handle for `startMerchantSession`; the SBT stays native. */
  bindingRef: string;
  /** The exact renderable QR payload (`deceipt1:` + base64url_nopad(CBOR)). */
  qrPayload: string;
  sessionIdHex: Id16Hex;
  expiresAtUnix: number;
}

export type TimeoutName =
  | 'T_ADVERTISE'
  | 'T_CONNECT'
  | 'T_HELLO_RESPONSE'
  | 'T_ACCEPT'
  | 'T_CONTROL_FRAG'
  | 'T_ACK_WAIT'
  | 'T_ACK_INTERVAL'
  | 'T_TRANSFER_IDLE'
  | 'T_VERIFY_BUDGET'
  | 'T_SESSION'
  | 'T_CLOSE'
  | 'T_BINDING_QR';

// ---------------------------------------------------------------------------
// Session states and progress metadata
// ---------------------------------------------------------------------------

/**
 * The native transfer/state projection (DESIGN.md §8.1). `RECEIPT_UNTRUSTED`
 * is a real, explicit state: native enters it after step 7 (AEAD open) and
 * MUST NOT leave it except by handing the exact bytes to the app for steps
 * 8–15. There is no path from `SESSION_DECRYPTED` to any trusted state inside
 * native, because native never holds a receipt-trust decision.
 */
export type NativeSessionState =
  | 'IDLE'
  | 'RECEIPT_SIGNED'
  | 'ADVERTISING'
  | 'SCANNING'
  | 'CONNECTED'
  | 'HANDSHAKE'
  | 'MERCHANT_SESSION_AUTHENTICATED'
  | 'SESSION_KEYS_ONLY'
  | 'RECEIPT_OFFERED'
  | 'TRANSFER'
  | 'CIPHERTEXT_REASSEMBLED'
  | 'SESSION_DECRYPTED'
  | 'RECEIPT_UNTRUSTED'
  | 'AWAITING_STORE'
  | 'ACKED'
  | 'DISCONNECT'
  | 'ABORTED';

export interface SessionSnapshot {
  sessionHandle: SessionHandle;
  role: 'merchant' | 'customer';
  state: NativeSessionState;
  /** Set once `ServerHello` has been verified (handshake.md §9). */
  authenticated: boolean;
  transferIdHex?: Id16Hex;
  sessionIdHex?: Id16Hex;
  attMtu?: number;
  frameSize?: number;
  frameCount?: number;
  highestContiguousSequence?: number;
  /** Non-secret; `undefined` until the handshake negotiated it. */
  merchantIdHex?: Id16Hex;
  deviceKeyIdHex?: Id16Hex;
}

/** Untrusted display metadata from `RECEIPT_OFFER` (DESIGN.md §8.3). */
export interface OfferMetadata {
  transferIdHex: Id16Hex;
  receiptIdHex: Id16Hex;
  merchantReference: string;
  totalAmountMinor: number;
  currency: string;
  issuedAt: number;
  kind: 1 | 2 | 3;
  ciphertextLength: number;
  merchantIdHex: Id16Hex;
  credentialHashHex: string;
  sessionIdHex: Id16Hex;
  /** Recomputable in JS from labels 3,4,5,6,7,10 (framing.md §7). */
  offerHashHex: string;
}

/**
 * The three-level session distinction of handshake.md §9 (r2), as three nominal
 * types. There is **no common base type that the transfer path accepts**, so the
 * distinction is enforced by the type checker and restated as a runtime guard in
 * `assertSessionMayTransfer` / `assertSessionAuthenticated` below.
 *
 *   SessionKeysOnly         keys derived, peer NOT authenticated. Diagnostics and
 *                           error handling only. MUST NOT send ACCEPT.
 *   SessionUnverifiedPeer   the ServerHello credential is well-formed but its
 *                           issuer is NOT a pinned anchor, and the transcript
 *                           signature verified against the credential's
 *                           SELF-ASSERTED device key. Internal consistency only,
 *                           NOT identity. MAY transfer; every receipt from it is
 *                           `UNVERIFIED_UNKNOWN_ISSUER` and can NEVER be TRUSTED.
 *   SessionAuthenticated    credential verified to a pinned anchor AND transcript
 *                           signature verified. The only session whose receipts
 *                           can be TRUSTED.
 *
 * Why `SessionUnverifiedPeer` carries `credentialTrust: 'unknown_issuer'` as a
 * literal: the trust level is a property of the *type*, not a mutable field. A
 * `SessionUnverifiedPeer` value is therefore structurally incapable of reporting
 * `'authenticated'`, and `SessionAuthenticated` is structurally incapable of
 * reporting `'unknown_issuer'`. The runtime guards and the proof that a
 * receipt from either type can only produce the outcome its type permits live in
 * `app/src/native/session.ts` (guards) and `app/tests/protocol.session.test.ts`
 * (the conformance proof).
 */

/** Keys derived, peer not authenticated. No transfer, no ACCEPT. */
export interface SessionKeysOnly {
  readonly kind: 'SessionKeysOnly';
  sessionHandle: SessionHandle;
}

/**
 * Well-formed credential from an **unpinned** issuer, transcript signature
 * verified against the credential's self-asserted device key (internal
 * consistency only). Transfer is permitted; trust is not attainable.
 */
export interface SessionUnverifiedPeer {
  readonly kind: 'SessionUnverifiedPeer';
  sessionHandle: SessionHandle;
  /** Self-asserted by the credential. NOT verified identity. */
  merchantIdHex: Id16Hex;
  /**
   * The `kid` the credential asserts. Verified only to equal the credential's
   * `device_key_id` field, not to belong to a pinned merchant.
   */
  deviceKeyIdHex: Id16Hex;
  /** The exact credential bytes received in `ServerHello` (public material). */
  credentialB64: Base64;
  /** Fixed by the type: this session can never report an authenticated peer. */
  readonly credentialTrust: 'unknown_issuer';
  /** The credential's issuer is not in the pinned anchor set (fixed `false`). */
  readonly keyAuthorized: false;
}

/** Credential verified to a pinned anchor AND transcript signature verified. */
export interface SessionAuthenticated {
  readonly kind: 'SessionAuthenticated';
  sessionHandle: SessionHandle;
  merchantIdHex: Id16Hex;
  deviceKeyIdHex: Id16Hex;
  /** The exact credential bytes verified in `ServerHello` (public material). */
  credentialB64: Base64;
  /** Fixed by the type: this session's credential is anchored. */
  readonly credentialTrust: 'authenticated';
  /** Fixed by the type: an unknown issuer never reaches this type. */
  readonly keyAuthorized: true;
  /** True only when every credential sub-state passed (trust.md §4). */
  credentialTemporallyAcceptable: boolean;
}

/** Any of the three levels, for adapters that must report their transition. */
export type AnySession = SessionKeysOnly | SessionUnverifiedPeer | SessionAuthenticated;

/**
 * The transfer path accepts exactly these two, and nothing else: a
 * `SessionKeysOnly` value cannot bind to this parameter.
 */
export type TransferableSession = SessionUnverifiedPeer | SessionAuthenticated;

// ---------------------------------------------------------------------------
// Events (verification.md §5 vocabulary; batched, typed)
// ---------------------------------------------------------------------------

export interface DiagnosticsOnly {
  /**
   * Diagnostics only. NEVER an input to eligibility, selection, ordering,
   * connection target, or trust (DESIGN.md §2.5, §7.3; A2 §2). Its presence in
   * this type is the only place a radio measurement may appear.
   */
  readonly diagnosticsOnly: true;
  rssi?: number;
  txPower?: number;
}

export type DeceiptEvent =
  | {type: 'advertising_started'; sessionHandle: SessionHandle; serviceUuid: string}
  | {type: 'advertising_stopped'; sessionHandle: SessionHandle; reason: TeardownReason}
  | {
      type: 'peer_candidate';
      peripheralId: PeripheralId;
      serviceUuid: string;
      /** `protocol_version` if the advertisement carried one; otherwise undefined. */
      protocolVersion?: number;
      /**
       * The checkout `session_id` this peripheral claims to be serving, when the
       * adapter can read it from the advertisement. Purely descriptive: it lets
       * the app notice two terminals claiming ONE scanned session (fail closed),
       * and it is NEVER a signal-strength or proximity input.
       */
      sessionIdHex?: Id16Hex;
      /** Untrusted, diagnostics-only label derived from the peripheral id. */
      deterministicLabel: string;
      diagnostics: DiagnosticsOnly;
    }
  | {type: 'peer_candidate_lost'; peripheralId: PeripheralId}
  | {type: 'scan_started'}
  | {type: 'scan_stopped'; reason: TeardownReason}
  | {type: 'bluetooth_state_changed'; state: BluetoothState}
  | {type: 'permission_changed'; permissions: PermissionReport}
  | {type: 'connected'; sessionHandle: SessionHandle; peripheralId: PeripheralId; attMtu: number}
  | {type: 'mtu_changed'; sessionHandle: SessionHandle; attMtu: number; frameSizeCeiling: number}
  | {type: 'disconnected'; sessionHandle: SessionHandle; reason: TeardownReason; error?: BridgeError}
  | {type: 'handshake_started'; sessionHandle: SessionHandle; role: 'merchant' | 'customer'}
  /** Keys derived but peer NOT authenticated: `SessionKeysOnly` (handshake.md §9). */
  | {type: 'session_keys_derived'; sessionHandle: SessionHandle; sessionKeysOnly: SessionKeysOnly}
  /**
   * The credential's issuer is not pinned, but its transcript signature
   * verified against its self-asserted device key: the session is
   * `SessionUnverifiedPeer`. Transfer is allowed; trust is not attainable.
   * Emitted once, at the transition out of `SessionKeysOnly`.
   */
  | {
      type: 'session_unverified_peer';
      sessionHandle: SessionHandle;
      unverifiedPeer: SessionUnverifiedPeer;
      credential: CredentialVerification;
    }
  | {
      type: 'session_authenticated';
      sessionHandle: SessionHandle;
      authenticated: SessionAuthenticated;
      credential: CredentialVerification;
    }
  | {type: 'binding_consumed'; sessionHandle: SessionHandle; sessionIdHex: Id16Hex}
  | {type: 'binding_stale'; sessionHandle: SessionHandle; sessionIdHex: Id16Hex; expiredAtUnix: number}
  | {type: 'offer_received'; sessionHandle: SessionHandle; offer: OfferMetadata}
  | {type: 'offer_accepted'; sessionHandle: SessionHandle}
  | {
      type: 'transfer_started';
      sessionHandle: SessionHandle;
      ciphertextLength: number;
      frameCount: number;
      frameSize: number;
      payloadHashHex: string;
    }
  | {
      type: 'transfer_progress';
      sessionHandle: SessionHandle;
      highestContiguousSequence: number;
      frameCount: number;
      /** Non-fatal replay/duplicate notices, e.g. FRAME_SEQUENCE_REPLAYED. */
      notices: ProtocolErrorName[];
    }
  | {type: 'transfer_complete'; sessionHandle: SessionHandle; frameCount: number; payloadHashHex: string}
  /**
   * The AEAD payload was authenticated and decrypted. The session is now in
   * `RECEIPT_UNTRUSTED`: these are the exact bytes to run steps 8–15 over.
   * Transport success is NOT trust (invariant 2).
   */
  | {
      type: 'receipt_received';
      sessionHandle: SessionHandle;
      state: 'RECEIPT_UNTRUSTED';
      /** Exact COSE_Sign1 bytes as received; pass these unchanged to `verifyReceiptContainer`. */
      coseSign1B64: Base64;
      /** SHA-256 of the received payload, transport-integrity evidence only. */
      payloadSha256Hex: string;
      /** Ciphertext length actually reassembled. */
      ciphertextLength: number;
    }
  | {
      type: 'receipt_ack_sent';
      sessionHandle: SessionHandle;
      receiptIdHex: Id16Hex;
      outcomeCode: number;
    }
  | {type: 'session_torn_down'; sessionHandle: SessionHandle; reason: TeardownReason}
  | {type: 'error'; error: BridgeError; sessionHandle?: SessionHandle};

export type TeardownReason =
  | 'completed'
  | 'user_cancelled'
  | 'aborted'
  | 'timeout'
  | 'link_lost'
  | 'bluetooth_off'
  | 'permission_denied'
  | 'peer_error'
  | 'app_shutdown'
  | 'replaced';

export type DeceiptEventListener = (events: DeceiptEvent[]) => void;

// ---------------------------------------------------------------------------
// Transfer outcomes (RECEIPT_ACK label 4 / verification.md §3)
// ---------------------------------------------------------------------------

export const RECEIPT_ACK_OUTCOME = {
  trusted: 1,
  unknown_issuer: 2,
  already_imported: 3,
  rejected: 4,
} as const;

export type ReceiptAckOutcome = keyof typeof RECEIPT_ACK_OUTCOME;

// ---------------------------------------------------------------------------
// Test-only provisioning (gated; MUST NOT be reachable in production builds)
// ---------------------------------------------------------------------------

/**
 * Test/dev-only entry point used to provision the pre-provisioned PoC test
 * merchant (docs/protocol/trust.md §3 step 3). It is separated from the main
 * contract on purpose:
 *
 *   * it is the ONLY operation that accepts private key material, and it does
 *     so only for the labelled, published test vectors;
 *   * implementations MUST refuse it unless `CapabilityReport.testProvisioningEnabled`
 *     is true, and MUST return `CAPABILITY_UNAVAILABLE` otherwise;
 *   * a production build MUST report `testProvisioningEnabled: false`, and
 *     conformance B9 asserts no test private key is bundled in an app build.
 */
export interface DeceiptTestProvisioning {
  /** Import the published test device key seed and its credential. Dev builds only. */
  provisionTestMerchant(request: {
    /** 32-byte Ed25519 seed from protocol/vectors/keys/test-keys.json. */
    deviceSeedB64: Base64;
    deviceKeyIdHex: Id16Hex;
    /** Exact COSE_Sign1 credential bytes (trust.md §3 step 2). */
    credentialB64: Base64;
  }): Promise<MerchantKeyStatus>;
  /** Remove test-provisioned key material. */
  clearTestProvisioning(): Promise<void>;
}

// ---------------------------------------------------------------------------
// THE CONTRACT
// ---------------------------------------------------------------------------

/**
 * Every method an A4/A5 adapter must implement, and every event it must emit.
 * Operations are listed in the order a session uses them.
 *
 * Method                      | Valid native states                       | Notes
 * ----------------------------|-------------------------------------------|------
 * capabilities                | any                                       | synchronous truth, no side effects
 * permissionState             | any                                       |
 * requestPermissions          | any                                       | prompts the OS
 * openSettings                | any                                       | deep link for the recovery affordance
 * merchantKeyStatus           | any                                       |
 * merchantKeyGenerate         | any                                       | replaces the existing key
 * merchantKeyDelete           | any                                       |
 * merchantPublicIdentity      | any                                       | public identifiers only
 * merchantSignReceipt         | any                                       | exact-bytes signing, native builds COSE container
 * verifyReceiptContainer      | any                                       | exact-bytes verification, native builds Sig_structure
 * verifyCredential            | any                                       | sub-states preserved
 * randomBytes                 | any                                       | CSPRNG; native-only, never a JS PRNG
 * normalizeNfc                | any                                       | OS NFC (ICU); used when the engine lacks String.prototype.normalize
 * mintBindingQr               | any (merchant)                            | SBT stays native
 * startMerchantSession        | after mintBindingQr                       | GATT server + advertising
 * beginTransfer               | MERCHANT_SESSION_AUTHENTICATED            | after ACCEPT; TransferableSession only
 * startScan                   | any (customer)                            |
 * stopScan                    | SCANNING                                  |
 * startCustomerSession        | after a selection exists                  | connects to the SELECTED peripheral only
 * acceptOffer                 | MERCHANT_SESSION_AUTHENTICATED (customer) | AEAD ACCEPT; TransferableSession only
 * retryTransfer               | TRANSFER                                  |
 * sendReceiptAck              | RECEIPT_UNTRUSTED / AWAITING_STORE        | then disconnect
 * cancelSession               | any active                                |
 * stopSession                 | any active                                | teardown + zeroize
 * sessionSnapshot             | any                                       |
 * subscribe                   | any                                       |
 */
export interface DeceiptNative {
  // --- capabilities & permissions -----------------------------------------
  capabilities(): Promise<CapabilityReport>;
  permissionState(): Promise<PermissionReport>;
  /** Prompts only for the kinds not already granted. */
  requestPermissions(kinds: PermissionKind[]): Promise<PermissionReport>;
  openSettings(target: 'app_permissions' | 'bluetooth'): Promise<void>;

  // --- merchant keys & signing --------------------------------------------
  merchantKeyStatus(): Promise<MerchantKeyStatus>;
  /** Generates a fresh device key in platform storage; returns public identity. */
  merchantKeyGenerate(): Promise<MerchantKeyIdentity>;
  merchantKeyDelete(): Promise<void>;
  merchantPublicIdentity(): Promise<MerchantKeyIdentity | null>;
  /**
   * Signs the exact receipt payload bytes. Native builds
   * `Sig_structure = CBOR(["Signature1", protected_bstr, h'', payload_bstr])`
   * (RFC 9052 §4.4) and returns the full COSE_Sign1 container. TS never builds
   * or re-encodes the signed structure.
   */
  merchantSignReceipt(payloadB64: Base64): Promise<SignedReceipt>;
  /**
   * Verifies Ed25519 over the exact received COSE_Sign1 bytes. MUST fail
   * (`signatureValid: false`) rather than accepting a re-encoded container.
   */
  verifyReceiptContainer(coseSign1B64: Base64, devicePublicKeyB64: Base64): Promise<ReceiptSignatureVerification>;
  /** Credential verification against the pinned anchor set (trust.md §4). */
  verifyCredential(credentialB64: Base64, anchors: TrustAnchor[], nowUnix?: number): Promise<CredentialVerification>;
  /**
   * CSPRNG-backed random bytes, `count` in 1..64, base64 encoded.
   *
   * Native owns this because the identifiers and nonces it produces are protocol
   * SECRETS: `session_id`, `client_nonce`, the ephemeral key material and the
   * session-binding token must come from a real CSPRNG (Android `SecureRandom`,
   * iOS `SecRandomCopyBytes`). Hermes on RN 0.87 has no `globalThis.crypto`, and
   * a JavaScript PRNG is NOT an acceptable substitute — a predictable nonce is a
   * security defect (DESIGN.md §6, invariant 2).
   *
   * The shared layer prefers WebCrypto when it is genuinely present and falls
   * back to this method otherwise; when neither exists it fails closed with
   * `CAPABILITY_UNAVAILABLE` rather than substituting a weaker source.
   */
  randomBytes(count: number): Promise<Base64>;
  /**
   * The OS's own NFC normalization: Android
   * `java.text.Normalizer.normalize(text, Form.NFC)`, iOS
   * `text.precomposedStringWithCanonicalMapping`. Both are ICU-backed.
   *
   * It exists because NFC is a REQUIRED receipt text rule (receipt-v1.md §8,
   * lookalike/bidi defense) and Hermes builds are not guaranteed to have
   * `String.prototype.normalize`. The shared layer uses the engine's normalizer
   * when it has one and this method otherwise, so a receipt is never accepted on
   * an unverified text field. Text in, text out — no base64, because the value
   * is public display data, not bytes.
   *
   * The guarantee is exactness for the Unicode version the OS supports, which is
   * the maintained, vendor-updated set; it is not a claim to carry the newest
   * tables independently of the platform.
   */
  normalizeNfc(text: string): Promise<string>;

  // --- session lifecycle ---------------------------------------------------
  /** Merchant: mint the SBT and build the QR payload. SBT never crosses the bridge. */
  mintBindingQr(request: MintBindingQrRequest): Promise<MintBindingQrResponse>;
  /** Merchant: start the GATT server, advertise the service UUID, await ClientHello. */
  startMerchantSession(request: StartMerchantSessionRequest): Promise<SessionSnapshot>;
  /**
   * Merchant: begin streaming `TRANSFER_BEGIN` + DATA frames. The caller must
   * hold a `TransferableSession`; a `SessionKeysOnly` handle is refused with
   * `PEER_NOT_AUTHENTICATED`.
   */
  beginTransfer(sessionHandle: SessionHandle, session?: TransferableSession): Promise<void>;

  /** Customer: start scanning for the Deceipt Transfer Service UUID. */
  startScan(): Promise<void>;
  stopScan(): Promise<void>;
  /**
   * Customer: connect to the one user-selected target and run ClientHello →
   * ServerHello → binding → credential → transcript verification. MUST connect
   * to the selected target only; never re-target on failure.
   */
  startCustomerSession(request: StartCustomerSessionRequest): Promise<SessionSnapshot>;
  /**
   * Customer: send `ACCEPT` (AEAD). The parameter type excludes
   * `SessionKeysOnly` at compile time; adapters MUST also refuse it at runtime
   * with `PEER_NOT_AUTHENTICATED`.
   */
  acceptOffer(session: TransferableSession): Promise<void>;
  /** Either role: request retransmission from a sequence (AEAD `RETRY`). */
  retryTransfer(sessionHandle: SessionHandle, fromSequence: number): Promise<void>;
  /** Customer: acknowledge the stored outcome, then disconnect (AEAD `RECEIPT_ACK`). */
  sendReceiptAck(
    session: TransferableSession,
    receiptIdHex: Id16Hex,
    outcome: ReceiptAckOutcome,
  ): Promise<void>;
  /** Either role: send `CANCEL` if keys exist, otherwise disconnect. No receipt is stored. */
  cancelSession(sessionHandle: SessionHandle, reason?: TeardownReason): Promise<void>;
  /** Either role: teardown, zeroize keys/buffers, drop the session record. */
  stopSession(sessionHandle: SessionHandle): Promise<void>;
  sessionSnapshot(sessionHandle: SessionHandle): Promise<SessionSnapshot>;

  // --- events --------------------------------------------------------------
  /**
   * Batched event subscription. The adapter MUST coalesce events and deliver
   * them in batches (at most one batch per animation frame / 16 ms), and MUST
   * deliver exactly one byte-carrying event per logical protocol object —
   * NEVER one event per BLE fragment.
   */
  subscribe(listener: DeceiptEventListener): () => void;
}

/** Resolved native bridge: the contract plus the gated test entry points. */
export interface DeceiptNativeWithTestProvisioning extends DeceiptNative {
  testProvisioning: DeceiptTestProvisioning;
}

// ---------------------------------------------------------------------------
// Runtime guards (used by the shared app; adapters MUST enforce these too)
// ---------------------------------------------------------------------------

export function isBridgeError(value: unknown): value is BridgeError {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Partial<BridgeError>;
  return (
    typeof candidate.name === 'string' &&
    typeof candidate.code === 'number' &&
    typeof candidate.fatal === 'boolean' &&
    typeof candidate.retryable === 'boolean'
  );
}
