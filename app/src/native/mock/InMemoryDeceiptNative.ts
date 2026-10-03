/**
 * A mock implementation of `DeceiptNative` so the shared logic, the checkout
 * state machine and the UI run end to end without hardware
 * (Deceipt_Subagent_Delegation_Plan.md §2/A3.6).
 *
 * Two instances — a merchant and a customer — are linked by `linkMockPeers`,
 * which carries LPdu fragments and DataFrame bytes over an in-process radio.
 * `MockRadio` is where fault injection lives: drop a frame, duplicate it,
 * reorder it, flip a byte, or substitute a whole control envelope. That is what
 * lets the shared test suite exercise the adversarial rows of conformance.md §E
 * without two phones.
 *
 * What the mock does NOT model — and therefore what still needs hardware:
 * real BLE timing and MTU negotiation, Core Bluetooth / Android advertising,
 * Keychain / Keystore storage and its accessibility behaviour, genuine
 * process-death recovery, and the real P-256 ECDH + HKDF + AES-GCM schedule
 * (the mock uses identity sealing so the *flow* is testable; the crypto bytes
 * are A4/A5's, verified against `protocol/vectors/aead-valid.json`).
 */

import {GATT, MESSAGE_TYPES, PROTOCOL_VERSION, SUITE_ID, TIMEOUTS_MS, maxFramePayloadForMtu} from '../../protocol/constants';
import {
  RECEIPT_ACK_OUTCOME,
  type TransferableSession,
  type Base64,
  type CapabilityReport,
  type CredentialVerification,
  type DeceiptEvent,
  type DeceiptEventListener,
  type DeceiptNative,
  type MerchantKeyIdentity,
  type MerchantKeyStatus,
  type MintBindingQrRequest,
  type MintBindingQrResponse,
  type OfferMetadata,
  type PermissionKind,
  type PermissionReport,
  type ReceiptAckOutcome,
  type ReceiptSignatureVerification,
  type SessionAuthenticated,
  type SessionHandle,
  type SessionKeysOnly,
  type SessionSnapshot,
  type SessionUnverifiedPeer,
  type SignedReceipt,
  type StartCustomerSessionRequest,
  type StartMerchantSessionRequest,
  type TrustAnchor,
} from '../DeceiptNative';
import {DeceiptBridgeError} from '../bridgeError';
import {ProtocolError, type ProtocolErrorName} from '../../protocol/errors';
import {
  base64Decode,
  base64Encode,
  bytesEqual,
  hexDecode,
  hexEncode,
} from '../../protocol/bytes';
import {CborMap, encodeCbor} from '../../protocol/cbor';
import {
  assertQrFresh,
  bindingProofMessage,
  computeBindingTupleDigest,
  encodeBindingQr,
  parseBindingQr,
  type BindingQrPayload,
} from '../../protocol/binding';
import {
  COSE_ALG_EDDSA,
  COSE_LABEL_ALG,
  COSE_LABEL_CONTENT_TYPE,
  COSE_LABEL_KID,
  CREDENTIAL_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  buildTranscript,
  checkProtectedHeader,
  parseCoseSign1,
  sigStructure,
  verifyCredential,
} from '../../protocol/handshake';
import {
  ed25519PublicKeyFromTestSeed,
  ed25519SignWithTestSeed,
  ed25519Verify,
  hmacSha256,
  randomBytes,
  sha256,
} from '../../protocol/crypto';
import {
  FrameReceiver,
  LpduReceiver,
  decodeControlMessage,
  encodeAeadEnvelope,
  encodeControlMessage,
  decodeBindingTuple,
  encodePlaintextEnvelope,
  parseAeadEnvelope,
  segmentLpdu,
  splitIntoFrames,
  type ClientHello,
  type ControlMessage,
  type DataFrame,
  type ReceiptOffer,
  type ServerHello,
  type TransferBegin,
} from '../../protocol/wire';
import {buildReceiptOfferFromReceipt, offerHashFromOfferMetadata} from '../offer';

/** Test-only merchant provisioning: seed, key id, credential and public key. */
export interface MockMerchantProvision {
  deviceSeed: Uint8Array;
  deviceKeyId: Uint8Array;
  credentialBytes: Uint8Array;
  merchantId: Uint8Array;
  devicePublicKey: Uint8Array;
}

/**
 * The in-process radio. Each hook may return `null` to drop the item, or a
 * different byte string to substitute it.
 */
export interface MockRadio {
  /** Drop or replace an outgoing DataFrame. */
  outboundFrame?(fromHandle: SessionHandle, frame: DataFrame): DataFrame | null;
  /** Drop or replace an outgoing LPdu fragment. */
  outboundFragment?(fromHandle: SessionHandle, fragment: Uint8Array): Uint8Array | null;
  /** Observe a reassembled control message on the receiving side. */
  inboundControl?(toHandle: SessionHandle, direction: 'c2m' | 'm2c', message: Uint8Array): Uint8Array | null;
  /**
   * Flip the last byte of the final DataFrame. That byte is always inside the
   * COSE_Sign1 signature, so the container still parses and the payload is
   * unchanged: only the Ed25519 check can catch it (conformance E5).
   */
  tamperFinalFrameByte?: boolean;
}

export interface MockNativeOptions {
  platform?: 'ios' | 'android';
  provision?: MockMerchantProvision;
  now?: () => number;
  capabilities?: Partial<CapabilityReport>;
}

interface MerchantSession {
  handle: SessionHandle;
  bindingRef: string;
  sessionId: Uint8Array;
  transferId: Uint8Array;
  receiptId: Uint8Array;
  offerHash: Uint8Array;
  sbt: Uint8Array;
  expiresAtUnix: number;
  claimCount: number;
  accepts: number;
  ciphertext: Uint8Array;
  frameSize: number;
  offerIdentity: {merchantReference: string; totalAmountMinor: number; currency: string; issuedAt: number; kind: 1 | 2 | 3} | null;
}

interface CustomerSession {
  handle: SessionHandle;
  sessionId: Uint8Array | null;
  sbt: Uint8Array | null;
  qrOfferHash: Uint8Array | null;
  expiresAtUnix: number;
  /** The client's own ClientHello inputs, needed to rebuild the transcript. */
  clientNonce: Uint8Array;
  clientEphemeralPubkey: Uint8Array;
  clientMaxFramePayload: number;
  frameSize: number;
  frameCount: number;
  frameReceiver: FrameReceiver | null;
  transferId: Uint8Array | null;
  offer: OfferMetadata | null;
  keysOnly: SessionKeysOnly | null;
  authenticated: SessionAuthenticated | null;
  unverifiedPeer: SessionUnverifiedPeer | null;
  ciphertext: Uint8Array | null;
  /** Deferred `SERVER_HELLO` state: keys derived, signature not yet checked. */
  serverHello: ServerHello | null;
  pendingCredential: CredentialVerification | null;
  pendingDevicePublicKey: Uint8Array | null;
  credentialBytes: Uint8Array | null;
}

export class InMemoryDeceiptNative implements DeceiptNative {
  private readonly listeners = new Set<DeceiptEventListener>();
  private pending: DeceiptEvent[] = [];
  private flushScheduled = false;
  private readonly now: () => number;
  private readonly capabilityOverrides: Partial<CapabilityReport>;
  private merchantKey: MerchantKeyIdentity | null = null;
  private provision: MockMerchantProvision | undefined;
  private permission: PermissionReport = {bluetooth: 'granted', camera: 'granted', bluetoothState: 'on'};
  private merchant: MerchantSession | null = null;
  private customer: CustomerSession | null = null;
  private readonly candidates: Array<{peripheralId: string; label: string; sessionIdHex?: string}> = [];
  private peer: InMemoryDeceiptNative | null = null;
  private radio: MockRadio | null = null;
  private lpdu: LpduReceiver | null = null;
  private counterC2m = 0;
  private counterM2c = 0;
  private msgSeq = 0;
  private teardownReason = 'completed';
  private anchors: TrustAnchor[] = [];
  private lastError: ProtocolError | null = null;

  constructor(options: MockNativeOptions = {}) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.capabilityOverrides = options.capabilities ?? {};
    if (options.provision !== undefined) {
      this.setProvision(options.provision);
    }
  }

  // --- test wiring ---------------------------------------------------------

  private setProvision(provision: MockMerchantProvision): void {
    this.provision = provision;
    this.merchantKey = {
      deviceKeyIdHex: hexEncode(provision.deviceKeyId),
      devicePublicKeyB64: base64Encode(provision.devicePublicKey),
      storage: 'keychain_software',
      createdAtMs: Date.now(),
    };
  }

  link(peer: InMemoryDeceiptNative, radio: MockRadio | null = null): void {
    this.peer = peer;
    this.radio = radio;
  }

  /**
   * Register a scannable peripheral. `sessionIdHex` is what the terminal
   * claims to serve; two candidates claiming the same scanned session is the
   * clone/impostor case that fails closed under r3.
   */
  advertiseCandidate(peripheralId: string, sessionIdHex?: string, label = peripheralId.slice(0, 8)): void {
    this.candidates.push({peripheralId, label, sessionIdHex});
  }

  /** Inject an arbitrary event (used to drive permission/Bluetooth failure UX). */
  emitExternal(event: DeceiptEvent): void {
    this.emit(event);
  }

  setAnchors(anchors: TrustAnchor[]): void {
    this.anchors = anchors;
  }

  setPermissionState(permission: PermissionReport): void {
    this.permission = permission;
    this.emit({type: 'permission_changed', permissions: permission});
    if (permission.bluetoothState !== 'on') {
      this.emit({type: 'bluetooth_state_changed', state: permission.bluetoothState});
    }
  }

  /** The last typed failure this endpoint produced, for assertions. */
  lastProtocolError(): ProtocolError | null {
    return this.lastError;
  }

  // --- capabilities & permissions -----------------------------------------

  async capabilities(): Promise<CapabilityReport> {
    const base: CapabilityReport = {
      platform: this.capabilityOverrides.platform ?? 'ios',
      bleCentral: true,
      blePeripheral: true,
      bleAdvertising: true,
      protocolVersion: PROTOCOL_VERSION,
      suiteIds: [SUITE_ID],
      ed25519: true,
      ed25519Keystore: this.merchantKey !== null,
      ed25519HardwareBacked: false,
      keyPersistence: true,
      cameraQrScan: true,
      testProvisioningEnabled: this.provision !== undefined,
      adapterBuild: 'mock-0.1.0',
    };
    return {...base, ...this.capabilityOverrides};
  }

  async permissionState(): Promise<PermissionReport> {
    return this.permission;
  }

  async requestPermissions(kinds: PermissionKind[]): Promise<PermissionReport> {
    if (kinds.includes('bluetooth') && this.permission.bluetooth === 'undetermined') {
      this.permission = {...this.permission, bluetooth: 'granted'};
    }
    if (kinds.includes('camera') && this.permission.camera === 'undetermined') {
      this.permission = {...this.permission, camera: 'granted'};
    }
    this.emit({type: 'permission_changed', permissions: this.permission});
    return this.permission;
  }

  async openSettings(): Promise<void> {
    // The mock has no OS settings pane to open.
  }

  // --- merchant keys & signing --------------------------------------------

  async merchantKeyStatus(): Promise<MerchantKeyStatus> {
    if (this.merchantKey === null || this.provision === undefined) {
      return {provisioned: false};
    }
    return {
      provisioned: true,
      identity: this.merchantKey,
      credentialB64: base64Encode(this.provision.credentialBytes),
      merchantIdHex: hexEncode(this.provision.merchantId),
    };
  }

  async merchantKeyGenerate(): Promise<MerchantKeyIdentity> {
    const seed = randomBytes(32);
    const publicKey = await ed25519PublicKeyFromTestSeed(seed);
    const identity: MerchantKeyIdentity = {
      deviceKeyIdHex: hexEncode(randomBytes(16)),
      devicePublicKeyB64: base64Encode(publicKey),
      storage: 'in_memory_ephemeral',
      createdAtMs: Date.now(),
    };
    this.merchantKey = identity;
    return identity;
  }

  async merchantKeyDelete(): Promise<void> {
    this.merchantKey = null;
    this.provision = undefined;
  }

  async merchantPublicIdentity(): Promise<MerchantKeyIdentity | null> {
    return this.merchantKey;
  }

  async merchantSignReceipt(payloadB64: Base64): Promise<SignedReceipt> {
    if (this.merchantKey === null || this.provision === undefined) {
      throw this.bridge(new ProtocolError('CAPABILITY_UNAVAILABLE', 'no merchant key is provisioned'));
    }
    const payload = base64Decode(payloadB64);
    const protectedMap = CborMap.of([
      [COSE_LABEL_ALG, COSE_ALG_EDDSA],
      [COSE_LABEL_CONTENT_TYPE, RECEIPT_CONTENT_TYPE],
      [COSE_LABEL_KID, this.provision.deviceKeyId],
    ]);
    const protectedBytes = encodeCbor(protectedMap);
    const signature = await ed25519SignWithTestSeed(this.provision.deviceSeed, sigStructure(protectedBytes, payload));
    const container = encodeCbor([protectedBytes, CborMap.of([]), payload, signature]);
    return {
      coseSign1B64: base64Encode(container),
      signatureB64: base64Encode(signature),
      protectedB64: base64Encode(protectedBytes),
      deviceKeyIdHex: this.merchantKey.deviceKeyIdHex,
    };
  }

  async verifyReceiptContainer(coseSign1B64: Base64, devicePublicKeyB64: Base64): Promise<ReceiptSignatureVerification> {
    try {
      const container = parseCoseSign1(base64Decode(coseSign1B64));
      const kid = container.protectedMap.get(COSE_LABEL_KID);
      const valid = await ed25519Verify(
        base64Decode(devicePublicKeyB64),
        sigStructure(container.protectedBstr, container.payload),
        container.signature,
      );
      return {signatureValid: valid, deviceKeyIdHex: kid instanceof Uint8Array ? hexEncode(kid) : undefined};
    } catch (error) {
      return {signatureValid: false, error: this.bridge(error).bridge};
    }
  }

  /**
   * MOCK ONLY: a deterministic, clearly-labelled test PRNG.
   *
   * It exists so the shared flow is reproducible in tests. It is NOT a CSPRNG
   * and MUST NOT be mistaken for one: the real adapters use SecureRandom /
   * SecRandomCopyBytes, and the shared layer never substitutes this.
   */
  async randomBytes(count: number): Promise<Base64> {
    if (!Number.isInteger(count) || count < 1 || count > 64) {
      throw new ProtocolError('CAPABILITY_UNAVAILABLE', `randomBytes count ${count} is outside 1..64`);
    }
    return base64Encode(nextMockRandom(count));
  }

  async verifyCredential(credentialB64: Base64, anchors: TrustAnchor[], nowUnix?: number): Promise<CredentialVerification> {
    const check = await verifyCredential(base64Decode(credentialB64), anchors, nowUnix ?? this.now());
    return {
      trust: check.trust === 'authenticated' ? 'authenticated' : 'unknown_issuer',
      signatureValid: check.signatureValid,
      temporallyAcceptable: check.temporallyAcceptable,
      merchantIdHex: check.body === null ? undefined : hexEncode(check.body.merchantId),
      deviceKeyIdHex: check.body === null ? undefined : hexEncode(check.body.deviceKeyId),
      devicePublicKeyB64: check.body === null ? undefined : base64Encode(check.body.devicePublicKey),
      capabilities: check.body?.capabilities,
      merchantReference: check.body?.merchantReference,
      displayName: check.body?.displayName,
      error: check.error === null ? undefined : this.bridge(errorName(check.error)).bridge,
    };
  }

  // --- merchant session ----------------------------------------------------

  async mintBindingQr(request: MintBindingQrRequest): Promise<MintBindingQrResponse> {
    const sessionId = hexDecode(request.sessionIdHex);
    const sbt = randomBytes(16);
    const bindingRef = `binding-${hexEncode(randomBytes(8))}`;
    const payload: BindingQrPayload = {
      qrFormatVersion: 1,
      sessionId,
      sessionBindingToken: sbt,
      offerHash: hexDecode(request.offerHashHex),
      expiresAtUnix: request.expiresAtUnix,
    };
    this.merchant = {
      handle: bindingRef,
      bindingRef,
      sessionId,
      transferId: new Uint8Array(0),
      receiptId: new Uint8Array(0),
      offerHash: hexDecode(request.offerHashHex),
      sbt,
      expiresAtUnix: request.expiresAtUnix,
      claimCount: 0,
      accepts: 0,
      ciphertext: new Uint8Array(0),
      frameSize: 162,
      offerIdentity: null,
    };
    return {
      bindingRef,
      qrPayload: encodeBindingQr(payload),
      sessionIdHex: request.sessionIdHex,
      expiresAtUnix: request.expiresAtUnix,
    };
  }

  async startMerchantSession(request: StartMerchantSessionRequest): Promise<SessionSnapshot> {
    const session = this.merchant;
    if (session === null || session.bindingRef !== request.bindingRef) {
      throw this.bridge(new ProtocolError('BINDING_UNKNOWN_SESSION', 'no binding was minted for this reference'));
    }
    if (this.merchantKey === null || this.provision === undefined) {
      throw this.bridge(new ProtocolError('CAPABILITY_UNAVAILABLE', 'merchant mode needs a provisioned key'));
    }
    session.transferId = hexDecode(request.transferIdHex);
    session.receiptId = hexDecode(request.receiptIdHex);
    session.offerHash = hexDecode(request.offerHashHex);
    session.ciphertext = base64Decode(request.receiptCose1B64);
    session.frameSize = request.frameSize ?? maxFramePayloadForMtu(185);
    session.claimCount = 0;
    session.accepts = 0;
    session.offerIdentity = buildReceiptOfferFromReceipt(session.ciphertext);
    this.teardownReason = 'completed';
    this.emit({type: 'advertising_started', sessionHandle: session.handle, serviceUuid: GATT.serviceUuid});
    return this.snapshotOfMerchant('ADVERTISING');
  }

  async beginTransfer(sessionHandle: SessionHandle, peerSession?: TransferableSession): Promise<void> {
    void peerSession;
    const session = this.merchant;
    if (session === null || session.handle !== sessionHandle) {
      throw this.bridge(new ProtocolError('SESSION_TORN_DOWN', 'merchant session is not active'));
    }
    if (this.peer === null) {
      throw this.bridge(new ProtocolError('TRANSPORT_LINK_LOST', 'no peer is linked'));
    }
    if (session.accepts === 0) {
      throw this.bridge(new ProtocolError('PEER_NOT_AUTHENTICATED', 'ACCEPT has not been received'));
    }
    const frames = splitIntoFrames(session.ciphertext, session.transferId, session.frameSize);
    const payloadHash = await sha256(session.ciphertext);
    const begin: TransferBegin = {
      type: 19,
      transferId: session.transferId,
      ciphertextLength: session.ciphertext.length,
      payloadHash,
      frameSize: session.frameSize,
      frameCount: frames.length,
    };
    this.emit({
      type: 'transfer_started',
      sessionHandle,
      ciphertextLength: session.ciphertext.length,
      frameCount: frames.length,
      frameSize: session.frameSize,
      payloadHashHex: hexEncode(payloadHash),
    });
    await this.sendControl(sessionHandle, 'm2c', begin);
    for (const [index, frame] of frames.entries()) {
      let outbound = this.radio?.outboundFrame?.(sessionHandle, frame) ?? frame;
      if (outbound !== null && this.radio?.tamperFinalFrameByte === true && index === frames.length - 1) {
        const payload = new Uint8Array(outbound.payload);
        payload[payload.length - 1] ^= 0x01;
        outbound = {...outbound, payload};
      }
      if (outbound !== null) {
        await this.peer.receiveFrame(outbound);
      }
    }
  }

  // --- customer session ----------------------------------------------------

  async startScan(): Promise<void> {
    this.emit({type: 'scan_started'});
    for (const candidate of this.candidates) {
      this.emit({
        type: 'peer_candidate',
        peripheralId: candidate.peripheralId,
        serviceUuid: GATT.serviceUuid,
        protocolVersion: PROTOCOL_VERSION,
        sessionIdHex: candidate.sessionIdHex,
        deterministicLabel: candidate.label,
        diagnostics: {diagnosticsOnly: true},
      });
    }
  }

  async stopScan(): Promise<void> {
    this.emit({type: 'scan_stopped', reason: 'user_cancelled'});
  }

  async startCustomerSession(request: StartCustomerSessionRequest): Promise<SessionSnapshot> {
    if (this.permission.bluetoothState !== 'on') {
      throw this.bridge(new ProtocolError('TRANSPORT_BLUETOOTH_OFF', 'Bluetooth is off'));
    }
    if (this.permission.bluetooth !== 'granted') {
      throw this.bridge(new ProtocolError('TRANSPORT_PERMISSION_DENIED', 'Bluetooth permission is not granted'));
    }
    if (this.peer === null || this.peer.merchant === null) {
      throw this.bridge(new ProtocolError('BINDING_UNKNOWN_SESSION', 'no merchant is listening'));
    }
    const handle = `customer-${hexEncode(randomBytes(8))}`;
    let sessionId: Uint8Array | null = null;
    let sbt: Uint8Array | null = null;
    let qrOfferHash: Uint8Array | null = null;
    let expiresAtUnix = this.now() + Math.floor(TIMEOUTS_MS.T_BINDING_QR / 1000);
    if (request.selection.kind === 'qr') {
      const qr = parseBindingQr(request.selection.qrPayload);
      assertQrFresh(qr, this.now());
      sessionId = qr.sessionId;
      sbt = qr.sessionBindingToken;
      qrOfferHash = qr.offerHash;
      expiresAtUnix = qr.expiresAtUnix;
    }
    const session: CustomerSession = {
      handle,
      sessionId,
      sbt,
      qrOfferHash,
      expiresAtUnix,
      clientNonce: randomBytes(32),
      clientEphemeralPubkey: validLookingPoint(),
      clientMaxFramePayload: request.clientMaxFramePayload ?? maxFramePayloadForMtu(185),
      frameSize: request.clientMaxFramePayload ?? maxFramePayloadForMtu(185),
      frameCount: 0,
      frameReceiver: null,
      transferId: null,
      offer: null,
      keysOnly: null,
      authenticated: null,
      unverifiedPeer: null,
      ciphertext: null,
      serverHello: null,
      pendingCredential: null,
      pendingDevicePublicKey: null,
      credentialBytes: null,
    };
    this.customer = session;
    this.anchors = request.anchors;
    // The QR names the session; the peripheral id is whatever the adapter
    // resolved that session to while scanning.
    this.emit({type: 'connected', sessionHandle: handle, peripheralId: 'qr-selected', attMtu: 185});
    this.emit({type: 'handshake_started', sessionHandle: handle, role: 'customer'});
    const proof =
      sbt === null
        ? randomBytes(32)
        : await hmacSha256(sbt, bindingProofMessage(session.clientNonce, session.clientEphemeralPubkey));
    const hello: ClientHello = {
      type: 1,
      protocolVersion: PROTOCOL_VERSION,
      cryptosuites: [SUITE_ID],
      sessionId: sessionId ?? randomBytes(16),
      clientNonce: session.clientNonce,
      clientEphemeralPubkey: session.clientEphemeralPubkey,
      bindingProof: proof,
      maxFramePayload: session.clientMaxFramePayload,
    };
    await this.sendControl(handle, 'c2m', hello);
    return this.snapshotOfCustomer();
  }

  async acceptOffer(session: TransferableSession): Promise<void> {
    const current = this.customer;
    if (current === null || current.handle !== session.sessionHandle) {
      throw this.bridge(new ProtocolError('SESSION_TORN_DOWN', 'no customer session for this handle'));
    }
    await this.sendControl(session.sessionHandle, 'c2m', {
      type: MESSAGE_TYPES.ACCEPT,
      transferId: current.transferId ?? new Uint8Array(16),
      protocolVersion: PROTOCOL_VERSION,
      suiteId: SUITE_ID,
    });
    this.emit({type: 'offer_accepted', sessionHandle: session.sessionHandle});
  }

  async retryTransfer(): Promise<void> {
    // The mock streams one pass; explicit retry has nothing to resend.
  }

  async sendReceiptAck(session: TransferableSession, receiptIdHex: string, outcome: ReceiptAckOutcome): Promise<void> {
    await this.sendControl(session.sessionHandle, 'c2m', {
      type: MESSAGE_TYPES.RECEIPT_ACK,
      transferId: this.customer?.transferId ?? new Uint8Array(16),
      receiptId: hexDecode(receiptIdHex),
      outcome: RECEIPT_ACK_OUTCOME[outcome],
    });
    this.emit({
      type: 'receipt_ack_sent',
      sessionHandle: session.sessionHandle,
      receiptIdHex,
      outcomeCode: RECEIPT_ACK_OUTCOME[outcome],
    });
    await this.stopSession(session.sessionHandle);
  }

  async cancelSession(sessionHandle: SessionHandle): Promise<void> {
    this.teardownReason = 'user_cancelled';
    const transferId = this.customer?.transferId ?? this.merchant?.transferId;
    await this.sendControl(sessionHandle, this.customer === null ? 'm2c' : 'c2m', {
      type: MESSAGE_TYPES.CANCEL,
      transferId,
      errorCode: 0x050b,
    });
    await this.stopSession(sessionHandle);
  }

  async stopSession(sessionHandle: SessionHandle): Promise<void> {
    if (this.merchant?.handle === sessionHandle) {
      this.emit({type: 'advertising_stopped', sessionHandle, reason: this.teardownReason as never});
      this.merchant = null;
    }
    if (this.customer?.handle === sessionHandle) {
      this.customer = null;
    }
    this.lpdu = null;
    this.emit({type: 'session_torn_down', sessionHandle, reason: this.teardownReason as never});
  }

  async sessionSnapshot(sessionHandle: SessionHandle): Promise<SessionSnapshot> {
    if (this.merchant?.handle === sessionHandle) {
      return this.snapshotOfMerchant(this.merchant.accepts > 0 ? 'TRANSFER' : 'ADVERTISING');
    }
    if (this.customer?.handle === sessionHandle) {
      return this.snapshotOfCustomer();
    }
    throw this.bridge(new ProtocolError('SESSION_TORN_DOWN', 'unknown session handle'));
  }

  subscribe(listener: DeceiptEventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // --- peer-facing entry points -------------------------------------------

  async receiveFragment(fragment: Uint8Array): Promise<void> {
    this.lpdu = this.lpdu ?? new LpduReceiver();
    const pdu = this.lpdu.push(fragment);
    if (pdu === null) {
      return;
    }
    // Direction is the *sender's* direction: a merchant endpoint receives
    // customer-to-merchant traffic, and vice versa.
    const inbound: 'c2m' | 'm2c' = this.merchant !== null ? 'c2m' : 'm2c';
    if (pdu[0] === 0x00) {
      await this.receiveControlBytes(inbound, pdu.subarray(1));
      return;
    }
    const counter = inbound === 'c2m' ? this.counterC2m++ : this.counterM2c++;
    const envelope = parseAeadEnvelope(pdu, counter);
    await this.receiveControlBytes(inbound, envelope.ciphertext);
  }

  private async receiveControlBytes(direction: 'c2m' | 'm2c', bytes: Uint8Array): Promise<void> {
    const substituted = this.radio?.inboundControl?.(this.handle(), direction, bytes) ?? bytes;
    if (substituted === null) {
      return;
    }
    const decoded = decodeControlMessage(substituted, PROTOCOL_VERSION);
    if (direction === 'c2m') {
      await this.handleClientMessage(decoded);
    } else {
      await this.handleServerMessage(decoded);
    }
  }

  async receiveFrame(frame: DataFrame): Promise<void> {
    const session = this.customer;
    if (session === null || session.frameReceiver === null) {
      return;
    }
    const status = session.frameReceiver.push(frame);
    this.emit({
      type: 'transfer_progress',
      sessionHandle: session.handle,
      highestContiguousSequence: status.highestContiguousSequence,
      frameCount: session.frameCount,
      notices: session.frameReceiver.notices.splice(0) as ProtocolErrorName[],
    });
    if (!status.complete) {
      return;
    }
    const ciphertext = session.frameReceiver.reassemble();
    session.ciphertext = ciphertext;
    const hash = await sha256(ciphertext);
    this.emit({
      type: 'transfer_complete',
      sessionHandle: session.handle,
      frameCount: session.frameCount,
      payloadHashHex: hexEncode(hash),
    });
    // Real AEAD open is native; the mock enters RECEIPT_UNTRUSTED with the
    // reassembled bytes and never claims trust (invariant 2).
    this.emit({
      type: 'receipt_received',
      sessionHandle: session.handle,
      state: 'RECEIPT_UNTRUSTED',
      coseSign1B64: base64Encode(ciphertext),
      payloadSha256Hex: hexEncode(hash),
      ciphertextLength: ciphertext.length,
    });
  }

  // --- internals -----------------------------------------------------------

  private handle(): SessionHandle {
    return this.customer?.handle ?? this.merchant?.handle ?? '';
  }

  private async sendControl(sessionHandle: SessionHandle, direction: 'c2m' | 'm2c', message: ControlMessage): Promise<void> {
    const target = this.peer;
    if (target === null) {
      return;
    }
    const bytes = encodeControlMessage(message);
    const isPlaintextHandshake = message.type === MESSAGE_TYPES.CLIENT_HELLO || message.type === MESSAGE_TYPES.SERVER_HELLO;
    const envelope = isPlaintextHandshake
      ? encodePlaintextEnvelope(bytes)
      : encodeAeadEnvelope({
          counter: direction === 'm2c' ? this.counterM2c++ : this.counterC2m++,
          ciphertext: bytes,
        });
    this.msgSeq += 1;
    for (const fragment of segmentLpdu(envelope, 182, this.msgSeq)) {
      const outbound = this.radio?.outboundFragment?.(sessionHandle, fragment) ?? fragment;
      if (outbound !== null) {
        await target.receiveFragment(outbound);
      }
    }
  }

  private async handleClientMessage(message: ControlMessage): Promise<void> {
    const session = this.merchant;
    if (session === null) {
      return;
    }
    if (message.type === MESSAGE_TYPES.CLIENT_HELLO) {
      await this.handleClientHello(message);
      return;
    }
    if (message.type === MESSAGE_TYPES.ACCEPT) {
      session.accepts += 1;
      return;
    }
    if (message.type === MESSAGE_TYPES.RECEIPT_ACK || message.type === MESSAGE_TYPES.CANCEL) {
      this.teardownReason = message.type === MESSAGE_TYPES.RECEIPT_ACK ? 'completed' : 'user_cancelled';
    }
  }

  private async handleClientHello(hello: ClientHello): Promise<void> {
    const session = this.merchant;
    if (session === null || this.provision === undefined) {
      return;
    }
    // A2 §3.7 merchant-side binding check, in the frozen order.
    if (!bytesEqual(hello.sessionId, session.sessionId)) {
      this.fail(new ProtocolError('BINDING_UNKNOWN_SESSION', 'no live session for that session_id'));
      return;
    }
    if (this.now() >= session.expiresAtUnix) {
      this.emit({
        type: 'binding_stale',
        sessionHandle: session.handle,
        sessionIdHex: hexEncode(session.sessionId),
        expiredAtUnix: session.expiresAtUnix,
      });
      return;
    }
    if (session.claimCount > 0) {
      this.emit({type: 'binding_consumed', sessionHandle: session.handle, sessionIdHex: hexEncode(session.sessionId)});
      return;
    }
    const expected = await hmacSha256(session.sbt, bindingProofMessage(hello.clientNonce, hello.clientEphemeralPubkey));
    if (!bytesEqual(expected, hello.bindingProof)) {
      this.fail(new ProtocolError('BINDING_PROOF_INVALID', 'binding proof HMAC mismatch'));
      return;
    }
    session.claimCount += 1;
    this.lpdu = null;

    const serverNonce = randomBytes(32);
    const serverEphemeralPubkey = validLookingPoint();
    const tuple = encodeCbor([1, session.sessionId, session.transferId, session.receiptId, session.offerHash]);
    const digest = await computeBindingTupleDigest(tuple);
    const transcript = buildTranscript({
      protocolVersion: PROTOCOL_VERSION,
      suiteId: SUITE_ID,
      clientNonce: hello.clientNonce,
      clientEphemeralPubkey: hello.clientEphemeralPubkey,
      serverNonce,
      serverEphemeralPubkey,
      transferId: session.transferId,
      sessionId: session.sessionId,
      bindingTupleDigest: digest,
      maxFramePayload: hello.maxFramePayload,
      bindingTuple: tuple,
    });
    const identity = session.offerIdentity;
    if (identity === null) {
      this.fail(new ProtocolError('INTERNAL_ERROR', 'no offer identity was derived'));
      return;
    }
    const signature = await ed25519SignWithTestSeed(this.provision.deviceSeed, transcript);
    const serverHello: ServerHello = {
      type: MESSAGE_TYPES.SERVER_HELLO,
      protocolVersion: PROTOCOL_VERSION,
      suiteId: SUITE_ID,
      transferId: session.transferId,
      serverNonce,
      serverEphemeralPubkey,
      merchantCredential: this.provision.credentialBytes,
      transcriptSignature: signature,
      bindingTupleDigest: digest,
      bindingTuple: tuple,
      maxFramePayload: hello.maxFramePayload,
    };
    await this.sendControl(session.handle, 'm2c', serverHello);
    const offer: ReceiptOffer = {
      type: MESSAGE_TYPES.RECEIPT_OFFER,
      transferId: session.transferId,
      receiptId: session.receiptId,
      merchantReference: identity.merchantReference,
      totalAmountMinor: identity.totalAmountMinor,
      currency: identity.currency,
      issuedAt: identity.issuedAt,
      kind: identity.kind,
      ciphertextLength: session.ciphertext.length,
      merchantId: this.provision.merchantId,
      credentialHash: await sha256(this.provision.credentialBytes),
      sessionId: session.sessionId,
    };
    await this.sendControl(session.handle, 'm2c', offer);
  }

  private async handleServerMessage(message: ControlMessage): Promise<void> {
    const session = this.customer;
    if (session === null) {
      return;
    }
    if (message.type === MESSAGE_TYPES.SERVER_HELLO) {
      session.transferId = message.transferId;
      await this.verifyServerHello(message);
      return;
    }
    if (message.type === MESSAGE_TYPES.RECEIPT_OFFER) {
      const offer = offerMetadata(message);
      session.offer = offer;
      session.frameCount = 0;
      session.frameReceiver = null;
      const authenticated = await this.authenticateWithOffer(offer);
      if (!authenticated) {
        return;
      }
      this.emit({type: 'offer_received', sessionHandle: session.handle, offer});
      return;
    }
    if (message.type === MESSAGE_TYPES.TRANSFER_BEGIN) {
      session.frameCount = message.frameCount;
      session.transferId = message.transferId;
      session.frameReceiver = new FrameReceiver(message.frameCount, message.transferId);
    }
  }

  /**
   * `SERVER_HELLO` handling. Keys are derived immediately (`SessionKeysOnly`),
   * because the AEAD-sealed offer cannot be read without them. The transcript
   * signature is verified in `authenticateWithOffer` once the offer supplies
   * the last binding-tuple member (`receipt_id`), which is the only ordering
   * the frozen transcript permits: the tuple is `[1, session_id, transfer_id,
   * receipt_id, offer_hash]` and the client knows session_id/offer_hash from the
   * QR and transfer_id from this message, but learns receipt_id from the offer.
   */
  private async verifyServerHello(hello: ServerHello): Promise<void> {
    const session = this.customer;
    if (session === null) {
      return;
    }
    session.serverHello = hello;
    const keysOnly: SessionKeysOnly = {kind: 'SessionKeysOnly', sessionHandle: session.handle};
    session.keysOnly = keysOnly;
    this.emit({type: 'session_keys_derived', sessionHandle: session.handle, sessionKeysOnly: keysOnly});

    const check = await verifyCredential(hello.merchantCredential, this.anchors, this.now());
    const credential: CredentialVerification = {
      trust: check.trust === 'authenticated' ? 'authenticated' : 'unknown_issuer',
      signatureValid: check.signatureValid,
      temporallyAcceptable: check.temporallyAcceptable,
      merchantIdHex: check.body === null ? undefined : hexEncode(check.body.merchantId),
      deviceKeyIdHex: check.body === null ? undefined : hexEncode(check.body.deviceKeyId),
      devicePublicKeyB64: check.body === null ? undefined : base64Encode(check.body.devicePublicKey),
      capabilities: check.body?.capabilities,
      displayName: check.body?.displayName,
      merchantReference: check.body?.merchantReference,
      error: check.error === null ? undefined : this.bridge(errorName(check.error)).bridge,
    };
    if (check.body === null) {
      this.fail(new ProtocolError('CREDENTIAL_MALFORMED', 'credential could not be parsed'));
      return;
    }
    if (check.error !== null && check.error !== 'CREDENTIAL_UNKNOWN_ISSUER') {
      this.fail(new ProtocolError(errorName(check.error), 'credential rejected'));
      return;
    }
    session.pendingCredential = {
      trust: credential.trust,
      signatureValid: check.signatureValid,
      temporallyAcceptable: check.temporallyAcceptable,
      merchantIdHex: hexEncode(check.body.merchantId),
      deviceKeyIdHex: hexEncode(check.body.deviceKeyId),
      capabilities: check.body.capabilities,
      displayName: check.body.displayName,
      merchantReference: check.body.merchantReference,
    };
    session.pendingDevicePublicKey = check.body.devicePublicKey;
    session.credentialBytes = hello.merchantCredential;
  }

  /**
   * Verify the merchant's transcript signature now that the offer completed the
   * binding tuple. Only this produces `SessionAuthenticated`, and only an
   * authenticated session may `ACCEPT` (handshake.md §9).
   */
  private async authenticateWithOffer(offer: OfferMetadata): Promise<boolean> {
    const session = this.customer;
    if (session === null || session.serverHello === null || session.pendingCredential === null) {
      return false;
    }
    const serverHello = session.serverHello;
    // Rule 1: label 10 is authoritative over label 9. Recompute the digest from
    // the received tuple bytes and require agreement.
    const tuple = serverHello.bindingTuple;
    const recomputedDigest = await computeBindingTupleDigest(tuple);
    if (!bytesEqual(recomputedDigest, serverHello.bindingTupleDigest)) {
      this.fail(new ProtocolError('HANDSHAKE_TRANSCRIPT_MISMATCH', 'binding tuple digest does not match label 9'));
      return false;
    }
    const tupleFields = decodeBindingTuple(tuple);
    // Rule 4: binding_tuple[1] (session_id) MUST equal CLIENT_HELLO label 4.
    if (session.sessionId !== null && !bytesEqual(tupleFields.sessionId, session.sessionId)) {
      this.fail(new ProtocolError('BINDING_UNKNOWN_SESSION', 'binding tuple session_id is not the scanned session'));
      return false;
    }
    // The offer must reproduce both the tuple's receipt_id/offer_hash and the
    // scanned QR's offer hash.
    if (hexEncode(tupleFields.receiptId) !== offer.receiptIdHex) {
      this.fail(new ProtocolError('WRONG_TRANSACTION', 'the offer receipt_id is not the bound one'));
      return false;
    }
    const recomputedOfferHash = await offerHashFromOfferMetadata(offer);
    if (hexEncode(tupleFields.offerHash) !== recomputedOfferHash) {
      this.fail(new ProtocolError('BINDING_PROOF_INVALID', 'the offer does not reproduce the bound offer hash'));
      return false;
    }
    if (session.qrOfferHash !== null && hexEncode(session.qrOfferHash) !== recomputedOfferHash) {
      this.fail(new ProtocolError('BINDING_PROOF_INVALID', 'the offer does not reproduce the scanned offer hash'));
      return false;
    }
    const transcript = buildTranscript({
      protocolVersion: serverHello.protocolVersion,
      suiteId: serverHello.suiteId,
      clientNonce: session.clientNonce,
      clientEphemeralPubkey: session.clientEphemeralPubkey,
      serverNonce: serverHello.serverNonce,
      serverEphemeralPubkey: serverHello.serverEphemeralPubkey,
      transferId: tupleFields.transferId,
      sessionId: tupleFields.sessionId,
      bindingTupleDigest: serverHello.bindingTupleDigest,
      // Rule 3: the merchant's signed value, never the client's own.
      maxFramePayload: serverHello.maxFramePayload,
      bindingTuple: tuple,
    });
    session.frameSize = serverHello.maxFramePayload;
    const signatureValid = await ed25519Verify(session.pendingDevicePublicKey ?? new Uint8Array(32), transcript, serverHello.transcriptSignature);
    if (!signatureValid) {
      this.fail(new ProtocolError('HANDSHAKE_SIGNATURE_INVALID', 'merchant transcript signature did not verify'));
      return false;
    }
    const credential: CredentialVerification = {...session.pendingCredential};
    const credentialB64 = base64Encode(session.credentialBytes ?? new Uint8Array(0));
    if (credential.trust === 'authenticated') {
      const authenticated: SessionAuthenticated = {
        kind: 'SessionAuthenticated',
        sessionHandle: session.handle,
        merchantIdHex: credential.merchantIdHex ?? '',
        deviceKeyIdHex: credential.deviceKeyIdHex ?? '',
        credentialB64,
        credentialTrust: 'authenticated',
        keyAuthorized: true,
        credentialTemporallyAcceptable: credential.temporallyAcceptable,
      };
      session.authenticated = authenticated;
      this.emit({type: 'session_authenticated', sessionHandle: session.handle, authenticated, credential});
      return true;
    }
    // Unpinned issuer: internal consistency only. May transfer; never trusted.
    const unverifiedPeer: SessionUnverifiedPeer = {
      kind: 'SessionUnverifiedPeer',
      sessionHandle: session.handle,
      merchantIdHex: credential.merchantIdHex ?? '',
      deviceKeyIdHex: credential.deviceKeyIdHex ?? '',
      credentialB64,
      credentialTrust: 'unknown_issuer',
      keyAuthorized: false,
    };
    session.unverifiedPeer = unverifiedPeer;
    this.emit({type: 'session_unverified_peer', sessionHandle: session.handle, unverifiedPeer, credential});
    return true;
  }


  private fail(error: ProtocolError): void {
    this.lastError = error;
    this.emit({type: 'error', error: this.bridge(error).bridge, sessionHandle: this.handle() || undefined});
  }

  /** Non-fatal notices (e.g. FRAME_SEQUENCE_REPLAYED) surfaced by the adapter. */
  private notices: ProtocolErrorName[] = [];

  private snapshotOfMerchant(state: SessionSnapshot['state']): SessionSnapshot {
    const session = this.merchant;
    return {
      sessionHandle: session?.handle ?? '',
      role: 'merchant',
      state,
      authenticated: (session?.accepts ?? 0) > 0,
      transferIdHex: session === undefined || session === null ? undefined : hexEncode(session.transferId),
      sessionIdHex: session === null ? undefined : hexEncode(session.sessionId),
      attMtu: 185,
      frameSize: session?.frameSize,
    };
  }

  private snapshotOfCustomer(): SessionSnapshot {
    const session = this.customer;
    return {
      sessionHandle: session?.handle ?? '',
      role: 'customer',
      state: session?.authenticated == null ? 'HANDSHAKE' : 'MERCHANT_SESSION_AUTHENTICATED',
      authenticated: session?.authenticated != null,
      transferIdHex: session?.transferId === null || session?.transferId === undefined ? undefined : hexEncode(session.transferId),
      attMtu: 185,
      frameSize: session?.frameSize,
      frameCount: session?.frameCount,
    };
  }

  private emit(event: DeceiptEvent): void {
    this.pending.push(event);
    if (this.flushScheduled) {
      return;
    }
    this.flushScheduled = true;
    queueMicrotask(() => {
      this.flushScheduled = false;
      const batch = this.pending;
      this.pending = [];
      for (const listener of this.listeners) {
        listener(batch);
      }
    });
  }

  private bridge(error: unknown): DeceiptBridgeError {
    return new DeceiptBridgeError(error);
  }
}

/** Link a merchant and a customer through one in-process radio. */
export function linkMockPeers(
  merchant: InMemoryDeceiptNative,
  customer: InMemoryDeceiptNative,
  radio: MockRadio | null = null,
): void {
  merchant.link(customer, radio);
  customer.link(merchant, radio);
}

/** Build a syntactically P-256-shaped uncompressed point for mock handshakes. */
function validLookingPoint(): Uint8Array {
  const point = randomBytes(65);
  point[0] = 0x04;
  return point;
}

function offerMetadata(offer: ReceiptOffer): OfferMetadata {
  return {
    transferIdHex: hexEncode(offer.transferId),
    receiptIdHex: hexEncode(offer.receiptId),
    merchantReference: offer.merchantReference,
    totalAmountMinor: offer.totalAmountMinor,
    currency: offer.currency,
    issuedAt: offer.issuedAt,
    kind: offer.kind,
    ciphertextLength: offer.ciphertextLength,
    merchantIdHex: hexEncode(offer.merchantId),
    credentialHashHex: hexEncode(offer.credentialHash),
    sessionIdHex: hexEncode(offer.sessionId),
    offerHashHex: '',
  };
}

function errorName(name: string): ProtocolErrorName {
  return name as ProtocolErrorName;
}

/**
 * MOCK ONLY deterministic byte stream. A xorshift32 is fine here because the
 * mock models the protocol, not the security: no test depends on these bytes
 * being unpredictable, and using the real CSPRNG would make runs unreproducible.
 */
let mockRandomState = 0x9e3779b9;
function nextMockRandom(count: number): Uint8Array {
  const out = new Uint8Array(count);
  for (let index = 0; index < count; index += 1) {
    mockRandomState ^= mockRandomState << 13;
    mockRandomState ^= mockRandomState >>> 17;
    mockRandomState ^= mockRandomState << 5;
    out[index] = mockRandomState & 0xff;
  }
  return out;
}
