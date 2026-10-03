/**
 * Checkout controller: binds the `DeceiptNative` event stream to the pure state
 * machine and performs the app-side verification (steps 8–15) plus persistence.
 *
 * This is the only place in the app that moves a receipt from
 * `RECEIPT_UNTRUSTED` to a stored outcome, and it does so exclusively through
 * `verifyReceipt` on the exact received bytes. No transport event can skip it.
 */

import type {
  DeceiptEvent,
  DeceiptNative,
  OfferMetadata,
  PermissionReport,
  SessionAuthenticated,
  SessionUnverifiedPeer,
  TransferableSession,
  TrustAnchor,
} from '../native/DeceiptNative';
import {DeceiptBridgeError} from '../native/bridgeError';
import {ProtocolError} from '../protocol/errors';
import {base64Decode, base64Encode, hexEncode} from '../protocol/bytes';
import {parseBindingQr} from '../protocol/binding';
import {verifyReceipt, type VerificationResult} from '../protocol/verification';
import {ReceiptStore, type ImportOutcome} from '../storage/receiptStore';
import {
  INITIAL_CHECKOUT,
  failureMessageFor,
  reduce,
  type CheckoutEvent,
  type CheckoutModel,
  type CheckoutState,
  type SavedReceiptView,
  type Selection,
} from './machine';

export interface CheckoutControllerOptions {
  native: DeceiptNative;
  store: ReceiptStore;
  anchors: TrustAnchor[];
  now?: () => number;
  /** Called after every model change; the UI subscribes here. */
  onChange?: (model: CheckoutModel) => void;
}

export interface CheckoutResult {
  model: CheckoutModel;
  verification: VerificationResult | null;
  importOutcome: ImportOutcome | null;
}

function requireUnverifiedPeer(session: SessionUnverifiedPeer | null): SessionUnverifiedPeer {
  if (session === null) {
    throw new ProtocolError('PEER_NOT_AUTHENTICATED', 'no peer was established for this session');
  }
  return session;
}

export class CheckoutController {
  private model: CheckoutModel = {...INITIAL_CHECKOUT};
  private unsubscribe: (() => void) | null = null;
  private activeSessionHandle: string | null = null;
  /** The `session_id` the user's scan named; the only selection input (r3). */
  private scannedSessionIdHex: string | null = null;
  private authenticated: SessionAuthenticated | null = null;
  private unverifiedPeer: SessionUnverifiedPeer | null = null;
  private pendingReceipt: {coseSign1B64: string; ciphertextLength: number} | null = null;
  private readonly now: () => number;
  private readonly options: CheckoutControllerOptions;

  constructor(options: CheckoutControllerOptions) {
    this.options = options;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  getModel(): CheckoutModel {
    return this.model;
  }

  getState(): CheckoutState {
    return this.model.state;
  }

  /** Begin listening to the adapter. Call once on mount. */
  start(): void {
    if (this.unsubscribe !== null) {
      return;
    }
    this.unsubscribe = this.options.native.subscribe(events => {
      for (const event of events) {
        this.handleEvent(event);
      }
    });
  }

  /** Stop listening and tear down any live session. */
  async dispose(): Promise<void> {
    if (this.unsubscribe !== null) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    if (this.activeSessionHandle !== null) {
      await this.safeStopSession(this.activeSessionHandle);
      this.activeSessionHandle = null;
    }
  }

  /** The customer's explicit act: scanning a terminal's QR (P1). */
  async onQRScanned(qrPayload: string): Promise<void> {
    const parsed = parseBindingQr(qrPayload);
    this.scannedSessionIdHex = hexEncode(parsed.sessionId);
    await this.beginSession({kind: 'qr', qrPayload});
  }

  /**
   * Open the scanner. Scanning is how the user reaches a terminal's QR; it is
   * not a selection act. r3 removed the candidate-tap-to-connect path entirely
   * (`checkout-flow-v1.json#selection_invariants`).
   */
  async onOpenScanner(): Promise<void> {
    this.dispatch({type: 'scanner_opened'});
    await this.options.native.startScan();
  }

  /** Accept the offered transaction: sends AEAD `ACCEPT` and starts transfer. */
  async onAcceptOffer(): Promise<void> {
    // Either an anchored peer or an unpinned-but-internally-consistent peer may
    // accept; a keys-only session never gets here because neither field is set.
    const session: TransferableSession | null = this.authenticated ?? this.unverifiedPeer;
    if (session === null) {
      this.fail(new ProtocolError('PEER_NOT_AUTHENTICATED', 'no transferable session to accept'));
      return;
    }
    try {
      await this.options.native.acceptOffer(session);
    } catch (error) {
      this.failFrom(error);
    }
  }

  /** Decline the offer without accepting it. */
  async onDeclineOffer(): Promise<void> {
    this.dispatch({type: 'offer_declined'});
    if (this.activeSessionHandle !== null) {
      await this.safeStopSession(this.activeSessionHandle);
      this.activeSessionHandle = null;
    }
  }

  async onCancel(): Promise<void> {
    if (this.activeSessionHandle !== null) {
      try {
        await this.options.native.cancelSession(this.activeSessionHandle, 'user_cancelled');
      } catch {
        // Cancellation is best-effort; the local state still fails closed.
      }
      this.activeSessionHandle = null;
    }
    this.dispatch({type: 'failure', error: new ProtocolError('USER_CANCELLED'), message: failureMessageFor('USER_CANCELLED')});
  }

  reset(): void {
    this.dispatch({type: 'reset'});
    this.authenticated = null;
    this.unverifiedPeer = null;
    this.pendingReceipt = null;
    this.activeSessionHandle = null;
  }

  async permissionState(): Promise<PermissionReport> {
    return this.options.native.permissionState();
  }

  private async beginSession(selection: Selection): Promise<void> {
    // The guard runs before any transport work, so no session is opened from a
    // state the machine has not permitted (A2 section 5 transition guards).
    this.dispatch({type: 'connect_started', selection});
    if (this.model.state !== 'connecting') {
      return;
    }
    try {
      const snapshot = await this.options.native.startCustomerSession({
        selection,
        anchors: this.options.anchors,
      });
      this.activeSessionHandle = snapshot.sessionHandle;
    } catch (error) {
      this.failFrom(error);
    }
  }

  private handleEvent(event: DeceiptEvent): void {
    switch (event.type) {
      case 'peer_candidate':
        this.dispatch({
          type: 'candidate_found',
          candidate: {
            peripheralId: event.peripheralId,
            deterministicLabel: event.deterministicLabel,
            protocolVersion: event.protocolVersion,
            matchesSelection: this.selectionMatches(event.sessionIdHex),
          },
        });
        if (this.model.ambiguity && this.model.state !== 'recoverable_failure') {
          this.dispatch({type: 'session_ambiguous', peripheralId: event.peripheralId});
        }
        return;
      case 'peer_candidate_lost':
        this.dispatch({type: 'candidate_lost', peripheralId: event.peripheralId});
        return;
      case 'scan_stopped':
        this.dispatch({type: 'scan_stopped'});
        return;
      case 'session_authenticated':
        this.authenticated = event.authenticated;
        return;
      case 'session_unverified_peer':
        // Non-fatal: the session may transfer, and the offer is shown marked
        // unknown key. `this.authenticated` stays null so no trusted-path call
        // can be made with it.
        this.unverifiedPeer = event.unverifiedPeer;
        return;
      case 'offer_received':
        this.onOfferReceived(event.offer);
        return;
      case 'transfer_started':
        this.dispatch({type: 'transfer_began', frameCount: event.frameCount});
        return;
      case 'transfer_progress':
        this.dispatch({
          type: 'transfer_progress',
          highestContiguousSequence: event.highestContiguousSequence,
          frameCount: event.frameCount,
          notices: event.notices,
        });
        return;
      case 'receipt_received':
        this.pendingReceipt = {coseSign1B64: event.coseSign1B64, ciphertextLength: event.ciphertextLength};
        this.dispatch({type: 'receipt_received'});
        void this.verifyPendingReceipt();
        return;
      case 'error':
        this.failFrom(event.error, event.sessionHandle);
        return;
      case 'session_torn_down':
        if (event.reason === 'link_lost') {
          this.fail(new ProtocolError('TRANSPORT_LINK_LOST'), event.sessionHandle);
        }
        return;
      case 'bluetooth_state_changed':
        if (event.state !== 'on') {
          this.fail(new ProtocolError('TRANSPORT_BLUETOOTH_OFF'), undefined);
        }
        return;
      case 'disconnected':
        if (this.model.state === 'transferring' || this.model.state === 'connecting') {
          this.fail(new ProtocolError('TRANSPORT_LINK_LOST'), event.sessionHandle);
        }
        return;
      default:
        return;
    }
  }

  private onOfferReceived(offer: OfferMetadata): void {
    const authenticated = this.authenticated;
    const unverifiedPeer = this.unverifiedPeer;
    if (authenticated === null && unverifiedPeer === null) {
      // An offer before the handshake authenticated the merchant is a protocol
      // violation; refuse to show it as if the merchant were known.
      this.fail(new ProtocolError('PEER_NOT_AUTHENTICATED', 'offer arrived before the peer was established'));
      return;
    }
    // Either branch yields a transferable session; `SessionKeysOnly` never
    // reaches this point because neither field is set for it.
    const transferable: TransferableSession = authenticated !== null ? authenticated : requireUnverifiedPeer(unverifiedPeer);
    this.dispatch({type: 'handshake_authenticated', session: transferable, offer});
  }

  /**
   * A candidate "matches the selection" only when it advertises the session the
   * scanned QR named. The adapter reports this by decoding the peripheral's
   * advertisement for the session token; the shared layer never guesses it from
   * radio properties.
   */
  private selectionMatches(candidateSessionIdHex: string | undefined): boolean {
    return candidateSessionIdHex !== undefined && candidateSessionIdHex === this.scannedSessionIdHex;
  }

  /**
   * Steps 8–15 on the exact received bytes, then atomic persistence. The result
   * is the only thing that can reach `saved`.
   */
  private async verifyPendingReceipt(): Promise<void> {
    const pending = this.pendingReceipt;
    if (pending === null) {
      return;
    }
    let seenReceipts: Map<string, Uint8Array>;
    try {
      seenReceipts = await this.options.store.seenReceiptPayloads();
    } catch {
      this.fail(new ProtocolError('STORAGE_FAILED', 'receipt history could not be read'));
      return;
    }
    let result: VerificationResult;
    try {
      result = await verifyReceipt({
        coseSign1Bytes: base64Decode(pending.coseSign1B64),
        anchors: this.options.anchors,
        nowUnix: this.now(),
        sessionCredentialBytes: this.credentialBytes(),
        offer: this.model.offer ?? undefined,
        seenReceipts,
        // Prefer the adapter's verifier: Ed25519 must run in native custody, and
        // Hermes has no WebCrypto for the shared fallback to use on device.
        signatureVerifier: async (devicePublicKey, coseSign1Bytes) => {
          const outcome = await this.options.native.verifyReceiptContainer(
            base64Encode(coseSign1Bytes),
            base64Encode(devicePublicKey),
          );
          return {signatureValid: outcome.signatureValid, deviceKeyIdHex: outcome.deviceKeyIdHex};
        },
      });
    } catch (error) {
      this.failFrom(error);
      return;
    }

    if (result.outcome === 'REJECTED') {
      // Evidence-only persistence: nothing trusted, and the failure is shown.
      await this.persistRejected(result);
      this.dispatch({
        type: 'failure',
        error: result.error,
        message: failureMessageFor(result.error?.name ?? null),
      });
      return;
    }

    let importOutcome: ImportOutcome;
    try {
      importOutcome = await this.options.store.import(result, this.now());
    } catch (error) {
      this.failFrom(error);
      return;
    }

    const receipt = result.receipt;
    const saved: SavedReceiptView = {
      receiptIdHex: importOutcome.receiptIdHex,
      merchantDisplayName: result.merchantDisplayName ?? receipt?.merchant.displayName ?? 'Unknown merchant',
      totalMinor: receipt?.totals.totalMinor ?? 0,
      currency: receipt?.currency ?? '',
      issuedAt: receipt?.issuedAt ?? 0,
      outcome: result.outcome,
      trustLabel: result.outcome === 'TRUSTED' ? 'trusted' : result.outcome === 'UNVERIFIED_UNKNOWN_ISSUER' ? 'unknown_key' : 'rejected',
      alreadyImported: importOutcome.kind === 'ALREADY_IMPORTED_IDENTICAL',
    };
    this.dispatch({type: 'verification_saved', saved});
    await this.acknowledge(result);
  }

  private async persistRejected(result: VerificationResult): Promise<void> {
    try {
      await this.options.store.import(result, this.now());
    } catch {
      // Rejected evidence that cannot be persisted must not block the failure UX.
    }
  }

  /** Step 16: `RECEIPT_ACK`, then disconnect. */
  private async acknowledge(result: VerificationResult): Promise<void> {
    const session: TransferableSession | null = this.authenticated ?? this.unverifiedPeer;
    if (session === null || result.receipt === undefined) {
      return;
    }
    const outcome: 'trusted' | 'unknown_issuer' | 'already_imported' | 'rejected' =
      result.outcome === 'TRUSTED'
        ? 'trusted'
        : result.outcome === 'UNVERIFIED_UNKNOWN_ISSUER'
          ? 'unknown_issuer'
          : result.outcome === 'ALREADY_IMPORTED_IDENTICAL'
            ? 'already_imported'
            : 'rejected';
    try {
      await this.options.native.sendReceiptAck(session, hexEncode(result.receipt.receiptId), outcome);
    } catch (error) {
      this.failFrom(error);
      return;
    }
    this.activeSessionHandle = null;
  }

  private credentialBytes(): Uint8Array | undefined {
    const credential = this.authenticated?.credentialB64 ?? this.unverifiedPeer?.credentialB64;
    return credential === undefined ? undefined : base64Decode(credential);
  }

  private fail(error: ProtocolError, sessionHandle?: string): void {
    this.dispatch({type: 'failure', error, message: failureMessageFor(error.name)});
    void sessionHandle;
  }

  private failFrom(error: unknown, sessionHandle?: string): void {
    const typed =
      error instanceof DeceiptBridgeError
        ? new ProtocolError(error.bridge.name, error.bridge.detail)
        : error instanceof ProtocolError
          ? error
          : new ProtocolError('INTERNAL_ERROR', error instanceof Error ? error.message : undefined);
    this.fail(typed, sessionHandle);
  }

  private async safeStopSession(sessionHandle: string): Promise<void> {
    try {
      await this.options.native.stopSession(sessionHandle);
    } catch {
      // Teardown failures must not mask the user-visible outcome.
    }
  }

  private dispatch(event: CheckoutEvent): void {
    const next = reduce(this.model, event);
    if (next === this.model) {
      return;
    }
    this.model = next;
    this.options.onChange?.(next);
  }
}

