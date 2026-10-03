/**
 * The checkout state machine of docs/flows/transaction-binding-and-checkout-v1.md
 * §5, as a pure reducer.
 *
 * Pure on purpose: the transitions, the guards and the RSSI prohibition are
 * testable without a bridge, a store or a renderer, and the controller cannot
 * reach a state the machine does not permit.
 *
 * The normative guards are enforced here:
 *
 *  * `selecting -> connecting` requires exactly one candidate chosen by an
 *    explicit user act; two or more eligible candidates with no selection is
 *    `TRANSPORT_PEER_AMBIGUOUS` and stays in `selecting`;
 *  * `connecting -> transferring` requires the binding check AND the merchant
 *    credential AND the transcript signature to have passed;
 *  * `transferring -> verifying` requires the full AEAD payload to be decrypted
 *    (`receipt_received`), and `verifying` is local-only work;
 *  * `verifying -> saved` requires ALL of the §9 steps 10–15 to pass, and the
 *    receipt is `RECEIPT_UNTRUSTED` until then;
 *  * `recoverable_failure` never auto-retries into a different peer.
 *
 * Nothing in this module reads `rssi`, `txPower`, `distance` or any radio
 * measurement — that is a type-level guarantee (`Candidate` has no such field)
 * and conformance row E10.
 */

import type {OfferMetadata, PeripheralId, QrBindingSelection, TransferableSession} from '../native/DeceiptNative';
import {ProtocolError, type PolicyOutcome} from '../protocol/errors';

export type CheckoutState = 'ready' | 'selecting' | 'connecting' | 'transferring' | 'verifying' | 'saved' | 'recoverable_failure';

/**
 * A peripheral advertising the Deceipt service. A candidate is NEVER a
 * connection target on the r3 path: the QR names the session, and a candidate
 * only becomes meaningful when it advertises that same `session_id` (in which
 * case a second one is an ambiguity, not a choice).
 *
 * No radio-derived field exists on this type, which is how the RSSI prohibition
 * is enforced structurally rather than by review (A2 §2, conformance E10).
 */
export interface Candidate {
  peripheralId: PeripheralId;
  /** Deterministic display label derived from the peripheral id. */
  deterministicLabel: string;
  /** The advertised protocol version, if present. */
  protocolVersion?: number;
  /** True when the candidate advertises the session named by the scanned QR. */
  matchesSelection: boolean;
}

/** Diagnostic-only radio data. Never an input to `select`. */
export interface CandidateDiagnostics {
  peripheralId: PeripheralId;
  readonly diagnosticsOnly: true;
  rssi?: number;
}

/**
 * The user's explicit selection. r3 makes the QR the ONLY selection act
 * (`checkout-flow-v1.json#selection_model = qr_mandatory_v1`): the QR's
 * `session_id` names exactly one session, so there is no candidate-tap-to-connect
 * edge and no binding-less variant to fall back to.
 */
export type Selection = QrBindingSelection;

export interface SavedReceiptView {
  receiptIdHex: string;
  merchantDisplayName: string;
  totalMinor: number;
  currency: string;
  issuedAt: number;
  outcome: PolicyOutcome;
  trustLabel: 'trusted' | 'unknown_key' | 'rejected';
  /** `ALREADY_IMPORTED_IDENTICAL` re-imports land here without a new row. */
  alreadyImported: boolean;
}

export interface CheckoutModel {
  state: CheckoutState;
  /**
   * Peripherals seen advertising the Deceipt service while the scanner is
   * active. Display/diagnostics only: r3 forbids connecting to one of these, so
   * the list is never tappable and never ordered by radio measurement.
   */
  candidates: Candidate[];
  /** The single explicit selection. Only `onQRScanned`/`onCandidateTapped` set it. */
  selection: Selection | null;
  /** The offer awaiting the user's decision (untrusted display data). */
  offer: OfferMetadata | null;
  /**
   * Set once the handshake established a transferable peer (handshake.md §9):
   * either `SessionAuthenticated` (anchored) or `SessionUnverifiedPeer`
   * (unpinned issuer, internal consistency only).
   */
  peer: TransferableSession | null;
  /** True only between `receipt_received` and the outcome of verification. */
  receiptUntrusted: boolean;
  progress: {highestContiguousSequence: number; frameCount: number} | null;
  saved: SavedReceiptView | null;
  failure: {error: ProtocolError | null; message: string} | null;
  /**
   * True when two or more peripherals advertise the SAME scanned `session_id`.
   * That is a clone/impostor condition and fails closed with
   * `TRANSPORT_PEER_AMBIGUOUS`; there is no user picker to resolve it.
   */
  ambiguity: boolean;
  notices: string[];
  /** Set when the failure came from an ambiguous session rather than the user. */
  ambiguousSessionHandle?: PeripheralId;
}

export type CheckoutEvent =
  | {type: 'scanner_opened'}
  | {type: 'user_scanned_qr'; qrPayload: string}
  | {type: 'candidate_found'; candidate: Candidate}
  | {type: 'candidate_lost'; peripheralId: PeripheralId}
  | {type: 'scan_stopped'}
  | {type: 'session_ambiguous'; peripheralId: PeripheralId}
  | {type: 'connect_started'; selection: Selection}
  | {type: 'handshake_authenticated'; session: TransferableSession; offer: OfferMetadata}
  | {type: 'offer_declined'}
  | {type: 'transfer_began'; frameCount: number}
  | {type: 'transfer_progress'; highestContiguousSequence: number; frameCount: number; notices: string[]}
  | {type: 'receipt_received'}
  | {type: 'verification_saved'; saved: SavedReceiptView}
  | {type: 'failure'; error: ProtocolError | null; message: string}
  | {type: 'reset'};

export const INITIAL_CHECKOUT: CheckoutModel = {
  state: 'ready',
  candidates: [],
  selection: null,
  offer: null,
  peer: null,
  receiptUntrusted: false,
  progress: null,
  saved: null,
  failure: null,
  ambiguity: false,
  notices: [],
};

/**
 * Structural eligibility: the candidate carries the Deceipt service (true by
 * construction — the adapter emits `candidate_found` only for advertisements
 * carrying the service UUID) and advertises a protocol version this build
 * implements. Radio-derived fields are absent from `Candidate`, so they cannot
 * enter the predicate (A2 §2).
 */
export function isEligible(candidate: Candidate): boolean {
  return candidate.protocolVersion === undefined || SUPPORTED_SUITE_VERSIONS.includes(candidate.protocolVersion);
}

/** Protocol versions this build understands (`protocol/REVISION.json`). */
export const SUPPORTED_SUITE_VERSIONS: readonly number[] = [1];

/**
 * Candidates advertising the session named by the scanned QR. Zero means no
 * terminal is answering this checkout; one is the ordinary case; two or more is
 * `TRANSPORT_PEER_AMBIGUOUS` and must fail closed.
 */
export function candidatesForScannedSession(model: CheckoutModel): Candidate[] {
  return orderCandidates(model.candidates.filter(candidate => candidate.matchesSelection && isEligible(candidate)));
}

/** All candidates seen while scanning, deterministically ordered. Display only. */
export function orderCandidates(candidates: Candidate[]): Candidate[] {
  return [...candidates].sort((left, right) => (left.peripheralId < right.peripheralId ? -1 : left.peripheralId > right.peripheralId ? 1 : 0));
}

export function reduce(model: CheckoutModel, event: CheckoutEvent): CheckoutModel {
  switch (event.type) {
    case 'scanner_opened':
      return {...model, state: 'selecting', ambiguity: false};

    case 'user_scanned_qr':
      // The ONLY transition into `connecting` (r3): the scan names one session.
      return {
        ...model,
        state: 'connecting',
        selection: {kind: 'qr', qrPayload: event.qrPayload},
        ambiguity: false,
        failure: null,
      };

    case 'candidate_found': {
      const candidates = orderCandidates([...model.candidates.filter(c => c.peripheralId !== event.candidate.peripheralId), event.candidate]);
      // `matchesSelection` is set only when the candidate advertises the exact
      // session the user's QR named. Two such candidates is a clone/impostor.
      const matching = candidates.filter(candidate => candidate.matchesSelection);
      return {...model, candidates, ambiguity: matching.length >= 2};
    }

    case 'candidate_lost': {
      const candidates = model.candidates.filter(candidate => candidate.peripheralId !== event.peripheralId);
      const matching = candidates.filter(candidate => candidate.matchesSelection);
      return {...model, candidates, ambiguity: matching.length >= 2};
    }

    case 'scan_stopped':
      return model.state === 'selecting' ? {...model, state: 'ready'} : model;

    case 'session_ambiguous':
      // Fail closed: no user picker exists to resolve this on the QR path.
      return {
        ...model,
        state: 'recoverable_failure',
        ambiguity: true,
        ambiguousSessionHandle: event.peripheralId,
        failure: {error: new ProtocolError('TRANSPORT_PEER_AMBIGUOUS'), message: failureMessageFor('TRANSPORT_PEER_AMBIGUOUS')},
      };

    case 'connect_started':
      return {...model, state: 'connecting', selection: event.selection, failure: null};

    case 'handshake_authenticated':
      return {
        ...model,
        state: 'transferring',
        peer: event.session,
        offer: event.offer,
        receiptUntrusted: false,
        failure: null,
      };

    case 'offer_declined':
      return {
        ...model,
        state: 'recoverable_failure',
        offer: null,
        peer: null,
        failure: {error: null, message: 'Cancelled.'},
      };

    case 'transfer_began':
      return {...model, state: 'transferring', progress: {highestContiguousSequence: -1, frameCount: event.frameCount}};

    case 'transfer_progress':
      return {
        ...model,
        progress: {highestContiguousSequence: event.highestContiguousSequence, frameCount: event.frameCount},
        notices: [...model.notices, ...event.notices].slice(-16),
      };

    case 'receipt_received':
      // Decryption success is NOT trust. The session holds untrusted bytes and
      // the only way out of `verifying` is a full §9 pass (or a failure).
      return {...model, state: 'verifying', receiptUntrusted: true};

    case 'verification_saved':
      return {...model, state: 'saved', saved: event.saved, receiptUntrusted: false, failure: null};

    case 'failure':
      return {
        ...model,
        state: 'recoverable_failure',
        receiptUntrusted: false,
        failure: {error: event.error, message: event.message},
      };

    case 'reset':
      return {...INITIAL_CHECKOUT};

    default:
      return model;
  }
}

/** Copy for the named failure situations of A2 §6, without crypto internals. */
export function failureMessageFor(errorName: string | null): string {
  switch (errorName) {
    case 'WRONG_TRANSACTION':
    case 'RECEIPT_OFFER_MISMATCH':
      return "This isn't the transaction you selected.";
    case 'BINDING_STALE':
    case 'SESSION_EXPIRED':
      return 'This checkout code has expired. Ask the merchant to show a new one.';
    case 'TRANSPORT_BLUETOOTH_OFF':
      return 'Bluetooth is off.';
    case 'TRANSPORT_PERMISSION_DENIED':
      return 'Deceipt needs Bluetooth to receive your receipt.';
    case 'TRANSPORT_PEER_AMBIGUOUS':
      return 'More than one terminal is answering this checkout code. Ask the merchant to show a new one.';
    case 'USER_CANCELLED':
    case 'TRANSFER_CANCELLED':
      return 'Cancelled.';
    case 'BINDING_CONSUMED':
      return 'This checkout code was already used. Ask the merchant to show a new one.';
    case 'RECEIPT_SIGNATURE_INVALID':
      return 'Rejected — the signature did not match.';
    case 'RECEIPT_UNSUPPORTED_VERSION':
      return 'This receipt was issued by an unsupported version.';
    case 'TRANSPORT_LINK_LOST':
      return 'The connection to the terminal was lost.';
    case 'TRANSPORT_CONNECT_TIMEOUT':
      return 'The terminal did not respond.';
    case 'HANDSHAKE_SIGNATURE_INVALID':
    case 'HANDSHAKE_TRANSCRIPT_MISMATCH':
      return 'Could not verify this terminal.';
    default:
      return errorName === null ? 'Something went wrong. Please try again.' : 'Could not verify this receipt.';
  }
}

/** The retry/fallback affordance a failure state offers (A2 §6). */
export function recoveryActionFor(errorName: string | null): 'retry' | 'rescan' | 'enable_bluetooth' | 'grant_permission' {
  switch (errorName) {
    case 'TRANSPORT_BLUETOOTH_OFF':
      return 'enable_bluetooth';
    case 'TRANSPORT_PERMISSION_DENIED':
      return 'grant_permission';
    case 'BINDING_STALE':
    case 'SESSION_EXPIRED':
    case 'BINDING_CONSUMED':
      return 'rescan';
    case 'TRANSPORT_PEER_AMBIGUOUS':
      return 'rescan';
    default:
      return 'retry';
  }
}
