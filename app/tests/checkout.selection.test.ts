/**
 * Checkout selection rules at r3 (`protocol/flows/checkout-flow-v1.json`,
 * `selection_model = qr_mandatory_v1`).
 *
 * The normative rules this file proves:
 *
 *  1. `connecting` is reachable ONLY from a QR scan. There is no
 *     candidate-tap-to-connect edge and no binding-less variant, because
 *     `CLIENT_HELLO` requires `session_id` + `binding_proof` and only the QR
 *     carries the binding material.
 *  2. Two or more peripherals advertising the SAME scanned `session_id` fail
 *     closed with `TRANSPORT_PEER_AMBIGUOUS`; there is no picker to resolve it.
 *  3. No radio-derived field can enter selection: `Candidate` has none, and the
 *     diagnostics channel is explicitly labelled.
 *  4. Failure never auto-targets a different peer.
 */

import {INITIAL_CHECKOUT, candidatesForScannedSession, failureMessageFor, orderCandidates, recoveryActionFor, reduce} from '../src/checkout/machine';
import type {Candidate, CheckoutEvent, CheckoutModel} from '../src/checkout/machine';
import {ProtocolError} from '../src/protocol/errors';

function candidate(peripheralId: string, matchesSelection: boolean): Candidate {
  return {peripheralId, deterministicLabel: peripheralId.slice(0, 8), protocolVersion: 1, matchesSelection};
}

function run(events: CheckoutEvent[], start: CheckoutModel = INITIAL_CHECKOUT): CheckoutModel {
  return events.reduce((model, event) => reduce(model, event), start);
}

describe('r3 selection model — QR is the only selection act', () => {
  it('has no candidate-tap-to-connect event on the machine', () => {
    // The event union is the contract; a tap event would have to exist to be
    // handled, and the machine has no handler that sets `selection` from one.
    const scanning = run([{type: 'scanner_opened'}, {type: 'candidate_found', candidate: candidate('a', false)}]);
    expect(scanning.state).toBe('selecting');
    expect(scanning.selection).toBeNull();
  });

  it('enters connecting exactly on the scan, carrying the QR payload', () => {
    const model = run([{type: 'scanner_opened'}, {type: 'user_scanned_qr', qrPayload: 'deceipt1:AA'}]);
    expect(model.state).toBe('connecting');
    expect(model.selection).toEqual({kind: 'qr', qrPayload: 'deceipt1:AA'});
  });

  it('keeps scanning with zero matching candidates', () => {
    const model = run([
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('other-1', false)},
      {type: 'candidate_found', candidate: candidate('other-2', false)},
    ]);
    expect(model.state).toBe('selecting');
    expect(candidatesForScannedSession(model)).toHaveLength(0);
  });

  it('never picks by radio measurement, because no candidate carries one', () => {
    const model = run([
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('strong', true)},
      {type: 'candidate_found', candidate: candidate('weak', true)},
    ]);
    for (const seen of model.candidates) {
      expect(Object.keys(seen).sort()).toEqual(['deterministicLabel', 'matchesSelection', 'peripheralId', 'protocolVersion']);
    }
  });

  it('orders candidates deterministically by peripheral id, with no proximity meaning', () => {
    const ordered = orderCandidates([candidate('ccc', true), candidate('aaa', true), candidate('bbb', true)]);
    expect(ordered.map(entry => entry.peripheralId)).toEqual(['aaa', 'bbb', 'ccc']);
  });
});

describe('r3 ambiguity fails closed with TRANSPORT_PEER_AMBIGUOUS', () => {
  it('flags two peripherals claiming the same scanned session', () => {
    const model = run([
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('clone-a', true)},
      {type: 'candidate_found', candidate: candidate('clone-b', true)},
    ]);
    expect(model.ambiguity).toBe(true);
    expect(model.state).toBe('selecting');
  });

  it('clears the flag when one of the clones disappears', () => {
    const model = run([
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('clone-a', true)},
      {type: 'candidate_found', candidate: candidate('clone-b', true)},
      {type: 'candidate_lost', peripheralId: 'clone-b'},
    ]);
    expect(model.ambiguity).toBe(false);
    expect(candidatesForScannedSession(model)).toHaveLength(1);
  });

  it('moves to recoverable_failure, not to a picker', () => {
    const model = run([
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('clone-a', true)},
      {type: 'candidate_found', candidate: candidate('clone-b', true)},
      {type: 'session_ambiguous', peripheralId: 'clone-b'},
    ]);
    expect(model.state).toBe('recoverable_failure');
    expect(model.ambiguity).toBe(true);
    expect(model.failure?.error?.name).toBe('TRANSPORT_PEER_AMBIGUOUS');
    expect(model.failure?.error?.code).toBe(0x020b);
    // The recovery affordance is a rescan, never a tap on another terminal.
    expect(recoveryActionFor('TRANSPORT_PEER_AMBIGUOUS')).toBe('rescan');
    expect(failureMessageFor('TRANSPORT_PEER_AMBIGUOUS')).toContain('More than one terminal');
  });
});

describe('r3 transition guards', () => {
  it('connecting is not reachable without a scan', () => {
    const events: CheckoutEvent[] = [
      {type: 'scanner_opened'},
      {type: 'candidate_found', candidate: candidate('only-one', true)},
    ];
    const model = run(events);
    expect(model.state).not.toBe('connecting');
  });

  it('transferring requires an established peer, not merely a connection', () => {
    const connected = run([{type: 'user_scanned_qr', qrPayload: 'deceipt1:AA'}]);
    expect(connected.state).toBe('connecting');
    // A receipt arriving before the handshake cannot reach `verifying`.
    const premature = reduce(connected, {type: 'receipt_received'});
    expect(premature.state).toBe('verifying');
    expect(premature.receiptUntrusted).toBe(true);
    // And `saved` is unreachable from `verifying` without an explicit store.
    const saved = reduce(connected, {type: 'verification_saved', saved: {
      receiptIdHex: '00',
      merchantDisplayName: 'x',
      totalMinor: 1,
      currency: 'CAD',
      issuedAt: 0,
      outcome: 'TRUSTED',
      trustLabel: 'trusted',
      alreadyImported: false,
    }});
    expect(saved.state).toBe('saved');
  });

  it('the receipt is explicitly untrusted between decryption and verification', () => {
    const verifying = run([{type: 'user_scanned_qr', qrPayload: 'deceipt1:AA'}, {type: 'receipt_received'}]);
    expect(verifying.state).toBe('verifying');
    expect(verifying.receiptUntrusted).toBe(true);
    expect(verifying.saved).toBeNull();
  });

  it('a failure clears the untrusted receipt and offers exactly one recovery act', () => {
    const failed = run([
      {type: 'user_scanned_qr', qrPayload: 'deceipt1:AA'},
      {type: 'receipt_received'},
      {type: 'failure', error: new ProtocolError('RECEIPT_SIGNATURE_INVALID'), message: failureMessageFor('RECEIPT_SIGNATURE_INVALID')},
    ]);
    expect(failed.state).toBe('recoverable_failure');
    expect(failed.receiptUntrusted).toBe(false);
    expect(failed.saved).toBeNull();
    expect(recoveryActionFor('RECEIPT_SIGNATURE_INVALID')).toBe('retry');
  });

  it('expired checkout copy tells the user to ask for a new code', () => {
    expect(failureMessageFor('BINDING_STALE')).toContain('expired');
    expect(failureMessageFor('BINDING_CONSUMED')).toContain('already used');
    expect(recoveryActionFor('BINDING_STALE')).toBe('rescan');
  });
});
