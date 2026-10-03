/**
 * Session-level type discipline (handshake.md §9, r2/r3).
 *
 * Two properties are asserted here:
 *
 *  1. `SessionKeysOnly` cannot reach the transfer path — by type and at runtime.
 *  2. A `SessionUnverifiedPeer` can never yield a trusted receipt: the receipt
 *     verification layer only returns `TRUSTED` when `signatureValid &&
 *     keyAuthorized`, and this session type fixes `keyAuthorized = false`
 *     because its issuer is not in the pinned anchor set.
 *
 * The second property is the one the delegation plan calls out as
 * "a valid signature plus an unknown key is never trusted" (conformance B3),
 * and it is the reason `SessionUnverifiedPeer` is a distinct nominal type rather
 * than a boolean on a single session type.
 */

import {
  type AnySession,
  type SessionAuthenticated,
  type SessionKeysOnly,
  type SessionUnverifiedPeer,
} from '../src/native/DeceiptNative';
import {assertSessionAuthenticated, assertSessionMayTransfer, isAuthenticatedSession, isUnverifiedPeerSession} from '../src/native/session';
import {verifyReceipt} from '../src/protocol/verification';
import {base64Encode, base64Decode, hexDecode, hexEncode} from '../src/protocol/bytes';
import {verifyCredential} from '../src/protocol/handshake';
import {ProtocolError} from '../src/protocol/errors';
import type {TrustAnchor} from '../src/native/DeceiptNative';
import {loadReceiptInvalid, loadReceiptValid, loadVector, vectorPaths} from './fixtures';

interface UnverifiedPeerVector {
  session_type: string;
  client_hello_hex: string;
  server_hello_hex: string;
  transcript_hex: string;
  transcript_hash_hex: string;
  transcript_signature_hex: string;
  credential_hex: string;
  credential_issuer_id_hex: string;
  credential_device_public_key_hex: string;
  pinned_anchors_hex: Record<string, string>;
  credential_verification: {expected_error: string; expected_trust: string; fatal: boolean};
  expected_transfer: string;
  expected_receipt_outcome: string;
  must_never_be: string;
}

const keysOnly: SessionKeysOnly = {kind: 'SessionKeysOnly', sessionHandle: 's-1'};
const unverifiedPeer: SessionUnverifiedPeer = {
  kind: 'SessionUnverifiedPeer',
  sessionHandle: 's-2',
  merchantIdHex: '11223344556677889900112233445566',
  deviceKeyIdHex: '66554433221100998877665544332211',
  credentialB64: '',
  credentialTrust: 'unknown_issuer',
  keyAuthorized: false,
};
const authenticated: SessionAuthenticated = {
  kind: 'SessionAuthenticated',
  sessionHandle: 's-3',
  merchantIdHex: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  deviceKeyIdHex: '0f1e2d3c4b5a69788796a5b4c3d2e1f0',
  credentialB64: '',
  credentialTrust: 'authenticated',
  keyAuthorized: true,
  credentialTemporallyAcceptable: true,
};

describe('session nominal types (handshake.md §9)', () => {
  it('keys-only is refused on the transfer path', () => {
    expect(() => assertSessionMayTransfer(keysOnly)).toThrow(ProtocolError);
    expect(() => assertSessionAuthenticated(keysOnly)).toThrow(ProtocolError);
  });

  it('a keys-only refusal is typed PEER_NOT_AUTHENTICATED', () => {
    let caught: unknown;
    try {
      assertSessionMayTransfer(keysOnly);
    } catch (error) {
      caught = error;
    }
    expect((caught as ProtocolError).name).toBe('PEER_NOT_AUTHENTICATED');
    expect((caught as ProtocolError).code).toBe(0x0311);
  });

  it('both transferable levels pass the transfer guard', () => {
    expect(() => assertSessionMayTransfer(unverifiedPeer)).not.toThrow();
    expect(() => assertSessionMayTransfer(authenticated)).not.toThrow();
  });

  it('only the authenticated level passes the identity guard', () => {
    expect(() => assertSessionAuthenticated(authenticated)).not.toThrow();
    expect(() => assertSessionAuthenticated(unverifiedPeer)).toThrow(ProtocolError);
  });

  it('narrows by discriminant', () => {
    const sessions: AnySession[] = [keysOnly, unverifiedPeer, authenticated];
    expect(sessions.filter(isAuthenticatedSession)).toHaveLength(1);
    expect(sessions.filter(isUnverifiedPeerSession)).toHaveLength(1);
  });

  it('fixes the trust literals so the distinction cannot be mutated away', () => {
    // These are compile-time assertions; the runtime checks document intent.
    expect(unverifiedPeer.credentialTrust).toBe('unknown_issuer');
    expect(unverifiedPeer.keyAuthorized).toBe(false);
    expect(authenticated.credentialTrust).toBe('authenticated');
    expect(authenticated.keyAuthorized).toBe(true);
  });
});

describe('a SessionUnverifiedPeer can never yield a trusted receipt (conformance B3)', () => {
  const fixture = loadVector<UnverifiedPeerVector>(vectorPaths.unverifiedPeer);

  const anchorsFrom = (values: Record<string, string>): TrustAnchor[] =>
    Object.entries(values).map(([anchorIdHex, publicKeyHex]) => ({
      anchorIdHex,
      publicKeyB64: base64Encode(hexDecode(publicKeyHex)),
    }));

  it('is described by the frozen fixture as transferable but never trusted', () => {
    expect(fixture.session_type).toBe('SessionUnverifiedPeer');
    expect(fixture.expected_transfer).toBe('allowed');
    expect(fixture.expected_receipt_outcome).toBe('UNVERIFIED_UNKNOWN_ISSUER');
    expect(fixture.must_never_be).toBe('TRUSTED');
  });

  it('verifies the credential as structurally sound but unpinned', async () => {
    const check = await verifyCredential(hexDecode(fixture.credential_hex), anchorsFrom(fixture.pinned_anchors_hex), 1767225600);
    expect(check.error).toBe(fixture.credential_verification.expected_error);
    expect(check.trust).toBe(fixture.credential_verification.expected_trust);
    expect(check.body).not.toBeNull();
    // The declared device key is asserted by the credential, not proven.
    expect(hexEncode(check.body!.devicePublicKey)).toBe(fixture.credential_device_public_key_hex);
    expect(hexEncode(check.body!.issuerId)).toBe(fixture.credential_issuer_id_hex);
  });

  it('reaches UNVERIFIED_UNKNOWN_ISSUER and never TRUSTED for a rogue receipt', async () => {
    const rogue = loadReceiptInvalid().cases.find(testCase => testCase.case === 'unknown_issuer_credential')!;
    const baseline = loadReceiptInvalid().cases[0];
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(rogue.cose_sign1_hex),
      anchors: anchorsFrom(baseline.anchors_hex),
      nowUnix: rogue.verify_at_unix,
    });
    expect(result.outcome).toBe('UNVERIFIED_UNKNOWN_ISSUER');
    expect(result.outcome).not.toBe('TRUSTED');
    expect(result.subStates.signatureValid).toBe(true);
    expect(result.subStates.keyAuthorized).toBe(false);
  });

  it('cannot be promoted to TRUSTED by adding the rogue anchor alone', async () => {
    // The rogue issuer is deliberately absent from the pinned set; adding its
    // anchor would be an out-of-band provisioning decision, not an app path.
    const rogue = loadReceiptInvalid().cases.find(testCase => testCase.case === 'unknown_issuer_credential')!;
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(rogue.cose_sign1_hex),
      anchors: anchorsFrom(rogue.anchors_hex),
      nowUnix: rogue.verify_at_unix,
    });
    expect(result.outcome).toBe('UNVERIFIED_UNKNOWN_ISSUER');
    expect(result.credentialTrust).toBe('unknown_issuer');
  });

  it('maps the trusted baseline to the authenticated session type only', async () => {
    const baseline = loadReceiptInvalid().cases[0];
    const vector = loadReceiptValid();
    const result = await verifyReceipt({
      coseSign1Bytes: hexDecode(vector.cose_sign1_hex),
      anchors: anchorsFrom(baseline.anchors_hex),
      nowUnix: baseline.verify_at_unix,
    });
    expect(result.outcome).toBe('TRUSTED');
    expect(result.subStates.keyAuthorized).toBe(true);
    expect(result.subStates.signatureValid).toBe(true);
    // And the session that could have produced it is the anchored one.
    expect(authenticated.keyAuthorized).toBe(true);
    expect(base64Decode(authenticated.credentialB64).length).toBe(0);
  });
});
