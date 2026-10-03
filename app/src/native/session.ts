/**
 * Runtime guards for the three-level session distinction of handshake.md §9
 * (r2/r3). The nominal types live in `DeceiptNative.ts`; these are the checks
 * every adapter and the shared controller run at the point of use, so the
 * compile-time split is also enforced when a value crosses the bridge.
 *
 * `DeceiptNative.ts` is a types-only contract and must stay importable without
 * pulling runtime code, which is why these live in their own module. Failures are
 * `ProtocolError` (the frozen identifiers); adapters wrap them in
 * `DeceiptBridgeError` when reporting across the bridge.
 */

import {ProtocolError} from '../protocol/errors';
import type {AnySession, SessionAuthenticated, SessionUnverifiedPeer, TransferableSession} from './DeceiptNative';

/** Narrow to `SessionAuthenticated`. */
export function isAuthenticatedSession(session: AnySession): session is SessionAuthenticated {
  return session.kind === 'SessionAuthenticated';
}

/** Narrow to `SessionUnverifiedPeer`. */
export function isUnverifiedPeerSession(session: AnySession): session is SessionUnverifiedPeer {
  return session.kind === 'SessionUnverifiedPeer';
}

/** Narrow to a session the transfer path accepts. */
export function isTransferableSession(session: AnySession): session is TransferableSession {
  return session.kind !== 'SessionKeysOnly';
}

/**
 * The transfer-path guard: `SessionKeysOnly` MUST NOT send `ACCEPT` and MUST NOT
 * transfer a receipt (handshake.md §9). Throws `PEER_NOT_AUTHENTICATED`.
 */
export function assertSessionMayTransfer(session: AnySession): asserts session is TransferableSession {
  if (session.kind === 'SessionKeysOnly') {
    throw new ProtocolError('PEER_NOT_AUTHENTICATED', 'a SessionKeysOnly session may not accept or transfer a receipt');
  }
}

/**
 * The stricter guard: the peer's identity was established against a pinned
 * anchor. Use it wherever the code's meaning depends on identity rather than on
 * internal consistency alone.
 */
export function assertSessionAuthenticated(session: AnySession): asserts session is SessionAuthenticated {
  if (session.kind !== 'SessionAuthenticated') {
    throw new ProtocolError('PEER_NOT_AUTHENTICATED', `a ${session.kind} session has no anchored merchant identity`);
  }
}
