/**
 * Bridge error type shared by the app and every adapter. The frozen
 * identifiers come from `protocol/vectors/errors.json`; only this wrapper adds
 * the bridge-facing shape (`DeceiptNative.BridgeError`).
 */

import type {BridgeError, BridgePhase} from './DeceiptNative';
import {PROTOCOL_ERRORS, ProtocolError, type ProtocolErrorName} from '../protocol/errors';

export class DeceiptBridgeError extends Error {
  readonly bridge: BridgeError;

  constructor(error: unknown, phase?: BridgePhase) {
    const typed = asProtocolErrorLike(error);
    super(typed.message);
    this.name = 'DeceiptBridgeError';
    this.bridge = {
      name: typed.name,
      code: typed.code,
      fatal: typed.fatal,
      retryable: typed.retryable,
      phase,
      detail: typed.detail,
    };
  }
}

function asProtocolErrorLike(error: unknown): {
  name: ProtocolErrorName;
  code: number;
  fatal: boolean;
  retryable: boolean;
  detail?: string;
  message: string;
} {
  if (error instanceof ProtocolError) {
    return {
      name: error.name,
      code: error.code,
      fatal: error.fatal,
      retryable: error.retryable,
      detail: error.detail,
      message: error.message,
    };
  }
  if (typeof error === 'string' && error in PROTOCOL_ERRORS) {
    const name = error as ProtocolErrorName;
    const descriptor = PROTOCOL_ERRORS[name];
    return {name, code: descriptor.code, fatal: descriptor.fatal, retryable: descriptor.retryable, message: error};
  }
  return {
    name: 'INTERNAL_ERROR',
    code: PROTOCOL_ERRORS.INTERNAL_ERROR.code,
    fatal: true,
    retryable: true,
    message: error instanceof Error ? error.message : 'unknown bridge failure',
  };
}
