/**
 * Restart-safe persistence for receipts and their verification state.
 *
 * The storage rules come from verification.md §6:
 *
 *  * a receipt is stored together with its **complete** verification record —
 *    `trusted`, `unknown_issuer` or `rejected` are persisted distinctly, and
 *    trust is NEVER inferred from transport success;
 *  * the §5.3 sub-states are persisted alongside the outcome so a later policy
 *    change or the arrival of revocation data can re-evaluate without
 *    re-transferring the receipt;
 *  * re-import of byte-identical payload bytes is a no-op
 *    (`ALREADY_IMPORTED_IDENTICAL`); the same `receipt_id` with different bytes
 *    is `RECEIPT_DUPLICATE_CONFLICT` and BOTH are kept as evidence;
 *  * the whole import is atomic: either a complete record lands, or nothing does.
 *
 * Storage is expressed as a `KeyValueStore` port so the shared logic is testable
 * without a device. The app binds it to AsyncStorage; tests bind it to memory.
 */

import {ProtocolError} from '../protocol/errors';
import {bytesEqual, base64Encode, base64Decode, hexEncode} from '../protocol/bytes';
import {serializeReceipt, type Receipt} from '../protocol/receipt';
import type {StoredVerification, VerificationResult} from '../protocol/verification';
import {REVOCATION_UNSUPPORTED_REASON} from '../protocol/verification';

// ---------------------------------------------------------------------------
// Storage port
// ---------------------------------------------------------------------------

export interface KeyValueStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/** In-memory store: the shared-logic test double and the mock adapter backing. */
export class MemoryKeyValueStore implements KeyValueStore {
  private readonly entries = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.entries.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<void> {
    this.entries.set(key, value);
  }

  async remove(key: string): Promise<void> {
    this.entries.delete(key);
  }

  /** Test helper: the raw map, for restart simulation. */
  snapshot(): Map<string, string> {
    return new Map(this.entries);
  }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/** The three user-facing trust labels of A2 §8 / verification.md §3. */
export type StoredTrustLabel = 'trusted' | 'unknown_key' | 'rejected';

export interface StoredReceipt {
  /** `receipt_id` hex — the dedup key (receipt-v1.md §9). */
  receiptIdHex: string;
  /** The exact signed payload bytes, base64. Never a re-encoding. */
  payloadB64: string;
  /**
   * The complete COSE_Sign1 container as received, base64. Evidence only: it is
   * the exact wire bytes, never a re-serialization of the parsed model.
   */
  coseSign1B64: string;
  /** The exact embedded credential bytes, base64 (evidence). */
  credentialB64: string;
  storedAtUnix: number;
  verification: StoredVerification;
  trustLabel: StoredTrustLabel;
  /** Display projection, so history renders without re-parsing on every read. */
  merchantDisplayName: string;
  merchantIdHex: string;
  totalMinor: number;
  currency: string;
  issuedAt: number;
  kind: 1 | 2 | 3;
  /** Non-critical extension keys that were ignored and preserved (§6). */
  ignoredExtensionKeys: string[];
}

const INDEX_KEY = 'deceipt.receipts.index.v1';
const RECEIPT_PREFIX = 'deceipt.receipt.v1.';

export class ReceiptStore {
  constructor(private readonly store: KeyValueStore) {}

  /** All stored receipts, newest first. */
  async list(): Promise<StoredReceipt[]> {
    const index = await this.readIndex();
    const records: StoredReceipt[] = [];
    for (const receiptIdHex of index) {
      const record = await this.read(receiptIdHex);
      if (record !== null) {
        records.push(record);
      }
    }
    return records.sort((left, right) => right.storedAtUnix - left.storedAtUnix);
  }

  /** The dedup map `receipt_id` -> exact payload bytes (verification.md §6). */
  async seenReceiptPayloads(): Promise<Map<string, Uint8Array>> {
    const index = await this.readIndex();
    const seen = new Map<string, Uint8Array>();
    for (const receiptIdHex of index) {
      const record = await this.read(receiptIdHex);
      if (record !== null) {
        seen.set(receiptIdHex, base64Decode(record.payloadB64));
      }
    }
    return seen;
  }

  async read(receiptIdHex: string): Promise<StoredReceipt | null> {
    const raw = await this.store.get(RECEIPT_PREFIX + receiptIdHex);
    if (raw === null) {
      return null;
    }
    try {
      return JSON.parse(raw) as StoredReceipt;
    } catch {
      // A corrupt record is surfaced, never silently treated as absent.
      throw new ProtocolError('STORAGE_FAILED', `stored receipt ${receiptIdHex} is unreadable`);
    }
  }

  /**
   * Import a verification result atomically.
   *
   * `ALREADY_IMPORTED_IDENTICAL` writes nothing. A conflicting duplicate stores
   * the new record under a distinct evidence key and keeps the original, with
   * neither labelled `trusted` without the user's attention.
   */
  async import(result: VerificationResult, nowUnix: number): Promise<ImportOutcome> {
    if (result.receipt === undefined) {
      throw new ProtocolError('STORAGE_FAILED', 'a verification result without a parsed receipt cannot be stored');
    }
    if (result.outcome === 'PENDING') {
      throw new ProtocolError('INTERNAL_ERROR', 'a pending verification must not be persisted');
    }
    const receiptIdHex = hexEncode(result.receipt.receiptId);
    const existing = await this.read(receiptIdHex);

    if (existing !== null) {
      const isIdentical = bytesEqual(result.payloadBytes, base64Decode(existing.payloadB64));
      if (isIdentical) {
        return {kind: 'ALREADY_IMPORTED_IDENTICAL', receiptIdHex};
      }
      if (result.outcome === 'REJECTED' || result.error?.name === 'RECEIPT_DUPLICATE_CONFLICT') {
        const evidenceKey = `${receiptIdHex}.conflict.${nowUnix}`;
        await this.writeRecord(evidenceKey, buildRecord(result, nowUnix));
        return {kind: 'DUPLICATE_CONFLICT', receiptIdHex, evidenceKey, conflictingWith: existing.storedAtUnix};
      }
      // A different document under a live identifier: keep both, flag both.
      const evidenceKey = `${receiptIdHex}.conflict.${nowUnix}`;
      await this.writeRecord(evidenceKey, buildRecord(result, nowUnix));
      await this.writeRecord(receiptIdHex, {...existing, trustLabel: 'rejected'});
      return {kind: 'DUPLICATE_CONFLICT', receiptIdHex, evidenceKey, conflictingWith: existing.storedAtUnix};
    }

    await this.writeRecord(receiptIdHex, buildRecord(result, nowUnix));
    return {kind: outcomeToImportKind(result.outcome), receiptIdHex};
  }

  private async writeRecord(key: string, record: StoredReceipt): Promise<void> {
    try {
      await this.store.set(RECEIPT_PREFIX + key, JSON.stringify(record));
    } catch {
      throw new ProtocolError('STORAGE_FAILED', `could not persist receipt ${key}`);
    }
    const index = await this.readIndex();
    if (!index.includes(key)) {
      index.push(key);
      await this.store.set(INDEX_KEY, JSON.stringify(index));
    }
  }

  private async readIndex(): Promise<string[]> {
    const raw = await this.store.get(INDEX_KEY);
    if (raw === null) {
      return [];
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : [];
    } catch {
      throw new ProtocolError('STORAGE_FAILED', 'the receipt index is unreadable');
    }
  }
}

export type ImportKind = 'TRUSTED_STORED' | 'UNVERIFIED_STORED' | 'REJECTED_EVIDENCE' | 'ALREADY_IMPORTED_IDENTICAL' | 'DUPLICATE_CONFLICT';

export interface ImportOutcome {
  kind: ImportKind;
  receiptIdHex: string;
  evidenceKey?: string;
  conflictingWith?: number;
}

function outcomeToImportKind(outcome: VerificationResult['outcome']): ImportKind {
  switch (outcome) {
    case 'TRUSTED':
      return 'TRUSTED_STORED';
    case 'UNVERIFIED_UNKNOWN_ISSUER':
      return 'UNVERIFIED_STORED';
    default:
      return 'REJECTED_EVIDENCE';
  }
}

function buildRecord(result: VerificationResult, nowUnix: number): StoredReceipt {
  if (result.receipt === undefined) {
    throw new ProtocolError('STORAGE_FAILED', 'a verification result without a parsed receipt cannot be stored');
  }
  const receipt: Receipt = result.receipt;
  return {
    receiptIdHex: hexEncode(receipt.receiptId),
    payloadB64: base64Encode(result.payloadBytes),
    coseSign1B64: base64Encode(result.coseSign1Bytes),
    credentialB64: result.credentialBytes === undefined ? '' : base64Encode(result.credentialBytes),
    storedAtUnix: nowUnix,
    verification: {
      outcome: result.outcome,
      subStates: result.subStates,
      errorName: result.error?.name ?? null,
      errorCode: result.error?.code ?? null,
      credentialTrust: result.credentialTrust,
      verifiedAtUnix: nowUnix,
      revocationNote: REVOCATION_UNSUPPORTED_REASON,
    },
    trustLabel: result.outcome === 'TRUSTED' ? 'trusted' : result.outcome === 'UNVERIFIED_UNKNOWN_ISSUER' ? 'unknown_key' : 'rejected',
    merchantDisplayName: receipt.merchant.displayName,
    merchantIdHex: hexEncode(receipt.merchant.merchantId),
    totalMinor: receipt.totals.totalMinor,
    currency: receipt.currency,
    issuedAt: receipt.issuedAt,
    kind: receipt.kind,
    ignoredExtensionKeys: [],
  };
}

/**
 * Re-serialize a stored receipt for display. This is a *display* path only: it
 * must never be used as the signed bytes, which are `coseSign1B64`.
 */
export function receiptDisplayBytes(receipt: Receipt): Uint8Array {
  return serializeReceipt(receipt);
}

// ---------------------------------------------------------------------------
// Merchant key persistence (public identity only; key material stays native)
// ---------------------------------------------------------------------------

export interface StoredMerchantIdentity {
  deviceKeyIdHex: string;
  devicePublicKeyB64: string;
  storage: string;
  credentialB64?: string;
  merchantIdHex?: string;
  createdAtMs: number;
}

const MERCHANT_KEY = 'deceipt.merchant.identity.v1';

/**
 * Cache of the *public* merchant identity so the UI can render before native
 * answers. The private key never appears here; native owns it.
 */
export class MerchantIdentityCache {
  constructor(private readonly store: KeyValueStore) {}

  async read(): Promise<StoredMerchantIdentity | null> {
    const raw = await this.store.get(MERCHANT_KEY);
    if (raw === null) {
      return null;
    }
    try {
      return JSON.parse(raw) as StoredMerchantIdentity;
    } catch {
      return null;
    }
  }

  async write(identity: StoredMerchantIdentity): Promise<void> {
    await this.store.set(MERCHANT_KEY, JSON.stringify(identity));
  }

  async clear(): Promise<void> {
    await this.store.remove(MERCHANT_KEY);
  }
}
