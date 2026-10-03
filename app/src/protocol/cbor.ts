/**
 * Canonical CBOR codec — RFC 8949 §4.2.1 core deterministic encoding, v1 subset
 * (docs/protocol/receipt-v1.md §1).
 *
 * ENCODE is total on the v1 domain: integer keys 0..255 only, definite
 * lengths, minimal integer arguments, no floats / tags / indefinite lengths /
 * null.
 *
 * DECODE is strict. Every deviation that the frozen tables assign an error to
 * is rejected with that error, so `protocol/vectors/encoding-invalid.json` and
 * the non-canonical receipt containers reproduce their recorded codes exactly:
 *
 *   duplicate map key          -> CBOR_DUPLICATE_KEY
 *   non-ascending map keys     -> CBOR_NONCANONICAL
 *   non-minimal argument       -> CBOR_NONCANONICAL
 *   indefinite length          -> CBOR_UNSUPPORTED_TYPE
 *   float / tag / null / simple-> CBOR_UNSUPPORTED_TYPE
 *   text map key               -> CBOR_UNSUPPORTED_TYPE
 *   map key > 255 or negative  -> CBOR_UNSUPPORTED_TYPE
 *   truncation / bad UTF-8     -> CBOR_MALFORMED
 *   trailing bytes             -> CBOR_MALFORMED
 *   depth / item / length caps -> CBOR_DEPTH_EXCEEDED / CBOR_SIZE_EXCEEDED
 *
 * The decoder also records the exact byte span each value occupied, which is
 * what lets the receipt parser prove that re-encoding reproduces the received
 * bytes (`RECEIPT_NONCANONICAL`, receipt-v1.md §2/§7).
 */

import {CBOR_LIMITS} from './constants';
import {ProtocolError} from './errors';
import {utf8Decode, utf8Encode} from './bytes';

export type CborValue = number | bigint | Uint8Array | string | boolean | CborValue[] | CborMap;

/** A CBOR map with integer keys 0..255. Insertion order is preserved. */
export class CborMap {
  private readonly entries = new Map<number, CborValue>();

  static of(entries: Array<[number, CborValue]>): CborMap {
    const map = new CborMap();
    for (const [key, value] of entries) {
      map.set(key, value);
    }
    return map;
  }

  set(key: number, value: CborValue): this {
    this.entries.set(key, value);
    return this;
  }

  get(key: number): CborValue | undefined {
    return this.entries.get(key);
  }

  has(key: number): boolean {
    return this.entries.has(key);
  }

  delete(key: number): boolean {
    return this.entries.delete(key);
  }

  get size(): number {
    return this.entries.size;
  }

  keys(): number[] {
    return [...this.entries.keys()];
  }

  values(): CborValue[] {
    return [...this.entries.values()];
  }

  /** Entries in insertion order. Canonical encoding requires ascending keys. */
  toEntries(): Array<[number, CborValue]> {
    return [...this.entries.entries()];
  }

  clone(): CborMap {
    const copy = new CborMap();
    for (const [key, value] of this.entries) {
      copy.set(key, cloneValue(value));
    }
    return copy;
  }
}

export function cloneValue(value: CborValue): CborValue {
  if (value instanceof CborMap) {
    return value.clone();
  }
  if (Array.isArray(value)) {
    return value.map(cloneValue);
  }
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  return value;
}

const MAJOR_UINT = 0;
const MAJOR_NEGINT = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

function argumentLength(argument: number): number {
  if (argument < 24) {
    return 0;
  }
  if (argument < 0x100) {
    return 1;
  }
  if (argument < 0x10000) {
    return 2;
  }
  if (argument < 0x100000000) {
    return 4;
  }
  return 8;
}

function writeHead(out: number[], major: number, argument: number | bigint): void {
  const head = major << 5;
  if (typeof argument === 'bigint') {
    if (argument < 0n || argument > 0xffffffffffffffffn) {
      throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'integer argument out of range');
    }
    if (argument < 24n) {
      out.push(head | Number(argument));
    } else if (argument < 0x100n) {
      out.push(head | 24, Number(argument));
    } else if (argument < 0x10000n) {
      out.push(head | 25, Number(argument >> 8n), Number(argument & 0xffn));
    } else if (argument < 0x100000000n) {
      out.push(head | 26);
      for (let shift = 24; shift >= 0; shift -= 8) {
        out.push(Number((argument >> BigInt(shift)) & 0xffn));
      }
    } else {
      out.push(head | 27);
      for (let shift = 56; shift >= 0; shift -= 8) {
        out.push(Number((argument >> BigInt(shift)) & 0xffn));
      }
    }
    return;
  }
  const width = argumentLength(argument);
  if (width === 0) {
    out.push(head | argument);
    return;
  }
  // Additional information 24/25/26/27 encodes a following 1/2/4/8-byte argument.
  // Extract bytes through BigInt: `>>` is an int32 shift and would corrupt any
  // value at or above 2^31 (a legal `amount_minor`, for instance).
  out.push(head | (24 + Math.log2(width)));
  const value = BigInt(argument);
  for (let shift = (width - 1) * 8; shift >= 0; shift -= 8) {
    out.push(Number((value >> BigInt(shift)) & 0xffn));
  }
}

/**
 * Encode a value in the v1 deterministic profile. Throws
 * `ProtocolError('CBOR_UNSUPPORTED_TYPE')` for anything outside it and
 * `ProtocolError('CBOR_NONCANONICAL')` for maps whose keys are not ascending.
 */
export function encodeCbor(value: CborValue): Uint8Array {
  const out: number[] = [];
  writeValue(out, value);
  return new Uint8Array(out);
}

function writeValue(out: number[], value: CborValue): void {
  if (typeof value === 'boolean') {
    out.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'floating point is forbidden in v1 CBOR');
    }
    if (!Number.isSafeInteger(value)) {
      throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'integer exceeds the safe range; use bigint');
    }
    if (value >= 0) {
      writeHead(out, MAJOR_UINT, value);
    } else {
      writeHead(out, MAJOR_NEGINT, -1 - value);
    }
    return;
  }
  if (typeof value === 'bigint') {
    if (value >= 0n) {
      writeHead(out, MAJOR_UINT, value);
    } else {
      writeHead(out, MAJOR_NEGINT, -1n - value);
    }
    return;
  }
  if (typeof value === 'string') {
    const bytes = utf8Encode(value);
    writeHead(out, MAJOR_TEXT, bytes.length);
    for (const byte of bytes) {
      out.push(byte);
    }
    return;
  }
  if (value instanceof Uint8Array) {
    writeHead(out, MAJOR_BYTES, value.length);
    for (const byte of value) {
      out.push(byte);
    }
    return;
  }
  if (Array.isArray(value)) {
    writeHead(out, MAJOR_ARRAY, value.length);
    for (const item of value) {
      writeValue(out, item);
    }
    return;
  }
  if (value instanceof CborMap) {
    const entries = value.toEntries();
    for (const [key] of entries) {
      if (!Number.isInteger(key) || key < 0 || key > CBOR_LIMITS.maxMapKey) {
        throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', `map key ${key} is outside 0..${CBOR_LIMITS.maxMapKey}`);
      }
    }
    const sorted = [...entries].sort((a, b) => a[0] - b[0]);
    writeHead(out, MAJOR_MAP, sorted.length);
    for (const [key, item] of sorted) {
      writeHead(out, MAJOR_UINT, key);
      writeValue(out, item);
    }
    return;
  }
  throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'value is not representable in v1 CBOR');
}

export interface CborSpan {
  /** Byte offset of the start of the value in the source buffer. */
  start: number;
  /** Byte offset one past the end of the value. */
  end: number;
}

export interface DecodedDocument {
  value: CborValue;
  /** Byte spans keyed by the JSON-ish path used by the receipt parser. */
  spans: Map<string, CborSpan>;
  /** Total bytes consumed (must equal the buffer length when strict). */
  bytesRead: number;
}

export interface DecodeOptions {
  /** Reject trailing bytes after the top-level item (default true). */
  requireComplete?: boolean;
  /** Collect byte spans so callers can slice exact original bytes. */
  collectSpans?: boolean;
}

class Decoder {
  private offset = 0;
  private items = 0;
  private readonly spans = new Map<string, CborSpan>();

  constructor(
    private readonly bytes: Uint8Array,
    private readonly options: DecodeOptions,
  ) {}

  decode(): DecodedDocument {
    const value = this.readValue(0, '');
    if (this.options.requireComplete !== false && this.offset !== this.bytes.length) {
      throw new ProtocolError('CBOR_MALFORMED', `${this.bytes.length - this.offset} trailing bytes after the top-level item`);
    }
    return {value, spans: this.spans, bytesRead: this.offset};
  }

  private countItem(): void {
    this.items += 1;
    if (this.items > CBOR_LIMITS.maxItems) {
      throw new ProtocolError('CBOR_SIZE_EXCEEDED', `more than ${CBOR_LIMITS.maxItems} items`);
    }
  }

  private readByte(): number {
    if (this.offset >= this.bytes.length) {
      throw new ProtocolError('CBOR_MALFORMED', 'truncated input');
    }
    const byte = this.bytes[this.offset];
    this.offset += 1;
    return byte;
  }

  private readExact(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) {
      throw new ProtocolError('CBOR_MALFORMED', 'truncated input');
    }
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  /**
   * Read an argument, enforcing minimal-length encoding (§4.2.1). The
   * additional-information value is compared against the minimal form of the
   * decoded number, which catches `0x18 0x05`, `0x78 0x03 "CAD"` and `0x98 0x02`.
   */
  private readArgument(additional: number): number {
    if (additional < 24) {
      return additional;
    }
    if (additional === 28 || additional === 29 || additional === 30 || additional === 31) {
      throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', `additional information ${additional} is reserved or indefinite`);
    }
    const length = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : 8;
    let value = 0;
    for (let i = 0; i < length; i += 1) {
      value = value * 256 + this.readByte();
    }
    if (argumentLength(value) !== length) {
      throw new ProtocolError('CBOR_NONCANONICAL', 'non-minimal integer or length argument');
    }
    return value;
  }

  private readValue(depth: number, path: string): CborValue {
    if (depth > CBOR_LIMITS.maxDepth) {
      throw new ProtocolError('CBOR_DEPTH_EXCEEDED', `nesting deeper than ${CBOR_LIMITS.maxDepth}`);
    }
    const start = this.offset;
    const initial = this.readByte();
    const major = initial >> 5;
    const additional = initial & 0x1f;

    let value: CborValue;
    switch (major) {
      case MAJOR_UINT:
        value = this.readArgument(additional);
        break;
      case MAJOR_NEGINT:
        value = -1 - this.readArgument(additional);
        break;
      case MAJOR_BYTES: {
        if (additional === 31) {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'indefinite-length byte string is forbidden');
        }
        const length = this.readArgument(additional);
        if (length > CBOR_LIMITS.maxBytes) {
          throw new ProtocolError('CBOR_SIZE_EXCEEDED', `byte string of ${length} exceeds ${CBOR_LIMITS.maxBytes}`);
        }
        value = new Uint8Array(this.readExact(length));
        break;
      }
      case MAJOR_TEXT: {
        if (additional === 31) {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'indefinite-length text string is forbidden');
        }
        const length = this.readArgument(additional);
        if (length > CBOR_LIMITS.maxTextBytes) {
          throw new ProtocolError('CBOR_SIZE_EXCEEDED', `text string of ${length} exceeds ${CBOR_LIMITS.maxTextBytes}`);
        }
        const raw = this.readExact(length);
        let text: string;
        try {
          text = utf8Decode(raw);
        } catch {
          throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
        }
        value = text;
        break;
      }
      case MAJOR_ARRAY: {
        if (additional === 31) {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'indefinite-length array is forbidden');
        }
        const length = this.readArgument(additional);
        if (length > CBOR_LIMITS.maxArray) {
          throw new ProtocolError('CBOR_SIZE_EXCEEDED', `array of ${length} exceeds ${CBOR_LIMITS.maxArray}`);
        }
        const items: CborValue[] = new Array(length);
        for (let i = 0; i < length; i += 1) {
          items[i] = this.readValue(depth + 1, `${path}[${i}]`);
        }
        value = items;
        break;
      }
      case MAJOR_MAP: {
        if (additional === 31) {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'indefinite-length map is forbidden');
        }
        const length = this.readArgument(additional);
        if (length > CBOR_LIMITS.maxMap) {
          throw new ProtocolError('CBOR_SIZE_EXCEEDED', `map of ${length} exceeds ${CBOR_LIMITS.maxMap}`);
        }
        const map = new CborMap();
        let previousKey = -1;
        for (let i = 0; i < length; i += 1) {
          const keyStart = this.offset;
          const keyInitial = this.readByte();
          const keyMajor = keyInitial >> 5;
          const keyAdditional = keyInitial & 0x1f;
          if (keyMajor !== MAJOR_UINT) {
            throw new ProtocolError(
              'CBOR_UNSUPPORTED_TYPE',
              'v1 maps require integer keys (negative, text and byte-string keys are forbidden)',
            );
          }
          const key = this.readArgument(keyAdditional);
          this.countItem();
          if (key > CBOR_LIMITS.maxMapKey) {
            throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', `map key ${key} is above ${CBOR_LIMITS.maxMapKey}`);
          }
          if (map.has(key)) {
            throw new ProtocolError('CBOR_DUPLICATE_KEY', `duplicate map key ${key}`);
          }
          if (key <= previousKey) {
            throw new ProtocolError('CBOR_NONCANONICAL', `map keys are not ascending (${previousKey} then ${key})`);
          }
          previousKey = key;
          map.set(key, this.readValue(depth + 1, `${path}{${key}}`));
          if (this.options.collectSpans !== false) {
            this.spans.set(`${path}{${key}}#key`, {start: keyStart, end: this.offset});
          }
        }
        value = map;
        break;
      }
      case MAJOR_SIMPLE:
        if (additional === 20) {
          value = false;
        } else if (additional === 21) {
          value = true;
        } else if (additional === 22 || additional === 23) {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'null and undefined are forbidden in v1 CBOR');
        } else if (additional === 25 || additional === 26 || additional === 27 || additional === 24) {
          if (additional === 24) {
            // Simple value: read and reject.
            this.readByte();
          } else {
            // Floats: always reject, and consume bytes so the error is about the type.
            const length = additional === 25 ? 2 : additional === 26 ? 4 : 8;
            this.offset = Math.min(this.offset + length, this.bytes.length);
          }
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'floating point and simple values are forbidden in v1 CBOR');
        } else {
          throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', `simple value ${additional} is forbidden in v1 CBOR`);
        }
        break;
      case 6:
        throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', 'CBOR tags are forbidden in v1 CBOR');
      default:
        throw new ProtocolError('CBOR_UNSUPPORTED_TYPE', `major type ${major} is not permitted`);
    }
    this.countItem();
    if (this.options.collectSpans !== false) {
      this.spans.set(path, {start, end: this.offset});
    }
    return value;
  }
}

/** Decode one deterministic-CBOR document. Trailing bytes are an error by default. */
export function decodeCbor(bytes: Uint8Array, options: DecodeOptions = {}): DecodedDocument {
  return new Decoder(bytes, options).decode();
}

/** Decode and discard spans (used for control messages and tests). */
export function decodeCborValue(bytes: Uint8Array, options: DecodeOptions = {}): CborValue {
  return decodeCbor(bytes, options).value;
}

export interface CanonicalityResult {
  canonical: boolean;
  /** Re-encoded bytes, present whether or not the original was canonical. */
  reencoded: Uint8Array;
  error?: ProtocolError;
}

/**
 * Prove that a received document re-encodes to itself. This is the container
 * canonicality check of receipt-v1.md §2 and the payload check of §7; both map
 * a mismatch to `RECEIPT_NONCANONICAL` at the receipt layer.
 */
export function checkCanonical(bytes: Uint8Array, options: DecodeOptions = {}): CanonicalityResult {
  const decoded = decodeCbor(bytes, options);
  const reencoded = encodeCbor(decoded.value);
  if (reencoded.length !== bytes.length) {
    return {canonical: false, reencoded, error: new ProtocolError('CBOR_NONCANONICAL', 're-encoding length differs')};
  }
  for (let i = 0; i < bytes.length; i += 1) {
    if (reencoded[i] !== bytes[i]) {
      return {canonical: false, reencoded, error: new ProtocolError('CBOR_NONCANONICAL', `re-encoding differs at byte ${i}`)};
    }
  }
  return {canonical: true, reencoded};
}
