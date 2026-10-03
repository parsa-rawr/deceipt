/**
 * Byte, base64, hex and UTF-8 helpers.
 *
 * The bridge speaks base64 (RFC 4648 §4, padding included); the vectors speak
 * hex; CBOR needs UTF-8. These helpers are deliberately total functions on
 * their valid domain and throw `ProtocolError` on anything malformed — a
 * silently-truncating decoder would break the exact-bytes rule.
 *
 * No external dependencies: this module must run in RN, in Jest under the RN
 * preset, and (for the mock adapters) in plain Node.
 */

import {ProtocolError} from './errors';

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const BASE64_LOOKUP = new Int16Array(128).fill(-1);
const BASE64URL_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < 64; i += 1) {
  BASE64_LOOKUP[BASE64_ALPHABET.charCodeAt(i)] = i;
  BASE64URL_LOOKUP[BASE64URL_ALPHABET.charCodeAt(i)] = i;
}

/**
 * TextEncoder/TextDecoder are provided by Hermes (RN >= 0.70), Node >= 11 and
 * every Jest environment we run in, but the RN base tsconfig's `lib` does not
 * declare them. Declare the minimal surface we use rather than pulling in DOM.
 */
declare const TextEncoder: {new (): {encode(input: string): Uint8Array}};
declare const TextDecoder: {new (label?: string, options?: {fatal?: boolean}): {decode(input: Uint8Array): string}};

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
}

/** Strict UTF-8 validity check without allocating a string. */
export function isValidUtf8(bytes: Uint8Array): boolean {
  let i = 0;
  while (i < bytes.length) {
    const byte = bytes[i];
    if (byte < 0x80) {
      i += 1;
      continue;
    }
    let extra: number;
    let codePoint: number;
    if (byte >= 0xc2 && byte <= 0xdf) {
      extra = 1;
      codePoint = byte & 0x1f;
    } else if (byte >= 0xe0 && byte <= 0xef) {
      extra = 2;
      codePoint = byte & 0x0f;
    } else if (byte >= 0xf0 && byte <= 0xf4) {
      extra = 3;
      codePoint = byte & 0x07;
    } else {
      return false;
    }
    if (i + extra >= bytes.length) {
      return false;
    }
    for (let k = 1; k <= extra; k += 1) {
      const continuation = bytes[i + k];
      if (continuation < 0x80 || continuation > 0xbf) {
        return false;
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    // Reject overlong encodings, surrogates and out-of-range code points.
    if (extra === 2 && (codePoint < 0x800 || (codePoint >= 0xd800 && codePoint <= 0xdfff))) {
      return false;
    }
    if (extra === 3 && (codePoint < 0x10000 || codePoint > 0x10ffff)) {
      return false;
    }
    if (extra === 1 && codePoint < 0x80) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

function decodeAlphabet(input: string, lookup: Int16Array, alphabet: string): Uint8Array {
  if (input.length % 4 !== 0) {
    throw new ProtocolError('CBOR_MALFORMED', 'base64 length is not a multiple of 4');
  }
  const paddingIndex = input.indexOf('=');
  const dataEnd = paddingIndex === -1 ? input.length : paddingIndex;
  if (paddingIndex !== -1) {
    for (let i = paddingIndex; i < input.length; i += 1) {
      if (input[i] !== '=') {
        throw new ProtocolError('CBOR_MALFORMED', 'base64 padding is not trailing');
      }
    }
  }
  const remainder = dataEnd % 4;
  if (remainder === 1) {
    throw new ProtocolError('CBOR_MALFORMED', 'base64 length cannot leave a single trailing character');
  }
  const out = new Uint8Array(Math.floor(dataEnd / 4) * 3 + (remainder === 0 ? 0 : remainder - 1));
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < dataEnd; i += 1) {
    const charCode = input.charCodeAt(i);
    const value = charCode < 128 ? lookup[charCode] : -1;
    if (value < 0) {
      throw new ProtocolError('CBOR_MALFORMED', `invalid base64 character at ${i} of "${alphabet}"`);
    }
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex] = (buffer >> bits) & 0xff;
      outIndex += 1;
    }
  }
  // Leftover bits must be zero (RFC 4648 §3.5 canonical padding).
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new ProtocolError('CBOR_MALFORMED', 'base64 has non-zero trailing bits');
  }
  if (outIndex !== out.length) {
    throw new ProtocolError('CBOR_MALFORMED', 'base64 padding does not match its length');
  }
  return out;
}

export function base64Decode(input: string): Uint8Array {
  return decodeAlphabet(input, BASE64_LOOKUP, 'base64');
}

export function base64UrlDecode(input: string): Uint8Array {
  const padded = input.length % 4 === 0 ? input : input + '='.repeat(4 - (input.length % 4));
  return decodeAlphabet(padded, BASE64URL_LOOKUP, 'base64url');
}

export function base64Encode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += BASE64_ALPHABET[b0 >> 2];
    out += BASE64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? BASE64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? BASE64_ALPHABET[b2 & 0x3f] : '=';
  }
  return out;
}

/** RFC 4648 §5 base64url without padding (the A2 QR payload encoding). */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const HEX_DIGITS = '0123456789abcdef';

export function hexEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += HEX_DIGITS[bytes[i] >> 4];
    out += HEX_DIGITS[bytes[i] & 0x0f];
  }
  return out;
}

export function hexDecode(input: string): Uint8Array {
  if (input.length % 2 !== 0) {
    throw new ProtocolError('CBOR_MALFORMED', 'hex string has odd length');
  }
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const highNibble = nibbleValue(input.charCodeAt(i * 2));
    const lowNibble = nibbleValue(input.charCodeAt(i * 2 + 1));
    if (highNibble < 0 || lowNibble < 0) {
      throw new ProtocolError('CBOR_MALFORMED', 'invalid hex digit');
    }
    out[i] = (highNibble << 4) | lowNibble;
  }
  return out;
}

function nibbleValue(charCode: number): number {
  if (charCode >= 0x30 && charCode <= 0x39) {
    return charCode - 0x30;
  }
  if (charCode >= 0x61 && charCode <= 0x66) {
    return charCode - 0x61 + 10;
  }
  return -1;
}

/** Constant-time byte comparison (no early exit on value mismatch). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) {
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
