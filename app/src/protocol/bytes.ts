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
 * TextEncoder/TextDecoder are NOT guaranteed on device: RN 0.87 on Hermes has no
 * `globalThis.TextDecoder` (and no `crypto`), even though Node — and therefore
 * Jest — provides both. Relying on them produced
 * `CBOR_MALFORMED: text string is not valid UTF-8` on real hardware, because a
 * missing global threw and the throw was indistinguishable from a genuinely
 * malformed string.
 *
 * So both directions are implemented here in plain TypeScript. The decoder is
 * STRICT: it rejects overlong encodings, surrogate halves and out-of-range code
 * points exactly as the frozen vectors require, rather than replacing them with
 * U+FFFD.
 */
declare const TextEncoder: {new (): {encode(input: string): Uint8Array}} | undefined;

/**
 * UTF-8 encoding. Uses the platform encoder when present (it is the faster
 * path); a `TextEncoder` that throws or is absent falls through to the local
 * implementation rather than propagating an environment error.
 */
export function utf8Encode(text: string): Uint8Array {
  if (typeof TextEncoder === 'function') {
    try {
      return new TextEncoder().encode(text);
    } catch {
      // Fall through to the local encoder.
    }
  }
  return utf8EncodeLocal(text);
}

/** Local UTF-8 encoder. Lone surrogates are encoded as U+FFFD, as JS expects. */
export function utf8EncodeLocal(text: string): Uint8Array {
  const out: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    let codePoint = text.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff && index + 1 < text.length) {
      const low = text.charCodeAt(index + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (low - 0xdc00);
        index += 1;
      } else {
        codePoint = 0xfffd;
      }
    } else if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
      codePoint = 0xfffd;
    }
    if (codePoint < 0x80) {
      out.push(codePoint);
    } else if (codePoint < 0x800) {
      out.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      out.push(0xe0 | (codePoint >> 12), 0x80 | ((codePoint >> 6) & 0x3f), 0x80 | (codePoint & 0x3f));
    } else {
      out.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}

/**
 * Strict UTF-8 decoding. Throws `ProtocolError('CBOR_MALFORMED')` on any invalid
 * sequence — the same identifier the decoder produced before, and never a
 * silent U+FFFD substitution.
 *
 * The platform decoder is tried first; because ours is strict, a platform that
 * returns replacement characters instead of failing (a non-`fatal` decoder) is
 * detected by the round-trip check and rejected.
 */
export function utf8Decode(bytes: Uint8Array): string {
  const viaLocal = utf8DecodeLocal(bytes);
  if (typeof TextDecoder === 'function') {
    try {
      const decoder = new TextDecoder('utf-8', {fatal: true});
      const decoded = decoder.decode(bytes);
      // Trust the platform only when it agrees with the strict decoder.
      if (decoded === viaLocal) {
        return decoded;
      }
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    } catch (error) {
      if (error instanceof ProtocolError) {
        throw error;
      }
      // A decoder that threw is also authoritative about invalidity, but our
      // local decoder already validated the bytes, so reaching here means the
      // platform disagrees with a strict reading: prefer the strict one.
      return viaLocal;
    }
  }
  return viaLocal;
}

/**
 * The strict decoder used on device. Rejects, in order: bad lead bytes,
 * truncation, bad continuations, overlong forms, surrogate halves and code
 * points above U+10FFFF.
 */
export function utf8DecodeLocal(bytes: Uint8Array): string {
  let out = '';
  let index = 0;
  while (index < bytes.length) {
    const lead = bytes[index];
    if (lead < 0x80) {
      out += String.fromCharCode(lead);
      index += 1;
      continue;
    }
    let extra: number;
    let codePoint: number;
    let minimum: number;
    if (lead >= 0xc2 && lead <= 0xdf) {
      extra = 1;
      codePoint = lead & 0x1f;
      minimum = 0x80;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      extra = 2;
      codePoint = lead & 0x0f;
      minimum = 0x800;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      extra = 3;
      codePoint = lead & 0x07;
      minimum = 0x10000;
    } else {
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    }
    if (index + extra >= bytes.length) {
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    }
    for (let offset = 1; offset <= extra; offset += 1) {
      const continuation = bytes[index + offset];
      if (continuation < 0x80 || continuation > 0xbf) {
        throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    if (codePoint < minimum) {
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    }
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    }
    if (codePoint > 0x10ffff) {
      throw new ProtocolError('CBOR_MALFORMED', 'text string is not valid UTF-8');
    }
    if (codePoint <= 0xffff) {
      out += String.fromCharCode(codePoint);
    } else {
      const adjusted = codePoint - 0x10000;
      out += String.fromCharCode(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
    }
    index += extra + 1;
  }
  return out;
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
