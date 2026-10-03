/**
 * Shared cryptographic primitives available to the TypeScript layer.
 *
 * Deliberately narrow. The *app* uses these for:
 *   * canonical-bytes digests and the A2 offer/binding hashes (SHA-256),
 *   * the A2 binding proof (HMAC-SHA-256) in the mock adapters and tests,
 *   * Ed25519 verification when a mock adapter stands in for native.
 *
 * The app NEVER performs Ed25519 *signing* with a real merchant key: that
 * happens in native custody (Keychain / Keystore) and the private half never
 * crosses the bridge. `ed25519SignWithTestSeed` exists only so MOCK adapters
 * and tests can reproduce A1's published test vectors, and it refuses to run
 * unless the caller is explicitly using test-only material.
 *
 * Session keys (ECDH/HKDF/AES-GCM) are native-only; there is no shared-app
 * implementation of the handshake crypto, by design.
 */

import {ProtocolError} from './errors';

/** Minimal WebCrypto surface, declared locally so we do not depend on DOM lib. */
interface CryptoKeyHandle {
  readonly type: string;
}

interface SubtleSurface {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  importKey(
    format: string,
    keyData: Uint8Array,
    algorithm: {name: string; hash?: string},
    extractable: boolean,
    usages: string[],
  ): Promise<CryptoKeyHandle>;
  exportKey(format: string, key: CryptoKeyHandle): Promise<unknown>;
  sign(algorithm: string | {name: string}, key: CryptoKeyHandle, data: Uint8Array): Promise<ArrayBuffer>;
  verify(algorithm: string | {name: string}, key: CryptoKeyHandle, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

interface CryptoSurface {
  subtle: SubtleSurface;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

/**
 * Resolve WebCrypto, or `null` when this runtime has none. React Native 0.87 on
 * Hermes has **no** `globalThis.crypto`; callers that only need a digest fall
 * back to the pure-TypeScript implementation below, and callers that need
 * Ed25519 raise `CAPABILITY_UNAVAILABLE` because that path must be native.
 */
function resolveCryptoOptional(): CryptoSurface | null {
  const candidate: unknown = (globalThis as unknown as {crypto?: unknown}).crypto;
  return isCryptoSurface(candidate) ? candidate : null;
}

function requireCrypto(feature: string): CryptoSurface {
  const resolved = resolveCryptoOptional();
  if (resolved === null) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', `${feature} needs WebCrypto or the native adapter`);
  }
  return resolved;
}

/** `getRandomValues`-only fallback is not acceptable; CSPRNG is required. */
export function requireSecureRandom(): CryptoSurface {
  return requireCrypto('secure random generation');
}

function isCryptoSurface(value: unknown): value is CryptoSurface {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const subtle: unknown = (value as {subtle?: unknown}).subtle;
  if (typeof subtle !== 'object' || subtle === null) {
    return false;
  }
  const digest: unknown = (subtle as {digest?: unknown}).digest;
  const importKey: unknown = (subtle as {importKey?: unknown}).importKey;
  const verify: unknown = (subtle as {verify?: unknown}).verify;
  return typeof digest === 'function' && typeof importKey === 'function' && typeof verify === 'function';
}

/**
 * SHA-256, preferring WebCrypto and falling back to the pure implementation so
 * the shared layer works on Hermes without a crypto polyfill.
 */

// ---------------------------------------------------------------------------
// Pure-TypeScript SHA-256 and HMAC-SHA-256
// ---------------------------------------------------------------------------
//
// React Native 0.87 does NOT polyfill `globalThis.crypto` on Hermes (the
// polyfill is not in the react-native package, and Jest only passes because the
// Node host exposes WebCrypto). Without a local implementation, every shared
// digest — the offer-hash recomputation, the transcript/credential hash and the
// binding proof — would throw `CAPABILITY_UNAVAILABLE` on device.
//
// So the digests are implemented here in plain TypeScript. The inputs are
// non-secret (public keys, canonical CBOR, domain-separated public values), and
// the construction is byte-for-byte the same on Hermes, JSC and Node. WebCrypto
// is still preferred when present, for speed, and these are validated against
// the frozen vectors in `tests/protocol.hashing.test.ts`.
//
// Ed25519 is deliberately NOT implemented here: signing and verification stay in
// native custody / WebCrypto, never in a hand-rolled curve implementation.

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr32(value: number, shift: number): number {
  return ((value >>> shift) | (value << (32 - shift))) >>> 0;
}

/** Raw SHA-256. Constant work per byte; no data-dependent branching. */
export function sha256Pure(data: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  // Pad: 0x80, zeros, then the 64-bit big-endian bit length.
  const blocks = Math.floor((data.length + 8) / 64) + 1;
  const padded = new Uint8Array(blocks * 64);
  padded.set(data, 0);
  padded[data.length] = 0x80;
  const bitLength = data.length * 8;
  // Write the bit length as a 64-bit big-endian integer using two 32-bit halves.
  padded[padded.length - 8] = Math.floor(bitLength / 0x100000000) >>> 24;
  padded[padded.length - 7] = Math.floor(bitLength / 0x100000000) >>> 16;
  padded[padded.length - 6] = Math.floor(bitLength / 0x100000000) >>> 8;
  padded[padded.length - 5] = Math.floor(bitLength / 0x100000000) & 0xff;
  padded[padded.length - 4] = (bitLength >>> 24) & 0xff;
  padded[padded.length - 3] = (bitLength >>> 16) & 0xff;
  padded[padded.length - 2] = (bitLength >>> 8) & 0xff;
  padded[padded.length - 1] = bitLength & 0xff;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      const base = offset + i * 4;
      w[i] = ((padded[base] << 24) | (padded[base + 1] << 16) | (padded[base + 2] << 8) | padded[base + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i += 1) {
    out[i * 4] = (h[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
    out[i * 4 + 3] = h[i] & 0xff;
  }
  return out;
}

/** Raw HMAC-SHA-256 (RFC 2104), block size 64. */
export function hmacSha256Pure(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  const normalized = key.length > blockSize ? sha256Pure(key) : key;
  const padded = new Uint8Array(blockSize);
  padded.set(normalized, 0);
  const inner = new Uint8Array(blockSize + message.length);
  const outer = new Uint8Array(blockSize + 32);
  for (let i = 0; i < blockSize; i += 1) {
    inner[i] = padded[i] ^ 0x36;
    outer[i] = padded[i] ^ 0x5c;
  }
  inner.set(message, blockSize);
  outer.set(sha256Pure(inner), blockSize);
  return sha256Pure(outer);
}

/** Constant-time byte comparison that never short-circuits on value. */
function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left[i] ^ right[i];
  }
  return diff === 0;
}

/** True when a usable WebCrypto `subtle` is present in this runtime. */
export function hasWebCrypto(): boolean {
  return isCryptoSurface((globalThis as unknown as {crypto?: unknown}).crypto);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const crypto = resolveCryptoOptional();
  if (crypto === null) {
    return sha256Pure(data);
  }
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

/** Synchronous SHA-256 for callers that cannot await (e.g. CBOR canonicality). */
export function sha256Sync(data: Uint8Array): Uint8Array {
  return sha256Pure(data);
}

/** Domain-separated SHA-256 as used by A2: `prefix || 0x00 || message`. */
export async function domainSeparatedSha256(prefixAscii: string, message: Uint8Array): Promise<Uint8Array> {
  const prefix = new Uint8Array([...prefixAscii].map(character => character.charCodeAt(0)));
  const joined = new Uint8Array(prefix.length + 1 + message.length);
  joined.set(prefix, 0);
  joined[prefix.length] = 0x00;
  joined.set(message, prefix.length + 1);
  return sha256(joined);
}

export async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const crypto = resolveCryptoOptional();
  if (crypto === null) {
    return hmacSha256Pure(key, message);
  }
  const cryptoKey = await crypto.subtle.importKey('raw', key, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(mac);
}

/** Synchronous HMAC-SHA-256; same construction as the WebCrypto path. */
export function hmacSha256Sync(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmacSha256Pure(key, message);
}

/**
 * HMAC-SHA-256 with a constant-time comparison, for A2's binding proof.
 * `bytesEqual` from `./bytes` performs the comparison without early exit.
 */
export async function verifyHmacSha256(key: Uint8Array, message: Uint8Array, expected: Uint8Array): Promise<boolean> {
  return constantTimeEqual(await hmacSha256(key, message), expected);
}

/** Verify an Ed25519 signature over exact bytes with a raw 32-byte public key. */
export async function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32) {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'Ed25519 public keys are 32 bytes');
  }
  if (signature.length !== 64) {
    return false;
  }
  const subtle = requireCrypto('Ed25519 verification').subtle;
  const key = await subtle.importKey('raw', publicKey, {name: 'Ed25519'}, false, ['verify']);
  return subtle.verify({name: 'Ed25519'}, key, signature, message);
}

/**
 * DER prefix of a PKCS#8 Ed25519 private key that carries its 32-byte seed
 * verbatim (RFC 8410 `OneAsymmetricKey` with a raw `CurvePrivateKey`).
 *
 * WebCrypto has no `raw` Ed25519 *private* import path, so a published test
 * seed is wrapped in this 16-byte prefix. The seed is never modified.
 */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function ed25519PrivateKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'Ed25519 seeds are 32 bytes');
  }
  const wrapped = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  wrapped.set(ED25519_PKCS8_PREFIX, 0);
  wrapped.set(seed, ED25519_PKCS8_PREFIX.length);
  return wrapped;
}

/**
 * Sign with a raw 32-byte Ed25519 seed. TEST AND MOCK-ADAPTER USE ONLY.
 *
 * The seed must be published test material from
 * `protocol/vectors/keys/test-keys.json`; a production merchant key is held by
 * native custody and never reaches this function.
 */
export async function ed25519SignWithTestSeed(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const subtle = requireCrypto('Ed25519 signing').subtle;
  const key = await subtle.importKey('pkcs8', ed25519PrivateKeyFromSeed(seed), {name: 'Ed25519'}, false, ['sign']);
  const signature = await subtle.sign({name: 'Ed25519'}, key, message);
  return new Uint8Array(signature);
}

/** Derive the raw 32-byte public key for a test seed (mock adapters only). */
export async function ed25519PublicKeyFromTestSeed(seed: Uint8Array): Promise<Uint8Array> {
  const subtle = requireCrypto('Ed25519 public-key derivation').subtle;
  const key = await subtle.importKey('pkcs8', ed25519PrivateKeyFromSeed(seed), {name: 'Ed25519'}, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', key);
  if (typeof jwk !== 'object' || jwk === null) {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'Ed25519 public key export is unavailable');
  }
  const x: unknown = (jwk as {x?: unknown}).x;
  if (typeof x !== 'string') {
    throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'Ed25519 JWK export did not carry an x coordinate');
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const normalized = x.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.length % 4 === 0 ? normalized : normalized + '='.repeat(4 - (normalized.length % 4));
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of padded) {
    if (character === '=') {
      break;
    }
    buffer = (buffer << 6) | alphabet.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** Cryptographically secure random bytes. Never a test vector. */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  return requireSecureRandom().getRandomValues(out);
}
