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
 * Resolve WebCrypto. Hermes/RN polyfills `globalThis.crypto`; Node exposes it
 * from v19 and Jest's RN preset runs on Node. A missing implementation is an
 * explicit capability failure rather than a silent fallback to weaker bytes.
 */
function resolveCrypto(): CryptoSurface {
  const candidate: unknown = (globalThis as unknown as {crypto?: unknown}).crypto;
  if (isCryptoSurface(candidate)) {
    return candidate;
  }
  throw new ProtocolError('CAPABILITY_UNAVAILABLE', 'WebCrypto is not available in this runtime');
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

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await resolveCrypto().subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
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
  const subtle = resolveCrypto().subtle;
  const cryptoKey = await subtle.importKey('raw', key, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  const mac = await subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(mac);
}

/**
 * HMAC-SHA-256 with a constant-time comparison, for A2's binding proof.
 * `bytesEqual` from `./bytes` performs the comparison without early exit.
 */
export async function verifyHmacSha256(key: Uint8Array, message: Uint8Array, expected: Uint8Array): Promise<boolean> {
  const mac = await hmacSha256(key, message);
  if (mac.length !== expected.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < mac.length; i += 1) {
    diff |= mac[i] ^ expected[i];
  }
  return diff === 0;
}

/** Verify an Ed25519 signature over exact bytes with a raw 32-byte public key. */
export async function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32) {
    throw new ProtocolError('HANDSHAKE_ECDH_INVALID_POINT', 'Ed25519 public keys are 32 bytes');
  }
  if (signature.length !== 64) {
    return false;
  }
  const subtle = resolveCrypto().subtle;
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
  const subtle = resolveCrypto().subtle;
  const key = await subtle.importKey('pkcs8', ed25519PrivateKeyFromSeed(seed), {name: 'Ed25519'}, false, ['sign']);
  const signature = await subtle.sign({name: 'Ed25519'}, key, message);
  return new Uint8Array(signature);
}

/** Derive the raw 32-byte public key for a test seed (mock adapters only). */
export async function ed25519PublicKeyFromTestSeed(seed: Uint8Array): Promise<Uint8Array> {
  const subtle = resolveCrypto().subtle;
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
  return resolveCrypto().getRandomValues(out);
}
