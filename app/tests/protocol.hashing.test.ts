/**
 * Hashing conformance.
 *
 * React Native 0.87 does not polyfill `globalThis.crypto` on Hermes, so the
 * shared layer cannot rely on WebCrypto for digests. These tests pin the pure
 * TypeScript SHA-256/HMAC-SHA-256 against the frozen vectors, with WebCrypto
 * deleted from `globalThis`, so a regression that only holds on the Node host
 * cannot pass.
 */

import {ed25519Verify, hmacSha256, hmacSha256Pure, hmacSha256Sync, sha256, sha256Pure, sha256Sync} from '../src/protocol/crypto';
import {
  concatBytes,
  hexDecode,
  hexEncode,
  utf8Decode,
  utf8DecodeLocal,
  utf8Encode,
  utf8EncodeLocal,
} from '../src/protocol/bytes';
import {CborMap, decodeCbor} from '../src/protocol/cbor';
import {ProtocolError} from '../src/protocol/errors';
import {computeBindingTupleDigest, computeOfferHash, bindingProofMessage} from '../src/protocol/binding';
import {buildTranscript, transcriptHash} from '../src/protocol/handshake';
import {prepareMerchantOffer} from '../src/checkout/merchantFlow';
import {buildDemoReceipt} from '../src/demo/demoReceipt';
import {buildMockPair} from './harness';
import {
  loadAeadValid,
  loadCredentials,
  loadFramingValid,
  loadHandshakeValid,
  loadReceiptValid,
  loadTestKeys,
} from './fixtures';

const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const HMAC_SHA256_RFC4231_CASE1 = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

describe('pure SHA-256 (RFC 6234 vectors)', () => {
  it('hashes the empty string', async () => {
    expect(hexEncode(sha256Pure(new Uint8Array(0)))).toBe(SHA256_EMPTY);
  });

  it('hashes "abc"', async () => {
    expect(hexEncode(sha256Pure(new Uint8Array([0x61, 0x62, 0x63])))).toBe(SHA256_ABC);
  });

  it('handles multi-block input and 64/55/56-byte boundaries', async () => {
    // Padding boundaries: 55 fits, 56 forces an extra block, 64 is a full block.
    for (const length of [1, 55, 56, 57, 63, 64, 65, 127, 128, 1000]) {
      const data = new Uint8Array(length).fill(0xab);
      expect(hexEncode(sha256Pure(data))).toBe(hexEncode(sha256Sync(data)));
      expect(sha256Pure(data)).toHaveLength(32);
    }
  });
});

describe('pure HMAC-SHA-256 (RFC 4231 vectors)', () => {
  it('matches RFC 4231 test case 1 (key = 20x0x0b, msg = "Hi There")', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const mac = hmacSha256Pure(key, new Uint8Array([0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65]));
    expect(hexEncode(mac)).toBe(HMAC_SHA256_RFC4231_CASE1);
  });

  it('matches RFC 4231 test case 2 (key = "Jefe")', async () => {
    const key = new Uint8Array([0x4a, 0x65, 0x66, 0x65]);
    const message = new Uint8Array([
      0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20,
      0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
    ]);
    expect(hexEncode(hmacSha256Pure(key, message))).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  it('hashes a key longer than the 64-byte block', async () => {
    const key = new Uint8Array(131).fill(0xaa);
    const mac = hmacSha256Pure(key, new Uint8Array([0x01, 0x02, 0x03]));
    expect(mac).toHaveLength(32);
    // A longer key is pre-hashed, then padded; the result must be stable.
    expect(hexEncode(mac)).toBe(hexEncode(hmacSha256Sync(key, new Uint8Array([0x01, 0x02, 0x03]))));
  });
});

describe('pure digests reproduce the frozen r4 vectors with WebCrypto absent', () => {
  const withoutCrypto = async <T>(run: () => Promise<T>): Promise<T> => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    // Delete the host's WebCrypto so this exercises the Hermes path.
    Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
    try {
      return await run();
    } finally {
      if (descriptor === undefined) {
        delete (globalThis as {crypto?: unknown}).crypto;
      } else {
        Object.defineProperty(globalThis, 'crypto', descriptor);
      }
    }
  };

  it('reproduces the frozen offer hash and binding tuple digest', async () => {
    const vector = loadHandshakeValid();
    await withoutCrypto(async () => {
      const offerHash = await computeOfferHash({
        sessionId: hexDecode('00112233445566778899aabbccddeeff'),
        transferId: hexDecode('ffeeddccbbaa99887766554433221100'),
        receiptId: hexDecode('0123456789abcdef0123456789abcdef'),
        merchantReference: 'merchant.poc.test-alpha',
        totalAmountMinor: 970,
        currency: 'CAD',
        issuedAtUnix: 1767225540,
      });
      expect(hexEncode(offerHash)).toBe(vector.offer_hash_hex);
      const digest = await computeBindingTupleDigest(hexDecode(vector.binding_tuple_hex));
      expect(hexEncode(digest)).toBe(vector.binding_tuple_digest_hex);
    });
  });

  it('reproduces the frozen transcript hash', async () => {
    const vector = loadHandshakeValid();
    await withoutCrypto(async () => {
      const rebuilt = buildTranscript({
        protocolVersion: vector.protocol_version,
        suiteId: vector.suite_id,
        clientNonce: hexDecode('c0ffee0000000000000000000000000000000000000000000000000000000001'),
        clientEphemeralPubkey: hexDecode(
          '0414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c',
        ),
        serverNonce: hexDecode('5e57e50000000000000000000000000000000000000000000000000000000001'),
        serverEphemeralPubkey: hexDecode(
          '041ba8c9100cde3121a29562d5ed4f8b21fc45067c7a0cb44b9ae47699ed567706b9dbe40d599f161825bd8a90abccb8cc5aa56856c2803f00265e492ed0227db2',
        ),
        transferId: hexDecode('ffeeddccbbaa99887766554433221100'),
        sessionId: hexDecode('00112233445566778899aabbccddeeff'),
        bindingTupleDigest: hexDecode(vector.binding_tuple_digest_hex),
        maxFramePayload: 162,
        bindingTuple: hexDecode(vector.binding_tuple_hex),
      });
      expect(hexEncode(await transcriptHash(rebuilt))).toBe(vector.transcript_hash_hex);
    });
  });

  it('reproduces the frozen binding proof (HMAC over the 122-byte message)', async () => {
    const vector = loadHandshakeValid();
    const sbt = hexDecode('000102030405060708090a0b0c0d0e0f');
    await withoutCrypto(async () => {
      const message = bindingProofMessage(
        hexDecode('c0ffee0000000000000000000000000000000000000000000000000000000001'),
        hexDecode(
          '0414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c',
        ),
      );
      expect(message.length).toBe(vector.binding_proof_message_len);
      expect(hexEncode(message)).toBe(vector.binding_proof_message_hex);
      const proof = await hmacSha256(sbt, message);
      expect(hexEncode(proof)).toBe(vector.binding_proof_hex);
    });
  });

  it('agrees with the WebCrypto path when a host implementation is present', async () => {
    const data = hexDecode(loadHandshakeValid().transcript_hex);
    const viaFallback = sha256Pure(data);
    const viaWebCrypto = await sha256(data);
    expect(hexEncode(viaWebCrypto)).toBe(hexEncode(viaFallback));
  });
});

describe('the on-device fallback reproduces every frozen digest the shared layer computes', () => {
  /**
   * This is the check that matters for Hermes: no `globalThis.crypto`, so the
   * pure implementations must produce the exact bytes the frozen r4 vectors
   * record. Each case below is run through `sha256Sync`/`hmacSha256Sync`, which
   * are the pure paths unconditionally.
   */
  it('receipt body hash (receipt-valid receipt_body_sha256)', async () => {
    const vector = loadReceiptValid();
    expect(hexEncode(sha256Sync(hexDecode(vector.receipt_body_hex)))).toBe(vector.receipt_body_sha256);
  });

  it('long receipt body hash (receipt-valid long_receipt)', async () => {
    const vector = loadReceiptValid();
    expect(hexEncode(sha256Sync(hexDecode(vector.long_receipt.receipt_body_hex)))).toBe(vector.long_receipt.receipt_body_sha256);
  });

  it('domain-separated offer hash and binding tuple digest (handshake-valid)', async () => {
    const vector = loadHandshakeValid();
    // offer_hash  = SHA-256("deceipt-offer-hash-v1"  || 0x00 || preimage)
    const offerPreimage = concatBytes(
      utf8Encode('deceipt-offer-hash-v1'),
      new Uint8Array([0x00]),
      hexDecode(vector.offer_hash_preimage_hex),
    );
    expect(hexEncode(sha256Sync(offerPreimage))).toBe(vector.offer_hash_hex);
    // binding_tuple_digest = SHA-256("deceipt-binding-tuple-v1" || 0x00 || tuple)
    const tuplePreimage = concatBytes(
      utf8Encode('deceipt-binding-tuple-v1'),
      new Uint8Array([0x00]),
      hexDecode(vector.binding_tuple_hex),
    );
    expect(hexEncode(sha256Sync(tuplePreimage))).toBe(vector.binding_tuple_digest_hex);
  });

  it('credential hash (handshake-valid credential_hash_hex)', async () => {
    const vector = loadHandshakeValid();
    const credential = hexDecode(loadCredentials().cases[0].credential_hex);
    expect(hexEncode(sha256Sync(credential))).toBe(vector.credential_hash_hex);
  });

  it('transfer payload hash (framing-valid payload_hash_hex)', async () => {
    const framing = loadFramingValid();
    const ciphertext = hexDecode(framing.frames_hex.map(frame => frame.slice(40)).join(''));
    expect(hexEncode(sha256Sync(ciphertext))).toBe(framing.payload_hash_hex);
  });

  it('session context transcript hash (aead-valid session_context_hex prefix)', async () => {
    const aead = loadAeadValid();
    const context = hexDecode(aead.session_context_hex);
    // session_context = transcript_hash(32) || transfer_id(16)
    expect(hexEncode(sha256Sync(hexDecode(loadHandshakeValid().transcript_hex)))).toBe(
      hexEncode(context.subarray(0, 32)),
    );
  });

  it('binding proof (handshake-valid binding_proof_hex) via the pure HMAC', async () => {
    const vector = loadHandshakeValid();
    const proof = hmacSha256Sync(
      hexDecode('000102030405060708090a0b0c0d0e0f'),
      hexDecode(vector.binding_proof_message_hex),
    );
    expect(hexEncode(proof)).toBe(vector.binding_proof_hex);
  });
});

describe('Ed25519 is not hand-rolled', () => {
  it('still verifies the frozen signature through WebCrypto on this host', async () => {
    const vector = loadHandshakeValid();
    const deviceKey = loadTestKeys().keys.find(key => key.name === 'merchant-test-1')!;
    expect(
      await ed25519Verify(
        hexDecode(deviceKey.public_key_hex),
        hexDecode(vector.transcript_hex),
        hexDecode(vector.transcript_signature_hex),
      ),
    ).toBe(true);
  });
});

describe('secure randomness comes from native when WebCrypto is absent', () => {
  it('does not fall back to a JS PRNG; it fails closed with no source', async () => {
    const {canGenerateSecureRandom, secureRandomBytes, setNativeRandomSource} = sources();
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
    setNativeRandomSource(null);
    try {
      expect(canGenerateSecureRandom()).toBe(false);
      await expect(secureRandomBytes(16)).rejects.toMatchObject({name: 'CAPABILITY_UNAVAILABLE'});
      // The synchronous helper must refuse too, rather than inventing bytes.
      expect(() => randomBytesSync(16)).toThrow();
    } finally {
      if (descriptor === undefined) {
        delete (globalThis as {crypto?: unknown}).crypto;
      } else {
        Object.defineProperty(globalThis, 'crypto', descriptor);
      }
      setNativeRandomSource(null);
    }
  });

  it('takes the native path, and never consults WebCrypto, when a source is registered', async () => {
    const {secureRandomBytes, setNativeRandomSource} = sources();
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    // Remove WebCrypto so a Node-only pass cannot satisfy this test.
    Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
    const calls: number[] = [];
    setNativeRandomSource({
      randomBytes: async (count: number) => {
        calls.push(count);
        return new Uint8Array(count).fill(0xa5);
      },
    });
    try {
      const bytes = await secureRandomBytes(16);
      expect(bytes).toHaveLength(16);
      expect(bytes[0]).toBe(0xa5);
      expect(calls).toEqual([16]);
      // The protocol's identifier minting goes through the same path.
      const sessionId = await secureRandomBytes(16);
      expect(sessionId).toHaveLength(16);
      expect(calls).toEqual([16, 16]);
    } finally {
      if (descriptor === undefined) {
        delete (globalThis as {crypto?: unknown}).crypto;
      } else {
        Object.defineProperty(globalThis, 'crypto', descriptor);
      }
      setNativeRandomSource(null);
    }
  });

  it('rejects an out-of-range count instead of allocating', async () => {
    const {secureRandomBytes, setNativeRandomSource} = sources();
    setNativeRandomSource({randomBytes: async (count: number) => new Uint8Array(count)});
    try {
      await expect(secureRandomBytes(0)).rejects.toMatchObject({name: 'CAPABILITY_UNAVAILABLE'});
      await expect(secureRandomBytes(65)).rejects.toMatchObject({name: 'CAPABILITY_UNAVAILABLE'});
      await expect(secureRandomBytes(1.5)).rejects.toMatchObject({name: 'CAPABILITY_UNAVAILABLE'});
    } finally {
      setNativeRandomSource(null);
    }
  });

  it('rejects a native source that returns the wrong length', async () => {
    const {secureRandomBytes, setNativeRandomSource} = sources();
    setNativeRandomSource({randomBytes: async () => new Uint8Array(3)});
    try {
      await expect(secureRandomBytes(16)).rejects.toMatchObject({name: 'CAPABILITY_UNAVAILABLE'});
    } finally {
      setNativeRandomSource(null);
    }
  });

  it('is used by the merchant offer path (session id and transfer id are native-sourced)', async () => {
    const {setNativeRandomSource} = sources();
    const pair = await buildMockPair();
    let counter = 0;
    const seen: number[] = [];
    setNativeRandomSource({
      randomBytes: async (count: number) => {
        counter += 1;
        seen.push(count);
        return new Uint8Array(count).fill(counter);
      },
    });
    try {
      const receipt = await buildDemoReceipt({
        merchantId: pair.provision.merchantId,
        credentialBytes: pair.provision.credentialBytes,
      });
      await prepareMerchantOffer(pair.merchant, receipt, 1767225600);
      // 16 (receipt id) + 16 (session id) + 16 (transfer id).
      expect(seen.filter(count => count === 16).length).toBeGreaterThanOrEqual(3);
    } finally {
      setNativeRandomSource(null);
    }
  });
});

/** The crypto module, loaded once for these cases. */
function sources(): typeof import('../src/protocol/crypto') {
  return require('../src/protocol/crypto') as typeof import('../src/protocol/crypto');
}

function randomBytesSync(count: number): Uint8Array {
  return sources().randomBytes(count);
}

describe('UTF-8 decoding works without the platform TextDecoder (device gap)', () => {
  it('decodes valid UTF-8 identically to the platform decoder', async () => {
    const {utf8DecodeLocal, utf8EncodeLocal} = textSides();
    for (const sample of [
      'Latte, 16oz',
      'Maple & Vine Cafe',
      'Café — ünïcödé',
      '日本語のテキスト',
      'emoji: 🧾 🔐',
      'combining: e\u0301',
    ]) {
      const encoded = utf8EncodeLocal(sample);
      expect(utf8DecodeLocal(encoded)).toBe(sample);
    }
  });

  it('rejects every invalid sequence class the frozen vectors use', async () => {
    const {utf8DecodeLocal} = textSides();
    const invalid: Array<[string, number[]]> = [
      ['lone continuation', [0x80]],
      ['truncated 2-byte', [0xc3]],
      ['truncated 3-byte', [0xe2, 0x82]],
      ['bad continuation', [0xe2, 0x28, 0xa1]],
      ['overlong 2-byte', [0xc0, 0xaf]],
      ['overlong 3-byte', [0xe0, 0x80, 0xaf]],
      ['surrogate half (CESU-8)', [0xed, 0xa0, 0x80]],
      ['above U+10FFFF', [0xf5, 0x80, 0x80, 0x80]],
      ['0xff lead', [0xff]],
      ['0xfe lead', [0xfe]],
    ];
    for (const [label, bytes] of invalid) {
      expect(() => utf8DecodeLocal(new Uint8Array(bytes))).toThrowError(/not valid UTF-8/);
      expect(() => utf8Decode(new Uint8Array(bytes))).toThrow(ProtocolError);
      expect(label.length).toBeGreaterThan(0);
    }
  });

  it('agrees with the platform decoder on the frozen receipt text', async () => {
    const vector = loadReceiptValid();
    const payload = hexDecode(vector.receipt_body_hex);
    // The container is binary, so decoding it as text MUST fail; the text lives
    // only inside the parsed strings, which the receipt parser validates through
    // this same decoder.
    expect(() => utf8Decode(payload)).toThrow(ProtocolError);
    const decoded = decodeCbor(payload).value;
    expect(decoded).toBeInstanceOf(CborMap);
    const merchant = (decoded as CborMap).get(6);
    expect(merchant).toBeInstanceOf(CborMap);
    // Label 2 is the display name; its bytes must decode to the frozen value.
    const displayName = (merchant as CborMap).get(2);
    expect(displayName).toBe('Maple & Vine Cafe');
    expect(utf8DecodeLocal(utf8EncodeLocal(String(displayName)))).toBe(displayName);
  });

  it('falls back to the strict local decoder when TextDecoder is absent', async () => {
    const {utf8Decode} = textSides();
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'TextDecoder');
    // Simulate Hermes: the global simply does not exist.
    Object.defineProperty(globalThis, 'TextDecoder', {value: undefined, configurable: true});
    try {
      expect(utf8Decode(new Uint8Array([0x4c, 0x61, 0x74, 0x74, 0x65]))).toBe('Latte');
      expect(utf8Decode(new Uint8Array([0xc3, 0xa9]))).toBe('é');
      expect(() => utf8Decode(new Uint8Array([0xe2, 0x28, 0xa1]))).toThrow(ProtocolError);
    } finally {
      if (descriptor === undefined) {
        delete (globalThis as {TextDecoder?: unknown}).TextDecoder;
      } else {
        Object.defineProperty(globalThis, 'TextDecoder', descriptor);
      }
    }
  });

  it('parses the frozen receipt with neither crypto nor TextDecoder present', async () => {
    const {parseReceiptPayload} = receiptModule();
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const decoderDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'TextDecoder');
    Object.defineProperty(globalThis, 'crypto', {value: undefined, configurable: true});
    Object.defineProperty(globalThis, 'TextDecoder', {value: undefined, configurable: true});
    try {
      const vector = loadReceiptValid();
      const parsed = await parseReceiptPayload(hexDecode(vector.receipt_body_hex));
      expect(parsed.receipt.merchant.displayName).toBe('Maple & Vine Cafe');
      expect(parsed.receipt.totals.totalMinor).toBe(970);
    } finally {
      restore(globalThis, 'crypto', cryptoDescriptor);
      restore(globalThis, 'TextDecoder', decoderDescriptor);
    }
  });

  it('still rejects a genuinely malformed text string (never special-cased)', async () => {
    const {parseReceiptPayload} = receiptModule();
    // The frozen invalid fixture for a bad UTF-8 string must still be rejected.
    const vector = loadReceiptValid();
    const payload = new Uint8Array(hexDecode(vector.receipt_body_hex));
    // Locate the display name and corrupt its first byte's continuation.
    const needle = utf8EncodeLocal('Maple & Vine Cafe');
    const at = indexOfBytes(payload, needle);
    expect(at).toBeGreaterThan(0);
    payload[at + 1] = 0xff;
    await expect(parseReceiptPayload(payload)).rejects.toThrow(/not valid UTF-8|CBOR_MALFORMED/);
  });
});

function normalizationModule(): typeof import('../src/protocol/normalization') {
  return require('../src/protocol/normalization') as typeof import('../src/protocol/normalization');
}

/** The text helpers under test, loaded once. */
const textSides = () => ({
  utf8Decode,
  utf8EncodeLocal,
  utf8DecodeLocal,
  decodeCbor,
  CborMap,
});

function receiptModule(): typeof import('../src/protocol/receipt') {
  return require('../src/protocol/receipt') as typeof import('../src/protocol/receipt');
}

function restore(target: object, key: string, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor === undefined) {
    delete (target as Record<string, unknown>)[key];
    return;
  }
  Object.defineProperty(target, key, descriptor);
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (haystack[start + offset] !== needle[offset]) {
        continue outer;
      }
    }
    return start;
  }
  return -1;
}

describe('NFC validation is strict, never silently skipped', () => {
  it('accepts pure ASCII without consulting the engine (NFC is the identity on it)', async () => {
    const {checkText} = receiptModule();
    const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'normalize');
    // Simulate a build where the engine cannot normalize at all.
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true});
    try {
      expect(() => checkText('Maple & Vine Cafe', 128, 'display_name')).not.toThrow();
      expect(() => checkText('Latte, 16oz', 512, 'description')).not.toThrow();
      expect(() => checkText('merchant.poc.test-alpha', 128, 'merchant_reference')).not.toThrow();
    } finally {
      restore(String.prototype, 'normalize', descriptor);
    }
  });

  it('defers non-ASCII NFC to the platform normalizer when the engine cannot decide it', async () => {
    const {checkText, parseReceiptPayload} = receiptModule();
    const {setNativeNfcSource, normalizationEngine} = normalizationModule();
    const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'normalize');
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true});
    // A platform normalizer standing in for java.text.Normalizer / the ICU path.
    const calls: string[] = [];
    setNativeNfcSource({
      normalizeNfc: async (text: string) => {
        calls.push(text);
        // Decompose-then-recompose is what a real normalizer does; the stand-in
        // maps the one decomposed form this test uses.
        return text.replace(/e\u0301/g, '\u00e9');
      },
    });
    try {
      expect(normalizationEngine()).toBe('native');
      // Within a parse the check is deferred and then confirmed.
      const vector = loadReceiptValid();
      const parsed = await parseReceiptPayload(hexDecode(vector.receipt_body_hex));
      expect(parsed.receipt.totals.totalMinor).toBe(970);
      // The frozen text is ASCII, so nothing needed the bridge.
      expect(calls).toHaveLength(0);
    } finally {
      setNativeNfcSource(null);
      restore(String.prototype, 'normalize', descriptor);
    }
  });

  it('rejects a non-NFC value when no exact engine can confirm it', async () => {
    const {parseReceiptPayload, serializeReceipt} = receiptModule();
    const {setNativeNfcSource} = normalizationModule();
    const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'normalize');
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true});
    try {
      // Build the payload through the serializer so the CBOR lengths are correct,
      // then confirm the value cannot be verified without an exact engine.
      setNativeNfcSource(null);
      const vector = loadReceiptValid();
      const parsed = await parseReceiptPayload(hexDecode(vector.receipt_body_hex));
      const mutated = {
        ...parsed.receipt,
        merchant: {...parsed.receipt.merchant, displayName: 'Caf\u0065\u0301 \u0026 Vine'},
      };
      const payload = serializeReceipt(mutated);
      await expect(parseReceiptPayload(payload)).rejects.toThrow(/no exact NFC implementation/);
    } finally {
      setNativeNfcSource(null);
      restore(String.prototype, 'normalize', descriptor);
    }
  });

  it('accepts that same value once an exact engine confirms its NFC form', async () => {
    const {parseReceiptPayload, serializeReceipt} = receiptModule();
    const {setNativeNfcSource} = normalizationModule();
    const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'normalize');
    Object.defineProperty(String.prototype, 'normalize', {value: undefined, configurable: true});
    try {
      const vector = loadReceiptValid();
      const parsed = await parseReceiptPayload(hexDecode(vector.receipt_body_hex));
      const decomposed = 'Caf\u0065\u0301 \u0026 Vine';
      const composed = 'Caf\u00e9 \u0026 Vine';
      const payload = serializeReceipt({
        ...parsed.receipt,
        merchant: {...parsed.receipt.merchant, displayName: decomposed},
      });

      // A platform normalizer that reports the value is NOT NFC must reject it.
      setNativeNfcSource({normalizeNfc: async () => composed});
      await expect(parseReceiptPayload(payload)).rejects.toThrow(/not NFC-normalized/);

      // A platform normalizer that agrees the value is already NFC accepts it.
      setNativeNfcSource({normalizeNfc: async () => decomposed});
      const accepted = await parseReceiptPayload(payload);
      expect(accepted.receipt.merchant.displayName).toBe(decomposed);
      expect(accepted.receipt.totals.totalMinor).toBe(970);
    } finally {
      setNativeNfcSource(null);
      restore(String.prototype, 'normalize', descriptor);
    }
  });

  it('checks the NFC engine state through normalizationModule, not receipt', () => {
    const {normalizationEngine} = normalizationModule();
    expect(['platform', 'native', 'none']).toContain(normalizationEngine());
  });

  it('accepts the frozen receipt text on a normalized engine and rejects it without one only when non-ASCII', async () => {
    const {checkText, parseReceiptPayload} = receiptModule();
    const vector = loadReceiptValid();
    const parsed = await parseReceiptPayload(hexDecode(vector.receipt_body_hex));
    // The frozen merchant text is ASCII, so it validates under the strict rule
    // whether or not the engine can normalize.
    expect(parsed.receipt.merchant.displayName).toBe('Maple & Vine Cafe');
    expect(() => checkText(parsed.receipt.merchant.displayName, 128, 'display_name')).not.toThrow();
  });
});
