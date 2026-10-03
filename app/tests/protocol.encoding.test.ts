/**
 * Encoding conformance: the deterministic-CBOR profile and the frozen
 * `encoding-invalid.json` fixtures, plus round-trips of every frozen byte blob.
 */

import {CborMap, checkCanonical, decodeCbor, encodeCbor} from '../src/protocol/cbor';
import {hexDecode, hexEncode} from '../src/protocol/bytes';
import {ProtocolError} from '../src/protocol/errors';
import {loadVector, vectorPaths, type EncodingInvalidCase} from './fixtures';
import {loadHandshakeValid, loadReceiptValid} from './fixtures';

interface EncodingVector {
  cases: EncodingInvalidCase[];
}

describe('deterministic CBOR — invalid fixtures', () => {
  const cases = loadVector<EncodingVector>(vectorPaths.encodingInvalid).cases;

  it.each(cases.map(testCase => [testCase.case, testCase.bytes_hex, testCase.expected_error]))(
    '%s => %s',
    (_name, bytesHex, expectedError) => {
      let thrown: ProtocolError | null = null;
      try {
        decodeCbor(hexDecode(bytesHex));
      } catch (error) {
        thrown = error as ProtocolError;
      }
      expect(thrown).not.toBeNull();
      expect(thrown!.name).toBe(expectedError);
    },
  );

  it('covers every documented rejection class', () => {
    const names = new Set(cases.map(testCase => testCase.expected_error));
    expect(names).toContain('CBOR_DUPLICATE_KEY');
    expect(names).toContain('CBOR_NONCANONICAL');
    expect(names).toContain('CBOR_UNSUPPORTED_TYPE');
    expect(names).toContain('CBOR_MALFORMED');
    expect(names).toContain('CBOR_DEPTH_EXCEEDED');
    expect(names).toContain('CBOR_SIZE_EXCEEDED');
  });
});

describe('deterministic CBOR — frozen blobs round-trip byte-for-byte', () => {
  const receipt = loadReceiptValid();
  const handshake = loadHandshakeValid();
  const blobs: Array<[string, string]> = [
    ['receipt body', receipt.receipt_body_hex],
    ['COSE_Sign1', receipt.cose_sign1_hex],
    ['protected header', receipt.protected_bstr_hex],
    ['Sig_structure', receipt.sig_structure_hex],
    ['ClientHello', handshake.client_hello_hex],
    ['ServerHello', handshake.server_hello_hex],
    ['binding tuple', handshake.binding_tuple_hex],
    ['offer hash preimage', handshake.offer_hash_preimage_hex],
  ];

  it.each(blobs)('%s', (_label, hex) => {
    const bytes = hexDecode(hex);
    const decoded = decodeCbor(bytes);
    expect(hexEncode(encodeCbor(decoded.value))).toBe(hex);
    expect(checkCanonical(bytes).canonical).toBe(true);
  });
});

describe('deterministic CBOR — encoder rules', () => {
  it('rejects floats, null and non-integer map keys', () => {
    expect(() => encodeCbor(1.5)).toThrow(ProtocolError);
    expect(() => encodeCbor(null as never)).toThrow(ProtocolError);
    const keyed = CborMap.of([[300, 1]]);
    expect(() => encodeCbor(keyed)).toThrow(ProtocolError);
  });

  it('encodes minimal integer arguments, including above 2^31', () => {
    expect(hexEncode(encodeCbor(23))).toBe('17');
    expect(hexEncode(encodeCbor(24))).toBe('1818');
    expect(hexEncode(encodeCbor(255))).toBe('18ff');
    expect(hexEncode(encodeCbor(256))).toBe('190100');
    // 2_000_000_000_000 is well above the int32 boundary; a naive `>>` would
    // silently truncate it (this is the case monetary_out_of_range exercises).
    expect(hexEncode(encodeCbor(2_000_000_000_000))).toBe('1b000001d1a94a2000');
    expect(hexEncode(encodeCbor(1_000_000_000_000_000))).toBe('1b00038d7ea4c68000');
  });

  it('sorts map keys ascending regardless of insertion order', () => {
    const map = CborMap.of([
      [8, 'CAD'],
      [1, 1],
    ]);
    expect(hexEncode(encodeCbor(map))).toBe('a201010863434144');
  });
});
