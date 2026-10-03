/// <reference types="node" />
/**
 * Typed loaders for A1's frozen vectors. Tests read the vectors from
 * `protocol/vectors/**` and `protocol/flows/vectors/**` directly so that every
 * expectation comes from the frozen revision, never from this implementation
 * (conformance.md §F).
 *
 * These loaders live in test code only; the shipped app never reads the repo
 * tree, and no test private key is bundled into a build (conformance B9).
 */

import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

export function loadVector<T>(relativePath: string): T {
  const absolute = path.join(REPO_ROOT, relativePath);
  return JSON.parse(fs.readFileSync(absolute, 'utf8')) as T;
}

export function loadBytes(relativePath: string): Uint8Array {
  return new Uint8Array(fs.readFileSync(path.join(REPO_ROOT, relativePath)));
}

export interface ErrorEntry {
  name: string;
  code: number;
  fatal: boolean;
  retryable: boolean;
  category: string;
}

export interface ErrorsVector {
  revision: string;
  outcomes: Array<{name: string; code: number}>;
  errors: ErrorEntry[];
}

export interface ReceiptValidVector {
  revision: string;
  receipt_body_hex: string;
  receipt_body_len: number;
  receipt_body_sha256: string;
  protected_bstr_hex: string;
  protected_map: Record<string, unknown>;
  sig_structure_hex: string;
  signature_hex: string;
  cose_sign1_hex: string;
  cose_sign1_len: number;
  receipt_offer_hex: string;
  expected_verification: {
    signature_valid: boolean;
    key_authorized: boolean;
    credential_temporally_acceptable: boolean;
    semantically_valid: boolean;
    unique_locally: boolean;
    outcome: string;
    error: string | null;
  };
  arithmetic: {
    lines: number[][];
    line_gross_minor: number[];
    subtotal_minor: number;
    discount_total_minor: number;
    tax_total_minor: number;
    tax_added_total_minor: number;
    tip_minor: number;
    total_minor: number;
    currency: string;
    currency_exponent: number;
    human_total: string;
  };
  dedup_semantics: Record<string, string>;
  long_receipt: {
    receipt_body_sha256: string;
    receipt_body_len: number;
    cose_sign1_len: number;
    lines: number;
    total_minor: number;
    receipt_body_hex: string;
  };
}

export interface ReceiptInvalidCase {
  case: string;
  cose_sign1_hex: string;
  expected_error: string | null;
  expected_outcome: string;
  fatal: boolean;
  note: string;
  session_credential_hex: string | null;
  receipt_offer_hex: string | null;
  seen_receipt_ids_hex: Record<string, string> | null;
  anchors_hex: Record<string, string>;
  verify_at_unix: number;
}

export interface ReceiptInvalidVector {
  revision: string;
  cases: ReceiptInvalidCase[];
}

export interface CredentialCase {
  case: string;
  credential_hex: string;
  credential_body_hex: string;
  expected_error: string | null;
  expected_trust: string;
  verify_at_unix: number;
  anchors_hex: Record<string, string>;
}

export interface CredentialsVector {
  revision: string;
  content_type: string;
  cases: CredentialCase[];
}

export interface EncodingInvalidCase {
  case: string;
  bytes_hex: string;
  expected_error: string;
}

export interface HandshakeValidVector {
  revision: string;
  transcript_len: number;
  protocol_version: number;
  suite_id: number;
  client_hello_hex: string;
  server_hello_hex: string;
  client_hello_pdu_hex: string;
  server_hello_pdu_hex: string;
  offer_hash_preimage_hex: string;
  offer_hash_hex: string;
  binding_tuple_hex: string;
  binding_tuple_len: number;
  binding_tuple_digest_hex: string;
  binding_proof_message_hex: string;
  binding_proof_message_len: number;
  binding_proof_hex: string;
  transcript_hex: string;
  transcript_hash_hex: string;
  transcript_signature_hex: string;
  shared_secret_hex: string;
  keys: Record<string, string>;
  session_context_hex: string;
  credential_hash_hex: string;
  transcript_layout: Array<{offset: number; field: string; size_bytes: number}>;
}

export interface HandshakeInvalidCase {
  case: string;
  expected_error: string;
  note: string;
  client_hello_hex?: string;
  server_hello_hex?: string;
  transcript_hex?: string;
  transcript_signature_hex?: string;
  offending_point_hex?: string;
  offer_receipt_id_hex?: string;
  qr_receipt_id_hex?: string;
  binding_claimed_at_unix?: number;
  binding_expires_at_unix?: number;
  prior_claims?: number;
  merchant_max_frame_payload?: number;
}

export interface AeadValidVector {
  revision: string;
  session_context_hex: string;
  payload_seal: {key: string; counter: number; plaintext_hex: string; ciphertext_hex: string};
  control_offer: {key: string; counter: number; direction: string; plaintext_hex: string; envelope_hex: string};
  control_transfer_begin: {key: string; counter: number; direction: string; plaintext_hex: string; envelope_hex: string};
  control_accept: {key: string; counter: number; direction: string; plaintext_hex: string; envelope_hex: string};
}

export interface AeadInvalidCase {
  case: string;
  key: string;
  direction: string;
  session_context_hex: string;
  envelope_or_ciphertext_hex: string;
  expected_counter?: number;
  expected_error: string;
  note: string;
}

export interface FramingValidVector {
  revision: string;
  frame_format: string;
  transfer_id_hex: string;
  frame_size: number;
  att_mtu_example: number;
  att_payload_max_example: number;
  frame_count: number;
  ciphertext_len: number;
  payload_hash_hex: string;
  frames_hex: string[];
  ack_example: Record<string, unknown>;
  ack_example_plaintext_hex: string;
}

export interface FramingInvalidCase {
  case: string;
  expected_error: string;
  note: string;
  frame_size?: number;
  peer_max_frame_payload?: number;
  frame_count?: number;
  frame_hex?: string;
  duplicate_byte_identical_hex?: string;
  duplicate_conflicting_hex?: string;
  originals_hex?: string[];
  window_floor?: number;
  expected_payload_hash_hex?: string;
  observed_payload_hash_hex?: string;
  received_frames?: number;
  declared_frames?: number;
  actual_frames?: number;
  ciphertext_length?: number;
  max_transfer_ciphertext?: number;
  max_frames?: number;
  retries_used?: number;
  elapsed_ms?: number;
  cancel_from?: string;
  disposition?: string;
  final_frame_payload_bytes?: number;
}

export interface LpduValidVector {
  revision: string;
  server_hello_pdu_hex: string;
  server_hello_pdu_len: number;
  frag_payload_max: number;
  att_mtu_example: number;
  fragments_hex: string[];
  fragment_count: number;
}

export interface LpduInvalidCase {
  case: string;
  expected_error: string;
  note: string;
  fragments_hex?: string[];
  pdu_len?: number;
  fragment_count?: number;
  received_fragments?: number;
  expected_fragments?: number;
  elapsed_ms?: number;
}

export interface TestKeysVector {
  revision: string;
  keys: Array<{
    name: string;
    type: string;
    private_seed_hex?: string;
    private_scalar_hex?: string;
    public_key_hex: string;
    trust_anchor?: boolean;
    note?: string;
  }>;
}

export interface TrustAnchorsVector {
  revision: string;
  anchors: Array<{anchor_id_hex: string; algorithm: string; cose_alg: number; public_key_hex: string; label: string; test_only: boolean}>;
}

export interface BindingVector {
  schema: string;
  revision: string;
  vectors: Array<{
    id: string;
    [key: string]: unknown;
  }>;
}

export const vectorPaths = {
  receiptValid: 'protocol/vectors/receipt-valid.json',
  receiptInvalid: 'protocol/vectors/receipt-invalid.json',
  arithmeticValid: 'protocol/vectors/arithmetic-valid.json',
  credentials: 'protocol/vectors/credentials.json',
  encodingInvalid: 'protocol/vectors/encoding-invalid.json',
  errors: 'protocol/vectors/errors.json',
  handshakeValid: 'protocol/vectors/handshake-valid.json',
  unverifiedPeer: 'protocol/vectors/handshake-unverified-peer.json',
  handshakeInvalid: 'protocol/vectors/handshake-invalid.json',
  aeadValid: 'protocol/vectors/aead-valid.json',
  aeadInvalid: 'protocol/vectors/aead-invalid.json',
  framingValid: 'protocol/vectors/framing-valid.json',
  framingInvalid: 'protocol/vectors/framing-invalid.json',
  lpduValid: 'protocol/vectors/lpdu-valid.json',
  lpduInvalid: 'protocol/vectors/lpdu-invalid.json',
  testKeys: 'protocol/vectors/keys/test-keys.json',
  trustAnchors: 'protocol/vectors/fixtures/trust-anchors-v1.json',
  validCredential: 'protocol/vectors/fixtures/valid-credential.cbor',
  checkoutFlow: 'protocol/flows/checkout-flow-v1.json',
  binding: 'protocol/flows/vectors/binding-v1.json',
} as const;

export function loadErrors(): ErrorsVector {
  return loadVector<ErrorsVector>(vectorPaths.errors);
}

export function loadReceiptValid(): ReceiptValidVector {
  return loadVector<ReceiptValidVector>(vectorPaths.receiptValid);
}

export function loadReceiptInvalid(): ReceiptInvalidVector {
  return loadVector<ReceiptInvalidVector>(vectorPaths.receiptInvalid);
}

export function loadCredentials(): CredentialsVector {
  return loadVector<CredentialsVector>(vectorPaths.credentials);
}

export function loadHandshakeValid(): HandshakeValidVector {
  return loadVector<HandshakeValidVector>(vectorPaths.handshakeValid);
}

export function loadAeadValid(): AeadValidVector {
  return loadVector<AeadValidVector>(vectorPaths.aeadValid);
}

export function loadFramingValid(): FramingValidVector {
  return loadVector<FramingValidVector>(vectorPaths.framingValid);
}

export function loadTestKeys(): TestKeysVector {
  return loadVector<TestKeysVector>(vectorPaths.testKeys);
}

export function loadTrustAnchors(): TrustAnchorsVector {
  return loadVector<TrustAnchorsVector>(vectorPaths.trustAnchors);
}

/** A test-only key by name; throws when absent so a typo fails loudly. */
export function testKey(name: string): TestKeysVector['keys'][number] {
  const key = loadTestKeys().keys.find(candidate => candidate.name === name);
  if (key === undefined) {
    throw new Error(`test key "${name}" is not in ${vectorPaths.testKeys}`);
  }
  return key;
}
