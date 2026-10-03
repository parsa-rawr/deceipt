# Conformance checklist

**Revision:** `deceipt-proto-r2` · **Owner of execution:** A6 (independent) · **Owners of the code:** A3, A4, A5

A3/A4/A5 are accepted only if every applicable row passes against this revision. A6 derives expectations **only** from `protocol/vectors/**`, never from the implementation under test.

## A. Receipt (A3 shared, A4/A5 native sign/verify)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| A1 | Reproduce the 669-byte receipt body from the field tables | `receipt-valid.json#receipt_body_hex` | byte-identical |
| A2 | Ed25519 verify over `Sig_structure` of the exact bytes | `receipt-valid.json` | pass |
| A3 | Ed25519 sign reproduces the signature with the test key | `receipt-valid.json#signature_hex` | identical signature (Ed25519 is deterministic) |
| A4 | COSE_Sign1 container parse + canonical check | `receipt-valid.json#cose_sign1_hex` | accept |
| A5 | Unknown protected header / `crit` / non-empty unprotected | `receipt-invalid.json` | `RECEIPT_UNKNOWN_HEADER` |
| A6 | Version / algorithm / content-type rejection | `receipt-invalid.json` | `RECEIPT_UNSUPPORTED_VERSION` / `RECEIPT_UNSUPPORTED_ALGORITHM` |
| A7 | Signature tamper | `receipt-invalid.json#receipt_signature_tampered` | `RECEIPT_SIGNATURE_INVALID` |
| A8 | Non-canonical payload **and** container | `receipt-invalid.json` | `RECEIPT_NONCANONICAL` |
| A9 | Unknown top-level/extension field, unknown critical extension | `receipt-invalid.json` | `RECEIPT_UNKNOWN_FIELD`, `RECEIPT_UNKNOWN_CRITICAL_EXTENSION` |
| A10 | Arithmetic: line/total/discount/tax mismatches | `receipt-invalid.json` | `RECEIPT_ARITHMETIC_MISMATCH` |
| A11 | Fractional quantities exact, half-away rounding | `arithmetic-valid.json` | `TRUSTED`, no float path |
| A12 | Monetary range, unsupported currency, qty scale | `receipt-invalid.json` | `RECEIPT_MONETARY_RANGE`, `RECEIPT_UNSUPPORTED_CURRENCY` |
| A13 | Text: non-NFC, bidi control, control char | `receipt-invalid.json` | `RECEIPT_TEXT_INVALID` |
| A14 | Bound: > 65536-byte container (signed) and oversized opaque bytes | `receipt-invalid.json#receipt_oversize_signed` / `#receipt_oversize_raw` | `RECEIPT_SIZE_EXCEEDED` before parse |
| A15 | 256-line long receipt parses and verifies | `receipt-valid.json#long_receipt` | `TRUSTED` |

## B. Trust (A4/A5)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| B1 | Valid credential from the pinned anchor | `credentials.json#valid_trusted_issuer` | `authenticated` |
| B2 | Unknown issuer, otherwise valid | `credentials.json#unknown_issuer` | `CREDENTIAL_UNKNOWN_ISSUER`, trust `unknown_issuer` |
| B3 | **A valid signature plus an unknown key is never trusted** | `receipt-invalid.json#unknown_issuer_credential` | outcome `UNVERIFIED_UNKNOWN_ISSUER`, never `TRUSTED` |
| B4 | Tampered / truncated / wrong-content-type credential | `credentials.json` | `CREDENTIAL_SIGNATURE_INVALID` / `CREDENTIAL_MALFORMED` |
| B5 | Expired / not-yet-valid | `credentials.json` | `CREDENTIAL_EXPIRED` / `CREDENTIAL_NOT_YET_VALID` |
| B6 | Missing capability for the receipt kind | `receipt-invalid.json#capability_missing_for_sale` | `CREDENTIAL_CAPABILITY_MISSING` |
| B7 | Receipt `kid` / `merchant_id` / credential bytes disagree | `receipt-invalid.json` | `RECEIPT_KEY_NOT_AUTHORIZED` / `RECEIPT_CREDENTIAL_MISMATCH` |
| B8 | Receipt outside credential validity window | `receipt-invalid.json#receipt_issued_in_future` | `RECEIPT_ISSUED_IN_FUTURE` |
| B9 | No production trust-root private key exists anywhere in the tree; no *test* private key is bundled into an app build | `git grep` over the tree + app bundle inspection | only the labelled test key in `protocol/vectors/keys/test-keys.json`; nothing in the app bundle |
| B10 | Every vector artifact carries the `_TESTONLY` header / NOTICE | header inspection | present |
| B11 | The pinned anchor is `bd65615a…87cb` (NOT the merchant device key `61d36a10…58ed`) | `fixtures/trust-anchors-v1.json` | `valid-credential.cbor` verifies under the anchor and fails under the device key |

## C. Handshake (A4/A5; A3 type distinction)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| C1 | Reproduce the 372-byte transcript | `handshake-valid.json#transcript_hex` | byte-identical |
| C1b | **Rebuild the transcript from received plaintext only** (`CLIENT_HELLO`{2,3,5,6} + `SERVER_HELLO`{4,5,6,9,10,11}); label 10 is authoritative over label 9 | `handshake-valid.json`; reconstruction asserted in `self-test.json` | rebuilt bytes == signed bytes |
| C1c | Label 10 absent / substituted / label 11 lowered / label 4 not a tuple member | `handshake-invalid.json` | `BINDING_REQUIRED` / `HANDSHAKE_TRANSCRIPT_MISMATCH` / `HANDSHAKE_SIGNATURE_INVALID` / `TRANSFER_ID_MISMATCH` |
| C2 | Transcript hash + Ed25519 signature | `handshake-valid.json` | identical |
| C2b | `transcript_layout.label` size is 20, offsets 218/250/285 | `handshake-valid.json#transcript_layout` | exact |
| C3 | ECDH shared secret + full HKDF schedule | `handshake-valid.json` | identical `prk`, `okm`, 4 keys |
| C4 | AEAD payload seal bytes | `aead-valid.json#payload_seal` | identical ciphertext |
| C5 | AEAD control envelope bytes (offer/begin/accept) | `aead-valid.json` | identical |
| C6 | Counter replay / gap / tag flip / AAD mismatch | `aead-invalid.json` | `AEAD_REPLAY_DETECTED` / `AEAD_COUNTER_MISMATCH` / `AEAD_AUTH_FAILED` |
| C7 | Plaintext control after handshake | `aead-invalid.json` | `MESSAGE_WRONG_STATE` |
| C8 | Version / suite / signature / digest / point substitution | `handshake-invalid.json` | recorded error each |
| C9 | Three session types: `SessionKeysOnly` cannot reach the transfer path; `SessionUnverifiedPeer` can transfer but every receipt is `UNVERIFIED_UNKNOWN_ISSUER`; `SessionAuthenticated` is the only one whose receipts can be `TRUSTED` | `handshake-unverified-peer.json`; type-level + runtime | compile/guard failure; unknown-issuer fixture yields `CREDENTIAL_UNKNOWN_ISSUER` but the transcript signature verifies against the self-asserted device key |
| C9b | One-shot `k_m2c_payload` (one seal, counter 0) | `aead-valid.json`; `bounds-v1.json#wire.k_m2c_payload_usage` | exactly one payload seal per session |
| C11 | `offer_hash` recomputed per `wire.md` §7 array order matches the frozen value and the QR | `handshake-valid.json#offer_hash_hex` | `efdc44f3…d4c5` |
| C10 | Keys zeroized on teardown | instrumentation | key buffers cleared |

## D. Wire and framing (A4/A5)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| D1 | Service + 3 characteristic UUIDs exactly as frozen | `wire.md` §1 | byte-identical UUIDs |
| D2 | Advertisement contains service UUID only | on-device AD capture | no merchant/amount/id/credential |
| D3 | LPdu segment and reassemble | `lpdu-valid.json` | byte-identical fragments |
| D4 | LPdu error cases | `lpdu-invalid.json` | recorded error each |
| D5 | Frame size from reported MTU, never fixed | `framing-valid.json` (`att_mtu 185` → `162`) | `FRAME_SIZE_INVALID` when above |
| D6 | 6-frame transfer reassembles to the ciphertext; final frame payload 4 bytes is valid | `framing-valid.json` | byte-identical; `frame_payload_sizes == [162,162,162,162,162,4]` and NOT `FRAME_SIZE_INVALID` |
| D7 | Frame errors | `framing-invalid.json` | recorded error each |
| D8 | Bounded retry, no infinite resend | on-device | `TRANSFER_RETRY_EXHAUSTED` after 5 |

## E. Ordering and end-to-end (A6 on hardware)

| # | Check | Expected |
|---:|---|---|
| E1 | iOS merchant → Android customer, and Android → iOS | full receipt, `TRUSTED` |
| E2 | Decryption success alone never yields trusted | inject a validly-encrypted but unverifiable receipt → `REJECTED`/unknown |
| E3 | Wrong transaction (offer mismatch after accept) | `WRONG_TRANSACTION`, nothing stored as trusted |
| E4 | Cross-session frame replay | `AEAD_AUTH_FAILED` / `TRANSFER_ID_MISMATCH` |
| E5 | Tampered ciphertext frame | `AEAD_AUTH_FAILED` |
| E6 | Oversized declared length / incomplete fragment set | `TRANSFER_SIZE_EXCEEDED` / `TRANSFER_INCOMPLETE` |
| E7 | Duplicate import identical / conflicting | `ALREADY_IMPORTED_IDENTICAL` / `RECEIPT_DUPLICATE_CONFLICT` |
| E8 | Disconnect / cancel / Bluetooth off mid-transfer | no trusted row, recoverable failure state |
| E9 | Restart persistence: keys + receipts + sub-states | survive restart |
| E10 | Competing terminals: no RSSI in selection; 2+ eligible fails closed (QR-mandatory v1: the picker is display guidance only, selection is a QR scan naming one `session_id`) | `TRANSPORT_PEER_AMBIGUOUS`; never a radio-derived pick |
| E11 | No key/session material in logs or crash output | verified by inspection |

## F. Reference-implementation self-test

`protocol/vectors/tools/gen_vectors.py` executes every byte-level invalid fixture (encoding, receipt, AEAD, LPdu, framing, handshake) through the reference implementation and asserts the recorded error. Result at this revision: `protocol/vectors/self-test.json` — **153 checks, 0 failures**. 18 additional cases are receiver-state/timeout policy assertions that cannot be decided by a single byte string; they are listed in `self-test.json#policy_only_cases` and MUST be tested on-device (rows D8, E4–E8).

## G. A6 early-review closure (r2)

Every `docs/security/early-contract-review.md` finding is closed in r2 except RX-04 (A2-owned, resolved by making the QR mandatory and removing the QR-less P0 path):

| Finding | Resolution | Where to verify |
|---|---|---|
| R4-01 (blocker) | `SERVER_HELLO` labels 10 (`binding_tuple`, authoritative) and 11 (`max_frame_payload`) added; transcript rebuild is defined from received plaintext only | `handshake.md` §3.1/§4.2; rows C1b/C1c; `self-test.json` reconstruction assertion |
| R1-02 | Three session types; `SessionUnverifiedPeer` reached on unknown issuer with the transcript signature verified against the credential's self-asserted device key; `UNVERIFIED_UNKNOWN_ISSUER` is now reachable and can never be `TRUSTED` | `handshake.md` §9; `trust.md` §4/§5; `handshake-unverified-peer.json`; rows C9/B3 |
| R2-01 | One `offer_hash` definition (array order `[session_id, transfer_id, receipt_id, merchant_reference, total, currency, issued_at]` = `RECEIPT_OFFER` labels `[12,2,3,4,5,6,7]`), stated identically in `wire.md` §7, `framing.md` §7, `handshake.md` §4.4 | row C11 |
| R2-02 | `transcript_layout.label` = 20 bytes; all offsets corrected | row C2b |
| R1-01 | Pinned anchor corrected to `bd65615a…87cb`; prose warns against the merchant device key | row B11 |
| R5-01 | `k_m2c_payload` declared one-shot (one seal, counter 0) | row C9b; `bounds-v1.json#wire.k_m2c_payload_usage` |
| R7-01 | `RECEIPT_OFFER_MISMATCH` removed; `WRONG_TRANSACTION` (`0x0614`) is the only name | `errors.json` (91 errors); `framing.md` §7 |
| RX-02 | `protocol/flows/**` (4 files) added to `REVISION.json` hash scope | row D9; `REVISION.json` |
| RX-03 | Final-frame payload bound `1..frame_size`; short final frame is valid | row D6; `framing-valid.json#frame_payload_sizes` |
| R3-01 | No byte-less invalid fixtures: oversize cases carry real bytes | row A14 |
| RX-04 | A2-owned: QR is mandatory in v1 and the QR-less P0 path is removed, so no binding-less wire variant is needed | `docs/flows/**` |

| # | Check | Fixture | Expected |
|---:|---|---|---|
| D9 | `REVISION.json` pins `protocol/flows/**` and every recorded hash matches on-disk | `protocol/REVISION.json` | no missing/mismatched rows |
| D10 | No pinned artifact declares a revision other than the frozen one | `verify_vectors.py` revision-alignment guard | no stale `deceipt-proto-rN` string in `docs/protocol/*.md`; A2-owned `protocol/flows/**` metadata aligned (see residual note) |

### Residual metadata note (r2)

`protocol/flows/**` is inside the r2 hash scope (RX-02). A2 owns those files. At this
writing A2 is aligning their internal `"revision"` / `$comment` strings from r1 to r2
(metadata only — no binding byte changes). `protocol/vectors/tools/verify_vectors.py`
prints a **WARN** line for any A2-owned pinned file still declaring r1, and **FAILS** on
any A1-owned doc doing so. If any A2 warning is still present when the r2 aggregate is
quoted, the pinned value is the one in `protocol/REVISION.json`; the warning names the
exact file and is an owner action for A2, not a byte-level inconsistency in the vectors.
