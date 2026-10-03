# Conformance checklist

**Revision:** `deceipt-proto-r1` · **Owner of execution:** A6 (independent) · **Owners of the code:** A3, A4, A5

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
| A14 | Bound: 65536-byte payload | `receipt-invalid.json#receipt_oversize_placeholder` | `RECEIPT_SIZE_EXCEEDED` |
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
| B9 | Root private key is absent from the app bundle and repo tree | build artifact + `git grep` | absent |

## C. Handshake (A4/A5; A3 type distinction)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| C1 | Reproduce the 372-byte transcript | `handshake-valid.json#transcript_hex` | byte-identical |
| C2 | Transcript hash + Ed25519 signature | `handshake-valid.json` | identical |
| C3 | ECDH shared secret + full HKDF schedule | `handshake-valid.json` | identical `prk`, `okm`, 4 keys |
| C4 | AEAD payload seal bytes | `aead-valid.json#payload_seal` | identical ciphertext |
| C5 | AEAD control envelope bytes (offer/begin/accept) | `aead-valid.json` | identical |
| C6 | Counter replay / gap / tag flip / AAD mismatch | `aead-invalid.json` | `AEAD_REPLAY_DETECTED` / `AEAD_COUNTER_MISMATCH` / `AEAD_AUTH_FAILED` |
| C7 | Plaintext control after handshake | `aead-invalid.json` | `MESSAGE_WRONG_STATE` |
| C8 | Version / suite / signature / digest / point substitution | `handshake-invalid.json` | recorded error each |
| C9 | `SessionKeysOnly` cannot reach the transfer path | type-level + runtime | compile/guard failure |
| C10 | Keys zeroized on teardown | instrumentation | key buffers cleared |

## D. Wire and framing (A4/A5)

| # | Check | Fixture | Expected |
|---:|---|---|---|
| D1 | Service + 3 characteristic UUIDs exactly as frozen | `wire.md` §1 | byte-identical UUIDs |
| D2 | Advertisement contains service UUID only | on-device AD capture | no merchant/amount/id/credential |
| D3 | LPdu segment and reassemble | `lpdu-valid.json` | byte-identical fragments |
| D4 | LPdu error cases | `lpdu-invalid.json` | recorded error each |
| D5 | Frame size from reported MTU, never fixed | `framing-valid.json` (`att_mtu 185` → `162`) | `FRAME_SIZE_INVALID` when above |
| D6 | 6-frame transfer reassembles to the ciphertext | `framing-valid.json` | byte-identical |
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
| E10 | Competing terminals: no RSSI in selection; 2+ eligible fails closed | picker or `TRANSPORT_PEER_AMBIGUOUS` |
| E11 | No key/session material in logs or crash output | verified by inspection |

## F. Reference-implementation self-test

`protocol/vectors/tools/gen_vectors.py` executes every byte-level invalid fixture (encoding, receipt, AEAD, LPdu, framing, handshake) through the reference implementation and asserts the recorded error. Result at this revision: `protocol/vectors/self-test.json` — **153 checks, 0 failures**. 18 additional cases are receiver-state/timeout policy assertions that cannot be decided by a single byte string; they are listed in `self-test.json#policy_only_cases` and MUST be tested on-device (rows D8, E4–E8).
