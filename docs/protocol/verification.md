# Verification order, outcomes, and typed errors

**Revision:** `deceipt-proto-r4` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A3 (state machine, persistence, UI), A4/A5 (native result events), A6 (adversarial checks)
**Machine-readable:** `protocol/vectors/errors.json` · **Vectors:** all files under `protocol/vectors/`

Implements `DESIGN.md` §9 (16 steps, no failure path reaching "verified"), §5.3 (separate verification sub-states), and §4.5 (dedup).

---

## 1. The 16-step order, mapped

Each step is a gate. **A failure at any step MUST NOT fall through to a verified receipt state** (`DESIGN.md` §9). The right column is the first typed error the reference implementation returns.

| # | Step | Produces / on failure |
|---:|---|---|
| 1 | Validate BLE/GATT framing enough to parse safely | `LPDU_*`, `TRANSPORT_*` |
| 2 | Validate handshake message format and versions | `MESSAGE_*`, `CBOR_*`, `HANDSHAKE_UNSUPPORTED_VERSION`, `HANDSHAKE_NO_COMMON_SUITE` |
| 3 | Verify merchant device credential against trust anchors | `CREDENTIAL_*` (unknown issuer = non-fatal, trust=unknown) |
| 4 | Verify merchant handshake signature over the exact transcript | `HANDSHAKE_SIGNATURE_INVALID`, `HANDSHAKE_TRANSCRIPT_MISMATCH`, `TRANSFER_ID_MISMATCH` |
| 5 | Derive session keys | — (`SessionAuthenticated`/`SessionUnverifiedPeer` only after 3 and 4) |
| 6 | Receive and reassemble the encrypted payload | `FRAME_*`, `TRANSFER_INCOMPLETE`, `TRANSFER_HASH_MISMATCH`, `TRANSFER_SIZE_EXCEEDED` |
| 7 | Authenticate/decrypt the AEAD payload | `AEAD_AUTH_FAILED`, `AEAD_REPLAY_DETECTED`, `AEAD_COUNTER_MISMATCH` |
| 8 | Parse the signed receipt container **as untrusted input** | `RECEIPT_CONTAINER_MALFORMED`, `RECEIPT_SIZE_EXCEEDED`, `RECEIPT_NONCANONICAL` |
| 9 | Validate supported COSE/signature suite and critical headers | `RECEIPT_UNSUPPORTED_ALGORITHM`, `RECEIPT_UNKNOWN_HEADER`, `RECEIPT_UNSUPPORTED_VERSION` |
| 10 | Verify receipt signature over the **exact received** receipt bytes | `RECEIPT_SIGNATURE_INVALID` |
| 11 | Verify the signing key is authorized for the claimed merchant | `RECEIPT_KEY_NOT_AUTHORIZED`, `RECEIPT_CREDENTIAL_MISMATCH`, `CREDENTIAL_UNKNOWN_ISSUER` (→ unknown) |
| 12 | Validate receipt schema and semantic invariants | `RECEIPT_UNKNOWN_FIELD`, `RECEIPT_SEMANTIC_INVALID`, `RECEIPT_ARITHMETIC_MISMATCH`, `RECEIPT_MONETARY_RANGE`, `RECEIPT_UNSUPPORTED_CURRENCY`, `RECEIPT_TEXT_INVALID`, `RECEIPT_UNKNOWN_CRITICAL_EXTENSION` |
| 13 | Check receipt ID deduplication | `RECEIPT_DUPLICATE_CONFLICT`, or `ALREADY_IMPORTED_IDENTICAL` |
| 14 | Apply revocation/validity policy | `RECEIPT_OUTSIDE_KEY_VALIDITY`, `RECEIPT_ISSUED_IN_FUTURE`; plus `CREDENTIAL_EXPIRED`/`CREDENTIAL_NOT_YET_VALID` from step 3 |
| 15 | Only then mark/store as verified per policy | outcome assignment |
| 16 | Send `ReceiptAck` and disconnect | `RECEIPT_ACK` message |

`RECEIPT_UNTRUSTED` is an explicit state between steps 7 and 8 (`DESIGN.md` §8.1). Decryption success MUST NOT skip steps 8–14.

## 2. Verification sub-states (§5.3, preserved separately)

Never collapse these into one boolean before policy combines them:

| Sub-state | Established by | Field in `verify_receipt` result |
|---|---|---|
| Signature valid | step 10 | `signature_valid` |
| Signing key authorized | step 11 | `key_authorized` |
| Credential temporally acceptable | steps 3/14 | `credential_temporally_acceptable` |
| Revocation status known/acceptable | step 14 | (not implemented in PoC; see `trust.md` §7) |
| Receipt semantically valid | step 12 | `semantically_valid` |
| Receipt unique locally | step 13 | `unique_locally` |

Storage MUST persist the sub-states, not just the policy outcome, so a later policy change or the arrival of revocation data can be re-evaluated without re-transferring the receipt.

## 3. Policy outcomes (user- and storage-facing)

| Outcome | Code | Meaning | Store? | UI |
|---|---:|---|---|---|
| `TRUSTED` | `0x0001` | all applicable sub-states pass, key authorized | yes, as trusted | "Verified · {display_name}" |
| `UNVERIFIED_UNKNOWN_ISSUER` | `0x0002` | signature valid, key **not** authorized (issuer not pinned); reachable only via a `SessionUnverifiedPeer` session (`handshake.md` §9) — never via `SessionKeysOnly`, which cannot transfer | yes, as **unverified** | "Unverified merchant" — never the trusted affordance |
| `ALREADY_IMPORTED_IDENTICAL` | `0x0003` | idempotent re-import, byte-identical | no new row | "Already saved" |
| `REJECTED` | `0x0004` | any fatal `RECEIPT_*`/`CREDENTIAL_*` failure | evidence only, never trusted | "Could not verify" + reason |
| `PENDING` | `0x0005` | in-flight / awaiting user decision | transient | progress |

The three user-facing labels A2 specified — `trusted`, `unknown_key`, `rejected` — map to `TRUSTED`, `UNVERIFIED_UNKNOWN_ISSUER`, `REJECTED`.

## 4. Typed error taxonomy

Full table: `protocol/vectors/errors.json` (92 errors, stable `u16` codes; `name` is the frozen identifier used in vectors and code). Categories: `encoding`, `message`, `transport`, `handshake`, `binding`, `session`, `framing`, `receipt`, `local`.

Each error carries:

* `name` — the identifier every implementation MUST use in logs, results, and metrics;
* `code` — stable `u16` wire code (also used in `ERROR` messages and `CANCEL.error_code`);
* `fatal` — `true` ⇒ the session aborts and no receipt may be stored as trusted;
* `retryable` — `true` ⇒ a bounded retry is permitted (`MAX_FRAME_RETRIES`, or a new session for transport/handshake classes);
* `category`.

Selected codes (see `errors.json` for all):

| Name | Code | Fatal | Retryable |
|---|---:|---|---|
| `CBOR_NONCANONICAL` | `0x0102` | ✔ | |
| `HANDSHAKE_SIGNATURE_INVALID` | `0x0304` | ✔ | |
| `CREDENTIAL_UNKNOWN_ISSUER` | `0x030A` | | |
| `BINDING_UNKNOWN_SESSION` | `0x0312` | ✔ | |
| `BINDING_PROOF_INVALID` | `0x0313` | ✔ | |
| `BINDING_STALE` | `0x0315` | ✔ | ✔ |
| `BINDING_CONSUMED` | `0x0316` | ✔ | |
| `AEAD_AUTH_FAILED` | `0x0401` | ✔ | |
| `AEAD_REPLAY_DETECTED` | `0x0403` | ✔ | |
| `FRAME_SEQUENCE_OUT_OF_RANGE` | `0x0503` | ✔ | |
| `FRAME_SEQUENCE_REPLAYED` | `0x0504` | | |
| `FRAME_CONFLICT` | `0x0505` | ✔ | |
| `TRANSFER_HASH_MISMATCH` | `0x0508` | ✔ | |
| `TRANSFER_INCOMPLETE` | `0x0507` | ✔ | ✔ |
| `RECEIPT_SIGNATURE_INVALID` | `0x0607` | ✔ | |
| `RECEIPT_KEY_NOT_AUTHORIZED` | `0x0608` | ✔ | |
| `RECEIPT_ARITHMETIC_MISMATCH` | `0x060A` | ✔ | |
| `RECEIPT_DUPLICATE_CONFLICT` | `0x060D` | ✔ | |
| `WRONG_TRANSACTION` | `0x0614` | ✔ | |
| `RECEIPT_NONCANONICAL` | `0x0615` | ✔ | |

**Semantics are transport-independent.** A4 and A5 may name their native types differently, but MUST emit the same `name`/`code`/`fatal`/`retryable` for the same condition, so A6's conformance runner can assert on identifiers alone.

## 5. Transport events (shared vocabulary)

| Event | Meaning |
|---|---|
| `advertising_started` / `advertising_stopped` | merchant endpoint availability |
| `peer_candidate(peripheral_id)` | a peripheral advertising the service UUID (never carries RSSI into selection) |
| `connected(peripheral_id)` / `disconnected(reason)` | link state |
| `mtu_changed(att_mtu)` | reported MTU changed; frame size is recomputed, never assumed |
| `session_type_resolved(kind, merchant_id, device_key_id)` | after step 4: `SessionAuthenticated` (pinned anchor), `SessionUnverifiedPeer` (unknown issuer, self-asserted key verified), or `SessionKeysOnly` (not authenticated; cannot transfer) |
| `offer_received(display fields)` | untrusted pre-verification metadata |
| `transfer_progress(highest_contiguous_sequence, frame_count)` | flow-control progress |
| `receipt_received(exact bytes)` | payload decrypted; still `RECEIPT_UNTRUSTED` |
| `verification_result(sub-states, outcome, error?)` | steps 8–15 |
| `session_torn_down(reason)` | teardown, keys zeroized |

RSSI may appear only as a diagnostics field marked `diagnostics_only`, and MUST NOT be an input to `peer_candidate` selection, ordering, or trust (`DESIGN.md` §2.5, §7.3).

## 6. Import idempotency

* Persist `receipt_id` → exact signed payload bytes.
* Test-only keys from `protocol/vectors/**` MUST NOT be bundled into a shipped build (public repo: they are published, but a build that trusts them would be trivially forgeable).
* The whole verification is atomic: either the receipt is stored with a complete verification record, or nothing is stored (a partial/failed transfer leaves no trusted row).
* Re-import of byte-identical payload ⇒ `ALREADY_IMPORTED_IDENTICAL`, no duplicate row.
* Re-import with the same `receipt_id` but different bytes ⇒ `RECEIPT_DUPLICATE_CONFLICT`; both are kept as evidence and neither is labelled trusted without the user's attention.
