# Deceipt protocol contract — index

**Revision:** `deceipt-proto-r3` — **FROZEN for the PoC**
**Aggregate hash:** see `protocol/REVISION.json` (`aggregate_sha256`) — computed over every file listed there.
**Owner:** A1. Changes require a new revision id and a full vector regeneration.

> `DESIGN.md` is a **planning draft** (`Status: Draft v0.1`). This directory is the frozen contract that A3/A4/A5 implement and A6 tests. Where the two differ, **this contract is normative for implementation**; `DESIGN.md`'s stable decisions (`§13`, `§4.4`) are preserved unchanged.

## Reading order

| File | Pass | What it fixes |
|---|---|---|
| [receipt-v1.md](receipt-v1.md) | A | `DeceiptReceiptV1` schema, deterministic CBOR profile, COSE_Sign1, monetary/fractional rules, bounds, dedup |
| [trust.md](trust.md) | B | Merchant device credential, PoC trust anchor, unknown-key policy, explicit unresolved items |
| [handshake.md](handshake.md) | C | Suite, canonical transcript (372 B), key schedule, AEAD nonces/AAD, replay, timeouts, failure transitions, A2 binding adoption |
| [wire.md](wire.md) | D | Service/characteristic UUIDs, message type ids, LPdu segmentation, transfer-id rules |
| [framing.md](framing.md) | D | `DataFrame`, MTU-derived frame sizing, flow control, cancellation/disconnect, A2 interface |
| [verification.md](verification.md) | — | 16-step order, sub-states, outcomes, typed errors, transport events, idempotency |
| [conformance.md](conformance.md) | — | The checklist A3/A4/A5 must satisfy and A6 must run |

## Machine-readable artifacts

* `protocol/schema/receipt-v1.fields.json` — Pass A field tables
* `protocol/schema/credential-v1.fields.json` — Pass B field tables
* `protocol/schema/wire-v1.messages.json` — Pass D message tables
* `protocol/schema/bounds-v1.json` — every numeric bound, timeout, currency exponent, error code
* `protocol/schema/*.cddl` — CDDL descriptions of all three structures
* `protocol/vectors/**` — valid and invalid fixtures with exact bytes and expected typed errors
* `protocol/vectors/self-test.json` — proof that every byte-level invalid fixture produces its recorded error
* `protocol/REVISION.json` — frozen file list + aggregate hash (r2 scope includes `protocol/flows/**`, the A2 artifacts this contract adopts)

## Non-negotiable invariants (restated)

1. BLE is an untrusted transport; AEAD decryption success NEVER yields a trusted receipt.
2. Trust requires the merchant signature over the **exact received bytes** plus merchant-key authorization. Never re-encode-then-verify.
3. Long-lived merchant signing keys are never reused for session key agreement.
4. RSSI is never a selection, association, or trust signal; ambiguous association fails closed.
5. Parser/allocation bounds are security requirements.
6. Merchant private keys and session secrets never enter committed files, logs, or bridge payloads. Only `protocol/vectors/keys/test-keys.json` holds private halves, and those are test-only and published deliberately.

## Test-only material and the public repository

This repository is **public**. Consequently:

* Every artifact under `protocol/vectors/**` is **test-only deterministic material** and says so in-file: each JSON vector carries a `_TESTONLY` header, and `protocol/vectors/NOTICE` / `protocol/vectors/fixtures/NOTICE` state the rule. Keys, nonces, seeds and session-binding tokens are derived from fixed ASCII labels and are public by construction.
* They **MUST NEVER** be used outside these test vectors — not in a build, not in a session, not as a trust anchor. Production sessions use fresh CSPRNG randomness.
* The only production-relevant value committed is the **PoC test root public key** (`protocol/vectors/fixtures/trust-anchors-v1.json`). It is public material. Its private half is an explicitly-labelled **test** key.
* **No real or production trust-root private key exists anywhere in this tree.** Production trust roots are generated offline; their private material never enters the repository. A3/A4/A5 MUST NOT bundle any test private key into a build.
* The public spec + public vectors are the single source of truth, so a third party can reproduce every byte with `python3 protocol/vectors/tools/verify_vectors.py`.

## Regenerating the vectors

```bash
python3 protocol/vectors/tools/gen_vectors.py     # deterministic; rewrites vectors, bounds, field tables, REVISION.json
```

Revision history: **r1** was the first freeze; **r2** closed A6's early-review findings (transcript reconstructibility from received bytes, `offer_hash` single definition, three session types incl. `SessionUnverifiedPeer`, final-frame bound, anchor-key correction, one-shot payload key, duplicate offer-mismatch error removed, `transcript_layout` label size, `protocol/flows/**` in hash scope, no placeholder fixtures). **r3** is a corrections-only revision: the final-frame rule is now encoded in `wire-v1.cddl` (was prose-only), the `SERVER_HELLO` field table's duplicated label 4 is removed, and the worked `ACK` example is now the AEAD envelope (a plaintext ACK was shown). **No binding byte and no session-structure byte changed in r2 or r3**; `offer_hash`, `binding_tuple`, its digest, `binding_proof`, the 372-byte transcript and all AEAD ciphertexts are identical across r1/r2/r3.

The generator runs a self-test that executes every byte-level invalid fixture through the reference implementation and fails the build if any recorded typed error does not match. `self-test.json` records the result (`checked: 165, failed: []` at this revision).

Independent re-derivation of every published value (including a live cross-check against A2's binding vectors):

```bash
python3 protocol/vectors/tools/verify_vectors.py
```
