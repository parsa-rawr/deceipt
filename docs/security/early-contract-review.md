# Early contract review — `deceipt-proto-r1` → re-reviewed against `deceipt-proto-r2`

**Reviewer:** A6 (independent validation + security)
**Date:** 2026-10-03
**Bursts:** first pass against `deceipt-proto-r1` (`aggregate_sha256 99ab1f0f…87c60`); re-review against
`deceipt-proto-r2` (`aggregate_sha256 5a7cc554…edda`), which A1 landed while this report was being finalised and
which closes most of the r1 findings.
**Scope reviewed:** `protocol/REVISION.json`, `protocol/schema/**` (incl. CDDL), `protocol/vectors/**`,
`protocol/flows/**`, `docs/protocol/*.md`, `docs/flows/**`, `DESIGN.md` (§2, §4, §5, §6, §9, §10).
**Method:** every claim checked against the files, not against A1's or A2's changelog. All cryptographic and
byte-level claims re-derived from the published inputs with an independent Python/CBOR implementation (§
"Independent verification performed").
**This burst is review only** — no tests, no edits outside `docs/security/`.

## Status against r2

**Open: 1 major, 2 minor.** Closed by r2: the r1 blocker, both r1 majors, and 7 r1 minors.
Targets 3, 5, 6 remain clean; targets 1, 2, 4 are now clean except for the CDDL residual (RX-03) and a new
schema-table defect (R2-03); target 7 retains R7-02.

| r1 finding | Sev | r2 status |
|---|---|---|
| R4-01 receiver cannot rebuild the signed transcript | blocker | **CLOSED** — `SERVER_HELLO` labels 10/11 + `handshake.md` §3.1 (§Target 4) |
| R1-02 unknown-issuer unreachable / undefined session type | major | **CLOSED** — `SessionUnverifiedPeer` + `handshake-unverified-peer.json` |
| R2-01 `offer_hash` member-set divergence | major | **CLOSED** — single definition in `wire.md` §7, `framing.md` §7 aligned |
| R1-01 `trust.md` §3 printed the device key as the anchor | minor | **CLOSED** (`bd65615a…` + explicit "do not confuse" note) |
| R2-02 `transcript_layout` label size 19 | minor | **CLOSED** (`size_bytes: 20`) |
| R5-01 one-shot payload key unstated | minor | **CLOSED** (`handshake.md` §6.2 "`k_m2c_payload` is one-shot") |
| R7-01 duplicate offer-mismatch error | minor | **CLOSED** — `RECEIPT_OFFER_MISMATCH` removed; A2 text aligned @ `a7993ea` |
| RX-02 `protocol/flows/**` outside the freeze | minor | **CLOSED** (now in `hash_rule` + `files`) |
| RX-04 P0 picker had no wire realisation | minor | **CLOSED** by A2 @ `a7993ea` (QR-mandatory) |
| RX-03 frame-payload bound vs 4-byte final frame | minor | **PARTIALLY CLOSED** — prose fixed, CDDL not → **remains open, now major** |
| R7-02 `wire.md` §7 prints `ACK` as plaintext | minor | **OPEN** |
| R2-03 `SERVER_HELLO` field table has a duplicate label | minor | **NEW in r2** |

RX-01 (A2's P-256 fix) was verified clean on the first pass and `protocol/flows/vectors/binding-v1.json` is now
inside the r2 freeze; re-verified unchanged.

---

## Target 1 — Trust bootstrap: is "supplied public key + valid signature does NOT prove merchant identity" enforced?

**Verdict: reviewed, no defect found at r2.**

* `trust.md` §4 step 7 splits on anchor presence *before* the signature check; the unknown path yields
  `(CREDENTIAL_UNKNOWN_ISSUER, trust = "unknown_issuer")`, never `authenticated`.
* `protocol/vectors/receipt-invalid.json#unknown_issuer_credential` is a real counterexample test: I decoded the
  COSE_Sign1, confirmed the embedded credential chains to the deliberately-unpinned `0badc0de…00ff`, confirmed
  `anchors_hex` holds only `0decea…0001`, and confirmed `expected_outcome = UNVERIFIED_UNKNOWN_ISSUER`,
  `fatal: false`. A structurally perfect rogue receipt is surfaced as unknown, not trusted (`DESIGN.md` §5.2).
* `CREDENTIAL_UNKNOWN_ISSUER` is the **only** non-fatal error in the `handshake`/`credential`/`receipt`/`binding`
  categories, so no other trust-relevant condition can be silently downgraded.
* `protocol/vectors/fixtures/valid-credential.cbor` verifies under the pinned anchor and its `device_public_key`
  equals `merchant-test-1`; `protected.kid == payload.issuer_id`. Chain sound.
* **r2 closes R1-02.** `handshake.md` §9 now defines three nominal types —
  `SessionKeysOnly` (no verified `ServerHello`; MUST NOT send `ACCEPT`), `SessionUnverifiedPeer` (credential
  well-formed, issuer not pinned, transcript signature verified against the credential's **self-asserted device
  key** → internal consistency only, transfer allowed, receipts can never be `TRUSTED`), and `SessionAuthenticated`
  (issuer pinned → the only type whose receipts can be `TRUSTED`). The reference fixture
  `protocol/vectors/handshake-unverified-peer.json` makes this executable, and I verified it end-to-end: 372-byte
  transcript, `transcript_hash` matches, the signature verifies against the self-asserted device key
  (`credential_device_public_key_hex`), the issuer `0badc0de…00ff` is **not** in the pinned anchor set, and the
  fixture declares `session_type: SessionUnverifiedPeer`, `expected_transfer: allowed`,
  `expected_receipt_outcome: UNVERIFIED_UNKNOWN_ISSUER`, `must_never_be: TRUSTED`. The r1 contradiction between
  `handshake.md` §9 and `trust.md` §4/§5 is therefore resolved in the correct direction: displayable-as-unknown
  without ever being trusted. `errors.json` now contains no `RECEIPT_OFFER_MISMATCH`, so R7-01's A1 half is closed.
* **r2 closes R1-01.** `trust.md` §3 now prints the true anchor
  `bd65615aed2e3adf4f91e8fccfd7b54d44e532456399115b33456d72668a87cb` and carries an explicit "Do not confuse the
  anchor with the merchant **device** key. `61d36a10…58ed` is …" note.

---

## Target 2 — Canonical signed bytes: can two implementations disagree?

**The `DeceiptReceiptV1` profile: reviewed, no defect found.** `receipt-v1.md` §1 is a closed profile (integer keys
0..255 ascending by encoded bytes, duplicates forbidden, minimal-length arguments, definite lengths only,
floats/tags/simple values forbidden, NFC + bidi/control rejection, no trailing bytes, explicit depth/item/array/map/
text/size caps), every clause has a byte-level fixture in `encoding-invalid.json` (21 cases incl. `float64_value`,
`float16_value`, `indefinite_map`, `non_minimal_int`, `unsorted_map_keys`, `text_map_key`, `depth_exceeded`), and the
frozen receipt body and container both re-encode byte-identically (`enc(dec(x)) == x`).

**r2 closes R2-01 and R2-02.** `wire.md` §7 now states the `offer_hash` definition **once** as the array element
order, with the label mapping `[12, 2, 3, 4, 5, 6, 7]`, an explicit errata note ("r1 stated `3,4,5,6,7,10` here and
in `framing.md`, which was wrong"), and `framing.md` §7 now points at that single definition. I re-derived the
frozen value from the frozen offer bytes in that order and confirm `efdc44f3…d4c5`.
`handshake-valid.json#transcript_layout` now starts `{"offset": 0, "field": "label", "size_bytes": 20}`, with the
subsequent offsets matching the byte truth I located directly in `transcript_hex`.

### RX-03 (now major) — the frozen CDDL still states the old frame-payload bound

* **Severity:** major
* **File+section:** `protocol/schema/wire-v1.cddl:33–35` — `payload = bytes .size (16..512)`
* **Counterexample:** r2 corrected the prose in all three places that carried the bug —
  `framing.md:19` ("Non-final frames carry exactly `frame_size` bytes; the **final** frame carries
  `ciphertext_length − frame_size·(frame_count−1)`, which is `1..frame_size` and MAY be shorter than the 16-byte
  minimum … only a **non-final** frame shorter than 16 bytes … is `FRAME_SIZE_INVALID`"), `wire.md:97`
  ("non-final frames `16..frame_size`; the **final** frame `1..frame_size`"), and `handshake.md` §7 (which now has
  a separate "Final-frame payload | `1..frame_size` bytes" row) — but the CDDL was not touched:
  `wire-v1.cddl` still admits only `16..512` and has no final-frame rule at all. The frozen
  `framing-valid.json` transfer has payload lengths `[162, 162, 162, 162, 162, 4]`, i.e. a 4-byte final frame that
  the CDDL rejects, so a CDDL-driven codec or validator still fails the spec's own vector. This is now in the r2
  freeze (`REVISION.json` lists `../schema/wire-v1.cddl`), so it is a frozen normative contradiction, not a stale
  side file.
* **Invariant violated:** `DESIGN.md` §8.5 framing + `verification.md` §4 (semantics are transport-independent):
  the CDDL is a normative artifact in the same revision as the prose it contradicts.
* **Owner:** A1
* **Note:** `framing.md:32` also still reads "last frame payload 24 bytes", which disagrees with the frozen vector's
  4 — harmless once the final-frame rule is applied, but it is the same class of example-vs-fixture drift.

### R2-03 (new in r2) — `SERVER_HELLO` field table lists label 4 twice

* **Severity:** minor
* **File+section:** `protocol/schema/wire-v1.messages.json`, `SERVER_HELLO.fields`
* **Counterexample:** the array has **12 entries for 11 labels**; label `4` (`transfer_id`) appears twice — once at
  index 3 and again as the last element. Declared labels are `[1,2,3,4,5,6,7,8,9,10,11,4]`. The r2 additions
  (label 10 `binding_tuple`, label 11 `max_frame_payload`) are otherwise correct and complete, and the frozen
  `handshake-valid.json#server_hello_hex` decodes to exactly labels `[1..11]` with **no** duplicate and no trailing
  bytes, so only the table is wrong. But `receipt-v1.md` §1 makes duplicate keys a hard `CBOR_DUPLICATE_KEY` in the
  same protocol family, and a schema-driven encoder built from this table would emit a 12-entry map.
* **Invariant violated:** `verification.md` §4 / `DESIGN.md` §4.1 — the machine-readable message tables are what
  A3/A4/A5 implement against and must describe exactly the bytes the frozen vectors contain.
* **Owner:** A1

---

## Target 3 — Key separation: merchant signing key vs session keys

**Verdict: reviewed, no defect found.**

* The long-lived merchant key is Ed25519 (`DESIGN.md` §4.4) and is used only for
  `Ed25519_sign(merchant_device_private_key, transcript)` and the receipt `Sig_structure`. No signature algorithm
  ever derives key material.
* `handshake.md` §5 derives all four session keys from ephemeral P-256 ECDH + HKDF-SHA-256 with
  `salt = transcript_hash` and `info = "deceipt-transfer-v1" ‖ transcript_hash`; the merchant key never enters the
  KDF. I reproduced `shared_secret`, `prk`, `okm` and all four slices exactly from the vector inputs.
* `keys/test-keys.json`'s `client-eph-1` (P-256) is disjoint from every Ed25519 key.
* Directional separation is real and I verified all three `aead-valid.json` envelopes reproduce under their own
  keys.
* `SessionUnverifiedPeer` (r2) does not weaken separation: its transcript signature is checked against the
  credential's self-asserted device key, i.e. the same Ed25519 role, and it explicitly cannot yield `TRUSTED`.

---

## Target 4 — Transcript binding: is `binding_tuple_digest` required, framed, and unsubstitutable?

**Verdict: reviewed, no defect found at r2. The r1 blocker is closed, with strong evidence.**

What is correct: `binding_tuple_digest` sits at fixed offset 250 (32 bytes) and the whole `binding_tuple` at offset
285 behind `binding_len` (1 byte, = 87), both inside the merchant-signed transcript, so neither can be renegotiated
after signing. I independently rebuilt the 372-byte transcript from its parts, confirmed the Ed25519 signature
verifies over the raw transcript, and confirmed `transcript_hash = SHA-256(transcript)`.

**How R4-01 was closed.** `SERVER_HELLO` gained exactly the two fields I identified as missing:
label 10 `binding_tuple` ("the exact A2 binding_tuple bytes (87 B in v1); authoritative over label 9; lets the
receiver rebuild the signed transcript") and label 11 `max_frame_payload` ("MUST equal the value signed in the
transcript; it MAY be below `CLIENT_HELLO` label 8"). `handshake.md` §3.1 now gives the complete field→source
mapping table plus five MUST rules — label 10 authoritative over label 9 with
`HANDSHAKE_TRANSCRIPT_MISMATCH` on recompute failure, `SERVER_HELLO` label 4 == `binding_tuple[2]` else
`TRANSFER_ID_MISMATCH`, label 11 taken from the merchant and allowed to be lower than the client's label 8,
`binding_tuple[1]` == `CLIENT_HELLO` label 4 else `BINDING_UNKNOWN_SESSION`, and label 10 required else
`BINDING_REQUIRED`. The circuit is broken because the tuple now arrives as plaintext in the same message as the
signature. I verified the frozen `server_hello_hex` decodes to labels `[1..11]` with label 10 = the 87-byte tuple,
label 11 = 162, and label 4 = `ffeeddcc…1100` == `binding_tuple[2]`.

The new negative vectors are present and correctly named: `server_hello_binding_tuple_absent` →
`BINDING_REQUIRED`, `server_hello_binding_tuple_substituted` → `HANDSHAKE_TRANSCRIPT_MISMATCH`,
`server_hello_max_frame_payload_unsigned` → `HANDSHAKE_SIGNATURE_INVALID`,
`server_hello_transfer_id_not_a_tuple_member` → `TRANSFER_ID_MISMATCH`, alongside the pre-existing
`binding_tuple_digest_substituted` / `max_frame_payload_substituted` / `client_eph_substituted_by_mitm`. The
generator self-test asserts `rebuild(...) == transcript`. Only the duplicate-row cosmetic defect R2-03 affects this
field's table.

---

## Target 5 — Nonce uniqueness, AAD per usage, 4-zero‖u64 counters, replay window

**Verdict: reviewed, no defect found at r2.**

* `nonce = 00000000 ‖ u64_be(counter)` is stated identically in `handshake.md` §6.1, `wire.md` §6 and
  `aead-valid.json`. The 4 reserved zeros are fixed.
* AAD is per-usage and per-direction (`session_context ‖ 0x01` payload; `… ‖ 0x02 ‖ 0x00` B→A control;
  `… ‖ 0x02 ‖ 0x01` A→B control) with `session_context = transcript_hash ‖ transfer_id`.
* Counters are per-key, each direction has its own key, each starts at 0. I reproduced all three frozen envelopes
  (`offer` counter 0 and `transfer_begin` counter 1 under `k_m2c_ctrl`; `accept` counter 0 under `k_c2m_ctrl`)
  byte-for-byte.
* No reset path; `HANDSHAKE_NONCE_REPLAYED`, `BINDING_CONSUMED` and `MAX_SESSION_ID_HISTORY = 32` cover
  cross-session replay; `aead-invalid.json` covers `AEAD_REPLAY_DETECTED`, `AEAD_COUNTER_MISMATCH`,
  `AEAD_AUTH_FAILED`, `MESSAGE_WRONG_STATE` and a payload-AAD mismatch.
* `AEAD_NONCE_EXHAUSTED`'s unreachability claim holds arithmetically (≤ 4096 control messages/direction ≪ 2^64).
* **r2 closes R5-01.** `handshake.md` §6.2 now states plainly: "**`k_m2c_payload` is one-shot.** Exactly one AEAD
  seal occurs per session and its counter is fixed at **0** … A second payload seal under the same key is a protocol
  violation, so GCM nonce reuse is impossible by construction rather than by luck." That is precisely the missing
  rule; it also explains why the payload AAD carries no counter while the control AAD does.

---

## Target 6 — Transaction selection: any RSSI ranking, and does 2+ candidates fail closed?

**Verdict: reviewed, no defect found.**

* Enumerated every RSSI/radio reference in `docs/` and `protocol/` (34 matching lines across `*.md`, `*.json`,
  `*.mmd`): all are prohibitions, negations, or `diagnostics_only` markers. No code path, sort key, predicate or
  `peer_candidate` field admits RSSI/`txPower`/`distance`/`signalStrength`; the only structural artifact that would
  carry one is `checkout-flow-v1.json#invariants.no_rssi.forbidden_fields_in_selection`, which lists them as
  *forbidden*.
* `verification.md` §5 pins the transport event as `peer_candidate(peripheral_id)` — "never carries RSSI into
  selection" — and permits RSSI only as `diagnostics_only`.
* A2 pins `picker_sort_key: peripheral_id` / `ascending`, the per-writer allow-list
  (`selected_writers: ["onQRScanned","onCandidateTapped"]`), and
  `recovery_may_auto_target_different_peer: false`.
* **r2 closes RX-04** (A2 @ `a7993ea`, verified): `§4` is now "Selection model: QR-MANDATORY for v1". A2 states
  plainly that `selecting → connecting` has no wire-level realisation without a QR, that the app never
  auto-connects, that 2+ candidates is display-only guidance ordered by `peripheral_id` and never RSSI, and that the
  residual ambiguity — two peripherals claiming the same `session_id` — fails closed with
  `TRANSPORT_PEER_AMBIGUOUS` (`0x020b`, fatal). `§4.3` records the QR-unavailable case as a deliberate v1
  limitation requiring an explicit A1 wire revision to lift. Matching
  `checkout-flow-v1.json#selection_model` (`name: qr_mandatory_v1`, `auto_connect: false`,
  `qr_less_path: "removed …"`). Removing the unimplementable branch rather than inventing a binding-less handshake
  outside the frozen contract is the right resolution, and the failure-closed property is now stronger (the
  ambiguity case is a fatal typed error) rather than weaker.

---

## Target 7 — Verification order: can any failure path reach "verified"?

**Verdict: reviewed, no defect found in the ordering itself; one frozen-artifact inconsistency remains (R7-02).**

* `verification.md` §1 restates the 16 gates with a first-typed-error each; every one of the `RECEIPT_*` errors in
  `errors.json` is `fatal: true` (verified programmatically), so no partial failure can be downgraded into a
  trusted store.
* `§3` makes `REJECTED` evidence-only and `UNVERIFIED_UNKNOWN_ISSUER` explicitly non-trusted; `§6` makes the whole
  verification atomic. `framing.md` §5 forbids any half-imported trusted receipt on cancel/disconnect/Bluetooth-off.
  `§2` keeps the six sub-states separate from the policy outcome.
* Idempotency is correctly placed after steps 10–11: `ALREADY_IMPORTED_IDENTICAL` is an *outcome*, not a bypass.
* **r2 closes R7-01:** `RECEIPT_OFFER_MISMATCH` is gone from `errors.json`; only `WRONG_TRANSACTION` (`0x0614`)
  remains, and A2's §6 aligns with it.

### R7-02 (open) — `wire.md` §7 prints `ACK` as plaintext

* **Severity:** minor
* **File+section:** `docs/protocol/wire.md` §7 "Complete worked example (must reproduce)", row `ACK plaintext`
* **Counterexample:** the row still reads
  "`ACK` plaintext | CBOR `{1:3, 2:transfer_id, 3:0}` = `a3 01 03 02 50 <transfer_id> 03 00`" — an un-enveloped
  control message. That contradicts three normative statements in the same frozen file: §2's message table marks
  `ACK` (`0x03`) `Encrypted = yes`; §6 states "Every other control message (§ `ACCEPT`/`ACK`/`RECEIPT_ACK`/
  `CANCEL`/`RETRY`/`RECEIPT_OFFER`/`TRANSFER_BEGIN`/`TRANSFER_COMPLETE`), and `ERROR` once keys exist, MUST use the
  AEAD envelope. A plaintext envelope received where AEAD is required ⇒ `MESSAGE_WRONG_STATE` (fatal)"; and
  conformance C7 asserts exactly that. So the worked example instructs an implementer to *emit* the one message the
  spec makes a fatal error to *receive*. No vector supplies the counterexample: `framing-valid.json
  #ack_example_plaintext_hex` is the same bare CBOR, and `aead-valid.json` carries envelopes for `offer`,
  `transfer_begin` and `accept` but **no `ACK` envelope**, while §7's heading claims these bytes "must reproduce".
* **Invariant violated:** `DESIGN.md` §13 / `verification.md` §4 — a frozen worked example must not contradict the
  frozen message table it demonstrates. The §9 no-fall-through ordering is not threatened; this is a fail-closed
  false-reject, the same class as RX-03.
* **Owner:** A1

---

## Cross-cutting

### RX-01 — A2's P-256 fix: verified clean (r1 and r2)

I re-derived all four vectors in `protocol/flows/vectors/binding-v1.json` from their own `inputs`; every `expected`
value reproduced, with all points decoding on `secp256r1`:

| vector | `offer_hash` | `binding_tuple` | `binding_tuple_digest` | `binding_proof` | point decodes |
|---|---|---|---|---|---|
| `V1_reconciled_with_A1_r1` | match | match | match | match | yes |
| `V2_same_inputs_wrong_sbt` | match | match | match | match | yes |
| `V3_different_transaction` | match | match | match | match | yes |
| `V4_invalid_point_rejected` | match | match | match | match | **no (as declared)** |

V1's four values are byte-identical to `handshake-valid.json`. The stale values (`b36d3c63…43aa`, `11f63f30…59be`,
`06ceaa65…7547`, `04070e15…d5dc`) no longer appear anywhere in `docs/` or `protocol/`. `handshake.md` §10.1 and
`framing.md` §7 are updated to "closed". **No defect.**

### RX-02 — `protocol/flows/**` outside the freeze: CLOSED in r2

`REVISION.json` now lists 39 files with `hash_rule` covering "docs/protocol/*.md, protocol/schema/*,
protocol/vectors/** **and protocol/flows/** (the A2 artifacts docs/protocol/README.md adopts and pins)", and
`../flows/{checkout-flow-v1.json,checkout-flow-v1.mmd,tools/gen_binding_vectors.py,vectors/binding-v1.json}` are all
present. I re-hashed all 39 rows: **0 mismatches**, and recomputed
`SHA-256("deceipt-proto-r2" ‖ 0x00 ‖ <sorted rows>)` = `5a7cc554dae28764155d478fa7cdd12eabb0aeac20bad982d44bddf5c045edda`, identical to the claimed aggregate.
A2 independently reports the same (38/38 rows, no-op reconciliation).

### RX-04 — P0 picker: CLOSED by A2

Recorded under Target 6.

---

## Independent verification performed

All executed against the working tree; every result observed, not inferred. Items 1–11 were run against r1 and
re-run against r2 where the artifact changed.

1. **Freeze integrity (passes at both revisions).** r1: all 34 listed files hash-match, aggregate recomputes to
   `99ab1f0f…87c60`. r2: all **39** listed files hash-match, aggregate recomputes to `5a7cc554…edda`;
   `protocol/flows/**` now in scope.
2. **A1's independent verifier (passes).** `python3 protocol/vectors/tools/verify_vectors.py` → "OK: all
   independent vector checks passed" at r1 and again at r2.
3. **Handshake (passes).** Rebuilt the 372-byte transcript from its parts with an independent CBOR encoder and an
   independent Ed25519 verifier: byte-identical to `transcript_hex`; `transcript_hash` matches; the merchant
   signature verifies over the raw transcript; re-signing is deterministic. r1's `transcript_layout` off-by-one
   (R2-02) is corrected to `size_bytes: 20` at r2.
4. **Key schedule (passes).** Independent P-256 ECDH both directions + HKDF-SHA-256: `shared_secret`, `prk`, `okm`
   and all four key slices match; client and server ECDH agree.
5. **AEAD (passes).** Independently sealed `payload_seal` (814 B), `control_offer`, `control_transfer_begin` and
   `control_accept` with AES-256-GCM, per-direction AAD and `00000000‖u64_be(counter)` nonces: all four reproduce.
6. **Binding (passes).** `binding_tuple_digest`, `binding_proof` and `offer_hash` re-derived from A2's inputs for
   all four vectors; V1 ≡ A1. r2: re-derived `offer_hash` from the frozen `RECEIPT_OFFER` bytes in the newly
   specified array element order and confirmed `efdc44f3…d4c5`.
7. **Receipt (passes).** 669-byte body re-encodes canonically, SHA-256 matches, `Sig_structure` matches, Ed25519
   verifies, deterministic re-sign identical, container canonical; `long_receipt` (11357 B body, 256 lines,
   30052 minor, 11486 B container) matches.
8. **Framing (passes except RX-03).** `att_payload_max(185)=182`, `max_frame_payload_for_mtu=162`; the 6 frozen
   frames reassemble to exactly 814 bytes with `payload_hash = SHA-256(ciphertext)`, equal to
   `aead-valid.json#payload_seal.ciphertext_hex`; payload lengths `[162,162,162,162,162,4]`. r2 fixed the prose
   bound but not `wire-v1.cddl:35`.
9. **Trust chain (passes).** `valid-credential.cbor` verifies under the pinned anchor `bd65615a…` and fails under
   `61d36a10…`; `kid == issuer_id`; embedded `device_public_key` == `merchant-test-1`. r2 additionally verified the
   new middle type: `handshake-unverified-peer.json` has a 372-byte transcript whose signature verifies against the
   credential's self-asserted device key, an issuer (`0badc0de…00ff`) absent from the pinned anchors, and declares
   `SessionUnverifiedPeer` / transfer allowed / `UNVERIFIED_UNKNOWN_ISSUER` / `must_never_be: TRUSTED`.
   `unknown_issuer_credential` remains a non-fatal unknown-issuer counterexample.
10. **Error taxonomy (passes).** r1: 92 codes, all 16 `RECEIPT_*` fatal, only `CREDENTIAL_UNKNOWN_ISSUER`
    non-fatal among trust-relevant codes. r2: `RECEIPT_OFFER_MISMATCH` removed; `TRANSPORT_PEER_AMBIGUOUS`,
    all `BINDING_*`, `HANDSHAKE_ECDH_INVALID_POINT`, `WRONG_TRANSACTION` present.
11. **Frozen CDDLs (partial — see RX-03).** `receipt-v1.cddl` faithfully restates the container
    (`unprotected : {}` must be empty, `signature : bstr .size 64`, the `Sig_structure` rule, protected header
    `{1: -8, 3: "application/deceipt-receipt+cbor", 4: receipt-id}`); `credential-v1.cddl` matches `trust.md` §2.
    `wire-v1.cddl:35` **still** states `payload = bytes .size (16..512)` and has no final-frame rule.
12. **Schema-table integrity (fails — R2-03).** Programmatically scanned every message in
    `wire-v1.messages.json` for duplicate field labels: `SERVER_HELLO` declares 12 fields for 11 labels with label 4
    twice; the frozen `server_hello_hex` decodes to exactly labels `[1..11]` with no duplicate and no trailing bytes.
13. **Repo hygiene / public-tree check (passes).** `git ls-files` outside the vendored RN trees: the only file with
    private key material is `protocol/vectors/keys/test-keys.json`, and every vector artifact carries the
    `_TESTONLY` header plus `NOTICE`. `app/src/**` references test keys only in doc comments and exposes seed import
    solely through `DeceiptTestProvisioning.provisionTestMerchant`, gated on
    `CapabilityReport.testProvisioningEnabled` with `CAPABILITY_UNAVAILABLE` otherwise — consistent with
    `repo-hygiene.md` and conformance B9.
    *Observation for A0 (pre-existing, outside my scope to change):* `app/android/app/debug.keystore` is **tracked**
    in `HEAD` (Wave-0 scaffold commit) even though `.gitignore` lists `*.keystore`. It is the standard RN debug
    signing key, not merchant/session material, so it does not violate the "no key material" invariant — but it
    makes the `.gitignore` rule non-self-enforcing and should be explicitly allowed or untracked.

## Scope statement

Files written by this burst: **`docs/security/early-contract-review.md` only.** No file was modified under
`protocol/**`, `docs/protocol/**`, `docs/flows/**`, `app/**`, or any other agent's scope, and no tests were added.

## Finding index (open items)

| ID | Severity | Owner | File+section | Target |
|---|---|---|---|---|
| RX-03 | major | A1 | `protocol/schema/wire-v1.cddl:33–35` vs `framing.md:19`, `wire.md:97`, `handshake.md` §7 | 2, 5 (cross-cutting) |
| R7-02 | minor | A1 | `docs/protocol/wire.md` §7 `ACK` row vs §2/§6, conformance C7 | 7 |
| R2-03 | minor | A1 | `protocol/schema/wire-v1.messages.json` `SERVER_HELLO.fields` (label 4 twice) | 2, 4 |

## Closed items (for A0's freeze record)

R4-01 (blocker), R1-02 / R2-01 (major), R1-01, R2-02, R5-01, R7-01, RX-02, RX-04 — all verified closed against the
files at r2 / `a7993ea`, not merely asserted in a changelog. RX-01 verified clean.
