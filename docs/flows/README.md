# Deceipt PoC — Flow Contracts

Owner: **A2** (transaction binding + checkout flow). Exclusive write scope: `docs/flows/**`, `protocol/flows/**`.

| File | What it is |
|---|---|
| `docs/flows/transaction-binding-and-checkout-v1.md` | Authoritative prose contract: binding bytes, QR bootstrap (mandatory), state machine, user-visible failures, demo flows, friction budget. |
| `protocol/flows/checkout-flow-v1.json` | Machine-readable flow contract (states, transitions, invariants, errors, A1 dependencies). |
| `protocol/flows/checkout-flow-v1.mmd` | Flow diagram; RSSI shown only as a forbidden input. |
| `protocol/flows/vectors/binding-v1.json` | Test vectors: exact binding bytes, digests, binding proofs, QR payload. Test-only deterministic secrets. **V1 reconciles byte-for-byte with A1's frozen `protocol/vectors/handshake-valid.json`.** |
| `protocol/flows/tools/gen_binding_vectors.py` | Regenerates the vectors above with valid P-256 points (mirrors A1's deterministic scalar derivation). |

## Status: binding bytes ADOPTED into the A1 frozen revision (r1 = r2 = r3); selection is QR-MANDATORY for v1

A1 **adopted this contract's binding bytes verbatim** into the frozen revision, and they are **byte-identical across r1, r2 and r3** (`docs/protocol/handshake.md` §10): `binding_tuple` + `binding_tuple_digest` (transcript offset 250), `ClientHello` fields 4–7, the `RECEIPT_OFFER` fields, `32`-byte `client_nonce`, and the typed `BINDING_*` errors. Current revision: `deceipt-proto-r3` (aggregate `bb203bd2…253dd8`). The bytes are **revision-agnostic**; machine-readable `protocol/flows/**` artifacts carry `revision_policy` instead of a pinned revision id.

**Selection model — QR-mandatory (A6 RX-04 resolved, §4 of the prose contract):** the QR bootstrap is the **single binding path**. `CLIENT_HELLO` requires `session_id` + `binding_proof`, so a QR-less connect is not realisable in the frozen wire contract; the former "P0 picker" path is **removed**. The `2+ candidates` case is display guidance only, with the duplicate-`session_id` case failing closed (`TRANSPORT_PEER_AMBIGUOUS`).

**Vector defect fix (post A1 cross-check):** A2's original `client_ephemeral_pubkey` was not a valid P-256 point. Vectors regenerated (see §13); V1 now matches A1's frozen fixture exactly; a negative vector (V4) with a non-decoding point was added.

**Reconciliation — verified no-op across r2 and r3:** A1's `deceipt-proto-r2` and `deceipt-proto-r3` left binding inputs unchanged (V1 values and transcript offsets 250/282/284/285 identical; all 39 frozen rows hash-match). No vector regeneration was ever needed — the r1 vectors are the r2 and r3 vectors. A1 resolved R4-01 with option (a) (`binding_tuple` in `SERVER_HELLO` label 10), so the QR map is unchanged. `protocol/flows/**` is in the A1 freeze hash scope; the artifacts are now **revision-agnostic** (a `revision_policy` field replaces the pinned revision id), so future A1 bumps never invalidate A2 metadata — see the prose §14.

**A6 R2-01 (A2 portion) fixed:** §3.5 now writes `currency` as `tstr` and states the offer-hash array element order explicitly. **A6 R7-01 closed in r2:** only `WRONG_TRANSACTION` (`0x0614`) survives; `RECEIPT_OFFER_MISMATCH` was removed from the taxonomy.

What is **not** negotiable and is restated as invariant:

- §7.3 ambiguity rule (0 → keep scanning, 1 → a single *unambiguous* sender, 2+ → explicit disambiguation, never RSSI). **Under QR-mandatory (§4) this is superseded for the connect path:** the explicit disambiguation act is the QR scan, so the app never auto-connects — even with one candidate. The rule still governs candidate *display*: 2+ eligible is guidance only, and the residual duplicate-`session_id` case fails closed.
- No RSSI in eligibility, selection, ordering, connection target, or trust.
- Session binding strictly distinct from merchant-key trust; decryption ≠ trust.
- Ambiguity fails closed.

## Binding bytes at a glance (adopted by A1 into the transcript)

```
offer_hash           = SHA-256("deceipt-offer-hash-v1" || 0x00 || cbor(offer-identity-array))   32 B
binding_tuple        = CBOR array(5): [1, session_id(16), transfer_id(16), receipt_id(16), offer_hash(32)]   87 B
binding_tuple_digest = SHA-256("deceipt-binding-tuple-v1" || 0x00 || binding_tuple)             32 B
binding_proof        = HMAC-SHA-256(SBT, "deceipt-binding-proof-v1" || 0x00 || client_nonce(32)
                                      || client_ephemeral_pubkey(65))                           32 B
```

`client_ephemeral_pubkey` MUST decode on `secp256r1` (`HANDSHAKE_ECDH_INVALID_POINT` otherwise). SBT is 16 CSPRNG bytes used directly as the HMAC key; rationale and a recorded HKDF hardening path (not in r1/r2) are in §3.4 of the prose contract.

## Consumes / feeds

- **Consumes:** `DESIGN.md` §2.5, §4.4–4.5, §6.3–6.4, §7.1–7.4, §8, §9, §11, §13.
- **Feeds:** A1 (pass C/D), A3 (checkout UI + state machine), A6 (adversarial review), A0 (freeze gate, open item 7 / 14 / 15).
