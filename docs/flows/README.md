# Deceipt PoC — Flow Contracts

Owner: **A2** (transaction binding + checkout flow). Exclusive write scope: `docs/flows/**`, `protocol/flows/**`.

| File | What it is |
|---|---|
| `docs/flows/transaction-binding-and-checkout-v1.md` | Authoritative prose contract: binding bytes, QR bootstrap **[PROPOSAL]**, state machine, user-visible failures, demo flows, friction budget. |
| `protocol/flows/checkout-flow-v1.json` | Machine-readable flow contract (states, transitions, invariants, errors, A1 dependencies). |
| `protocol/flows/checkout-flow-v1.mmd` | Flow diagram; RSSI shown only as a forbidden input. |
| `protocol/flows/vectors/binding-v1.json` | Test vectors: exact binding bytes, digests, binding proofs, QR payload. Test-only deterministic secrets. |

## Status: PROPOSAL, not decision

Per the delegation plan, A2 proposes **one** primary binding flow and publishes its bytes before A1 freezes the wire contract. The **QR bootstrap is explicitly a proposal** — A1/A0 may adopt, replace, or reject it. What is **not** negotiable and is restated as invariant:

- §7.3 ambiguity rule (0 → scan, 1 → may auto-connect, 2+ → explicit disambiguation).
- No RSSI in eligibility, selection, ordering, connection target, or trust.
- Session binding strictly distinct from merchant-key trust; decryption ≠ trust.
- Ambiguity fails closed.

## Binding bytes at a glance (A1 must bind these into the transcript)

```
offer_hash            = SHA-256("deceipt-offer-hash-v1" || 0x00 || cbor(offer-identity-array))    32 B
binding_tuple         = CBOR array(5): [1, session_id(16), transfer_id(16), receipt_id(16), offer_hash(32)]   87 B
binding_tuple_digest  = SHA-256("deceipt-binding-tuple-v1" || 0x00 || binding_tuple)              32 B
binding_proof         = HMAC-SHA-256(SBT, "deceipt-binding-proof-v1" || 0x00 || client_nonce(32)
                                     || client_ephemeral_pubkey(65))                              32 B
```

**A1 dependency:** `binding_tuple_digest` MUST be a required field of the merchant-signed canonical handshake transcript; `ClientHello` MUST carry `session_id`, `client_nonce`, `client_ephemeral_pubkey`, `binding_proof`.

## Consumes / feeds

- **Consumes:** `DESIGN.md` §2.5, §4.4–4.5, §6.3–6.4, §7.1–7.4, §8, §9, §11, §13.
- **Feeds:** A1 (pass C/D), A3 (checkout UI + state machine), A6 (adversarial review), A0 (freeze gate, open item 7 / 14 / 15).
