# Deceipt PoC — Transaction Binding & Checkout Flow (v1)

**Owner:** A2 (transaction binding + checkout flow)
**Status:** v1 — binding bytes **adopted verbatim by A1 into the frozen revision `deceipt-proto-r1`, and confirmed unchanged by `deceipt-proto-r2`** (`docs/protocol/handshake.md` §10). **Selection model: QR-mandatory** (§4, resolution of A6 RX-04).
**Revision note:** binding vectors regenerated after A1's cross-check found the published `client_ephemeral_pubkey` was not a valid P-256 point; V1 reconciles byte-for-byte with `protocol/vectors/handshake-valid.json`. **r2 reconciliation: verified no-op** — `deceipt-proto-r2` did not change the binding inputs, and the frozen `offer_hash`/`binding_tuple`/`binding_tuple_digest`/`binding_proof` values and transcript offsets (250, 282, 284, 285) are identical to r1; `protocol/flows/**` is now inside the r2 revision hash scope (A6 RX-02). See §12/§14.
**Consumes:** `DESIGN.md` §2.5, §4.4–4.5, §6.3–6.4, §7.1–7.4, §8, §9, §11, §13.
**Feeds:** A1 (pass C/D — closed in r1), A3 (checkout UI + state machine), A6 (adversarial review), A0 (freeze gate).

> **Labelling rule.** The **QR bootstrap is the single, mandatory binding path for v1** (§4). Values marked **[FROZEN r1]** are byte-identical across A1's `deceipt-proto-r1` and `deceipt-proto-r2` (confirmed: r2 did not change binding bytes) and must not change without a revision bump. The removal of the QR-less path is recorded in §4 and §14.

---

## 1. Scope

This document fixes four things:

1. **Which merchant/transaction the user intends** — an explicit, user-driven selection, with no code path that ranks, filters, or selects by RSSI.
2. **The exact bytes that bind a BLE transfer session to one intended receipt** — adopted by A1 into the frozen handshake transcript.
3. **The checkout state machine and its user-visible failure behavior** — the seven contract states and the named failure situations.
4. **The demo path** — merchant with a synthetic receipt, customer showing merchant + total + verification status, exercising real BLE delivery.

Non-goals: receipt schema (A1 pass A), merchant trust hierarchy (A1 pass B), transfer-session crypto (A1 pass C), UUID assignment (A1 pass D), production disambiguation experience (§14 provisional).

---

## 2. The invariant: no RSSI anywhere in selection

`DESIGN.md` §2.5 and §7.3 are restated verbatim as the governing rule:

```
0 candidates  -> keep scanning
1 eligible candidate -> may automatically attempt connection
2+ eligible candidates -> do not infer intent from RSSI;
                          enter explicit disambiguation/fallback path
```

**Definitions used by this contract:**

- **Candidate** — a BLE peripheral whose advertisement carries the assigned Deceipt Transfer Service UUID.
- **Eligible** — a candidate that additionally passes *only* non-radio, cryptographic/structural checks: correct service UUID, supported protocol version in the advertisement, and **possession of the scanned session-binding material (`session_id` + `SBT`)**. Eligibility is **never** a function of signal strength.
- **Selected** — the single candidate named by the user's QR scan. Only a `selected` candidate may be connected to for receipt transfer.

**How v1 satisfies §7.3 (QR-mandatory — see §4):** the *explicit disambiguation act* is the QR scan. The app **never** connects to any candidate without a QR-named session, so the `2+ eligible` auto-connect hazard cannot arise; the `2+ candidates` case is resolved by the user intentionally scanning the one terminal they are paying. A set of `2+ eligible` candidates — which under QR-mandatory can only mean two or more peripherals advertising the *same* `session_id` (clone/impostor) — **fails closed**.

**Normative constraints on any implementation (A3/A4/A5):**

- RSSI (and any radio-derived proximity, distance, or "closest"/"nearest" score) MUST NOT appear in the eligibility predicate, the selection decision, the connection target, the display order of any candidate list, or any trust decision.
- If RSSI is recorded at all it is diagnostics only, must be labelled as such in the UI, and must not be an input to `select()`.
- Any candidate list is display-only guidance ("which terminal to scan"). It MUST use a deterministic, non-radio tiebreak over the peripheral identifier bytes (ascending `peripheral_id`) and MUST NOT be tappable-to-connect.
- Ambiguity **fails closed**: two or more eligible candidates is an error state, never an automatic pick.

---

## 3. Primary flow (P1) — QR bootstrap over BLE delivery [FROZEN r1]

### 3.1 Overview

```
 MERCHANT (A)                                        CUSTOMER (B)
 ------------                                        ------------
 create synthetic receipt
 compute binding tuple + offer_hash
 mint session-binding token (SBT)
 render QR at terminal  ─── QR (out-of-band, scanned) ───▶  scan QR
 start transfer session                                      parse session_id + SBT + offer_hash
 start GATT + advertise fixed UUID                           verify QR freshness (expires_at)
        ◀─────────────── BLE connect (central) ───────────────  connect to the ONE eligible
 (no RSSI used to choose the target; QR fixed it)              candidate matching session_id
        ◀──── ClientHello {session_id, cnonce, ceph, binding_proof} ──  binding_proof = HMAC-SHA-256(SBT, ...)
 merchant validates ClientHello (ceph must decode, else
 HANDSHAKE_ECDH_INVALID_POINT), verifies binding_proof
 -> else abort
        ─── ServerHello {server_nonce, server_eph_pub,   ───▶  verify merchant credential + sig,
            credential, transcript_signature, digest}          recompute binding_tuple_digest
                                                               derive keys; binding check vs QR
        ───────────── RECEIPT_OFFER {offer fields} ──────────▶  compare offer vs QR values
        ◀──────────── ACCEPT (AEAD) ─────────────────────────  (user taps Accept)
        ───────────── TRANSFER_BEGIN + DATA frames ──────────▶  reassemble, AEAD decrypt
                                                              RECEIPT_UNTRUSTED
                                                              verify sig + authorization (§9)
        ◀──────────── RECEIPT_ACK ───────────────────────────  STORE (verified, policy)
        ───────────── disconnect ────────────────────────────▶  SAVED
```

The QR is a **selection and bootstrap channel only**. It carries no receipt, no amount, no line items, and no merchant credential. The synthetic receipt itself travels **only** over the GATT `DATA` characteristic, AEAD-encrypted for the session. The demo therefore *does* exercise BLE delivery; deleting the BLE leg breaks it.

### 3.2 Why a QR at all

With two phones and no pairing, nothing else gives the customer a *fresh, merchant-generated, unambiguous* pointer to exactly one transaction without radio inference. The QR is out-of-band, physical, and intentional: the user points a camera at one terminal. That is the explicit user act §7.3 requires, and it collapses "2+ candidates" to a single named session. It is **also required by the frozen wire contract** — see §4.

### 3.3 QR content and exact bytes [FROZEN r1]

The QR payload is a CBOR map, prefixed with a version tag, base64url (unpadded).

```
qr_payload        = "deceipt1:" || base64url_nopad( qr_cbor )
qr_cbor           = CBOR map(5), definite-length, integer keys ascending
  1 : uint      = 1                                 -- qr_format_version
  2 : bytes(16) = session_id
  3 : bytes(16) = session_binding_token (SBT)       -- SECRET; see §3.4
  4 : bytes(32) = offer_hash                        -- see §3.5
  5 : uint64    = expires_at_unix                   -- seconds; TTL see §3.8
```

Rules:

- The QR MUST NOT contain merchant name, amount, receipt id, line items, customer data, or any credential. (If the terminal screen separately displays the amount as text, that text is *display*, not protocol input.)
- `session_id` is random 16 bytes per checkout session; not derived from merchant identity.
- Implementations MUST reject `qr_format_version != 1` and MUST reject a payload whose declared lengths differ from the fixed sizes above.
- **r2 status:** A1's `deceipt-proto-r2` resolution of A6 R4-01 used **option (a)** — the full `binding_tuple` travels in `SERVER_HELLO`, not the QR — so this map is **unchanged**; no `transfer_id`/`receipt_id` fields are added. (Confirmed at r2; see §14.)

**Vector (V1) [FROZEN r1]:**

```
qr raw CBOR (80 B):
a50101025000112233445566778899aabbccddeeff0350000102030405060708090a0b0c0d0e0f045820efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5051a6955b9f0
payload (116 chars):
deceipt1:pQEBAlAAESIzRFVmd4iZqrvM3e7_A1AAAQIDBAUGBwgJCgsMDQ4PBFgg79xE86bQiPzSPun7j5tl9GRXLag95T8M43pdIcmU1MUFGmlVufA
(expires_at_unix = 0x6955b9f0 = 1767225840 = issued_at 1767225540 + T_BINDING_QR 300)
```

### 3.4 Session-binding token (SBT) [FROZEN r1] — with rationale

`SBT` is 16 random bytes, generated by the merchant at checkout, unique per session. It is **not** a key and **not** a trust credential. Its only jobs:

1. **Identify the exact BLE session** — a client that presents a valid binding proof is answering *this* checkout, not another nearby one.
2. **Prove possession of the QR** — only a party that read the QR knows `SBT`.
3. **Bind the session's ephemeral ECDH key to the intended transaction** — the proof covers the client's ephemeral public key (§3.7), so a substituted key fails.

`SBT` is kept in merchant memory for the session only, and **never** is logged or committed. It is destroyed on consumption (§3.8) or expiry.

**Rationale for using 16 random bytes directly as the HMAC-SHA-256 key** (flagged low-end by A1):

- The SBT is **128 bits of CSPRNG entropy** (not password-derived, not user-chosen, not structured). HMAC-SHA-256 with an *n*-bit uniformly random key provides *n*-bit security; the effective security here is therefore **128 bits**, which is the PoC's target strength and is not attackable by brute force within the 300 s QR TTL.
- HMAC is not vulnerable to the SHA-256 length-extension issue, so a key shorter than the 64-byte block adds no structural weakness — it only caps security at the key entropy.
- The SBT is **single-use** (`BINDING_CONSUMED`), **short-lived** (`T_BINDING_QR`, §3.8), and compared in **constant time**. Reuse across sessions is forbidden by construction (fresh CSPRNG per checkout).
- The binding proof is **not** the receipt trust decision: even a full SBT compromise yields only session identification, never a trusted receipt (`DESIGN.md` §9 steps 10–11 still required).

**Recorded hardening path (NOT in r1 — requires a revision bump and A1 re-adoption):** derive the HMAC key with HKDF-SHA-256 from a 16-byte salt plus a longer secret, e.g. `k_binding = HKDF-SHA-256(ikm = SBT_32_random, salt = session_id, info = "deceipt-binding-key-v1")`, and use `k_binding` as the HMAC key. This raises the key to 256 bits at zero protocol risk. It is **not** applied to r1 because A1 adopted and froze the construction below; changing it would change every `binding_proof` byte and every vector.

### 3.5 Offer hash — exact bytes [FROZEN r1]

The QR must name the exact intended receipt before the receipt is transferred. `offer_hash` is a domain-separated SHA-256 over the *identity* fields of the checkout (not the receipt's full content).

**CBOR array element order (this order is what reproduces the frozen `efdc44f3…d4c5` value; it MUST NOT be reordered):**

```
offer_hash = SHA-256(
    "deceipt-offer-hash-v1" || 0x00 || cbor(
        [ bytes(16) session_id,            -- RECEIPT_OFFER label 12
          bytes(16) transfer_id,           -- RECEIPT_OFFER label 2
          bytes(16) receipt_id,            -- RECEIPT_OFFER label 3
          tstr      merchant_reference,    -- RECEIPT_OFFER label 4
          uint      total_amount_minor,    -- RECEIPT_OFFER label 5
          tstr      currency,              -- RECEIPT_OFFER label 6; ISO-4217, e.g. "CAD"
          uint      issued_at_unix ] )     -- RECEIPT_OFFER label 7
)
```

- **`currency` is a `tstr` (ISO-4217 code), not a `uint`.** The array's scalar types are exactly: `bstr, bstr, bstr, tstr, uint, tstr, uint`.
- **Element order ↔ label mapping** (array position → `RECEIPT_OFFER` label): `session_id=12, transfer_id=2, receipt_id=3, merchant_reference=4, total_amount_minor=5, currency=6, issued_at_unix=7`. A receiver recomputes the hash from those offer fields in **this array order**; it is *not* the label order and *not* the label-list order `2,3,4,5,6,7,12`. (A6 R2-01: an implementation following a label-list order computes a different hash and false-rejects every transaction.)
- `total_amount_minor` is an integer + ISO-4217 `currency`; **no floating point** (§4.2).
- A1 recomputes this value from the authenticated `RECEIPT_OFFER` fields, so the QR and the offer cannot disagree.
- The domain separator and the `0x00` byte make this value unusable as any other Deceipt hash.

**Vector (V1) [FROZEN r1]:**

```
offer_hash_preimage (CBOR array(7), 64 B):
875000112233445566778899aabbccddeeff50ffeeddccbbaa99887766554433221100500123456789abcdef0123456789abcdef77
6d65726368616e742e706f632e746573742d616c7068611903ca634341441a6955b8c4

offer_hash:
efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5
```

### 3.6 Binding tuple — exact bytes bound into the transcript [FROZEN r1]

```
binding_tuple = CBOR array(5), definite-length
  [0] uint       1                    -- binding_format_version
  [1] bytes(16)  session_id
  [2] bytes(16)  transfer_id
  [3] bytes(16)  receipt_id
  [4] bytes(32)  offer_hash

encoded (87 bytes, V1):
85                                # array(5)
   01                             # uint 1
   50 <16B session_id>            # bstr(16)
   50 <16B transfer_id>           # bstr(16)
   50 <16B receipt_id>            # bstr(16)
   58 20 <32B offer_hash>         # bstr(32)
```

```
binding_tuple_digest = SHA-256("deceipt-binding-tuple-v1" || 0x00 || binding_tuple)
```

A1's frozen transcript carries **both** `binding_tuple_digest` (offset 250) and the full `binding_tuple` (length-prefixed by a `u8` at offset 284), so the merchant's `ServerHello` signature covers the transaction binding and the derived session keys are transcript-bound (`docs/protocol/handshake.md` §3).

> **[transcript-reconstruction dependency, A6 R4-01]** A6 found that the *receiver* cannot rebuild the signed transcript from the messages as currently defined, because `session_id`, the offer-hash members and the raw `binding_tuple` are not all reachable before key derivation. This is A1's wire-contract fix. A2's requirement is unchanged: the 32-byte `binding_tuple_digest` and the 87-byte `binding_tuple` MUST both be inside the merchant-signed transcript and both reachable by the receiver. A1's chosen resolution may put the tuple source in `SERVER_HELLO` (option a) or in the QR (option b); A2 reconciles the QR layout if (b) is chosen (§12/§14).

**Vector (V1) [FROZEN r1]:**

```
binding_tuple (87 B):
85015000112233445566778899aabbccddeeff50ffeeddccbbaa99887766554433221100500123456789abcdef0123456789abcdef5820efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5

binding_tuple_digest:
d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2
```

### 3.7 Binding proof in ClientHello — exact bytes [FROZEN r1]

The client proves it possesses `SBT` and binds the proof to its own ephemeral ECDH key:

```
proof_message = "deceipt-binding-proof-v1" || 0x00
                || client_nonce(32)              -- ClientHello field 5
                || client_ephemeral_pubkey(65)   -- ClientHello field 6; P-256 uncompressed 0x04||X||Y

binding_proof = HMAC-SHA-256(key = SBT, msg = proof_message)   -- 32 bytes
```

`proof_message` is exactly **122 bytes** for P-256. `client_ephemeral_pubkey` MUST be a point that decodes on `secp256r1`; a non-decoding point is rejected at `ClientHello` with `HANDSHAKE_ECDH_INVALID_POINT` **before** any binding check.

Merchant-side check, before doing any session work (A1's `CLIENT_HELLO` fields 4–7):

```
1. session_id resolves to a live, unconsumed, unexpired session  -> else BINDING_UNKNOWN_SESSION
2. client_ephemeral_pubkey decodes as P-256                       -> else HANDSHAKE_ECDH_INVALID_POINT
3. constant-time compare HMAC-SHA-256(SBT, proof_message) == binding_proof
                                                                  -> else BINDING_PROOF_INVALID
4. mark session "claimed by client_nonce/client_ephemeral_pubkey"
```

Because `proof_message` covers `client_ephemeral_pubkey`, a man-in-the-middle that substitutes the client's ECDH key cannot produce a valid proof: it would have to know `SBT`, and if it did, the client's own proof would no longer match the key the merchant derives against. **Binding is not trust**: passing this check says only "this session, this ephemeral key" — never "this merchant is authentic".

**Vector (V1) [FROZEN r1] — matches A1 `handshake-valid.json`:**

```
client_nonce                c0ffee0000000000000000000000000000000000000000000000000000000001
client_ephemeral_pubkey(65) 0414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c
proof_message (122 B):
646563656970742d62696e64696e672d70726f6f662d763100c0ffee00000000000000000000000000000000000000000000000000000000010414e02cf948541686573b744c58e8f92e70f93009333c81edc9a5f7bbda5445e88dbc8b8c812b139c60a85eea163240781d840eb17fb3ab28788aef78dec1bf5c

binding_proof:
fa19790fda7c85c1c745d4299c4177f9bcd15090de78961a38b7ebc36565083e
```

### 3.8 Expiration and consumption

Three independent clocks, all fail-closed, reconciled to A1's `handshake.md` §7:

| Clock | Owner | Value | Effect |
|---|---|---|---|
| QR validity | merchant | `T_BINDING_QR = 300 s`; `expires_at_unix` in QR | Client refuses to start a session from an expired QR → `BINDING_STALE`. |
| Session lifetime | merchant | `T_SESSION = 120 s`; `T_ADVERTISE = 60 s` | Session, `SBT`, and `session_id` are destroyed; `ServerHello` unavailable; client surfaces recoverable expiry (`SESSION_EXPIRED`). |
| Consumption | merchant | on first accepted `ClientHello` with valid `binding_proof` | Session marked **claimed**; a second `ClientHello` for the same `session_id` is rejected (`BINDING_CONSUMED`). |

**Stale binding** (QR expired, or session torn down before the client connected) → `BINDING_STALE`. The customer scans a fresh QR (§4).

**Consumed binding** (proof already used once) → `BINDING_CONSUMED`. This is the anti-replay guard for the *binding*, independent of §6 AEAD replay handling and §4.5 receipt-ID dedup.

### 3.9 What the binding proves, and what it does NOT

| Property | Established by binding? |
|---|---|
| User intended this terminal/transaction | **Yes** — explicit QR scan. |
| This BLE session is the one named by the QR | **Yes** — `session_id` + `binding_proof`. |
| Possession of the QR/session secret | **Yes** — HMAC over `SBT`. |
| The receipt is authentic | **No.** Only the merchant signature over exact received bytes + key authorization (design §9 steps 10–11) does that. |
| Merchant identity | **No.** Session binding is strictly distinct from merchant-key trust. |
| Physical proximity of the merchant | **No** — and it is never inferred from RSSI. |

---

## 4. Selection model: QR-MANDATORY for v1 (resolution of A6 RX-04)

**Decision: the QR bootstrap is the single binding path.** There is **no QR-less connection path** in v1. This section replaces the former "P0 manual picker" fallback and resolves A6 RX-04.

### 4.1 Why QR is mandatory — the wire contract forbids the alternative

- A1's frozen `CLIENT_HELLO` requires `session_id` (label 4, `required: true`) and `binding_proof` (label 7, `required: true`). `protocol/vectors/handshake-invalid.json#binding_required_fields_absent` yields **fatal `BINDING_REQUIRED`** when either is absent.
- There is **no** `session_id`-less handshake variant and **no** P0 error path anywhere in `docs/protocol/`.
- `binding_proof = HMAC-SHA-256(SBT, …)` — the client cannot compute it without `SBT`, and `SBT` is only obtainable from the QR (§3.4).
- Therefore a client that connects without a QR cannot produce a valid `CLIENT_HELLO`, so `selecting → connecting` **has no wire-level realisation** without the QR.
- RSSI-free disambiguation (§2.5/§7.3) requires **possession of the binding material**: the only non-radio way to single out one terminal's transaction is to hold the secret that terminal generated. That secret is delivered by the QR.

### 4.2 Candidate rule under QR-mandatory

```
scan for candidates advertising the Deceipt Transfer Service UUID
  |
  +-- 0 candidates -> keep scanning; UI: "No Deceipt terminal found nearby."
  |
  +-- 1..N candidates -> display-only guidance only:
  |     "Scan the code shown at the terminal you are paying."
  |     (list is non-tappable-to-connect, ordered by peripheral_id, NEVER by RSSI)
  |
  +-- user scans a QR -> the QR's session_id names ONE session -> connecting
  |
  +-- 2+ peripherals claim the SAME session_id (clone/impostor) -> FAIL CLOSED
         TRANSPORT_PEER_AMBIGUOUS (0x020b, fatal)
```

The app **never** auto-connects. Because selection is always a QR scan, the `2+ eligible → auto-connect` hazard of §7.3 cannot occur; the §7.3 requirement is met by the explicit, physical, non-radio QR act, and the residual ambiguous case (duplicate `session_id`) fails closed.

### 4.3 QR unavailable

If the merchant cannot render a QR, expired it, the camera is denied, or the customer cannot scan: **the customer cannot receive a receipt in v1.** This is a deliberate v1 limitation, not a defect — the alternative (a binding-less connect path) would require a change to A1's frozen wire contract. The UI states: "This terminal isn't showing a checkout code yet." with a *rescan* affordance. Any future binding-less path MUST be requested from A1 as an explicit wire-contract revision; it is **not** assumed here.

---

## 5. Checkout state machine

Seven contract states. `DESIGN.md` §8.1 names the transfer-internal states (IDLE…DISCONNECT); this is the **checkout/UI** projection that A3 implements, mapped onto them.

```
ready
  │  user acts (scan QR)
  ▼
selecting ──(0 candidates)──▶ ready        (keep scanning)
  │  QR scanned → exactly one session selected (explicit user act)
  ▼
connecting ──(connect fail/timeout)──▶ recoverable_failure
  │  ClientHello/ServerHello, point decode, binding check, credential+signature check
  ▼
transferring ──(cancel | disconnect | bluetooth off)──▶ recoverable_failure
  │  reassemble → AEAD decrypt → RECEIPT_UNTRUSTED
  ▼
verifying ──(any §9 failure)──▶ recoverable_failure (rejected, audited)
  │  §9 steps 10–15 all pass
  ▼
saved
```

State notes:

- `selecting` is where the §7.3 rule lives. It is the **only** state permitted to change the selected session, and the only trigger is a QR scan (the explicit user act). A candidate list in this state is display-only and cannot transition the machine.
- `transferring` never implies trust; the receipt is `RECEIPT_UNTRUSTED` until `verifying` completes (§8.1, §9).
- `verifying` is local-only work; no transport success can shortcut it.
- `saved` records the §5.3 verification outcome (trusted / unknown-key / rejected-by-policy). Dedup (§9 step 13) may turn a re-received receipt into `saved` **without** re-adding it.
- `recoverable_failure` always carries a typed reason and an explicit retry affordance; it never auto-retries into a different peer.

Transition guards (normative):

| Transition | Guard |
|---|---|
| `selecting → connecting` | **exactly one QR scan** names a session; 2+ peripherals claiming the same `session_id` is `TRANSPORT_PEER_AMBIGUOUS` (fail closed); there is no candidate-tap edge into this transition |
| `connecting → transferring` | point decode ok AND binding check passed AND merchant credential+transcript signature verified (§9 steps 3–4) |
| `transferring → verifying` | full AEAD payload authenticated/decrypted (§9 step 7) |
| `verifying → saved` | **all** of §9 steps 10–15 pass; any failure goes to `recoverable_failure` |

---

## 6. User-visible behavior for the named situations

| Situation | State | User sees (no crypto internals) | Recovery |
|---|---|---|---|
| **Wrong terminal / wrong transaction** | `connecting → recoverable_failure` | "This isn't the transaction you selected." (`WRONG_TRANSACTION`, `0x0614`); no partial receipt is kept. | Rescan the intended terminal's QR. |
| **Expired transaction** | `selecting` or `connecting → recoverable_failure` | "This checkout code has expired. Ask the merchant to show a new one." (`BINDING_STALE`) | Rescan a fresh QR. |
| **QR unavailable / not rendering** | `selecting` | "This terminal isn't showing a checkout code yet." | Rescan when it appears. |
| **Denied Bluetooth permission** | pre-`selecting` | "Deceipt needs Bluetooth to receive your receipt." Explanation + Settings deep-link. | Grant permission; retry. |
| **Denied camera permission** | pre-`selecting` | "Scanning needs camera access." | Grant; retry. |
| **Cancellation (user)** | any → `recoverable_failure(USER_CANCELLED)` | Immediate; "Cancelled." No half-imported receipt retained. | Rescan / retry. |
| **Bluetooth disabled** | any → `recoverable_failure(TRANSPORT_BLUETOOTH_OFF)` | "Bluetooth is off." | Enable; retry. |
| **No terminal found** | `selecting → ready` | "No Deceipt terminal found nearby." Keeps scanning. | Wait / retry. |
| **2+ terminals, none scanned** | `selecting` | "Scan the code shown at the terminal you are paying." Guidance only; the list is not tappable-to-connect and is never sorted by signal strength. | Scan one terminal's QR. |
| **Duplicate `session_id` advertised** | `selecting → recoverable_failure` | "More than one terminal is claiming this checkout." (`TRANSPORT_PEER_AMBIGUOUS`) | Retry; report. |

Rules: no state ever displays "verified" before §9 completes; a failure never shows a receipt as trusted; `recoverable_failure` never auto-targets a different peripheral. The error identifier used for offer mismatch is **`WRONG_TRANSACTION`** only (A6 R7-01: `RECEIPT_OFFER_MISMATCH` is not the frozen identifier used by any vector or doc).

---

## 7. Merchant demo flow (synthetic receipt)

1. Merchant app enters **Merchant mode** (dev/test build); a test trust anchor and test merchant key are provisioned per A1 pass B. UI states plainly this is a PoC test merchant.
2. Merchant creates a **synthetic** `DeceiptReceiptV1` (no POS): fixed line items, integer minor units, a random `receipt_id`.
3. Merchant computes `transfer_id`, `offer_hash` (§3.5), mints `session_id` + `SBT`, and renders the QR at "the terminal".
4. Merchant taps **Send**: creates the ephemeral session, starts the Deceipt GATT service, advertises the fixed service UUID only (§7.2 — no name/amount/receipt in the advertisement).
5. Customer scans; merchant validates `ClientHello` (point decodes) and `binding_proof`; merchant signs the transcript; offers; on `ACCEPT` streams `DATA` frames; signs nothing new (receipt was signed at step 2 over exact bytes).
6. On `RECEIPT_ACK`, merchant tears down the session and destroys `SBT`.

The merchant's signed artifact is produced once, before the BLE session, over exact canonical bytes (§4.1); the transfer never re-encodes it.

---

## 8. Customer display rules (no cryptographic detail)

The customer screen shows, in order:

- **Merchant** — the merchant display name, marked with its verification outcome (`trusted` / `unknown key` / `rejected`). An `unknown key` receipt is shown, but never as trusted.
- **Total** — `currency + amount_minor` formatted; the amount is only presented as *the offered total* until `saved`.
- **When** — receipt timestamp.
- **Verification status** — plain language: "Verified — issued by a recognized Deceipt merchant", or "Not verified — signing key is not recognized", or "Rejected — signature did not match".
- **Recovery affordances** on failure — retry, rescan, or cancel.

Never shown: key identifiers, signature bytes, nonces, transcript hashes, session IDs, `SBT`, or any transport success framed as trust. The copy never equates "encrypted"/"delivered" with "verified".

---

## 9. Friction budget — OBSERVED step counts

Counts below are the **protocol-required, code-observable** steps an implementation must take, enumerated from the state machine. They are **not** a claim about perceived taps: OS permission prompts, camera focus, and real-device timing are unknown until A4/A5 device testing and are excluded here. No "zero taps" claim is made.

**Happy path — protocol step count: 5 user-visible phases**

| # | Phase | Automatic? |
|---|---|---|
| 1 | Grant permissions (Bluetooth; camera) | once per install — **not** automatic |
| 2 | Scan QR | user act |
| 3 | Connect + handshake + binding check | automatic |
| 4 | Review offer (merchant + total) | user act (Accept) |
| 5 | Save + show verified | automatic |

Protocol actions between the user's scan and the accept: connect, `ClientHello`, point decode, binding verify, `ServerHello` + credential/signature verify, digest recompute, key derivation, `RECEIPT_OFFER`, binding compare — 9 protocol actions, 0 user taps.

**Failure paths add exactly one explicit recovery act** (rescan / retry / enable Bluetooth), never a silent auto-retry to a different peer.

These are minimum protocol steps; perceived taps are pending A4/A5 device runs and OS-prompt behaviour.

---

## 10. Acceptance walk: competing merchants, explicit selection, no RSSI

Scenario: 3 merchants A, B, C all advertising the Deceipt service UUID within radio range; customer intends only B.

```
ready
 └─ user scans B's QR
selecting: candidates {A,B,C}; QR names session_id_B
           eligible = candidates matching session_id_B  -> {B}   (structural/secret match, not RSSI)
           exactly one session selected by the user's explicit act
connecting: ClientHello{session_id_B, cnonce, ceph, proof}
           A and C cannot answer:  they hold no session_id_B / SBT_B  -> BINDING_UNKNOWN_SESSION
           B validates ClientHello (ceph decodes), verifies proof -> ServerHello ->
           binding + credential + sig verified
transferring -> verifying -> saved
```

A and C are eliminated by **possession of B's session secret**, not by signal strength. If the user had scanned A's QR, B and C would equally fail.

**With 2+ terminals and no scan yet:** the app shows only display guidance ("Scan the code shown at the terminal you are paying"), ordered by `peripheral_id`, non-tappable-to-connect; it **never** auto-connects and never picks the strongest signal. The user's selection is the physical act of scanning one terminal.

**With 2+ peripherals advertising the same `session_id`** (clone/impostor): `TRANSPORT_PEER_AMBIGUOUS` — fail closed, no connection.

**Code-level check the reviewer can make:** every write to `selected` is reachable only from a user-act handler (`onQRScanned`); there is no `onCandidateTapped`-to-connect edge; the type of the eligibility predicate excludes RSSI/`rssi`/`txPower`/`distance`; any guidance list sort key is `peripheral_id`. (Named in `protocol/flows/checkout-flow-v1.json` as `selection_invariants`.)

---

## 11. Handoff to A1 — CLOSED in r1; r2 reconciliation pending

A1 **adopted** this contract's binding bytes verbatim (`docs/protocol/handshake.md` §10). The dependency is satisfied:

| Requirement | Status in `deceipt-proto-r1` |
|---|---|
| `binding_tuple_digest` required in the signed transcript | **Yes** — transcript offset 250; full `binding_tuple` at offset 285, len-prefixed at 284 |
| `ClientHello` carries `session_id`, `client_nonce`, `client_ephemeral_pubkey`, `binding_proof` | **Yes** — labels 4, 5, 6, 7 |
| `RECEIPT_OFFER` carries the offer-hash members | **Yes** — labels 2, 3, 4, 5, 6, 7, 12 |
| Wire IDs for the three 16-byte identifiers | **Yes** — `bstr(16)`, pass D |
| Typed binding errors | **Yes** — `BINDING_*` codes `0x0312..0x0316`, `WRONG_TRANSACTION` `0x0614`, plus `HANDSHAKE_ECDH_INVALID_POINT` |
| 32-byte `client_nonce` | **Yes** (`handshake.md` §1) |

**Open cross-checks with A1 (not A2-owned):**

- **A6 R2-01** — `offer_hash` member set/type contradiction across `wire.md` §7 and `framing.md` §7 (labels `3,4,5,6,7,10` — wrong) vs `handshake.md` §10 and this contract (correct: array order `session_id(12), transfer_id(2), receipt_id(3), merchant_reference(4), total(5), currency(6), issued_at(7)`). A1 is fixing this in `deceipt-proto-r2`; A2's prose/JSON now match A1's frozen `efdc44f3…` value.
- **A6 R4-01** — receiver transcript reconstruction (blocker, A1-owned). If A1's resolution moves the `binding_tuple` source into the QR (option b), A2 updates the QR layout (§3.3).
- **A6 RX-02** — `protocol/flows/**` is outside `REVISION.json`'s hash scope; A1 owns revision scope. A2 keeps its artifact revision marker explicit and will re-mark on r2.
- **A6 RX-04** — resolved by A2 in §4 (QR-mandatory).

---

## 12. Open items / provisional markers

| Item | Status |
|---|---|
| QR bootstrap as the PoC binding path | **MANDATORY for v1** (§4); bytes FROZEN (r1 = r2) |
| QR-less / picker-connect path | **REMOVED** — not realisable in r1/r2 (§4.1); any replacement requires an A1 wire revision |
| `qr_format_version`, domain separators, `proof_message` layout | **FROZEN r1 = r2** (adopted by A1) |
| Transcript field placement of `binding_tuple_digest` | **FROZEN r1 = r2** — A1 pass C, offset 250 |
| Wire IDs for session/transfer/receipt | **FROZEN r1 = r2** — A1 pass D |
| `offer_hash` member set/type | **A2 prose/JSON corrected**; A1 fixed the conflicting docs in r2 (A6 R2-01 closed) |
| HKDF-expanded SBT key | **Recorded hardening path**, not in r1/r2 (§3.4) |
| r2 reconciliation of A2 vectors | **DONE — verified no-op** (§14); `protocol/flows/**` now inside r2 hash scope |
| Production disambiguation UX | §14 provisional, out of PoC scope |
| Perceived tap count on real devices | pending A4/A5 |

Machine-readable companion: `protocol/flows/checkout-flow-v1.json`.
Binding test vectors: `protocol/flows/vectors/binding-v1.json` (generator: `protocol/flows/tools/gen_binding_vectors.py`).
Flow overview: `protocol/flows/checkout-flow-v1.mmd` (diagram), `docs/flows/README.md` (index).

---

## 13. Vector defect fix record (post A1 cross-check)

A1's `protocol/vectors/binding-crosscheck.json` recorded a **high** finding: the `client_ephemeral_pubkey_hex` in A2's original V1/V2/V3 was **not a valid P-256 point**, so no ECDH was possible and the vectors could not be used as handshake vectors. A2's HMAC/offer/tuple/digest values were internally correct (HMAC treats the key material as opaque bytes).

**Fix applied:**

- Vectors regenerated by `protocol/flows/tools/gen_binding_vectors.py` using **valid, reproducible P-256 points** derived exactly as A1's reference does (`SHA-256("deceipt-testkey:p256:" || name || "#counter")` reduced mod `n`).
- **V1 reconciles byte-for-byte with A1's frozen `handshake-valid.json`.**
- V2 (same transaction, wrong SBT) and V3 (different transaction) use valid points.
- **V4** added: a point with the final byte flipped, which fails `secp256r1` decode and MUST be rejected at `ClientHello` with `HANDSHAKE_ECDH_INVALID_POINT`.
- Every non-negative vector's point is asserted to decode; V4's is asserted not to.
- Independently re-verified by A6 (`docs/security/early-contract-review.md` RX-01: "the fix is verified", all four vectors reproduce from inputs).

**Regenerated values:**

| Vector | valid P-256 | `offer_hash` | `binding_tuple_digest` | `binding_proof` |
|---|---|---|---|---|
| V1 (== A1 r1) | yes | `efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5` | `d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2` | `fa19790fda7c85c1c745d4299c4177f9bcd15090de78961a38b7ebc36565083e` |
| V2 (wrong SBT) | yes | `efdc44f3…4c5` (same) | `d9d3d7df…9e2` (same) | `49b9edb37943d3c4c3607e429a85118050b3a3f7c3f70fcaf6444ec4df81e4fc` |
| V3 (other txn) | yes | `043f3cde62ad673bc72cd828dd1f0bba2f66516e3bf4a504da344c1b8921dfac` | `e7b28cffce49a18686d8cf97a18566416724ea1d8ca78c2c788660ffdad1d14f` | `45aa8fcd46cee2030c95ddf443febcd2cf7445d24abb44daeb440da9f8be8edb` |
| V4 (bad point) | **no** | `efdc44f3…4c5` (same) | `d9d3d7df…9e2` (same) | `17b28db865405a3328aef05d0409b2adce1d6ff0c37ad307073c7d4524d6aa02` (informational; rejected before use) |

All four vectors and their exact bytes live in `protocol/flows/vectors/binding-v1.json`.

---

## 14. Change record: A6 early review (RX-04 + R2-01)

**RX-04 (minor, A2) — resolved.** A6 found the former P0 picker path had no wire-level realisation: `CLIENT_HELLO` requires `session_id` + `binding_proof`, absence is fatal `BINDING_REQUIRED`, and no binding-less variant exists in r1.

- **Chosen resolution: QR-mandatory for v1** (§4). Rationale: (a) it matches the frozen wire contract with no change; (b) RSSI-free disambiguation requires possession of the binding material, which only the QR delivers; (c) a binding-less connect path would be a change to A1's frozen wire contract and must be requested explicitly, not assumed.
- The former **§4 P0 branch and its `selecting → connecting` picker edge are removed**; the `2+ candidates` case is now display guidance plus explicit physical selection, with the residual duplicate-`session_id` case failing closed (`TRANSPORT_PEER_AMBIGUOUS`). §5, §6, §9 and §10 updated to match.

**R2-01 (major, A1 + A2) — A2 portion fixed.** §3.5 previously wrote `uint currency` for a `tstr` `currency` and listed offer-hash members ambiguously. Corrected: `currency` is `tstr`; the array element order is stated explicitly and mapped to `RECEIPT_OFFER` labels (`12,2,3,4,5,6,7` in array order — not the label-list order `2,3,4,5,6,7,12`). This order is the one that reproduces the frozen `efdc44f3…d4c5` value and is now unambiguous in both prose and JSON. **No binding bytes changed**, so the vectors still reconcile with r1.

**R7-01 (minor, A1) — A2 text aligned.** §6 now cites only `WRONG_TRANSACTION` (`0x0614`), the frozen identifier; `RECEIPT_OFFER_MISMATCH` is no longer presented as an alternative name.

**r2 reconciliation (2026-10-03) — verified no-op.** A1 published `deceipt-proto-r2` (offer_hash member-definition fix, A6 R2-01) and folded `protocol/flows/**` into the revision hash scope (A6 RX-02). A2 reconciled against r2 and found:

| Check | Result |
|---|---|
| `offer_hash`, `binding_tuple`, `binding_tuple_digest`, `binding_proof` (V1) vs r2 `handshake-valid.json` | **byte-identical** |
| `binding_proof_message` / `client_ephemeral_pubkey` | **identical** |
| transcript offsets (`binding_tuple_digest` 250, `max_frame_payload` 282, `binding_len` 284, `binding_tuple` 285) | **unchanged** |
| all 38 frozen rows vs their recorded SHA-256 | **0 mismatches** (includes all four `protocol/flows/**` files) |
| recomputed revision aggregate | **matches** r2's stated aggregate |

**Conclusion:** r2 changed no binding input, so **no A2 vector regeneration was required** — the r1 vectors are the r2 vectors. Because `protocol/flows/**` is now hash-pinned in `REVISION.json`, A2 makes **no** further edits to those four files under r2; any future change to them requires a new revision id (A0/A1). A1's option-a resolution of R4-01 (no QR layout change) means the QR map in §3.3 is unchanged, so the `pending r2` note there is resolved (no `transfer_id`/`receipt_id` added).
