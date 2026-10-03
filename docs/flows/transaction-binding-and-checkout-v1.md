# Deceipt PoC — Transaction Binding & Checkout Flow (v1)

**Owner:** A2 (transaction binding + checkout flow)
**Status:** v1 — **adopted verbatim by A1 into the frozen revision `deceipt-proto-r1`** (`docs/protocol/handshake.md` §10).
**Revision note:** binding vectors regenerated after A1's cross-check found the published `client_ephemeral_pubkey` was not a valid P-256 point (see §13). V1 now reconciles byte-for-byte with `protocol/vectors/handshake-valid.json`.
**Consumes:** `DESIGN.md` §2.5, §4.4–4.5, §6.3–6.4, §7.1–7.4, §8, §9, §11, §13.
**Feeds:** A1 (pass C/D — **closed**, see §11), A3 (checkout UI + state machine), A6 (adversarial review), A0 (freeze gate).

> **Labelling rule for this document.** Everything normative about *peer ambiguity* is `DESIGN.md` §7.3 and is restated here as an invariant. The **QR bootstrap remains a proposal** as a *product* flow; its **bytes** were adopted by A1 into `deceipt-proto-r1`. A1 or A0 may still replace the product flow; the byte-level binding contract below is frozen only insofar as A1 adopted it.
> Values marked **[FROZEN r1]** are byte-identical to A1's revision and must not change without a revision bump.

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
- **Eligible** — a candidate that additionally passes *only* non-radio, cryptographic/structural checks: correct service UUID, supported protocol version in the advertisement, and (in the primary flow) possession of the scanned session-binding token. Eligibility is **never** a function of signal strength.
- **Selected** — the single candidate the user explicitly chose (QR scan, or an item tap in the picker). Only a `selected` candidate may be connected to for receipt transfer.

**Normative constraints on any implementation (A3/A4/A5):**

- RSSI (and any radio-derived proximity, distance, or "closest"/"nearest" score) MUST NOT appear in the eligibility predicate, the selection decision, the connection target, the display order of the picker, or any trust decision.
- If RSSI is recorded at all it is diagnostics only, must be labelled as such in the UI, and must not be an input to `select()`.
- Display ordering of 2+ candidates MUST be a deterministic, non-radio tiebreak over the peripheral identifier bytes (e.g. ascending `peripheral_id`), so that ordering is stable and carries no proximity meaning.
- Ambiguity **fails closed**: two or more eligible candidates with no explicit user selection is an error state, never an automatic pick.

---

## 3. Primary flow (P1) — QR bootstrap over BLE delivery [PROPOSAL as product flow; bytes FROZEN r1]

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

With two phones and no pairing, nothing else gives the customer a *fresh, merchant-generated, unambiguous* pointer to exactly one transaction without radio inference. The QR is out-of-band, physical, and intentional: the user points a camera at one terminal. That is the explicit user act §7.3 requires, and it collapses "2+ eligible candidates" to a single named session.

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

**Rationale for using 16 random bytes directly as the HMAC-SHA-256 key** (flagged low-end by A1, §10 of the handshake spec):

- The SBT is **128 bits of CSPRNG entropy** (not password-derived, not user-chosen, not structured). HMAC-SHA-256 with an *n*-bit uniformly random key provides *n*-bit security; the effective security here is therefore **128 bits**, which is the PoC's target strength and is not attackable by brute force within the 300 s QR TTL.
- HMAC is not vulnerable to the SHA-256 length-extension issue, so a key shorter than the 64-byte block adds no structural weakness — it only caps security at the key entropy.
- The SBT is **single-use** (`BINDING_CONSUMED`), **short-lived** (`T_BINDING_QR`, §3.8), and compared in **constant time**. Reuse across sessions is forbidden by construction (fresh CSPRNG per checkout).
- The binding proof is **not** the receipt trust decision: even a full SBT compromise yields only session identification, never a trusted receipt (`DESIGN.md` §9 steps 10–11 still required).

**Recorded hardening path (NOT in r1 — requires a revision bump and A1 re-adoption):** for a future revision, derive the HMAC key with HKDF-SHA-256 from a 16-byte salt plus a longer secret, e.g. `k_binding = HKDF-SHA-256(ikm = SBT_32_random, salt = session_id, info = "deceipt-binding-key-v1")`, and use `k_binding` as the HMAC key. This raises the key to 256 bits at zero protocol risk. It is **not** applied to r1 because A1 adopted and froze the construction below; changing it would change every `binding_proof` byte and every vector.

### 3.5 Offer hash — exact bytes [FROZEN r1]

The QR must name the exact intended receipt before the receipt is transferred. `offer_hash` is a domain-separated SHA-256 over the *identity* fields of the checkout (not the receipt's full content):

```
offer_hash = SHA-256(
    "deceipt-offer-hash-v1" || 0x00 || cbor(
        [ bytes(16) session_id,
          bytes(16) transfer_id,
          bytes(16) receipt_id,
          tstr      merchant_reference,
          uint      total_amount_minor,
          uint      currency,                 -- ISO-4217 tstr, e.g. "CAD"
          uint      issued_at_unix ] )
)
```

- `merchant_reference` and `issued_at_unix` are the names used by A1's `RECEIPT_OFFER` (labels 4 and 7).
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
| Session lifetime | merchant | `T_SESSION = 120 s`; `T_ADVERTISE = 60 s` | Session, `SBT`, and `session_id` are destroyed; `ServerHello` is unavailable; client surfaces recoverable expiry (`SESSION_EXPIRED`). |
| Consumption | merchant | on first accepted `ClientHello` with valid `binding_proof` | Session marked **claimed**; a second `ClientHello` for the same `session_id` is rejected (`BINDING_CONSUMED`). |

**Stale binding** (QR expired, or session torn down before the client connected) → `BINDING_STALE`. Client offers the §4 fallback (manual selection), which re-establishes intent explicitly.

**Consumed binding** (proof already used once) → `BINDING_CONSUMED`. This is the anti-replay guard for the *binding*, independent of §6 AEAD replay handling and §4.5 receipt-ID dedup.

### 3.9 What the binding proves, and what it does NOT

| Property | Established by binding? |
|---|---|
| User intended this terminal/transaction | **Yes** — explicit QR scan (or picker tap). |
| This BLE session is the one named by the QR | **Yes** — `session_id` + `binding_proof`. |
| Possession of the QR/session secret | **Yes** — HMAC over `SBT`. |
| The receipt is authentic | **No.** Only the merchant signature over exact received bytes + key authorization (design §9 steps 10–11) does that. |
| Merchant identity | **No.** Session binding is strictly distinct from merchant-key trust. |
| Physical proximity of the merchant | **No** — and it is never inferred from RSSI. |

---

## 4. Fallback path (P0) — manual disambiguation, no QR [PROPOSAL]

When QR bootstrap is unavailable (peripheral did not render, token expired, camera denied) or when the merchant does not use a QR, the §7.3 rule runs directly:

```
scan -> candidates = peripherals advertising Deceipt Transfer Service UUID
       eligible   = candidates passing structural/version checks (NO RSSI)
       0 eligible -> keep scanning (show "no Deceipt terminal found")
       1 eligible -> may auto-connect (single unambiguous sender)
       2+ eligible -> DISAMBIGUATE: show explicit picker; connect only after a tap
```

In the picker, each row shows only non-sensitive, non-radio display metadata supplied by the advertisement/`RECEIPT_OFFER`. If the advertisement carries no merchant name (§7.2 forbids merchant name in advertisements), rows are labelled by a deterministic short label derived from the peripheral identifier, and the user is told to match it against the terminal. **Any tap is the explicit selection**; no row is highlighted, sorted, or auto-chosen by signal strength.

The fallback loses one property the QR has: the binding tuple's `session_id` is unknown before connecting, so the client cannot pre-filter by session. It must therefore connect, read the merchant's `RECEIPT_OFFER`, and *then* present `ACCEPT` only for the offer the user selected. Session binding in P0 is derived post-connect from the authenticated `transfer_id`/`receipt_id` in the offer, and the user's tap is the intent record. This is strictly weaker than P1 (no proof-of-possession), which is why P1 is the primary demo flow and P0 is the documented fallback.

---

## 5. Checkout state machine

Seven contract states. `DESIGN.md` §8.1 names the transfer-internal states (IDLE…DISCONNECT); this is the **checkout/UI** projection that A3 implements, mapped onto them.

```
ready
  │  user acts (scan QR | open picker)
  ▼
selecting ──(0 eligible)──▶ ready        (keep scanning)
  │  (1 eligible → may auto)  |  (2+ eligible → explicit tap required)
  │  explicit selection of exactly one candidate/transaction
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

- `selecting` is where the §7.3 rule lives. It is the **only** state permitted to change the selected candidate, and it requires an explicit user act.
- `transferring` never implies trust; the receipt is `RECEIPT_UNTRUSTED` until `verifying` completes (§8.1, §9).
- `verifying` is local-only work; no transport success can shortcut it.
- `saved` records the §5.3 verification outcome (trusted / unknown-key / rejected-by-policy). Dedup (§9 step 13) may turn a re-received receipt into `saved` **without** re-adding it.
- `recoverable_failure` always carries a typed reason and an explicit retry/fallback affordance; it never auto-retries into a different peer.

Transition guards (normative):

| Transition | Guard |
|---|---|
| `selecting → connecting` | exactly one candidate selected by explicit user act; 2+ eligible with no selection is unreachable |
| `connecting → transferring` | point decode ok AND binding check passed AND merchant credential+transcript signature verified (§9 steps 3–4) |
| `transferring → verifying` | full AEAD payload authenticated/decrypted (§9 step 7) |
| `verifying → saved` | **all** of §9 steps 10–15 pass; any failure goes to `recoverable_failure` |

---

## 6. User-visible behavior for the named situations

| Situation | State | User sees (no crypto internals) | Recovery |
|---|---|---|---|
| **Wrong terminal / wrong transaction** | `connecting → recoverable_failure` | "This isn't the transaction you selected." (`WRONG_TRANSACTION` / `RECEIPT_OFFER_MISMATCH`); no partial receipt is kept. | Rescan QR / reopen picker. |
| **Expired transaction** | `selecting` or `connecting → recoverable_failure` | "This checkout code has expired. Ask the merchant to show a new one." | Rescan a fresh QR; P0 fallback. |
| **Denied Bluetooth permission** | pre-`selecting` | "Deceipt needs Bluetooth to receive your receipt." Explanation + Settings deep-link. | Grant permission; retry. |
| **Denied camera permission** | pre-`selecting` | "Scanning needs camera access." Camera-free picker fallback offered. | Grant, or use picker. |
| **Cancellation (user)** | any → `recoverable_failure(USER_CANCELLED)` | Immediate; "Cancelled." No half-imported receipt retained. | Rescan / retry. |
| **Bluetooth disabled** | any → `recoverable_failure(TRANSPORT_BLUETOOTH_OFF)` | "Bluetooth is off." | Enable; retry. |
| **No eligible terminal** | `selecting → ready` | "No Deceipt terminal found nearby." Keeps scanning. | Wait / retry. |
| **Multiple terminals, none selected** | `selecting` | Picker with explicit tap; copy states selection is manual and never by signal strength. | User taps one. |

Rules: no state ever displays "verified" before §9 completes; a failure never shows a receipt as trusted; `recoverable_failure` never auto-targets a different peripheral.

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

**P1 (QR) happy path — protocol step count: 5 user-visible phases**

| # | Phase | Automatic? |
|---|---|---|
| 1 | Grant permissions (Bluetooth; camera) | once per install — **not** automatic |
| 2 | Scan QR | user act |
| 3 | Connect + handshake + binding check | automatic |
| 4 | Review offer (merchant + total) | user act (Accept) |
| 5 | Save + show verified | automatic |

Protocol actions between the user's scan and the accept: connect, `ClientHello`, point decode, binding verify, `ServerHello` + credential/signature verify, digest recompute, key derivation, `RECEIPT_OFFER`, binding compare — 9 protocol actions, 0 user taps.

**P0 (picker) happy path — 5 user-visible phases:** permissions; open picker; **tap one candidate** (extra explicit act that P1 folds into the scan); review offer/Accept; save.

**Failure paths add exactly one explicit recovery act** (rescan / retry / enable Bluetooth), never a silent auto-retry to a different peer.

These are minimum protocol steps; perceived taps are pending A4/A5 device runs and OS-prompt behaviour.

---

## 10. Acceptance walk: competing merchants, explicit selection, no RSSI

Scenario: 3 merchants A, B, C all advertising the Deceipt service UUID within radio range; customer intends only B.

**P1 walk:**
```
ready
 └─ user scans B's QR
selecting: candidates {A,B,C}; QR names session_id_B
           eligible = candidates matching session_id_B  -> {B}   (structural match, not RSSI)
           1 eligible -> may auto-connect; selected = B by the user's scan
connecting: ClientHello{session_id_B, cnonce, ceph, proof}
           A and C cannot answer:  they hold no session_id_B / SBT_B  -> BINDING_UNKNOWN_SESSION
           B validates ClientHello (ceph decodes), verifies proof -> ServerHello ->
           binding + credential + sig verified
transferring -> verifying -> saved
```
A and C are eliminated by **possession of B's session secret**, not by signal strength. If the user had scanned A's QR, B and C would equally fail.

**P0 walk (no QR):**
```
selecting: eligible = {A,B,C}; |eligible| >= 2
           -> DISAMBIGUATE. No auto-connect. No RSSI ranking.
           picker rows ordered by peripheral_id bytes (deterministic, no proximity)
           user taps B  -> selected = B
connecting -> ... -> saved
```
If the user taps nothing, the app stays in `selecting`; it never picks the strongest signal.

**Code-level check the reviewer can make:** every write to `selected` is reachable only from a user-act handler (`onQRScanned`, `onCandidateTapped`); the type of the eligibility predicate excludes RSSI/`rssi`/`txPower`/`distance`; picker sort key is `peripheral_id`. (Named in `protocol/flows/checkout-flow-v1.json` as `selection_invariants`.)

---

## 11. Handoff to A1 — CLOSED (adopted into `deceipt-proto-r1`)

A1 has **adopted** this contract verbatim (`docs/protocol/handshake.md` §10). The dependency is satisfied:

| Requirement | Status in `deceipt-proto-r1` |
|---|---|
| `binding_tuple_digest` required in the signed transcript | **Yes** — transcript offset 250; full `binding_tuple` at offset 285, len-prefixed at 284 |
| `ClientHello` carries `session_id`, `client_nonce`, `client_ephemeral_pubkey`, `binding_proof` | **Yes** — labels 4, 5, 6, 7 |
| `RECEIPT_OFFER` carries the offer-hash members | **Yes** — labels 2–7, 12 (`session_id`, `transfer_id`, `receipt_id`, `merchant_reference`, `total_amount_minor`, `currency`, `issued_at`, `session_id`) |
| Wire IDs for the three 16-byte identifiers | **Yes** — `bstr(16)`, pass D |
| Typed binding errors | **Yes** — `BINDING_*` codes `0x0312..0x0316`, `WRONG_TRANSACTION` `0x0614`, plus `HANDSHAKE_ECDH_INVALID_POINT` |
| 32-byte `client_nonce` | **Yes** (`handshake.md` §1) |

**Remaining A2→A1 items:** none open. The only change A1 made to A2's published bytes was procedural: A2's original `client_ephemeral_pubkey` values were not valid P-256 points; A1 used valid points, so A1's `binding_proof` differs from A2's *original* value. A2 has regenerated vectors to reconcile (§13).

---

## 12. Open items / provisional markers

| Item | Status |
|---|---|
| QR bootstrap as the PoC primary **product** flow | **PROPOSAL** — A1 adopted its bytes; product flow still A0-replaceable |
| `qr_format_version`, domain separators, `proof_message` layout | **FROZEN r1** (adopted by A1) |
| Transcript field placement of `binding_tuple_digest` | **FROZEN r1** — A1 pass C, offset 250 |
| Wire IDs for session/transfer/receipt | **FROZEN r1** — A1 pass D |
| HKDF-expanded SBT key | **Recorded hardening path**, not in r1 (§3.4) |
| Production disambiguation UX | §14 provisional, out of PoC scope |
| Perceived tap count on real devices | pending A4/A5 |

Machine-readable companion: `protocol/flows/checkout-flow-v1.json`.
Binding test vectors: `protocol/flows/vectors/binding-v1.json` (generator: `protocol/flows/tools/gen_binding_vectors.py`).
Flow overview: `protocol/flows/checkout-flow-v1.mmd` (diagram), `docs/flows/README.md` (index).

---

## 13. Vector defect fix record (post A1 cross-check)

A1's `protocol/vectors/binding-crosscheck.json` recorded a **high** finding: the `client_ephemeral_pubkey_hex` in A2's original V1/V2/V3 was **not a valid P-256 point**, so no ECDH was possible and the vectors could not be used as handshake vectors. A2's HMAC/offer/tuple/digest values were internally correct (HMAC treats the key material as opaque bytes).

**Fix applied (this revision):**

- Vectors regenerated by `protocol/flows/tools/gen_binding_vectors.py` using **valid, reproducible P-256 points** derived exactly as A1's reference does (`SHA-256("deceipt-testkey:p256:" || name || "#counter")` reduced mod `n`).
- **V1 now reconciles byte-for-byte with A1's frozen `handshake-valid.json`:** identical inputs, and identical `offer_hash`, `binding_tuple`, `binding_tuple_digest`, and `binding_proof`.
- V2 (same transaction, wrong SBT) and V3 (different transaction) use valid points; V3's outputs differ from V1.
- **V4 added as a negative vector:** a point with the final byte flipped, which fails `secp256r1` decode and MUST be rejected at `ClientHello` with `HANDSHAKE_ECDH_INVALID_POINT` before any binding check.
- Every non-negative vector's point is asserted to decode (`client_ephemeral_pubkey_valid_p256 == true`); V4's is asserted `false`.

**Regenerated values:**

| Vector | valid P-256 | `offer_hash` | `binding_tuple_digest` | `binding_proof` |
|---|---|---|---|---|
| V1 (== A1 r1) | yes | `efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5` | `d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2` | `fa19790fda7c85c1c745d4299c4177f9bcd15090de78961a38b7ebc36565083e` |
| V2 (wrong SBT) | yes | `efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5` (same) | `d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2` (same) | `49b9edb37943d3c4c3607e429a85118050b3a3f7c3f70fcaf6444ec4df81e4fc` |
| V3 (other txn) | yes | `043f3cde62ad673bc72cd828dd1f0bba2f66516e3bf4a504da344c1b8921dfac` | `e7b28cffce49a18686d8cf97a18566416724ea1d8ca78c2c788660ffdad1d14f` | `45aa8fcd46cee2030c95ddf443febcd2cf7445d24abb44daeb440da9f8be8edb` |
| V4 (bad point) | **no** | `efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5` (same) | `d9d3d7df72b1e4df615c68dabac1f8fb6eb24371efe9cde6bfda2985abde59e2` (same) | `17b28db865405a3328aef05d0409b2adce1d6ff0c37ad307073c7d4524d6aa02` (informational; rejected before use) |

All four vectors and their exact bytes live in `protocol/flows/vectors/binding-v1.json`, regenerated by `protocol/flows/tools/gen_binding_vectors.py`.
