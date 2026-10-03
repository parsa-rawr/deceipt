# Deceipt PoC — Transaction Binding & Checkout Flow (v1)

**Owner:** A2 (transaction binding + checkout flow)
**Status:** Draft v0.1 — **proposal for A1/A0 adoption or replacement.** Not a prior decision.
**Consumes:** `DESIGN.md` §2.5, §4.4–4.5, §6.3–6.4, §7.1–7.4, §8, §9, §11, §13.
**Feeds:** A1 (freeze pass C/D — handshake transcript binding + wire identifiers), A3 (checkout UI + state machine), A6 (adversarial review), A0 (freeze gate).

> **Labelling rule for this document.** Everything normative about *peer ambiguity* is `DESIGN.md` §7.3 and is restated here as an invariant. The **QR bootstrap is a proposal**, not a decision: A1 or A0 may adopt, replace, or reject it. Where a byte layout is proposed, it is marked **[PROPOSAL]** and is only binding once A1 adopts it into the frozen wire revision.

---

## 1. Scope

This document fixes four things:

1. **Which merchant/transaction the user intends** — an explicit, user-driven selection, with no code path that ranks, filters, or selects by RSSI.
2. **The exact bytes that bind a BLE transfer session to one intended receipt** — so A1 can bind the handshake transcript to them.
3. **The checkout state machine and its user-visible failure behavior** — the seven contract states and the five named failure situations.
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

## 3. Primary flow (P1) — QR bootstrap over BLE delivery [PROPOSAL]

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
        ◀──── ClientHello {cnonce, ceph, binding_proof} ──────  binding_proof = HMAC-SHA-256(SBT, ...)
 verify binding_proof (proves SBT possession,
 identifies session) -> else abort
        ─── ServerHello {session_id, transcript sig} ────────▶  verify merchant credential + sig
                                                              derive keys; binding check vs QR
        ───────────── ReceiptOffer {binding fields} ─────────▶  compare offer vs QR values
        ◀──────────── Accept ─────────────────────────────────  (user taps Accept)
        ───────────── TransferBegin + DATA frames ───────────▶  reassemble, AEAD decrypt
                                                              RECEIPT_UNTRUSTED
                                                              verify sig + authorization (§9)
        ◀──────────── ReceiptAck ─────────────────────────────  STORE (verified, policy)
        ───────────── disconnect ────────────────────────────▶  SAVED
```

The QR is a **selection and bootstrap channel only**. It carries no receipt, no amount shown as trusted, no line items, and no merchant credential. The synthetic receipt itself travels **only** over the GATT `DATA` characteristic, AEAD-encrypted for the session. The demo therefore *does* exercise BLE delivery; deleting the BLE leg breaks it.

### 3.2 Why a QR at all

With two phones and no pairing, nothing else gives the customer a *fresh, merchant-generated, unambiguous* pointer to exactly one transaction without radio inference. The QR is out-of-band, physical, and intentional: the user points a camera at one terminal. That is the explicit user act §7.3 requires, and it collapses "2+ eligible candidates" to a single named session.

### 3.3 QR content and exact bytes [PROPOSAL]

The QR payload is a CBOR map, prefixed with a version tag, base64url (unpadded).

```
qr_payload        = "deceipt1:" || base64url_nopad( qr_cbor )
qr_cbor           = CBOR map(5), definite-length, integer keys ascending
  1 : uint   = 1                                    -- qr_format_version
  2 : bytes(16) = session_id
  3 : bytes(16) = session_binding_token (SBT)       -- SECRET; see §3.4
  4 : bytes(32) = offer_hash                        -- see §3.5
  5 : uint64    = expires_at_unix                   -- seconds; see §3.8
```

Rules:

- The QR MUST NOT contain merchant name, amount, receipt id, line items, customer data, or any credential. (If the terminal screen separately displays the amount as text, that text is *display*, not protocol input.)
- `session_id` is random 16 bytes per checkout session; not derived from merchant identity.
- `expires_at_unix` is a QR-validity deadline set by the merchant.
- Implementations MUST reject `qr_format_version != 1` and MUST reject a payload whose declared lengths differ from the fixed sizes above.

**Vector (V1):**

```
qr raw bytes (80 B):
a50101025000112233445566778899aabbccddeeff0350000102030405060708090a0b0c0d0e0f045820b36d3c63ab963189e1335a4a6cfc00789672c62433748a370f7e06148c7743aa051a6955b978
payload (116 chars):
deceipt1:pQEBAlAAESIzRFVmd4iZqrvM3e7_A1AAAQIDBAUGBwgJCgsMDQ4PBFggs208Y6uWMYnhM1pKbPwAeJZyxiQzdIo3D34GFIx3Q6oFGmlVuXg
```

### 3.4 Session-binding token (SBT) [PROPOSAL]

`SBT` is 16 random bytes, generated by the merchant at checkout, unique per session. It is **not** a key and **not** a trust credential. Its only jobs:

1. **Identify the exact BLE session** — a client that presents a valid binding proof is answering *this* checkout, not another nearby one.
2. **Prove possession of the QR** — only a party that read the QR knows `SBT`.
3. **Bind the session's ephemeral ECDH key to the intended transaction** — the proof covers the client's ephemeral public key (§3.6), so a substituted key fails.

`SBT` is kept in merchant memory for the session only, and **never** is logged or committed. It is destroyed on consumption (§3.8) or expiry.

### 3.5 Offer hash — exact bytes [PROPOSAL]

The QR must name the exact intended receipt before the receipt is transferred. `offer_hash` is a domain-separated SHA-256 over the *identity* fields of the checkout (not the receipt's full content):

```
offer_hash = SHA-256(
    "deceipt-offer-hash-v1" || 0x00 || cbor(
        [ bytes(16) session_id,
          bytes(16) transfer_id,
          bytes(16) receipt_id,
          tstr      merchant_id,
          uint      total_amount_minor,
          tstr      currency,
          uint      issued_at_unix ] )
)
```

- `receipt_id` is the random, globally unique receipt identifier from §4.5 — created at checkout, before the QR renders.
- `total_amount_minor` is an integer + ISO-4217 `currency`; **no floating point** (§4.2).
- The domain separator and the `0x00` byte make this value unusable as any other Deceipt hash.
- **[A1 dependency]** `ReceiptOffer` (§8.3) must carry `session_id`, `transfer_id`, `receipt_id`, `merchant_id`, `total_amount_minor`, `currency`, `issued_at_unix`, and `offer_hash`. A1 may redefine `offer_hash` to be a hash over A1's canonical `ReceiptOffer` bytes; the *requirement* is (a) it is 32 bytes, (b) it is derived from the offer content, (c) the QR carries it before the BLE session exists.

**Vector (V1):**

```
offer_hash = b36d3c63ab963189e1335a4a6cfc00789672c62433748a370f7e06148c7743aa
```

### 3.6 Binding tuple — exact bytes to bind into the transcript [PROPOSAL]

This is the object A1 incorporates into the canonical handshake transcript.

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

Canonicalization: the array uses definite lengths and minimal integer encodings exactly as RFC 8949 §4.2 deterministic encoding requires. All three identifiers are fixed-length `bstr(16)`; `offer_hash` is fixed `bstr(32)`.

```
binding_tuple_digest = SHA-256("deceipt-binding-tuple-v1" || 0x00 || binding_tuple)
```

**A1 requirement (pass C):** the merchant-signed canonical handshake transcript MUST include `binding_tuple_digest` (32 bytes) as a **required, length-framed field**, so that:

- the merchant's ServerHello signature covers the transaction binding, and therefore
- the derived session keys (transcript-hash-bound per §6.4) are bound to *this* transaction.

A1 owns the exact transcript layout; A2 only requires that this 32-byte value is in it and cannot be omitted or truncated.

**Vector (V1):**

```
binding_tuple    (87 B):
85015000112233445566778899aabbccddeeff50ffeeddccbbaa99887766554433221100500123456789abcdef0123456789abcdef5820b36d3c63ab963189e1335a4a6cfc00789672c62433748a370f7e06148c7743aa
binding_tuple_digest:
11f63f30af68580b95ffa4b456dd0f89ced8204ba144e105812b61d2fe2259be
```

### 3.7 Binding proof in ClientHello — exact bytes [PROPOSAL]

The client proves it possesses `SBT` and binds the proof to its own ephemeral ECDH key:

```
proof_message = "deceipt-binding-proof-v1" || 0x00
                || client_nonce(32)              -- the ClientHello nonce (§6.3)
                || client_ephemeral_pubkey(65)   -- P-256 uncompressed: 0x04 || X || Y

binding_proof = HMAC-SHA-256(key = SBT, msg = proof_message)   -- 32 bytes
```

`proof_message` is exactly **122 bytes** for P-256.

The `ClientHello` (§8.2, §6.3) therefore gains **[PROPOSAL]**:

```
ClientHello {
  protocol_version
  crypto_suites[]
  session_id            (bstr 16)
  client_nonce          (bstr 32)
  client_ephemeral_pubkey (bstr 65)
  binding_proof         (bstr 32)
}
```

Merchant-side check, before doing any session work:

```
1. session_id resolves to a live, unconsumed, unexpired session  -> else BINDING_UNKNOWN_SESSION
2. constant-time compare HMAC-SHA-256(SBT, proof_message) == binding_proof
                                                                  -> else BINDING_PROOF_INVALID
3. mark session "claimed by client_nonce/client_ephemeral_pubkey"
```

Because `proof_message` covers `client_ephemeral_pubkey`, a man-in-the-middle that substitutes the client's ECDH key cannot produce a valid proof: it would have to know `SBT`, and if it did, the client's own proof would no longer match the key the merchant derives against. **Binding is not trust**: passing this check says only "this session, this ephemeral key" — never "this merchant is authentic".

**Vector (V1) — test-only deterministic SBT (`000102…0f`):**

```
proof_message (122 B):
646563656970742d62696e64696e672d70726f6f662d763100  <- "deceipt-binding-proof-v1" || 0x00
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f  <- client_nonce
04070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc  <- client_ephemeral_pubkey(65)

binding_proof = 06ceaa6595ade4ec34e74f44a7b8a85e82f69a71959a125118b23bc7de337547
```

### 3.8 Expiration and consumption

Two independent clocks, both fail-closed:

| Clock | Owner | Value | Effect |
|---|---|---|---|
| QR validity | merchant | `expires_at_unix` in QR (§3.3) | Client refuses to start a session from an expired QR. |
| Session lifetime | merchant | server-side deadline (proposed 120 s from `ADVERTISING` start) | Session, `SBT`, and `session_id` are destroyed; `ServerHello` is unavailable; client surfaces recoverable expiry. |
| Consumption | merchant | on first accepted `ClientHello` with valid `binding_proof` | Session marked **claimed**; a second `ClientHello` for the same `session_id` is rejected. |

**Stale binding** (QR expired, or session torn down before the client connected) → `BINDING_STALE`. Client offers the §5 fallback (manual selection), which re-establishes intent explicitly.

**Consumed binding** (proof already used once) → `BINDING_CONSUMED`. This is the anti-replay guard for the *binding*, independent of §6 replay handling and §4.5 receipt-ID dedup.

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

In the picker, each row shows only non-sensitive, non-radio display metadata supplied by the advertisement/§8.3 offer. If the advertisement carries no merchant name (§7.2 forbids merchant name in advertisements), rows are labelled by a deterministic short label derived from the peripheral identifier, and the user is told to match it against the terminal. **Any tap is the explicit selection**; no row is highlighted, sorted, or auto-chosen by signal strength.

The fallback loses one property the QR has: the binding tuple's `session_id` is unknown before connecting, so the client cannot pre-filter by session. It must therefore connect, read the merchant's `ReceiptOffer`, and *then* present `Accept` only for the offer the user selected. Session binding in P0 is derived post-connect from `transfer_id`/`receipt_id` in the authenticated offer, and the user's tap is the intent record. This is strictly weaker than P1 (no proof-of-possession), which is why P1 is the primary demo flow and P0 is the documented fallback.

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
  │  ClientHello/ServerHello, binding check, credential+signature check
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
| `connecting → transferring` | binding check passed AND merchant credential+transcript signature verified (§9 steps 3–4) |
| `transferring → verifying` | full AEAD payload authenticated/decrypted (§9 step 7) |
| `verifying → saved` | **all** of §9 steps 10–15 pass; any failure goes to `recoverable_failure` |

---

## 6. User-visible behavior for the named situations

| Situation | State | User sees (no crypto internals) | Recovery |
|---|---|---|---|
| **Wrong terminal / wrong transaction** | `connecting → recoverable_failure` | "This isn't the transaction you selected." Offer shown vs selected transaction mismatch is reported plainly; no partial receipt is kept. | Rescan QR / reopen picker. |
| **Expired transaction** | `selecting` or `connecting → recoverable_failure` | "This checkout code has expired. Ask the merchant to show a new one." | Rescan a fresh QR; P0 fallback available. |
| **Denied Bluetooth permission** | pre-`selecting` | "Deceipt needs Bluetooth to receive your receipt." Explanation + Settings deep-link. | Grant permission; retry. |
| **Denied camera permission** | pre-`selecting` | "Scanning needs camera access." Camera-free picker fallback offered. | Grant, or use picker. |
| **Cancellation (user)** | any → `recoverable_failure(USER_CANCELLED)` | Immediate; "Cancelled." No half-imported receipt retained. | Rescan / retry. |
| **Bluetooth disabled** | any → `recoverable_failure(BLUETOOTH_OFF)` | "Bluetooth is off." | Enable; retry. |
| **No eligible terminal** | `selecting → ready` | "No Deceipt terminal found nearby." Keeps scanning. | Wait / retry. |
| **Multiple terminals, none selected** | `selecting` | Picker with explicit tap; copy states selection is manual and never by signal strength. | User taps one. |

Rules: no state ever displays "verified" before §9 completes; a failure never shows a receipt as trusted; `recoverable_failure` never auto-targets a different peripheral.

---

## 7. Merchant demo flow (synthetic receipt)

1. Merchant app enters **Merchant mode** (dev/test build); a test trust anchor and test merchant key are provisioned per A1 pass B. UI states plainly this is a PoC test merchant.
2. Merchant creates a **synthetic** `DeceiptReceiptV1` (no POS): fixed line items, integer minor units, a random `receipt_id`.
3. Merchant computes `transfer_id`, `offer_hash` (§3.5), mints `session_id` + `SBT`, and renders the QR at "the terminal".
4. Merchant taps **Send**: creates the ephemeral session, starts the Deceipt GATT service, advertises the fixed service UUID only (§7.2 — no name/amount/receipt in the advertisement).
5. Customer scans; merchant verifies `binding_proof`; merchant signs the transcript; offers; on `Accept` streams `DATA` frames; signs nothing new (receipt was signed at step 2 over exact bytes).
6. On `ReceiptAck`, merchant tears down the session and destroys `SBT`.

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

Protocol actions between the user's scan and the accept: connect, `ClientHello`, binding verify, `ServerHello` + credential/signature verify, key derivation, `ReceiptOffer`, binding compare — 7 protocol actions, 0 user taps.

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
           B verifies proof -> ServerHello -> binding + credential + sig verified
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

## 11. Handoff to A1

**A1 dependency, stated plainly:** A1's frozen revision (pass C, pass D) MUST:

1. Include `binding_tuple_digest` (32 bytes) as a required field of the canonical handshake transcript, covered by the merchant's ServerHello signature.
2. Include `session_id`, `client_nonce`, `client_ephemeral_pubkey`, and `binding_proof` in the `ClientHello` schema, and define the merchant's binding-verification failure (proposed code `BINDING_PROOF_INVALID`).
3. Define `ReceiptOffer` to carry the §3.5 fields.
4. Define the wire identifiers for `session_id`/`transfer_id`/`receipt_id` (fixed 16-byte, A1's pass D may assign meaning).
5. Provide typed errors (open item 12) that include at least: `BINDING_UNKNOWN_SESSION`, `BINDING_PROOF_INVALID`, `BINDING_STALE`, `BINDING_CONSUMED`, `WRONG_TRANSACTION`.
6. Publish test vectors for the transcript containing the binding digest, so A6 can build conformance expectations from frozen vectors only.

If A1 replaces the QR proposal, the replacement must still satisfy §2 (no RSSI), §2.4 (session binding ≠ key trust), and provide a 32-byte session-binding value bindable into the transcript.

---

## 12. Open items / provisional markers

| Item | Status |
|---|---|
| QR bootstrap as the PoC primary flow | **PROPOSAL** — A1/A0 adopt or replace |
| `qr_format_version`, domain separators, `proof_message` layout | **PROPOSAL** — A2, pending A1 pass C |
| Transcript field placement of `binding_tuple_digest` | **A1** (pass C) |
| Wire IDs for session/transfer/receipt | **A1** (pass D) |
| Typed error taxonomy | **A1** (open item 12) |
| Production disambiguation UX | §14 provisional, out of PoC scope |
| Perceived tap count on real devices | pending A4/A5 |

Machine-readable companion: `protocol/flows/checkout-flow-v1.json`.
Binding test vectors: `protocol/flows/vectors/binding-v1.json`.
Flow overview: `protocol/flows/checkout-flow-v1.mmd` (diagram), `docs/flows/README.md` (index).
