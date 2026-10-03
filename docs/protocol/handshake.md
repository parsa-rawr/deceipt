# Handshake — Pass C (byte-for-byte)

**Revision:** `deceipt-proto-r1` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A4/A5 (native handshake, framing), A3 (session types, state machine), A6 (crypto review)
**Vectors:** `protocol/vectors/handshake-valid.json`, `handshake-invalid.json`, `aead-valid.json`, `aead-invalid.json`, `binding-crosscheck.json`

Closes `DESIGN.md` §15.C and executes §6.4's "Do not improvise these details during implementation" — every item in that list is fixed below, with vectors, and A4/A5 MUST NOT choose alternatives.

---

## 1. Suite: `Deceipt-Session-Suite-1` (id `1`)

| Primitive | Choice | Source |
|---|---|---|
| Key agreement | ephemeral **P-256** ECDH (`secp256r1`), uncompressed points `0x04‖X‖Y` | §6.2 |
| KDF | **HKDF-SHA-256** (RFC 5869) | §6.2 |
| AEAD | **AES-256-GCM** (96-bit nonce, 128-bit tag) | §6.2 |
| Transcript hash | **SHA-256** | §6.2 |
| Merchant authentication | Ed25519 (EdDSA, COSE alg `-8`) over the transcript | §6.3 |

Suite replacement is by `suite_id`; `protocol_version` and `suite_id` are both authenticated inside the transcript, so downgrade attempts change the signed bytes.

**Nonce length.** v1 uses **32-byte nonces** (`client_nonce`, `server_nonce`) for both platforms, matching the transaction-binding contract published by A2 (`docs/flows/transaction-binding-and-checkout-v1.md` §3.2/§3.7). 32 bytes leaves the door open to a future XOF-derived nonce without a transcript re-layout.

## 2. Message sequence

```text
B -> A  CLIENT_HELLO   (plaintext control envelope)
A -> B  SERVER_HELLO   (plaintext control envelope)
        [A: derive keys, sign transcript]
        [B: verify credential -> verify transcript signature -> derive keys]
        [B: compare binding digests]
B -> A  ACCEPT         (AEAD control envelope)
A -> B  RECEIPT_OFFER  (AEAD)
A -> B  TRANSFER_BEGIN + DATA frames (AEAD payload + notifications)
B -> A  ACK ...        (AEAD)
B -> A  RECEIPT_ACK    (AEAD)
        DISCONNECT
```

`CLIENT_HELLO` and `SERVER_HELLO` travel in the plaintext envelope (`tag 0x00`). `ERROR` may also be plaintext **only while no session keys exist** (pre-key handshake failure reporting). Every other control message, and `ERROR` once keys exist, MUST use the AEAD envelope; a plaintext control message where AEAD is required is `MESSAGE_WRONG_STATE` (fatal).

## 3. Canonical transcript (exact bytes)

**`TRANSCRIPT_LEN = 372`.** Concatenation, no separators, big-endian integers. `client_hello`/`server_hello` messages are **not** themselves in the transcript; their authenticated fields are, individually, in this fixed order:

| Offset | Field | Bytes | Value / rule |
|---:|---|---:|---|
| 0 | `label` | 20 | ASCII `"deceipt-handshake-v1"` (domain separation) |
| 20 | `protocol_version` | 2 | u16 BE, `1` |
| 22 | `suite_id` | 2 | u16 BE, `1` |
| 24 | `client_nonce` | 32 | from `ClientHello` |
| 56 | `client_ephemeral_pubkey` | 65 | P-256 uncompressed `0x04‖X‖Y` |
| 121 | `server_nonce` | 32 | from `ServerHello` |
| 153 | `server_ephemeral_pubkey` | 65 | P-256 uncompressed |
| 218 | `transfer_id` | 16 | A2 binding-tuple member |
| 234 | `session_id` | 16 | A2 binding-tuple member |
| 250 | `binding_tuple_digest` | 32 | `SHA-256("deceipt-binding-tuple-v1" ‖ 0x00 ‖ binding_tuple)` (A2) |
| 282 | `max_frame_payload` | 2 | u16 BE, negotiated frame size (≤ 512) |
| 284 | `binding_len` | 1 | `0..128` |
| 285 | `binding_tuple` | var | the exact A2 `binding_tuple` bytes (`binding_len` bytes) |

```text
transcript      = label ‖ u16(protocol_version) ‖ u16(suite_id)
                ‖ client_nonce ‖ client_eph_pub
                ‖ server_nonce ‖ server_eph_pub
                ‖ transfer_id ‖ session_id ‖ binding_tuple_digest
                ‖ u16(max_frame_payload) ‖ u8(len(binding_tuple)) ‖ binding_tuple
transcript_hash = SHA-256(transcript)                                  # 32 bytes
signature       = Ed25519_sign(merchant_device_private_key, transcript)  # 64 bytes
```

`max_frame_payload` and `binding_tuple` are *in* the transcript precisely so neither can be renegotiated after the merchant signs: changing either breaks `signature` (vectors `max_frame_payload_substituted`, `binding_tuple_digest_substituted`).

### 3.1 Vector values (must reproduce)

Fixture `protocol/vectors/handshake-valid.json`:

| Quantity | Value |
|---|---|
| transcript (372 B) | see `transcript_hex` |
| `transcript_hash` | `0f7ec36321515c01b7c1cb2e6cf61c7bbbc8b067162eb945c4e9b6ddfc624c3b` |
| `transcript_signature` | `a80f32f51c02240c975b5d1144fbd6a7c98c630d70153ad43b2dfa5f6f5385bd8198379f4475f9d8757752f75a578dc0808d36aef02e7de1467f78a6d0e00f0f` |

## 4. Messages on the wire

Both hello messages are CBOR maps with integer labels, in the plaintext envelope: `0x00 ‖ CBOR(map)`. Bounds: message ≤ 2048 bytes (`MAX_CONTROL_PDU`).

### 4.1 `CLIENT_HELLO` (type `0x01`, direction B→A)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `type` | uint | ✔ | `1` |
| 2 | `protocol_version` | uint | ✔ | `1`; else `HANDSHAKE_UNSUPPORTED_VERSION` |
| 3 | `crypto_suites` | array of uint | ✔ | non-empty; must intersect `{1}` else `HANDSHAKE_NO_COMMON_SUITE` |
| 4 | `session_id` | bstr(16) | ✔ | from the scanned QR (A2 §3.3) |
| 5 | `client_nonce` | bstr(32) | ✔ | fresh CSPRNG per attempt |
| 6 | `client_ephemeral_pubkey` | bstr(65) | ✔ | uncompressed P-256; must decode, else `HANDSHAKE_ECDH_INVALID_POINT` |
| 7 | `binding_proof` | bstr(32) | ✔ | A2 §3.7; else `BINDING_PROOF_INVALID` |
| 8 | `max_frame_payload` | uint | ✔ | `16..512`; else `FRAME_SIZE_INVALID` |

`a8 01 01 02 01 03 81 01 04 50 … 05 58 20 … 06 58 41 … 07 58 20 … 08 18 a2`
→ full bytes in `handshake-valid.json#client_hello_hex` (167 bytes; 168 with the plaintext envelope tag).

### 4.2 `SERVER_HELLO` (type `0x11`, direction A→B)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `type` | uint | ✔ | `17` |
| 2 | `protocol_version` | uint | ✔ | `1` |
| 3 | `suite_id` | uint | ✔ | MUST be a suite the client offered, else `HANDSHAKE_SUITE_MISMATCH` |
| 4 | `transfer_id` | bstr(16) | ✔ | MUST equal the binding tuple's `transfer_id`, else `TRANSFER_ID_MISMATCH` |
| 5 | `server_nonce` | bstr(32) | ✔ | fresh CSPRNG |
| 6 | `server_ephemeral_pubkey` | bstr(65) | ✔ | uncompressed P-256 |
| 7 | `merchant_credential` | bstr | ✔ | exact credential bytes, ≤ 1024 |
| 8 | `transcript_signature` | bstr(64) | ✔ | Ed25519 over §3 |
| 9 | `binding_tuple_digest` | bstr(32) | ✔ | receiver MUST recompute and compare, else `HANDSHAKE_TRANSCRIPT_MISMATCH` |

### 4.3 `ACCEPT` (type `0x02`, B→A, AEAD)

`{1: 2, 2: transfer_id, 3: protocol_version, 4: suite_id}`.

### 4.4 `RECEIPT_OFFER` (type `0x12`, A→B, AEAD)

| Label | Name | Type | REQ | Notes |
|---|---|---|---|---|
| 1 | `type` | uint | ✔ | `18` |
| 2 | `transfer_id` | bstr(16) | ✔ | |
| 3 | `receipt_id` | bstr(16) | ✔ | A2 offer-hash member |
| 4 | `merchant_reference` | tstr | ✔ | A2 offer-hash member |
| 5 | `total_amount_minor` | uint | ✔ | A2 offer-hash member; **integer minor units** |
| 6 | `currency` | tstr | ✔ | A2 offer-hash member |
| 7 | `issued_at` | uint | ✔ | A2 offer-hash member |
| 8 | `kind` | uint | ✔ | 1/2/3 |
| 9 | `ciphertext_length` | uint | ✔ | AEAD payload length, ≤ 65552 |
| 10 | `merchant_id` | bstr(16) | ✔ | |
| 11 | `credential_hash` | bstr(32) | ✔ | `SHA-256(credential bytes)` |
| 12 | `session_id` | bstr(16) | ✔ | |

All `RECEIPT_OFFER` fields are **untrusted display data until the receipt verifies** (`DESIGN.md` §8.3). Labels 3,4,5,6,7,10 are exactly the A2 `offer_hash` members; the receiver MUST recompute the offer hash from them and compare to the QR value and to the receipt (Pass D / A2 §3.5).

## 5. Key schedule (finalized §6.4)

```text
shared_secret   = ECDH(local_ephemeral_private, peer_ephemeral_public)    # 32-byte X coord
transcript_hash = SHA-256(transcript)                                     # 32 bytes

prk = HKDF-Extract(salt = transcript_hash, ikm = shared_secret)           # 32 bytes
info = "deceipt-transfer-v1" ‖ transcript_hash                            # 50 bytes
okm  = HKDF-Expand(prk, info, 128)                                        # 128 bytes

k_c2m_ctrl     = okm[ 0:32]   # customer -> merchant, control envelopes
k_m2c_ctrl     = okm[32:64]   # merchant -> customer, control envelopes
k_m2c_payload  = okm[64:96]   # merchant -> customer, receipt payload AEAD
k_exporter     = okm[96:128]  # reserved; not used in v1 (no exported-key consumers)
```

Notes:

* `salt = transcript_hash` (not a constant) so the keys are bound to this exact handshake; `info` repeats `transcript_hash` per §6.4's formula (`info = "deceipt-transfer-v1" ‖ transcript_hash`).
* Directional keys are **separate** for each direction and each usage class → no key/nonce reuse across directions, which is what makes the shared 12-byte nonce space safe (§6).
* Session context (never a key, used in AAD):

```text
session_context = transcript_hash ‖ transfer_id        # 48 bytes
```

### 5.1 Vector values (must reproduce)

| Quantity | Value |
|---|---|
| `shared_secret` | `2ff243b1e3ce612584e76f1fc3d082c4becd549b252e37095f9cb0991162a9fb` |
| `prk` | `0db91575fd7a5195963332163fd39b6ec783f18ba7fb6173a7d762eb59ecfd4e` |
| `okm` | `720f5d7081470c3cfc37f7762a7f0b33a01f101ba0f9cdebe0ff7a22171ba3fbe9d18ae4d55eb7cd262331bfa597ac7372f89cbb2f7e7e8e6aa2e58f8a9ab8f6b9e43f0e2f2b6e36d455511b453cd1bf7ba67281506ac1f29b584e270a8178b22d0f5e4e29d188d6500497cbeee746d0cc6b8623c940b6d4602d260b90d4a061` |
| `k_c2m_ctrl` | `720f5d7081470c3cfc37f7762a7f0b33a01f101ba0f9cdebe0ff7a22171ba3fb` |
| `k_m2c_ctrl` | `e9d18ae4d55eb7cd262331bfa597ac7372f89cbb2f7e7e8e6aa2e58f8a9ab8f6` |
| `k_m2c_payload` | `b9e43f0e2f2b6e36d455511b453cd1bf7ba67281506ac1f29b584e270a8178b2` |
| `k_exporter` | `2d0f5e4e29d188d6500497cbeee746d0cc6b8623c940b6d4602d260b90d4a061` |
| `session_context` | `0f7ec36321515c01b7c1cb2e6cf61c7bbbc8b067162eb945c4e9b6ddfc624c3bffeeddccbbaa99887766554433221100` |

## 6. AEAD: nonces, AAD, replay window (finalized §6.4)

### 6.1 Nonce construction

```text
nonce = 00000000 ‖ u64_be(counter)      # 12 bytes: 4 reserved zero bytes + 64-bit counter
```

The 4 leading zero bytes are reserved and MUST be zero. Each direction has its own key, so the counter is per-key and starts at `0`. Counter exhaustion (reaching `2^64`) is `AEAD_NONCE_EXHAUSTED`; it cannot occur in a session bounded by `max_frames` and `max_control_messages`.

### 6.2 AAD

| Usage | Key | AAD |
|---|---|---|
| Receipt payload seal/open | `k_m2c_payload` | `session_context ‖ 0x01` |
| Control envelope, B→A | `k_c2m_ctrl` | `session_context ‖ 0x02 ‖ 0x00` |
| Control envelope, A→B | `k_m2c_ctrl` | `session_context ‖ 0x02 ‖ 0x01` |

Binding `transfer_id` (inside `session_context`) into the AAD is what makes a frame or envelope from another session fail even with a stolen key (vector `payload_aad_mismatch` → `AEAD_AUTH_FAILED`).

### 6.3 Control envelope

```text
AEAD envelope    = 0x01 ‖ u64_be(counter) ‖ AES-256-GCM(key, nonce(counter), aad, cbor(message))
plaintext envelope = 0x00 ‖ CBOR(message)          # ClientHello / ServerHello only
```

Receiver rule on the counter: `counter < expected` ⇒ `AEAD_REPLAY_DETECTED`; `counter > expected` ⇒ `AEAD_COUNTER_MISMATCH`; then the tag is checked and a tag failure is `AEAD_AUTH_FAILED`. Because the expected counter is checked **before** decryption, counter-level replays are rejected without spending AEAD work.

### 6.4 Replay window and counters

* Control: strict in-order, `expected_counter` starts at 0 for each direction's key; no gaps, no repeats.
* Payload frames: sliding window of `WINDOW_FRAMES = 64`; `highest_contiguous_sequence` is the resume point (Pass D / `framing.md`).
* Session-level: a `session_id` may be claimed once (`BINDING_CONSUMED`); a `client_nonce` may not repeat within a session (`HANDSHAKE_NONCE_REPLAYED`); the receiver retains the last `MAX_SESSION_ID_HISTORY = 32` `session_id`s to answer replay.

## 7. Message size limits and timeouts (finalized §6.4)

| Limit | Value | Error |
|---|---|---|
| Reassembled control PDU | 2048 bytes | `LPDU_MESSAGE_TOO_LARGE` |
| Plaintext/control CBOR message | 2048 bytes | `MESSAGE_TOO_LARGE` |
| Control fragments per message | 512 | `LPDU_MESSAGE_TOO_LARGE` |
| ATT payload (any characteristic) | 512 bytes | `TRANSPORT_MTU_TOO_SMALL` if the negotiated payload cannot carry the minimum frame |
| DataFrame payload | 16..512 bytes | `FRAME_SIZE_INVALID` |
| Transfer ciphertext | 65552 bytes | `TRANSFER_SIZE_EXCEEDED` |
| Frames per transfer | 32768 | `TRANSFER_SIZE_EXCEEDED` |
| Control messages per direction | 4096 | `MESSAGE_TOO_LARGE` |

| Timeout | Value | On expiry |
|---|---|---|
| `T_ADVERTISE` | 60 s | stop advertising, `SESSION_EXPIRED` |
| `T_CONNECT` | 15 s | `TRANSPORT_CONNECT_TIMEOUT` |
| `T_HELLO_RESPONSE` | 5 s | `HANDSHAKE_TIMEOUT` |
| `T_ACCEPT` | 10 s | `HANDSHAKE_TIMEOUT` |
| `T_CONTROL_FRAG` | 5 s | `LPDU_REASSEMBLY_TIMEOUT` (retryable) |
| `T_ACK_WAIT` | 3 s | retransmit; after `MAX_FRAME_RETRIES` ⇒ `TRANSFER_RETRY_EXHAUSTED` |
| `T_ACK_INTERVAL` | 500 ms | receiver emits `ACK` if ≥1 new contiguous frame and none pending |
| `T_TRANSFER_IDLE` | 10 s | `TRANSFER_TIMEOUT` |
| `T_VERIFY_BUDGET` | 5 s | `VERIFY_BUDGET_EXCEEDED` |
| `T_SESSION` | 120 s | `SESSION_EXPIRED` |
| `T_CLOSE` | 2 s | force disconnect |
| `T_BINDING_QR` | 300 s | `BINDING_STALE` |

## 8. Per-state failure transitions

No failure transition reaches a verified receipt (`DESIGN.md` §9).

| State | Event | Transition | Typed error |
|---|---|---|---|
| `CONNECTED` | ClientHello parse/validate fails | `ABORT` | `CBOR_*`, `MESSAGE_*`, `HANDSHAKE_UNSUPPORTED_VERSION`, `HANDSHAKE_NO_COMMON_SUITE` |
| `HANDSHAKE` | binding check fails | `ABORT` | `BINDING_UNKNOWN_SESSION`, `BINDING_PROOF_INVALID`, `BINDING_REQUIRED`, `BINDING_STALE`, `BINDING_CONSUMED` |
| `HANDSHAKE` | credential issuer unknown | continue, mark unknown | `CREDENTIAL_UNKNOWN_ISSUER` (non-fatal) |
| `HANDSHAKE` | credential invalid/expired | `ABORT` | `CREDENTIAL_MALFORMED`, `CREDENTIAL_SIGNATURE_INVALID`, `CREDENTIAL_NOT_YET_VALID`, `CREDENTIAL_EXPIRED`, `CREDENTIAL_CAPABILITY_MISSING` |
| `HANDSHAKE` | transcript signature/digest mismatch | `ABORT` | `HANDSHAKE_SIGNATURE_INVALID`, `HANDSHAKE_TRANSCRIPT_MISMATCH`, `HANDSHAKE_SUITE_MISMATCH`, `TRANSFER_ID_MISMATCH` |
| `MERCHANT_SESSION_AUTHENTICATED` | offer rejected by user | `DISCONNECT` | `USER_CANCELLED` |
| `TRANSFER` | AEAD/control/framing failure | `ABORT` | `AEAD_*`, `FRAME_*`, `LPDU_*`, `TRANSFER_*` |
| `TRANSFER` | link lost / Bluetooth off | `ABORT`, no store | `TRANSPORT_LINK_LOST`, `TRANSPORT_BLUETOOTH_OFF` |
| `RECEIPT_UNTRUSTED` | any §9 step 8–14 fails | `REJECT + AUDIT` | `RECEIPT_*` |
| any | session timeout | `ABORT` | `SESSION_EXPIRED`, `HANDSHAKE_TIMEOUT`, `TRANSFER_TIMEOUT` |

**Teardown.** On `ABORT`/`DISCONNECT`/timeout the endpoint: stops advertising (merchant), zeroizes `shared_secret`, `prk`, `okm` and all directional keys and the SBT, clears frame buffers, and drops the session record. Zeroization is best-effort in a managed runtime (RN/native) and MUST NOT be claimed as guaranteed by the UI; native adapters MUST overwrite key byte buffers where the platform allows.

## 9. Encrypted-only vs authenticated-peer sessions

The type system MUST distinguish these, and the receipt path MUST require the authenticated one (`DESIGN.md` §6.3: "the handshake signature does not replace receipt signature verification"):

```text
SessionKeysOnly        # keys derived, peer NOT authenticated -> may be used only for
                       # diagnostics / error handling, NEVER to transfer or accept a receipt
SessionAuthenticated   # credential verified to a pinned anchor AND transcript signature
                       # verified -> the only session type the transfer path accepts
```

A receiver that derives keys but has not verified `ServerHello`'s signature holds `SessionKeysOnly`. `ACCEPT` MUST NOT be sent from it. This is a compile-time distinction in A3's shared types (two nominal types, no common base that the transfer path accepts) and a runtime guard in A4/A5. A `SessionAuthenticated` value carries the verified `merchant_id`, `device_key_id`, and the exact credential bytes.

## 10. A2 transaction-binding adoption (dependency closure)

A1 **adopts** `docs/flows/transaction-binding-and-checkout-v1.md` v1 with the deviations below. The binding bytes are reproduced verbatim from A2 and cross-checked in `protocol/vectors/binding-crosscheck.json`.

| A2 item | A1 adoption |
|---|---|
| `binding_tuple` = CBOR `[1, session_id(16), transfer_id(16), receipt_id(16), offer_hash(32)]`, 87 B | adopted verbatim |
| `binding_tuple_digest` = `SHA-256("deceipt-binding-tuple-v1" ‖ 0x00 ‖ tuple)` | adopted verbatim; required transcript field at offset 250 |
| `offer_hash` = `SHA-256("deceipt-offer-hash-v1" ‖ 0x00 ‖ CBOR([session_id, transfer_id, receipt_id, merchant_reference, total_amount_minor, currency, issued_at_unix]))` | adopted verbatim (A2's option "(b) hash over offer content"); it is recomputed from the `RECEIPT_OFFER` fields, so the offer and the QR cannot disagree |
| `binding_proof` = `HMAC-SHA-256(SBT, "deceipt-binding-proof-v1" ‖ 0x00 ‖ client_nonce ‖ client_ephemeral_pubkey)` | adopted verbatim, in `CLIENT_HELLO.binding_proof` |
| 32-byte `client_nonce` | adopted (see §1) |
| typed errors `BINDING_*`, `WRONG_TRANSACTION` | adopted; codes `0x0312..0x0316`, `0x0614` in `errors.json` |
| QR `deceipt1:` payload | adopted; consumed by A2/A3, out of A1 scope |

### 10.1 Defect found in the published A2 vectors (A2 must regenerate)

`protocol/vectors/binding-crosscheck.json` records that A2's `client_ephemeral_pubkey_hex` in vectors V1, V2 and V3 is **not a valid P-256 point** (standard EC point decoding fails, so no ECDH is possible). The HMAC values in those vectors are still correct because HMAC treats the key bytes as opaque, but the vectors cannot be used as handshake vectors.

Consequently A1's `handshake-valid.json#binding_proof_hex = fa19790f…` is computed over a **valid** client point and therefore differs from A2's V1 `binding_proof` value; the QR/offer/tuple/digest values remain byte-identical. A2 action: regenerate V1–V3 `client_ephemeral_pubkey_hex` with a decodable point, or mark those three vectors "binding-hash only, not handshake".

## 11. What is NOT fixed here (escalated)

| Item | Status |
|---|---|
| Production disambiguation for 2+ candidates (§7.3/§14) | PoC rule only (fail closed + explicit picker); production UX unresolved, owned by A2/A0 |
| Revocation freshness and offline behaviour | unresolved (see `trust.md` §7) |
| Nonce derivation from an XOF / future suite | deferred; 32-byte CSPRNG nonces are used |
| Post-quantum / hybrid suite | deferred; `suite_id` reserves the extension point |
