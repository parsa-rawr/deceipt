# Wire identifiers and control messages — Pass D

**Revision:** `deceipt-proto-r2` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A4/A5 (GATT, advertising, framing), A3 (message models), A6 (interop)
**Machine-readable:** `protocol/schema/wire-v1.messages.json` · **CDDL:** `protocol/schema/wire-v1.cddl` · **Vectors:** `protocol/vectors/handshake-valid.json`, `aead-valid.json`, `lpdu-valid.json`, `framing-valid.json`

Closes `DESIGN.md` §15.D (`DESIGN.md` §7.4 left the UUIDs deliberately unassigned) and finalizes the provisional "three-characteristic GATT layout".

---

## 1. GATT service and characteristics (finalized §7.4)

One 128-bit service, three characteristics. These values are now assigned and frozen; changing them is a revision break.

| Role | UUID | Notes |
|---|---|---|
| **Deceipt Transfer Service** | `8decc0de-1e57-4000-8000-000000000001` | |
| COMMAND (B→A) | `8decc0de-1e57-4000-8000-000000000002` | Write with response (`WriteRequest`) |
| EVENT (A→B) | `8decc0de-1e57-4000-8000-000000000003` | Indicate (client confirms) |
| DATA (A→B) | `8decc0de-1e57-4000-8000-000000000004` | Notify (no confirmation) |

The base UUID `8decc0de-1e57-4000-8000-000000NNNNNN` is Deceipt-owned and not derived from any vendor block; it is a random v4-shaped identifier with a fixed tail, used for the four v1 attributes (service + three characteristics). It is not registered with the Bluetooth SIG and MUST NOT be advertised as a standard service.

**Advertising** (`DESIGN.md` §7.2, §11): the advertisement carries the service UUID and nothing else — no merchant name, no amount, no receipt id, no customer data, no credential, no payload. Optionally the 128-bit service UUID is placed in the `Complete List of 128-bit Service Class UUIDs` AD type. The advertisement means only "a Deceipt transfer endpoint is available".

* Peripheral: merchant (`A`), GATT server. Central: customer (`B`), GATT client (`DESIGN.md` §7.1).
* When no receipt is ready the merchant MUST NOT advertise.
* Stop advertising when committed to one receiver, cancelled, expired, or completed.
* No OS-level pairing for any of this; the service is open (security comes from the handshake and the signature, never from the link).

## 2. Message type IDs

`type` is always label `1` of a CBOR control message. `0x00` is invalid (reserved).

| ID | Name | Direction | Characteristic | Encrypted | State |
|---:|---|---|---|---|---|
| `0x01` | `CLIENT_HELLO` | B→A | COMMAND | no | `CONNECTED` |
| `0x02` | `ACCEPT` | B→A | COMMAND | yes | `RECEIPT_OFFERED` |
| `0x03` | `ACK` | B→A | COMMAND | yes | `TRANSFER` |
| `0x04` | `RECEIPT_ACK` | B→A | COMMAND | yes | `STORED` |
| `0x05` | `CANCEL` | B→A | COMMAND | yes | any |
| `0x06` | `RETRY` | B→A | COMMAND | yes | `TRANSFER` |
| `0x11` | `SERVER_HELLO` | A→B | EVENT | no | `HANDSHAKE` |
| `0x12` | `RECEIPT_OFFER` | A→B | EVENT | yes | `MERCHANT_SESSION_AUTHENTICATED` |
| `0x13` | `TRANSFER_BEGIN` | A→B | EVENT | yes | `TRANSFER` |
| `0x14` | `TRANSFER_COMPLETE` | A→B | EVENT | yes | `TRANSFER` |
| `0x15` | `ERROR` | A→B | EVENT | plaintext only before keys; AEAD once keys exist | any |

* The high nibble distinguishes direction: `0x0_` = B→A, `0x1_` = A→B. A message arriving on the wrong characteristic or with the wrong direction nibble is `MESSAGE_WRONG_DIRECTION` (fatal).
* Unknown `type` ⇒ `MESSAGE_UNKNOWN_TYPE` (fatal).
* `DataFrame` is **not** a control message and carries no `type`; it has its own layout (§5).

Message field tables: `protocol/schema/wire-v1.messages.json`. Every listed label is required unless marked optional there; unknown labels ⇒ `MESSAGE_UNKNOWN_FIELD`.

## 3. Control message transport: LPdu segmentation

Control messages (both hello messages and every AEAD envelope) travel on COMMAND (B→A) and EVENT (A→B) as **fragments** of one Logical PDU, because a single ATT write/indication payload is small. Bounds: reassembled PDU ≤ `2048` bytes; ≤ `512` fragments; fragment payload ≤ `512` bytes.

```text
LPdu fragment = u16_be(msg_seq) ‖ u8(frag_index) ‖ u8(frag_count) ‖ fragment_bytes
```

| Rule | Violation |
|---|---|
| `frag_count ≥ 1`; first fragment has `frag_index = 0` | `LPDU_FRAGMENT_INVALID` |
| `frag_index` arrives in order `0,1,2,…` | `LPDU_SEQUENCE_ERROR` |
| all fragments of a message share `msg_seq` | `LPDU_SEQUENCE_ERROR` |
| `msg_seq` is strictly increasing per sender per session; no reuse | `LPDU_SEQUENCE_ERROR` |
| reassembled length ≤ 2048 | `LPDU_MESSAGE_TOO_LARGE` |
| fragments of two messages MUST NOT interleave | `LPDU_SEQUENCE_ERROR` |
| a repeated fragment index with different bytes | `LPDU_CONFLICT` (fatal) |
| a repeated fragment index with identical bytes | ignored |
| incomplete set within `T_CONTROL_FRAG` | `LPDU_REASSEMBLY_TIMEOUT` (retryable) |
| `msg_seq` per session per direction ≤ 4096 | `MESSAGE_TOO_LARGE` |

`msg_seq` is scoped to the sender within the session and is used only for LPdu reassembly ordering; the AEAD counter of §6 is the cryptographic anti-replay mechanism. A receiver MUST NOT allocate buffers for a peer-declared `frag_count` before checking it against 512.

Vector: `lpdu-valid.json` (ServerHello → 3 fragments of 182/182/171 bytes over an example ATT MTU of 185) and `lpdu-invalid.json`.

## 4. Transfer identity rules

* `transfer_id`: 16 random bytes chosen by the merchant for the session. It **is** a member of the A2 binding tuple (`handshake.md` §10), so it is authenticated by the transcript signature.
* `session_id`: 16 random bytes, merchant-minted per checkout, delivered in the QR (A2 §3.3), carried in `CLIENT_HELLO`, the transcript, `RECEIPT_OFFER`, and the binding tuple.
* `receipt_id`: 16 random bytes, minted by the merchant at checkout before the QR renders; it is the receipt's dedup key (Pass A §9) and an offer-hash member.
* Every `DataFrame` carries `transfer_id`; every transfer-scoped control message carries it. A mismatch anywhere ⇒ `TRANSFER_ID_MISMATCH` (fatal).
* All three identifiers are **opaque random bytes**. They never encode merchant identity and are never derived from a key or from RSSI.

## 5. DATA frames (finalized §8.5)

```text
DataFrame = transfer_id(16) ‖ u32_be(sequence_number) ‖ payload_bytes
```

| Rule | Value / violation |
|---|---|
| Total frame bytes | ≤ `att_payload_max` of the negotiated MTU, and header + payload ≤ 512 |
| `payload_bytes` length | non-final frames `16..frame_size`; the **final** frame `1..frame_size` (ciphertext length need not be a multiple of `frame_size`) ⇒ else `FRAME_SIZE_INVALID` |
| `frame_size` | negotiated in the transcript; MUST be `≤` the peer's declared `max_frame_payload` |
| `sequence_number` | `0..frame_count−1`; out of range ⇒ `FRAME_SEQUENCE_OUT_OF_RANGE` |
| duplicate sequence, identical bytes | ignored (`FRAME_SEQUENCE_REPLAYED`, non-fatal) |
| duplicate sequence, different bytes | `FRAME_CONFLICT` (fatal) |
| sequence below the sliding window floor | ignored (`FRAME_SEQUENCE_REPLAYED`, non-fatal) |
| `transfer_id` mismatch | `TRANSFER_ID_MISMATCH` (fatal) |

Frame size is **never** a fixed ATT MTU. It is derived from the reported MTU at connect time:

```text
att_payload_max(att_mtu)      = min(att_mtu − 3, 512)
max_frame_payload_for_mtu(m)  = min(att_payload_max(m) − 20, 512)      # 20 = DataFrame header
```

Worked example (vectors): `att_mtu = 185` ⇒ `att_payload_max = 182`; merchant negotiates `frame_size = 162` (a conservative value below the ceiling) and the receipt's 814-byte ciphertext becomes **6 frames** of 162 bytes except the last (24 bytes). Bounds on the negotiated value live in the transcript and are therefore authenticated.

## 6. AEAD control envelopes (summary; full rules in `handshake.md` §6)

```text
plaintext envelope = 0x00 ‖ CBOR(message)              # ClientHello / ServerHello ONLY
AEAD envelope      = 0x01 ‖ u64_be(counter) ‖ AES-256-GCM(key, nonce(counter), aad, CBOR(message))
nonce              = 00000000 ‖ u64_be(counter)
aad(B→A control)   = session_context ‖ 0x02 ‖ 0x00
aad(A→B control)   = session_context ‖ 0x02 ‖ 0x01
```

Counter is strict in-order per direction: `counter < expected` ⇒ `AEAD_REPLAY_DETECTED`; `counter > expected` ⇒ `AEAD_COUNTER_MISMATCH`; tag failure ⇒ `AEAD_AUTH_FAILED`.

**Exactly which messages may be plaintext.** Only these, and only while no session keys exist:

| Message | Plaintext permitted when |
|---|---|
| `CLIENT_HELLO` | always (sent before any keys exist) |
| `SERVER_HELLO` | always (sent before the client has keys) |
| `ERROR` | only in the `CONNECTED` / pre-key `HANDSHAKE` states — so a peer can report `HANDSHAKE_UNSUPPORTED_VERSION`, `HANDSHAKE_NO_COMMON_SUITE`, `HANDSHAKE_ECDH_INVALID_POINT`, `CREDENTIAL_*` |

Every other control message (§ `ACCEPT`/`ACK`/`RECEIPT_ACK`/`CANCEL`/`RETRY`/`RECEIPT_OFFER`/`TRANSFER_BEGIN`/`TRANSFER_COMPLETE`), and `ERROR` once keys exist, MUST use the AEAD envelope. A plaintext envelope received where AEAD is required ⇒ `MESSAGE_WRONG_STATE` (fatal). A peer that cannot or will not send AEAD at that point MUST `ABORT`/disconnect instead.

## 7. Complete worked example (must reproduce)

All values from `handshake-valid.json` / `aead-valid.json` / `framing-valid.json` / `lpdu-valid.json`:

| Step | Bytes |
|---|---|
| `CLIENT_HELLO` PDU | `00` ‖ CBOR, 168 B (`ClientHello` 167 B + envelope tag) |
| `SERVER_HELLO` PDU | 523 B (`00` ‖ 522-byte CBOR), fragmented into 3 LPdu fragments (182/182/171) |
| `RECEIPT_OFFER` AEAD envelope | 181 B: `01 0000000000000000` ‖ 172-byte GCM ciphertext (`010000000000000000 10f4d62494cb0cc5…fa5d15`) |
| `TRANSFER_BEGIN` AEAD envelope | 90 B: `01 0000000000000001` ‖ … (`0118eda47f49904311…aaa52eeade`) |
| `ACCEPT` AEAD envelope (B→A) | 50 B: `01 0000000000000000` ‖ … (`4f9409395765eee3…01de8e43cb`) |
| `ACK` plaintext | CBOR `{1:3, 2:transfer_id, 3:0}` = `a3 01 03 02 50 <transfer_id> 03 00` |
| Frames | 6 × (`transfer_id ‖ u32_be(i) ‖ ciphertext[i*162:(i+1)*162]`) |

`RECEIPT_OFFER` plaintext CBOR (156 B) begins `ac 01 12 02 50 <transfer_id> 03 50 <receipt_id> 04 77 "merchant.poc.test-alpha" 05 19 03ca 06 63 "CAD" 07 1a 6955b8c4 08 01 09 19 032e 0a 50 <merchant_id> 0b 58 20 <credential_hash> 0c 50 <session_id>`; `19 03ca` = **970 minor**, i.e. the offer commits to exactly the receipt that follows (CAD 9.70).

**`offer_hash` (single definition, r2).** The hash is over the **array element order**, not label order:

```text
offer_hash = SHA-256("deceipt-offer-hash-v1" ‖ 0x00 ‖ CBOR([
    session_id, transfer_id, receipt_id, merchant_reference,
    total_amount_minor, currency, issued_at_unix ]))
```

In `RECEIPT_OFFER` label terms the members are `[12, 2, 3, 4, 5, 6, 7]`. (r1 stated `3,4,5,6,7,10` here and in `framing.md`, which was wrong; this is the corrected, single statement. The frozen `offer_hash_hex` and the receipt's binding tuple already use this order.)


## 8. Explicitly deferred

| Item | Reason |
|---|---|
| Manufacturer-specific advertising payloads | not needed for the PoC; the advertisement is service-UUID only |
| GATT L2CAP CoC / connection-oriented channels | deferred; the PoC uses GATT notifications |
| Second service for firmware/telemetry | out of scope |
| UUID registration with the Bluetooth SIG | not a PoC requirement; the UUID is Deceipt-private |
