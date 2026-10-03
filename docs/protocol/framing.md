# Transfer framing and flow control

**Revision:** `deceipt-proto-r4` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A4/A5 (native fragmentation/flow control), A3 (progress semantics), A6 (fragmentation proof)
**Vectors:** `protocol/vectors/framing-valid.json`, `framing-invalid.json`, `lpdu-valid.json`, `lpdu-invalid.json` · **Bounds:** `protocol/schema/bounds-v1.json`

Finalizes `DESIGN.md` §8.4–§8.6 and the provisional transaction-selection binding interface required by A2.

---

## 1. Frame format

```text
DataFrame = transfer_id(16) ‖ u32_be(sequence_number) ‖ payload_bytes
```

* `transfer_id` — the session's 16-byte identifier, authenticated in the transcript.
* `sequence_number` — `0..frame_count−1`, big-endian `u32`.
* `payload_bytes` — a slice of the AEAD ciphertext. Non-final frames carry exactly `frame_size` bytes; the **final** frame carries `ciphertext_length − frame_size·(frame_count−1)`, which is `1..frame_size` and MAY be shorter than the 16-byte minimum that applies to the negotiated `frame_size`. A final frame of 4 bytes (as in the frozen vector) is valid; only a **non-final** frame shorter than 16 bytes, or any frame longer than `frame_size`, is `FRAME_SIZE_INVALID`. Byte boundaries of BLE packets MUST NOT influence cryptographic object boundaries (`DESIGN.md` §6.5); frames are fragments of one ciphertext, reassembled before AEAD open.

**Frame size is negotiated from the reported MTU, never a fixed ATT MTU** (`DESIGN.md` §8.5, §12):

```text
att_payload_max(att_mtu)     = min(att_mtu − 3, 512)
max_frame_payload_for_mtu(m) = min(att_payload_max(m) − 20, 512)
frame_size                   ∈ [16, 512], and ≤ the peer's SERVER_HELLO label 11 value
final_frame_payload          ∈ [1, frame_size]
```

`max_frame_payload` is a member of the canonical transcript (`handshake.md` §3), so the negotiated size is authenticated. Neither side may renegotiate it after `SERVER_HELLO`.

Vector: `att_mtu = 185` ⇒ ceiling `162`; `frame_size = 162`; 814-byte ciphertext ⇒ `frame_count = 6`; payload sizes `[162,162,162,162,162,4]` (the final frame is 4 bytes and is valid).

## 2. Transfer begin and complete

`TRANSFER_BEGIN` (AEAD control, A→B) — `{1:0x13, 2:transfer_id, 3:ciphertext_length, 4:payload_hash, 5:frame_size, 6:frame_count}`.

* `ciphertext_length` MUST be `≤ 65552` else `TRANSFER_SIZE_EXCEEDED`.
* `frame_count` MUST equal `ceil(ciphertext_length / frame_size)` else `TRANSFER_BEGIN_MISMATCH`.
* `payload_hash` = `SHA-256(ciphertext)`; it is a **transport-integrity checkpoint, not a substitute** for AEAD authentication or the merchant signature (`DESIGN.md` §8.4). A mismatch at completion ⇒ `TRANSFER_HASH_MISMATCH`.
* `frame_size` MUST satisfy the bounds above and `≤` the transcript value else `FRAME_SIZE_INVALID`.

`TRANSFER_COMPLETE` (AEAD control, A→B) — `{1:0x14, 2:transfer_id, 3:frame_count, 4:payload_hash}`, sent after the last frame; the receiver checks `frame_count` and `payload_hash` before AEAD open.

## 3. Receiver buffering

* Allocate a ciphertext buffer bounded by `min(ciphertext_length, 65552)` **after** checking the declared length; never allocate from the peer's number unchecked (`DESIGN.md` §13.11).
* Maintain a sliding window of `WINDOW_FRAMES = 64` sequence slots above `highest_contiguous_sequence`.
* On a frame:
  * `transfer_id` mismatch ⇒ `TRANSFER_ID_MISMATCH` (fatal).
  * `sequence_number ≥ frame_count` (or `≥ MAX_FRAMES`) ⇒ `FRAME_SEQUENCE_OUT_OF_RANGE` (fatal).
  * sequence already buffered, **byte-identical** ⇒ ignore (`FRAME_SEQUENCE_REPLAYED`, non-fatal).
  * sequence already buffered, **different bytes** ⇒ `FRAME_CONFLICT` (fatal).
  * sequence below the window floor ⇒ ignore (`FRAME_SEQUENCE_REPLAYED`, non-fatal).
  * otherwise buffer it; advance `highest_contiguous_sequence` while the next slot is present.
* If buffering would exceed `WINDOW_FRAMES` distinct un-acked slots ⇒ `FRAME_BUFFER_EXCEEDED` (fatal); the sender is outrunning flow control.

## 4. Flow control and acknowledgement

`ACK` (AEAD control, B→A) — `{1:0x03, 2:transfer_id, 3:highest_contiguous_sequence}`.

* `ACK.3` is the highest sequence `s` such that frames `0..s` are all present (`uint`, or absent-equivalent when none). It is monotonic non-decreasing; a decreasing value is ignored as a stale duplicate.
* Receiver emits `ACK` when it has advanced `highest_contiguous_sequence` by ≥ `ACK_EVERY_FRAMES = 32` frames since the last ACK, or after `T_ACK_INTERVAL = 500 ms` of having un-acked progress, or immediately on a gap stall.
* Sender window: it may have at most `WINDOW_FRAMES = 64` frames in flight beyond `highest_contiguous_sequence`; a missing ACK past `T_ACK_WAIT = 3 s` triggers retransmission of frames from `highest_contiguous_sequence + 1`.
* **Bounded retry:** at most `MAX_FRAME_RETRIES = 5` retransmission rounds per transfer; exceeding it ⇒ `TRANSFER_RETRY_EXHAUSTED`.
* `RETRY` (AEAD control, B→A) — `{1:0x06, 2:transfer_id, 3:from_sequence}` — explicit receiver-driven retransmission request. Selective retransmission beyond this is out of scope for the PoC (`DESIGN.md` §8.6).

Application acknowledgements do not prove merchant authenticity (`DESIGN.md` §8.6); they only advance transport state.

## 5. Cancellation and disconnect

| Event | Behavior | Error |
|---|---|---|
| Customer taps Cancel | send `CANCEL` (AEAD); abort local buffers; no store | `TRANSFER_CANCELLED` |
| Merchant error | send `ERROR`, then `TRANSFER_COMPLETE`-less teardown | `TRANSFER_ABORTED` (+ specific code) |
| User cancels at offer | `DISCONNECT` before any frames | `USER_CANCELLED` |
| Link lost mid-transfer | abort; drop partial buffer; no store | `TRANSPORT_LINK_LOST` |
| Bluetooth off | abort; drop partial buffer; no store | `TRANSPORT_BLUETOOTH_OFF` |
| `T_TRANSFER_IDLE` exceeded | abort | `TRANSFER_TIMEOUT` |
| session lifetime exceeded | abort | `SESSION_EXPIRED` |

**No disconnect or cancellation path may leave a half-imported receipt marked trusted** (`DESIGN.md` §13.4, gate 8). A partial ciphertext never reaches AEAD open, and even a fully decrypted payload is `RECEIPT_UNTRUSTED` until §9 verification (`verification.md`) completes atomically.

## 6. Bound on the whole transfer

```text
receipt bytes                 ≤ 65536               (Pass A)
AEAD ciphertext               ≤ 65536 + 16 = 65552  (TRANSFER_SIZE_EXCEEDED)
frame_count                   ≤ 32768               (TRANSFER_SIZE_EXCEEDED)
bytes moved over the air      ≤ 65552
```

Long-receipt vector (`receipt-valid.json#long_receipt`): COSE 11486 bytes ⇒ ciphertext 11502 bytes ⇒ 71 frames at 162 bytes ≈ 11.2 KiB over the air — exercised by A6's fragmentation proof.

## 7. Binding to A2's transaction-selection contract

A2 owns *how the user selects a transaction*; A1 owns *how the selection is bound into the session and how a mismatch fails*. The interface:

| A2 provides | A1 consumes |
|---|---|
| `session_id(16)` in the QR | `CLIENT_HELLO.label 4`, transcript offset 234 |
| `transfer_id(16)` | binding tuple member; transcript offset 218; every frame |
| `receipt_id(16)` | binding tuple member; `RECEIPT_OFFER.label 3`; dedup key |
| `offer_hash(32)` | binding tuple member (offset 285); recomputed from `RECEIPT_OFFER` members in array order `[session_id(12), transfer_id(2), receipt_id(3), merchant_reference(4), total_amount_minor(5), currency(6), issued_at(7)]` — see `wire.md` §7 for the single definition |
| `binding_tuple_digest(32)` | transcript offset 250, signed by the merchant |
| `binding_proof(32)` | `CLIENT_HELLO.label 7` |

**Fail-closed rules at the interface:**

1. QR/session expired ⇒ `BINDING_STALE`; already claimed ⇒ `BINDING_CONSUMED`; unknown `session_id` ⇒ `BINDING_UNKNOWN_SESSION`; bad HMAC ⇒ `BINDING_PROOF_INVALID`.
2. `RECEIPT_OFFER` fields MUST reproduce `offer_hash` (recompute-and-compare, array order per `wire.md` §7); the offer hash MUST equal the value from the QR, else `WRONG_TRANSACTION`.
3. The verified receipt MUST match the offer on `receipt_id`, `kind`, `total_minor`, `currency`, `issued_at`, `merchant_id`, `merchant_reference`; any mismatch ⇒ **`WRONG_TRANSACTION`** (`0x0614`, fatal, audited). This is the only name for the condition; the r1 duplicate `RECEIPT_OFFER_MISMATCH` is removed.

Session binding is **never** merchant-key trust (A2 §3.9): passing every binding check says only "this session, this transaction"; the receipt is still untrusted until Pass B and the §9 receipt checks pass.

**Dependency status:** A2's binding contract v1 is adopted verbatim (`handshake.md` §10). The one defect found (an invalid P-256 point in A2's original vectors) was fixed by A2 at commit `7e90945`; A1 re-derived all regenerated vectors and they reconcile byte-for-byte with r1. `binding-crosscheck.json` records the live result (`a2_bytes_match: true`). No open A2 dependency.
