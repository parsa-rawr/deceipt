# DeceiptReceiptV1 — Pass A (receipt schema)

**Revision:** `deceipt-proto-r3` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A3 (validation/serialization), A4/A5 (sign/verify over exact bytes), A6 (conformance)
**Machine-readable companion:** `protocol/schema/receipt-v1.fields.json` · **CDDL:** `protocol/schema/receipt-v1.cddl` · **Bounds:** `protocol/schema/bounds-v1.json`
**Vectors:** `protocol/vectors/receipt-valid.json`, `receipt-invalid.json`, `arithmetic-valid.json`

This closes `DESIGN.md` §15.A and finalizes the provisional choices of §4.2 (deterministic CBOR) and §4.3 (COSE_Sign1).

---

## 1. Encoding profile (normative)

`DeceiptReceiptV1` is a **CBOR map** encoded with **RFC 8949 §4.2.1 core deterministic encoding**. v1 is a strict subset:

| Requirement | Rule | Violation |
|---|---|---|
| Map keys | integers `0..255` only; no text keys | `CBOR_UNSUPPORTED_TYPE` |
| Map key order | ascending by encoded bytes (equals numeric order for `0..255`) | `CBOR_NONCANONICAL` |
| Duplicate keys | forbidden | `CBOR_DUPLICATE_KEY` |
| Integer encoding | minimal-length argument | `CBOR_NONCANONICAL` |
| Lengths | definite only; `0x9f`/`0xbf` indefinite forbidden | `CBOR_UNSUPPORTED_TYPE` |
| Floats | **forbidden** (`0xf9`, `0xfa`, `0xfb`) | `CBOR_UNSUPPORTED_TYPE` |
| Tags | forbidden | `CBOR_UNSUPPORTED_TYPE` |
| `null`/`undefined`/other simple values | forbidden (only `false`/`true` allowed) | `CBOR_UNSUPPORTED_TYPE` |
| Text strings | valid UTF-8; NFC; no control or bidi-control characters | `CBOR_MALFORMED` / `RECEIPT_TEXT_INVALID` |
| Trailing bytes after the top-level item | forbidden | `CBOR_MALFORMED` |
| Depth / item count / sizes | see §8 | `CBOR_DEPTH_EXCEEDED` / `CBOR_SIZE_EXCEEDED` |

**Binary floating point is prohibited at every level of the receipt.** Money is always an integer count of currency minor units; fractional quantities use an exact scaled-integer representation (§5.2).

## 2. Signed container (finalized §4.3)

The signed artifact is a **COSE_Sign1** (RFC 9052) 4-element array:

```text
COSE_Sign1 = [ protected : bstr .cbor protected-map,
               unprotected : {} ,          # MUST be an empty map
               payload : bstr,             # the exact DeceiptReceiptV1 bytes
               signature : bstr(64) ]      # Ed25519 (COSE alg -8, EdDSA)
```

| Rule | Value |
|---|---|
| Protected headers | label `1` `alg` = `-8` (EdDSA); label `3` `content type` = `application/deceipt-receipt+cbor`; label `4` `kid` = merchant **device key id** (`bstr16`) |
| Label `2` `crit` | MUST be absent; any `crit` ⇒ `RECEIPT_UNKNOWN_HEADER` |
| Unknown protected header label | `RECEIPT_UNKNOWN_HEADER` |
| Unprotected header | MUST be `{}`; non-empty ⇒ `RECEIPT_UNKNOWN_HEADER` |
| Payload | MUST be attached; `null` (detached) ⇒ `RECEIPT_CONTAINER_MALFORMED` |
| Signature | exactly 64 bytes; any other length ⇒ `RECEIPT_CONTAINER_MALFORMED` |
| Container canonicality | re-encoding the parsed array MUST reproduce the received bytes, else `RECEIPT_NONCANONICAL` |

**Signature computation (exact signed bytes, §4.1/§13.9):**

```text
Sig_structure = CBOR( ["Signature1", protected_bstr, h'', payload_bstr] )   # RFC 9052 §4.4
signature     = Ed25519_sign(device_private_key, Sig_structure)
```

The receiver MUST verify over `payload_bstr` **as received**. Decoding, modifying, and re-encoding is prohibited (`DESIGN.md` §4.1). `external_aad` is the empty byte string (`h''`).

## 3. Top-level map

Labels `1..21`. All are integer labels in the receipt map. `REQ` = required.

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `receipt_version` | uint | ✔ | MUST be `1`; otherwise `RECEIPT_UNSUPPORTED_VERSION` |
| 2 | `kind` | uint | ✔ | `1`=sale, `2`=refund, `3`=void |
| 3 | `receipt_id` | bstr(16) | ✔ | cryptographically random, globally unique; dedup key (§9) |
| 4 | `issued_at` | uint | ✔ | unix seconds, `1577836800..4102444800` (2020-01-01 .. 2100-01-01) |
| 5 | `tz_offset_minutes` | int | | `-840..840`; display only |
| 6 | `merchant` | map | ✔ | see §4.1 |
| 7 | `location` | map | | see §4.2 |
| 8 | `currency` | tstr | ✔ | ISO 4217 alpha-3 present in the v1 exponent table (`bounds-v1.json`); else `RECEIPT_UNSUPPORTED_CURRENCY` |
| 9 | `lines` | array | ✔ | ≤ 256 items; see §4.3 |
| 10 | `discounts` | array | | ≤ 64 items; see §4.4 |
| 11 | `taxes` | array | | ≤ 64 items; see §4.5 |
| 12 | `tip_amount_minor` | uint | | ≥ 0 |
| 13 | `service_charge_minor` | uint | | ≥ 0 |
| 14 | `rounding_adjustment_minor` | int | | signed |
| 15 | `totals` | map | ✔ | labels 1,2,3,4,8 required; see §4.6 |
| 16 | `payment` | map | ✔ | labels 1,2 required; see §4.7 |
| 17 | `refund_of_receipt_id` | bstr(16) | when `kind=2` | required for refunds |
| 18 | `void_of_receipt_id` | bstr(16) | when `kind=3` | required for voids |
| 19 | `order_reference` | map | | see §4.8 |
| 20 | `merchant_credential` | bstr | ✔ (PoC profile) | the **exact** COSE_Sign1 credential bytes presented in `ServerHello` (§5.3) |
| 21 | `extensions` | array | | ≤ 32 items; see §6 |

## 4. Sub-maps

### 4.1 `merchant` (label 6)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `merchant_id` | bstr(16) | ✔ | MUST equal the credential's `merchant_id` (label 3) |
| 2 | `display_name` | tstr | ✔ | ≤ 128 UTF-8 bytes, NFC, no control/bidi chars |
| 3 | `merchant_reference` | tstr | ✔ | stable merchant-chosen string; this is the value the A2 `offer_hash` commits to |

`merchant_id` is an **opaque 16-byte identifier**. It is a stable identifier, not a trust credential; only the credential (Pass B) authorizes it.

### 4.2 `location` (label 7)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `label` | tstr | | ≤ 128 bytes |
| 2 | `street` | tstr | | ≤ 512 bytes |
| 3 | `city` | tstr | | ≤ 512 bytes |
| 4 | `region` | tstr | | ≤ 512 bytes |
| 5 | `address_lines` | array of tstr | | ≤ 8 items, each ≤ 512 bytes |
| 6 | `postal_code` | tstr | | digits only |

### 4.3 `line` (element of label 9)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `line_id` | uint | ✔ | ≥ 1, unique within `lines` and referenced by `discount.target_line_id` / `line.parent_line_ids` |
| 2 | `description` | tstr | ✔ | ≤ 512 UTF-8 bytes, NFC |
| 3 | `quantity` | map | ✔ | `{1: scale uint 0..9, 2: value int, 3?: unit tstr ≤16}` |
| 4 | `unit_price_minor` | int | ✔ | `|v| ≤ 1e12` |
| 5 | `line_amount_minor` | uint | ✔ | `0..1e15`; MUST equal `round_half_away(unit_price_minor * qty_value, 10^qty_scale)` |
| 6 | `line_discount_minor` | uint | | `0..line_amount_minor` |
| 7 | `parent_line_ids` | array of uint | | non-empty; each must be an existing `line_id` (modifier attachment) |
| 8 | `line_type` | uint | | `1`=item `2`=modifier `3`=discount `4`=info |
| 9 | `sku` | tstr | | ≤ 64 bytes |
| 10 | `modifiers` | array | | ≤ 16 items: `{1: description tstr ≤512, 2: unit_price_minor int, 3: qty_value int, 4: qty_scale uint 0..9}` |

### 4.4 `discount` (element of label 10)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `discount_id` | uint | ✔ | unique within `discounts` |
| 2 | `amount_minor` | uint | ✔ | `0..1e15` |
| 3 | `label` | tstr | | ≤ 128 bytes |
| 4 | `scope` | uint | ✔ | `1`=order, `2`=line |
| 5 | `target_line_id` | uint | when `scope=2` | must be an existing `line_id` |
| 6 | `rate_ppm` | uint | | `0..999999`; if present, label 7 required and `amount_minor == round_half_away(base_amount_minor * rate_ppm, 1000000)` |
| 7 | `base_amount_minor` | uint | with 6 | ≥ 0 |

Discounts are stated and **subtracted** from the subtotal. A per-line discount (label 6 of a line) is informational; the authoritative order-level `discounts` array drives the totals.

### 4.5 `tax` (element of label 11)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `tax_id` | uint | ✔ | unique within `taxes` |
| 2 | `label` | tstr | | ≤ 128 bytes |
| 3 | `rate_ppm` | uint | ✔ | `0..999999` (parts-per-million of the base) |
| 4 | `base_amount_minor` | uint | ✔ | `0..1e15` |
| 5 | `amount_minor` | uint | ✔ | MUST equal `round_half_away(base_amount_minor * rate_ppm, 1000000)` |
| 6 | `jurisdiction` | tstr | | ≤ 64 bytes |
| 7 | `code` | tstr | | ≤ 64 bytes |
| 8 | `included_in_prices` | bool | | `true` ⇒ excluded from the total and `base_amount_minor` MUST be 0 |

`totals.tax_total_minor` (label 3) is the sum of **all** taxes; `totals.tax_added_total_minor` (label 8) is the sum of taxes with `included_in_prices != true`.

### 4.6 `totals` (label 15)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `subtotal_minor` | uint | ✔ | `sum(line_amount_minor)` |
| 2 | `discount_total_minor` | uint | ✔ | `sum(discount.amount_minor)` |
| 3 | `tax_total_minor` | uint | ✔ | `sum(tax.amount_minor)`, included + added |
| 4 | `total_minor` | uint | ✔ | `subtotal − discount_total + tax_added_total + tip + service_charge + rounding`; MUST be ≥ 0 |
| 5 | `tip_minor` | uint | | MUST equal label 12 when label 12 present |
| 6 | `service_charge_minor` | uint | | MUST equal label 13 when present |
| 7 | `rounding_adjustment_minor` | int | | MUST equal label 14 when present |
| 8 | `tax_added_total_minor` | uint | ✔ | `sum` of taxes not marked included |

Any mismatch between a stated total and the recomputation is `RECEIPT_ARITHMETIC_MISMATCH`.

### 4.7 `payment` (label 16)

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `status` | uint | ✔ | `1`=paid `2`=partial `3`=unpaid `4`=refunded `5`=voided |
| 2 | `amount_paid_minor` | uint | ✔ | `0..1e15`; for `kind=refund` this is the refunded amount |
| 3 | `change_minor` | uint | | required iff `amount_paid_minor > total_minor`; MUST equal the difference |
| 4 | `tenders` | array | | ≤ 32 items: `{1: method uint 1..4, 2: amount_minor uint, 3?: card_last4 tstr exactly 4 digits, 4?: brand tstr ≤64, 5?: auth_ref tstr ≤64}` |

Constraints by `kind`:

| kind | `status` | tenders | amount |
|---|---|---|---|
| sale (`1`) | `1`/`2`/`3` | required iff status = 1 | `status=1` ⇒ `amount_paid ≥ total`; `status=2` ⇒ `amount_paid < total`; `status=3` ⇒ `amount_paid = 0` |
| refund (`2`) | `4` | MUST be empty | `amount_paid = total` |
| void (`3`) | `5` | MUST be empty | `amount_paid = 0`, `lines` empty, `totals` all 0 |

`sum(tenders.amount_minor) == amount_paid_minor` whenever tenders are present.

### 4.8 `order_reference` (label 19)

| Label | Name | Type | Rule |
|---|---|---|---|
| 1 | `order_number` | tstr | ≤ 64 bytes |
| 2 | `table` | tstr | ≤ 64 bytes |
| 3 | `server` | tstr | ≤ 64 bytes |

## 5. Monetary representation (§4.2, finalized)

### 5.1 Minor units

* Every monetary value is an **integer count of minor units** of the receipt's `currency`.
* The minor-unit exponent is the ISO 4217 exponent for the currency, from the v1 table in `protocol/schema/bounds-v1.json` (`currency_minor_unit_exponent`): CAD/USD/EUR/… = 2, JPY/KRW/… = 0, KWD/BHD/… = 3.
* `amount_minor = 525`, `currency = "CAD"` ⇒ CAD $5.25. `amount_minor = 525`, `currency = "JPY"` ⇒ ¥525.
* Absolute bound: `|amount| ≤ 1e15` (`MAX_MONETARY_ABS`) — comfortably below `2^53`, so JavaScript `Number` round-trips exactly. A value outside the bound is `RECEIPT_MONETARY_RANGE`.
* Amounts are **never** floats, never strings, never scaled decimals.

### 5.2 Fractional quantities (exact, schema-level)

A quantity is `{scale, value}` in the `line.quantity` map, both integers:

```text
quantity = value × 10^(−scale)          scale ∈ 0..9, |value| ≤ 1e6
```

Examples: `{1: 0, 2: 1}` = 1 ea; `{1: 2, 2: 75}` = 0.75 kg; `{1: 3, 2: 1005}` = 1.005 kg.

The line amount is computed **exactly**, with no floating point, and stated in the receipt:

```text
line_amount_minor = round_half_away(unit_price_minor × value, 10^scale)
```

where `round_half_away(n, d) = sign(n) × floor((2|n| + d) / (2d))`, `d > 0` — round half away from zero.

Worked values (all in `protocol/vectors/arithmetic-valid.json`, each signature-verified):

| Quantity | `unit_price_minor` | Product | `line_amount_minor` |
|---|---|---|---|
| 0.75 kg (`{2,75}`) | 360 | 270.00 | **270** (exact, no rounding) |
| 1.005 kg (`{3,1005}`) | 1 | 0.01005 | **1** (0.01005 → half-away → 0.01) |
| 0.5 kg (`{1,5}`) | 3 | 0.015 | **2** (0.015 → half-away → 0.02) |
| 0.25 kg (`{2,25}`) | 7 | 0.0175 | **2** (0.0175 → half-away → 0.02) |

Overflow guard: `|unit_price_minor × value| > 2^62` ⇒ `RECEIPT_MONETARY_RANGE`, checked **before** the division.

Both parties compute the same value by construction: integer multiply, integer rounding, no platform float. A4/A5 MUST NOT use platform decimal/float types for this step.

## 6. Extensions (label 21)

Each extension is `{1: key tstr ≤64 bytes, 2: critical bool, 3?: value (any canonical CBOR, ≤ 4096 bytes)}`.

| Situation | Result |
|---|---|
| `critical = false`, key unknown | ignored; the exact signed bytes MUST still be preserved when storing |
| `critical = true`, key known to v1 | none are known in v1 — the set (`KNOWN_EXTENSIONS`) is empty |
| `critical = true`, key unknown | `RECEIPT_UNKNOWN_CRITICAL_EXTENSION` (fatal) |

## 7. Unknown fields and version negotiation

| Case | Result |
|---|---|
| Unknown integer label in any receipt map | `RECEIPT_UNKNOWN_FIELD` (fatal) |
| Unknown protected COSE header label | `RECEIPT_UNKNOWN_HEADER` (fatal) |
| `crit` header present | `RECEIPT_UNKNOWN_HEADER` (fatal) |
| `receipt_version != 1` | `RECEIPT_UNSUPPORTED_VERSION` (fatal) |
| Unknown COSE `alg` | `RECEIPT_UNSUPPORTED_ALGORITHM` (fatal) |
| `content type` not the receipt content type | `RECEIPT_UNSUPPORTED_ALGORITHM` (fatal) |

**Version negotiation is explicit and not implicit-compatible.** The transport advertises `protocol_version = 1` in `ClientHello`/`ServerHello`; the **signed receipt** carries its own `receipt_version`, which is authoritative and independent of the transport version. A receiver MUST reject any `receipt_version` it does not implement rather than best-effort parsing it. There is no "ignore unknown fields and continue" mode; the strictness is deliberate (`DESIGN.md` §13.11).

## 8. Parser and allocation bounds (security requirements, §13.11)

| Bound | Value | Error |
|---|---|---|
| Receipt COSE_Sign1 total bytes | 65536 | `RECEIPT_SIZE_EXCEEDED` |
| Credential bytes | 1024 | `CREDENTIAL_MALFORMED` |
| CBOR depth | 12 | `CBOR_DEPTH_EXCEEDED` |
| CBOR items per document | 8192 | `CBOR_SIZE_EXCEEDED` |
| CBOR array length | 1024 | `CBOR_SIZE_EXCEEDED` |
| CBOR map length | 256 | `CBOR_SIZE_EXCEEDED` |
| CBOR text string | 4096 bytes | `CBOR_SIZE_EXCEEDED` |
| `lines` / `discounts` / `taxes` / `tenders` / `extensions` / `modifiers` | 256 / 64 / 64 / 32 / 32 / 16 | `RECEIPT_SEMANTIC_INVALID` |
| `address_lines` | 8 | `RECEIPT_TEXT_INVALID` |
| Description text | 512 bytes | `RECEIPT_TEXT_INVALID` |
| Display-name text | 128 bytes | `RECEIPT_TEXT_INVALID` |
| Short text (`sku`, `jurisdiction`, `code`, order refs, brand, auth_ref) | 64 bytes | `RECEIPT_TEXT_INVALID` |
| Unit text | 16 bytes | `RECEIPT_TEXT_INVALID` |

Exact values live in `protocol/schema/bounds-v1.json`. Allocation MUST be bounded by these limits **before** reading (e.g. do not allocate an array of a peer-declared length before checking it against the cap). A4/A5 MUST enforce these in native code; A3 MUST enforce them in shared validation.

**Text safety** (`check_text`): valid UTF-8, NFC-normalized, and free of C0/C1 control characters, surrogates, and Unicode bidi controls (`U+061C`, `U+200E/F`, `U+202A..E`, `U+2066..9`). Any violation ⇒ `RECEIPT_TEXT_INVALID`. Rationale: a receipt is a user-facing document; bidi overrides can make a displayed amount or merchant read differently from the signed bytes.

## 9. Dedup semantics (§4.5)

* Key: **`receipt_id` only** (`bstr16`), compared as bytes.
* The comparison happens **after** signature and merchant-authorization verification (`DESIGN.md` §9 step 13).
* Comparison is over the **exact signed payload bytes** (`Sig_structure`'s `payload_bstr`), not a re-encoding.

| Local state for `receipt_id` | Incoming payload | Result |
|---|---|---|
| absent | any valid | `TRUSTED`; store |
| present, bytes identical | valid | outcome **`ALREADY_IMPORTED_IDENTICAL`** — idempotent success, not an error, no duplicate row |
| present, bytes differ | valid | `RECEIPT_DUPLICATE_CONFLICT` (fatal, `0x060D`) — a genuine anomaly: one merchant key signed two different documents under one identifier |

Because `receipt_id` uniqueness does not itself provide authenticity (§4.5), a `RECEIPT_DUPLICATE_CONFLICT` is reported but never "resolves" which document is real. Both are stored as evidence and flagged for the user.

Vectors: `receipt-invalid.json` cases `duplicate_receipt_id_different_bytes` and `identical_reimport`.

## 10. Worked vector (must reproduce byte-for-byte)

Fixture `protocol/vectors/receipt-valid.json` (test-only keys, `protocol/vectors/keys/test-keys.json`):

| Quantity | Value |
|---|---|
| Receipt payload | 669 bytes, SHA-256 `69255f589539bb767f9dbe0056f3f159c7f960650014342ca6a776151bbd8135` |
| COSE_Sign1 | 798 bytes |
| Protected header | `a3 01 27 03 78 20 "application/deceipt-receipt+cbor" 04 50 0f1e2d3c4b5a69788796a5b4c3d2e1f0` |
| Signature (Ed25519, 64 B) | `13b40bbba3118346d196e935497fd4519b50890904509cbb7267fbf75b2f2df6615ca62b1394ec814d25dd56acac72ab7d13e2b1a6f37eaa93c2bbcd82857808` |
| Lines | 1× Latte @475 = 475; 0.75 kg Croissant @360 = 270; 1× Oat milk @75 = 75 |
| Subtotal / discount / tax_total / tax_added / tip | 820 / 50 / 100 / 100 / 100 |
| **Total** | **970** minor = **CAD 9.70** |
| Expected verification | `signature_valid=true, key_authorized=true, credential_temporally_acceptable=true, semantically_valid=true, outcome=TRUSTED` |

A4/A5 MUST verify this signature and A3 MUST reproduce this payload from the field tables above. A second, 256-line receipt (`long_receipt`, COSE 11486 bytes, body SHA-256 `6588d08a563b007a01d5db85b43c24adfceff0a5def6cc6cf6f9cb06b005fc34`, total 30052 minor) exercises the parser and fragmentation bounds.
