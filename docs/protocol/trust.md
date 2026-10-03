# Merchant trust bootstrap — Pass B

**Revision:** `deceipt-proto-r1` · **Status:** FROZEN for the PoC
**Owner:** A1 · **Consumers:** A4/A5 (credential verification), A3 (trust-policy outcomes, UI), A6 (adversarial review)
**Machine-readable:** `protocol/schema/credential-v1.fields.json` · **CDDL:** `protocol/schema/credential-v1.cddl` · **Vectors:** `protocol/vectors/credentials.json`, `receipt-invalid.json`

Closes `DESIGN.md` §15.B for the PoC and finalizes the provisional items "Deceipt as sole PoC trust root" and "merchant device credential format". It does **not** finalize the production hierarchy (enrollment, identity proofing, delegation, revocation, anti-backdating) — those are explicitly escated in §7.

---

## 1. The claim being made, and the claim that is NOT being made

A merchant receipt is trusted only if **both** hold:

1. the receipt signature verifies over the **exact received receipt bytes** (Pass A); and
2. the signing key is **authorized for the claimed merchant** by a credential that chains to a pinned trust anchor (this pass).

> **A supplied public key plus a valid signature does NOT prove merchant identity.**
> Any party can generate a key pair and sign a self-consistent receipt. Identity comes only from a credential issued by a party the receiver already trusts. A signature that verifies proves *integrity and possession of that key*, not *who the merchant is*, and not *that the receipt predates key compromise* (`DESIGN.md` §5.2, §5.4).

This is why a structurally perfect rogue receipt must be surfaced as **unknown**, never as trusted (vector `unknown_issuer_credential` in `receipt-invalid.json`).

## 2. Credential format — `DeceiptMerchantCredentialV1`

A COSE_Sign1 (identical container rules to Pass A) whose protected `content type` is `application/deceipt-credential+cbor`, signed by the **issuer** (in the PoC, the Deceipt root), over the deterministic-CBOR payload below.

```text
COSE_Sign1 = [ protected : bstr .cbor issuer-protected-header, {} , payload : bstr, signature : bstr(64) ]
payload    = DeceiptMerchantCredentialV1 (deterministic CBOR map, labels 1..11)
```

| Label | Name | Type | REQ | Rule |
|---|---|---|---|---|
| 1 | `credential_version` | uint | ✔ | MUST be `1` |
| 2 | `issuer_id` | bstr(16) | ✔ | MUST equal the protected `kid`; looked up in the pinned anchor set |
| 3 | `merchant_id` | bstr(16) | ✔ | stable merchant identifier; the same value the receipt's `merchant.merchant_id` must carry |
| 4 | `device_key_id` | bstr(16) | ✔ | MUST equal the receipt's COSE protected `kid` |
| 5 | `device_public_key` | bstr(32) | ✔ | Ed25519 public key used to sign receipts |
| 6 | `valid_from` | uint | ✔ | unix seconds, inclusive |
| 7 | `valid_until` | uint | ✔ | unix seconds, exclusive; MUST be `> valid_from` |
| 8 | `capabilities` | uint | ✔ | bitmask (below) |
| 9 | `merchant_reference` | tstr | ✔ | ≤ 128 bytes, NFC; MUST equal the receipt's `merchant.merchant_reference` |
| 10 | `display_name` | tstr | ✔ | ≤ 128 bytes, NFC |
| 11 | `issued_at` | uint | ✔ | credential issuance time |

Protected header (issuer's signature target):

| Label | Name | Value |
|---|---|---|
| 1 | `alg` | `-8` (EdDSA) |
| 3 | `content type` | `application/deceipt-credential+cbor` |
| 4 | `kid` | the issuer's `anchor_id` (`bstr16`) |

**Signature:** Ed25519 over `Sig_structure = CBOR(["Signature1", protected_bstr, h'', payload_bstr])`. Deterministic CBOR, no floats/tags/indefinite lengths, integer labels only. Max credential size **1024 bytes** (`CREDENTIAL_MALFORMED` beyond).

### 2.1 Capabilities

| Bit | Name | Meaning |
|---|---|---|
| `0x0001` | `CAP_ISSUE_SALE` | may issue `kind=1` receipts |
| `0x0002` | `CAP_ISSUE_REFUND` | may issue `kind=2` receipts |
| `0x0004` | `CAP_ISSUE_VOID` | may issue `kind=3` receipts |
| `0x0008` | `CAP_RECEIVE_TRANSFER` | may be the merchant endpoint of a transfer session |
| `0x0010` | `CAP_EMBED_CREDENTIAL` | may embed this credential in a receipt (poC profile requires it) |

A receipt of kind *K* requires the credential to carry the matching `CAP_ISSUE_*` bit, else `CREDENTIAL_CAPABILITY_MISSING`.

## 3. Trust anchor (PoC provisioning)

The app ships **public verification material only**. The root private key never ships in the app, never enters the repo, and never crosses the JS bridge (`DESIGN.md` §5.1, invariant 8).

Pinned anchor set (`protocol/vectors/fixtures/trust-anchors-v1.json`, test-only):

| Field | Value |
|---|---|
| `anchor_id` | `0decea00000000000000000000000001` |
| Algorithm | EdDSA (Ed25519) |
| Public key | `61d36a1033982810583469d18733d5810bcc8f06db10d11d391e3945d51c58ed` |
| Label | "Deceipt PoC Test Root 1" |

**Deliberate PoC test-merchant bootstrap.** So both phones and the test harness agree on the exact bytes:

1. The harness holds the root private key (test-only, `protocol/vectors/keys/test-keys.json`, `root-poc-1`).
2. It signs one credential for the pre-provisioned **test merchant** (`merchant_id = a1b2c3d4e5f60718293a4b5c6d7e8f90`, `device_key_id = 0f1e2d3c4b5a69788796a5b4c3d2e1f0`, device key `merchant-test-1`) and commits it as `protocol/vectors/fixtures/valid-credential.cbor`.
3. The merchant phone is provisioned with that credential and the matching device private key.
4. **The customer app is provisioned with the root public key only.** It is the sole pinned trust anchor.
5. A second, deliberately **untrusted** root (`root-unknown-1`) signs a rogue credential (`merchant-unknown-1`) used by the `unknown_issuer` vectors. It is never added to the anchor set.

`trust-anchors-v1.json` contains public keys only and is committed. `test-keys.json` contains test private halves and is committed too — it is test material by construction; `docs/decisions.md` D-003 un-ignores `protocol/vectors/**` for exactly this reason. Production builds MUST NOT bundle any test private key.

## 4. Verification algorithm (receiver)

Run after `ServerHello` is parsed and before the transcript signature is accepted (`DESIGN.md` §9 steps 3–4):

```text
verify_credential(credential_bytes, anchor_set, now):
  1. len(credential_bytes) <= 1024                                   else CREDENTIAL_MALFORMED
  2. parse COSE_Sign1; require canonical container; protected ctype = credential;
     unprotected = {}; signature = 64 bytes                           else CREDENTIAL_MALFORMED
  3. payload is deterministic-CBOR map; credential_version == 1       else CREDENTIAL_MALFORMED
  4. protected.kid == payload.issuer_id                               else CREDENTIAL_MALFORMED
  5. fixed lengths: merchant_id 16, device_key_id 16, device_pubkey 32 else CREDENTIAL_MALFORMED
  6. text checks on merchant_reference, display_name                  else CREDENTIAL_MALFORMED
  7. anchor = anchor_set[issuer_id]
        absent  -> (CREDENTIAL_UNKNOWN_ISSUER, trust = "unknown_issuer")   # NOT fatal here
  8. Ed25519_verify(anchor, Sig_structure)                            else CREDENTIAL_SIGNATURE_INVALID
  9. now < valid_from - CLOCK_SKEW_MAX_S                              else CREDENTIAL_NOT_YET_VALID
 10. now >= valid_until + CLOCK_SKEW_MAX_S                            else CREDENTIAL_EXPIRED
 11. -> (None, trust = "authenticated")
```

`CLOCK_SKEW_MAX_S = 300` applies to the validity window only. Step 7 is the trust split: an unknown issuer is **not** a malformed credential, so the session may continue for diagnostic display, but the key is never authorized and any receipt from it can never be `TRUSTED`.

## 5. Unknown merchant keys: display vs reject (explicit policy)

| Observation | Session | Receipt | UI |
|---|---|---|---|
| Issuer present in anchors, signature valid, in window | continues | can be `TRUSTED` | "Verified · {display_name}" |
| Issuer **not** in anchors, signature valid | continues (PoC) | outcome `UNVERIFIED_UNKNOWN_ISSUER`, error `CREDENTIAL_UNKNOWN_ISSUER`; stored as evidence, **never** trusted | "Unverified merchant — signing key not issued by Deceipt" + the raw display name, visually distinct |
| Issuer in anchors, signature invalid | abort (`ServerHello` rejected) | none | "Could not verify this terminal" |
| Issuer in anchors, expired / not-yet-valid | abort (outside skew) | none | "This terminal's certificate isn't currently valid" |

"Displayed as unknown" never renders the same affordance as "trusted", and never persists a trusted flag. `DESIGN.md` §5.3's separate sub-states (`signature_valid`, `key_authorized`, `credential_temporally_acceptable`, …) are preserved in storage; only the policy layer combines them (see `verification.md`).

## 6. Binding the credential to the session and the receipt

* The credential presented in `ServerHello` is hashed into the handshake transcript (`credential_hash = SHA-256(exact credential bytes)`, Pass C). Replacing the credential after the merchant signs breaks the transcript signature: `HANDSHAKE_SIGNATURE_INVALID`.
* The receipt embeds the **exact** credential bytes at label 20. The receiver MUST require byte equality with the session credential, else `RECEIPT_CREDENTIAL_MISMATCH`.
* The receipt's protected `kid` MUST equal `credential.device_key_id`, and `merchant.merchant_id` MUST equal `credential.merchant_id`; else `RECEIPT_KEY_NOT_AUTHORIZED`.
* The receipt `issued_at` MUST lie inside `[valid_from, valid_until)` (skew-adjusted), else `RECEIPT_OUTSIDE_KEY_VALIDITY`; and `issued_at ≤ now + 300`, else `RECEIPT_ISSUED_IN_FUTURE`.

## 7. Explicitly unresolved (escalated, not assumed)

These `DESIGN.md` §14 items are out of scope for the PoC and remain open. They MUST NOT be treated as solved by this pass:

| Item | Why unresolved | Consequence for the PoC |
|---|---|---|
| Production trust hierarchy (multiple roots, merchant-owned delegation) | requires a governance design, not a PoC choice | single pinned root; documented as test-only |
| Merchant enrollment & identity proofing | needs a real-world onboarding process | the test merchant is pre-provisioned out of band |
| Revocation model | needs distribution + freshness | no revocation is evaluated; a revoked-in-production key is indistinguishable |
| Historical validity / anti-backdating (§5.4) | needs trusted timestamping or transparency logs | a stolen key can backdate within its validity window; the PoC signature cannot detect it |
| Hardware-backed signing keys / migration off PoC Ed25519 | §4.4 defers; §14 provisional | PoC keys are software-held; A5 documents the Keystore fallback explicitly |

The UI and the acceptance report MUST state these limitations; A6 MUST NOT claim they are covered.
