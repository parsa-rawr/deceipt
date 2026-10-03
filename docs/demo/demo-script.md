# Deceipt PoC — demonstration script (A6)

**Revision:** `deceipt-proto-r4` · **Status:** PoC review, not a formal audit.
**Device reality (read first):** there is **no Android device and no usable Android emulator**, and
only one iPhone which is currently unavailable to the toolchain. Android emulators cannot do BLE
peripheral/advertising at all. Therefore the *physical* demo (Part C) is **BLOCKED / UNVERIFIED**.
Parts A and B run today, without a radio, and are the ones whose output is quoted as evidence.

---

## Part A — What runs now (no radio)

### A.0 Prerequisites
```bash
cd /Users/mateo/CODE/Deceipt
python3 -c "import cryptography"        # OpenSSL-backed, independent of the app
cd app && npm ci                        # only if node_modules is absent
```

### A.1 Verify the frozen revision is intact
```bash
python3 tests/conformance/run_conformance.py
```
Expected: `D9*` PASS — all 39 pinned files hash-match and the aggregate recomputes to
`3d4b812a…b971c0`.

### A.2 Valid delivery (byte-level, shared app through mock adapters)
```bash
cd app && npx jest tests/checkout.e2e.test.ts
```
This drives merchant → customer entirely through `InMemoryDeceiptNative` (no radio): the frozen
valid receipt is offered, transferred, AEAD-opened, **verified** and stored as `TRUSTED`.
Expected: suite passes; a `TRUSTED` row exists with the sub-states persisted.

### A.3 Tampering rejection
```bash
python3 tests/security/run_security.py
```
Watch `V1`/`V2`: 600 random single-bit and byte-flip mutations of the valid receipt are run through
the independent verifier — **0 of 600 become TRUSTED**. `V7`: an oversized container is rejected
before any parse.

### A.4 Wrong-session / wrong-transaction rejection
```bash
python3 tests/conformance/run_conformance.py
```
Watch `V5`-equivalent row `A5-A14` (`wrong_transaction_*`) and `C6/C7` (`payload_aad_mismatch` — a
cross-session transfer_id AAD mismatch is `AEAD_AUTH_FAILED`). Mutating any committed offer member
(`receipt_id`, `kind`, `total`, `currency`, `issued_at`, `merchant_id`, `merchant_reference`)
yields `WRONG_TRANSACTION`; no such case stores anything trusted.

### A.5 Unknown-issuer: valid signature is still not trust
```bash
python3 tests/conformance/run_conformance.py      # row B3 / C9
```
A structurally perfect rogue receipt (valid signature, unpinned issuer) is surfaced as
`UNVERIFIED_UNKNOWN_ISSUER`, `key_authorized = false`, and **can never** be `TRUSTED`.

### A.6 Persistence after restart
```bash
cd app && npx jest tests/checkout.e2e.test.ts
```
The receipt store persists `receipt_id → exact signed payload bytes` plus the verification
sub-states. A byte-identical re-import yields `ALREADY_IMPORTED_IDENTICAL` (idempotent, no duplicate
row); a same-`receipt_id`/**different**-bytes import yields `RECEIPT_DUPLICATE_CONFLICT`.
Restart-safety of the *key* store is platform behaviour (Keychain `AfterFirstUnlockThisDeviceOnly`,
Android Keystore) and is **UNVERIFIED** here because it needs a device restart.

---

## Part B — Native, still no radio

### B.1 iOS (A4)
```bash
cd modules/deceipt-native/ios && swift test
```
Expected: 46 tests, 0 failures — transcript rebuild from received plaintext, HKDF schedule, AEAD
sealing, Ed25519 receipt verification, unknown-issuer session typing.

### B.2 Android (A5) — **currently BLOCKED**
```bash
cd app/android && ./gradlew :deceipt-native:testDebugUnitTest
```
Currently fails at configuration:
`Namespace 'com.deceipt.native' is not a valid Java package name as 'native' is a Java keyword` and
`project ':deceipt-native' does not specify compileSdk`. Owner: **A5** (finding F-01). Re-run after
the package rename to `com.deceipt.adapter` lands.

---

## Part C — Physical-device demo — **BLOCKED / UNVERIFIED**

> Do **not** present any of Part C as having been performed. It cannot be run in this environment.

**Setup (when devices exist):** two phones (one iOS, one Android), Bluetooth on, camera permission
granted, Deceipt built on both.

| step | action | expected |
|---|---|---|
| C1 | Merchant screen → *Start transfer*; customer → *Scan receipt QR* | QR shown; customer camera opens |
| C2 | Customer scans the QR | one session selected by the QR; **no RSSI ranking** anywhere |
| C3 | Customer confirms the offer (merchant + total shown as untrusted display data) | `session_id` matched; ACCEPT sent inside the AEAD envelope |
| C4 | Receipt transfers and verifies | outcome `TRUSTED`; merchant name + total shown |
| C5 | Tamper test: flip a ciphertext byte in the DATA path | transfer aborts `AEAD_AUTH_FAILED`; nothing stored trusted |
| C6 | Wrong-session test: scan merchant A's QR, accept merchant B's offer | `WRONG_TRANSACTION` / `TRANSFER_ID_MISMATCH`; nothing stored trusted |
| C7 | Restart the customer app | saved receipt + `TRUSTED` state still present; merchant key still present |
| C8 | With two eligible terminals advertising, attempt selection | display-only guidance ordered by `peripheral_id`; same-`session_id` ambiguity fails closed `TRANSPORT_PEER_AMBIGUOUS` |

Every row above is **UNVERIFIED** until a physical pair exists. The blocked reason is recorded in
`tests/interop/matrix.json` and `docs/security/final-acceptance-report.md`.

---

## Limitations to state aloud during any demo

* This is a **PoC review, not a formal audit**; no third-party cryptography review was performed.
* BLE is an **untrusted transport**: successful decryption is never trust (invariant 2), and the
  demo must be shown to reject a validly-encrypted-but-unverifiable receipt.
* **Relay/resistance is not claimed.** The PoC does not claim relay-attack resistance; a relay can
  forward bytes, though a relay cannot forge a receipt signature or an unknown-key receipt as trusted.
* The pinned trust anchor is a **test root** generated from an ASCII label. Production roots are
  generated offline; no production private key exists in the repo.
* **No revocation** is evaluated, and **anti-backdating is out of scope** — a stolen key can backdate
  within its validity window (`trust.md` §7).
* Android key storage on the fallback path is **not** hardware-backed non-exportable; it is a seed
  wrapped by a device-bound Keystore AES key (`docs/security/android-key-storage.md`).
