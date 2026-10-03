# Deceipt PoC — final acceptance report (A6)

**Reviewer:** A6 (independent validation + security)
**Date:** 2026-10-03
**Scope:** independent conformance, adversarial, interop and security verification of the Deceipt
PoC at `deceipt-proto-r4` (`aggregate_sha256 3d4b812adc2b8eb71a2f62d444d45f981632d08c832d4d6b2519ece2f7b971c0`,
39 frozen files, commit `893dddd`).
**This is a PoC review, not a formal audit.** No third-party cryptography review was performed.

> **Revision note.** This report was first written against `r3`. My r3 review raised two major and
> two minor findings (F‑02, F‑06, F‑03/F‑04, F‑07) in the frozen CDDL/doc artifacts; A1 published
> `r4` with **zero serialization-byte change** (all frozen hashes — offer_hash `efdc44f3…d4c5`,
> transcript 372 B, transcript_hash `0f7ec363…4c3b`, receipt_body_sha256 `69255f58…8135`, LPdu
> 616 B/4 frags — identical) and fixed all four. **All findings in §3 below were re-run and verified
> closed against r4.** The r4 aggregate independently recomputes to `3d4b812a…b971c0`.

## Verdict up front

* The **frozen protocol revision is internally consistent and implementable**: every byte-level
  vector expectation I recomputed with an implementation wholly independent of A3/A4/A5 (Python +
  OpenSSL) matches. The four frozen-*artifact* defects I raised against r3 (F‑02, F‑06, F‑03/F‑04,
  F‑07) were all fixed in r4 with **zero serialization-byte change** and re-verified closed (§3).
* The **radio-independent gates pass on the shared app (A3) and iOS (A4)**: a valid receipt travels
  merchant → customer through two mock adapters and verifies to `TRUSTED`; **600/600 random
  mutations never become `TRUSTED`**; a validly-signed rogue receipt is `UNVERIFIED_UNKNOWN_ISSUER`,
  never trusted; a wrong-session credential/AAD/offer is rejected.
* **The Android implementation (A5) now passes all 25 of its frozen-vector JVM tests** (F‑09 closed;
  was 7 failures). The trust-relevant regression — a tampered issuer signature reported
  `authenticated` — was fixed and **independently confirmed by my own Python/OpenSSL verifier**
  (`CREDENTIAL_SIGNATURE_INVALID`, trust `none`, never `TRUSTED`); the signature-relevant
  `server_hello_max_frame_payload_unsigned` likewise now yields `HANDSHAKE_SIGNATURE_INVALID`.
  Both platforms pass the identical frozen r4 fixture set.
* **Gate 3 (physical cross-platform transfer) is BLOCKED** by a user-confirmed device constraint and
  is **not claimed**. See §2.

---

## 1. What was actually run (commands + observed results)

| # | Command | Observed | Verdict |
|---|---|---|---|
| R1 | `python3 tests/conformance/run_conformance.py` | **54 PASS / 0 FAIL** | independent runner works, r4 consistent |
| R2 | `python3 tests/security/run_security.py` | **30 PASS / 0 FAIL** | security invariants hold (H2 resolved structurally) |
| R3 | `cd app && npx tsc --noEmit && npx jest` | `tsc` exit 0; **8 suites, 205 tests, all pass** | A3 shared app green on mock adapters |
| R4 | `cd modules/deceipt-native/ios && swift test` | **46 tests, 0 failures** | A4 iOS radio-independent vectors pass |
| R5 | `cd app/android && ./gradlew :deceipt-protocol:testDebugUnitTest` | **25 tests, 0 failures — BUILD SUCCESSFUL** (was 7 then 4 failures) | A5 Android JVM vectors pass |
| R6 | frozen-vector reproduction (inside R1) | transcript 372 B, HKDF prk/okm/4 keys, 3 AEAD envelopes, 814-byte payload seal, Ed25519 sig, offer_hash all recomputed byte-identically | independent derivation confirmed |

**Independence.** The runner (`tests/conformance/runner/**`) implements deterministic CBOR,
COSE_Sign1, the receipt schema/arithmetic, credential trust, the handshake transcript, HKDF and
AEAD **from the normative docs and the frozen vectors only**. No expected value is read from the
implementation under test.

### 1.1 Disposition of the ten named adversarial cases (delegation plan §2/A6.4, §4)

Every case the plan names, with the vector/repro that decides it and its status. "UNVERIFIED"
always means the decision needs a radio or receiver-state/timing that a single byte string cannot
carry (the same cases `protocol/vectors/self-test.json#policy_only_cases` lists).

| # | Adversarial case | Vector / repro | Result |
|---|---|---|---|
| 1 | Multiple nearby merchants, no RSSI ranking, 2+ eligible fails closed | static: no RSSI in any selection path (`D1`/gate 7); `TRANSPORT_PEER_AMBIGUOUS` | **PASS** (static). On-device picker behaviour **UNVERIFIED** (needs a radio) |
| 2 | Wrong / stale / consumed / forged bootstrap | `handshake-invalid.json#wrong_transaction` (→`WRONG_TRANSACTION`) **PASS**; `binding_stale`/`binding_consumed`/`binding_unknown_session`/`binding_proof_invalid` | wrong-transaction **PASS**; session-registry cases **UNVERIFIED** (need A2 live/consumed/expired state) |
| 3 | Unknown merchant key (valid signature, unpinned issuer) | `credentials.json#unknown_issuer`; `receipt-invalid.json#unknown_issuer_credential`; `handshake-unverified-peer.json` | **PASS** — `UNVERIFIED_UNKNOWN_ISSUER`, `key_authorized=false`, never `TRUSTED` (`B3`/`C9`) |
| 4 | Invalid signature | `receipt-invalid.json#receipt_signature_tampered`; `credentials.json#issuer_signature_tampered`; `handshake-invalid.json#transcript_signature_tampered` | **PASS** — `RECEIPT_SIGNATURE_INVALID` / `CREDENTIAL_SIGNATURE_INVALID` / `HANDSHAKE_SIGNATURE_INVALID` |
| 5 | Modified ciphertext / frames | `aead-invalid.json#payload_ciphertext_bit_flipped`, `payload_tag_bit_flipped`, `control_ciphertext_flipped`; `security V1/V2` | **PASS** — `AEAD_AUTH_FAILED`; 600/600 mutations never `TRUSTED` |
| 6 | Replayed / cross-session frame | `aead-invalid.json#control_counter_replayed` (`AEAD_REPLAY_DETECTED`), `payload_aad_mismatch` (`AEAD_AUTH_FAILED`, cross-session transfer_id); `framing-invalid.json#sequence_replayed_identical` | counter replay + cross-session **PASS**; frame-sequence sliding-window replay **UNVERIFIED** (receiver state) |
| 7 | Oversized declared length | `receipt-invalid.json#receipt_oversize_raw`/`receipt_oversize_signed` (`RECEIPT_SIZE_EXCEEDED`); `framing-invalid.json#declared_ciphertext_above_bound`/`too_many_frames`; `frame_size_above_*` | **PASS** — rejected before parse/allocation |
| 8 | Incomplete fragment set | `framing-invalid.json#incomplete_frame_set` (`TRANSFER_INCOMPLETE`); `lpdu-invalid.json#reassembly_timeout` | **UNVERIFIED** off-radio — receiver-state/timeout policy (`policy_only_cases`) |
| 9 | Unsupported version | `receipt-invalid.json#receipt_version_2` (`RECEIPT_UNSUPPORTED_VERSION`); `handshake-invalid.json#unsupported_protocol_version` (`HANDSHAKE_UNSUPPORTED_VERSION`) | **PASS** |
| 10 | Duplicate import | `receipt-invalid.json#identical_reimport` (`ALREADY_IMPORTED_IDENTICAL`), `#duplicate_receipt_id_different_bytes` (`RECEIPT_DUPLICATE_CONFLICT`) | **PASS** |

**No case silently becomes "trusted":** across all ten, every decidable byte-level outcome is a
typed error or a non-trusted outcome; the three UNVERIFIED rows need device/receiver-state, and
none of them is reported as passing.

---

## 2. Completion-gate status (delegation plan §4)

| # | Gate | Status | Deciding evidence |
|---|---|---|---|
| 1 | One shared RN/TS app builds for iOS and Android with working native BLE + crypto adapters | **PASS (radio-independent) / UNVERIFIED (radio)** | Shared TS `tsc`+8 suites/205 tests pass (R3); iOS Swift 46/46 (R4); Android `:deceipt-protocol` 25/25 (R5). Physical BLE peripheral/central behaviour **UNVERIFIED** (no radio), so the "working native BLE adapters" half is not claimed. |
| 2 | One documented wire revision + fixture set used by both platforms | **PASS** | `REVISION.json` r4, 39 files, 0 hash mismatches, aggregate recomputes; **all three** implementations reproduce the same bytes: A6 independent runner 54/54 (`D9`/`D9b`/`D9d`), A4 iOS 46/46, A5 Android 25/25 (F‑09 closed). |
| 3 | iOS merchant → Android customer **and** Android → iOS on physical phones | **BLOCKED** | User-confirmed: no Android device and no usable Android emulator (Android emulators cannot do BLE peripheral/advertising); only one iPhone, unavailable to the toolchain. Recorded in `tests/interop/matrix.json` (I6–I9). **Not claimed.** |
| 4 | BLE payload encryption verified; no trust merely from decryption | **PASS (radio-independent part)** | AEAD open is followed by steps 8–14; 600/600 mutations never TRUSTED (`V1`/`V2`); `E2`. On-device part UNVERIFIED. |
| 5 | Ed25519 verify **plus** merchant-key trust binding required for trust | **PASS** | `B3`/`C9`: valid signature + unpinned issuer → `UNVERIFIED_UNKNOWN_ISSUER`, `key_authorized=false`; `TRUSTED` requires both (`A2`+`B1`). |
| 6 | Wrong transaction / malformed / tampered / replay/cross-session → rejected | **PASS (radio-independent part)** | 45/45 receipt vectors; 8/8 AEAD; 18/18 handshake byte cases; `V5`; `wrong_transaction_*`. On-device replay timing UNVERIFIED. |
| 7 | No RSSI-based implicit selection; 2+ eligible fails closed | **PASS (static)** | No source path ranks by RSSI; RSSI is `diagnostics_only`; QR-mandatory selection; `TRANSPORT_PEER_AMBIGUOUS` fails closed. On-device UNVERIFIED. |
| 8 | Receipt imports exactly once; disconnect/cancel leaves no half-imported trusted receipt | **PARTIAL** | `identical_reimport` → `ALREADY_IMPORTED_IDENTICAL`; conflict → `RECEIPT_DUPLICATE_CONFLICT`; atomicity documented. Disconnect/cancel mid-transfer is state/timing → UNVERIFIED off-radio. |
| 9 | Keys + receipts survive restart; no key/session material in committed files or ordinary logs | **PARTIAL** | No log sinks at all (`L1`/`L2`); no test private key in app/native sources (`B9a`); Keychain `ThisDeviceOnly` + `allowBackup=false`. Restart persistence is device behaviour → UNVERIFIED. One hygiene finding (H2). |
| 10 | Build commands, device/OS matrix, permission setup, demo script recorded; limitations stated | **PASS** | `tests/interop/README.md`, `tests/interop/matrix.json`, `docs/demo/demo-script.md`, this report. |

**Gate 3 — explicit BLOCKED reason.** The user confirmed there is no Android device and no usable
Android emulator, and that Android emulators cannot perform BLE peripheral/advertising; only one
iPhone exists and it is currently unavailable to the toolchain, with the iOS simulator (which
cannot advertise) directed as the fallback. The user directed that gate 3 be documented as blocked
with evidence rather than claimed. No device result is fabricated anywhere in this report.

---

## 3. Findings

Severity: **blocker** (cannot proceed) / **major** (breaks a stated guarantee) / **minor**
(inconsistency, no runtime trust impact). Owner fixes; A6 re-runs.

### F-01 — Android JVM vector path: config blocker CLOSED, vector failures remain — **major** (superseded by F‑09)
* **Owner:** A5 · **Target:** `modules/deceipt-native/android/build.gradle`, `:deceipt-native` Kotlin sources
* **Invariant:** conformance §F / delegation gate 2 — A5 must pass the **same** frozen vectors as A4
  on its radio-independent JVM path.
* **First run (r3):** `:deceipt-native` failed at configuration —
  `Namespace 'com.deceipt.native' is not a valid Java package name as 'native' is a Java keyword'`
  and missing `compileSdk`; zero Android tests executed.
* **Resolution:** A5 split the radio-independent protocol/crypto core into a pure-Kotlin
  **`:deceipt-protocol`** module (namespace `com.deceipt.adapter.protocolcore`, BouncyCastle Ed25519,
  no RN dependency). It now **configures and runs**. The residual failure is no longer a build defect
  but vector disagreements — tracked as **F-09**.

### F-09 — Android JVM vector suite diverged from the frozen r4 vectors — **major** (CLOSED)
* **Owner:** A5 · **Target:** `modules/deceipt-native/protocol/**`
* **Invariant:** conformance §F / gate 2 — the *same* frozen vectors must pass on both platforms.
* **Repro:** `cd app/android && ./gradlew :deceipt-protocol:testDebugUnitTest`
* **History:** 24 tests / 7 failed → 25 tests / 4 failed → **25 tests / 0 failures (BUILD
  SUCCESSFUL)**. The trust-relevant case (`issuer_signature_tampered` reporting `authenticated`) was
  fixed first and **independently confirmed by A6's own Python/OpenSSL verifier**
  (`CREDENTIAL_SIGNATURE_INVALID`, trust `none`; the full receipt path → `REJECTED`). The last
  signature-relevant case `server_hello_max_frame_payload_unsigned` now yields
  `HANDSHAKE_SIGNATURE_INVALID` (also independently confirmed). A5 added regression test
  `tampered_issuer_signature_never_reports_authenticated`.
* **Result:** both platforms now pass the identical frozen r4 fixture set.

### F-08 — A3 HMAC conformance test asserted the wrong RFC 4231 constant — **minor** (CLOSED)
* **Owner:** A3 · **Target:** `app/tests/protocol.hashing.test.ts`
* **Invariant:** a conformance test must compare against the correct published constant.
* **Detail:** the test computed HMAC over RFC 4231 **case 1** inputs (key = 20×`0x0b`, msg =
  "Hi There") but asserted `HMAC_SHA256_RFC4231_CASE2 = 5bdcc146…3843`, which is **case 2** (key
  "Jefe"). My independent computation gave HMAC-SHA-256(`0x0b`×20, "Hi There") = `b0344c61…cff7` —
  exactly what `hmacSha256Pure` returned, so **the implementation was correct and the constant was
  wrong.** No protocol impact (HMAC is the A2 binding proof, computed natively; the shared HMAC
  exists for the mock adapters/tests).
* **Resolution:** A3 renamed the constant to CASE1 and added a genuine case-2 assertion (both
  `b0344c61…cff7` and `5bdcc146…3843`) at `c37b03a`. Re-verified: `npx jest` → **8 suites / 205
  tests, all pass**; `npx tsc --noEmit` → exit 0.

### Closed in r4 — my r3 findings (re-run, verified)
A1 published `deceipt-proto-r4` with **no serialization-byte change** and fixed all four:

| Finding | r4 resolution | Verification |
|---|---|---|
| **F-02 (major)** CDDL `server-hello` omitted labels 10/11 | CDDL now declares `10 : bstr` (binding_tuple, authoritative) and `11 : uint .le 512` (max_frame_payload) | conformance `F-02` **PASS** (cddl labels `[1..11]`) |
| **F-06 (major)** `tz_offset_minutes` units/bound conflicted with the valid vector | spec/CDDL/fields now all read `-50400..50400`, **units = SECONDS** (name historical), matching the vector's `-14400` | conformance `F-06` **PASS**; vector tz `-14400` accepted |
| **F-03 / F-04 (minor)** CDDL headers said `r1` | all three CDDL headers (`wire-v1`, `receipt-v1`, `credential-v1`) bumped to `r4` | conformance `F-03`/`F-04` **PASS**; `D10` clean |
| **F-07 (minor)** `wire.md` §7 fragment figures | corrected to `616 B / 4 fragments 178/178/178/82`, matching `lpdu-valid.json` | conformance `F-07` **PASS** |

The r4 aggregate `3d4b812a…b971c0` recomputes from the 39 pinned files with zero mismatches
(conformance `D9`/`D9b`), and every vector file declares `deceipt-proto-r4` (`D9d`).

### H2 — tracked Android debug keystore — **minor / hygiene** (RESOLVED as a narrow, enforced exception)
* **Owner:** A0 · **Target:** `app/android/app/debug.keystore` (git-tracked)
* **Nuance:** it is the standard **Android SDK debug keystore** (JKS, one `androiddebugkey` entry,
  conventional password `android`, no secret content). `app/android/app/build.gradle:90`
  (`storeFile file('debug.keystore')`) requires the file to exist, so untracking it breaks a
  clean-clone Android debug build — untracking is not a free win.
* **Resolution (not a blanket pass):** both suites now fail on **any** tracked
  `*.keystore`/`*.jks`/`*.pem`/… file **except** this one path, and they independently re-open the
  allow-listed file with `keytool` and require a single-`androiddebugkey` JKS. I proved the exception
  is not blanket by generating a release-style keystore (different alias/password) and confirming the
  checker rejects it. The justification is stated in `docs/security/repo-hygiene.md` §"Permitted
  exception: the Android debug keystore".
* **Repro / evidence:** `run_security.py` → `H2` (no violations) and `H2b`
  (`entries=1 androiddebugkey=True`); `run_conformance.py` → `B9b` PASS.

### Closed — earlier A6 findings, re-verified on r4 (do not re-report)
Verified against the frozen r4 files, not against any changelog:

| Finding | Verification |
|---|---|
| RX-03 (CDDL final-frame rule) | **CLOSED** — `wire-v1.cddl` now carries `frame-payload-nonfinal = bytes .size (16..512)` / `frame-payload-final = bytes .size (1..512)` (conformance `RX-03`, PASS). |
| R2-03 (SERVER_HELLO duplicate label row) | **CLOSED** — field-table labels are unique and ascending `[1..11]` (conformance `R2-03`, PASS). |
| R7-02 (plaintext ACK worked example) | **CLOSED** — `wire.md` §7 now prints the AEAD envelope; I independently decrypt `framing-valid.json#ack_envelope_hex` under `k_c2m_ctrl` counter 0 and reproduce the ACK CBOR (conformance `R7-02`, PASS). |
| R4-01 (transcript reconstructibility) | **CLOSED** — I rebuild the 372-byte transcript from received plaintext only and it equals the signed bytes (conformance `C1`, PASS). |
| R1-02 (unknown-issuer reachable, never trusted) | **CLOSED** — `handshake-unverified-peer.json` transcript signature verifies against the credential's self-asserted device key, issuer unpinned, outcome `UNVERIFIED_UNKNOWN_ISSUER`, `must_never_be: TRUSTED` (conformance `C9`/`B3`, PASS). |
| R2-01 (single `offer_hash` definition) | **CLOSED** — recomputed in array order `[session_id,transfer_id,receipt_id,ref,total,currency,issued_at]`, equals `efdc44f3…d4c5` (conformance `C11`, PASS). |
| R2-02 (`transcript_layout.label` = 20 B) | **CLOSED** — label size 20, offsets 218/250/285 (conformance `C2b`, PASS). |
| R1-01 (anchor vs device key) | **CLOSED** — anchor `bd65615a…`; `valid-credential.cbor` verifies under the anchor and **fails** under the device key `61d36a10…` (conformance `B11c`, PASS). |
| R5-01 (`k_m2c_payload` one-shot) | **CLOSED** — stated in `handshake.md` §6.2 and `bounds-v1.json#wire.k_m2c_payload_usage`; the payload AAD carries no counter (design consistent). |
| R7-01 (duplicate offer-mismatch error) | **CLOSED** — `RECEIPT_OFFER_MISMATCH` absent from `errors.json` (91 errors); only `WRONG_TRANSACTION` (`0x0614`). |
| RX-02 (`protocol/flows/**` in freeze) | **CLOSED** — in the r4 hash scope; 0 mismatches. |
| RX-04 (P0 picker wire realisation) | **CLOSED** by A2 — QR-mandatory v1, QR-less path removed. |

---

## 4. Security invariants reviewed (radio-independent)

| Area | Result |
|---|---|
| **Key storage — iOS** | Keychain generic-password item, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; never UserDefaults/files; no Secure Enclave claim (honestly reported `keychain_software`). PASS |
| **Key storage — Android** | Direct Ed25519 **probed** (API 33+), else fallback: app-generated seed wrapped by a device-bound Keystore AES-256-GCM key in private app storage, `setReadable(false,false)`; seed zeroized. Explicitly **not** hardware-backed non-exportable. PASS |
| **Bridge payloads** | No seed/session-key field crosses the bridge (contract, mock, iOS backend — comments excluded); sessions keyed by opaque handles. PASS |
| **Logs / crash output** | **No** `NSLog`/`console.log`/`Log.*`/`println` sink anywhere in native or shared code; none referencing key material. PASS |
| **Backup exposure** | Android `allowBackup="false"`; iOS Keychain `ThisDeviceOnly` (excluded from iCloud/encrypted backups). PASS |
| **Parser / resource bounds** | CBOR depth 12 / items 8192 / text 4096 / bytes 65536; receipt 65536; transfer 65552 / 32768 frames / 2048 PDU / window 64. Independence-checked depth bomb rejected. PASS |
| **Repo hygiene (public)** | `.gitignore` covers key material; no plaintext secret in tracked files; only the labelled `_TESTONLY` test root private exists and it is absent from the app. `debug.keystore` accepted only via the structurally-enforced exception (H2 resolved). PASS |
| **No failure path reaches verified** | 400 single-bit + 200 byte-flip mutations → 0 TRUSTED; wrong session credential → `RECEIPT_CREDENTIAL_MISMATCH`; unknown issuer → `UNVERIFIED_UNKNOWN_ISSUER`; every committed offer member mutation → `WRONG_TRANSACTION`; oversized → `RECEIPT_SIZE_EXCEEDED` before parse. PASS |

---

## 5. Limitations (state these; none is covered by a passing gate)

1. **No physical-device evidence.** Gates 3 and all on-device rows are BLOCKED/UNVERIFIED (§2).
2. **PoC review only.** No external cryptographic audit; the protocol is unproven against a
   determined adaptive attacker.
3. **No relay resistance claimed.** A relay can forward bytes; it cannot forge a receipt signature,
   and an unknown-key receipt can never become trusted, but relay/coercion resistance is not a PoC
   property.
4. **No revocation model.** A revoked-in-production key is indistinguishable (`trust.md` §7).
5. **Anti-backdating out of scope.** A stolen key can backdate within its validity window.
6. **Test anchor is a test root.** Generated from an ASCII label; production roots are offline-only.
7. **Android fallback keys are software-held.** Not Secure-Enclave/StrongBox non-exportable.
8. **Radio-independent ≠ end-to-end.** R3/R4 prove shared bytes and verification logic agree across
   three implementations; they do not prove a receipt crossed a Bluetooth link.
9. **`protocol/flows/**` residual metadata.** A2-owned files may still name an earlier revision in
   prose (metadata only; no binding byte differs) — owner action, not a byte-level inconsistency.

---

## 6. Artifacts

* `tests/conformance/run_conformance.py` + `tests/conformance/runner/**` — independent runner (revision-agnostic).
* `tests/conformance/results/conformance.{json,md}` — 54 PASS / 0 FAIL, per-check.
* `tests/security/run_security.py` + `tests/security/results/security.{json,md}` — 30 PASS / 0 FAIL.
* `tests/interop/matrix.json` + `tests/interop/README.md` — cross-platform matrix with BLOCKED/UNVERIFIED columns.
* `docs/demo/demo-script.md` — demo (radio-free parts runnable; physical part marked BLOCKED).
* `docs/security/early-contract-review.md` — earlier two-pass contract review (r1→r2 findings, re-verified closed in this report).
