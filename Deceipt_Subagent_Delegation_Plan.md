# Deceipt PoC — Subagent Delegation Plan

**Revision 2 — 2026-10-03.** Supersedes rev 1, which was written while the repository was unreachable and therefore guessed at paths and left the spec unread. Rev 2 is grounded in the live tree, read directly.
**Status:** planning only. No subagents launched. This document authorizes nothing; the coordinator (A0) dispatches.

---

## 0. Live-repo ground truth (verified by direct read, 2026-10-03)

| Fact | Evidence |
|---|---|
| Project root is `/Users/mateo/CODE/Deceipt` and contains **exactly two files** | directory listing: `DESIGN.md` (25,591 B), `deceipt-crypto-ble.mmd` (2,390 B) |
| `DESIGN.md` is the spec: 881 lines, self-declared "Status: Draft v0.1 — planning only" | read in full (§1–§16) |
| `deceipt-crypto-ble.mmd` is the authoritative flow diagram (merchant phone A, BLE/GATT, customer phone B) | read in full |
| There is **no repository at all yet**: no `.git`, no branches, no worktrees | `git status` → `fatal: not a git repository` |
| There is **no `AGENTS.md`**, no repo instructions, no `package.json`, no app scaffold | root listing; no config files matched |
| Both files are mode `0600` and untracked → a single-disk failure destroys the spec | `ls -la` |

**Canonical remote (user-directed, 2026-10-03):** `https://github.com/parsa-rawr/deceipt.git` — verified **empty**, **public**, default branch unnamed, created 2026-10-03T19:12:38Z. Local root stays `/Users/mateo/CODE/Deceipt`; A0 pushes `main` there.

**Public-repo consequence (now load-bearing):** the spec, the vectors, and everything else are world-readable. `.gitignore` MUST exclude `*.pem`, `*.key`, `*.p12`, `*.jks`, `*.keystore`, `*.mobileprovision`, `*.cer`, `*.pfx`, `keys/`, `secrets/`, `.env*`, keychain stores, and any generated merchant key store. Test-only deterministic keys in `protocol/vectors/` are permitted only when each file states in-header that the material is test-only and must never be reused. No real merchant key, session key, or production trust-root material may ever be committed. A6 gates this (see §4 gate 9).

**A0's first actions, before any dispatch:** `git init` at the project root, commit `DESIGN.md` + `deceipt-crypto-ble.mmd` as the baseline, and only then create the per-agent worktrees. Rev 1 assumed these existed; they do not.

### What the spec actually fixes vs. leaves open

Already decided in `DESIGN.md` (do not re-litigate; implement as written):

- Merchant A = BLE **peripheral + GATT server**; customer B = BLE **central + GATT client** (§7.1). This is the PoC role assignment and is confirmable only by A4/A5's hardware spike, not assumed.
- **Ed25519** for receipt signatures, carried as COSE `EdDSA` — a PoC **decision**, not provisional (§4.4).
- iOS key storage: CryptoKit `Curve25519.Signing.PrivateKey`, private material in Keychain, no Secure Enclave claim (§4.4).
- Android: direct Keystore Ed25519 if the device/API supports it, else app-generated key wrapped by a Keystore AES key — **explicitly not** hardware-backed non-exportable (§4.4).
- Receipt identity: random, globally unique receipt ID; used for dedup/idempotency (§4.5).
- 11 stable architectural commitments (§13) — including "receipt format is transport-independent", "decryption ≠ trust", "exact signed bytes are authoritative", "RSSI cannot select or authenticate".
- Verification order fixed at 16 steps, with **no failure path falling through to verified** (§9).
- Threat model with 9 named adversaries and their mitigations (§10).

Provisional in `DESIGN.md` (§14) — A1 must finalize, not assume:

- deterministic CBOR as receipt/control encoding (§4.2, tentative);
- COSE_Sign1 as the signed container (§4.3, tentative);
- transfer session suite: P-256 ECDH + HKDF-SHA-256 + AES-256-GCM + SHA-256 transcript (§6.2, tentative);
- exact key schedule, directional keys, nonce construction, transcript canonicalization, replay window (§6.4 — "Do not improvise these details during implementation");
- merchant device credential format and the PoC trust-bootstrap rule (§5.1–§5.2);
- the three-characteristic GATT layout; **all UUIDs are unassigned** (§7.4);
- candidate-ambiguity disambiguation path in production (§7.3 gives the PoC rule only);
- revocation model; anti-backdating/historical validity (§5.4, out of scope for the PoC).

`DESIGN.md` §15 prescribes four design passes before implementation: **A** receipt schema, **B** trust hierarchy, **C** handshake byte-for-byte, **D** UUID/wire identifiers. These are A1's gate, not a preamble to skip.

### Non-negotiable invariants (violation ⇒ agent output rejected)

1. One shared React Native/TypeScript app for iOS and Android. **No separate SwiftUI app, no separate Android UI app.**
2. BLE is an untrusted transport. Successful AEAD decryption never yields a trusted receipt.
3. Trust requires merchant receipt signature over the **exact received bytes** plus merchant-key authorization. Never re-encode-then-verify.
4. Long-lived merchant signing keys are never reused for session key agreement (§2.4).
5. **RSSI is never** a selection, association, or trust signal (§2.5, §7.3).
6. Ambiguous peer association **fails closed** (§7.3).
7. Parser/allocation bounds are security requirements, not polish (§13.11).
8. Merchant private keys and session secrets never enter committed files, ordinary logs, or the JS bridge payload.

---

## 1. Ownership map (real paths)

Paths below are the layout A0 will create at the project root. Where a convention exists, it follows `DESIGN.md` §15 ("A. Define DeceiptReceiptV1", etc.). Nothing exists yet, so these are proposals A0 confirms at dispatch — but the *scopes* are exclusive and firm.

| Agent | Owns (exclusive write scope) | Starts after |
|---|---|---|
| **A0** Coordinator/integrator | `package.json`, `tsconfig.json`, `app.json`, `metro.config.js`, `Podfile`, root Gradle wiring, `docs/status/`, `docs/decisions.md` | immediately |
| **A1** Protocol + receipt contract | `docs/protocol/**`, `protocol/schema/**`, `protocol/vectors/**` | A0 baseline commit |
| **A2** Transaction binding + checkout flow | `docs/flows/**`, `protocol/flows/**` | A0 baseline commit; co-signs with A1 before freeze |
| **A3** React Native app | `app/src/**`, `app/App.tsx`, `app/tests/**`, `modules/deceipt-native/index.ts` (bridge types only) | A1/A2 contract freeze; bridge contract drafted early |
| **A4** iOS native adapter | `app/ios/**`, `modules/deceipt-native/ios/**` | frozen wire + bridge revisions |
| **A5** Android native adapter | `app/android/**`, `modules/deceipt-native/android/**` | same revisions as A4 |
| **A6** Independent validation + security | `tests/conformance/**`, `tests/interop/**`, `tests/security/**`, `docs/security/**`, `docs/demo/**` | draft review immediately; final run after integration |

**A3's contract file is the seam.** `app/src/native/DeceiptNative.ts` is drafted by A3 and implemented identically by A4 and A5; neither A4 nor A5 may extend it unilaterally. Root config changes go through A0 only.

Max 4 concurrent implementation workers + A0. A6 runs two short bursts, not continuously.

---

## 2. Role briefs

### A0 — Coordinator / integrator

**Task.** Turn a two-file draft into a buildable, demonstrable PoC.

1. `git init`; commit `DESIGN.md` + `deceipt-crypto-ble.mmd` as the baseline (`DESIGN.md` is the only spec and it is untracked/mode 0600 — commit it first).
2. Choose the React Native flavor: a workflow that permits **custom native modules** (BLE peripheral/advertising + platform crypto). Do not assume a managed runtime is sufficient. Verify current official RN, iOS, and Android docs before pinning versions.
3. Create the directory layout in §1 and one worktree/branch per agent.
4. Record unresolved spec items as decisions with owners (see §5), not as platform-local choices.
5. Freeze **one** protocol revision (schema + vectors + state machine + binding + typed errors) after A6's early review, then dispatch A3/A4/A5 against the identical revision hash.
6. Dispatch A6 against a named integrated commit; route defects back to the owning agent.
7. Run the demo on physical devices and report device/OS matrix + limitations.

**Deliverables.** Baseline commit; ownership map; decision log (`docs/decisions.md`); integrated code; reproducible build commands; final acceptance report referencing §4 gates.
**Done when.** All §4 gates pass, or the report names each blocked gate with the evidence that blocked it.

### A1 — Protocol and receipt contract

**Task.** Close `DESIGN.md` §15 passes **A, B, C, D** and produce bytes both phones implement identically.

1. **Pass A — `DeceiptReceiptV1` schema.** Merchant/location fields, timestamps, currency, monetary representation, line items, discounts, taxes, tips, totals, payment summary, refunds/voids, extensions, identifiers/references. Monetary values as `amount_minor` integers + currency code; **no binary floating point** (§4.2). Fractional quantities need an exact schema-level representation.
2. **Pass B — trust bootstrap.** Credential = merchant ID, device key ID, device public key, validity start/end, capabilities, version, issuer, issuer signature (§5.2). Root key never ships in the app (§5.1). For the PoC, define the deliberate test-merchant provisioning: which public key is pre-trusted, and how unknown keys are displayed vs. rejected. State plainly that a supplied key + valid signature does not prove merchant identity.
3. **Pass C — handshake byte-for-byte.** Canonical transcript, algorithm identifiers, HKDF `info`/salt, directional AEAD keys, nonce/counter construction, replay window, message size limits, timeouts, teardown, failure transitions. Follow §6.3/§6.4 as written. Encrypted-only vs. authenticated-peer sessions must be distinguishable in the type system.
4. **Pass D — wire identifiers.** Assign the Deceipt Transfer Service UUID and the three characteristic UUIDs (§7.4 lists them unassigned), plus message type IDs and transfer-ID rules.
5. **Framing.** `DataFrame{transfer_id, sequence_number, payload_bytes}` (§8.5); frame size from negotiated MTU, never a fixed ATT MTU; flow control per §8.6 (`highest_contiguous_sequence`); bounded retry; cancellation; disconnect semantics. Bind to A2's transaction-selection contract.
6. **Vectors.** Valid **and** invalid fixtures with exact signed bytes: test-only deterministic keys/nonces, expected signatures, AEAD ciphertexts, framing examples, expected typed errors. Production sessions use fresh randomness.
7. **Semantics.** Verification outcomes, transport events, import idempotency — transport-independent so A4/A5 can differ in type names but not meaning.

**Deliverables.** Frozen protocol revision + conformance checklist consumed by A3/A4/A5/A6.
**Done when.** A4 and A5 can reproduce envelope, signature verification, handshake transcript, and framing with **zero** protocol gaps. If A1 leaves anything to "reasonable judgment", the gate fails.

### A2 — Transaction binding and checkout flow

**Task.** Make the intended merchant *and* transaction unambiguous with minimum friction.

1. `DESIGN.md` does not fix a binding mechanism; §7.3 fixes only the ambiguity rule. Propose **one** primary PoC flow and publish its exact binding bytes and expiration before A1 freezes the wire contract.
2. **Proposed fallback (unagreed, A1/A0 must adopt or replace):** customer scans a merchant transaction QR to obtain a fresh transaction reference + session-binding material, then the receipt travels over BLE. QR is selection/bootstrap only — the demo must still exercise BLE delivery. Label this a proposal, not a decision.
3. Define: how the bootstrap identifies the exact BLE session and intended receipt; what proves possession of the binding material; how stale/consumed bindings fail. Keep **session binding distinct from merchant-key trust**.
4. States: `ready, selecting, connecting, transferring, verifying, saved, recoverable failure`. User-visible behavior for wrong terminal, expired transaction, denied permission, cancellation, Bluetooth off.
5. Merchant demo flow (synthetic receipt) and customer flow showing merchant + total + verification status without exposing crypto internals.
6. Report friction as an **observed step count**, not a claimed "zero taps".

**Done when.** With competing nearby merchants present, a user intentionally selects one transaction, and no code path ranks by RSSI.

### A3 — React Native app and shared contracts

**Task.** Build the single shared app.

1. Publish `app/src/native/DeceiptNative.ts` — the one typed adapter contract — **before** A4/A5 start: key ops, sign/verify over exact bytes, session start/stop, transfer/cancel, capability reporting, typed connection/transfer/error events.
2. Keep merchant keys and session secrets in native code. The bridge returns public identifiers, signatures, verification results, and bounded receipt bytes. Native owns handshake crypto, nonce/sequence state, BLE callbacks, fragmentation, bounded buffers. **Never one bridge call per BLE fragment.**
3. Implement deterministic-CBOR/canonical handling per A1: schema validation, canonical serialization, trust-policy decisions, import idempotency. Pass exact canonical bytes to native sign/verify; never rebuild the signed structure separately on the two platforms.
4. Implement A2's bootstrap and the shared merchant/customer UI: receipt preview, transfer progress, verification result, receipt history, permission/capability failures, cancel, retry.
5. Restart-safe persistence. Persist the **verification state** (trusted / unknown-key / rejected per §5.3), never infer trust from transport success.
6. Mock adapters first for shared-logic tests, then swap to A4/A5 for device tests. Record which checks need hardware.

**Done when.** Both builds run the *same* TypeScript app at the same fixture revision, and the flows run through real native adapters.

### A4 — iOS native adapter

**Task.** iOS implementation beneath the shared app; no native UI app.

1. Hardware spike: validate Core Bluetooth central **and** peripheral/advertising on target iPhones; define the supported iOS/device floor from current official docs.
2. Implement A3's bridge and event semantics; report unavailable capabilities explicitly; clean up callbacks/sessions across cancel, RN reload/unmount, disconnect, and lifecycle transitions.
3. Ed25519 sign/verify passing A1's vectors; merchant key generated into Keychain via CryptoKit `Curve25519.Signing.PrivateKey`, documented accessibility/reset behavior; session secrets ephemeral.
4. Implement A1 handshake, native encrypted framing, GATT client **and** server roles, bounded queues, backpressure, timeouts.
5. Expose permission/capability state to shared UI; route root project config changes through A0.
6. Test on device: signature vectors, tampering, unknown-key, Keychain persistence, permissions, malformed/oversized transfers, cleanup.

**Done when.** Physical iOS build passes the shared vectors and completes a real receipt transfer.

### A5 — Android native adapter

**Task.** Android implementation beneath the shared app; no native UI app.

1. Hardware spike: GATT server, **advertising** support, and permission model on target devices/API floor. Android advertising support is device-dependent — verify, don't assume.
2. Implement the same bridge/event semantics as A4, including explicit capability failures and lifecycle cleanup.
3. **Validate direct Keystore Ed25519 support rather than assuming it.** If unsupported, app-generated Ed25519 key wrapped by a device-bound Keystore AES key in private app storage — and document that this is weaker than hardware-backed non-exportability (§4.4).
4. Implement the frozen handshake, framing, GATT roles, bounded queues, backpressure, permissions, teardown.
5. Route root config through A0; expose capability outcomes to shared UI.
6. Test the same persistence/crypto/malformed/lifecycle matrix as A4 on device.

**Done when.** Physical Android build passes the *same* fixtures as A4 and interoperates without a second wire dialect.

### A6 — Independent interoperability and security reviewer

**Task.** Review the contracts early; validate the integrated build independently. A6 never edits another agent's files — it reports with severity, repro, violated invariant, owner.

1. **Early (pre-implementation):** review trust bootstrap, canonical signed bytes, key separation, transcript binding, nonce uniqueness, replay policy, transaction selection against `DESIGN.md` §2/§5/§6/§9/§10. File defects to A0/A1/A2.
2. Build conformance expectations from the **frozen public vectors only**; never derive expected values from the implementation under test.
3. Physical-device runs: iOS→Android and Android→iOS **required**. iOS→iOS and Android→Android when two devices of a platform exist. Report untested combinations explicitly rather than implying coverage.
4. Adversarial cases (from §9/§10): multiple nearby merchants, wrong/expired bootstrap, unknown merchant key, invalid signature, modified ciphertext frame, replayed/cross-session frame, oversized length, incomplete fragment set, unsupported version, duplicate import. **No case may silently become "trusted".**
5. Lifecycle: disconnect, cancel, Bluetooth off, denied permission, app restart, RN reload/unmount, bridge cleanup. No stale callbacks, no half-imported trusted receipt.
6. Review key storage, bridge payloads, logs/crash output, backup exposure, parser/resource limits. Keep session binding distinct from merchant identity and physical proximity. **Do not claim complete relay resistance.**
7. Fragmentation proof: one concrete long synthetic receipt — record size, transfer time, attempts, outcome.
8. Publish device/build matrix, security limitations, and demo script: valid delivery, tampering rejection, wrong-session rejection, persistence after restart. Call it a PoC review, **not a formal audit**.

**Done when.** Both cross-platform directions pass on hardware, and no open finding allows forged/tampered/unknown-key data to be labeled trusted, an unintended transaction to be silently accepted, or ordinary logs to leak key/session material.

---

## 3. Execution waves

| Wave | Work | Exit condition |
|---|---|---|
| **0. Baseline** | A0: `git init`, commit `DESIGN.md` + `.mmd`, pin RN toolchain, create scopes | Repo exists; scaffold builds empty app |
| **1. Contract** | A1 (passes A–D + vectors), A2 (binding + states), A3 (`DeceiptNative.ts` draft); A6 early review; A0 freezes | One revision hash; A6 comments resolved; **no open contract items** |
| **2. Implementation** | A3 shared app ‖ A4 iOS ‖ A5 Android, all against the frozen revision; mocks unblock UI | Each platform builds; A3 shared tests green on mocks |
| **3. Device verification** | A6 independent interop + adversarial + lifecycle on hardware; owners fix; A6 reruns | §4 gates pass |
| **4. Delivery** | A0 demo script, matrix, limitations, acceptance report | Gate report published |

**Hard rule:** no implementation against an unfinished wire or bridge contract. Keep ≤4 active workers + A0.

---

## 4. Completion gates

1. One shared RN/TypeScript app builds for iOS and Android with working native BLE + crypto adapters.
2. One documented wire revision + fixture set, used by both platforms.
3. iOS merchant → Android customer **and** Android merchant → iOS customer demonstrated on physical phones. **STATUS (2026-10-03): BLOCKED by the user's confirmed device availability** — no Android device or usable Android emulator (BLE peripheral is not emulable), and only one iPhone. The user directed that this gate be documented as blocked with evidence rather than claimed. Radio-independent vector tests must still pass on both platforms.
4. BLE payload encryption verified; no trusted status granted merely because decryption succeeded.
5. Ed25519 verification **plus** merchant-key trust binding required for a trusted receipt.
6. Wrong transaction, malformed payload, tampered receipt, replay/cross-session frames → rejected per contract.
7. Nearby competing terminals never trigger implicit RSSI-based selection.
8. A receipt imports exactly once; disconnect/cancel leaves no half-imported trusted receipt.
9. Merchant keys and saved receipts survive restart; no key/session material in committed files or ordinary logs.
10. Build commands, device/OS matrix, permission setup, demo script recorded; untested combinations and PoC limitations stated.

---

## 5. Open contract items and owners

| Item | Source | Owner | Blocks |
|---|---|---|---|
| Receipt schema + monetary rules (pass A) | §15.A | A1 | A3 |
| Trust bootstrap + credential format (pass B) | §5.1–5.2, §15.B | A1 | A4/A5 verification paths |
| Handshake key schedule, nonces, transcript (pass C) | §6.4, §15.C | A1 | A4/A5 |
| UUIDs + wire IDs (pass D) | §7.4, §15.D | A1 | A4/A5 |
| CBOR vs. alternative encoding | §4.2 provisional | A1 (default: keep CBOR) | A3 |
| Transfer suite confirmation (P-256/HKDF/AES-256-GCM) | §6.2 provisional | A1 | A4/A5 |
| Transaction binding mechanism + binding bytes | not specified (§7.3 only) | A2 → A1 adopts | A1 freeze |
| RN flavor + dependency versions | not specified | A0 | all |
| Android Keystore Ed25519 viability | §4.4 conditional | A5 | A5 |
| iOS/Android BLE peripheral support floor | not specified | A4/A5 spikes | gate 3 |

---

## 6. Dispatch template

```
Agent: <A0..A6 + name>
Goal: <one deliverable from §2>
Read: DESIGN.md §<relevant sections>, deceipt-crypto-ble.mmd, frozen protocol revision <hash>, vectors <rev>
Allowed write paths: <exclusive scope from §1>
Consumes: <interfaces/fixture revision>
Required checks: <specific §4 cases that apply>
Do not: change shared contracts, another agent's files, or root build config independently.
If a contract is insufficient: report the exact gap to A0, propose a revision, wait on dependent work,
  continue independent tasks.
Return: commit/diff, changed paths, test commands + results, device evidence, limitations, blockers.
```

---

## 7. Provenance

Rev 1 of this plan was written without repository access and flagged that as a limitation. Rev 2 was produced after reading `/Users/mateo/CODE/Deceipt/DESIGN.md` (all 881 lines) and `deceipt-crypto-ble.mmd` directly on 2026-10-03, plus `git status` and the root directory listing. All §0 claims are evidence-backed by those reads. Rev 2 keeps rev 1's role structure but replaces guessed paths with the real project root, replaces "spec unreachable" caveats with the actual stable/provisional split from `DESIGN.md` §13/§14, and adds the missing prerequisite that the spec is not yet under version control.

**React Native remains mandatory for the PoC** (restated per the explicit requirement): one shared TypeScript app for merchant and customer modes on both platforms; native modules only where BLE/crypto platform APIs require them.

Canonical copy: this file at the project root. The earlier copy in `~/Downloads` is superseded.
