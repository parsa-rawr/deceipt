# A6 security results

`30` PASS / `0` FAIL

| id | target | status | detail |
|---|---|---|---|
| K1 | iOS merchant key uses Keychain ThisDeviceOnly accessibility | PASS | DeceiptKeyStore.swift |
| K2 | iOS key material stored only in the Keychain, not UserDefaults/files | PASS | DeceiptKeyStore.swift |
| K3 | Android fallback wraps the seed with an AES key held in AndroidKeyStore | PASS | modules/deceipt-native/android/src/main/java/com/deceipt/adapter/crypto/MerchantKeyStore.kt |
| K4 | Android wrapped-key file is written non-world-readable in private app storage | PASS | MerchantKeyStore.kt |
| K5 | Android direct Ed25519 is PROBED at runtime, never assumed | PASS | MerchantKeyStore.kt |
| K6 | Android seed buffers are zeroized after use | PASS | MerchantKeyStore.kt |
| K7 | no seed/session-key field crosses the JS bridge (contract, mock, iOS backend; comments excluded) | PASS | 0 leaks |
| L1 | no NSLog/console.log/Log./println in native or shared code (ordinary logs) | PASS | 0 sinks |
| L2 | no log/print statement referencing seed/key material | PASS | 0 hits |
| X1 | Android app disables adb/cloud backup (allowBackup=false) | PASS | app AndroidManifest.xml |
| X2 | iOS Keychain items are excluded from backups (ThisDeviceOnly) | PASS | DeceiptKeyStore.swift |
| P1 | CBOR hard caps present (depth 12, items 8192, text 4096, bytes 65536) | PASS | {"max_depth": 12, "max_items": 8192, "max_array": 1024, "max_map": 256, "max_text_bytes": 4096, "max_bytes": 65536, "max_map_key": 255} |
| P2 | receipt byte cap 65536 and per-collection caps defined | PASS |  |
| P3 | nested-array depth bomb is rejected (CBOR_DEPTH_EXCEEDED) | PASS | CBOR_DEPTH_EXCEEDED |
| P4 | transfer/control caps defined (ciphertext 65552, frames 32768, pdu 2048, window 64) | PASS |  |
| H1 | .gitignore excludes key/credential/env material | PASS | all present |
| H2 | no tracked private-key/keystore files except the verified debug-keystore throwaway | PASS | no violations |
| H2b | allow-listed debug keystore app/android/app/debug.keystore structurally verified (single androiddebugkey) | PASS | entries=1 androiddebugkey=True |
| H3 | frozen test vectors are intentionally tracked (docs/decisions.md D-003) | PASS | protocol/vectors/** tracked |
| H4 | no secrets directory or .env file is tracked (excluding intentional test vectors) | PASS | none |
| H5 | only the labelled test root private key exists, and it is not in the app | PASS | root-poc-1 private absent from app |
| H6 | repository declares PoC / test-only status in-band | PASS |  |
| V0 | control: the unmutated valid receipt IS TRUSTED | PASS | TRUSTED |
| V1 | 400 random single-bit mutations of the valid receipt: none TRUSTED | PASS | 0 trusted of 400 |
| V2 | 200 random byte-flip mutations of the valid receipt: none TRUSTED | PASS | 0 trusted of 200 |
| V3 | wrong session credential never TRUSTED | PASS | REJECTED/RECEIPT_CREDENTIAL_MISMATCH |
| V4 | validly signed rogue receipt (unknown issuer) never TRUSTED | PASS | UNVERIFIED_UNKNOWN_ISSUER |
| V5 | mutating any committed offer member yields WRONG_TRANSACTION | PASS | 7 members |
| V6 | control still trusted before downgrade | PASS |  |
| V7 | oversized container rejected before parse (RECEIPT_SIZE_EXCEEDED) | PASS | RECEIPT_SIZE_EXCEEDED |
