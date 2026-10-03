# A6 conformance results

`54` PASS / `0` FAIL

| id | target | status | detail |
|---|---|---|---|
| D9 | REVISION.json file hashes recompute | PASS | 39 files, missing=[], mismatched=0 |
| D9b | REVISION.json aggregate recomputes | PASS | recomputed 3d4b812adc2b8eb7… vs pinned 3d4b812adc2b8eb7… |
| D9c | frozen revision declared consistently as deceipt-proto-r4 | PASS | deceipt-proto-r4 |
| D9d | every vector file's declared revision matches REVISION.json | PASS | all deceipt-proto-r4 |
| D10 | no stale deceipt-proto-rN in docs/protocol/*.md (expect deceipt-proto-r4) | PASS | clean |
| B10 | every JSON vector artifact carries the _TESTONLY header | PASS | all present |
| A16 | all 22 malformed/non-canonical CBOR encoding vectors yield the frozen error | PASS | 22/22 |
| A16b/binding_tuple_hex | binding_tuple_hex decodes+re-encodes byte-identically | PASS |  |
| A16b/offer_hash_preimage_hex | offer_hash_preimage_hex decodes+re-encodes byte-identically | PASS |  |
| A1 | receipt body byte-identical to field-table reproduction | PASS | 669 B, sha 69255f589539bb76… |
| A1b | receipt body decodes+re-encodes byte-identically (canonical) | PASS |  |
| A2/ss | Sig_structure reproduction byte-identical | PASS |  |
| A2 | Ed25519 verify over Sig_structure of the exact bytes | PASS |  |
| A3 | Ed25519 sign reproduces the frozen signature | PASS |  |
| A4 | COSE_Sign1 container parses and is canonical | PASS |  |
| A15a | 256-line long receipt body parses, canonical, hash+len | PASS | 11357 B |
| A15b | long receipt has 256 lines and totals.total == 30052 | PASS | lines=256 total=30052 |
| A11 | fractional quantities exact, half-away rounding, no float path | PASS | 4 cases |
| A5-A14 | all 45 receipt adversarial vectors yield the frozen error+outcome | PASS | 45/45 |
| E2 | no adversarial receipt case silently reaches TRUSTED | PASS | 0 silent trusts |
| B1-B5 | all 9 credential vectors yield frozen error+trust | PASS | 9/9 |
| B3 | valid signature + unknown key is UNVERIFIED_UNKNOWN_ISSUER, never TRUSTED | PASS | UNVERIFIED_UNKNOWN_ISSUER signature_valid=True key_authorized=False |
| B11a | pinned anchor is bd65615a… | PASS | bd65615aed2e3adf |
| B11b | anchor is NOT the merchant device key 61d36a10… | PASS |  |
| B11c | valid-credential.cbor verifies under the anchor and fails under the device key | PASS | anchor=authenticated devicekey=none |
| B9a | no test private key embedded in app/module/native sources | PASS | 0 hits |
| B9b | no tracked private-key/keystore files except the verified debug-keystore throwaway | PASS | only the structurally-verified debug keystore |
| B9c | shipped trust-anchor constant carries public material only | PASS | app/src/config/trustAnchors.ts |
| C1 | 372-byte transcript reproduced from received plaintext | PASS | 372 B |
| C2b | transcript_layout label 20 B, offsets 218/250/285 | PASS |  |
| C2 | transcript_hash + Ed25519 signature over the exact transcript | PASS |  |
| C1c | binding-rule negatives (tuple absent / label4 not a tuple member) reproduce | PASS | delegated to handshake-invalid suite |
| C3 | ECDH shared secret + full HKDF schedule (prk/okm/4 keys) | PASS | prk/okm/4 slices reproduced from the frozen inputs |
| C11 | offer_hash recomputed in array order [session_id,transfer_id,receipt_id,ref,total,cur,issued_at] | PASS | efdc44f3a6d088fc |
| C5 | AEAD control envelope bytes (offer/begin/accept) reproduced | PASS | 3/3 |
| C4 | AEAD payload seal bytes reproduced | PASS | 814 B |
| R7-02 | ACK worked example is the AEAD envelope and decrypts to the ACK CBOR | PASS | 48 B |
| C6/C7 | all 8 AEAD adversarial vectors yield the frozen error | PASS | 8/8 |
| C1c/C8 | handshake byte-decidable adversarial vectors yield the frozen error | PASS | 18/18 decidable (4 session-state cases UNVERIFIED off-radio: binding_unknown_session,binding_proof_invalid,binding_stale,binding_consumed) |
| C9 | SessionUnverifiedPeer fixture: transcript signature verifies under the self-asserted device key, issuer NOT pinned | PASS | session_type=SessionUnverifiedPeer |
| D1 | service + 3 characteristic UUIDs frozen | PASS |  |
| D3 | LPdu 4 fragments reassemble to the SERVER_HELLO PDU | PASS | 4 fragments, 616 B |
| D4 | LPdu byte-decidable adversarial vectors yield the frozen error | PASS | 4/4 decidable (4 policy/timeout cases UNVERIFIED off-radio) |
| D5 | frame size derived from reported MTU (185 -> 162), never a fixed ATT MTU | PASS |  |
| D6 | 6 frames reassemble to the ciphertext; final frame 4 bytes is valid | PASS | sizes=[162, 162, 162, 162, 162, 4] |
| D7 | frame-size byte-decidable adversarial vectors yield the frozen error | PASS | 5/5 decidable (13 sequence/timeout/retry cases UNVERIFIED off-radio) |
| RX-03 | wire-v1.cddl encodes the final-frame rule (nonfinal 16..512 / final 1..512) | PASS | final-frame type present |
| R2-03 | SERVER_HELLO field table labels unique and ascending [1..11] | PASS | labels=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] |
| F-02 | wire-v1.cddl server-hello includes labels 10 (binding_tuple) and 11 (max_frame_payload) | PASS | cddl labels=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] |
| F-03 | wire-v1.cddl header names the frozen revision deceipt-proto-r4 | PASS | ; Revision: deceipt-proto-r4 (FROZEN for the PoC) |
| F-04 | receipt-v1.cddl header names the frozen revision deceipt-proto-r4 | PASS | ; Revision: deceipt-proto-r4 (FROZEN for the PoC) |
| F-05 | self-test.json records 165 checks / 0 failures at deceipt-proto-r4 | PASS | checked=165 failed=0 revision=deceipt-proto-r4 |
| F-06 | tz_offset_minutes bound+units consistent between spec, CDDL, fields and valid vector | PASS | vector tz=-14400 (seconds); rule=-50400..50400 (= -840..840 minutes in SE |
| F-07 | wire.md worked example SERVER_HELLO size/fragment count matches lpdu-valid.json | PASS | vector: 616 B / 4 fragments 178/178/178/82 |
