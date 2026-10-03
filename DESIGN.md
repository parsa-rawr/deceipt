# Deceipt Cryptography and BLE/GATT Design

**Status:** Draft v0.1 — planning only  
**Project:** Deceipt  
**Scope:** Receipt authenticity, merchant trust boundaries, ephemeral BLE session security, and BLE/GATT transport for the A↔B proof of concept  
**Non-goal:** This document does not start implementation and does not finalize the merchant trust hierarchy.

---

## 1. Goal

The Deceipt proof of concept should demonstrate a receipt moving directly between two modern smartphones:

- A may be iOS or Android.
- B may be iOS or Android.
- Either platform combination should work.
- No Bluetooth pairing in system settings should be required.
- No POS integration is required for the PoC.
- BLE is a transport, not a trust source.
- BLE traffic should be encrypted in transit.
- Encrypted BLE traffic is still considered untrusted until the received receipt and its merchant authorization chain have been cryptographically verified.
- RSSI must never be used to decide which merchant, cashier, or transaction is intended.

The core security idea is:

~~~text
Transport confidentiality != receipt authenticity

BLE may deliver confidential bytes successfully,
but Deceipt does not trust the receipt until the
merchant signature and authorization evidence verify.
~~~

---

## 2. Security principles

The following principles are intended to be stable even if algorithms or trust hierarchy details change later.

### 2.1 Receipts are self-authenticating documents

A valid receipt must carry enough cryptographic evidence for a Deceipt client to determine that:

1. the receipt bytes have not been modified;
2. the signing key was authorized to issue receipts for the claimed merchant;
3. the signature is valid for the exact received receipt bytes;
4. the receipt format and signature suite are supported;
5. the receipt has not already been accepted locally under the same receipt identifier.

The BLE connection itself never establishes these properties.

### 2.2 BLE is an untrusted byte transport

BLE is responsible for:

- discovery;
- connection establishment;
- protocol negotiation;
- moving encrypted transfer bytes;
- flow control;
- acknowledgements;
- disconnecting cleanly.

BLE is not responsible for proving:

- merchant identity;
- receipt authenticity;
- historical validity;
- cashier identity;
- payment validity;
- customer identity.

A compromised or malicious BLE peer should not be able to produce a receipt that passes merchant verification unless it controls an authorized merchant signing key.

### 2.3 Encrypt before transport, verify after transport

The sender encrypts the signed receipt for the temporary transfer session. The receiver:

1. establishes an authenticated encrypted session;
2. receives ciphertext;
3. checks transfer framing/integrity;
4. decrypts the signed receipt;
5. treats the resulting object as untrusted input;
6. verifies the receipt signature and merchant authorization chain;
7. validates receipt semantics and deduplicates;
8. only then stores/displays the receipt as verified.

This ordering is deliberate. Successful AEAD decryption means only that the current session delivered intact ciphertext under the negotiated session key. It does not prove the merchant receipt is legitimate.

### 2.4 Long-lived signing keys and ephemeral session keys are separate

Never reuse a merchant receipt-signing key for transport key agreement.

~~~text
merchant signing key
    purpose: receipt + handshake authentication
    lifetime: long-lived
    algorithm: Ed25519 for the PoC
    storage: OS-protected secure storage; hardware-backed protection deferred

ephemeral session key
    purpose: one transfer session
    lifetime: seconds
    storage: volatile memory
    destroyed: after disconnect/session expiry
~~~

### 2.5 No RSSI-based association

Signal strength may be recorded for diagnostics, but it must not determine:

- which checkout is selected;
- which receipt is accepted;
- which peer is trusted;
- whether a merchant identity is valid.

For the two-phone PoC, automatic connection is allowed only when the receiver has one unambiguous active Deceipt sender. If multiple candidates exist, the protocol fails closed into an explicit disambiguation path.

---

## 3. Cryptographic layers

Deceipt separates three cryptographic concerns.

~~~text
Layer 1 — Receipt authenticity
    Merchant/device signature over exact receipt bytes

Layer 2 — Merchant/device authorization
    Evidence that the receipt signing key is authorized
    for the claimed merchant

Layer 3 — Transfer-session security
    Ephemeral authenticated key agreement and AEAD
    protecting receipt bytes in transit
~~~

None of these layers should be collapsed into another.

---

## 4. Receipt encoding and signature container

### 4.1 Logical receipt versus canonical bytes

Deceipt should distinguish the logical receipt model from the exact byte representation that is signed.

~~~text
Logical DeceiptReceiptV1
        |
        v
Deterministic canonical encoding
        |
        v
Exact receipt bytes
        |
        v
Digital signature
~~~

Once a receipt is issued, the exact signed bytes are authoritative.

The receiver must verify the signature over the original received bytes. It must not decode the receipt, reconstruct a new object, re-encode it, and verify that reconstruction.

### 4.2 Proposed canonical format: deterministic CBOR

**Provisional choice:** deterministic CBOR.

Reasons:

- compact for BLE;
- binary-safe;
- standardized deterministic encoding rules;
- integrates naturally with COSE;
- avoids ambiguity around JSON whitespace, key ordering, and number formatting.

Deceipt Receipt v1 should prohibit IEEE floating-point values for monetary values.

Example logical amount:

~~~text
amount_minor = 525
currency = "CAD"
~~~

means CAD $5.25.

Fractional quantities should use an exact representation defined by the receipt schema, not binary floating point.

Reference: RFC 8949, Concise Binary Object Representation (CBOR).

### 4.3 Proposed signature container: COSE_Sign1

**Provisional choice:** COSE_Sign1.

The signed artifact conceptually contains:

~~~text
SignedReceiptV1
    protected headers
        algorithm
        content type
        key identifier
        protocol/schema version where appropriate

    payload
        exact deterministic DeceiptReceiptV1 bytes

    signature
        merchant/device signature
~~~

Reference: RFC 9052, CBOR Object Signing and Encryption (COSE).

### 4.4 Receipt signature suite — PoC decision: Ed25519

**PoC decision:** Ed25519, carried as EdDSA in COSE_Sign1.

For the proof of concept, Deceipt does not require the merchant signing key to be Secure Enclave- or StrongBox-backed. The priority is a compact, modern, interoperable signature scheme with straightforward implementations on both iOS and Android.

Expected properties:

- Ed25519 public key: 32 bytes;
- Ed25519 signature: 64 bytes;
- deterministic signatures;
- COSE algorithm: EdDSA with the Ed25519 curve;
- long-lived merchant signing key is distinct from ephemeral transfer-session keys.

**iOS PoC storage:** use CryptoKit `Curve25519.Signing.PrivateKey`. Persist its private key material in the Keychain as protected generic data. Prefer a device-only accessibility class appropriate for the app's foreground issuance model. The PoC does not claim Secure Enclave protection for this key.

**Android PoC storage:** prefer direct Android Keystore Ed25519 when the target device/API exposes the required support. For broader PoC compatibility, an acceptable fallback is to generate the Ed25519 key in application crypto code and persist the serialized private key only after encrypting it with a device-bound AES key held by Android Keystore. In that fallback, the Ed25519 private key exists in application memory while signing, so this is explicitly not equivalent to hardware-backed non-exportability.

Production hardening may later introduce a hardware-backed signing suite or platform-specific hardware-backed key policy without changing the transport-independent receipt model.

### 4.5 Receipt identity

Every receipt requires a cryptographically random, globally unique receipt identifier.

The identifier is used for:

- local deduplication;
- idempotent receipt ingestion;
- references from refunds/voids;
- audit logs;
- future server synchronization.

Receipt ID uniqueness does not itself provide authenticity.

---

## 5. Merchant trust model

This section is intentionally provisional. The trust hierarchy must be designed separately and carefully.

### 5.1 Minimum PoC model

For the PoC, the simplest candidate hierarchy is:

~~~text
Deceipt trust root
        |
        | signs/authorizes
        v
Merchant device credential
        |
        | binds
        v
Merchant identity + device public signing key
        |
        | signs
        v
Receipt
~~~

The root private key must never ship inside the mobile application.

A Deceipt client may contain trusted root public key material or another securely updateable trust-anchor mechanism.

### 5.2 Merchant device credential

A candidate credential includes:

- merchant identifier;
- device key identifier;
- device public signing key;
- validity start;
- validity end;
- allowed capabilities;
- credential version;
- issuer;
- issuer signature.

The credential answers:

> Is this public key authorized to issue Deceipt receipts for this merchant?

It does not answer:

> Was this exact receipt issued before a later key compromise?

Historical validity and trusted timestamping are separate future problems.

### 5.3 Verification states

Internally, Deceipt should preserve distinct verification results rather than reducing everything to one Boolean.

Suggested internal states:

1. **Signature valid** — exact receipt bytes match the signature.
2. **Signing key authorized** — credential binds key to claimed merchant.
3. **Credential temporally acceptable** — validity window is acceptable according to available evidence.
4. **Revocation status known/acceptable** — according to available revocation information.
5. **Receipt semantically valid** — required fields, totals, schema rules, and identifiers are valid.
6. **Receipt unique locally** — not already accepted under the same receipt ID.

Only policy may combine these into a user-facing verified state.

### 5.4 Known unresolved security problem: backdating after compromise

If a merchant signing key is stolen, an attacker may sign a new receipt containing an earlier issued-at timestamp.

A merchant signature alone cannot prove the receipt existed before compromise.

Future solutions may include:

- trusted timestamping;
- online issuance anchoring;
- append-only transparency logs;
- POS/payment-processor evidence;
- merchant-side counters chained to a transparency service.

This is explicitly out of scope for the first A↔B PoC but must remain in the threat model.

---

## 6. Ephemeral transfer-session cryptography

### 6.1 Goals

The transfer session should provide:

- confidentiality against passive BLE observers;
- integrity of transferred ciphertext;
- fresh keys per session;
- forward isolation between separate transfer sessions;
- authentication of the merchant endpoint before receipt transfer;
- no dependency on OS-level Bluetooth pairing;
- no persistent customer identity requirement for the PoC.

### 6.2 Proposed session suite

**Provisional choices:**

- Key agreement: ephemeral P-256 ECDH
- KDF: HKDF-SHA-256
- AEAD: AES-256-GCM
- Transcript hashing: SHA-256

A future crypto-suite field should permit versioned replacement without changing the receipt format.

### 6.3 Session authentication

Plain ephemeral ECDH is vulnerable to active man-in-the-middle substitution. The merchant therefore authenticates the handshake transcript with its authorized long-lived signing key.

Conceptual flow:

~~~text
B -> A: ClientHello
    protocol version
    crypto suites
    client nonce
    client ephemeral ECDH public key

A -> B: ServerHello
    selected protocol/suite
    session ID
    server nonce
    server ephemeral ECDH public key
    merchant device credential
    signature over canonical handshake transcript
~~~

The receiver verifies the merchant credential and handshake signature before accepting the merchant endpoint as authenticated.

The handshake signature does not replace receipt signature verification.

### 6.4 Session key derivation

Conceptually:

~~~text
shared_secret =
    ECDH(local_ephemeral_private, peer_ephemeral_public)

transcript_hash =
    SHA256(canonical_handshake_transcript)

session_key_material =
    HKDF-SHA256(
        input_key_material = shared_secret,
        salt = handshake-derived salt,
        info = "deceipt-transfer-v1" || transcript_hash
    )
~~~

The exact key schedule must be finalized before implementation, including:

- directional keys;
- nonce construction;
- key lengths;
- transcript canonicalization;
- replay handling;
- exporter/context values.

Do not improvise these details during implementation.

### 6.5 Encrypt signed receipt as an application payload

The signed receipt should be produced first, then encrypted for the transfer session.

~~~text
DeceiptReceiptV1
        |
        v
COSE_Sign1 / SignedReceiptV1
        |
        v
session AEAD encryption
        |
        v
EncryptedTransferPayload
        |
        v
BLE fragmentation
~~~

BLE packet boundaries must not influence cryptographic object boundaries.

The receiver reassembles the complete encrypted transfer payload, authenticates/decrypts it, then independently validates the signed receipt.

---

## 7. BLE/GATT service design

### 7.1 Roles

Initial A↔B PoC:

- A / merchant: BLE peripheral + GATT server
- B / customer: BLE central + GATT client

The protocol should not assume Apple-to-Apple or Android-to-Android. The same logical GATT contract must work across all four platform combinations.

### 7.2 Advertising

When no receipt is ready, the merchant should not advertise a transferable Deceipt receipt session.

When the merchant explicitly chooses Send:

1. create a short-lived transfer session;
2. start the Deceipt GATT service;
3. advertise the fixed Deceipt service UUID;
4. wait for a receiver for a bounded interval;
5. stop advertising when committed to one receiver, cancelled, expired, or completed.

Advertisements must not contain:

- merchant name;
- receipt amount;
- receipt identifier;
- customer information;
- merchant credential;
- receipt payload.

The advertisement means only:

> A Deceipt transfer endpoint is currently available.

### 7.3 Candidate ambiguity rule

Receiver behavior:

~~~text
0 candidates
    continue scanning

1 eligible candidate
    may automatically attempt connection

2+ eligible candidates
    do not infer intent from RSSI
    enter explicit disambiguation/fallback path
~~~

This is a product/protocol invariant.

### 7.4 GATT service

One fixed 128-bit **Deceipt Transfer Service UUID** should identify the service.

Initial service has three characteristics:

| Characteristic | Direction | BLE behavior | Purpose |
|---|---|---|---|
| COMMAND | B → A | Write with response | ClientHello, Accept, ACK, Cancel, Retry |
| EVENT | A → B | Indicate | ServerHello, Offer, Begin, Complete, Error |
| DATA | A → B | Notify | High-throughput encrypted transfer frames |

UUID values are intentionally not assigned in this planning draft.

### 7.5 Why three characteristics

**COMMAND** provides a clear client-to-server control path with acknowledged writes.

**EVENT** carries important server-to-client state transitions using indications, where confirmation is desirable.

**DATA** carries bulk bytes using notifications for throughput. Reliability beyond the BLE link is provided by Deceipt framing, sequence tracking, and application acknowledgements.

This separates control plane from data plane and simplifies debugging.

---

## 8. Transfer protocol

### 8.1 High-level state machine

~~~text
IDLE
  |
  v
RECEIPT_SIGNED
  |
  v
ADVERTISING
  |
  v
CONNECTED
  |
  v
HANDSHAKE
  |
  +-- failure --> ABORT
  |
  v
MERCHANT_SESSION_AUTHENTICATED
  |
  v
RECEIPT_OFFERED
  |
  +-- reject --> DISCONNECT
  |
  v
TRANSFER
  |
  v
CIPHERTEXT_REASSEMBLED
  |
  v
SESSION_DECRYPTED
  |
  v
RECEIPT_UNTRUSTED
  |
  v
VERIFY_RECEIPT_SIGNATURE_AND_AUTHORIZATION
  |
  +-- failure --> REJECT + AUDIT
  |
  v
VALIDATE_RECEIPT
  |
  v
STORE
  |
  v
ACK
  |
  v
DISCONNECT
~~~

The explicit **RECEIPT_UNTRUSTED** state is important. Decryption success must never skip receipt verification.

### 8.2 Protocol messages

Initial conceptual message set:

**Client to merchant**
- ClientHello
- Accept
- ReceiptAck
- Cancel
- Retry / flow-control acknowledgement as needed

**Merchant to client**
- ServerHello
- ReceiptOffer
- TransferBegin
- TransferComplete
- Error

**Bulk data**
- DataFrame

Message encoding should use the same deterministic binary discipline as the rest of the protocol, but control-message schema details remain open.

### 8.3 Receipt offer

Before moving the full receipt, the merchant may send a small authenticated offer after the secure handshake.

Candidate fields:

- protocol version;
- transfer/session identifier;
- merchant identifier or safe display metadata;
- total amount;
- currency;
- receipt type;
- encrypted payload length.

The exact privacy policy for pre-verification merchant display metadata is unresolved. The UI must not imply that offer metadata is trusted merely because the session encrypted it.

### 8.4 Transfer begin

Candidate fields:

~~~text
transfer_id
ciphertext_length
payload_hash
frame_size
frame_count
~~~

The payload hash is a transport-integrity/checkpoint aid, not a replacement for AEAD authentication or the merchant receipt signature.

### 8.5 Data frames

Conceptual framing:

~~~text
DataFrame
    transfer_id
    sequence_number
    payload_bytes
~~~

Frame size is negotiated or chosen according to platform-reported write/notification capacity. Never assume a fixed ATT MTU.

### 8.6 Flow control and acknowledgement

The receiver tracks contiguous sequence progress.

A candidate acknowledgement form:

~~~text
Ack
    transfer_id
    highest_contiguous_sequence
~~~

The protocol may later support selective retransmission, but the PoC can begin with a bounded retry strategy.

Application acknowledgements do not prove merchant authenticity.

---

## 9. Verification order on the receiver

The receiver should conceptually process a transfer in this order:

1. Validate BLE/GATT framing enough to safely parse the protocol.
2. Validate handshake message format and protocol versions.
3. Verify merchant device credential against configured trust anchors/policy.
4. Verify merchant handshake signature over the exact canonical transcript.
5. Derive session keys.
6. Receive and reassemble encrypted payload.
7. Authenticate/decrypt AEAD payload.
8. Parse signed receipt container as untrusted input.
9. Validate supported COSE/signature suite and critical headers.
10. Verify receipt signature over the exact received receipt bytes.
11. Verify the receipt signing key is authorized for the claimed merchant.
12. Validate receipt schema and semantic invariants.
13. Check receipt ID deduplication.
14. Apply revocation/validity policy available to the device.
15. Only then mark/store as verified according to policy.
16. Send ReceiptAck and disconnect.

A failure at any stage must never fall through into a verified receipt state.

---

## 10. Threat model for the PoC

The PoC should explicitly consider:

### Passive BLE observer
Can observe radio traffic.

Mitigation: ephemeral key agreement + AEAD.

### Active BLE man-in-the-middle
Attempts to replace ephemeral keys or messages.

Mitigation: merchant-signed handshake transcript plus transcript-bound key derivation.

### Malicious nearby sender
Advertises Deceipt service and sends arbitrary ciphertext/receipts.

Mitigation: receipt remains untrusted until merchant credential and receipt signature verification pass.

### Replay of an old encrypted BLE transfer
Attacker replays captured session traffic.

Mitigation: fresh nonces/session IDs, transcript binding, ephemeral keys, AEAD, session expiry, receipt-ID deduplication.

### Replay of a genuine signed receipt
Attacker transfers a real historical receipt again.

Mitigation: receipt ID deduplication and receipt-state policy. A genuine receipt can remain cryptographically genuine even when replayed, so replay status must remain distinct from signature validity.

### Modified receipt
Attacker edits line items, total, timestamp, or merchant fields.

Mitigation: merchant signature over exact canonical receipt bytes.

### Fake merchant
Attacker creates its own key and calls itself a real merchant.

Mitigation: merchant/device authorization credential chain.

### Compromised merchant signing key
Attacker can create signatures that appear legitimate while the credential is accepted.

Mitigation requires revocation and potentially trusted historical anchoring. This cannot be solved by receipt signatures alone.

### Malformed protocol input
Peer sends oversized, truncated, recursive, or invalid structures.

Mitigation: strict length bounds, schema validation, bounded allocation, parser hardening, timeouts, and fail-closed state transitions.

---

## 11. Privacy notes

The PoC should avoid creating a persistent customer identity unless required.

Prefer:

- ephemeral receiver key material;
- no customer name in merchant advertisements;
- no receipt contents in BLE advertising;
- no stable BLE-derived customer tracking identifier at the application layer;
- minimum metadata before merchant authentication.

Receipt-at-rest privacy and customer-account synchronization are separate designs.

---

## 12. Cross-platform requirements

The BLE protocol must be implementable through native iOS and Android BLE APIs even if React Native owns the application shell.

Do not assume:

- a particular negotiated MTU;
- a particular notification packet size;
- background behavior identical across iOS and Android;
- OS Bluetooth pairing;
- a device name being available or trustworthy;
- RSSI implying physical intent;
- advertisements being delivered at deterministic timing.

React Native should eventually expose a transport-neutral Deceipt transfer interface while native modules implement platform-specific BLE details.

This document does not define that implementation API yet.

---

## 13. Decisions considered stable

These are the architectural commitments currently intended to survive later design changes:

1. Receipt format is transport-independent.
2. BLE is an untrusted transport.
3. BLE payload is encrypted for privacy.
4. Successful BLE-session decryption does not establish receipt trust.
5. Receipt authenticity is independently verified using merchant cryptographic evidence.
6. Long-lived receipt signing keys and ephemeral transport keys are distinct.
7. RSSI cannot select or authenticate a cashier/session.
8. The receiver fails closed when peer association is ambiguous.
9. Exact signed receipt bytes are authoritative.
10. Cryptographic and protocol suites are versioned.
11. Parser and allocation bounds are part of the security design, not implementation polish.

---

## 14. Provisional decisions requiring deeper review

The following are proposals, not final requirements:

- deterministic CBOR as receipt/control encoding;
- COSE_Sign1 as the signed receipt container;
- production hardware-backed merchant signing-key policy and any future migration from the PoC Ed25519 suite;
- P-256 ECDH + HKDF-SHA-256 + AES-256-GCM for transfer sessions;
- Deceipt acting as the sole PoC trust root;
- merchant device credential format;
- three-characteristic GATT layout;
- exact handshake key schedule;
- exact nonce construction;
- revocation model;
- historical timestamp/anti-backdating model;
- merchant enrollment and identity proofing;
- merchant-owned delegation roots;
- how multiple active BLE candidates are disambiguated in the production experience.

None of these should become production assumptions merely because they appear in this draft.

---

## 15. Next design work

Recommended next planning passes:

### A. Define DeceiptReceiptV1
Specify:
- merchant and location fields;
- timestamps;
- currency and monetary representation;
- line items;
- discounts;
- taxes;
- tips;
- totals;
- payment summary;
- refunds/voids;
- extensions;
- receipt identifiers and references.

### B. Threat-model the trust hierarchy
Design:
- merchant enrollment;
- trust roots;
- device authorization;
- key creation;
- hardware-backed key requirements;
- key rotation;
- device loss;
- revocation;
- offline behavior;
- historical validity;
- merchant delegation.

### C. Specify the handshake byte-for-byte
Only after A and B are sufficiently stable:
- canonical handshake transcript;
- algorithm identifiers;
- KDF inputs;
- directional AEAD keys;
- nonces/counters;
- replay windows;
- message limits;
- timeout rules;
- state-machine failure behavior.

### D. Assign protocol UUIDs and wire identifiers
Do this only once the service/message structure is stable enough that identifiers will not churn.

---

## 16. References

Standards worth using rather than inventing equivalents:

- RFC 8949 — CBOR
- RFC 9052 — COSE structures
- RFC 9053 — COSE algorithms
- RFC 5869 — HKDF
- NIST SP 800-38D — AES-GCM
- Apple Core Bluetooth / CryptoKit / Secure Enclave documentation
- Android Bluetooth Low Energy / Android Keystore / hardware-backed key documentation
