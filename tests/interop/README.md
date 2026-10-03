# Cross-platform interoperability matrix (A6)

**Revision:** `deceipt-proto-r4` · `aggregate_sha256 3d4b812adc2b8eb71a2f62d444d45f981632d08c832d4d6b2519ece2f7b971c0`
**Machine-readable:** `tests/interop/matrix.json`

## Headline

**Completion gate 3 is BLOCKED.** No cross-platform physical-phone transfer was performed, and
none is claimed. The reason is a hard, user-confirmed device constraint:

* no Android device and no usable Android emulator — Android emulators **cannot** act as a BLE
  peripheral/advertiser, so the merchant role cannot be emulated at all;
* only one iPhone exists and it is currently `unavailable` to the toolchain; the user directed the
  iOS simulator be used, and a simulator cannot do BLE peripheral/advertising either.

Everything that does **not** need a radio was built and run; see the radio-independent rows.

## Radio-independent (built and executed)

| id | row | command | observed | status |
|---|---|---|---|---|
| I1 | Shared TS merchant↔customer via **mock adapters** | `cd app && npx jest` | `tsc --noEmit` exit 0; 8 suites, **205 tests, all pass** (F-08 closed) | **PASS** |
| I2 | A6 independent Python conformance vs frozen vectors | `python3 tests/conformance/run_conformance.py` | 53 PASS / 1 FAIL (the 1 FAIL is the `debug.keystore` hygiene item H2; 45/45 receipt, 9/9 credential, 22/22 encoding, 8/8 AEAD, 18/18 decidable handshake) | **PASS** |
| I3 | A4 iOS Swift radio-independent vector tests | `cd modules/deceipt-native/ios && swift test` | **46 tests, 0 failures** | **PASS** |
| I4 | A5 Android JVM radio-independent vector tests | `cd app/android && ./gradlew :deceipt-protocol:testDebugUnitTest` | **25 tests, 0 failures — BUILD SUCCESSFUL** (F-09 closed) | **PASS** |
| I5 | Cross-language byte agreement | both of the above reproduce `protocol/vectors/**` bytes | transcript/AEAD/signature identical | **PASS** |

## Radio-dependent (NOT run — marked, never implied)

| id | row | status | reason |
|---|---|---|---|
| I6 | iOS merchant → Android customer (physical) | **BLOCKED** | no Android device/emulator |
| I7 | Android merchant → iOS customer (physical) | **BLOCKED** | no Android device/emulator |
| I8 | iOS → iOS (two phones) | **UNVERIFIED** | only one iPhone, unavailable to the toolchain |
| I9 | Android → Android (two phones) | **BLOCKED** | no Android devices |
| I10 | On-device D2/D8/E1/E8/E9/E10 (AD capture, retry, lifecycle) | **UNVERIFIED** | needs a radio |

## Build matrix

| target | toolchain | status | note |
|---|---|---|---|
| iOS Swift package | Apple Swift 6.4 (arm64-macos27.0) | **PASS** (vector tests) | radio-independent core only; CoreBluetooth/Keychain live in the Xcode app target |
| Android JVM | JDK 17 (Zulu 17.0.9), Gradle 9.4.1 | **PASS** | `:deceipt-protocol` 25/25; BLE/Keystore/RN bridge in `:deceipt-native` are radio-dependent and unexercised |
| Shared TS | Node 24.19.0, Jest 29 | **PASS** | mock adapters, no radio |
| Independent runner | Python 3.12.1 + `cryptography` 42.0.8 | **PASS** | OpenSSL-backed, independent of all implementations |

## What "PASS" does and does not mean here

A PASS on I1/I2/I3/I5 means the **bytes and the verification logic** are correct and agree across
three independent implementations (A3 TypeScript, A4 Swift, A6 Python) against the frozen vectors.
It does **not** mean a receipt travelled over Bluetooth between two phones. That is I6–I9, and it
is blocked.
