# Android merchant-key storage — Keystore Ed25519 verdict

**Owner:** A5 (Android adapter) · **Applies to:** `modules/deceipt-native/android`, `app/android`
**Related:** `DESIGN.md` §4.4, `docs/protocol/trust.md` §3, `docs/protocol/trust.md` §7 (escalated items)

This note records what was **verified against current official Android documentation**, not assumed,
and it states plainly where the PoC is weaker than hardware-backed non-exportability.

---

## 1. Can Android Keystore hold an Ed25519 key directly?

**Verdict: only from API 33 (Android 13) upward, and only where the device's KeyMint implementation
supports it. The PoC floor is `minSdk 24`, so a majority of the floor cannot.**

Evidence:

| Claim | Source |
|---|---|
| The `AndroidKeyStore` provider began supporting **Curve25519 for signatures (Ed25519)** and X25519 key agreement in **Android 13** (API 33). Hardware-backed when the device's KeyMint supports it. | Google Issue Tracker 356158095 *"Support EdDSA (Curve25519 and Curve448) keys in the Android KeyStore"* — https://issuetracker.google.com/issues/356158095 |
| `java.security` Ed25519 (`NamedParameterSpec.ED25519`, `Signature.getInstance("Ed25519")`) is a **platform** API that is not uniformly present even on API 33+: there are open reports of it failing on Android 15. | Google Issue Tracker 399856239 *"ed25519 signature algorithm not supported for android 15"* — https://issuetracker.google.com/issues/399856239 |
| `KeyProperties` (the Keystore key-algorithm constants, *"Added in API level 23"*) lists `KEY_ALGORITHM_EC`, `KEY_ALGORITHM_AES`, `KEY_ALGORITHM_RSA`, `KEY_ALGORITHM_HMAC_*`, and (later) `KEY_ALGORITHM_ML_DSA*` — **there is no `KEY_ALGORITHM_ED25519` constant**. Ed25519 in Keystore is selected by passing `NamedParameterSpec.ED25519` to an `EC`-family generator. | https://developer.android.com/reference/android/security/keystore/KeyProperties |
| `KeyGenParameterSpec` documents `EC`/`secp256r1`, `RSA`, `AES`, `HMAC` examples; EdDSA/Curve25519 is not in the documented example set and the spec's `setAlgorithmParameterSpec` accepts an `AlgorithmParameterSpec`, which is where `NamedParameterSpec.ED25519` enters. | https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec |

Because the introduction is **API 33** and the documented support level is **device-dependent**, the
adapter does not assume it. `MerchantKeyStore.directKeystoreEd25519Available()` gates on `SDK_INT >= 33`
and then **probes** the device: it generates a probe key in `AndroidKeyStore`, signs one message,
verifies it, and deletes the alias. Only a successful probe selects the direct path.

## 2. What this adapter does

```
generate(deviceKeyId):
  if directKeystoreEd25519Available():       # API 33+, probed
      generate an Ed25519 key inside AndroidKeyStore (alias deceipt.merchant.ed25519.v1)
      -> storage = "keystore_ed25519"        # private key non-exportable
  else:
      DESIGN.md §4.4 fallback:
        seed = 32 CSPRNG bytes (app crypto)
        wrapped = AES-256-GCM(keystore_key("deceipt.merchant.wrapAes.v1"), seed)
        persist `DECEIPTK1 || idLen || device_key_id || iv(12) || ciphertext` in private app storage
        -> storage = "keystore_wrapped_aes"
```

The wrapped file is written under `Context.filesDir` (private app storage, not external, not
world-readable). The AES wrapping key lives in `AndroidKeyStore` (`PURPOSE_ENCRYPT|DECRYPT`,
`BLOCK_MODE_GCM`, `ENCRYPTION_PADDING_NONE`, 256-bit, `setRandomizedEncryptionRequired(true)`), so a
fresh IV is generated per wrap. Signing decrypts the seed into the app process, signs, and zeroizes
the seed buffer.

## 3. The limitation, stated plainly

* **`keystore_wrapped_aes` is NOT hardware-backed non-exportability.** The Ed25519 private key is
  materialised in ordinary app memory to sign. Its protection is **device-bound confidentiality at
  rest**, not TEE-enforced signing.
* What the fallback *does* buy: the wrapped blob is useless without the Keystore AES key, which never
  leaves the TEE/StrongBox and cannot be extracted. Copying the blob to another device yields nothing.
* What it does *not* buy: on a rooted device with the app's Keystore key usable, the seed can be
  decrypted; and — per `docs/protocol/trust.md` §7 — **revocation and anti-backdating are out of scope
  for the PoC**, so a stolen key can backdate within its validity window regardless of storage class.
* `CapabilityReport.ed25519HardwareBacked` reports `true` **only** when `storage == "keystore_ed25519"`,
  so the shared UI never overstates the guarantee.

## 4. Backup / reset behaviour

| Event | Effect |
|---|---|
| App uninstall / "Clear storage" | Both the wrapped file and the Keystore aliases are destroyed. The merchant key is **gone**; the merchant regenerates and re-provisions its credential. |
| Android auto-backup | `android:allowBackup="false"` in `app/android/app/src/main/AndroidManifest.xml`. Neither the wrapped blob nor the Keystore key is backed up or restored, so a restored install is a fresh identity. |
| OS "Device-to-device transfer" | Keystore keys are non-transferable; the wrapped blob is not backed up (see above), so the key does not follow. |
| `merchantKeyDelete()` | Deletes both Keystore aliases and the wrapped file; clears any test-provisioned credential. |
| Biometric/PIN change | Irrelevant here: the PoC key requires no user-authentication authorisation, so there is no per-use auth binding (and therefore the key is usable whenever the app runs). |

**Consequence for users:** losing the device (or clearing storage) loses the merchant identity. That is
acceptable for the PoC because the merchant credential is pre-provisioned out of band
(`docs/protocol/trust.md` §3); a production system needs an enrolment/recovery design, which is
explicitly escalated and **not** solved here.

## 5. Session secrets

Session secrets are **unaffected** by this: ephemeral P-256 scalar(s), `shared_secret`, HKDF `prk`,
`okm`, the directional keys, the SBT and the reassembly buffers live only in memory for the life of a
session and are zeroized on teardown (`Session.teardown` → `Bytes.zeroize`). They never touch disk, the
Keystore, or the JS bridge. Zeroization in a managed runtime is best-effort and is **not** claimed as
guaranteed by the UI (`docs/protocol/handshake.md` §8).
