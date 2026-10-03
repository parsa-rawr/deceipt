# Deceipt — repo hygiene. THIS REPOSITORY IS PUBLIC.

Remote: https://github.com/parsa-rawr/deceipt (public). Anything committed here is world-readable forever
(git history is not erasable). Treat every commit as a publication.

## MUST NEVER be committed
- Real merchant private keys or merchant key stores (`*.pem`, `*.key`, `*.p8`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keystore`, `*.mobileprovision`, `*.provisionprofile`, `*.keychain`, `merchant-keys/`, `session-keys/`).
- Real session keys, handshake ephemeral secrets, or AEAD key material.
- Anything derived from a production trust root (root signing keys, delegation certs, enrollment secrets).
- `.env` / `.env.*` files with live values (`.env.example` is fine).
- iOS/Android signing identities, provisioning profiles, upload keys.
- Build artifacts: `node_modules/`, Pods/, `.gradle/`, `build/`, derived output, `*.ipa`, `*.apk`, `*.aab`.

## Permitted exception: protocol test vectors
`protocol/vectors/**` contains **test-only deterministic** keys and nonces so both phones can reproduce
frozen fixtures byte-for-byte. They are permitted **only if** they are clearly labelled test-only in-file
and described in `docs/protocol/`. They are not secret, must never be reused for a real merchant, and must
never be derived from a production root.

## Permitted exception: the Android debug keystore (A6, 2026-10-03)
`app/android/app/debug.keystore` **is tracked on purpose.** `app/android/app/build.gradle` sets
`storeFile file('debug.keystore')`, so AGP fails a clean-clone Android debug build if the file is absent.
It is the standard Android SDK-generated throwaway:

* one entry, alias `androiddebugkey`, store password `android` (the SDK default — world-known, not a secret);
* it signs only local `debug` builds; it can never sign a release (`release` uses a separate, git-ignored key);
* it contains no merchant, session, trust-root, or production material.

**This exception is narrow and enforced structurally, not by comment.** A6's suites
(`tests/conformance/runner/hygiene.py`, used by `run_conformance.py` check `B9b` and
`run_security.py` checks `H2`/`H2b`) fail on **any** tracked `*.keystore`/`*.jks`/`*.pem`/… file
**except** this one path, and they re-open the allow-listed file with `keytool` and require it to be a
JKS with exactly one `androiddebugkey` entry. A release keystore dropped at that path (different alias
or password) **fails** the check. Untracking the file remains preferable if the build is ever changed
to generate or ignore it.

## Enforcement
`.gitignore` covers the key-material and build-artifact patterns above; repo-root `/keys/` and `/secrets/`
are local-only secret stores. Before any push, run `git status` and `git diff --cached` and confirm no real
key material is staged. If a real secret is ever committed to a public repo, treat the secret as burned and
rotate it — deleting the file does not remove it from history.
