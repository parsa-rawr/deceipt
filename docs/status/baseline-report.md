# Deceipt PoC — Wave 0 Baseline Status

**Date:** 2026-10-03 · **Owner:** A0 · **Baseline commit:** `0e84520c385cc1671b7dcacebffb13142d6af99c`

## Wave 0 exit condition
Repo exists; scaffold builds an empty app. Contract freeze happens in Wave 1.

## Done
- `git init` at `/Users/mateo/CODE/Deceipt`; baseline commit `0e84520` contains the spec under version control:
  - `DESIGN.md` (mode was `0600` → `644`, now tracked)
  - `deceipt-crypto-ble.mmd` (mode was `0600` → `644`, now tracked)
  - `Deceipt_Subagent_Delegation_Plan.md` (rev 2, already `644`)
- RN flavor decided and sourced: **bare React Native Community CLI** (see `docs/decisions.md` D-001).
- §1 directory layout created (A0-owned roots + A1/A2 scopes so they can write immediately).
- `.gitignore` covering `node_modules`, build outputs, Pods/Gradle caches, env, and key material patterns.
- `docs/decisions.md` seeded: D-001 RN flavor + sources, D-002 stable/provisional boundary, 15-row open-items table.

## Toolchain observed locally
| Tool | Observed |
|---|---|
| git | 2.47.0 |
| node | v24.19.0 |
| npm | 11.17.0 |
| Xcode | 27.0 (27A266a) |
| CocoaPods | 1.15.2 |
| JDK | 17.0.9 (Zulu) at `/Library/Java/JavaVirtualMachines/zulu-17.jdk`; JDK 21 also installed |
| Android SDK | **incomplete** — only Homebrew `android-platform-tools` 37.0.1 (adb); no `platforms/`, `build-tools/`, or emulator under `$ANDROID_HOME` |

## Open / deferred to Wave 1+
- Android native build cannot proceed until an Android SDK is installed at `$ANDROID_HOME` (`/Users/mateo/Library/Android/sdk`) — recorded, not worked around.
- iOS/Android BLE peripheral support floor: A4/A5 hardware spikes (open item 10).
- Contract freeze: A1 passes A–D + A6 early review (open items 1–6, 11–13).
- A2 binding mechanism must be published before A1 freezes the wire contract (open item 7).

## Build evidence (observed, 2026-10-03)
Scaffold command (run verbatim):
```
npx @react-native-community/cli@20.2.0 init DeceiptApp --directory app --version 0.87.1 \
  --title Deceipt --package-name com.deceipt.poc --pm npm --install-pods true --skip-git-init true
```
Result: completed; template copied, deps installed, Ruby gems + CocoaPods installed.

| Check | Command | Observed |
|---|---|---|
| TypeScript | `cd app && npx tsc --noEmit` | exit 0, no output |
| Jest | `cd app && npx jest --ci` | 1 suite / 1 test passed |
| iOS simulator build | `cd app && xcodebuild -workspace ios/DeceiptApp.xcworkspace -scheme DeceiptApp -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath /tmp/deceipt-dd build` | **BUILD SUCCEEDED**, exit 0; product `/tmp/deceipt-dd/Build/Products/Debug-iphonesimulator/DeceiptApp.app` |
| Android debug build | `cd app/android && ./gradlew :app:assembleDebug --no-daemon` | see Android blocker below |

**Android blocker (explicit).** `$ANDROID_HOME=/Users/mateo/Library/Android/sdk` does not exist; the only Android tooling present is Homebrew `android-platform-tools` 37.0.1 (`adb`). No `platforms/`, `build-tools/`, or emulator. Command run: `cd app/android && ./gradlew :app:assembleDebug --no-daemon` → exit 1 in 7m23s with:

```
FAILURE: Build failed with an exception.
* Where:
Build file '/Users/mateo/CODE/Deceipt/app/android/build.gradle' line: 21
* What went wrong:
A problem occurred evaluating root project 'com.deceipt.poc'.
> Failed to apply plugin 'com.facebook.react.rootproject'.
   > A problem occurred configuring project ':app'.
      > SDK location not found. Define a valid SDK location with an ANDROID_HOME environment variable
        or by setting the sdk.dir path in your project's local properties file at
        '/Users/mateo/CODE/Deceipt/app/android/local.properties'.
BUILD FAILED in 7m 23s
```

This is an environment gap, not a code defect. Fix: install the Android SDK (cmdline-tools + platform + build-tools matching RN 0.87's `compileSdk`), set `sdk.dir` in `app/android/local.properties` (git-ignored) or `ANDROID_HOME`, then re-run. A5 owns the Android API floor decision from its hardware spike.

## Remote
- Canonical remote (user-directed, 2026-10-03): `https://github.com/parsa-rawr/deceipt.git` — **PUBLIC**.
- Default branch: `main`. Push verified: local `HEAD` == `origin/main` == `6562be9d97cfd7d5417a101eaea843e45fb986ab`.
- Repo is public → `docs/security/repo-hygiene.md` states what must never be committed.
