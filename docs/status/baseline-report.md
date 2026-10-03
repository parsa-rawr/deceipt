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
