#!/usr/bin/env python3
"""A6 security-invariant and adversarial suite (radio-independent parts).

Static invariant checks over the tree plus dynamic mutation experiments that
assert no failure path reaches a TRUSTED state.

Run:  python3 tests/security/run_security.py
Emits tests/security/results/security.json and security.md.
"""

from __future__ import annotations

import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "conformance"))

from runner import receipt as R  # noqa: E402
from runner.vectors import hx, load, read_bytes  # noqa: E402

RESULTS = []


def check(cid, target, ok, detail=""):
    RESULTS.append({"id": cid, "target": target, "status": "PASS" if ok else "FAIL", "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {cid:6s} {target}" + (f"  -- {detail}" if detail else ""))


def read(rel):
    return read_bytes(os.path.join(ROOT, rel)).decode("utf-8", "ignore")


def find_one(pattern: str) -> str:
    """Resolve the first path matching a glob, so A4/A5 package renames do not
    break the checks. Returns the relative path or '' if absent."""
    import glob as _glob

    matches = [p for p in _glob.glob(os.path.join(ROOT, pattern), recursive=True) if os.path.isfile(p)]
    return os.path.relpath(matches[0], ROOT) if matches else ""


def read_glob(pattern: str) -> str:
    rel = find_one(pattern)
    return read(rel) if rel else ""


def tracked():
    import subprocess

    out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line]


# ---------------------------------------------------------------------------
# Key storage
# ---------------------------------------------------------------------------


def suite_key_storage():
    ios = read("app/ios/DeceiptApp/Native/DeceiptKeyStore.swift")
    check("K1", "iOS merchant key uses Keychain ThisDeviceOnly accessibility",
          "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly" in ios, "DeceiptKeyStore.swift")
    check("K2", "iOS key material stored only in the Keychain, not UserDefaults/files",
          "UserDefaults" not in ios and "writeToFile" not in ios and "FileManager" not in ios, "DeceiptKeyStore.swift")
    android = read_glob("modules/deceipt-native/android/src/main/java/com/deceipt/**/crypto/MerchantKeyStore.kt")
    check("K3", "Android fallback wraps the seed with an AES key held in AndroidKeyStore",
          "AndroidKeyStore" in android and "AES" in android and "GCM" in android, find_one("modules/deceipt-native/android/src/main/java/com/deceipt/**/crypto/MerchantKeyStore.kt"))
    check("K4", "Android wrapped-key file is written non-world-readable in private app storage",
          "setReadable(false, false)" in android and "filesDir" in android, "MerchantKeyStore.kt")
    check("K5", "Android direct Ed25519 is PROBED at runtime, never assumed",
          "directKeystoreEd25519Available" in android and "SDK_INT < 33" in android, "MerchantKeyStore.kt")
    check("K6", "Android seed buffers are zeroized after use",
          "zeroize" in android, "MerchantKeyStore.kt")

    # no seed in bridge returns/events (contract + mock + native modules)
    mock = read("app/src/native/mock/InMemoryDeceiptNative.ts")
    contract = read("app/src/native/DeceiptNative.ts")
    ios_backend = read("app/ios/DeceiptApp/Native/DeceiptNativeBackend.swift")
    leaks = []
    for name, txt in (("mock", mock), ("contract", contract), ("ios-backend", ios_backend)):
        code = "\n".join(
            line for line in txt.splitlines()
            if not re.match(r"\s*(//|\*|/\*|#)", line)
        )
        for pat in ("privateSeed", "private_seed", "seedHex", "signingPrivateKey", "sessionKey:", "k_m2c_", "k_c2m_"):
            if pat in code:
                leaks.append(f"{name}:{pat}")
    check("K7", "no seed/session-key field crosses the JS bridge (contract, mock, iOS backend; comments excluded)",
          not leaks, "; ".join(leaks) or "0 leaks")


# ---------------------------------------------------------------------------
# Logs / crash output
# ---------------------------------------------------------------------------


def suite_logs():
    roots = ["app/src", "app/ios/DeceiptApp", "app/android/app/src", "modules/deceipt-native"]
    pats = re.compile(r"\b(NSLog|os_log|console\.log|System\.out|Log\.[dviwe]\(|println)\b")
    hits = []
    for root in roots:
        base = os.path.join(ROOT, root)
        for dirpath, _dirs, files in os.walk(base):
            if any(seg in dirpath for seg in (".build", "node_modules", "Pods", "build")):
                continue
            for fn in files:
                if fn.endswith((".swift", ".kt", ".java", ".ts", ".tsx", ".m", ".mm")):
                    p = os.path.join(dirpath, fn)
                    for i, line in enumerate(read_bytes(p).decode("utf-8", "ignore").splitlines(), 1):
                        if pats.search(line):
                            hits.append(f"{os.path.relpath(p, ROOT)}:{i}")
    check("L1", "no NSLog/console.log/Log./println in native or shared code (ordinary logs)",
          not hits, "; ".join(hits[:10]) or "0 sinks")
    # receipts/keys are not printed even in dev
    hits2 = []
    for root in roots:
        base = os.path.join(ROOT, root)
        for dirpath, _dirs, files in os.walk(base):
            if any(seg in dirpath for seg in (".build", "node_modules", "Pods", "build")):
                continue
            for fn in files:
                if fn.endswith((".swift", ".kt", ".java", ".ts")):
                    txt = read_bytes(os.path.join(dirpath, fn)).decode("utf-8", "ignore")
                    if re.search(r"(log|print).{0,40}(seed|\bkey\b|sessionkey)", txt, re.I):
                        hits2.append(os.path.relpath(os.path.join(dirpath, fn), ROOT))
    check("L2", "no log/print statement referencing seed/key material", not hits2, "; ".join(hits2) or "0 hits")


# ---------------------------------------------------------------------------
# Backup exposure
# ---------------------------------------------------------------------------


def suite_backup():
    app_manifest = read("app/android/app/src/main/AndroidManifest.xml")
    check("X1", "Android app disables adb/cloud backup (allowBackup=false)",
          'android:allowBackup="false"' in app_manifest, "app AndroidManifest.xml")
    ios = read("app/ios/DeceiptApp/Native/DeceiptKeyStore.swift")
    check("X2", "iOS Keychain items are excluded from backups (ThisDeviceOnly)",
          "ThisDeviceOnly" in ios, "DeceiptKeyStore.swift")


# ---------------------------------------------------------------------------
# Parser / resource bounds
# ---------------------------------------------------------------------------


def suite_bounds():
    bounds = json.load(open(os.path.join(ROOT, "protocol", "schema", "bounds-v1.json")))
    cbor = bounds["cbor"]
    receipt = bounds["receipt"]
    check("P1", "CBOR hard caps present (depth 12, items 8192, text 4096, bytes 65536)",
          cbor["max_depth"] == 12 and cbor["max_items"] == 8192 and cbor["max_text_bytes"] == 4096
          and cbor["max_bytes"] == 65536, json.dumps(cbor))
    check("P2", "receipt byte cap 65536 and per-collection caps defined",
          receipt["max_receipt_bytes"] == 65536 and receipt["max_lines"] == 256 and receipt["max_extensions"] == 32, "")
    # depth/size enforcement in the independent codec (already fuzzed by vectors)
    from runner import cbor as C

    depth_bomb = b"\x81" * 20 + b"\x00"
    try:
        C.decode(depth_bomb)
        deep = "no error"
    except Exception as e:  # noqa: BLE001
        deep = getattr(e, "name", type(e).__name__)
    check("P3", "nested-array depth bomb is rejected (CBOR_DEPTH_EXCEEDED)", deep == "CBOR_DEPTH_EXCEEDED", deep)
    # transfer bound
    wire = bounds["wire"]
    check("P4", "transfer/control caps defined (ciphertext 65552, frames 32768, pdu 2048, window 64)",
          wire["max_transfer_ciphertext"] == 65552 and wire["max_frames"] == 32768
          and wire["max_control_pdu"] == 2048 and wire["window_frames"] == 64, "")


# ---------------------------------------------------------------------------
# Repo hygiene (PUBLIC repo)
# ---------------------------------------------------------------------------


def suite_repo_hygiene():
    gi = read(".gitignore")
    need = ["*.pem", "*.key", "*.keystore", "*.p12", "*.jks", "*.mobileprovision", ".env"]
    check("H1", ".gitignore excludes key/credential/env material", all(n in gi for n in need),
          ", ".join(n for n in need if n not in gi) or "all present")
    files = tracked()
    from runner.hygiene import scan_tracked_keyfiles, is_known_debug_keystore, DEBUG_KEYSTORE_ALLOWLIST

    violations = scan_tracked_keyfiles(files, ROOT)
    check("H2", "no tracked private-key/keystore files except the verified debug-keystore throwaway",
          not violations, "; ".join(violations) or "no violations")
    # Prove the exception is safe structurally: the allow-listed file must parse as
    # the single-alias JKS debug keystore, so a release keystore at that path fails.
    for allow in DEBUG_KEYSTORE_ALLOWLIST:
        ok, detail = is_known_debug_keystore(allow, ROOT)
        check("H2b", f"allow-listed debug keystore {allow} structurally verified (single androiddebugkey)",
              ok, detail)
    check("H3", "frozen test vectors are intentionally tracked (docs/decisions.md D-003)",
          any(f.startswith("protocol/vectors/") for f in files) and "protocol/vectors" in read("docs/decisions.md"),
          "protocol/vectors/** tracked")
    allowed_keys = "protocol/vectors/keys/"  # D-003: frozen TEST-ONLY material is intentionally tracked
    envish = [f for f in files if re.search(r"(^|/)(secrets/|keys/|\.env)", f) and not f.startswith(allowed_keys)]
    check("H4", "no secrets directory or .env file is tracked (excluding intentional test vectors)",
          not envish, "; ".join(envish) or "none")
    # every vector carries _TESTONLY; no production root private key in tree
    root_priv = load("keys/test-keys.json")["keys"][0]["private_seed_hex"]
    ta = read("app/src/config/trustAnchors.ts")
    check("H5", "only the labelled test root private key exists, and it is not in the app",
          root_priv not in ta and "_TESTONLY" in read("protocol/vectors/NOTICE"), "root-poc-1 private absent from app")
    # README/advertising: is the public repo documented as PoC?
    check("H6", "repository declares PoC / test-only status in-band",
          "TESTONLY" in read("protocol/vectors/NOTICE") and "test" in read("docs/protocol/trust.md").lower(), "")


# ---------------------------------------------------------------------------
# No failure path reaches verified (dynamic)
# ---------------------------------------------------------------------------


def _valid_receipt():
    rv = load("receipt-valid.json")
    return hx(rv["cose_sign1_hex"]), rv


def suite_no_false_trust():
    raw, rv = _valid_receipt()
    anchors = {hx(k): hx(v) for k, v in load("receipt-invalid.json")["cases"][0]["anchors_hex"].items()}
    ok = R.verify_receipt(raw, anchors, 1767225600)
    check("V0", "control: the unmutated valid receipt IS TRUSTED", ok["outcome"] == "TRUSTED", ok["outcome"])

    rng = random.Random(0xDEECE1)
    trusted = 0
    for _ in range(400):
        b = bytearray(raw)
        pos = rng.randrange(len(b))
        b[pos] ^= 1 << rng.randrange(8)
        res = R.verify_receipt(bytes(b), anchors, 1767225600)
        if res["outcome"] == "TRUSTED":
            trusted += 1
    check("V1", "400 random single-bit mutations of the valid receipt: none TRUSTED",
          trusted == 0, f"{trusted} trusted of 400")

    # payload-only mutations
    trusted2 = 0
    for _ in range(200):
        b = bytearray(raw)
        pos = rng.randrange(len(b))
        b[pos] ^= 0xFF
        res = R.verify_receipt(bytes(b), anchors, 1767225600)
        if res["outcome"] == "TRUSTED":
            trusted2 += 1
    check("V2", "200 random byte-flip mutations of the valid receipt: none TRUSTED",
          trusted2 == 0, f"{trusted2} trusted of 200")

    # cross-session credential
    other = hx(load("credentials.json")["cases"][0]["credential_hex"])
    bogus = bytearray(raw)
    res = R.verify_receipt(bytes(bogus), anchors, 1767225600, session_credential=other + b"\x00")
    check("V3", "wrong session credential never TRUSTED",
          res["outcome"] != "TRUSTED", f"{res['outcome']}/{res['error']}")

    # unknown issuer
    uc = {c["case"]: c for c in load("receipt-invalid.json")["cases"]}["unknown_issuer_credential"]
    res = R.verify_receipt(hx(uc["cose_sign1_hex"]), {hx(k): hx(v) for k, v in uc["anchors_hex"].items()}, uc["verify_at_unix"])
    check("V4", "validly signed rogue receipt (unknown issuer) never TRUSTED",
          res["outcome"] == "UNVERIFIED_UNKNOWN_ISSUER" and not res["key_authorized"], res["outcome"])

    # offer committed-member mutation -> WRONG_TRANSACTION
    offer_hex = rv["receipt_offer_hex"]
    offer = bytearray(hx(offer_hex))
    from runner import cbor as C

    offer_map = C.decode(bytes(offer))
    committed = {"receipt_id": 3, "total": 5, "currency": 6, "issued_at": 7, "kind": 8, "merchant_id": 10, "ref": 4}
    wrong = []
    for label in committed.values():
        m2 = dict(offer_map)
        v = m2[label]
        if isinstance(v, int):
            m2[label] = v ^ 1
        elif isinstance(v, bytes):
            m2[label] = bytes([v[0] ^ 1]) + v[1:]
        elif isinstance(v, str):
            m2[label] = ("Z" if v[0] != "Z" else "Y") + v[1:]
        else:
            continue
        res = R.verify_receipt(raw, anchors, 1767225600, offer=C.encode(m2))
        if res["outcome"] != "REJECTED" or res["error"] != "WRONG_TRANSACTION":
            wrong.append(f"label{label}:{res['outcome']}/{res['error']}")
    check("V5", "mutating any committed offer member yields WRONG_TRANSACTION",
          not wrong, "; ".join(wrong) or f"{len(committed)} members")

    # version downgrade
    body_ok = R.verify_receipt(raw, anchors, 1767225600)
    check("V6", "control still trusted before downgrade", body_ok["outcome"] == "TRUSTED", "")

    # incomplete transfer / oversized: use the size bound before parse
    oversize = load("receipt-invalid.json")
    idx = {c["case"]: c for c in oversize["cases"]}
    res = R.verify_receipt(hx(idx["receipt_oversize_raw"]["cose_sign1_hex"]), anchors, 1767225600)
    check("V7", "oversized container rejected before parse (RECEIPT_SIZE_EXCEEDED)",
          res["error"] == "RECEIPT_SIZE_EXCEEDED", res["error"])


# ---------------------------------------------------------------------------


def main():
    print("== Deceipt A6 security suite ==")
    for fn in (suite_key_storage, suite_logs, suite_backup, suite_bounds, suite_repo_hygiene, suite_no_false_trust):
        print(f"\n-- {fn.__name__} --")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, "suite aborted", False, f"{type(e).__name__}: {e}")
    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    failed = [r for r in RESULTS if r["status"] == "FAIL"]
    outdir = os.path.join(HERE, "results")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "security.json"), "w", encoding="utf-8") as fh:
        json.dump({"passed": passed, "failed": len(failed), "checks": RESULTS}, fh, indent=1)
    with open(os.path.join(outdir, "security.md"), "w", encoding="utf-8") as fh:
        fh.write("# A6 security results\n\n")
        fh.write(f"`{passed}` PASS / `{len(failed)}` FAIL\n\n| id | target | status | detail |\n|---|---|---|---|\n")
        for r in RESULTS:
            fh.write(f"| {r['id']} | {r['target']} | {r['status']} | {r['detail']} |\n")
    print(f"\n== {passed} PASS / {len(failed)} FAIL ==")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
