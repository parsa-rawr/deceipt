"""Repo-hygiene helpers shared by the conformance and security suites.

The only permitted key-material-looking file in this public repo is the standard
Android SDK debug keystore, which `app/android/app/build.gradle` requires to exist
for a clean-clone build. It is allowed *only* while it structurally parses as the
well-known throwaway debug keystore (single `androiddebugkey` entry, conventional
store password). A release keystore dropped at that path fails the check.
"""

from __future__ import annotations

import os
import re
import subprocess

DEBUG_KEYSTORE_ALLOWLIST = {"app/android/app/debug.keystore"}

KEYFILE_RE = re.compile(
    r"\.(pem|key|p8|p12|pfx|jks|keystore|keychain|mobileprovision|provisionprofile|der|cer|crt|csr)$",
    re.IGNORECASE,
)


def is_known_debug_keystore(rel_path: str, repo_root: str) -> tuple[bool, str]:
    """True iff `rel_path` is the standard Android debug keystore.

    Structural proof, not a blanket exception: the file must open as a JKS with
    the conventional debug store password and contain exactly the one
    `androiddebugkey` alias. A release keystore (different alias/password) fails.
    """
    path = os.path.join(repo_root, rel_path)
    if not os.path.isfile(path):
        return False, "file missing"
    try:
        out = subprocess.run(
            ["keytool", "-list", "-keystore", path, "-storepass", "android"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"keytool error: {e}"
    if out.returncode != 0:
        return False, f"not the debug keystore (keytool: {out.stderr.strip()[:120]})"
    m = re.search(r"contains (\d+) entr", out.stdout)
    entries = int(m.group(1)) if m else -1
    has_alias = "androiddebugkey" in out.stdout
    ok = entries == 1 and has_alias
    return ok, f"entries={entries} androiddebugkey={has_alias}"


def scan_tracked_keyfiles(tracked: list[str], repo_root: str) -> list[str]:
    """Return violations: tracked private-key/keystore files that are neither the
    allow-listed debug keystore nor structurally identical to it."""
    violations = []
    for f in tracked:
        if not KEYFILE_RE.search(f):
            continue
        if f in DEBUG_KEYSTORE_ALLOWLIST:
            ok, detail = is_known_debug_keystore(f, repo_root)
            if not ok:
                violations.append(f"{f} (allow-listed debug-keystore exception denied: {detail})")
            continue
        violations.append(f)
    return violations
