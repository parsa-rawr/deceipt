"""Frozen-vector loading + revision-integrity verification.

Every expected value the runner asserts comes from `protocol/vectors/**` or
`protocol/flows/vectors/**`. Nothing here reads the implementation under test.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any


def repo_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


REPO = repo_root()
VECTOR_DIR = os.path.join(REPO, "protocol", "vectors")
FLOW_VECTOR_DIR = os.path.join(REPO, "protocol", "flows", "vectors")


def load(name: str) -> Any:
    with open(os.path.join(VECTOR_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_flow(name: str) -> Any:
    with open(os.path.join(FLOW_VECTOR_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def revision_manifest() -> dict:
    with open(os.path.join(REPO, "protocol", "REVISION.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def verify_revision_integrity() -> dict:
    """Recompute every pinned file hash and the aggregate.

    Hash rule (REVISION.json): SHA-256(<revision id> || 0x00 ||
    <sorted 'path=sha256' rows joined by 0x00>) where paths are as listed in
    `files`, relative to protocol/vectors/.
    """
    man = revision_manifest()
    rev = man["revision"]
    rows = []
    missing = []
    mismatched = []
    for key, want in man["files"].items():
        path = os.path.normpath(os.path.join(VECTOR_DIR, key))
        if not os.path.isfile(path):
            missing.append(key)
            continue
        got = _sha256_file(path)
        if got != want:
            mismatched.append({"file": key, "expected": want, "actual": got})
        rows.append(f"{key}={want}")
    rows.sort()
    blob = rev.encode() + b"\x00" + b"\x00".join(r.encode() for r in rows)
    agg = hashlib.sha256(blob).hexdigest()
    return {
        "revision": rev,
        "file_count": len(man["files"]),
        "missing": missing,
        "mismatched": mismatched,
        "aggregate_recomputed": agg,
        "aggregate_pinned": man.get("aggregate_sha256"),
        "aggregate_match": agg == man.get("aggregate_sha256"),
        "status": man.get("status"),
    }


def test_keys() -> dict:
    return {k["name"]: k for k in load("keys/test-keys.json")["keys"]}


def trust_anchors() -> dict:
    return load("fixtures/trust-anchors-v1.json")


def case_index(vector: dict) -> dict:
    return {c["case"]: c for c in vector.get("cases", [])}
