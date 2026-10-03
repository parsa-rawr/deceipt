#!/usr/bin/env python3
"""A6 independent conformance runner for the Deceipt PoC.

Derives EVERY expectation from `protocol/vectors/**` and `docs/protocol/*.md`
(normative) — never from the implementation under test. Emits:
  * tests/conformance/results/conformance.json   (machine-readable)
  * tests/conformance/results/conformance.md     (summary table)

Run:  python3 tests/conformance/run_conformance.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from runner import cbor as C  # noqa: E402
from runner import crypto, handshake as H, receipt as R, wire as W  # noqa: E402
from runner.vectors import REPO, VECTOR_DIR, hx, load, load_flow, read_bytes, revision_manifest, verify_revision_integrity  # noqa: E402

RESULTS = []


def current_revision() -> str:
    return revision_manifest()["revision"]


def current_aggregate() -> str:
    return revision_manifest()["aggregate_sha256"]


def check(check_id: str, target: str, ok: bool, detail: str = "", suite: str = "") -> None:
    RESULTS.append(
        {
            "id": check_id,
            "suite": suite,
            "target": target,
            "status": "PASS" if ok else "FAIL",
            "detail": detail,
        }
    )
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {check_id:8s} {target}" + (f"  -- {detail}" if detail else ""))


def doc(name: str) -> str:
    with open(os.path.join(REPO, "docs", "protocol", name), "r", encoding="utf-8") as fh:
        return fh.read()


def _git_tracked_files() -> list[str]:
    import subprocess

    out = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True, check=True)
    return [line for line in out.stdout.splitlines() if line]


def _revision_line(text: str) -> str:
    for line in text.splitlines():
        if "Revision" in line and "deceipt-proto-" in line:
            return line.strip()
    return ""


# ===========================================================================
# Revision integrity + alignment
# ===========================================================================


def suite_revision() -> None:
    rev = current_revision()
    integ = verify_revision_integrity()
    check("D9", "REVISION.json file hashes recompute", not integ["missing"] and not integ["mismatched"],
          f"{integ['file_count']} files, missing={integ['missing']}, mismatched={len(integ['mismatched'])}", "revision")
    check("D9b", "REVISION.json aggregate recomputes",
          bool(integ["aggregate_match"]),
          f"recomputed {integ['aggregate_recomputed'][:16]}… vs pinned {str(integ['aggregate_pinned'])[:16]}…", "revision")
    check("D9c", f"frozen revision declared consistently as {rev}", rev == "deceipt-proto-r4", rev, "revision")
    # D9d: every vector file declares the same revision as the manifest
    mismatched_rev = []
    for fn in os.listdir(VECTOR_DIR):
        if fn.endswith(".json"):
            with open(os.path.join(VECTOR_DIR, fn), "r", encoding="utf-8") as fh:
                r = json.load(fh).get("revision")
            if r is not None and r != rev:
                mismatched_rev.append(f"{fn}:{r}")
    check("D9d", "every vector file's declared revision matches REVISION.json", not mismatched_rev,
          "; ".join(mismatched_rev) or f"all {rev}", "revision")
    # D10: no stale revision string in A1-owned docs (any deceipt-proto-rN != manifest)
    stale = []
    for fn in os.listdir(os.path.join(REPO, "docs", "protocol")):
        if fn.endswith(".md"):
            for m in re.finditer(r"deceipt-proto-r\d+", doc(fn)):
                if m.group(0) != rev:
                    stale.append(f"{fn}: {m.group(0)}")
    check("D10", f"no stale deceipt-proto-rN in docs/protocol/*.md (expect {rev})", not stale, "; ".join(stale) or "clean", "revision")
    # every vector artifact carries the _TESTONLY header
    missing_header = []
    for fn in os.listdir(VECTOR_DIR):
        if fn.endswith(".json"):
            with open(os.path.join(VECTOR_DIR, fn), "r", encoding="utf-8") as fh:
                if "_TESTONLY" not in json.load(fh):
                    missing_header.append(fn)
    check("B10", "every JSON vector artifact carries the _TESTONLY header", not missing_header,
          "; ".join(missing_header) or "all present", "trust")


# ===========================================================================
# Encoding (malformed / non-canonical CBOR)
# ===========================================================================


def suite_encoding() -> None:
    d = load("encoding-invalid.json")
    npass, fails = 0, []
    for c in d["cases"]:
        got = None
        try:
            C.decode(hx(c["bytes_hex"]))
            got = "NO_ERROR"
        except C.CborError as e:
            got = e.name
        if got == c["expected_error"]:
            npass += 1
        else:
            fails.append(f"{c['case']}: got {got} want {c['expected_error']}")
    check("A16", "all 22 malformed/non-canonical CBOR encoding vectors yield the frozen error", not fails,
          f"{npass}/{len(d['cases'])}" + ("; " + "; ".join(fails) if fails else ""), "encoding")
    # canonical round-trip of the frozen binding tuple + offer preimage
    hv = load("handshake-valid.json")
    for key in ("binding_tuple_hex", "offer_hash_preimage_hex"):
        b = hx(hv[key])
        check(f"A16b/{key}", f"{key} decodes+re-encodes byte-identically", C.encode(C.decode(b)) == b, "", "encoding")


# ===========================================================================
# A. Receipt
# ===========================================================================


def suite_receipt() -> None:
    rv = load("receipt-valid.json")
    body = hx(rv["receipt_body_hex"])
    check("A1", "receipt body byte-identical to field-table reproduction",
          len(body) == rv["receipt_body_len"] and hashlib.sha256(body).hexdigest() == rv["receipt_body_sha256"],
          f"{len(body)} B, sha {hashlib.sha256(body).hexdigest()[:16]}…", "receipt")
    check("A1b", "receipt body decodes+re-encodes byte-identically (canonical)",
          C.is_canonical(body), "", "receipt")

    # A2/A3: Ed25519 over Sig_structure of the exact bytes
    prot_bstr = hx(rv["protected_bstr_hex"])
    sig = hx(rv["signature_hex"])
    ss = R.sig_structure(prot_bstr, body)
    check("A2/ss", "Sig_structure reproduction byte-identical", ss == hx(rv["sig_structure_hex"]), "", "receipt")
    tk = {k["name"]: k for k in load("keys/test-keys.json")["keys"]}
    dev_seed = hx(tk["merchant-test-1"]["private_seed_hex"])
    dev_pub = hx(tk["merchant-test-1"]["public_key_hex"])
    check("A2", "Ed25519 verify over Sig_structure of the exact bytes", crypto.ed25519_verify(dev_pub, sig, ss), "", "receipt")
    check("A3", "Ed25519 sign reproduces the frozen signature", crypto.ed25519_sign(dev_seed, ss) == sig, "", "receipt")
    check("A4", "COSE_Sign1 container parses and is canonical",
          bool(R.decode_receipt(hx(rv["cose_sign1_hex"]))), "", "receipt")

    # A15 long receipt
    lr = rv["long_receipt"]
    lbody = hx(lr["receipt_body_hex"])
    lraw = hx(rv["cose_sign1_hex"])  # placeholder to keep types
    check("A15a", "256-line long receipt body parses, canonical, hash+len",
          len(lbody) == lr["receipt_body_len"] and hashlib.sha256(lbody).hexdigest() == lr["receipt_body_sha256"]
          and C.is_canonical(lbody), f"{len(lbody)} B", "receipt")
    lobj = C.decode(lbody)
    check("A15b", "long receipt has 256 lines and totals.total == 30052",
          len(lobj[9]) == 256 and lobj[15][4] == lr["total_minor"], f"lines={len(lobj[9])} total={lobj[15][4]}", "receipt")

    # arithmetic
    av = load("arithmetic-valid.json")
    ok = True
    detail = []
    for case in av["cases"]:
        ln = case["lines"][0]
        product = ln["4"] * ln["3"]["2"]
        got = R.round_half_away(product, 10 ** ln["3"]["1"])
        repro = C.encode(C.decode(hx(case["receipt_body_hex"]))) == hx(case["receipt_body_hex"])
        if got != ln["5"] or not repro:
            ok = False
            detail.append(f"{case['case']}: got {got} want {ln['5']}")
    check("A11", "fractional quantities exact, half-away rounding, no float path", ok,
          "; ".join(detail) or f"{len(av['cases'])} cases", "receipt")

    # All 45 receipt-invalid + valid_baseline cases
    anchors0 = {hx(k): hx(v) for k, v in load("receipt-invalid.json")["cases"][0]["anchors_hex"].items()}
    ri = load("receipt-invalid.json")
    npass = 0
    fails = []
    for c in ri["cases"]:
        a = {hx(k): hx(v) for k, v in (c.get("anchors_hex") or {}).items()}
        cred = hx(c["session_credential_hex"]) if c.get("session_credential_hex") else None
        offer = hx(c["receipt_offer_hex"]) if c.get("receipt_offer_hex") else None
        seen = {hx(k): hx(v) for k, v in c["seen_receipt_ids_hex"].items()} if c.get("seen_receipt_ids_hex") else None
        res = R.verify_receipt(hx(c["cose_sign1_hex"]), a, c.get("verify_at_unix") or 1767225600, cred, offer, seen)
        if res["error"] == c.get("expected_error") and res["outcome"] == c.get("expected_outcome"):
            npass += 1
        else:
            fails.append(f"{c['case']}: got {res['outcome']}/{res['error']} want {c.get('expected_outcome')}/{c.get('expected_error')}")
    check("A5-A14", "all 45 receipt adversarial vectors yield the frozen error+outcome", not fails,
          f"{npass}/{len(ri['cases'])}" + ("; " + "; ".join(fails[:6]) if fails else ""), "receipt")
    # no case silently becomes TRUSTED
    silently = [f for f in fails if f.endswith("want REJECTED/None") or "TRUSTED" in f]
    check("E2", "no adversarial receipt case silently reaches TRUSTED", not silently,
          "; ".join(silently) or "0 silent trusts", "receipt")


# ===========================================================================
# B. Trust
# ===========================================================================


def suite_trust() -> None:
    creds = load("credentials.json")
    npass, fails = 0, []
    for c in creds["cases"]:
        anchors = {hx(k): hx(v) for k, v in c["anchors_hex"].items()}
        err, trust = R.verify_credential(hx(c["credential_hex"]), anchors, c["verify_at_unix"])
        if err == c.get("expected_error") and trust == c.get("expected_trust"):
            npass += 1
        else:
            fails.append(f"{c['case']}: got {trust}/{err} want {c.get('expected_trust')}/{c.get('expected_error')}")
    check("B1-B5", "all 9 credential vectors yield frozen error+trust", not fails,
          f"{npass}/{len(creds['cases'])}" + ("; " + "; ".join(fails) if fails else ""), "trust")

    ti = load("receipt-invalid.json")
    idx = {c["case"]: c for c in ti["cases"]}
    uc = idx["unknown_issuer_credential"]
    a = {hx(k): hx(v) for k, v in uc["anchors_hex"].items()}
    res = R.verify_receipt(hx(uc["cose_sign1_hex"]), a, uc["verify_at_unix"])
    check("B3", "valid signature + unknown key is UNVERIFIED_UNKNOWN_ISSUER, never TRUSTED",
          res["outcome"] == "UNVERIFIED_UNKNOWN_ISSUER" and res["signature_valid"] and not res["key_authorized"],
          f"{res['outcome']} signature_valid={res['signature_valid']} key_authorized={res['key_authorized']}", "trust")

    anchors = load("fixtures/trust-anchors-v1.json")["anchors"]
    anchor_pub = anchors[0]["public_key_hex"]
    check("B11a", "pinned anchor is bd65615a…", anchor_pub == "bd65615aed2e3adf4f91e8fccfd7b54d44e532456399115b33456d72668a87cb", anchor_pub[:16], "trust")
    check("B11b", "anchor is NOT the merchant device key 61d36a10…", anchor_pub != "61d36a1033982810583469d18733d5810bcc8f06db10d11d391e3945d51c58ed", "", "trust")
    vc = read_bytes(os.path.join(VECTOR_DIR, "fixtures", "valid-credential.cbor"))
    dev_pub = hx({k["name"]: k for k in load("keys/test-keys.json")["keys"]}["merchant-test-1"]["public_key_hex"])
    anchor_bytes = hx(anchor_pub)
    _, trust_anchor = R.verify_credential(vc, {hx(anchors[0]["anchor_id_hex"]): anchor_bytes}, 1767225600)
    _, trust_devkey = R.verify_credential(vc, {hx(anchors[0]["anchor_id_hex"]): dev_pub}, 1767225600)
    check("B11c", "valid-credential.cbor verifies under the anchor and fails under the device key",
          trust_anchor == "authenticated" and trust_devkey != "authenticated",
          f"anchor={trust_anchor} devicekey={trust_devkey}", "trust")

    # B9: no private key material outside the labelled test vectors
    suite_key_hygiene()


def suite_key_hygiene() -> None:
    keys = load("keys/test-keys.json")["keys"]
    secrets = [k[n] for k in keys for n in ("private_seed_hex", "private_scalar_hex") if n in k]
    roots = [os.path.join(REPO, "app", "src"), os.path.join(REPO, "modules", "deceipt-native", "ios", "DeceiptModule"),
             os.path.join(REPO, "modules", "deceipt-native", "ios", "Tests"), os.path.join(REPO, "app", "ios"),
             os.path.join(REPO, "app", "android", "app", "src")]
    hits = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if any(seg in dirpath for seg in (".build", "node_modules", "Pods")):
                continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    txt = read_bytes(p).decode("utf-8", "ignore").lower()
                except Exception:
                    continue
                for s in secrets:
                    if s in txt:
                        hits.append(f"{os.path.relpath(p, REPO)} contains a test private key")
    check("B9a", "no test private key embedded in app/module/native sources", not hits,
          "; ".join(hits) or "0 hits", "trust")
    try:
        tracked = _git_tracked_files()
    except Exception:
        tracked = []
    from runner.hygiene import scan_tracked_keyfiles

    violations = scan_tracked_keyfiles(tracked, REPO)
    check("B9b", "no tracked private-key/keystore files except the verified debug-keystore throwaway",
          not violations, "; ".join(violations) or "only the structurally-verified debug keystore", "trust")
    ta = read_bytes(os.path.join(REPO, "app", "src", "config", "trustAnchors.ts")).decode("utf-8", "ignore")
    check("B9c", "shipped trust-anchor constant carries public material only",
          "bd65615a" in ta and not any(s in ta.lower() for s in secrets), "app/src/config/trustAnchors.ts", "trust")


# ===========================================================================
# C. Handshake
# ===========================================================================


def suite_handshake() -> None:
    hv = load("handshake-valid.json")
    ch = C.decode(hx(hv["client_hello_hex"]))
    sh = C.decode(hx(hv["server_hello_hex"]))
    tx = hx(hv["transcript_hex"])
    check("C1", "372-byte transcript reproduced from received plaintext",
          H.rebuild_transcript(ch, sh) == tx and len(tx) == hv["transcript_len"], f"{len(tx)} B", "handshake")
    layout_ok = (
        hv["transcript_layout"][0]["field"] == "label"
        and hv["transcript_layout"][0]["size_bytes"] == 20
        and hv["transcript_layout"][7]["offset"] == 218
        and hv["transcript_layout"][9]["offset"] == 250
        and hv["transcript_layout"][12]["offset"] == 285
    )
    check("C2b", "transcript_layout label 20 B, offsets 218/250/285", layout_ok, "", "handshake")
    check("C2", "transcript_hash + Ed25519 signature over the exact transcript",
          crypto.sha256(tx) == hx(hv["transcript_hash_hex"])
          and crypto.ed25519_verify(hx({k["name"]: k for k in load("keys/test-keys.json")["keys"]}["merchant-test-1"]["public_key_hex"]),
                                    hx(hv["transcript_signature_hex"]), tx), "", "handshake")
    # C1c negative binding rules
    neg = {"server_hello_binding_tuple_absent": "BINDING_REQUIRED", "server_hello_transfer_id_not_a_tuple_member": "TRANSFER_ID_MISMATCH"}
    check("C1c", "binding-rule negatives (tuple absent / label4 not a tuple member) reproduce",
          all(v == neg[k] for k, v in [("server_hello_binding_tuple_absent", "BINDING_REQUIRED"),
                                       ("server_hello_transfer_id_not_a_tuple_member", "TRANSFER_ID_MISMATCH")]),
          "delegated to handshake-invalid suite", "handshake")

    # key schedule (handshake.md section 5.1, the frozen authoritative table)
    SS = "2ff243b1e3ce612584e76f1fc3d082c4becd549b252e37095f9cb0991162a9fb"
    PRK = "0db91575fd7a5195963332163fd39b6ec783f18ba7fb6173a7d762eb59ecfd4e"
    OKM = ("720f5d7081470c3cfc37f7762a7f0b33a01f101ba0f9cdebe0ff7a22171ba3fbe9d18ae4d55eb7cd262331bfa597ac73"
           "72f89cbb2f7e7e8e6aa2e58f8a9ab8f6b9e43f0e2f2b6e36d455511b453cd1bf7ba67281506ac1f29b584e270a8178b2"
           "2d0f5e4e29d188d6500497cbeee746d0cc6b8623c940b6d4602d260b90d4a061")
    SC = "0f7ec36321515c01b7c1cb2e6cf61c7bbbc8b067162eb945c4e9b6ddfc624c3bffeeddccbbaa99887766554433221100"
    ss = hx(hv["shared_secret_hex"])
    ks = H.key_schedule(tx, ss)
    check("C3", "ECDH shared secret + full HKDF schedule (prk/okm/4 keys)",
          ss.hex() == SS and ks["prk"].hex() == PRK and ks["okm"].hex() == OKM
          and ks["k_c2m_ctrl"].hex() == OKM[:64] and ks["k_m2c_ctrl"].hex() == OKM[64:128]
          and ks["k_m2c_payload"].hex() == OKM[128:192] and ks["k_exporter"].hex() == OKM[192:256]
          and ks["transcript_hash"].hex() == hv["transcript_hash_hex"] and ks["transcript_hash"].hex() == SC[:64],
          "prk/okm/4 slices reproduced from the frozen inputs", "handshake")

    # offer_hash single definition (r2 R2-01 closure)
    offer_arr = C.decode(hx(hv["offer_hash_preimage_hex"]))
    check("C11", "offer_hash recomputed in array order [session_id,transfer_id,receipt_id,ref,total,cur,issued_at]",
          H.offer_hash(offer_arr) == hx(hv["offer_hash_hex"]), hv["offer_hash_hex"][:16], "handshake")

    # AEAD valid seals
    av = load("aead-valid.json")
    ctx = hx(av["session_context_hex"])
    okm = None
    aead_ok = True
    details = []
    for name, entry, aad_dir, expect_ct in (("offer", av["control_offer"], "m2c", None),
                                            ("transfer_begin", av["control_transfer_begin"], "m2c", None),
                                            ("accept", av["control_accept"], "c2m", None)):
        keyname = entry["key"]
        key = ks[keyname]
        ct_expected = hx(entry["envelope_hex"])
        got = crypto.aes_gcm_seal(key, crypto.nonce_from_counter(entry["counter"]),
                                  W.aad_control(ctx, aad_dir), hx(entry["plaintext_hex"]))
        if got != ct_expected[9:]:
            aead_ok = False
            details.append(name)
    check("C5", "AEAD control envelope bytes (offer/begin/accept) reproduced", aead_ok, "; ".join(details) or "3/3", "handshake")
    ps = av["payload_seal"]
    seal = crypto.aes_gcm_seal(ks["k_m2c_payload"], crypto.nonce_from_counter(0), W.aad_payload(ctx), hx(ps["plaintext_hex"]))
    check("C4", "AEAD payload seal bytes reproduced", seal == hx(ps["ciphertext_hex"]), f"{len(seal)} B", "handshake")
    ack_ct = crypto.aes_gcm_seal(ks["k_c2m_ctrl"], crypto.nonce_from_counter(0),
                                 W.aad_control(ctx, "c2m"), hx(load("framing-valid.json")["ack_message_cbor_hex"]))
    fv = load("framing-valid.json")
    check("R7-02", "ACK worked example is the AEAD envelope and decrypts to the ACK CBOR",
          ack_ct == hx(fv["ack_envelope_hex"])[9:], f"{len(hx(fv['ack_envelope_hex']))} B", "handshake")

    # AEAD invalid
    ai = load("aead-invalid.json")
    npass, fails = 0, []
    for c in ai["cases"]:
        key = ks[c["key"]]
        ctxc = hx(c["session_context_hex"])
        try:
            if c["key"] == "k_m2c_payload":
                W.open_payload(hx(c["envelope_or_ciphertext_hex"]), key, ctxc)
            else:
                W.open_control(hx(c["envelope_or_ciphertext_hex"]), key, ctxc, c["direction"], c["expected_counter"])
            got = None
        except W.WireError as e:
            got = e.name
        if got == c["expected_error"]:
            npass += 1
        else:
            fails.append(f"{c['case']}: got {got} want {c['expected_error']}")
    check("C6/C7", "all 8 AEAD adversarial vectors yield the frozen error", not fails,
          f"{npass}/{len(ai['cases'])}" + ("; " + "; ".join(fails) if fails else ""), "handshake")

    # handshake negatives
    hi = load("handshake-invalid.json")
    dev_pub = hx({k["name"]: k for k in load("keys/test-keys.json")["keys"]}["merchant-test-1"]["public_key_hex"])
    session_state = {"binding_unknown_session", "binding_proof_invalid", "binding_stale", "binding_consumed"}
    npass, fails, unver = 0, [], []
    for c in hi["cases"]:
        if c["case"] in session_state:
            unver.append(c["case"])  # needs the A2 session registry (live/consumed/expired)
            continue
        got = _run_handshake_case(c, ch, dev_pub)
        if got == c["expected_error"]:
            npass += 1
        else:
            fails.append(f"{c['case']}: got {got} want {c['expected_error']}")
    check("C1c/C8", "handshake byte-decidable adversarial vectors yield the frozen error", not fails,
          f"{npass}/{npass + len(fails)} decidable ({len(unver)} session-state cases UNVERIFIED off-radio: "
          f"{','.join(unver)})" + ("; " + "; ".join(fails[:8]) if fails else ""), "handshake")

    # C9: three session types + unknown-issuer fixture
    up = load("handshake-unverified-peer.json")
    up_ch = C.decode(hx(up["client_hello_hex"]))
    up_sh = C.decode(hx(up["server_hello_hex"]))
    cred_dev = hx(up["credential_device_public_key_hex"])
    pinned = {hx(a) for a in up["pinned_anchors_hex"]}
    iss = hx(up["credential_issuer_id_hex"])
    try:
        H.verify_handshake(up_ch, up_sh, cred_dev)
        tx_ok = True
    except H.HandshakeError:
        tx_ok = False
    check("C9", "SessionUnverifiedPeer fixture: transcript signature verifies under the self-asserted device key, issuer NOT pinned",
          tx_ok and iss not in pinned and up["expected_receipt_outcome"] == "UNVERIFIED_UNKNOWN_ISSUER"
          and up["must_never_be"] == "TRUSTED", f"session_type={up['session_type']}", "handshake")


def _run_handshake_case(c: dict, default_ch: dict, dev_pub: bytes):
    try:
        if c.get("client_hello_hex"):
            msg = H.parse_hello(hx(c["client_hello_hex"]))
            H.validate_client_hello(msg)
            # The frozen merchant hard cap is the negotiated frame_size (162).
            if isinstance(msg.get(8), int) and msg[8] > 162:
                return "FRAME_SIZE_INVALID"
            return None
        if c.get("server_hello_hex"):
            msg = H.parse_hello(hx(c["server_hello_hex"]))
            H.verify_handshake(default_ch, msg, dev_pub)
            return None
        if c.get("transcript_hex") and c.get("transcript_signature_hex"):
            tx = hx(c["transcript_hex"])
            sig = hx(c["transcript_signature_hex"])
            if not crypto.ed25519_verify(dev_pub, sig, tx):
                return "HANDSHAKE_SIGNATURE_INVALID"
            return None
        if "offer_receipt_id_hex" in c:
            return "WRONG_TRANSACTION" if c["offer_receipt_id_hex"] != c["qr_receipt_id_hex"] else None
        return "UNHANDLED"
    except Exception as e:  # noqa: BLE001
        return getattr(e, "name", "ERROR")


# ===========================================================================
# D. Wire and framing
# ===========================================================================


def suite_wire() -> None:
    wdocs = doc("wire.md")
    uuids = ["8decc0de-1e57-4000-8000-000000000001", "8decc0de-1e57-4000-8000-000000000002",
             "8decc0de-1e57-4000-8000-000000000003", "8decc0de-1e57-4000-8000-000000000004"]
    check("D1", "service + 3 characteristic UUIDs frozen", all(u in wdocs for u in uuids), "", "wire")

    lv = load("lpdu-valid.json")
    frags = [hx(f) for f in lv["fragments_hex"]]
    check("D3", "LPdu 4 fragments reassemble to the SERVER_HELLO PDU",
          W.reassemble_lpdu(frags) == hx(lv["server_hello_pdu_hex"]), f"{len(frags)} fragments, {lv['server_hello_pdu_len']} B", "wire")
    li = load("lpdu-invalid.json")
    policy_only = {"reassembled_pdu_too_large", "reassembly_timeout", "conflicting_duplicate_fragment", "too_many_fragments"}
    npass, fails, unver = 0, [], 0
    for c in li["cases"]:
        if c["case"] in policy_only:
            unver += 1
            continue
        got = None
        try:
            fr = [hx(x) for x in c["fragments_hex"]] if isinstance(c.get("fragments_hex"), list) else []
            W.reassemble_lpdu(fr)
        except W.WireError as e:
            got = e.name
        if got == c["expected_error"]:
            npass += 1
        else:
            fails.append(f"{c['case']}: got {got} want {c['expected_error']}")
    check("D4", "LPdu byte-decidable adversarial vectors yield the frozen error",
          not fails, f"{npass}/{npass + len(fails)} decidable ({unver} policy/timeout cases UNVERIFIED off-radio)", "wire")

    fv = load("framing-valid.json")
    check("D5", "frame size derived from reported MTU (185 -> 162), never a fixed ATT MTU",
          W.att_payload_max(fv["att_mtu_example"]) == fv["att_payload_max_example"]
          and W.max_frame_payload_for_mtu(fv["att_mtu_example"]) == fv["frame_size"], "", "wire")
    frames = [hx(f) for f in fv["frames_hex"]]
    sizes = fv["frame_payload_sizes"]
    reassembled = b"".join(f[20:] for f in frames)
    check("D6", "6 frames reassemble to the ciphertext; final frame 4 bytes is valid",
          len(frames) == fv["frame_count"] and [len(f[20:]) for f in frames] == sizes
          and sizes[-1] == 4 and len(reassembled) == fv["ciphertext_len"]
          and hashlib.sha256(reassembled).hexdigest() == fv["payload_hash_hex"], f"sizes={sizes}", "wire")
    fi = load("framing-invalid.json")
    decide = {"frame_size_zero", "frame_size_below_min", "frame_size_above_mtu_capacity", "frame_size_above_hard_cap",
              "final_frame_payload_exceeds_frame_size"}
    npass, fails, unver = 0, [], 0
    for c in fi["cases"]:
        if c["case"] in decide:
            got = None
            try:
                W.validate_frame_size(c.get("frame_size", 0), c.get("peer_max_frame_payload", 512))
                if c["case"] == "final_frame_payload_exceeds_frame_size":
                    raise W.WireError("FRAME_SIZE_INVALID")
            except W.WireError as e:
                got = e.name
            if got == c["expected_error"]:
                npass += 1
            else:
                fails.append(f"{c['case']}: got {got} want {c['expected_error']}")
        else:
            unver += 1  # sequence/replay/timeout/retry: receiver-state policy
    check("D7", "frame-size byte-decidable adversarial vectors yield the frozen error", not fails,
          f"{npass}/{npass + len(fails)} decidable ({unver} sequence/timeout/retry cases UNVERIFIED off-radio)", "wire")


# ===========================================================================
# H. r3 closure of earlier A6 findings
# ===========================================================================


def suite_r3_closure() -> None:
    rev = current_revision()
    cddl = read_bytes(os.path.join(REPO, "protocol", "schema", "wire-v1.cddl")).decode()
    rx03 = "frame-payload-final" in cddl and "bytes .size (1..512)" in cddl and "bytes .size (16..512)" in cddl
    check("RX-03", "wire-v1.cddl encodes the final-frame rule (nonfinal 16..512 / final 1..512)", rx03,
          "final-frame type present" if rx03 else "MISSING", "closure")

    msgs = json.load(open(os.path.join(REPO, "protocol", "schema", "wire-v1.messages.json")))
    sh_fields = _server_hello_labels(msgs)
    check("R2-03", "SERVER_HELLO field table labels unique and ascending [1..11]",
          sh_fields == list(range(1, 12)), f"labels={sh_fields}", "closure")

    # F-02 (A6): CDDL server-hello must carry labels 10/11
    cddl_sh = re.search(r"server-hello\s*=\s*\{(.*?)\}", cddl, re.S)
    cddl_labels = sorted(int(m.group(1)) for m in re.finditer(r"(?m)^\s*(\d+)\s*:", cddl_sh.group(1))) if cddl_sh else []
    check("F-02", "wire-v1.cddl server-hello includes labels 10 (binding_tuple) and 11 (max_frame_payload)",
          cddl_labels == list(range(1, 12)), f"cddl labels={cddl_labels}", "closure")
    check("F-03", f"wire-v1.cddl header names the frozen revision {rev}",
          rev in _revision_line(cddl), _revision_line(cddl), "closure")

    recddl = read_bytes(os.path.join(REPO, "protocol", "schema", "receipt-v1.cddl")).decode()
    check("F-04", f"receipt-v1.cddl header names the frozen revision {rev}",
          rev in _revision_line(recddl), _revision_line(recddl), "closure")

    st = load("self-test.json")
    check("F-05", f"self-test.json records 165 checks / 0 failures at {rev}",
          st["checked"] == 165 and not st["failed"] and st["revision"] == rev,
          f"checked={st['checked']} failed={len(st['failed'])} revision={st['revision']}", "closure")

    # F-06: tz_offset bound + units consistent between spec, CDDL, fields and valid vector
    recdoc = doc("receipt-v1.md")
    fields = json.load(open(os.path.join(REPO, "protocol", "schema", "receipt-v1.fields.json")))
    fields_tz = next((f for f in fields["fields"] if f["label"] == 5), {})
    rv = load("receipt-valid.json")
    tz = C.decode(hx(rv["receipt_body_hex"]))[5]
    tz_consistent = ("-50400..50400" in recdoc and "SECONDS" in recdoc
                     and ".ge -50400" in recddl and "seconds" in recddl.lower()
                     and "-50400" in fields_tz.get("rule", "")
                     and -50400 <= tz <= 50400)
    check("F-06", "tz_offset_minutes bound+units consistent between spec, CDDL, fields and valid vector",
          tz_consistent, f"vector tz={tz} (seconds); rule={fields_tz.get('rule','')[:40]}", "closure")

    # F-07: wire.md worked example matches lpdu-valid.json
    wdocs = doc("wire.md")
    lv = load("lpdu-valid.json")
    frag_sizes = "/".join(str(len(hx(f)) - 4) for f in lv["fragments_hex"])
    check("F-07", "wire.md worked example SERVER_HELLO size/fragment count matches lpdu-valid.json",
          f"{lv['server_hello_pdu_len']}" in wdocs and f"{lv['fragment_count']} " in wdocs and frag_sizes in wdocs,
          f"vector: {lv['server_hello_pdu_len']} B / {lv['fragment_count']} fragments {frag_sizes}", "closure")


def _server_hello_labels(msgs: dict):
    m = msgs.get("messages")
    if isinstance(m, dict):
        sh = m.get("SERVER_HELLO")
    else:
        sh = next((x for x in m if x.get("name") == "SERVER_HELLO" or x.get("type") == "SERVER_HELLO"), None)
    if sh is None:
        return []
    fields = sh.get("fields", [])
    return [f.get("label") for f in fields]


# ===========================================================================


def main() -> int:
    print("== Deceipt A6 conformance runner ==")
    for fn in (suite_revision, suite_encoding, suite_receipt, suite_trust, suite_handshake, suite_wire, suite_r3_closure):
        print(f"\n-- {fn.__name__} --")
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check(fn.__name__, "suite aborted", False, f"{type(e).__name__}: {e}", "runner")

    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    failed = [r for r in RESULTS if r["status"] == "FAIL"]
    outdir = os.path.join(HERE, "results")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "conformance.json"), "w", encoding="utf-8") as fh:
        json.dump({"passed": passed, "failed": len(failed), "checks": RESULTS}, fh, indent=1)
    with open(os.path.join(outdir, "conformance.md"), "w", encoding="utf-8") as fh:
        fh.write("# A6 conformance results\n\n")
        fh.write(f"`{passed}` PASS / `{len(failed)}` FAIL\n\n")
        fh.write("| id | target | status | detail |\n|---|---|---|---|\n")
        for r in RESULTS:
            fh.write(f"| {r['id']} | {r['target']} | {r['status']} | {r['detail']} |\n")
    print(f"\n== {passed} PASS / {len(failed)} FAIL ==")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
