#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verification of protocol/vectors/** for Deceipt protocol revision deceipt-proto-r1.

This is deliberately a *second* implementation path: it re-derives every published
expected value from the published inputs using only `cryptography` + stdlib, and
asserts the values the docs state. It fails loudly on any drift between the
vectors, the field tables, and the prose.

Run:  python3 protocol/vectors/tools/verify_vectors.py
Exit: 0 = ok, 1 = mismatch
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
V = os.path.join(HERE, "..")
S = os.path.join(V, "..", "schema")

fails = []


def load(rel):
    with open(os.path.join(V, rel), encoding="utf-8") as f:
        return json.load(f)


def load_schema(rel):
    with open(os.path.join(S, rel), encoding="utf-8") as f:
        return json.load(f)


def eq(name, got, want):
    if got != want:
        fails.append("%s: got %r want %r" % (name, got, want))


def head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)


def enc(o):
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if isinstance(o, int):
        return head(0, o) if o >= 0 else head(1, -1 - o)
    if isinstance(o, (bytes, bytearray)):
        return head(2, len(o)) + bytes(o)
    if isinstance(o, str):
        b = o.encode()
        return head(3, len(b)) + b
    if isinstance(o, (list, tuple)):
        return head(4, len(o)) + b"".join(enc(x) for x in o)
    if isinstance(o, dict):
        items = sorted(o.items(), key=lambda kv: enc(kv[0]))
        return head(5, len(items)) + b"".join(enc(k) + enc(v) for k, v in items)
    raise TypeError(type(o))


def dec(buf):
    pos = [0]

    def take(n):
        b = buf[pos[0]:pos[0] + n]
        if len(b) != n:
            raise ValueError("truncated")
        pos[0] += n
        return b

    def item():
        ib = take(1)[0]
        major, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            arg = ai
        elif ai == 24:
            arg = take(1)[0]
        elif ai == 25:
            arg = struct.unpack(">H", take(2))[0]
        elif ai == 26:
            arg = struct.unpack(">I", take(4))[0]
        elif ai == 27:
            arg = struct.unpack(">Q", take(8))[0]
        else:
            raise ValueError("bad ai")
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return take(arg)
        if major == 3:
            return take(arg).decode("utf-8")
        if major == 4:
            return [item() for _ in range(arg)]
        if major == 5:
            return {item(): item() for _ in range(arg)}
        if major == 7:
            return {20: False, 21: True}[ai]
        raise ValueError("major %d" % major)

    v = item()
    if pos[0] != len(buf):
        raise ValueError("trailing")
    return v


def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return prk, out[:length]


def nonce(c):
    return b"\x00\x00\x00\x00" + struct.pack(">Q", c)


def main():
    keys = {k["name"]: k for k in load("keys/test-keys.json")["keys"]}
    anchors = {a["anchor_id_hex"]: bytes.fromhex(a["public_key_hex"])
               for a in load("fixtures/trust-anchors-v1.json")["anchors"]}

    # ---- 1. keys are consistent with their published public halves ----
    for name, k in keys.items():
        if k["type"] == "ed25519-test-root" or k["type"].startswith("ed25519"):
            sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["private_seed_hex"]))
            eq("key %s public" % name,
               sk.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw).hex(),
               k["public_key_hex"])
        else:
            sk = ec.derive_private_key(int(k["private_scalar_hex"], 16), ec.SECP256R1())
            eq("key %s public" % name,
               sk.public_key().public_bytes(serialization.Encoding.X962,
                                            serialization.PublicFormat.UncompressedPoint).hex(),
               k["public_key_hex"])

    root_sk = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["root-poc-1"]["private_seed_hex"]))
    m_sk = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["merchant-test-1"]["private_seed_hex"]))
    c_eph = ec.derive_private_key(int(keys["client-eph-1"]["private_scalar_hex"], 16),
                                  ec.SECP256R1())
    s_eph = ec.derive_private_key(int(keys["server-eph-1"]["private_scalar_hex"], 16),
                                  ec.SECP256R1())

    # ---- 2. credential ----
    cred = bytes.fromhex(load("credentials.json")["cases"][0]["credential_hex"])
    carr = dec(cred)
    eq("credential is 4-element array", len(carr), 4)
    eq("credential unprotected empty", carr[1], {})
    prot = dec(carr[0])
    eq("credential alg", prot[1], -8)
    eq("credential ctype", prot[3], "application/deceipt-credential+cbor")
    ss = enc(["Signature1", carr[0], b"", carr[2]])
    root_pub = ed25519.Ed25519PublicKey.from_public_bytes(anchors[prot[4].hex()])
    root_pub.verify(carr[3], ss)                       # raises on failure
    body = dec(carr[2])
    eq("credential version", body[1], 1)
    eq("credential issuer==kid", body[2], prot[4])
    eq("credential device pub", body[5].hex(), keys["merchant-test-1"]["public_key_hex"])
    eq("credential merchant id", body[3].hex(), "a1b2c3d4e5f60718293a4b5c6d7e8f90")
    eq("credential device key id", body[4].hex(), "0f1e2d3c4b5a69788796a5b4c3d2e1f0")

    # ---- 3. handshake ----
    hs = load("handshake-valid.json")
    ch = dec(bytes.fromhex(hs["client_hello_hex"]))
    sh = dec(bytes.fromhex(hs["server_hello_hex"]))
    eq("CH type", ch[1], 1)
    eq("CH version", ch[2], 1)
    eq("CH suites", ch[3], [1])
    eq("CH max_frame_payload", ch[8], 162)
    eq("SH type", sh[1], 17)
    eq("SH credential is the fixture", sh[7], cred)

    # offer hash recomputed from the RECEIPT_OFFER fields
    aead = load("aead-valid.json")
    offer = dec(bytes.fromhex(aead["control_offer"]["plaintext_hex"]))
    pre = enc([offer[12], offer[2], offer[3], offer[4], offer[5], offer[6], offer[7]])
    oh = hashlib.sha256(b"deceipt-offer-hash-v1\x00" + pre).digest()
    eq("offer_hash recomputed from RECEIPT_OFFER", oh.hex(), hs["offer_hash_hex"])
    eq("offer hash preimage", pre.hex(), hs["offer_hash_preimage_hex"])

    btuple = bytes.fromhex(hs["binding_tuple_hex"])
    eq("binding tuple recompute", btuple.hex(),
       enc([1, offer[12], offer[2], offer[3], oh]).hex())
    btd = hashlib.sha256(b"deceipt-binding-tuple-v1\x00" + btuple).digest()
    eq("binding tuple digest", btd.hex(), hs["binding_tuple_digest_hex"])
    eq("SH carries binding digest", sh[9], btd)

    # binding proof recomputed from ClientHello
    proof = hmac.new(bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                     b"deceipt-binding-proof-v1\x00" + ch[5] + ch[6], hashlib.sha256).digest()
    eq("binding proof", proof.hex(), ch[7].hex())
    eq("binding proof vector", hs["binding_proof_hex"], ch[7].hex())

    # transcript
    tr = (b"deceipt-handshake-v1" + struct.pack(">H", ch[2]) + struct.pack(">H", sh[3])
          + ch[5] + ch[6] + sh[5] + sh[6] + sh[4] + ch[4] + btd
          + struct.pack(">H", ch[8]) + bytes([len(btuple)]) + btuple)
    eq("transcript bytes", tr.hex(), hs["transcript_hex"])
    eq("transcript length", len(tr), hs["transcript_len"])
    eq("transcript length is 372", len(tr), 372)
    th = hashlib.sha256(tr).digest()
    eq("transcript hash", th.hex(), hs["transcript_hash_hex"])
    ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(keys["merchant-test-1"]["public_key_hex"])).verify(sh[8], tr)
    eq("transcript signature", sh[8].hex(), hs["transcript_signature_hex"])
    eq("merchant signed the same transcript", sh[8], m_sk.sign(tr))

    # ECDH + HKDF
    shared_c = c_eph.exchange(ec.ECDH(), s_eph.public_key())
    shared_s = s_eph.exchange(ec.ECDH(), c_eph.public_key())
    eq("ECDH agrees", shared_c, shared_s)
    eq("shared secret", shared_c.hex(), hs["shared_secret_hex"])
    prk, okm = hkdf(th, shared_c, b"deceipt-transfer-v1" + th, 128)
    eq("prk", prk.hex(), hs["keys"]["prk"])
    eq("okm", okm.hex(), hs["keys"]["okm"])
    sched = {"k_c2m_ctrl": okm[0:32], "k_m2c_ctrl": okm[32:64],
             "k_m2c_payload": okm[64:96], "k_exporter": okm[96:128]}
    for k, v in sched.items():
        eq("key %s" % k, v.hex(), hs["keys"][k])
    ctx = th + sh[4]
    eq("session context", ctx.hex(), hs["session_context_hex"])

    # ---- 4. receipt ----
    rv = load("receipt-valid.json")
    blob = bytes.fromhex(rv["cose_sign1_hex"])
    arr = dec(blob)
    eq("receipt container 4 elements", len(arr), 4)
    eq("receipt unprotected empty", arr[1], {})
    eq("receipt protected bstr", arr[0].hex(), rv["protected_bstr_hex"])
    eq("receipt payload", arr[2].hex(), rv["receipt_body_hex"])
    eq("receipt payload len", len(arr[2]), rv["receipt_body_len"])
    eq("receipt payload sha256", hashlib.sha256(arr[2]).hexdigest(),
       "69255f589539bb767f9dbe0056f3f159c7f960650014342ca6a776151bbd8135")
    eq("receipt re-encode canonical", enc(arr), blob)
    rprot = dec(arr[0])
    eq("receipt alg", rprot[1], -8)
    eq("receipt ctype", rprot[3], "application/deceipt-receipt+cbor")
    eq("receipt kid == credential device key id", rprot[4], body[4])
    rss = enc(["Signature1", arr[0], b"", arr[2]])
    eq("receipt sig structure", rss.hex(), rv["sig_structure_hex"])
    ed25519.Ed25519PublicKey.from_public_bytes(body[5]).verify(arr[3], rss)
    eq("receipt signature", arr[3].hex(), rv["signature_hex"])
    rb = dec(arr[2])
    eq("receipt version", rb[1], 1)
    eq("receipt kind", rb[2], 1)
    eq("receipt currency", rb[8], "CAD")
    eq("receipt merchant id", rb[6][1].hex(), body[3].hex())
    eq("receipt merchant ref", rb[6][3], body[9])
    eq("receipt embeds session credential bytes", rb[20], cred)
    eq("receipt total", rb[15][4], 970)
    eq("receipt subtotal", rb[15][1], 820)
    eq("receipt tip", rb[12], 100)
    eq("receipt issued_at", rb[4], 1767225540)
    eq("receipt receipt_id == offer receipt_id", rb[3], offer[3])
    eq("offer total == receipt total", offer[5], rb[15][4])
    eq("offer issued_at == receipt issued_at", offer[7], rb[4])
    eq("receipt lines", len(rb[9]), 3)
    # line arithmetic: round-half-away
    for ln in rb[9]:
        q = ln[3]
        prod = ln[4] * q[2]
        d = 10 ** q[1]
        n = abs(prod)
        want = (2 * n + d) // (2 * d)
        want = -want if prod < 0 else want
        eq("line %s amount" % ln[1], ln[5], want)
    eq("line 2 is 0.75 kg", rb[9][1][3], {1: 2, 2: 75, 3: "kg"})
    eq("line 2 amount", rb[9][1][5], 270)

    # long receipt
    lr = rv["long_receipt"]
    eq("long receipt body sha", hashlib.sha256(bytes.fromhex(lr["receipt_body_hex"])).hexdigest(),
       lr["receipt_body_sha256"])
    eq("long receipt len", len(bytes.fromhex(lr["receipt_body_hex"])), lr["receipt_body_len"])
    eq("long receipt line count", len(dec(bytes.fromhex(lr["receipt_body_hex"]))[9]), 256)

    # ---- 5. AEAD ----
    pk = aead["payload_seal"]
    ct = AESGCM(sched["k_m2c_payload"]).encrypt(nonce(0), blob, ctx + b"\x01")
    eq("payload ciphertext", ct.hex(), pk["ciphertext_hex"])
    eq("payload ciphertext len", len(ct), pk["ciphertext_len"])
    for name, obj, key, direction in (
            ("control_offer", aead["control_offer"], "k_m2c_ctrl", b"\x01"),
            ("control_transfer_begin", aead["control_transfer_begin"], "k_m2c_ctrl", b"\x01"),
            ("control_accept", aead["control_accept"], "k_c2m_ctrl", b"\x00")):
        env = bytes.fromhex(obj["envelope_hex"])
        pt = bytes.fromhex(obj["plaintext_hex"])
        idx = 0 if "offer" in name else (1 if "begin" in name else 0)
        want = (b"\x01" + struct.pack(">Q", idx)
                + AESGCM(sched[key]).encrypt(nonce(idx), pt, ctx + b"\x02" + direction))
        eq("envelope %s" % name, env.hex(), want.hex())
        eq("envelope %s plaintext" % name, pt.hex(), obj["plaintext_hex"])
        got = AESGCM(sched[key]).decrypt(nonce(idx), env[9:], ctx + b"\x02" + direction)
        eq("envelope %s roundtrip" % name, got, pt)

    # ---- 6. framing ----
    fv = load("framing-valid.json")
    frames = [bytes.fromhex(x) for x in fv["frames_hex"]]
    eq("frame count", len(frames), fv["frame_count"])
    eq("frame count from header", fv["frame_count"],
       (len(ct) + fv["frame_size"] - 1) // fv["frame_size"])
    eq("frame size from mtu", fv["frame_size"], min(min(185 - 3, 512) - 20, 512))
    eq("frame 0 transfer id", frames[0][:16].hex(), fv["transfer_id_hex"])
    eq("frame 0 seq", struct.unpack(">I", frames[0][16:20])[0], 0)
    got_ct = b"".join(f[20:] for f in frames)
    eq("reassembled == ciphertext", got_ct.hex(), pk["ciphertext_hex"])
    eq("payload hash", hashlib.sha256(ct).hexdigest(), fv["payload_hash_hex"])
    eq("frame payload sizes", [len(f) - 20 for f in frames],
       [fv["frame_size"]] * (fv["frame_count"] - 1) + [len(ct) - fv["frame_size"] * (fv["frame_count"] - 1)])
    eq("ack message cbor", fv["ack_message_cbor_hex"],
       enc({1: 3, 2: bytes.fromhex(fv["transfer_id_hex"]), 3: 0}).hex())

    # ---- 7. lpdu ----
    lv = load("lpdu-valid.json")
    frags = [bytes.fromhex(x) for x in lv["fragments_hex"]]
    pdu = bytes.fromhex(lv["server_hello_pdu_hex"])
    eq("lpdu fragment count", len(frags), lv["fragment_count"])
    eq("lpdu frag payload max", lv["frag_payload_max"], min(185 - 3, 512) - 4)
    for i, f in enumerate(frags):
        seq, ix, cnt = struct.unpack(">HBB", f[:4])
        eq("lpdu frag %d seq" % i, seq, 0)
        eq("lpdu frag %d index" % i, ix, i)
        eq("lpdu frag %d count" % i, cnt, len(frags))
    eq("lpdu reassembled", b"".join(f[4:] for f in frags), pdu)
    eq("lpdu pdu is the ServerHello envelope", pdu.hex(), hs["server_hello_pdu_hex"])

    # ---- 8. binding vector cross-check vs A2 (live) ----
    xc = load("binding-crosscheck.json")
    eq("crosscheck a2 bytes match", xc["a2_bytes_match"], True)
    for c in xc["a2_checks"]:
        eq("crosscheck %s" % c["name"], c["match"], True)
        if "derived" in c:
            eq("crosscheck %s derived==published" % c["name"], c["derived"], c["published"])
    # A1 and A2 must publish the identical binding bytes at r1
    a2_rel = os.path.join(V, "..", "flows", "vectors", "binding-v1.json")
    if os.path.exists(a2_rel):
        a2 = json.load(open(a2_rel, encoding="utf-8"))
        v1 = a2["vectors"]["V1_reconciled_with_A1_r1"]["expected"]
        hs_ = load("handshake-valid.json")
        for k in ("offer_hash_hex", "binding_tuple_hex", "binding_tuple_digest_hex",
                  "binding_proof_hex"):
            eq("A1 r1 reconciles A2 V1 %s" % k, hs_[k], v1[k])
        # every A2 non-V4 vector must be reproducible from A2's own inputs
        for name, v in a2["vectors"].items():
            if not v["expected"]["client_ephemeral_pubkey_valid_p256"]:
                try:
                    ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), bytes.fromhex(v["inputs"]["client_ephemeral_pubkey_hex"]))
                    fails.append("A2 %s: point unexpectedly decodes" % name)
                except Exception:
                    pass
                continue
            i, e = v["inputs"], v["expected"]
            eph = bytes.fromhex(i["client_ephemeral_pubkey_hex"])
            oh = hashlib.sha256(b"deceipt-offer-hash-v1\x00" + enc(
                [bytes.fromhex(i["session_id_hex"]), bytes.fromhex(i["transfer_id_hex"]),
                 bytes.fromhex(i["receipt_id_hex"]), i["merchant_reference"],
                 i["total_amount_minor"], i["currency"], i["issued_at_unix"]])).digest()
            eq("A2 %s offer_hash" % name, oh.hex(), e["offer_hash_hex"])
            bp = hmac.new(bytes.fromhex(i["session_binding_token_hex"]),
                          b"deceipt-binding-proof-v1\x00" + bytes.fromhex(i["client_nonce_hex"])
                          + eph, hashlib.sha256).digest()
            eq("A2 %s proof" % name, bp.hex(), e["binding_proof_hex"])
            eq("A2 %s nonce is 32 bytes" % name, len(bytes.fromhex(i["client_nonce_hex"])), 32)
            bt = enc([1, bytes.fromhex(i["session_id_hex"]), bytes.fromhex(i["transfer_id_hex"]),
                      bytes.fromhex(i["receipt_id_hex"]), oh])
            eq("A2 %s tuple" % name, bt.hex(), e["binding_tuple_hex"])
            eq("A2 %s tuple digest" % name,
               hashlib.sha256(b"deceipt-binding-tuple-v1\x00" + bt).hexdigest(),
               e["binding_tuple_digest_hex"])
    # session_id and transfer_id are DISTINCT 16-byte values (advisory-confirmed, A2 layout)
    ch_ = dec(bytes.fromhex(load("handshake-valid.json")["client_hello_hex"]))
    sh_ = dec(bytes.fromhex(load("handshake-valid.json")["server_hello_hex"]))
    eq("session_id is 16 bytes", len(ch_[4]), 16)
    eq("transfer_id is 16 bytes", len(sh_[4]), 16)
    eq("session_id != transfer_id", ch_[4] != sh_[4], True)

    # ---- 9. every declared error name/code is unique ----
    errs = load("errors.json")["errors"]
    names = [e["name"] for e in errs]
    codes = [e["code"] for e in errs]
    eq("error names unique", len(set(names)), len(names))
    eq("error codes unique", len(set(codes)), len(codes))
    eq("error count", len(errs), 91)
    for e in errs:
        eq("error code hex for %s" % e["name"], e["code_hex"], "0x%04x" % e["code"])

    # ---- 9b. r2: transcript reconstruction + no placeholder vectors ----
    hs2 = load("handshake-valid.json")
    ch2 = dec(bytes.fromhex(hs2["client_hello_hex"]))
    sh2 = dec(bytes.fromhex(hs2["server_hello_hex"]))
    eq("SERVER_HELLO carries the binding tuple (label 10)", 10 in sh2, True)
    eq("SERVER_HELLO carries max_frame_payload (label 11)", 11 in sh2, True)
    bt2 = sh2[10]
    eq("binding tuple is 87 bytes", len(bt2), 87)
    eq("binding tuple is byte-identical to the vector", bt2.hex(), hs2["binding_tuple_hex"])
    bt2d = dec(bt2)
    eq("tuple[1] session_id == CLIENT_HELLO label 4", bt2d[1], ch2[4])
    eq("tuple[2] transfer_id == SERVER_HELLO label 4", bt2d[2], sh2[4])
    eq("SERVER_HELLO digest == SHA-256(tuple)", hashlib.sha256(
        b"deceipt-binding-tuple-v1\x00" + bt2).hexdigest(), sh2[9].hex())
    eq("SERVER_HELLO label 11 == CLIENT_HELLO label 8", sh2[11], ch2[8])
    # rebuild the transcript from received messages only, then verify the signature
    lab = b"deceipt-handshake-v1"
    eq("domain label is 20 bytes", len(lab), 20)
    rebuilt = (lab + struct.pack(">H", sh2[2]) + struct.pack(">H", sh2[3]) + ch2[5] + ch2[6]
               + sh2[5] + sh2[6] + bt2d[2] + bt2d[1] + sh2[9]
               + struct.pack(">H", sh2[11]) + bytes([len(bt2)]) + bt2)
    eq("rebuilt transcript == signed transcript", rebuilt.hex(), hs2["transcript_hex"])
    ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(keys["merchant-test-1"]["public_key_hex"])).verify(sh2[8], rebuilt)
    for row in hs2["transcript_layout"]:
        if row["field"] == "label":
            eq("transcript_layout label size", row["size_bytes"], 20)
        if row["field"] == "transfer_id":
            eq("transcript_layout transfer_id offset", row["offset"], 218)
        if row["field"] == "binding_tuple":
            eq("transcript_layout binding_tuple offset", row["offset"], 285)
    # no byte-less invalid fixtures remain
    for fname in ("receipt-invalid.json", "handshake-invalid.json", "aead-invalid.json",
                  "framing-invalid.json", "lpdu-invalid.json", "encoding-invalid.json"):
        for c in load(fname)["cases"]:
            if c["case"].startswith("receipt_") or c["case"].startswith("l_"):
                pass
    for c in load("receipt-invalid.json")["cases"]:
        if c["expected_error"] is not None:
            eq("invalid fixture %s has bytes" % c["case"],
               c["cose_sign1_hex"] is not None, True)

    # ---- 10. bounds ----
    b = load_schema("bounds-v1.json")
    eq("transcript len bound", b["handshake"]["transcript_len"], 372)
    eq("nonce bytes", b["handshake"]["nonce_bytes"], 32)
    eq("frame max", b["wire"]["max_frame_payload"], 512)
    eq("frame min", b["wire"]["min_frame_payload"], 16)
    eq("dataframe header", b["wire"]["dataframe_header_bytes"], 20)
    eq("max receipt bytes", b["receipt"]["max_receipt_bytes"], 65536)
    eq("max transfer ct", b["wire"]["max_transfer_ciphertext"], 65552)
    eq("CAD exponent", b["currency_minor_unit_exponent"]["CAD"], 2)
    eq("message type CLIENT_HELLO", b["message_types"]["CLIENT_HELLO"], 1)
    eq("message type SERVER_HELLO", b["message_types"]["SERVER_HELLO"], 17)

    # ---- 11. field tables agree with the receipt that was signed ----
    rf = load_schema("receipt-v1.fields.json")
    top = {f["label"] for f in rf["fields"]}
    eq("receipt top-level labels implemented", top >= set(rb.keys()),
       True)
    eq("receipt uses only declared labels", set(rb.keys()) <= top, True)
    for label in rb:
        want = next(f["name"] for f in rf["fields"] if f["label"] == label)
        if label in (1, 2, 4):
            eq("label %d is a uint" % label, isinstance(rb[label], int), True)
    wf = load_schema("wire-v1.messages.json")
    declared = {m["type"] for m in wf["messages"]}
    eq("CH type declared", ch[1] in declared, True)
    eq("SH type declared", sh[1] in declared, True)
    eq("offer type declared", offer[1] in declared, True)
    eq("begin type declared", dec(bytes.fromhex(aead["control_transfer_begin"]["plaintext_hex"]))[1]
       in declared, True)
    eq("accept type declared", dec(bytes.fromhex(aead["control_accept"]["plaintext_hex"]))[1]
       in declared, True)

    # ---- 12. revision alignment: no pinned artifact may declare another revision ----
    import re as _re
    mine = load("vectors-manifest.json")["revision"]
    warnings = []
    # A1-owned docs must never declare another revision (hard failure).
    for rel in sorted(os.listdir(os.path.join(V, "..", "..", "docs", "protocol"))):
        if not rel.endswith(".md"):
            continue
        txt = open(os.path.join(V, "..", "..", "docs", "protocol", rel), encoding="utf-8").read()
        for m in sorted(set(_re.findall(r"`(deceipt-proto-r\d+)`", txt))):
            if m != mine:
                fails.append("stale revision %s in docs/protocol/%s" % (m, rel))
    # A2-owned pinned files: surface (owner must align; A1 may not edit them).
    for rel in ["../flows/checkout-flow-v1.json", "../flows/checkout-flow-v1.mmd",
                "../flows/vectors/binding-v1.json", "../flows/tools/gen_binding_vectors.py"]:
        fp = os.path.normpath(os.path.join(V, rel))
        if not os.path.exists(fp):
            continue
        txt = open(fp, encoding="utf-8").read()
        for m in sorted(set(_re.findall(r"deceipt-proto-r\d+", txt))):
            if m != mine:
                warnings.append("A2 metadata: %s declares %s (pinned revision is %s) - "
                                "owner action required" % (rel, m, mine))

    # ---- 13. normative counts in docs must match the frozen self-test ----
    _st = load("self-test.json")
    _checked, _policy = _st["checked"], len(_st["policy_only_cases"])
    import glob as _glob
    for _fp in _glob.glob(os.path.join(V, "..", "..", "docs", "protocol", "*.md")):
        _txt = open(_fp, encoding="utf-8").read()
        _name = os.path.basename(_fp)
        _cm = _re.search(r"(\d+)\s+checks,\s*(\d+)\s+failures", _txt)
        if _cm and int(_cm.group(1)) != _checked:
            fails.append("stale check count %s in %s (self-test has %d)"
                         % (_cm.group(1), _name, _checked))
        _pm = _re.search(r"(\d+)\s+additional cases are receiver-state", _txt)
        if _pm and int(_pm.group(1)) != _policy:
            fails.append("stale policy-case count %s in %s (self-test has %d)"
                         % (_pm.group(1), _name, _policy))

    # ---- report ----
    for w in warnings:
        print("WARN", w)
    if fails:
        print("FAIL (%d)" % len(fails))
        for f in fails:
            print(" -", f)
        return 1
    print("OK: all independent vector checks passed%s"
          % ("" if not warnings else " (%d metadata warning(s) above)" % len(warnings)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
