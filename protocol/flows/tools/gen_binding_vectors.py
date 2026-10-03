#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deceipt PoC - A2 transaction-binding vector generator (owner A2 scope).

Generates protocol/flows/vectors/binding-v1.json, reconciled to the A1 frozen
protocol revision published in protocol/vectors/handshake-valid.json.
The binding bytes are revision-agnostic: no A1 revision bump changes them.

Deterministic CBOR + exact P-256 points via the `cryptography` package.
TEST-ONLY deterministic material. Production uses fresh CSPRNG randomness.

    python3 protocol/flows/tools/gen_binding_vectors.py
"""
import base64, hashlib, hmac, json, os, sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REVISION_POLICY = ("reconciles byte-for-byte with the A1 frozen protocol revision in "
                   "protocol/vectors/handshake-valid.json at the time of publication; the "
                   "binding bytes are revision-agnostic")
DOMAIN_OFFER = b"deceipt-offer-hash-v1"
DOMAIN_TUPLE = b"deceipt-binding-tuple-v1"
DOMAIN_PROOF = b"deceipt-binding-proof-v1"
QR_PREFIX = "deceipt1:"
T_BINDING_QR = 300

_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# --- deterministic CBOR (RFC 8949 4.2.1) ---------------------------------
def _head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 2 ** 32: return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def cint(n): return _head(0, n)
def cbytes(b): return _head(2, len(b)) + b
def ctext(s): b = s.encode("utf-8"); return _head(3, len(b)) + b
def carray(items): return _head(4, len(items)) + b"".join(items)
def cmap(pairs):
    enc = sorted(((cint(k), v) for k, v in pairs), key=lambda kv: kv[0])
    return _head(5, len(enc)) + b"".join(k + v for k, v in enc)


# --- deterministic test-only P-256 keys (mirrors A1 gen_vectors.py) -------
def test_p256(name, counter=0):
    c = counter
    while True:
        material = hashlib.sha256(
            b"deceipt-testkey:p256:" + name.encode() + ("#%d" % c).encode()).digest()
        d = (int.from_bytes(material, "big") % (_P256_N - 1)) + 1
        try:
            return ec.derive_private_key(d, ec.SECP256R1())
        except ValueError:
            c += 1


def p256_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint)


def valid_point(blob):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), blob); return True
    except Exception:
        return False


# --- A2 binding bytes ----------------------------------------------------
def offer_hash(session_id, transfer_id, receipt_id, merchant_ref, amount_minor, currency, issued_at):
    return hashlib.sha256(DOMAIN_OFFER + b"\x00" + carray([
        cbytes(session_id), cbytes(transfer_id), cbytes(receipt_id),
        ctext(merchant_ref), cint(amount_minor), ctext(currency), cint(issued_at)])).digest()


def binding_tuple(session_id, transfer_id, receipt_id, oh):
    return carray([cint(1), cbytes(session_id), cbytes(transfer_id), cbytes(receipt_id), cbytes(oh)])


def binding_tuple_digest(t):
    return hashlib.sha256(DOMAIN_TUPLE + b"\x00" + t).digest()


def binding_proof(sbt, client_nonce, client_eph):
    return hmac.new(sbt, DOMAIN_PROOF + b"\x00" + client_nonce + client_eph, hashlib.sha256).digest()


def qr_payload(session_id, sbt, oh, expires_at):
    raw = cmap([(1, cint(1)), (2, cbytes(session_id)), (3, cbytes(sbt)),
                (4, cbytes(oh)), (5, cint(expires_at))])
    return raw, QR_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def scenario(name, merchant_ref, amount, currency, issued_at, sbt, client_nonce, point_name,
             session_id, transfer_id, receipt_id, qr_expires_at=None, description="", expect="accept"):
    eph = p256_pub(test_p256(point_name))
    oh = offer_hash(session_id, transfer_id, receipt_id, merchant_ref, amount, currency, issued_at)
    tup = binding_tuple(session_id, transfer_id, receipt_id, oh)
    dig = binding_tuple_digest(tup)
    proof = binding_proof(sbt, client_nonce, eph)
    qr_raw, qr = qr_payload(session_id, sbt, oh,
                            qr_expires_at if qr_expires_at is not None else issued_at + T_BINDING_QR)
    return {
        "description": description,
        "inputs": {
            "session_binding_token_hex": sbt.hex(),
            "client_nonce_hex": client_nonce.hex(),
            "client_ephemeral_pubkey_hex": eph.hex(),
            "session_id_hex": session_id.hex(),
            "transfer_id_hex": transfer_id.hex(),
            "receipt_id_hex": receipt_id.hex(),
            "merchant_reference": merchant_ref,
            "total_amount_minor": amount,
            "currency": currency,
            "issued_at_unix": issued_at,
        },
        "expected": {
            "client_ephemeral_pubkey_valid_p256": valid_point(eph),
            "offer_hash_hex": oh.hex(),
            "binding_tuple_hex": tup.hex(),
            "binding_tuple_length_bytes": len(tup),
            "binding_tuple_digest_hex": dig.hex(),
            "binding_proof_message_hex": (DOMAIN_PROOF + b"\x00" + client_nonce + eph).hex(),
            "binding_proof_message_length_bytes": 122,
            "binding_proof_hex": proof.hex(),
            "qr_raw_cbor_hex": qr_raw.hex(),
            "qr_payload": qr,
            "qr_payload_length_chars": len(qr),
            "qr_expires_at_unix": qr_expires_at if qr_expires_at is not None else issued_at + T_BINDING_QR,
        },
        "expect": expect,
    }


def build():
    SID = bytes.fromhex("00112233445566778899aabbccddeeff")
    TID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    RID = bytes.fromhex("0123456789abcdef0123456789abcdef")
    SBT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    CN = bytes.fromhex("c0ffee00" + "00" * 27 + "01")

    v = {}
    # V1 reconciles byte-for-byte to A1's frozen handshake-valid.json scenario.
    v["V1_reconciled_with_A1_r1"] = scenario(
        "V1", "merchant.poc.test-alpha", 970, "CAD", 1767225540, SBT, CN, "client-eph-1",
        SID, TID, RID,
        description=("Canonical vector. Inputs identical to the A1 protocol/vectors/"
                     "handshake-valid.json scenario: offer_hash, binding_tuple, "
                     "binding_tuple_digest and binding_proof are byte-identical there."),
        expect="accept")
    # V2: same transaction, wrong SBT -> proof differs, offer/tuple/digest identical.
    v["V2_same_inputs_wrong_sbt"] = scenario(
        "V2", "merchant.poc.test-alpha", 970, "CAD", 1767225540,
        bytes.fromhex("ffeeddccbbaa99887766554433221100"), CN, "client-eph-1",
        SID, TID, RID,
        description=("Identical to V1 except session_binding_token. offer_hash/binding_tuple/"
                     "digest are IDENTICAL (they do not depend on SBT); binding_proof DIFFERS. "
                     "Merchant must reject with BINDING_PROOF_INVALID."),
        expect="reject_binding_proof_invalid")
    # V3: a different transaction, different valid point.
    v["V3_different_transaction"] = scenario(
        "V3", "merchant.poc.test-beta", 1234, "USD", 1767225900,
        bytes.fromhex("1f1e1d1c1b1a19181716151413121110"),
        bytes.fromhex("ab" * 32), "client-eph-2",
        bytes.fromhex("aa" * 16), bytes.fromhex("bb" * 16), bytes.fromhex("cc" * 16),
        description=("A distinct transaction with a distinct valid P-256 point; every output "
                     "differs from V1."),
        expect="accept_with_distinct_values")
    # V4: negative - point that fails P-256 decode, so ECDH is impossible.
    bad = bytearray(bytes.fromhex(v["V1_reconciled_with_A1_r1"]["inputs"]["client_ephemeral_pubkey_hex"]))
    bad[-1] ^= 0x01
    v4 = scenario(
        "V4", "merchant.poc.test-alpha", 970, "CAD", 1767225540, SBT, CN, "client-eph-1",
        SID, TID, RID,
        description=("Negative vector: client_ephemeral_pubkey is V1's point with the final byte "
                     "flipped, so it is not on secp256r1. A receiver MUST reject at ClientHello "
                     "field 6 before any binding check: HANDSHAKE_ECDH_INVALID_POINT."),
        expect="reject_handshake_ecdh_invalid_point")
    v4["inputs"]["client_ephemeral_pubkey_hex"] = bytes(bad).hex()
    v4["expected"]["client_ephemeral_pubkey_valid_p256"] = valid_point(bytes(bad))
    v4["expected"]["binding_proof_hex"] = binding_proof(SBT, CN, bytes(bad)).hex()
    v4["expected"]["binding_proof_message_hex"] = (DOMAIN_PROOF + b"\x00" + CN + bytes(bad)).hex()
    v["V4_invalid_point_rejected"] = v4
    return v


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out = os.path.normpath(os.path.join(script_dir, "..", "vectors", "binding-v1.json"))
    vecs = build()
    doc = {
        "$comment": ("Deceipt PoC binding test vectors v1. Owner A2. TEST-ONLY deterministic "
                     "secrets so A1/A4/A5/A6 can reproduce expected values. Production sessions MUST "
                     "use fresh CSPRNG randomness. V1 reconciles byte-for-byte with the A1 frozen "
                     "protocol/vectors/handshake-valid.json; the binding bytes are revision-agnostic."),
        "_generated": "generated by protocol/flows/tools/gen_binding_vectors.py; do not edit by hand",
        "schema": "deceipt.binding-vectors/v1",
        "owner": "A2",
        "revision_policy": REVISION_POLICY,
        "derivation_reference": "docs/flows/transaction-binding-and-checkout-v1.md",
        "algorithms": {
            "identifier": "16 random bytes",
            "offer_hash": "SHA-256",
            "binding_tuple": "CBOR array(5) definite-length minimal-int",
            "binding_tuple_digest": "SHA-256",
            "binding_proof": "HMAC-SHA-256",
            "client_ephemeral_pubkey": "P-256 uncompressed 0x04||X||Y (65 bytes)",
        },
        "domain_separators": {
            "binding_tuple": {"ascii": DOMAIN_TUPLE.decode(), "hex_utf8": DOMAIN_TUPLE.hex()},
            "offer_hash": {"ascii": DOMAIN_OFFER.decode(), "hex_utf8": DOMAIN_OFFER.hex()},
            "binding_proof": {"ascii": DOMAIN_PROOF.decode(), "hex_utf8": DOMAIN_PROOF.hex()},
        },
        "vectors": vecs,
        "expected_relationships": {
            "V1_offer_hash_equals_A1_r1": vecs["V1_reconciled_with_A1_r1"]["expected"]["offer_hash_hex"]
                == "efdc44f3a6d088fcd23ee9fb8f9b65f464572da83de53f0ce37a5d21c994d4c5",
            "V1_binding_proof_equals_A1_r1": vecs["V1_reconciled_with_A1_r1"]["expected"]["binding_proof_hex"]
                == "fa19790fda7c85c1c745d4299c4177f9bcd15090de78961a38b7ebc36565083e",
            "V2_vs_V1_offer_hash_equal": vecs["V2_same_inputs_wrong_sbt"]["expected"]["offer_hash_hex"]
                == vecs["V1_reconciled_with_A1_r1"]["expected"]["offer_hash_hex"],
            "V2_vs_V1_binding_proof_differ": vecs["V2_same_inputs_wrong_sbt"]["expected"]["binding_proof_hex"]
                != vecs["V1_reconciled_with_A1_r1"]["expected"]["binding_proof_hex"],
            "V4_point_invalid": vecs["V4_invalid_point_rejected"]["expected"]["client_ephemeral_pubkey_valid_p256"] is False,
            "all_non_negative_points_valid": all(
                vecs[k]["expected"]["client_ephemeral_pubkey_valid_p256"]
                for k in ("V1_reconciled_with_A1_r1", "V2_same_inputs_wrong_sbt", "V3_different_transaction")),
        },
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    # sanity assertions
    for k, vv in vecs.items():
        if vv["expect"] != "reject_handshake_ecdh_invalid_point":
            assert valid_point(bytes.fromhex(vv["inputs"]["client_ephemeral_pubkey_hex"])), k
    rel = doc["expected_relationships"]
    assert rel["V1_offer_hash_equals_A1_r1"] and rel["V1_binding_proof_equals_A1_r1"], "V1 not reconciled"
    assert rel["all_non_negative_points_valid"] and rel["V4_point_invalid"]
    print("wrote", out)
    for k, vv in vecs.items():
        e = vv["expected"]
        print(f"{k}: valid_point={e['client_ephemeral_pubkey_valid_p256']} "
              f"offer={e['offer_hash_hex'][:16]}.. digest={e['binding_tuple_digest_hex'][:16]}.. "
              f"proof={e['binding_proof_hex'][:16]}..")
    print("V1 tuple:", vecs["V1_reconciled_with_A1_r1"]["expected"]["binding_tuple_hex"])
    print("V1 QR   :", vecs["V1_reconciled_with_A1_r1"]["expected"]["qr_payload"])


if __name__ == "__main__":
    main()
