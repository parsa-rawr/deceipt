"""Independent handshake / transcript verification.

Implements `docs/protocol/handshake.md` §3-§6 directly. Reconstructs the signed
transcript from received plaintext only (the r2/r3 closure of R4-01) and checks
the transcript hash, the Ed25519 signature, and the key schedule.
"""

from __future__ import annotations

from typing import Optional

from . import cbor as C
from . import crypto
from .cbor import CborError

TRANSCRIPT_LABEL = b"deceipt-handshake-v1"
OFFER_HASH_LABEL = b"deceipt-offer-hash-v1"
BINDING_TUPLE_LABEL = b"deceipt-binding-tuple-v1"
INFO_PREFIX = b"deceipt-transfer-v1"
PROTOCOL_VERSION = 1
SUPPORTED_SUITES = {1}


class HandshakeError(Exception):
    def __init__(self, name: str, detail: str = "") -> None:
        self.name = name
        self.detail = detail
        super().__init__(name)


def binding_tuple_digest(tuple_bytes: bytes) -> bytes:
    return crypto.sha256(BINDING_TUPLE_LABEL + b"\x00" + tuple_bytes)


def offer_hash(offer_array: list) -> bytes:
    return crypto.sha256(OFFER_HASH_LABEL + b"\x00" + C.encode(offer_array))


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def rebuild_transcript(client_hello: dict, server_hello: dict) -> bytes:
    """handshake.md §3.1: build the signed transcript from received plaintext.

    Raises HandshakeError with the rule's typed error on any violated rule.
    """
    bh = server_hello
    ch = client_hello
    if 10 not in bh:
        raise HandshakeError("BINDING_REQUIRED")
    tup = C.decode(bh[10])
    if not isinstance(tup, list) or len(tup) != 5:
        raise HandshakeError("HANDSHAKE_TRANSCRIPT_MISMATCH")
    # rule 1: label 10 authoritative over label 9
    if bh.get(9) != binding_tuple_digest(bh[10]):
        raise HandshakeError("HANDSHAKE_TRANSCRIPT_MISMATCH")
    # rule 2: label 4 == tuple[2]
    if bh.get(4) != tup[2]:
        raise HandshakeError("TRANSFER_ID_MISMATCH")
    # rule 4: tuple[1] == client label 4
    if tup[1] != ch.get(4):
        raise HandshakeError("BINDING_UNKNOWN_SESSION")
    parts = []
    parts.append(TRANSCRIPT_LABEL)
    parts.append(_u16(bh[2]))
    parts.append(_u16(bh[3]))
    parts.append(ch[5])
    parts.append(ch[6])
    parts.append(bh[5])
    parts.append(bh[6])
    parts.append(tup[2])  # transfer_id
    parts.append(tup[1])  # session_id
    parts.append(bh[9])   # binding_tuple_digest (== recomputed)
    parts.append(_u16(bh[11]))
    parts.append(bytes([len(bh[10])]))
    parts.append(bh[10])
    return b"".join(parts)


def parse_hello(raw: bytes) -> dict:
    """Parse a hello message. Accepts the plaintext envelope `0x00 || CBOR(map)`
    or the bare `CBOR(map)` (the frozen handshake-invalid vectors publish the
    message body without the envelope tag)."""
    body = raw[1:] if raw and raw[0] == 0x00 else raw
    try:
        msg, consumed = C.decode_prefix(body)
    except CborError as e:
        raise HandshakeError(e.name)
    if consumed != len(body):
        raise HandshakeError("CBOR_MALFORMED")
    if not isinstance(msg, dict):
        raise HandshakeError("MESSAGE_FIELD_TYPE")
    return msg


def validate_client_hello(msg: dict) -> None:
    expected = {1, 2, 3, 4, 5, 6, 7, 8}
    for k in msg:
        if k not in expected:
            raise HandshakeError("MESSAGE_UNKNOWN_FIELD")
    # binding requires session_id (4) and binding_proof (7)
    if 4 not in msg or 7 not in msg:
        raise HandshakeError("BINDING_REQUIRED")
    for req in (1, 2, 3, 5, 6, 8):
        if req not in msg:
            raise HandshakeError("MESSAGE_MISSING_FIELD")
    if msg[1] != 1:
        raise HandshakeError("MESSAGE_FIELD_TYPE")
    if msg[2] != PROTOCOL_VERSION:
        raise HandshakeError("HANDSHAKE_UNSUPPORTED_VERSION")
    suites = msg[3]
    if not isinstance(suites, list) or not suites:
        raise HandshakeError("MESSAGE_FIELD_TYPE")
    if not (set(suites) & SUPPORTED_SUITES):
        raise HandshakeError("HANDSHAKE_NO_COMMON_SUITE")
    if not crypto.p256_valid_point(msg[6] if isinstance(msg[6], bytes) else b""):
        raise HandshakeError("HANDSHAKE_ECDH_INVALID_POINT")
    mfp = msg[8]
    if not isinstance(mfp, int) or not (16 <= mfp <= 512):
        raise HandshakeError("FRAME_SIZE_INVALID")


def validate_server_hello(msg: dict, client_hello: dict) -> None:
    expected = set(range(1, 12))
    for k in msg:
        if k not in expected:
            raise HandshakeError("MESSAGE_UNKNOWN_FIELD")
    for req in expected:
        if req not in msg:
            if req == 10:
                raise HandshakeError("BINDING_REQUIRED")
            raise HandshakeError("MESSAGE_MISSING_FIELD")
    if msg[2] != PROTOCOL_VERSION:
        raise HandshakeError("HANDSHAKE_UNSUPPORTED_VERSION")
    if msg[3] not in (client_hello.get(3) or []):
        raise HandshakeError("HANDSHAKE_SUITE_MISMATCH")
    if not crypto.p256_valid_point(msg[6] if isinstance(msg[6], bytes) else b""):
        raise HandshakeError("HANDSHAKE_ECDH_INVALID_POINT")


def verify_handshake(
    client_hello_msg: dict,
    server_hello_msg: dict,
    device_public_key: bytes,
) -> dict:
    """Full receiver-side handshake check. Returns {'transcript', 'transcript_hash',
    'signature_valid'} or raises HandshakeError."""
    validate_client_hello(client_hello_msg)
    validate_server_hello(server_hello_msg, client_hello_msg)
    transcript = rebuild_transcript(client_hello_msg, server_hello_msg)
    t_hash = crypto.sha256(transcript)
    sig = server_hello_msg[8]
    if not crypto.ed25519_verify(device_public_key, sig, transcript):
        raise HandshakeError("HANDSHAKE_SIGNATURE_INVALID")
    return {"transcript": transcript, "transcript_hash": t_hash, "signature_valid": True}


def key_schedule(transcript: bytes, shared_secret: bytes) -> dict:
    import hashlib
    import hmac

    t_hash = crypto.sha256(transcript)
    info = INFO_PREFIX + t_hash
    prk = hmac.new(t_hash, shared_secret, hashlib.sha256).digest()  # HKDF-Extract
    okm = crypto.hkdf_sha256(shared_secret, t_hash, info, 128)      # Extract+Expand
    return {
        "transcript_hash": t_hash,
        "shared_secret": shared_secret,
        "prk": prk,
        "info": info,
        "okm": okm,
        "k_c2m_ctrl": okm[0:32],
        "k_m2c_ctrl": okm[32:64],
        "k_m2c_payload": okm[64:96],
        "k_exporter": okm[96:128],
    }
