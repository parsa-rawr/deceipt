"""Independent AEAD / framing / LPdu verifiers.

Implements `docs/protocol/handshake.md` §6, `docs/protocol/wire.md` §3/§5/§6 and
`docs/protocol/framing.md` §1-§4.
"""

from __future__ import annotations

from typing import Optional

from . import cbor as C
from . import crypto
from .cbor import CborError


class WireError(Exception):
    def __init__(self, name: str, detail: str = "") -> None:
        self.name = name
        self.detail = detail
        super().__init__(name)


# --- AEAD control envelopes -------------------------------------------------


def aad_control(session_context: bytes, direction: str) -> bytes:
    return session_context + b"\x02" + (b"\x00" if direction == "c2m" else b"\x01")


def aad_payload(session_context: bytes) -> bytes:
    return session_context + b"\x01"


def parse_envelope(raw: bytes):
    """Return ('plaintext', cbor_bytes) or ('aead', counter, ct)."""
    if not raw:
        raise WireError("MESSAGE_MALFORMED")
    tag = raw[0]
    if tag == 0x00:
        return ("plaintext", raw[1:])
    if tag == 0x01:
        if len(raw) < 9:
            raise WireError("MESSAGE_MALFORMED")
        counter = int.from_bytes(raw[1:9], "big")
        return ("aead", counter, raw[9:])
    raise WireError("MESSAGE_UNKNOWN_TYPE")


def open_control(
    raw: bytes,
    key: bytes,
    session_context: bytes,
    direction: str,
    expected_counter: int,
):
    """Receiver rule (handshake.md §6.3): counter checks BEFORE decryption."""
    kind, *rest = parse_envelope(raw)
    if kind == "plaintext":
        raise WireError("MESSAGE_WRONG_STATE")
    counter, ct = rest
    if counter < expected_counter:
        raise WireError("AEAD_REPLAY_DETECTED")
    if counter > expected_counter:
        raise WireError("AEAD_COUNTER_MISMATCH")
    nonce = crypto.nonce_from_counter(counter)
    pt = crypto.aes_gcm_open(key, nonce, aad_control(session_context, direction), ct)
    if pt is None:
        raise WireError("AEAD_AUTH_FAILED")
    return pt


def open_payload(raw_ct: bytes, key: bytes, session_context: bytes) -> bytes:
    nonce = crypto.nonce_from_counter(0)
    pt = crypto.aes_gcm_open(key, nonce, aad_payload(session_context), raw_ct)
    if pt is None:
        raise WireError("AEAD_AUTH_FAILED")
    return pt


# --- LPdu -------------------------------------------------------------------


def parse_lpdu_fragment(frag: bytes):
    if len(frag) < 4:
        raise WireError("LPDU_FRAGMENT_INVALID")
    msg_seq = int.from_bytes(frag[0:2], "big")
    frag_index = frag[2]
    frag_count = frag[3]
    payload = frag[4:]
    if frag_count < 1 or frag_count > 512:
        raise WireError("LPDU_FRAGMENT_INVALID")
    if frag_index >= frag_count:
        raise WireError("LPDU_FRAGMENT_INVALID")
    return msg_seq, frag_index, frag_count, payload


def reassemble_lpdu(fragments: list[bytes]) -> bytes:
    if not fragments:
        raise WireError("LPDU_FRAGMENT_INVALID")
    seqs, parts, counts = [], [], []
    for i, f in enumerate(fragments):
        seq, idx, count, payload = parse_lpdu_fragment(f)
        counts.append(count)
        if len(set(counts)) != 1:
            raise WireError("LPDU_FRAGMENT_INVALID")
        if i == 0 and idx != 0:
            raise WireError("LPDU_FRAGMENT_INVALID")
        if idx != i:
            raise WireError("LPDU_SEQUENCE_ERROR")
        seqs.append(seq)
        parts.append(payload)
    if len(set(seqs)) != 1:
        raise WireError("LPDU_SEQUENCE_ERROR")
    if counts[0] != len(fragments):
        raise WireError("LPDU_FRAGMENT_INVALID")
    out = b"".join(parts)
    if len(out) > 2048:
        raise WireError("LPDU_MESSAGE_TOO_LARGE")
    return out


# --- Frames -----------------------------------------------------------------


def att_payload_max(att_mtu: int) -> int:
    return min(att_mtu - 3, 512)


def max_frame_payload_for_mtu(att_mtu: int) -> int:
    return min(att_payload_max(att_mtu) - 20, 512)


def validate_frame_size(frame_size: int, peer_max_frame_payload: int) -> None:
    if not (16 <= frame_size <= 512):
        raise WireError("FRAME_SIZE_INVALID")
    if frame_size > peer_max_frame_payload:
        raise WireError("FRAME_SIZE_INVALID")


def parse_frame(frame: bytes, frame_size: int, max_frame_payload: int):
    if len(frame) < 20:
        raise WireError("FRAME_SIZE_INVALID")
    transfer_id = frame[0:16]
    seq = int.from_bytes(frame[16:20], "big")
    payload = frame[20:]
    return transfer_id, seq, payload


def frame_payload_sizes(ciphertext_len: int, frame_size: int) -> list[int]:
    if ciphertext_len <= 0:
        return []
    count = (ciphertext_len + frame_size - 1) // frame_size
    sizes = [frame_size] * (count - 1)
    sizes.append(ciphertext_len - frame_size * (count - 1))
    return sizes
