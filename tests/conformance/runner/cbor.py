"""Deterministic-CBOR codec implementing the Deceipt v1 profile.

Derived ONLY from RFC 8949 section 4.2.1 (core deterministic encoding) and the
normative clause lists in `docs/protocol/receipt-v1.md` and
`protocol/schema/bounds-v1.json`. No implementation under test is consulted.

Violations raise `CborError(name)` where `name` is the protocol error name the
frozen `expected_error` fixtures use, so the runner can compare by name.

Profile enforced:
  * definite lengths only (indefinite arrays/maps/strings -> CBOR_UNSUPPORTED_TYPE)
  * minimal-length argument encoding (else CBOR_NONCANONICAL)
  * integer map keys only, 0..255 (else CBOR_UNSUPPORTED_TYPE)
  * strictly ascending bytewise key order, no duplicates
  * no floats / tags / simple values (null, undefined, ...) -> CBOR_UNSUPPORTED_TYPE
  * well-formed UTF-8 text -> CBOR_MALFORMED
  * no trailing bytes -> CBOR_MALFORMED
  * size/depth caps from bounds-v1.json
"""

from __future__ import annotations

import struct
from typing import Any


class CborError(Exception):
    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(name)


MAJOR_UINT = 0
MAJOR_NINT = 1
MAJOR_BSTR = 2
MAJOR_TSTR = 3
MAJOR_ARR = 4
MAJOR_MAP = 5
MAJOR_TAG = 6
MAJOR_SIMPLE = 7


class Limits:
    """Bounds from protocol/schema/bounds-v1.json (cbor block)."""

    def __init__(
        self,
        max_depth: int = 12,
        max_items: int = 8192,
        max_array: int = 1024,
        max_map: int = 256,
        max_text_bytes: int = 4096,
        max_bytes: int = 65536,
        max_map_key: int = 255,
    ) -> None:
        self.max_depth = max_depth
        self.max_items = max_items
        self.max_array = max_array
        self.max_map = max_map
        self.max_text_bytes = max_text_bytes
        self.max_bytes = max_bytes
        self.max_map_key = max_map_key


DEFAULT_LIMITS = Limits()


class _Buf:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes) -> None:
        self.b = b
        self.i = 0

    def need(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise CborError("CBOR_MALFORMED")
        out = self.b[self.i : self.i + n]
        self.i += n
        return out


def _read_head(buf: _Buf, allow_minimal_check: bool = True):
    """Return (major, value, ai). Raises on malformed / non-minimal."""
    ib = buf.need(1)[0]
    major = ib >> 5
    ai = ib & 0x1F
    if ai < 24:
        return major, ai, ai
    if ai == 24:
        v = buf.need(1)[0]
        if allow_minimal_check and v <= 23:
            raise CborError("CBOR_NONCANONICAL")
        return major, v, ai
    if ai == 25:
        v = int.from_bytes(buf.need(2), "big")
        if allow_minimal_check and v <= 255:
            raise CborError("CBOR_NONCANONICAL")
        return major, v, ai
    if ai == 26:
        v = int.from_bytes(buf.need(4), "big")
        if allow_minimal_check and v <= 65535:
            raise CborError("CBOR_NONCANONICAL")
        return major, v, ai
    if ai == 27:
        v = int.from_bytes(buf.need(8), "big")
        if allow_minimal_check and v <= 0xFFFFFFFF:
            raise CborError("CBOR_NONCANONICAL")
        return major, v, ai
    if ai == 31:
        raise CborError("CBOR_UNSUPPORTED_TYPE")  # indefinite length
    # 28..30 are reserved / malformed
    raise CborError("CBOR_MALFORMED")


def _utf8_text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        raise CborError("CBOR_MALFORMED")


def decode(data: bytes, limits: Limits = DEFAULT_LIMITS) -> Any:
    """Decode `data` under the profile; raise CborError on any violation.

    Rejects trailing bytes.
    """
    buf = _Buf(data)
    state = {"items": 0}
    value = _decode_one(buf, limits, 0, state)
    if buf.i != len(data):
        raise CborError("CBOR_MALFORMED")  # trailing bytes
    return value


def _count(state, limits) -> None:
    state["items"] += 1
    if state["items"] > limits.max_items:
        raise CborError("CBOR_SIZE_EXCEEDED")


def _decode_one(buf: _Buf, limits: Limits, depth: int, state) -> Any:
    if depth > limits.max_depth:
        raise CborError("CBOR_DEPTH_EXCEEDED")
    major, val, ai = _read_head(buf)
    _count(state, limits)

    if major == MAJOR_UINT:
        return val
    if major == MAJOR_NINT:
        return -1 - val
    if major == MAJOR_BSTR:
        if val > limits.max_bytes:
            raise CborError("CBOR_SIZE_EXCEEDED")
        return buf.need(val)
    if major == MAJOR_TSTR:
        if val > limits.max_text_bytes:
            raise CborError("CBOR_SIZE_EXCEEDED")
        return _utf8_text(buf.need(val))
    if major == MAJOR_ARR:
        if val > limits.max_array:
            raise CborError("CBOR_SIZE_EXCEEDED")
        return [_decode_one(buf, limits, depth + 1, state) for _ in range(val)]
    if major == MAJOR_MAP:
        if val > limits.max_map:
            raise CborError("CBOR_SIZE_EXCEEDED")
        out = {}
        prev_key_bytes: bytes | None = None
        for _ in range(val):
            kstart = buf.i
            kmajor, kval, _kai = _read_head(buf)
            if kmajor != MAJOR_UINT:
                raise CborError("CBOR_UNSUPPORTED_TYPE")
            if kval > limits.max_map_key:
                raise CborError("CBOR_UNSUPPORTED_TYPE")
            kbytes = buf.b[kstart : buf.i]
            if prev_key_bytes is not None:
                if kbytes == prev_key_bytes:
                    raise CborError("CBOR_DUPLICATE_KEY")
                if not (kbytes > prev_key_bytes):
                    raise CborError("CBOR_NONCANONICAL")
            prev_key_bytes = kbytes
            out[kval] = _decode_one(buf, limits, depth + 1, state)
        return out
    # major 7: simple values. Only false/true are permitted by the profile
    # (receipt-v1.md section 1: "only false/true allowed"); floats, null,
    # undefined and other simple values are CBOR_UNSUPPORTED_TYPE.
    if major == MAJOR_SIMPLE:
        if ai == 20:
            return False
        if ai == 21:
            return True
        raise CborError("CBOR_UNSUPPORTED_TYPE")
    # tag
    raise CborError("CBOR_UNSUPPORTED_TYPE")


# ---------------------------------------------------------------------------
# Canonical encoder (used only to test round-trips of frozen bytes, never to
# synthesise expectations).
# ---------------------------------------------------------------------------


def _head(major: int, val: int) -> bytes:
    if val < 24:
        return bytes([(major << 5) | val])
    if val <= 0xFF:
        return bytes([(major << 5) | 24, val])
    if val <= 0xFFFF:
        return bytes([(major << 5) | 25]) + val.to_bytes(2, "big")
    if val <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + val.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + val.to_bytes(8, "big")


def encode(value: Any) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(MAJOR_UINT, value) if value >= 0 else _head(MAJOR_NINT, -1 - value)
    if isinstance(value, bytes):
        return _head(MAJOR_BSTR, len(value)) + value
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _head(MAJOR_TSTR, len(b)) + b
    if isinstance(value, (list, tuple)):
        return _head(MAJOR_ARR, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        pairs = []
        for k, v in value.items():
            if not isinstance(k, int) or k < 0:
                raise CborError("CBOR_UNSUPPORTED_TYPE")
            kb = _head(MAJOR_UINT, k)
            pairs.append((kb, encode(v)))
        pairs.sort(key=lambda p: p[0])
        out = bytearray(_head(MAJOR_MAP, len(pairs)))
        for kb, vb in pairs:
            out += kb + vb
        return bytes(out)
    raise CborError("CBOR_UNSUPPORTED_TYPE")


def decode_prefix(data: bytes, limits: Limits = DEFAULT_LIMITS):
    """Decode one item and return (value, bytes_consumed) without trailing check."""
    buf = _Buf(data)
    state = {"items": 0}
    value = _decode_one(buf, limits, 0, state)
    return value, buf.i


class _Permissive:
    """Marker for CBOR null/undefined under the permissive decoder."""

    NULL = object()
    UNDEFINED = object()


def decode_lenient_prefix(data: bytes):
    """Permissive top-level decode for CONTAINER INSPECTION ONLY.

    Allows non-minimal headers and null/simple values so the runner can tell a
    non-canonical container from a detached payload. Never used to assert
    canonicality or to verify signatures.
    """
    buf = _Buf(data)

    def one(depth: int):
        ib = buf.need(1)[0]
        major = ib >> 5
        ai = ib & 0x1F
        if ai < 24:
            val = ai
        elif ai == 24:
            val = buf.need(1)[0]
        elif ai == 25:
            val = int.from_bytes(buf.need(2), "big")
        elif ai == 26:
            val = int.from_bytes(buf.need(4), "big")
        elif ai == 27:
            val = int.from_bytes(buf.need(8), "big")
        elif ai == 31:
            raise CborError("CBOR_UNSUPPORTED_TYPE")
        else:
            raise CborError("CBOR_MALFORMED")
        if major == MAJOR_UINT:
            return val
        if major == MAJOR_NINT:
            return -1 - val
        if major == MAJOR_BSTR:
            return buf.need(val)
        if major == MAJOR_TSTR:
            return _utf8_text(buf.need(val))
        if major == MAJOR_ARR:
            return [one(depth + 1) for _ in range(val)]
        if major == MAJOR_MAP:
            return {one(depth + 1): one(depth + 1) for _ in range(val)}
        # major 6 (tag) / 7 (simple, float)
        if major == MAJOR_TAG:
            return (_Permissive.UNDEFINED, one(depth + 1))
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return _Permissive.NULL
        if ai == 23:
            return _Permissive.UNDEFINED
        return _Permissive.UNDEFINED  # float / other simple

    value = one(0)
    return value, buf.i


def is_canonical(data: bytes, limits: Limits = DEFAULT_LIMITS) -> bool:
    """True iff `data` decodes and re-encodes byte-identically (canonical)."""
    try:
        v = decode(data, limits)
    except CborError:
        return False
    try:
        return encode(v) == data
    except CborError:
        return False
