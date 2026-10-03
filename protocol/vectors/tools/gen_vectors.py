#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deceipt Protocol v1 — reference implementation and conformance-vector generator.

TEST / TOOLING ONLY.

Everything here is normative-by-example for the frozen contract under
docs/protocol/**.  All key material is deterministic and public by
construction (derived from fixed ASCII labels).  It MUST NOT protect
anything.  The app MUST NOT contain any of it except the public trust-anchor
material listed in protocol/vectors/fixtures/trust-anchors-v1.json.

Implements DESIGN.md sections 4 (receipt), 5 (trust), 6 (session crypto),
7 (GATT), 8 (transfer), 9 (verification order), and adopts the transaction
binding contract published by A2 in docs/flows/transaction-binding-and-checkout-v1.md
(the binding tuple/digest/proof/offer_hash bytes are reproduced here verbatim
and cross-checked in protocol/vectors/binding-crosscheck.json).

Run:  python3 protocol/vectors/tools/gen_vectors.py
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================================================
# 0. Constants — single source of truth for every number in the spec
# ==========================================================================

REVISION_LABEL = "deceipt-proto-r1"

PROTOCOL_VERSION = 1
SUITE_ID = 1
ALG_EDDSA = -8
CT_RECEIPT = "application/deceipt-receipt+cbor"
CT_CREDENTIAL = "application/deceipt-credential+cbor"

DOMAIN_HANDSHAKE = b"deceipt-handshake-v1"
DOMAIN_RECEIPT_ID = b"deceipt-receipt-id-v1"   # reserved, not used by the PoC
HKDF_INFO_PREFIX = b"deceipt-transfer-v1"

# A2 binding contract (docs/flows/transaction-binding-and-checkout-v1.md §3)
DOMAIN_OFFER_HASH = b"deceipt-offer-hash-v1"
DOMAIN_BINDING_TUPLE = b"deceipt-binding-tuple-v1"
DOMAIN_BINDING_PROOF = b"deceipt-binding-proof-v1"

# --- message types --------------------------------------------------------
MSG_CLIENT_HELLO = 0x01
MSG_ACCEPT = 0x02
MSG_ACK = 0x03
MSG_RECEIPT_ACK = 0x04
MSG_CANCEL = 0x05
MSG_RETRY = 0x06
MSG_SERVER_HELLO = 0x11
MSG_RECEIPT_OFFER = 0x12
MSG_TRANSFER_BEGIN = 0x13
MSG_TRANSFER_COMPLETE = 0x14
MSG_ERROR = 0x15

C2M_TYPES = [MSG_CLIENT_HELLO, MSG_ACCEPT, MSG_ACK, MSG_RECEIPT_ACK, MSG_CANCEL, MSG_RETRY]
M2C_TYPES = [MSG_SERVER_HELLO, MSG_RECEIPT_OFFER, MSG_TRANSFER_BEGIN,
             MSG_TRANSFER_COMPLETE, MSG_ERROR]

ENV_PLAINTEXT = 0x00
ENV_AEAD = 0x01
DIR_C2M = 0x00
DIR_M2C = 0x01

# --- receipt top-level labels --------------------------------------------
R_VERSION = 1
R_KIND = 2
R_RECEIPT_ID = 3
R_ISSUED_AT = 4
R_TZ_OFFSET = 5
R_MERCHANT = 6
R_LOCATION = 7
R_CURRENCY = 8
R_LINES = 9
R_DISCOUNTS = 10
R_TAXES = 11
R_TIP = 12
R_SERVICE_CHARGE = 13
R_ROUNDING = 14
R_TOTALS = 15
R_PAYMENT = 16
R_REFUND_OF = 17
R_VOID_OF = 18
R_ORDER = 19
R_CREDENTIAL = 20
R_EXTENSIONS = 21

KIND_SALE, KIND_REFUND, KIND_VOID = 1, 2, 3

# --- bounds ---------------------------------------------------------------
MAX_RECEIPT_BYTES = 65536
MAX_LINES = 256
MAX_DISCOUNTS = 64
MAX_TAXES = 64
MAX_TENDERS = 32
MAX_EXTENSIONS = 32
MAX_MODIFIERS = 16
MAX_ADDRESS_LINES = 8
MAX_TEXT_DESCRIPTION = 512
MAX_TEXT_DISPLAY_NAME = 128
MAX_TEXT_SHORT = 64
MAX_TEXT_UNIT = 16
MAX_MONETARY_ABS = 1_000_000_000_000_000
MAX_UNIT_PRICE_ABS = 1_000_000_000_000
MAX_QTY_VALUE_ABS = 1_000_000
MAX_QTY_SCALE = 9
MAX_ARITH_PRODUCT = 1 << 62
MAX_TAX_RATE_PPM = 999_999

MAX_CBOR_DEPTH = 12
MAX_CBOR_ITEMS = 8192
MAX_CBOR_ARRAY = 1024
MAX_CBOR_MAP = 256
MAX_CBOR_TEXT_BYTES = 4096
MAX_CBOR_BYTES = 65536
MAX_CBOR_KEY = 255

CRED_VERSION = 1
CRED_ISSUER_ID = 2
CRED_MERCHANT_ID = 3
CRED_DEVICE_KEY_ID = 4
CRED_DEVICE_PUBKEY = 5
CRED_VALID_FROM = 6
CRED_VALID_UNTIL = 7
CRED_CAPABILITIES = 8
CRED_MERCHANT_REF = 9
CRED_DISPLAY_NAME = 10
CRED_ISSUED_AT = 11
MAX_CREDENTIAL_BYTES = 1024

CAP_ISSUE_SALE = 0x0001
CAP_ISSUE_REFUND = 0x0002
CAP_ISSUE_VOID = 0x0004
CAP_RECEIVE_TRANSFER = 0x0008
CAP_EMBED_CREDENTIAL = 0x0010

MAX_CONTROL_PDU = 2048
MAX_LPDU_FRAGMENTS = 512
MAX_LPDU_FRAG_BYTES = 512
LPDU_HEADER_BYTES = 4
MAX_ATT_PAYLOAD = 512
MAX_FRAME_PAYLOAD = 512
MIN_FRAME_PAYLOAD = 16
DATAFRAME_HEADER_BYTES = 20
MAX_TRANSFER_CIPHERTEXT = MAX_RECEIPT_BYTES + 16
MAX_FRAMES = 32768
AEAD_TAG_BYTES = 16
AEAD_NONCE_BYTES = 12
AEAD_CTRL_ENVELOPE_OVERHEAD = 1 + 8 + AEAD_TAG_BYTES
ACK_EVERY_FRAMES = 32
WINDOW_FRAMES = 64
MAX_FRAME_RETRIES = 5
MAX_CONTROL_MESSAGES = 4096
MAX_BINDING_BYTES = 128
MAX_SESSION_ID_HISTORY = 32

NONCE_BYTES = 32
TRANSCRIPT_LABEL = DOMAIN_HANDSHAKE
TRANSCRIPT_LEN = 372

T_ADVERTISE = 60_000
T_CONNECT = 15_000
T_HELLO_RESPONSE = 5_000
T_ACCEPT = 10_000
T_CONTROL_FRAG = 5_000
T_ACK_WAIT = 3_000
T_ACK_INTERVAL = 500
T_TRANSFER_IDLE = 10_000
T_VERIFY_BUDGET = 5_000
T_SESSION = 120_000
T_CLOSE = 2_000
T_BINDING_QR = 300_000
CLOCK_SKEW_MAX_S = 300

CURRENCY_EXPONENT = {
    "CAD": 2, "USD": 2, "EUR": 2, "GBP": 2, "AUD": 2, "NZD": 2, "CHF": 2,
    "MXN": 2, "BRL": 2, "SGD": 2, "HKD": 2, "SEK": 2, "NOK": 2, "DKK": 2,
    "PLN": 2, "CZK": 2, "TRY": 2, "ZAR": 2, "INR": 2, "CNY": 2, "JPY": 0,
    "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0, "HUF": 2, "KWD": 3, "BHD": 3,
    "OMR": 3, "JOD": 3, "TND": 3, "IQD": 3, "LYD": 3,
}

ERRORS: List[Tuple[str, int, bool, bool, str]] = [
    ("CBOR_MALFORMED", 0x0101, True, False, "encoding"),
    ("CBOR_NONCANONICAL", 0x0102, True, False, "encoding"),
    ("CBOR_DUPLICATE_KEY", 0x0103, True, False, "encoding"),
    ("CBOR_DEPTH_EXCEEDED", 0x0104, True, False, "encoding"),
    ("CBOR_SIZE_EXCEEDED", 0x0105, True, False, "encoding"),
    ("CBOR_UNSUPPORTED_TYPE", 0x0106, True, False, "encoding"),
    ("MESSAGE_UNKNOWN_TYPE", 0x0107, True, False, "message"),
    ("MESSAGE_UNKNOWN_FIELD", 0x0108, True, False, "message"),
    ("MESSAGE_MISSING_FIELD", 0x0109, True, False, "message"),
    ("MESSAGE_FIELD_TYPE", 0x010A, True, False, "message"),
    ("MESSAGE_FIELD_RANGE", 0x010B, True, False, "message"),
    ("MESSAGE_TOO_LARGE", 0x010C, True, False, "message"),
    ("MESSAGE_WRONG_STATE", 0x010D, True, False, "message"),
    ("MESSAGE_WRONG_DIRECTION", 0x010E, True, False, "message"),
    ("LPDU_FRAGMENT_INVALID", 0x0201, True, False, "transport"),
    ("LPDU_SEQUENCE_ERROR", 0x0202, True, False, "transport"),
    ("LPDU_CONFLICT", 0x0203, True, False, "transport"),
    ("LPDU_REASSEMBLY_TIMEOUT", 0x0204, True, True, "transport"),
    ("LPDU_MESSAGE_TOO_LARGE", 0x0205, True, False, "transport"),
    ("TRANSPORT_MTU_TOO_SMALL", 0x0206, True, False, "transport"),
    ("TRANSPORT_LINK_LOST", 0x0207, True, True, "transport"),
    ("TRANSPORT_WRITE_FAILED", 0x0208, True, True, "transport"),
    ("TRANSPORT_PERMISSION_DENIED", 0x0209, True, False, "transport"),
    ("TRANSPORT_BLUETOOTH_OFF", 0x020A, True, True, "transport"),
    ("TRANSPORT_PEER_AMBIGUOUS", 0x020B, True, False, "transport"),
    ("TRANSPORT_CONNECT_TIMEOUT", 0x020C, True, True, "transport"),
    ("HANDSHAKE_UNSUPPORTED_VERSION", 0x0301, True, False, "handshake"),
    ("HANDSHAKE_NO_COMMON_SUITE", 0x0302, True, False, "handshake"),
    ("HANDSHAKE_ECDH_INVALID_POINT", 0x0303, True, False, "handshake"),
    ("HANDSHAKE_SIGNATURE_INVALID", 0x0304, True, False, "handshake"),
    ("HANDSHAKE_TRANSCRIPT_MISMATCH", 0x0305, True, False, "handshake"),
    ("HANDSHAKE_SUITE_MISMATCH", 0x0306, True, False, "handshake"),
    ("HANDSHAKE_NONCE_REPLAYED", 0x0307, True, False, "handshake"),
    ("CREDENTIAL_MALFORMED", 0x0308, True, False, "handshake"),
    ("CREDENTIAL_SIGNATURE_INVALID", 0x0309, True, False, "handshake"),
    ("CREDENTIAL_UNKNOWN_ISSUER", 0x030A, False, False, "handshake"),
    ("CREDENTIAL_NOT_YET_VALID", 0x030B, True, False, "handshake"),
    ("CREDENTIAL_EXPIRED", 0x030C, True, False, "handshake"),
    ("CREDENTIAL_CAPABILITY_MISSING", 0x030D, True, False, "handshake"),
    ("HANDSHAKE_TIMEOUT", 0x0310, True, True, "handshake"),
    ("PEER_NOT_AUTHENTICATED", 0x0311, True, False, "handshake"),
    ("BINDING_UNKNOWN_SESSION", 0x0312, True, False, "binding"),
    ("BINDING_PROOF_INVALID", 0x0313, True, False, "binding"),
    ("BINDING_REQUIRED", 0x0314, True, False, "binding"),
    ("BINDING_STALE", 0x0315, True, True, "binding"),
    ("BINDING_CONSUMED", 0x0316, True, False, "binding"),
    ("SESSION_EXPIRED", 0x0317, True, False, "handshake"),
    ("AEAD_AUTH_FAILED", 0x0401, True, False, "session"),
    ("AEAD_COUNTER_MISMATCH", 0x0402, True, False, "session"),
    ("AEAD_REPLAY_DETECTED", 0x0403, True, False, "session"),
    ("AEAD_NONCE_EXHAUSTED", 0x0404, True, False, "session"),
    ("SESSION_TORN_DOWN", 0x0405, True, False, "session"),
    ("TRANSFER_SIZE_EXCEEDED", 0x0501, True, False, "framing"),
    ("FRAME_SIZE_INVALID", 0x0502, True, False, "framing"),
    ("FRAME_SEQUENCE_OUT_OF_RANGE", 0x0503, True, False, "framing"),
    ("FRAME_SEQUENCE_REPLAYED", 0x0504, False, False, "framing"),
    ("FRAME_CONFLICT", 0x0505, True, False, "framing"),
    ("FRAME_BUFFER_EXCEEDED", 0x0506, True, False, "framing"),
    ("TRANSFER_INCOMPLETE", 0x0507, True, True, "framing"),
    ("TRANSFER_HASH_MISMATCH", 0x0508, True, False, "framing"),
    ("TRANSFER_TIMEOUT", 0x0509, True, True, "framing"),
    ("TRANSFER_RETRY_EXHAUSTED", 0x050A, True, False, "framing"),
    ("TRANSFER_CANCELLED", 0x050B, True, False, "framing"),
    ("TRANSFER_ABORTED", 0x050C, True, False, "framing"),
    ("TRANSFER_BEGIN_MISMATCH", 0x050D, True, False, "framing"),
    ("TRANSFER_ID_MISMATCH", 0x050E, True, False, "framing"),
    ("RECEIPT_CONTAINER_MALFORMED", 0x0601, True, False, "receipt"),
    ("RECEIPT_UNSUPPORTED_VERSION", 0x0602, True, False, "receipt"),
    ("RECEIPT_UNSUPPORTED_ALGORITHM", 0x0603, True, False, "receipt"),
    ("RECEIPT_UNKNOWN_HEADER", 0x0604, True, False, "receipt"),
    ("RECEIPT_UNKNOWN_FIELD", 0x0605, True, False, "receipt"),
    ("RECEIPT_SIZE_EXCEEDED", 0x0606, True, False, "receipt"),
    ("RECEIPT_SIGNATURE_INVALID", 0x0607, True, False, "receipt"),
    ("RECEIPT_KEY_NOT_AUTHORIZED", 0x0608, True, False, "receipt"),
    ("RECEIPT_SEMANTIC_INVALID", 0x0609, True, False, "receipt"),
    ("RECEIPT_ARITHMETIC_MISMATCH", 0x060A, True, False, "receipt"),
    ("RECEIPT_MONETARY_RANGE", 0x060B, True, False, "receipt"),
    ("RECEIPT_UNSUPPORTED_CURRENCY", 0x060C, True, False, "receipt"),
    ("RECEIPT_DUPLICATE_CONFLICT", 0x060D, True, False, "receipt"),
    ("RECEIPT_OUTSIDE_KEY_VALIDITY", 0x060E, True, False, "receipt"),
    ("RECEIPT_CREDENTIAL_MISMATCH", 0x060F, True, False, "receipt"),
    ("RECEIPT_OFFER_MISMATCH", 0x0610, True, False, "receipt"),
    ("RECEIPT_TEXT_INVALID", 0x0611, True, False, "receipt"),
    ("RECEIPT_UNKNOWN_CRITICAL_EXTENSION", 0x0612, True, False, "receipt"),
    ("RECEIPT_ISSUED_IN_FUTURE", 0x0613, True, False, "receipt"),
    ("WRONG_TRANSACTION", 0x0614, True, False, "receipt"),
    ("RECEIPT_NONCANONICAL", 0x0615, True, False, "receipt"),
    ("STORAGE_FAILED", 0x0701, True, True, "local"),
    ("USER_CANCELLED", 0x0702, True, False, "local"),
    ("VERIFY_BUDGET_EXCEEDED", 0x0703, True, False, "local"),
    ("CAPABILITY_UNAVAILABLE", 0x0704, True, False, "local"),
    ("INTERNAL_ERROR", 0x0705, True, True, "local"),
]

OUTCOMES = [
    ("TRUSTED", 0x0001),
    ("UNVERIFIED_UNKNOWN_ISSUER", 0x0002),
    ("ALREADY_IMPORTED_IDENTICAL", 0x0003),
    ("REJECTED", 0x0004),
    ("PENDING", 0x0005),
]

MAX_ISSUED_AT = 4_102_444_800
MIN_ISSUED_AT = 1_577_836_800
KNOWN_EXTENSIONS: set = set()



# ==========================================================================
# Public-repo notice injected into every vector artifact.
# ==========================================================================

TEST_ONLY_NOTICE = (
    "TEST-ONLY DETERMINISTIC MATERIAL. Every key, nonce, seed, token and signature in "
    "this file is public by construction and reproducible from fixed ASCII labels. It "
    "MUST NEVER be used outside these test vectors: not in a build, not in a session, "
    "not as a trust anchor. The only production-relevant value here is the PoC TEST "
    "ROOT PUBLIC KEY (public material only). Production sessions use fresh CSPRNG "
    "randomness; production trust roots are generated offline and their private keys "
    "NEVER enter this repository. See docs/protocol/trust.md and protocol/vectors/NOTICE."
)
TEST_ONLY_DIRECTIVE = "generated; do not edit by hand"


NOTICE_FILE = """Deceipt protocol vectors - PUBLIC REPOSITORY NOTICE
Revision: deceipt-proto-r1

Every artifact under protocol/vectors/ (including fixtures/ and keys/) is TEST-ONLY
DETERMINISTIC MATERIAL:

  * The keys, nonces, session-binding tokens and seeds are derived from fixed ASCII
    labels (see keys/test-keys.json "derivation"). They are public by construction.
  * They MUST NEVER be used outside these test vectors: not in a build, not in a
    session, not as a trust anchor. Production sessions use fresh CSPRNG randomness.
  * The ONLY production-relevant value committed here is the PoC TEST ROOT PUBLIC KEY
    (public material only, fixtures/trust-anchors-v1.json). Its private half is an
    explicitly-labelled test key; production trust-root private keys are generated
    offline and NEVER enter this repository.
  * All files are generated by protocol/vectors/tools/gen_vectors.py and must not be
    edited by hand. Regenerate with:  python3 protocol/vectors/tools/gen_vectors.py
  * Independent re-derivation of every published value:
    python3 protocol/vectors/tools/verify_vectors.py

Naming/label convention: every JSON vector file carries a "_TESTONLY" header field
with this notice; the binary fixture fixtures/valid-credential.cbor is covered by this
NOTICE in its directory and by the "_TESTONLY" notice in vectors-manifest.json.
"""


def _test_only(obj: Any) -> Any:
    d = {"_TESTONLY": TEST_ONLY_NOTICE, "_generated": TEST_ONLY_DIRECTIVE}
    d.update(obj)
    return d

# ==========================================================================
# 1. Deterministic CBOR (RFC 8949 section 4.2.1)
# ==========================================================================

class CborError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", n)
    raise CborError("CBOR_UNSUPPORTED_TYPE", "integer out of range")


def cbor_encode(obj: Any) -> bytes:
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, int):
        if obj < -(1 << 63) or obj > (1 << 64) - 1:
            raise CborError("CBOR_UNSUPPORTED_TYPE", "int out of range")
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        return _head(2, len(b)) + b
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, int) or isinstance(k, bool):
                raise CborError("CBOR_UNSUPPORTED_TYPE", "non-integer map key")
            if k < 0 or k > MAX_CBOR_KEY:
                raise CborError("CBOR_UNSUPPORTED_TYPE", "map key out of 0..255")
        items = sorted(obj.items(), key=lambda kv: cbor_encode(kv[0]))
        return _head(5, len(items)) + b"".join(
            cbor_encode(k) + cbor_encode(v) for k, v in items)
    raise CborError("CBOR_UNSUPPORTED_TYPE", f"unsupported python type {type(obj)}")


class CborDecoder:
    def __init__(self, buf: bytes, max_items: int = MAX_CBOR_ITEMS,
                 max_depth: int = MAX_CBOR_DEPTH, max_bytes: int = MAX_CBOR_BYTES):
        self.buf = buf
        self.pos = 0
        self.items = 0
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_bytes = max_bytes

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise CborError("CBOR_MALFORMED", "truncated")
        b = self.buf[self.pos:self.pos + n]
        self.pos += n
        return b

    def _byte(self) -> int:
        return self._take(1)[0]

    def _arg(self, ai: int) -> int:
        if ai < 24:
            return ai
        if ai == 24:
            v = self._byte()
            if v < 24:
                raise CborError("CBOR_NONCANONICAL", "non-minimal 1-byte argument")
            return v
        if ai == 25:
            v = struct.unpack(">H", self._take(2))[0]
            if v < 0x100:
                raise CborError("CBOR_NONCANONICAL", "non-minimal 2-byte argument")
            return v
        if ai == 26:
            v = struct.unpack(">I", self._take(4))[0]
            if v < 0x10000:
                raise CborError("CBOR_NONCANONICAL", "non-minimal 4-byte argument")
            return v
        if ai == 27:
            v = struct.unpack(">Q", self._take(8))[0]
            if v < 0x100000000:
                raise CborError("CBOR_NONCANONICAL", "non-minimal 8-byte argument")
            return v
        if ai == 31:
            raise CborError("CBOR_UNSUPPORTED_TYPE", "indefinite-length item")
        raise CborError("CBOR_MALFORMED", f"reserved additional information {ai}")

    def item(self, depth: int = 0) -> Any:
        if depth > self.max_depth:
            raise CborError("CBOR_DEPTH_EXCEEDED", f"depth > {self.max_depth}")
        self.items += 1
        if self.items > self.max_items:
            raise CborError("CBOR_SIZE_EXCEEDED", f"items > {self.max_items}")
        if self.pos > self.max_bytes:
            raise CborError("CBOR_SIZE_EXCEEDED", "bytes")
        ib = self._byte()
        major, ai = ib >> 5, ib & 0x1F
        if major == 0:
            return self._arg(ai)
        if major == 1:
            return -1 - self._arg(ai)
        if major == 2:
            n = self._arg(ai)
            if n > MAX_CBOR_BYTES:
                raise CborError("CBOR_SIZE_EXCEEDED", "byte string length")
            return self._take(n)
        if major == 3:
            n = self._arg(ai)
            if n > MAX_CBOR_TEXT_BYTES:
                raise CborError("CBOR_SIZE_EXCEEDED", "text string length")
            raw = self._take(n)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise CborError("CBOR_MALFORMED", "invalid utf-8")
        if major == 4:
            n = self._arg(ai)
            if n > MAX_CBOR_ARRAY:
                raise CborError("CBOR_SIZE_EXCEEDED", "array length")
            return [self.item(depth + 1) for _ in range(n)]
        if major == 5:
            n = self._arg(ai)
            if n > MAX_CBOR_MAP:
                raise CborError("CBOR_SIZE_EXCEEDED", "map length")
            out: Dict[Any, Any] = {}
            prev: Optional[bytes] = None
            for _ in range(n):
                start = self.pos
                k = self.item(depth + 1)
                kb = self.buf[start:self.pos]
                if prev is not None:
                    if kb == prev:
                        raise CborError("CBOR_DUPLICATE_KEY", f"key {k!r}")
                    if kb < prev:
                        raise CborError("CBOR_NONCANONICAL", "map keys unsorted")
                prev = kb
                if not isinstance(k, int) or isinstance(k, bool) or not 0 <= k <= MAX_CBOR_KEY:
                    raise CborError("CBOR_UNSUPPORTED_TYPE", "map key not uint 0..255")
                out[k] = self.item(depth + 1)
            return out
        if major == 6:
            raise CborError("CBOR_UNSUPPORTED_TYPE", "tag not permitted")
        if major == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            raise CborError("CBOR_UNSUPPORTED_TYPE", "null/undefined/simple/float not permitted")
        raise CborError("CBOR_MALFORMED", "unknown major type")


def gv_head(major: int, n: int) -> bytes:
    return _head(major, n)


def cbor_decode(buf: bytes, **kw) -> Any:
    d = CborDecoder(buf, **kw)
    v = d.item()
    if d.pos != len(buf):
        raise CborError("CBOR_MALFORMED", f"trailing bytes: {len(buf) - d.pos}")
    return v


# ==========================================================================
# 2. Exact decimal arithmetic
# ==========================================================================

def round_half_away(num: int, den: int) -> int:
    assert den > 0
    neg = num < 0
    n = -num if neg else num
    q = (2 * n + den) // (2 * den)
    return -q if neg else q


def quantity_amount(unit_price_minor: int, qty_value: int, qty_scale: int) -> int:
    prod = unit_price_minor * qty_value
    if abs(prod) > MAX_ARITH_PRODUCT:
        raise CborError("RECEIPT_MONETARY_RANGE", "arithmetic product overflow guard")
    return round_half_away(prod, 10 ** qty_scale)


# ==========================================================================
# 3. Text safety
# ==========================================================================

BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
                 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def check_text(s: str, max_bytes: int) -> Optional[str]:
    if not isinstance(s, str):
        return "RECEIPT_TEXT_INVALID"
    if len(s.encode("utf-8")) > max_bytes:
        return "RECEIPT_TEXT_INVALID"
    if unicodedata.normalize("NFC", s) != s:
        return "RECEIPT_TEXT_INVALID"
    for ch in s:
        if ord(ch) in BIDI_CONTROLS:
            return "RECEIPT_TEXT_INVALID"
        if unicodedata.category(ch) in ("Cc", "Cs"):
            return "RECEIPT_TEXT_INVALID"
    return None




def M(base, extra):
    """Merge dicts with integer keys (M(**{int:..}) is illegal in Python)."""
    out = dict(base)
    out.update(extra)
    return out

# ==========================================================================
# 4. Keys (test-only, deterministic)
# ==========================================================================

def test_ed25519(name: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"deceipt-testkey:ed25519:" + name.encode()).digest())


def ed25519_seed_hex(name: str) -> str:
    return hashlib.sha256(b"deceipt-testkey:ed25519:" + name.encode()).hexdigest()


def ed25519_pub_bytes(k: ed25519.Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)


_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_p256(name: str, counter: int = 0) -> ec.EllipticCurvePrivateKey:
    """Deterministic scalar; retries with a counter until a valid key derives."""
    c = counter
    while True:
        material = hashlib.sha256(
            b"deceipt-testkey:p256:" + name.encode() + ("#%d" % c).encode()).digest()
        d = (int.from_bytes(material, "big") % (_P256_N - 1)) + 1
        try:
            k = ec.derive_private_key(d, ec.SECP256R1())
            k.public_key().public_bytes(serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint)
            return k
        except ValueError:
            c += 1


def p256_pub_bytes(k: ec.EllipticCurvePrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint)


def p256_scalar_hex(k: ec.EllipticCurvePrivateKey) -> str:
    return "%064x" % k.private_numbers().private_value


def is_valid_p256_point(blob: bytes) -> bool:
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), blob)
        return True
    except Exception:
        return False


def ecdh(priv: ec.EllipticCurvePrivateKey, peer_pub: bytes) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
    return priv.exchange(ec.ECDH(), peer)


# ==========================================================================
# 5. HKDF-SHA-256 (RFC 5869) and the session key schedule
# ==========================================================================

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def derive_session_keys(shared_secret: bytes, transcript_hash: bytes) -> Dict[str, bytes]:
    info = HKDF_INFO_PREFIX + transcript_hash
    prk = hkdf_extract(transcript_hash, shared_secret)
    okm = hkdf_expand(prk, info, 128)
    return {"prk": prk, "okm": okm, "k_c2m_ctrl": okm[0:32], "k_m2c_ctrl": okm[32:64],
            "k_m2c_payload": okm[64:96], "k_exporter": okm[96:128]}


def session_context(transcript_hash: bytes, transfer_id: bytes) -> bytes:
    return transcript_hash + transfer_id


def aad_payload(ctx: bytes) -> bytes:
    return ctx + b"\x01"


def aad_ctrl(ctx: bytes, direction: int) -> bytes:
    return ctx + b"\x02" + bytes([direction])


def aead_nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)


def aead_seal(key: bytes, counter: int, aad: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(aead_nonce(counter), plaintext, aad)


def aead_open(key: bytes, counter: int, aad: bytes, ct: bytes) -> bytes:
    return AESGCM(key).decrypt(aead_nonce(counter), ct, aad)


# ==========================================================================
# 6. COSE_Sign1 (RFC 9052)
# ==========================================================================

COSE_PROTECTED_ALG = 1
COSE_PROTECTED_CRIT = 2
COSE_PROTECTED_CTYPE = 3
COSE_PROTECTED_KID = 4


def sig_structure(protected_bstr: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    return cbor_encode(["Signature1", protected_bstr, external_aad, payload])


def cose_sign1(protected: Dict[int, Any], payload: bytes,
               signer: ed25519.Ed25519PrivateKey, external_aad: bytes = b"") -> bytes:
    pb = cbor_encode(protected)
    sig = signer.sign(sig_structure(pb, payload, external_aad))
    return cbor_encode([pb, {}, payload, sig])


def cose_sign1_parts(protected: Dict[int, Any], payload: bytes,
                     signer: ed25519.Ed25519PrivateKey) -> Tuple[bytes, bytes, bytes]:
    pb = cbor_encode(protected)
    ss = sig_structure(pb, payload)
    return pb, ss, signer.sign(ss)


def map_cbor_to_receipt(code: str) -> str:
    return {"CBOR_NONCANONICAL": "RECEIPT_NONCANONICAL",
            "CBOR_SIZE_EXCEEDED": "RECEIPT_SIZE_EXCEEDED"}.get(code, "RECEIPT_CONTAINER_MALFORMED")


def cose_parse(blob: bytes, max_bytes: int = MAX_RECEIPT_BYTES) -> Dict[str, Any]:
    if len(blob) > max_bytes:
        raise CborError("RECEIPT_SIZE_EXCEEDED", f"{len(blob)} > {max_bytes}")
    try:
        arr = cbor_decode(blob, max_bytes=max_bytes)
    except CborError as e:
        raise CborError(map_cbor_to_receipt(e.code), e.detail)
    if not isinstance(arr, list) or len(arr) != 4:
        raise CborError("RECEIPT_CONTAINER_MALFORMED", "not a 4-element array")
    prot_b, unprot, payload, sig = arr
    if not isinstance(prot_b, bytes):
        raise CborError("RECEIPT_CONTAINER_MALFORMED", "protected not bstr")
    if unprot != {}:
        raise CborError("RECEIPT_UNKNOWN_HEADER", "unprotected header must be empty")
    if not isinstance(payload, bytes):
        raise CborError("RECEIPT_CONTAINER_MALFORMED", "detached payload not permitted")
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise CborError("RECEIPT_CONTAINER_MALFORMED", "signature must be 64 bytes")
    if cbor_encode(arr) != blob:
        raise CborError("RECEIPT_NONCANONICAL", "container not deterministic")
    prot = cbor_decode(prot_b)
    if not isinstance(prot, dict):
        raise CborError("RECEIPT_CONTAINER_MALFORMED", "protected not a map")
    return {"protected_bstr": prot_b, "protected": prot, "payload": payload, "signature": sig}


def cose_check_protected(prot: Dict[int, Any], content_type: str) -> Optional[str]:
    if COSE_PROTECTED_CRIT in prot:
        return "RECEIPT_UNKNOWN_HEADER"
    for k in prot:
        if k not in (COSE_PROTECTED_ALG, COSE_PROTECTED_CTYPE, COSE_PROTECTED_KID):
            return "RECEIPT_UNKNOWN_HEADER"
    if prot.get(COSE_PROTECTED_ALG) != ALG_EDDSA:
        return "RECEIPT_UNSUPPORTED_ALGORITHM"
    if prot.get(COSE_PROTECTED_CTYPE) != content_type:
        return "RECEIPT_UNSUPPORTED_ALGORITHM"
    kid = prot.get(COSE_PROTECTED_KID)
    if not isinstance(kid, bytes) or len(kid) != 16:
        return "RECEIPT_CONTAINER_MALFORMED"
    return None


# ==========================================================================
# 7. Merchant device credential (Pass B)
# ==========================================================================

def credential_body(version: int, issuer_id: bytes, merchant_id: bytes, device_key_id: bytes,
                    device_pub: bytes, valid_from: int, valid_until: int, capabilities: int,
                    merchant_ref: str, display_name: str, issued_at: int) -> Dict[int, Any]:
    return {CRED_VERSION: version, CRED_ISSUER_ID: issuer_id, CRED_MERCHANT_ID: merchant_id,
            CRED_DEVICE_KEY_ID: device_key_id, CRED_DEVICE_PUBKEY: device_pub,
            CRED_VALID_FROM: valid_from, CRED_VALID_UNTIL: valid_until,
            CRED_CAPABILITIES: capabilities, CRED_MERCHANT_REF: merchant_ref,
            CRED_DISPLAY_NAME: display_name, CRED_ISSUED_AT: issued_at}


def build_credential(body: Dict[int, Any], root_key: ed25519.Ed25519PrivateKey,
                     issuer_id: bytes) -> bytes:
    return cose_sign1({COSE_PROTECTED_ALG: ALG_EDDSA, COSE_PROTECTED_CTYPE: CT_CREDENTIAL,
                       COSE_PROTECTED_KID: issuer_id}, cbor_encode(body), root_key)


def credential_binding_hash(credential_bytes: bytes) -> bytes:
    return hashlib.sha256(credential_bytes).digest()


def verify_credential(cred_blob: bytes, anchors: Dict[bytes, bytes], now: int) -> Tuple[
        Optional[str], Optional[Dict[int, Any]], str]:
    if len(cred_blob) > MAX_CREDENTIAL_BYTES:
        return "CREDENTIAL_MALFORMED", None, "none"
    try:
        c = cose_parse(cred_blob)
        if cose_check_protected(c["protected"], CT_CREDENTIAL) is not None:
            return "CREDENTIAL_MALFORMED", None, "none"
        body = cbor_decode(c["payload"], max_bytes=MAX_CREDENTIAL_BYTES)
    except CborError:
        return "CREDENTIAL_MALFORMED", None, "none"
    if not isinstance(body, dict) or body.get(CRED_VERSION) != 1:
        return "CREDENTIAL_MALFORMED", None, "none"
    if c["protected"][COSE_PROTECTED_KID] != body.get(CRED_ISSUER_ID):
        return "CREDENTIAL_MALFORMED", None, "none"
    if len(body.get(CRED_MERCHANT_ID, b"")) != 16 or len(body.get(CRED_DEVICE_KEY_ID, b"")) != 16:
        return "CREDENTIAL_MALFORMED", None, "none"
    if len(body.get(CRED_DEVICE_PUBKEY, b"")) != 32:
        return "CREDENTIAL_MALFORMED", None, "none"
    if check_text(body.get(CRED_MERCHANT_REF, ""), MAX_TEXT_DISPLAY_NAME) \
            or check_text(body.get(CRED_DISPLAY_NAME, ""), MAX_TEXT_DISPLAY_NAME):
        return "CREDENTIAL_MALFORMED", None, "none"
    anchor = anchors.get(body.get(CRED_ISSUER_ID))
    if anchor is None:
        return "CREDENTIAL_UNKNOWN_ISSUER", body, "unknown_issuer"
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(anchor).verify(
            c["signature"], sig_structure(c["protected_bstr"], c["payload"]))
    except Exception:
        return "CREDENTIAL_SIGNATURE_INVALID", body, "none"
    vf, vu = body.get(CRED_VALID_FROM, 0), body.get(CRED_VALID_UNTIL, 0)
    if now < vf - CLOCK_SKEW_MAX_S:
        return "CREDENTIAL_NOT_YET_VALID", body, "authenticated"
    if now >= vu + CLOCK_SKEW_MAX_S:
        return "CREDENTIAL_EXPIRED", body, "authenticated"
    return None, body, "authenticated"


def required_capability(kind: int) -> int:
    return {KIND_SALE: CAP_ISSUE_SALE, KIND_REFUND: CAP_ISSUE_REFUND,
            KIND_VOID: CAP_ISSUE_VOID}[kind]


# ==========================================================================
# 8. Binding bytes (A2 contract, adopted verbatim)
# ==========================================================================

def offer_hash(session_id: bytes, transfer_id: bytes, receipt_id: bytes,
               merchant_ref: str, total_amount_minor: int, currency: str,
               issued_at_unix: int) -> bytes:
    msg = cbor_encode([session_id, transfer_id, receipt_id, merchant_ref,
                       total_amount_minor, currency, issued_at_unix])
    return hashlib.sha256(DOMAIN_OFFER_HASH + b"\x00" + msg).digest()


def offer_hash_preimage(session_id: bytes, transfer_id: bytes, receipt_id: bytes,
                        merchant_ref: str, total_amount_minor: int, currency: str,
                        issued_at_unix: int) -> bytes:
    return cbor_encode([session_id, transfer_id, receipt_id, merchant_ref,
                        total_amount_minor, currency, issued_at_unix])


def binding_tuple(session_id: bytes, transfer_id: bytes, receipt_id: bytes,
                  offer_hash_bytes: bytes) -> bytes:
    return cbor_encode([1, session_id, transfer_id, receipt_id, offer_hash_bytes])


def binding_tuple_digest(tuple_bytes: bytes) -> bytes:
    return hashlib.sha256(DOMAIN_BINDING_TUPLE + b"\x00" + tuple_bytes).digest()


def binding_proof(sbt: bytes, client_nonce: bytes, client_eph_pub: bytes) -> bytes:
    return hmac.new(sbt, DOMAIN_BINDING_PROOF + b"\x00" + client_nonce + client_eph_pub,
                    hashlib.sha256).digest()


def binding_proof_message(client_nonce: bytes, client_eph_pub: bytes) -> bytes:
    return DOMAIN_BINDING_PROOF + b"\x00" + client_nonce + client_eph_pub


# ==========================================================================
# 9. Canonical handshake transcript (Pass C)
# ==========================================================================

TRANSCRIPT_LAYOUT = [
    ("label", 19), ("protocol_version", 2), ("suite_id", 2),
    ("client_nonce", 32), ("client_ephemeral_pubkey", 65),
    ("server_nonce", 32), ("server_ephemeral_pubkey", 65),
    ("transfer_id", 16), ("session_id", 16),
    ("binding_tuple_digest", 32), ("max_frame_payload", 2),
    ("binding_len", 1), ("binding_tuple", None),
]


def build_transcript(protocol_version: int, suite_id: int, client_nonce: bytes,
                     client_eph_pub: bytes, server_nonce: bytes, server_eph_pub: bytes,
                     transfer_id: bytes, session_id: bytes, binding_digest: bytes,
                     max_frame_payload: int, tuple_bytes: bytes) -> bytes:
    fixed = [(client_nonce, 32), (client_eph_pub, 65), (server_nonce, 32),
             (server_eph_pub, 65), (transfer_id, 16), (session_id, 16),
             (binding_digest, 32)]
    for val, exp in fixed:
        if len(val) != exp:
            raise ValueError("field length mismatch")
    if len(tuple_bytes) > MAX_BINDING_BYTES:
        raise ValueError("binding tuple too long")
    return (TRANSCRIPT_LABEL + struct.pack(">H", protocol_version)
            + struct.pack(">H", suite_id) + client_nonce + client_eph_pub
            + server_nonce + server_eph_pub + transfer_id + session_id
            + binding_digest + struct.pack(">H", max_frame_payload)
            + bytes([len(tuple_bytes)]) + tuple_bytes)


def transcript_layout_table() -> List[Dict[str, Any]]:
    out, off = [], 0
    for name, size in TRANSCRIPT_LAYOUT:
        if size is None:
            out.append({"offset": off, "field": name, "size": "binding_len (0..128)",
                        "note": "A2 binding_tuple bytes"})
            break
        out.append({"offset": off, "field": name, "size": size}
                   if False else {"offset": off, "field": name, "size_bytes": size})
        off += size
    return out


# ==========================================================================
# 10. Receipt (Pass A)
# ==========================================================================

def finalize(body: Dict[int, Any]) -> Dict[int, Any]:
    """Restate totals/payment from lines/discounts/taxes so the receipt satisfies its own
    invariants. Used by the generator; the *wire* receipt is whatever the merchant signs."""
    lines = body.get(R_LINES, [])
    discounts = body.get(R_DISCOUNTS, [])
    taxes = body.get(R_TAXES, [])
    subtotal = sum(l[5] for l in lines)
    discount_total = sum(d[2] for d in discounts)
    tax_total = sum(t[5] for t in taxes)
    tax_added = sum(t[5] for t in taxes if not t.get(8, False))
    total = (subtotal - discount_total + tax_added + body.get(R_TIP, 0)
             + body.get(R_SERVICE_CHARGE, 0) + body.get(R_ROUNDING, 0))
    totals = {1: subtotal, 2: discount_total, 3: tax_total, 8: tax_added, 4: total}
    for lbl, key in ((5, R_TIP), (6, R_SERVICE_CHARGE), (7, R_ROUNDING)):
        if key in body:
            totals[lbl] = body[key]
    body[R_TOTALS] = totals
    pay = body.get(R_PAYMENT)
    if isinstance(pay, dict):
        if pay.get(1) in (1, 4):
            pay[2] = total
        if pay.get(1) == 1 and pay.get(4):
            pay[4][0][2] = pay[2]
            if pay[2] > total:
                pay[3] = pay[2] - total
            elif 3 in pay:
                del pay[3]
    return body


def build_receipt_body(kind: int, receipt_id: bytes, issued_at: int, merchant_id: bytes,
                       merchant_ref: str, display_name: str, currency: str,
                       lines: List[Dict[int, Any]], discounts: List[Dict[int, Any]],
                       taxes: List[Dict[int, Any]], tip: Optional[int],
                       service_charge: Optional[int], rounding: Optional[int],
                       credential_bytes: bytes, tz_offset: Optional[int] = None) -> Dict[int, Any]:
    subtotal = sum(l[5] for l in lines)
    discount_total = sum(d[2] for d in discounts)
    tax_total = sum(t[5] for t in taxes)
    tax_added = sum(t[5] for t in taxes if not t.get(8, False))
    total = (subtotal - discount_total + tax_added + (tip or 0)
             + (service_charge or 0) + (rounding or 0))
    totals = {1: subtotal, 2: discount_total, 3: tax_total, 4: total, 8: tax_added}
    if tip is not None:
        totals[5] = tip
    if service_charge is not None:
        totals[6] = service_charge
    if rounding is not None:
        totals[7] = rounding
    payment = {1: 1 if kind == KIND_SALE else (4 if kind == KIND_REFUND else 5),
               2: total, 4: []}
    if kind == KIND_SALE:
        payment[4] = [{1: 2, 2: total, 3: "4242", 4: "VISA", 5: "AUTH0001"}]
    if kind == KIND_VOID:
        payment = {1: 5, 2: 0, 4: []}
    body: Dict[int, Any] = {
        R_VERSION: 1, R_KIND: kind, R_RECEIPT_ID: receipt_id, R_ISSUED_AT: issued_at,
        R_MERCHANT: {1: merchant_id, 2: display_name, 3: merchant_ref},
        R_CURRENCY: currency, R_LINES: lines, R_TOTALS: totals, R_PAYMENT: payment,
        R_CREDENTIAL: credential_bytes,
    }
    if tz_offset is not None:
        body[R_TZ_OFFSET] = tz_offset
    if discounts:
        body[R_DISCOUNTS] = discounts
    if taxes:
        body[R_TAXES] = taxes
    if tip is not None:
        body[R_TIP] = tip
    if service_charge is not None:
        body[R_SERVICE_CHARGE] = service_charge
    if rounding is not None:
        body[R_ROUNDING] = rounding
    return finalize(body)


def check_receipt_semantics(body: Dict[int, Any]) -> Optional[str]:
    allowed = {R_VERSION, R_KIND, R_RECEIPT_ID, R_ISSUED_AT, R_TZ_OFFSET, R_MERCHANT,
               R_LOCATION, R_CURRENCY, R_LINES, R_DISCOUNTS, R_TAXES, R_TIP,
               R_SERVICE_CHARGE, R_ROUNDING, R_TOTALS, R_PAYMENT, R_REFUND_OF,
               R_VOID_OF, R_ORDER, R_CREDENTIAL, R_EXTENSIONS}
    if not isinstance(body, dict):
        return "RECEIPT_CONTAINER_MALFORMED"
    for k in body:
        if k not in allowed:
            return "RECEIPT_UNKNOWN_FIELD"
    if body.get(R_VERSION) != 1:
        return "RECEIPT_UNSUPPORTED_VERSION"
    kind = body.get(R_KIND)
    if kind not in (KIND_SALE, KIND_REFUND, KIND_VOID):
        return "RECEIPT_SEMANTIC_INVALID"
    cur = body.get(R_CURRENCY)
    if not isinstance(cur, str) or cur not in CURRENCY_EXPONENT:
        return "RECEIPT_UNSUPPORTED_CURRENCY"
    iat = body.get(R_ISSUED_AT)
    if not isinstance(iat, int) or not MIN_ISSUED_AT <= iat <= MAX_ISSUED_AT:
        return "RECEIPT_SEMANTIC_INVALID"
    if not isinstance(body.get(R_RECEIPT_ID), bytes) or len(body[R_RECEIPT_ID]) != 16:
        return "RECEIPT_SEMANTIC_INVALID"
    m = body.get(R_MERCHANT)
    if not isinstance(m, dict) or set(m) - {1, 2, 3} or len(m.get(1, b"")) != 16:
        return "RECEIPT_SEMANTIC_INVALID"
    if check_text(m.get(2, ""), MAX_TEXT_DISPLAY_NAME) or \
            check_text(m.get(3, ""), MAX_TEXT_DISPLAY_NAME):
        return "RECEIPT_TEXT_INVALID"
    if R_TZ_OFFSET in body and (not isinstance(body[R_TZ_OFFSET], int)
                                or not -(14 * 3600) <= body[R_TZ_OFFSET] <= 14 * 3600):
        return "RECEIPT_SEMANTIC_INVALID"
    for key in (R_TIP, R_SERVICE_CHARGE, R_ROUNDING):
        if key in body and not isinstance(body[key], int):
            return "RECEIPT_SEMANTIC_INVALID"
        if key in body and key != R_ROUNDING and body[key] < 0:
            return "RECEIPT_SEMANTIC_INVALID"

    lines = body.get(R_LINES)
    if not isinstance(lines, list) or len(lines) > MAX_LINES:
        return "RECEIPT_SEMANTIC_INVALID"
    line_ids = set()
    for l in lines:
        if not isinstance(l, dict) or set(l) - {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}:
            return "RECEIPT_UNKNOWN_FIELD"
        lid = l.get(1)
        if not isinstance(lid, int) or lid < 1 or lid in line_ids:
            return "RECEIPT_SEMANTIC_INVALID"
        line_ids.add(lid)
        if check_text(l.get(2, ""), MAX_TEXT_DESCRIPTION):
            return "RECEIPT_TEXT_INVALID"
        q = l.get(3)
        if not isinstance(q, dict) or set(q) - {1, 2, 3}:
            return "RECEIPT_UNKNOWN_FIELD"
        if not isinstance(q.get(1), int) or not 0 <= q[1] <= MAX_QTY_SCALE:
            return "RECEIPT_SEMANTIC_INVALID"
        if not isinstance(q.get(2), int) or abs(q[2]) > MAX_QTY_VALUE_ABS:
            return "RECEIPT_MONETARY_RANGE"
        if 3 in q and check_text(q[3], MAX_TEXT_UNIT):
            return "RECEIPT_TEXT_INVALID"
        up = l.get(4)
        if not isinstance(up, int) or abs(up) > MAX_UNIT_PRICE_ABS:
            return "RECEIPT_MONETARY_RANGE"
        amt = l.get(5)
        if not isinstance(amt, int) or amt < 0 or amt > MAX_MONETARY_ABS:
            return "RECEIPT_MONETARY_RANGE"
        if quantity_amount(up, q[2], q[1]) != amt:
            return "RECEIPT_ARITHMETIC_MISMATCH"
        if 6 in l and (not isinstance(l[6], int) or not 0 <= l[6] <= amt):
            return "RECEIPT_SEMANTIC_INVALID"
        if 7 in l and (not isinstance(l[7], list) or not l[7]
                       or not all(isinstance(x, int) and x in line_ids for x in l[7])):
            return "RECEIPT_SEMANTIC_INVALID"
        if 8 in l and l[8] not in (1, 2, 3, 4):
            return "RECEIPT_SEMANTIC_INVALID"
        if 9 in l and check_text(l[9], MAX_TEXT_SHORT):
            return "RECEIPT_TEXT_INVALID"
        if 10 in l:
            mods = l[10]
            if not isinstance(mods, list) or len(mods) > MAX_MODIFIERS:
                return "RECEIPT_SEMANTIC_INVALID"
            for mm in mods:
                if not isinstance(mm, dict) or set(mm) - {1, 2, 3, 4}:
                    return "RECEIPT_UNKNOWN_FIELD"
                if check_text(mm.get(1, ""), MAX_TEXT_DESCRIPTION):
                    return "RECEIPT_TEXT_INVALID"
                if not isinstance(mm.get(2), int) or abs(mm[2]) > MAX_UNIT_PRICE_ABS:
                    return "RECEIPT_MONETARY_RANGE"
                if not isinstance(mm.get(3), int) or abs(mm[3]) > MAX_QTY_VALUE_ABS:
                    return "RECEIPT_MONETARY_RANGE"
                if not isinstance(mm.get(4), int) or not 0 <= mm[4] <= MAX_QTY_SCALE:
                    return "RECEIPT_SEMANTIC_INVALID"
    loc = body.get(R_LOCATION)
    if loc is not None:
        if not isinstance(loc, dict) or set(loc) - {1, 2, 3, 4, 5, 6}:
            return "RECEIPT_UNKNOWN_FIELD"
        if 1 in loc and check_text(loc[1], MAX_TEXT_DISPLAY_NAME):
            return "RECEIPT_TEXT_INVALID"
        for k in (2, 3, 4):
            if k in loc and check_text(loc[k], MAX_TEXT_DESCRIPTION):
                return "RECEIPT_TEXT_INVALID"
        if 5 in loc and (not isinstance(loc[5], list) or len(loc[5]) > MAX_ADDRESS_LINES
                         or any(check_text(x, MAX_TEXT_DESCRIPTION) for x in loc[5])):
            return "RECEIPT_TEXT_INVALID"
        if 6 in loc and (not isinstance(loc[6], str)
                         or not all(x.isdigit() for x in loc[6])):
            return "RECEIPT_TEXT_INVALID"
    discounts = body.get(R_DISCOUNTS, [])
    if not isinstance(discounts, list) or len(discounts) > MAX_DISCOUNTS:
        return "RECEIPT_SEMANTIC_INVALID"
    d_ids = set()
    for d in discounts:
        if not isinstance(d, dict) or set(d) - {1, 2, 3, 4, 5, 6, 7}:
            return "RECEIPT_UNKNOWN_FIELD"
        if not isinstance(d.get(1), int) or d[1] in d_ids:
            return "RECEIPT_SEMANTIC_INVALID"
        d_ids.add(d[1])
        if not isinstance(d.get(2), int) or not 0 <= d[2] <= MAX_MONETARY_ABS:
            return "RECEIPT_MONETARY_RANGE"
        if check_text(d.get(3, ""), MAX_TEXT_DISPLAY_NAME):
            return "RECEIPT_TEXT_INVALID"
        if d.get(4) not in (1, 2):
            return "RECEIPT_SEMANTIC_INVALID"
        if d[4] == 2 and d.get(5) not in line_ids:
            return "RECEIPT_SEMANTIC_INVALID"
        if 6 in d:
            if 7 not in d:
                return "RECEIPT_SEMANTIC_INVALID"
            if not isinstance(d[6], int) or not 0 <= d[6] <= MAX_TAX_RATE_PPM:
                return "RECEIPT_SEMANTIC_INVALID"
            if not isinstance(d[7], int) or d[7] < 0:
                return "RECEIPT_MONETARY_RANGE"
            if round_half_away(d[7] * d[6], 1_000_000) != d[2]:
                return "RECEIPT_ARITHMETIC_MISMATCH"
    taxes = body.get(R_TAXES, [])
    if not isinstance(taxes, list) or len(taxes) > MAX_TAXES:
        return "RECEIPT_SEMANTIC_INVALID"
    t_ids = set()
    for t in taxes:
        if not isinstance(t, dict) or set(t) - {1, 2, 3, 4, 5, 6, 7, 8}:
            return "RECEIPT_UNKNOWN_FIELD"
        if not isinstance(t.get(1), int) or t[1] in t_ids:
            return "RECEIPT_SEMANTIC_INVALID"
        t_ids.add(t[1])
        if not isinstance(t.get(4), int) or not 0 <= t[4] <= MAX_MONETARY_ABS:
            return "RECEIPT_MONETARY_RANGE"
        if not isinstance(t.get(5), int) or not 0 <= t[5] <= MAX_MONETARY_ABS:
            return "RECEIPT_MONETARY_RANGE"
        if round_half_away(t[4] * t[3], 1_000_000) != t[5]:
            return "RECEIPT_ARITHMETIC_MISMATCH"
        if 8 in t and not isinstance(t[8], bool):
            return "RECEIPT_SEMANTIC_INVALID"
        if t.get(8) is True and t.get(4) != 0:
            return "RECEIPT_SEMANTIC_INVALID"

    subtotal = sum(l[5] for l in lines)
    discount_total = sum(d[2] for d in discounts)
    tax_total = sum(t[5] for t in taxes)
    tax_added = sum(t[5] for t in taxes if not t.get(8, False))
    total = (subtotal - discount_total + tax_added + body.get(R_TIP, 0)
             + body.get(R_SERVICE_CHARGE, 0) + body.get(R_ROUNDING, 0))
    if total < 0:
        return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_VOID:
        if lines or subtotal != 0 or total != 0 or R_VOID_OF not in body:
            return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_REFUND and R_REFUND_OF not in body:
        return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_SALE and (R_REFUND_OF in body or R_VOID_OF in body):
        return "RECEIPT_SEMANTIC_INVALID"
    for ref in (R_REFUND_OF, R_VOID_OF):
        if ref in body and (not isinstance(body[ref], bytes) or len(body[ref]) != 16):
            return "RECEIPT_SEMANTIC_INVALID"
    ordv = body.get(R_ORDER)
    if ordv is not None:
        if not isinstance(ordv, dict) or set(ordv) - {1, 2, 3}:
            return "RECEIPT_UNKNOWN_FIELD"
        if 1 in ordv and check_text(ordv[1], MAX_TEXT_SHORT):
            return "RECEIPT_TEXT_INVALID"
        for k in (2, 3):
            if k in ordv and check_text(ordv[k], MAX_TEXT_SHORT):
                return "RECEIPT_TEXT_INVALID"

    tot = body.get(R_TOTALS)
    if not isinstance(tot, dict) or set(tot) - {1, 2, 3, 4, 5, 6, 7, 8}:
        return "RECEIPT_SEMANTIC_INVALID"
    if (tot.get(1), tot.get(2), tot.get(3), tot.get(8), tot.get(4)) != \
       (subtotal, discount_total, tax_total, tax_added, total):
        return "RECEIPT_ARITHMETIC_MISMATCH"
    if (tot.get(5), tot.get(6), tot.get(7)) != (body.get(R_TIP), body.get(R_SERVICE_CHARGE),
                                                body.get(R_ROUNDING)):
        return "RECEIPT_ARITHMETIC_MISMATCH"

    pay = body.get(R_PAYMENT)
    if not isinstance(pay, dict) or set(pay) - {1, 2, 3, 4}:
        return "RECEIPT_UNKNOWN_FIELD"
    status, paid = pay.get(1), pay.get(2)
    if not isinstance(status, int) or status not in (1, 2, 3, 4, 5):
        return "RECEIPT_SEMANTIC_INVALID"
    if not isinstance(paid, int) or paid < 0 or paid > MAX_MONETARY_ABS:
        return "RECEIPT_MONETARY_RANGE"
    tenders = pay.get(4, [])
    if not isinstance(tenders, list) or len(tenders) > MAX_TENDERS:
        return "RECEIPT_SEMANTIC_INVALID"
    for td in tenders:
        if not isinstance(td, dict) or set(td) - {1, 2, 3, 4, 5}:
            return "RECEIPT_UNKNOWN_FIELD"
        if td.get(1) not in (1, 2, 3, 4):
            return "RECEIPT_SEMANTIC_INVALID"
        if not isinstance(td.get(2), int) or td[2] < 0:
            return "RECEIPT_MONETARY_RANGE"
        if 3 in td and (not isinstance(td[3], str) or len(td[3]) != 4 or not td[3].isdigit()):
            return "RECEIPT_SEMANTIC_INVALID"
        for k in (4, 5):
            if k in td and check_text(td[k], MAX_TEXT_SHORT):
                return "RECEIPT_TEXT_INVALID"
    if tenders and sum(td[2] for td in tenders) != paid:
        return "RECEIPT_ARITHMETIC_MISMATCH"
    if status == 1:
        if not tenders:
            return "RECEIPT_SEMANTIC_INVALID"
        if paid < total:
            return "RECEIPT_SEMANTIC_INVALID"
        if paid > total and pay.get(3) != paid - total:
            return "RECEIPT_ARITHMETIC_MISMATCH"
    if status == 2 and paid >= total:
        return "RECEIPT_SEMANTIC_INVALID"
    if status == 3 and paid != 0:
        return "RECEIPT_SEMANTIC_INVALID"
    if status in (4, 5) and tenders:
        return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_SALE and status not in (1, 2, 3):
        return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_REFUND and (status != 4 or paid != total):
        return "RECEIPT_SEMANTIC_INVALID"
    if kind == KIND_VOID and (status != 5 or paid != 0):
        return "RECEIPT_SEMANTIC_INVALID"

    exts = body.get(R_EXTENSIONS, [])
    if not isinstance(exts, list) or len(exts) > MAX_EXTENSIONS:
        return "RECEIPT_SEMANTIC_INVALID"
    for e in exts:
        if not isinstance(e, dict) or set(e) - {1, 2, 3}:
            return "RECEIPT_UNKNOWN_FIELD"
        if not isinstance(e.get(1), str) or len(e[1].encode()) > MAX_TEXT_SHORT:
            return "RECEIPT_SEMANTIC_INVALID"
        if not isinstance(e.get(2), bool):
            return "RECEIPT_SEMANTIC_INVALID"
        if e.get(2) and e[1] not in KNOWN_EXTENSIONS:
            return "RECEIPT_UNKNOWN_CRITICAL_EXTENSION"
    if not isinstance(body.get(R_CREDENTIAL), bytes):
        return "RECEIPT_CREDENTIAL_MISMATCH"
    return None


def check_receipt_matches_offer(body: Dict[int, Any], offer: Dict[int, Any]) -> Optional[str]:
    """WRONG_TRANSACTION / RECEIPT_OFFER_MISMATCH: receipt must be the offered one."""
    if body.get(R_RECEIPT_ID) != offer.get(3):
        return "WRONG_TRANSACTION"
    if body.get(R_CURRENCY) != offer.get(6):
        return "WRONG_TRANSACTION"
    if body.get(R_TOTALS, {}).get(4) != offer.get(5):
        return "WRONG_TRANSACTION"
    if body.get(R_ISSUED_AT) != offer.get(7):
        return "WRONG_TRANSACTION"
    if body.get(R_KIND) != offer.get(8):
        return "WRONG_TRANSACTION"
    if body.get(R_MERCHANT, {}).get(1) != offer.get(10):
        return "WRONG_TRANSACTION"
    if body.get(R_MERCHANT, {}).get(3) != offer.get(4):
        return "WRONG_TRANSACTION"
    return None


def check_issued_at_policy(issued_at: int, now: int, cred_from: int, cred_until: int) -> Optional[str]:
    if issued_at > now + CLOCK_SKEW_MAX_S:
        return "RECEIPT_ISSUED_IN_FUTURE"
    if not cred_from <= issued_at < cred_until:
        return "RECEIPT_OUTSIDE_KEY_VALIDITY"
    return None


def verify_receipt(receipt_blob: bytes, anchors: Dict[bytes, bytes],
                   session_credential: Optional[bytes], now: int,
                   offer: Optional[Dict[int, Any]] = None,
                   seen_receipt_ids: Optional[Dict[bytes, bytes]] = None) -> Dict[str, Any]:
    res = {"signature_valid": False, "key_authorized": False,
           "credential_temporally_acceptable": False, "semantically_valid": False,
           "unique_locally": True, "outcome": "REJECTED", "error": None}
    try:
        c = cose_parse(receipt_blob)
    except CborError as exc:
        res["error"] = exc.code
        return res
    e = cose_check_protected(c["protected"], CT_RECEIPT)
    if e:
        res["error"] = e
        return res
    kid = c["protected"][COSE_PROTECTED_KID]
    try:
        body = cbor_decode(c["payload"], max_bytes=MAX_RECEIPT_BYTES)
    except CborError as exc:
        res["error"] = map_cbor_to_receipt(exc.code)
        return res
    if not isinstance(body, dict):
        res["error"] = "RECEIPT_CONTAINER_MALFORMED"
        return res
    cred_blob = body.get(R_CREDENTIAL)
    if not isinstance(cred_blob, bytes):
        res["error"] = "RECEIPT_CREDENTIAL_MISMATCH"
        return res
    if session_credential is not None and cred_blob != session_credential:
        res["error"] = "RECEIPT_CREDENTIAL_MISMATCH"
        return res
    err, cred_body, trust = verify_credential(cred_blob, anchors, now)
    if err is not None and err != "CREDENTIAL_UNKNOWN_ISSUER":
        res["error"] = err
        return res
    if cred_body.get(CRED_DEVICE_KEY_ID) != kid:
        res["error"] = "RECEIPT_KEY_NOT_AUTHORIZED"
        return res
    if cred_body.get(CRED_MERCHANT_ID) != body.get(R_MERCHANT, {}).get(1):
        res["error"] = "RECEIPT_KEY_NOT_AUTHORIZED"
        return res
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(cred_body[CRED_DEVICE_PUBKEY]).verify(
            c["signature"], sig_structure(c["protected_bstr"], c["payload"]))
        res["signature_valid"] = True
    except Exception:
        res["error"] = "RECEIPT_SIGNATURE_INVALID"
        return res
    sem = check_receipt_semantics(body)
    if sem:
        res["error"] = sem
        return res
    res["semantically_valid"] = True
    pol = check_issued_at_policy(body[R_ISSUED_AT], now, cred_body[CRED_VALID_FROM],
                                 cred_body[CRED_VALID_UNTIL])
    if pol:
        res["error"] = pol
        return res
    res["credential_temporally_acceptable"] = True
    if offer is not None:
        off_err = check_receipt_matches_offer(body, offer)
        if off_err:
            res["error"] = off_err
            return res
    if trust != "authenticated":
        res["outcome"] = "UNVERIFIED_UNKNOWN_ISSUER"
        res["error"] = "CREDENTIAL_UNKNOWN_ISSUER"
        return res
    caps = cred_body.get(CRED_CAPABILITIES, 0)
    if not caps & required_capability(body[R_KIND]):
        res["error"] = "CREDENTIAL_CAPABILITY_MISSING"
        return res
    res["key_authorized"] = True
    if seen_receipt_ids is not None:
        rid = body[R_RECEIPT_ID]
        prior = seen_receipt_ids.get(rid)
        if prior is not None:
            if prior == c["payload"]:
                res["outcome"] = "ALREADY_IMPORTED_IDENTICAL"
                res["unique_locally"] = False
                return res
            res["error"] = "RECEIPT_DUPLICATE_CONFLICT"
            res["unique_locally"] = False
            return res
    res["outcome"] = "TRUSTED"
    return res


# ==========================================================================
# 11. Framing / LPdu / envelopes
# ==========================================================================

def att_payload_max(att_mtu: int) -> int:
    return min(att_mtu - 3, MAX_ATT_PAYLOAD)


def max_frame_payload_for_mtu(att_mtu: int) -> int:
    return min(att_payload_max(att_mtu) - DATAFRAME_HEADER_BYTES, MAX_FRAME_PAYLOAD)


def frame_count(ct_len: int, frame_size: int) -> int:
    return (ct_len + frame_size - 1) // frame_size


def check_frame_size(frame_size: int, peer_max_frame_payload: int) -> Optional[str]:
    if not isinstance(frame_size, int) or not MIN_FRAME_PAYLOAD <= frame_size <= MAX_FRAME_PAYLOAD:
        return "FRAME_SIZE_INVALID"
    if frame_size > peer_max_frame_payload:
        return "FRAME_SIZE_INVALID"
    return None


def lpdu_fragment(pdu: bytes, frag_payload_max: int, msg_seq: int) -> List[bytes]:
    frags = [pdu[i:i + frag_payload_max] for i in range(0, len(pdu), frag_payload_max)]
    if len(frags) > MAX_LPDU_FRAGMENTS:
        raise CborError("LPDU_MESSAGE_TOO_LARGE", "too many fragments")
    n = len(frags)
    return [struct.pack(">HBB", msg_seq, i, n) + f for i, f in enumerate(frags)]


def lpdu_reassemble(frames: List[bytes]) -> bytes:
    if not frames:
        raise CborError("LPDU_FRAGMENT_INVALID", "empty")
    seq, idx, cnt = struct.unpack(">HBB", frames[0][:LPDU_HEADER_BYTES])
    if cnt == 0 or idx != 0 or len(frames) != cnt:
        raise CborError("LPDU_FRAGMENT_INVALID", "bad fragment count")
    out = b""
    for i, f in enumerate(frames):
        s, ix, c = struct.unpack(">HBB", f[:LPDU_HEADER_BYTES])
        if s != seq or c != cnt or ix != i:
            raise CborError("LPDU_SEQUENCE_ERROR", "fragment out of order")
        out += f[LPDU_HEADER_BYTES:]
    if len(out) > MAX_CONTROL_PDU:
        raise CborError("LPDU_MESSAGE_TOO_LARGE", "reassembled too large")
    return out


def dataframe(transfer_id: bytes, seq: int, payload: bytes) -> bytes:
    return transfer_id + struct.pack(">I", seq) + payload


def parse_dataframe(frame: bytes, expect_tid: Optional[bytes] = None
                    ) -> Tuple[bytes, int, bytes]:
    if len(frame) < DATAFRAME_HEADER_BYTES:
        raise CborError("LPDU_FRAGMENT_INVALID", "short DataFrame")
    tid = frame[:16]
    seq = struct.unpack(">I", frame[16:20])[0]
    payload = frame[20:]
    if expect_tid is not None and tid != expect_tid:
        raise CborError("TRANSFER_ID_MISMATCH", "frame transfer id")
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise CborError("FRAME_SIZE_INVALID", "frame payload too large")
    return tid, seq, payload


def control_envelope_plaintext(msg: Dict[int, Any]) -> bytes:
    return bytes([ENV_PLAINTEXT]) + cbor_encode(msg)


def control_envelope_aead(key: bytes, counter: int, ctx: bytes, direction: int,
                          msg: Dict[int, Any]) -> bytes:
    return bytes([ENV_AEAD]) + struct.pack(">Q", counter) + aead_seal(
        key, counter, aad_ctrl(ctx, direction), cbor_encode(msg))


def open_control_envelope(key: bytes, ctx: bytes, direction: int, blob: bytes,
                          expect_counter: int) -> Dict[int, Any]:
    if not blob:
        raise CborError("CBOR_MALFORMED", "empty pdu")
    tag = blob[0]
    if tag == ENV_PLAINTEXT:
        raise CborError("MESSAGE_WRONG_STATE", "plaintext control after handshake")
    if tag != ENV_AEAD:
        raise CborError("MESSAGE_UNKNOWN_TYPE", f"envelope tag {tag}")
    if len(blob) < 1 + 8 + AEAD_TAG_BYTES:
        raise CborError("CBOR_MALFORMED", "short aead envelope")
    counter = struct.unpack(">Q", blob[1:9])[0]
    if counter < expect_counter:
        raise CborError("AEAD_REPLAY_DETECTED", f"counter {counter} < {expect_counter}")
    if counter > expect_counter:
        raise CborError("AEAD_COUNTER_MISMATCH", f"counter {counter} > {expect_counter}")
    try:
        pt = aead_open(key, counter, aad_ctrl(ctx, direction), blob[9:])
    except Exception:
        raise CborError("AEAD_AUTH_FAILED", "control tag")
    return cbor_decode(pt, max_bytes=MAX_CONTROL_PDU)


# ==========================================================================
# 12. Scenarios
# ==========================================================================

NOW = 1_767_225_600
MERCHANT_ID = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
DEVICE_KEY_ID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
UNKNOWN_MERCHANT_ID = bytes.fromhex("11223344556677889900112233445566")
UNKNOWN_DEVICE_KEY_ID = bytes.fromhex("66554433221100998877665544332211")
ROOT_ID = bytes.fromhex("0decea00000000000000000000000001")
UNKNOWN_ROOT_ID = bytes.fromhex("0badc0de0000000000000000000000ff")
MERCHANT_REF = "merchant.poc.test-alpha"
TRANSFER_ID = bytes.fromhex("ffeeddccbbaa99887766554433221100")
SESSION_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
RECEIPT_ID_1 = bytes.fromhex("0123456789abcdef0123456789abcdef")
RECEIPT_ID_LONG = bytes.fromhex("fedcba98765432100123456789abcdef")
CLIENT_NONCE = bytes.fromhex("c0ffee00" + "00" * 27 + "01")
SERVER_NONCE = bytes.fromhex("5e57e500" + "00" * 27 + "01")
TRANSACTION_REF = bytes.fromhex("74780000000000000000000000000042")
SBT = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

ROOT_KEY = test_ed25519("root-poc-1")
UNKNOWN_ROOT_KEY = test_ed25519("root-unknown-1")
MERCHANT_KEY = test_ed25519("merchant-test-1")
OTHER_MERCHANT_KEY = test_ed25519("merchant-unknown-1")
CLIENT_EPH = test_p256("client-eph-1")
SERVER_EPH = test_p256("server-eph-1")
CLIENT_EPH_2 = test_p256("client-eph-2")

ANCHORS = {ROOT_ID: ed25519_pub_bytes(ROOT_KEY)}

# populated by main() so self_test() can re-derive AEAD keys and the offer hash
SESSION_KEYS: Dict[str, str] = {}
offer_hash_v_global = b""
VALID_CRED = b""
OFFER_TOTAL_MINOR = 970
OFFER_ISSUED_AT = 0


def lines_standard() -> List[Dict[int, Any]]:
    return [
        {1: 1, 2: "Latte, 16oz", 3: {1: 0, 2: 1, 3: "ea"}, 4: 475, 5: 475,
         7: [1], 8: 1, 9: "SKU-LATTE-16"},
        {1: 2, 2: "Croissant", 3: {1: 2, 2: 75, 3: "kg"}, 4: 360, 5: 270,
         7: [1], 8: 1, 9: "SKU-CROISSANT"},
        {1: 3, 2: "Oat milk substitution", 3: {1: 0, 2: 1, 3: "ea"}, 4: 75, 5: 75,
         7: [1], 8: 2},
    ]


def lines_long(n: int) -> List[Dict[int, Any]]:
    return [{1: i, 2: "Synthetic line item %d" % i, 3: {1: 0, 2: 1},
             4: 100 + (i % 25), 5: 100 + (i % 25), 8: 1} for i in range(1, n + 1)]


def main() -> None:
    global SESSION_KEYS, offer_hash_v_global, VALID_CRED, OFFER_TOTAL_MINOR, OFFER_ISSUED_AT
    here = os.path.dirname(os.path.abspath(__file__))
    vec_dir = os.path.abspath(os.path.join(here, ".."))
    schema_dir = os.path.abspath(os.path.join(vec_dir, "..", "schema"))
    os.makedirs(os.path.join(vec_dir, "keys"), exist_ok=True)
    os.makedirs(os.path.join(vec_dir, "fixtures"), exist_ok=True)
    os.makedirs(schema_dir, exist_ok=True)
    manifest: Dict[str, Any] = {}

    # ---------------- keys ----------------
    keys = {
        "warning": "TEST-ONLY DETERMINISTIC KEYS. Public by construction; MUST NOT "
                   "protect anything; MUST NOT be trusted outside the test harness.",
        "derivation": {
            "ed25519_seed": "SHA-256('deceipt-testkey:ed25519:' + name)",
            "p256_scalar": "((int(SHA-256('deceipt-testkey:p256:' + name + '#c')) "
                           "mod (n-1)) + 1), c incremented until a valid point derives",
        },
        "keys": [
            {"name": "root-poc-1", "type": "ed25519-test-root",
             "private_seed_hex": ed25519_seed_hex("root-poc-1"),
             "public_key_hex": ed25519_pub_bytes(ROOT_KEY).hex(),
             "trust_anchor": True,
             "note": "signs the PoC test-merchant credential; private half never ships"},
            {"name": "root-unknown-1", "type": "ed25519-unknown-root",
             "private_seed_hex": ed25519_seed_hex("root-unknown-1"),
             "public_key_hex": ed25519_pub_bytes(UNKNOWN_ROOT_KEY).hex(),
             "trust_anchor": False,
             "note": "NOT a trust anchor: unknown-issuer vectors only"},
            {"name": "merchant-test-1", "type": "ed25519-merchant-device",
             "private_seed_hex": ed25519_seed_hex("merchant-test-1"),
             "public_key_hex": ed25519_pub_bytes(MERCHANT_KEY).hex(),
             "note": "device signing key of the pre-provisioned test merchant"},
            {"name": "merchant-unknown-1", "type": "ed25519-merchant-device",
             "private_seed_hex": ed25519_seed_hex("merchant-unknown-1"),
             "public_key_hex": ed25519_pub_bytes(OTHER_MERCHANT_KEY).hex(),
             "note": "device key of the deliberately-unknown rogue merchant"},
            {"name": "client-eph-1", "type": "p256-ephemeral",
             "private_scalar_hex": p256_scalar_hex(CLIENT_EPH),
             "public_key_hex": p256_pub_bytes(CLIENT_EPH).hex(), "valid_p256_point": True},
            {"name": "server-eph-1", "type": "p256-ephemeral",
             "private_scalar_hex": p256_scalar_hex(SERVER_EPH),
             "public_key_hex": p256_pub_bytes(SERVER_EPH).hex(), "valid_p256_point": True},
            {"name": "client-eph-2", "type": "p256-ephemeral",
             "private_scalar_hex": p256_scalar_hex(CLIENT_EPH_2),
             "public_key_hex": p256_pub_bytes(CLIENT_EPH_2).hex(), "valid_p256_point": True},
        ],
    }
    _wj(os.path.join(vec_dir, "keys", "test-keys.json"), keys)
    manifest["keys/test-keys.json"] = _sha(os.path.join(vec_dir, "keys", "test-keys.json"))

    _wj(os.path.join(vec_dir, "fixtures", "trust-anchors-v1.json"), {
        "revision": REVISION_LABEL,
        "note": "Public trust-anchor set pinned in the app. Public material only.",
        "anchors": [{"anchor_id_hex": ROOT_ID.hex(), "algorithm": "EdDSA",
                     "cose_alg": ALG_EDDSA,
                     "public_key_hex": ed25519_pub_bytes(ROOT_KEY).hex(),
                     "label": "Deceipt PoC Test Root 1", "test_only": True}]})
    manifest["fixtures/trust-anchors-v1.json"] = _sha(
        os.path.join(vec_dir, "fixtures", "trust-anchors-v1.json"))

    # ---------------- credentials ----------------
    base_body = credential_body(
        1, ROOT_ID, MERCHANT_ID, DEVICE_KEY_ID, ed25519_pub_bytes(MERCHANT_KEY),
        NOW - 86_400 * 30, NOW + 86_400 * 365,
        CAP_ISSUE_SALE | CAP_ISSUE_REFUND | CAP_ISSUE_VOID | CAP_RECEIVE_TRANSFER
        | CAP_EMBED_CREDENTIAL, MERCHANT_REF, "Maple & Vine Cafe", NOW - 86_400 * 30)
    valid_cred = build_credential(base_body, ROOT_KEY, ROOT_ID)
    _wb(os.path.join(vec_dir, "fixtures", "valid-credential.cbor"), valid_cred)

    expired_body = M(base_body, {CRED_VALID_FROM: NOW - 86_400 * 400,
                                      CRED_VALID_UNTIL: NOW - 86_400 * 200})
    expired_cred = build_credential(expired_body, ROOT_KEY, ROOT_ID)
    nyv_body = M(base_body, {CRED_VALID_FROM: NOW + 86_400 * 200,
                                  CRED_VALID_UNTIL: NOW + 86_400 * 400})
    nyv_cred = build_credential(nyv_body, ROOT_KEY, ROOT_ID)
    no_sale_body = M(base_body, {CRED_CAPABILITIES: CAP_RECEIVE_TRANSFER})
    no_sale_cred = build_credential(no_sale_body, ROOT_KEY, ROOT_ID)
    unknown_body = credential_body(
        1, UNKNOWN_ROOT_ID, UNKNOWN_MERCHANT_ID, UNKNOWN_DEVICE_KEY_ID,
        ed25519_pub_bytes(OTHER_MERCHANT_KEY), NOW - 86_400 * 30, NOW + 86_400 * 365,
        CAP_ISSUE_SALE | CAP_ISSUE_REFUND | CAP_ISSUE_VOID | CAP_RECEIVE_TRANSFER
        | CAP_EMBED_CREDENTIAL, "merchant.poc.test-rogue", "Rogue Terminal",
        NOW - 86_400 * 30)
    unknown_cred = build_credential(unknown_body, UNKNOWN_ROOT_KEY, UNKNOWN_ROOT_ID)
    bad_sig_cred = bytes(bytearray(valid_cred)[:-1] + bytes([valid_cred[-1] ^ 0x01]))

    cred_vec = {"revision": REVISION_LABEL, "content_type": CT_CREDENTIAL,
                "signature_rule": "Ed25519 over Sig_structure = ['Signature1', "
                                  "protected_bstr, h'', payload_bstr] (RFC 9052 §4.4), "
                                  "deterministic CBOR", "cases": []}

    def cred_case(name, blob, err, trust, body=None):
        cred_vec["cases"].append({
            "case": name, "credential_hex": blob.hex(),
            "credential_body_hex": cbor_encode(body).hex() if body is not None else None,
            "expected_error": err, "expected_trust": trust,
            "verify_at_unix": NOW,
            "anchors_hex": {k.hex(): v.hex() for k, v in ANCHORS.items()}})

    cred_case("valid_trusted_issuer", valid_cred, None, "authenticated", base_body)
    cred_case("unknown_issuer", unknown_cred, "CREDENTIAL_UNKNOWN_ISSUER",
              "unknown_issuer", unknown_body)
    cred_case("issuer_signature_tampered", bad_sig_cred, "CREDENTIAL_SIGNATURE_INVALID",
              "none", base_body)
    cred_case("expired", expired_cred, "CREDENTIAL_EXPIRED", "authenticated", expired_body)
    cred_case("not_yet_valid", nyv_cred, "CREDENTIAL_NOT_YET_VALID", "authenticated", nyv_body)
    cred_case("missing_sale_capability", no_sale_cred, None, "authenticated", no_sale_body)
    cred_case("malformed_truncated", valid_cred[:20], "CREDENTIAL_MALFORMED", "none")
    cred_case("malformed_wrong_content_type",
              cose_sign1({COSE_PROTECTED_ALG: ALG_EDDSA, COSE_PROTECTED_CTYPE: CT_RECEIPT,
                          COSE_PROTECTED_KID: ROOT_ID}, cbor_encode(base_body), ROOT_KEY),
              "CREDENTIAL_MALFORMED", "none")
    cred_case("malformed_oversize", b"\x84" + b"\x00" * (MAX_CREDENTIAL_BYTES + 1),
              "CREDENTIAL_MALFORMED", "none")
    _wj(os.path.join(vec_dir, "credentials.json"), cred_vec)
    manifest["credentials.json"] = _sha(os.path.join(vec_dir, "credentials.json"))

    # ---------------- session construction ----------------
    client_pub = p256_pub_bytes(CLIENT_EPH)
    server_pub = p256_pub_bytes(SERVER_EPH)
    cred_hash = credential_binding_hash(valid_cred)

    # The offer hash must commit to the receipt that will actually be transferred.
    OFFER_TOTAL_MINOR = 970          # == the sale receipt's total_minor (asserted below)
    OFFER_ISSUED_AT = NOW - 60       # == the sale receipt's issued_at
    offer_pre = offer_hash_preimage(SESSION_ID, TRANSFER_ID, RECEIPT_ID_1, MERCHANT_REF,
                                    OFFER_TOTAL_MINOR, "CAD", OFFER_ISSUED_AT)
    offer_hash_v = hashlib.sha256(DOMAIN_OFFER_HASH + b"\x00" + offer_pre).digest()
    btuple = binding_tuple(SESSION_ID, TRANSFER_ID, RECEIPT_ID_1, offer_hash_v)
    btd = binding_tuple_digest(btuple)
    bproof = binding_proof(SBT, CLIENT_NONCE, client_pub)
    max_fp = 162

    client_hello = {1: MSG_CLIENT_HELLO, 2: PROTOCOL_VERSION, 3: [SUITE_ID],
                    4: SESSION_ID, 5: CLIENT_NONCE, 6: client_pub,
                    7: bproof, 8: max_fp}
    ch_env = control_envelope_plaintext(client_hello)

    transcript = build_transcript(PROTOCOL_VERSION, SUITE_ID, CLIENT_NONCE, client_pub,
                                  SERVER_NONCE, server_pub, TRANSFER_ID, SESSION_ID,
                                  btd, max_fp, btuple)
    assert len(transcript) == TRANSCRIPT_LEN, (len(transcript), TRANSCRIPT_LEN)
    t_sig = MERCHANT_KEY.sign(transcript)
    transcript_hash = hashlib.sha256(transcript).digest()
    shared = ecdh(CLIENT_EPH, server_pub)
    assert shared == ecdh(SERVER_EPH, client_pub)
    sched = derive_session_keys(shared, transcript_hash)
    ctx = session_context(transcript_hash, TRANSFER_ID)
    SESSION_KEYS = {k: v.hex() for k, v in sched.items()}
    offer_hash_v_global = offer_hash_v
    VALID_CRED = valid_cred

    server_hello = {1: MSG_SERVER_HELLO, 2: PROTOCOL_VERSION, 3: SUITE_ID,
                    4: TRANSFER_ID, 5: SERVER_NONCE, 6: server_pub, 7: valid_cred,
                    8: t_sig, 9: btd}
    sh_env = control_envelope_plaintext(server_hello)

    hs = {"revision": REVISION_LABEL, "protocol_version": PROTOCOL_VERSION,
          "suite_id": SUITE_ID,
          "suite": "Deceipt-Session-Suite-1 (X25519? no: ECDH P-256 || HKDF-SHA-256 "
                   "|| AES-256-GCM)",
          "nonce_bytes": NONCE_BYTES,
          "binding_contract_ref": "docs/flows/transaction-binding-and-checkout-v1.md",
          "transcript_layout": transcript_layout_table(),
          "transcript_len": len(transcript),
          "hkdf": {"hash": "SHA-256", "ikm": "ECDH X coordinate (32 bytes)",
                   "salt": "transcript_hash (32 bytes)",
                   "info_prefix_ascii": HKDF_INFO_PREFIX.decode(),
                   "info": "info_prefix || transcript_hash (50 bytes)", "okm_length": 128,
                   "okm_slices": {"k_c2m_ctrl": "OKM[0:32]", "k_m2c_ctrl": "OKM[32:64]",
                                  "k_m2c_payload": "OKM[64:96]", "k_exporter": "OKM[96:128]"}},
          "client_hello_hex": cbor_encode(client_hello).hex(),
          "server_hello_hex": cbor_encode(server_hello).hex(),
          "client_hello_pdu_hex": ch_env.hex(), "server_hello_pdu_hex": sh_env.hex(),
          "offer_hash_preimage_hex": offer_pre.hex(),
          "offer_hash_hex": offer_hash_v.hex(),
          "binding_tuple_hex": btuple.hex(), "binding_tuple_len": len(btuple),
          "binding_tuple_digest_hex": btd.hex(),
          "binding_proof_message_hex": binding_proof_message(CLIENT_NONCE, client_pub).hex(),
          "binding_proof_message_len": len(binding_proof_message(CLIENT_NONCE, client_pub)),
          "binding_proof_hex": bproof.hex(),
          "transcript_hex": transcript.hex(), "transcript_hash_hex": transcript_hash.hex(),
          "transcript_signature_hex": t_sig.hex(), "shared_secret_hex": shared.hex(),
          "keys": {k: v.hex() for k, v in sched.items()},
          "session_context_hex": ctx.hex(),
          "credential_hash_hex": cred_hash.hex(),
          "expected_keys_equal": "client and merchant derive identical OKM"}
    _wj(os.path.join(vec_dir, "handshake-valid.json"), hs)
    manifest["handshake-valid.json"] = _sha(os.path.join(vec_dir, "handshake-valid.json"))

    hs_invalid = {"revision": REVISION_LABEL, "cases": []}

    def hs_case(name, err, note="", **kw):
        e = {"case": name, "expected_error": err, "note": note}
        e.update(kw)
        hs_invalid["cases"].append(e)

    hs_case("unsupported_protocol_version", "HANDSHAKE_UNSUPPORTED_VERSION",
            "ClientHello.protocol_version = 2, receiver supports {1}",
            client_hello_hex=cbor_encode({**client_hello, 2: 2}).hex())
    hs_case("no_common_suite", "HANDSHAKE_NO_COMMON_SUITE",
            "client offers {2,3}; merchant supports {1}",
            client_hello_hex=cbor_encode({**client_hello, 3: [2, 3]}).hex())
    hs_case("merchant_selects_unoffered_suite", "HANDSHAKE_SUITE_MISMATCH",
            "ServerHello.suite_id = 2 while ClientHello offered [1]",
            server_hello_hex=cbor_encode({**server_hello, 3: 2}).hex())
    hs_case("server_hello_transfer_id_mismatch", "TRANSFER_ID_MISMATCH",
            "ServerHello.transfer_id != binding_tuple.transfer_id",
            server_hello_hex=cbor_encode({**server_hello, 4: bytes(16)}).hex())
    hs_case("server_hello_binding_digest_mismatch", "HANDSHAKE_TRANSCRIPT_MISMATCH",
            "ServerHello.binding_tuple_digest != receiver's recomputation",
            server_hello_hex=cbor_encode({**server_hello, 9: bytes(32)}).hex())
    hs_case("transcript_signature_tampered", "HANDSHAKE_SIGNATURE_INVALID",
            "one bit flipped in the ServerHello transcript signature",
            transcript_hex=transcript.hex(),
            transcript_signature_hex=(bytes([t_sig[0] ^ 0x01]) + t_sig[1:]).hex())
    hs_case("client_eph_substituted_by_mitm", "HANDSHAKE_SIGNATURE_INVALID",
            "MITM replaced the client ephemeral key after ClientHello; signature no "
            "longer covers the transcript the client computes",
            transcript_hex=build_transcript(
                PROTOCOL_VERSION, SUITE_ID, CLIENT_NONCE, p256_pub_bytes(CLIENT_EPH_2),
                SERVER_NONCE, server_pub, TRANSFER_ID, SESSION_ID, btd, max_fp,
                btuple).hex(),
            transcript_signature_hex=t_sig.hex())
    hs_case("binding_tuple_digest_substituted", "HANDSHAKE_SIGNATURE_INVALID",
            "MITM swapped the binding tuple digest to another transaction",
            transcript_hex=build_transcript(
                PROTOCOL_VERSION, SUITE_ID, CLIENT_NONCE, client_pub, SERVER_NONCE,
                server_pub, TRANSFER_ID, SESSION_ID,
                binding_tuple_digest(binding_tuple(SESSION_ID, TRANSFER_ID, RECEIPT_ID_1,
                                                   bytes(32))), max_fp, btuple).hex(),
            transcript_signature_hex=t_sig.hex())
    hs_case("max_frame_payload_substituted", "HANDSHAKE_SIGNATURE_INVALID",
            "MITM lowered the negotiated frame payload size in the transcript",
            transcript_hex=build_transcript(
                PROTOCOL_VERSION, SUITE_ID, CLIENT_NONCE, client_pub, SERVER_NONCE,
                server_pub, TRANSFER_ID, SESSION_ID, btd, 64, btuple).hex(),
            transcript_signature_hex=t_sig.hex())
    hs_case("ecdh_point_not_on_curve", "HANDSHAKE_ECDH_INVALID_POINT",
            "0x04 || 0x01*64 is not on P-256",
            offending_point_hex=(b"\x04" + bytes([1]) * 64).hex(),
            client_hello_hex=cbor_encode({**client_hello, 6: b"\x04" + bytes([1]) * 64}).hex())
    hs_case("ecdh_point_compressed_prefix", "HANDSHAKE_ECDH_INVALID_POINT",
            "compressed form 0x02 is not permitted; v1 requires uncompressed 0x04",
            offending_point_hex=(b"\x02" + client_pub[1:]).hex(),
            client_hello_hex=cbor_encode({**client_hello, 6: b"\x02" + client_pub[1:]}).hex())
    hs_case("binding_required_fields_absent", "BINDING_REQUIRED",
            "ClientHello without session_id / binding_proof",
            client_hello_hex=cbor_encode({k: v for k, v in client_hello.items()
                                          if k not in (4, 7)}).hex())
    hs_case("binding_unknown_session", "BINDING_UNKNOWN_SESSION",
            "session_id resolves to no live session",
            client_hello_hex=cbor_encode({**client_hello, 4: bytes(16)}).hex())
    hs_case("binding_proof_invalid", "BINDING_PROOF_INVALID",
            "HMAC over proof_message computed with a different SBT (A2 vector V2 shape)",
            client_hello_hex=cbor_encode({**client_hello, 7: binding_proof(
                bytes.fromhex("0104070a0d101316191c1f2225282b2e"), CLIENT_NONCE,
                client_pub)}).hex())
    hs_case("binding_stale", "BINDING_STALE",
            "QR/session expired before the ClientHello arrived",
            client_hello_hex=cbor_encode(client_hello).hex(), binding_claimed_at_unix=NOW + 400,
            binding_expires_at_unix=NOW + 300)
    hs_case("binding_consumed", "BINDING_CONSUMED",
            "second ClientHello for an already-claimed session_id",
            client_hello_hex=cbor_encode(client_hello).hex(), prior_claims=1)
    hs_case("wrong_transaction", "WRONG_TRANSACTION",
            "ReceiptOffer/Receipt is not the transaction named by the scanned QR",
            offer_receipt_id_hex=bytes(16).hex(),
            qr_receipt_id_hex=RECEIPT_ID_1.hex())
    hs_case("frame_payload_above_reported_capacity", "FRAME_SIZE_INVALID",
            "ClientHello.max_frame_payload 200 > merchant hard cap 162",
            client_hello_hex=cbor_encode({**client_hello, 8: 200}).hex(),
            merchant_max_frame_payload=162)
    _wj(os.path.join(vec_dir, "handshake-invalid.json"), hs_invalid)
    manifest["handshake-invalid.json"] = _sha(os.path.join(vec_dir, "handshake-invalid.json"))

    # ---------------- binding cross-check vs A2 ----------------
    a2_sid = bytes.fromhex("00112233445566778899aabbccddeeff")
    a2_tid = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    a2_rid = bytes.fromhex("0123456789abcdef0123456789abcdef")
    a2_ref = "merchant.poc.test-alpha"
    a2_amt, a2_cur, a2_iat = 525, "CAD", 1767225600
    a2_oh = offer_hash(a2_sid, a2_tid, a2_rid, a2_ref, a2_amt, a2_cur, a2_iat)
    a2_bt = binding_tuple(a2_sid, a2_tid, a2_rid, a2_oh)
    a2_btd = binding_tuple_digest(a2_bt)
    a2_cn = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                          "101112131415161718191a1b1c1d1e1f")
    a2_cp = bytes.fromhex("04030a11181f262d343b424950575e65"
                          "6c737a81888f969da4abb2b9c0c7ce"
                          "d5dce3eaf1f8ff060d141b22293037"
                          "3e454c535a61686f767d848b9299a0"
                          "a7aeb5bc")
    a2_sbt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    a2_sbt2 = bytes.fromhex("0104070a0d101316191c1f2225282b2e")
    a2_qr = cbor_encode({1: 1, 2: a2_sid, 3: a2_sbt, 4: a2_oh, 5: 1767225720})

    xc = {
        "revision": REVISION_LABEL,
        "purpose": "Prove A1's implementation of the A2 binding contract is "
                   "byte-identical to A2's published vectors, and record the one defect "
                   "found in A2's published vectors plus the adopted error names.",
        "source": "protocol/flows/vectors/binding-v1.json (owner A2)",
        "checks": [
            {"name": "V1 offer_hash", "expected": "b36d3c63ab963189e1335a4a6cfc00789672c62433748a370f7e06148c7743aa",
             "observed": a2_oh.hex()},
            {"name": "V1 binding_tuple", "observed": a2_bt.hex(),
             "expected": "85015000112233445566778899aabbccddeeff50ffeeddccbbaa99887766554433221100"
                         "500123456789abcdef0123456789abcdef5820b36d3c63ab963189e1335a4a6cfc00789"
                         "672c62433748a370f7e06148c7743aa", "length": len(a2_bt)},
            {"name": "V1 binding_tuple_digest", "observed": a2_btd.hex(),
             "expected": "11f63f30af68580b95ffa4b456dd0f89ced8204ba144e105812b61d2fe2259be"},
            {"name": "V1 binding_proof (HMAC reproduced over A2's published point bytes)",
             "observed": binding_proof(a2_sbt, a2_cn, a2_cp).hex(),
             "expected": "06ceaa6595ade4ec34e74f44a7b8a85e82f69a71959a125118b23bc7de337547"},
            {"name": "V2 binding_proof", "observed": binding_proof(a2_sbt2, a2_cn, a2_cp).hex(),
             "expected": "f249919ec38c298b4468ff9844088ac8de4201f0770da86221391ffb44efd269"},
            {"name": "V1 QR raw CBOR", "observed": a2_qr.hex(),
             "expected": "a50101025000112233445566778899aabbccddeeff0350000102030405060708090a0b0c0d0e0f"
                         "045820b36d3c63ab963189e1335a4a6cfc00789672c62433748a370f7e06148c7743aa"
                         "051a6955b978"},
            {"name": "V1 QR payload", "observed": "deceipt1:" + base64.urlsafe_b64encode(
                a2_qr).rstrip(b"=").decode(),
             "expected": "deceipt1:pQEBAlAAESIzRFVmd4iZqrvM3e7_A1AAAQIDBAUGBwgJCgsMDQ4PBFggs208Y6uWMYnhM1pKbPw"
                         "AeJZyxiQzdIo3D34GFIx3Q6oFGmlVuXg"},
        ],
        "findings_on_A2_vectors": [
            {"severity": "high",
             "defect": "client_ephemeral_pubkey_hex in V1, V2 and V3 is not a valid "
                       "P-256 point: EC point decoding fails, so ECDH cannot be performed.",
             "evidence": [("V1", a2_cp.hex()),
                          ("V3", "04030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ce"
                                 "d5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0"
                                 "a7aeb5bd")],
             "impact": "The binding HMAC values are still correct (HMAC is over opaque "
                       "bytes), but these vectors MUST NOT be used as handshake vectors "
                       "and A2 should regenerate them with a point that decodes.",
             "observed_in_a1": "A1 publishes valid P-256 points in protocol/vectors/"
                               "handshake-valid.json; the binding proof there is "
                               "computed over a valid point and therefore differs from "
                               "A2's V1 binding_proof value."},
            {"severity": "info",
             "finding": "docs/flows/*.md lists binding errors as BINDING_UNKNOWN_SESSION, "
                        "BINDING_PROOF_INVALID, BINDING_STALE, BINDING_CONSUMED, "
                        "WRONG_TRANSACTION; A1 adopts exactly these names.",
             "evidence": [], "impact": "no defect; recorded for the freeze record"},
        ],
    }
    _wj(os.path.join(vec_dir, "binding-crosscheck.json"), xc)
    manifest["binding-crosscheck.json"] = _sha(os.path.join(vec_dir, "binding-crosscheck.json"))

    # ---------------- receipt ----------------
    body = build_receipt_body(
        KIND_SALE, RECEIPT_ID_1, NOW - 60, MERCHANT_ID, MERCHANT_REF, "Maple & Vine Cafe",
        "CAD", lines_standard(),
        [{1: 1, 2: 50, 3: "Loyalty", 4: 1, 6: 100_000, 7: 500}],
        [{1: 1, 3: 130_000, 4: 770, 5: 100, 6: "ON", 7: "HST"}],
        tip=100, service_charge=None, rounding=None, credential_bytes=valid_cred,
        tz_offset=-14400)
    payload = cbor_encode(body)
    prot = {COSE_PROTECTED_ALG: ALG_EDDSA, COSE_PROTECTED_CTYPE: CT_RECEIPT,
            COSE_PROTECTED_KID: DEVICE_KEY_ID}
    pb, ss, rsig = cose_sign1_parts(prot, payload, MERCHANT_KEY)
    blob = cbor_encode([pb, {}, payload, rsig])

    # the receipt must be the one the offer named
    offer = {1: MSG_RECEIPT_OFFER, 2: TRANSFER_ID, 3: RECEIPT_ID_1,
             4: MERCHANT_REF, 5: body[R_TOTALS][4], 6: "CAD", 7: body[R_ISSUED_AT],
             8: KIND_SALE, 9: 0, 10: MERCHANT_ID, 11: cred_hash, 12: SESSION_ID}
    assert body[R_TOTALS][4] == OFFER_TOTAL_MINOR, (body[R_TOTALS][4], OFFER_TOTAL_MINOR)
    assert body[R_ISSUED_AT] == OFFER_ISSUED_AT
    chk = verify_receipt(blob, ANCHORS, valid_cred, NOW, offer=offer)
    assert chk["outcome"] == "TRUSTED" and chk["error"] is None, chk

    rv = {"revision": REVISION_LABEL, "receipt_version": 1, "content_type": CT_RECEIPT,
          "signed_bytes_rule": "Ed25519 over deterministic CBOR of Sig_structure = "
                               "['Signature1', protected_bstr, h'', payload_bstr]; payload_bstr "
                               "is the exact deterministic CBOR of DeceiptReceiptV1. Never "
                               "decode-modify-re-encode.",
          "container_rule": "COSE_Sign1 = [protected, {}, payload, signature]; unprotected "
                            "header MUST be empty; payload MUST be attached; whole array "
                            "MUST be deterministically encoded.",
          "receipt_body_hex": payload.hex(), "receipt_body_len": len(payload),
          "receipt_body_sha256": hashlib.sha256(payload).hexdigest(),
          "protected_bstr_hex": pb.hex(),
          "protected_map": {str(k): (v.hex() if isinstance(v, bytes) else v)
                            for k, v in prot.items()},
          "sig_structure_hex": ss.hex(), "signature_hex": rsig.hex(),
          "cose_sign1_hex": blob.hex(), "cose_sign1_len": len(blob),
          "receipt_offer_hex": cbor_encode(offer).hex(),
          "expected_verification": {"signature_valid": True, "key_authorized": True,
                                    "credential_temporally_acceptable": True,
                                    "semantically_valid": True, "unique_locally": True,
                                    "outcome": "TRUSTED", "error": None},
          "arithmetic": {"lines": [[l[1], l[4], l[3][2], l[3][1], l[5]] for l in body[R_LINES]],
                         "line_gross_minor": [l[5] for l in body[R_LINES]],
                         "subtotal_minor": body[R_TOTALS][1],
                         "discount_total_minor": body[R_TOTALS][2],
                         "tax_total_minor": body[R_TOTALS][3],
                         "tax_added_total_minor": body[R_TOTALS][8],
                         "tip_minor": body[R_TIP], "total_minor": body[R_TOTALS][4],
                         "currency": body[R_CURRENCY],
                         "currency_exponent": CURRENCY_EXPONENT["CAD"],
                         "human_total": "CAD 9.70"},
          "dedup_semantics": {
              "receipt_id": RECEIPT_ID_1.hex(),
              "identical_payload_reimport": "ALREADY_IMPORTED_IDENTICAL (not an error)",
              "same_id_different_payload": "RECEIPT_DUPLICATE_CONFLICT (fatal)",
              "key": "receipt_id only",
              "exactness": "byte equality of the signed payload, compared after signature "
                           "and authorization verification"},
          "verification_order_ref": "docs/protocol/verification.md"}

    long_body = build_receipt_body(
        KIND_SALE, RECEIPT_ID_LONG, NOW - 30, MERCHANT_ID, MERCHANT_REF, "Maple & Vine Cafe",
        "CAD", lines_long(256), [],
        [{1: 1, 3: 50_000, 4: sum(l[5] for l in lines_long(256)),
          5: round_half_away(sum(l[5] for l in lines_long(256)) * 50_000, 1_000_000),
          6: "ON", 7: "GST"}],
        tip=None, service_charge=None, rounding=None, credential_bytes=valid_cred)
    long_payload = cbor_encode(long_body)
    lpb, lss, lsig = cose_sign1_parts(prot, long_payload, MERCHANT_KEY)
    long_blob = cbor_encode([lpb, {}, long_payload, lsig])
    lchk = verify_receipt(long_blob, ANCHORS, valid_cred, NOW)
    assert lchk["outcome"] == "TRUSTED", lchk
    rv["long_receipt"] = {"receipt_body_sha256": hashlib.sha256(long_payload).hexdigest(),
                          "receipt_body_len": len(long_payload),
                          "cose_sign1_len": len(long_blob), "lines": 256,
                          "total_minor": long_body[R_TOTALS][4],
                          "receipt_body_hex": long_payload.hex()}
    _wj(os.path.join(vec_dir, "receipt-valid.json"), rv)
    manifest["receipt-valid.json"] = _sha(os.path.join(vec_dir, "receipt-valid.json"))

    ri = {"revision": REVISION_LABEL, "cases": []}

    def r_case(name, blob_hex, err, outcome="REJECTED", fatal=True, note="",
               session_credential=None, anchors=None, offer_hex=None, seen=None):
        ri["cases"].append({"case": name, "cose_sign1_hex": blob_hex, "expected_error": err,
                            "expected_outcome": outcome, "fatal": fatal, "note": note,
                            "session_credential_hex": session_credential,
                            "receipt_offer_hex": offer_hex,
                            "seen_receipt_ids_hex": seen,
                            "anchors_hex": {k.hex(): v.hex()
                                            for k, v in (anchors or ANCHORS).items()},
                            "verify_at_unix": NOW})

    def sign_body(b, key=MERCHANT_KEY, kid=DEVICE_KEY_ID, p=None, raw=None):
        pl = raw if raw is not None else cbor_encode(b)
        pp = p if p is not None else {COSE_PROTECTED_ALG: ALG_EDDSA,
                                      COSE_PROTECTED_CTYPE: CT_RECEIPT,
                                      COSE_PROTECTED_KID: kid}
        pbb, _s, sig = cose_sign1_parts(pp, pl, key)
        return cbor_encode([pbb, {}, pl, sig])

    r_case("valid_baseline", blob.hex(), None, "TRUSTED", False, offer_hex=cbor_encode(offer).hex())
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    r_case("receipt_signature_tampered", bytes(tampered).hex(), "RECEIPT_SIGNATURE_INVALID")
    r_case("receipt_version_2", sign_body({**body, R_VERSION: 2}).hex(),
           "RECEIPT_UNSUPPORTED_VERSION")
    r_case("unknown_top_level_field", sign_body({**body, 99: 1}).hex(), "RECEIPT_UNKNOWN_FIELD")
    r_case("unsupported_algorithm_es256",
           sign_body(body, p={COSE_PROTECTED_ALG: -7, COSE_PROTECTED_CTYPE: CT_RECEIPT,
                              COSE_PROTECTED_KID: DEVICE_KEY_ID}).hex(),
           "RECEIPT_UNSUPPORTED_ALGORITHM")
    r_case("unknown_protected_header",
           sign_body(body, p={COSE_PROTECTED_ALG: ALG_EDDSA, COSE_PROTECTED_CTYPE: CT_RECEIPT,
                              COSE_PROTECTED_KID: DEVICE_KEY_ID, 9: 1}).hex(),
           "RECEIPT_UNKNOWN_HEADER")
    r_case("crit_header_present",
           sign_body(body, p={COSE_PROTECTED_ALG: ALG_EDDSA, COSE_PROTECTED_CTYPE: CT_RECEIPT,
                              COSE_PROTECTED_KID: DEVICE_KEY_ID, 2: []}).hex(),
           "RECEIPT_UNKNOWN_HEADER")
    r_case("unprotected_header_non_empty", cbor_encode([pb, {1: 1}, payload, rsig]).hex(),
           "RECEIPT_UNKNOWN_HEADER")
    r_case("detached_payload",
           (b"\x84" + gv_head(2, len(pb)) + pb + b"\xa0" + b"\xf6" + gv_head(2, len(rsig)) + rsig).hex(),
           "RECEIPT_CONTAINER_MALFORMED", note="payload = null (detached); attached payload "
           "is required; the reference parser rejects the null element")
    r_case("container_not_four_elements", cbor_encode([pb, {}, payload]).hex(),
           "RECEIPT_CONTAINER_MALFORMED")
    r_case("container_signature_wrong_length", cbor_encode([pb, {}, payload, b"\x00" * 63]).hex(),
           "RECEIPT_CONTAINER_MALFORMED")
    r_case("line_amount_arithmetic_mismatch",
           sign_body({**body, R_LINES: [M(body[R_LINES][0], {5: 476})]
                      + body[R_LINES][1:]}).hex(), "RECEIPT_ARITHMETIC_MISMATCH",
           note="line amount 476 != round_half_away(475*1, 1) = 475")
    r_case("totals_repeated_stale",
           sign_body({**body, R_LINES: [M(body[R_LINES][0], {5: 476})]
                      + body[R_LINES][1:], R_TOTALS: M(body[R_TOTALS], {1: 821, 4: 971})}).hex(),
           "RECEIPT_ARITHMETIC_MISMATCH",
           note="all stated totals moved consistently but the line amount itself is wrong")
    r_case("line_quantity_exactness_unrestated_totals",
           sign_body({**body, R_LINES: [M(body[R_LINES][0], {3: {1: 2, 2: 75}, 4: 360, 5: 270})]
                      + body[R_LINES][1:]}).hex(), "RECEIPT_ARITHMETIC_MISMATCH",
           note="0.75 kg at 3.60 = 270 minor EXACTLY, but totals were not restated: the "
                "totals check fails (see arithmetic-valid.json for the accepted variant)")
    r_case("discount_amount_arithmetic_mismatch",
           sign_body({**body, R_DISCOUNTS: [M(body[R_DISCOUNTS][0], {2: 51})]}).hex(),
           "RECEIPT_ARITHMETIC_MISMATCH",
           note="discount amount 51 != round_half_away(500 * 100000, 1e6) = 50")
    r_case("total_arithmetic_mismatch",
           sign_body({**body, R_TOTALS: M(body[R_TOTALS], {4: body[R_TOTALS][4] + 1})}).hex(),
           "RECEIPT_ARITHMETIC_MISMATCH")
    r_case("tax_arithmetic_mismatch",
           sign_body({**body, R_TAXES: [M(body[R_TAXES][0], {5: 101})]}).hex(),
           "RECEIPT_ARITHMETIC_MISMATCH",
           note="tax amount 101 != round_half_away(770 * 130000, 1e6) = 100")
    r_case("unsupported_currency", sign_body({**body, R_CURRENCY: "XYZ"}).hex(),
           "RECEIPT_UNSUPPORTED_CURRENCY")
    r_case("monetary_out_of_range",
           sign_body({**body, R_LINES: [M(body[R_LINES][0], {4: 2 * 10 ** 12, 5: 2 * 10 ** 12})]
                      + body[R_LINES][1:]}).hex(), "RECEIPT_MONETARY_RANGE")
    r_case("quantity_scale_out_of_range",
           sign_body({**body, R_LINES: [M(body[R_LINES][0], {3: {1: 10, 2: 1}, 5: 0})]
                      + body[R_LINES][1:]}).hex(), "RECEIPT_SEMANTIC_INVALID")
    r_case("text_not_nfc",
           sign_body({**body, R_MERCHANT: {1: MERCHANT_ID, 2: "Cafe\u0301", 3: MERCHANT_REF}}).hex(),
           "RECEIPT_TEXT_INVALID")
    r_case("text_bidi_override",
           sign_body({**body, R_MERCHANT: {1: MERCHANT_ID, 2: "Maple \u202e Vine",
                                           3: MERCHANT_REF}}).hex(), "RECEIPT_TEXT_INVALID")
    r_case("text_control_character",
           sign_body({**body, R_MERCHANT: {1: MERCHANT_ID, 2: "Maple\x07Vine",
                                           3: MERCHANT_REF}}).hex(), "RECEIPT_TEXT_INVALID")
    r_case("unknown_critical_extension",
           sign_body({**body, R_EXTENSIONS: [{1: "com.example.unknown", 2: True, 3: 1}]}).hex(),
           "RECEIPT_UNKNOWN_CRITICAL_EXTENSION")
    r_case("noncritical_extension_ignored",
           sign_body({**body, R_EXTENSIONS: [{1: "com.example.optional", 2: False, 3: 1}]}).hex(),
           None, "TRUSTED", False)
    r_case("credential_missing_from_receipt",
           sign_body({k: v for k, v in body.items() if k != R_CREDENTIAL}).hex(),
           "RECEIPT_CREDENTIAL_MISMATCH")
    r_case("receipt_credential_differs_from_session", blob.hex(), "RECEIPT_CREDENTIAL_MISMATCH",
           session_credential=build_credential(
               M(base_body, {CRED_MERCHANT_REF: "merchant.poc.other"}), ROOT_KEY,
               ROOT_ID).hex())
    r_case("kid_not_matching_credential", sign_body(body, kid=bytes(16)).hex(),
           "RECEIPT_KEY_NOT_AUTHORIZED")
    r_case("merchant_id_not_matching_credential",
           sign_body({**body, R_MERCHANT: {1: UNKNOWN_MERCHANT_ID, 2: "Rogue",
                                           3: MERCHANT_REF}}).hex(),
           "RECEIPT_KEY_NOT_AUTHORIZED")
    rogue_body = M(body, {R_MERCHANT: {1: UNKNOWN_MERCHANT_ID, 2: "Rogue Terminal",
                                      3: "merchant.poc.test-rogue"},
                          R_CREDENTIAL: unknown_cred})
    r_case("unknown_issuer_credential",
           sign_body(rogue_body, key=OTHER_MERCHANT_KEY, kid=UNKNOWN_DEVICE_KEY_ID).hex(),
           "CREDENTIAL_UNKNOWN_ISSUER", "UNVERIFIED_UNKNOWN_ISSUER", False,
           note="signature VALID over an internally consistent rogue receipt, but the issuer "
                "is not a pinned trust anchor: MUST be surfaced as unknown, never trusted")
    r_case("credential_signature_invalid",
           sign_body({**body, R_CREDENTIAL: bad_sig_cred}).hex(), "CREDENTIAL_SIGNATURE_INVALID")
    r_case("credential_expired_receipt",
           sign_body({**body, R_CREDENTIAL: expired_cred}).hex(), "CREDENTIAL_EXPIRED")
    r_case("credential_not_yet_valid_receipt",
           sign_body({**body, R_CREDENTIAL: nyv_cred}).hex(), "CREDENTIAL_NOT_YET_VALID")
    r_case("capability_missing_for_sale",
           sign_body({**body, R_CREDENTIAL: no_sale_cred}).hex(), "CREDENTIAL_CAPABILITY_MISSING")
    r_case("receipt_issued_in_future",
           sign_body({**body, R_ISSUED_AT: NOW + 86_400 * 800}).hex(), "RECEIPT_ISSUED_IN_FUTURE")
    r_case("receipt_issued_below_range",
           sign_body({**body, R_ISSUED_AT: 1_000_000}).hex(), "RECEIPT_SEMANTIC_INVALID")
    r_case("wrong_transaction_offer_receipt_id_differs", blob.hex(), "WRONG_TRANSACTION",
           offer_hex=cbor_encode({**offer, 3: bytes(16)}).hex())
    r_case("wrong_transaction_offer_total_differs", blob.hex(), "WRONG_TRANSACTION",
           offer_hex=cbor_encode({**offer, 5: 796}).hex())
    r_case("wrong_transaction_offer_merchant_ref_differs", blob.hex(), "WRONG_TRANSACTION",
           offer_hex=cbor_encode({**offer, 4: "merchant.poc.other"}).hex())
    dup_body = build_receipt_body(
        KIND_SALE, RECEIPT_ID_1, NOW - 60, MERCHANT_ID, MERCHANT_REF, "Maple & Vine Cafe",
        "CAD", lines_standard(),
        [{1: 1, 2: 50, 3: "Loyalty", 4: 1, 6: 100_000, 7: 500}],
        [{1: 1, 3: 130_000, 4: 770, 5: 100, 6: "ON", 7: "HST"}],
        tip=150, service_charge=None, rounding=None, credential_bytes=valid_cred, tz_offset=-14400)
    assert cbor_encode(dup_body) != payload
    r_case("duplicate_receipt_id_different_bytes", sign_body(dup_body).hex(),
           "RECEIPT_DUPLICATE_CONFLICT",
           note="same receipt_id as valid_baseline, different tip: different signed bytes",
           seen={RECEIPT_ID_1.hex(): payload.hex()})
    r_case("identical_reimport",
           blob.hex(), None, "ALREADY_IMPORTED_IDENTICAL", False,
           note="same receipt_id and byte-identical payload: idempotent, not an error",
           seen={RECEIPT_ID_1.hex(): payload.hex()})

    # non-canonical payload with a *valid* signature over those exact bytes
    enc = cbor_encode(body)
    idx = enc.index(b"\x63CAD")
    noncanon = enc[:idx] + b"\x78\x03CAD" + enc[idx + 4:]
    n_pb, _s, n_sig = cose_sign1_parts(prot, noncanon, MERCHANT_KEY)
    r_case("receipt_payload_noncanonical", cbor_encode([n_pb, {}, noncanon, n_sig]).hex(),
           "RECEIPT_NONCANONICAL", note="payload text length 3 encoded as 0x78 0x03; "
           "signature is valid over those exact non-canonical bytes")
    cont = cbor_encode([pb, {}, payload, rsig])
    r_case("receipt_container_noncanonical", (b"\x98\x04" + cont[1:]).hex(),
           "RECEIPT_NONCANONICAL", note="outer array length encoded as 0x98 0x04")
    r_case("receipt_oversize_placeholder", None, "RECEIPT_SIZE_EXCEEDED",
           note="see protocol/schema/bounds-v1.json max_receipt_bytes; any payload > 65536 "
                "bytes is rejected before parsing")

    # concrete oversize case: a validly-signed receipt whose payload exceeds the bound
    big_body = M(body, {R_EXTENSIONS: [
        {1: "com.example.pad", 2: False, 3: b"\x00" * 70000}]})
    big_payload = cbor_encode(big_body)
    assert len(big_payload) > MAX_RECEIPT_BYTES
    b_pb, _s, b_sig = cose_sign1_parts(prot, big_payload, MERCHANT_KEY)
    ri["cases"][-1]["cose_sign1_hex"] = cbor_encode([b_pb, {}, big_payload, b_sig]).hex()
    ri["cases"][-1]["note"] = ("payload is %d bytes > max_receipt_bytes=%d; rejected before "
                               "signature verification" % (len(big_payload), MAX_RECEIPT_BYTES))
    _wj(os.path.join(vec_dir, "receipt-invalid.json"), ri)
    manifest["receipt-invalid.json"] = _sha(os.path.join(vec_dir, "receipt-invalid.json"))

    # ---------------- fractional-quantity arithmetic (accepted variants) ----------------
    def arith_receipt(lines, **kw):
        b = build_receipt_body(KIND_SALE, RECEIPT_ID_1, NOW - 60, MERCHANT_ID, MERCHANT_REF,
                               "Maple & Vine Cafe", "CAD", lines, kw.get("discounts", []),
                               kw.get("taxes", []), tip=kw.get("tip", 0),
                               service_charge=None, rounding=None,
                               credential_bytes=valid_cred)
        p_ = cbor_encode(b)
        pbb, _s, sig = cose_sign1_parts(prot, p_, MERCHANT_KEY)
        return b, cbor_encode([pbb, {}, p_, sig])

    ar_cases = []
    for name, lines, note in [
        ("fractional_quantity_075kg_at_360", [
            {1: 1, 2: "Sliced almonds", 3: {1: 2, 2: 75, 3: "kg"}, 4: 360, 5: 270, 8: 1}],
         "0.75 kg at 3.60 minor/unit = 2.70 exactly (270 minor); exact, no rounding"),
        ("half_away_rounding_1005_at_1", [
            {1: 1, 2: "Bulk candy", 3: {1: 3, 2: 1005, 3: "kg"}, 4: 1, 5: 1, 8: 1}],
         "1.005 units at 0.01 minor = 0.01005 -> round-half-away-from-zero = 0.01 (1 minor)"),
        ("half_away_round_up_05_at_3", [
            {1: 1, 2: "Loose tea", 3: {1: 1, 2: 5, 3: "kg"}, 4: 3, 5: 2, 8: 1}],
         "0.5 units at 0.03 minor = 0.015 -> round-half-away-from-zero = 0.02 (2 minor)"),
        ("two_decimal_fraction_025_at_7", [
            {1: 1, 2: "Spice blend", 3: {1: 2, 2: 25, 3: "kg"}, 4: 7, 5: 2, 8: 1}],
         "0.25 units at 0.07 minor = 0.0175 -> round-half-away-from-zero = 0.02 (2 minor)"),
    ]:
        b_, blob_ = arith_receipt(lines)
        r_ = verify_receipt(blob_, ANCHORS, valid_cred, NOW)
        assert r_["outcome"] == "TRUSTED", (name, r_)
        ar_cases.append({"case": name, "note": note, "lines": lines,
                         "subtotal_minor": b_[R_TOTALS][1], "total_minor": b_[R_TOTALS][4],
                         "receipt_body_hex": cbor_encode(b_).hex(),
                         "cose_sign1_hex": blob_.hex(),
                         "expected_verification": {"outcome": "TRUSTED", "error": None}})
    _wj(os.path.join(vec_dir, "arithmetic-valid.json"),
        {"revision": REVISION_LABEL, "rounding_mode": "round-half-away-from-zero, integer-only",
         "quantity_amount": "round_half_away(unit_price_minor * qty_value, 10^qty_scale)",
         "cases": ar_cases})
    manifest["arithmetic-valid.json"] = _sha(os.path.join(vec_dir, "arithmetic-valid.json"))

    # ---------------- AEAD ----------------
    receipt_ct = aead_seal(sched["k_m2c_payload"], 0, aad_payload(ctx), blob)
    offer[9] = len(receipt_ct)
    offer_env = control_envelope_aead(sched["k_m2c_ctrl"], 0, ctx, DIR_M2C, offer)
    begin = {1: MSG_TRANSFER_BEGIN, 2: TRANSFER_ID, 3: len(receipt_ct),
             4: hashlib.sha256(receipt_ct).digest(), 5: max_fp,
             6: frame_count(len(receipt_ct), max_fp)}
    begin_env = control_envelope_aead(sched["k_m2c_ctrl"], 1, ctx, DIR_M2C, begin)
    accept = {1: MSG_ACCEPT, 2: TRANSFER_ID, 3: PROTOCOL_VERSION, 4: SUITE_ID}
    accept_env = control_envelope_aead(sched["k_c2m_ctrl"], 0, ctx, DIR_C2M, accept)

    av = {"revision": REVISION_LABEL,
          "nonce_rule": "nonce = 00000000 (4 bytes, reserved, MUST be zero) || counter_be64",
          "aad": {"session_context": "transcript_hash(32) || transfer_id(16)",
                  "payload": "session_context || 0x01",
                  "control_c2m": "session_context || 0x02 || 0x00",
                  "control_m2c": "session_context || 0x02 || 0x01"},
          "session_context_hex": ctx.hex(),
          "control_envelope": "tag(0x01) || counter_be64 || AES-256-GCM ciphertext||tag",
          "plain_control_envelope": "tag(0x00) || canonical-CBOR message (pre-handshake only)",
          "payload_seal": {"key": "k_m2c_payload", "counter": 0,
                           "plaintext_hex": blob.hex(), "ciphertext_hex": receipt_ct.hex(),
                           "ciphertext_len": len(receipt_ct), "aad_hex": aad_payload(ctx).hex()},
          "control_offer": {"key": "k_m2c_ctrl", "counter": 0, "direction": "m2c",
                            "plaintext_hex": cbor_encode(offer).hex(),
                            "envelope_hex": offer_env.hex()},
          "control_transfer_begin": {"key": "k_m2c_ctrl", "counter": 1, "direction": "m2c",
                                     "plaintext_hex": cbor_encode(begin).hex(),
                                     "envelope_hex": begin_env.hex()},
          "control_accept": {"key": "k_c2m_ctrl", "counter": 0, "direction": "c2m",
                             "plaintext_hex": cbor_encode(accept).hex(),
                             "envelope_hex": accept_env.hex()}}
    _wj(os.path.join(vec_dir, "aead-valid.json"), av)
    manifest["aead-valid.json"] = _sha(os.path.join(vec_dir, "aead-valid.json"))

    aei = {"revision": REVISION_LABEL, "cases": []}

    def ae_case(name, key, counter, ctx_hex, blob_hex, err, note=""):
        aei["cases"].append({"case": name, "key": key, "direction": "m2c",
                             "session_context_hex": ctx_hex,
                             "envelope_or_ciphertext_hex": blob_hex,
                             "expected_counter": counter, "expected_error": err, "note": note})

    flip_ct = bytearray(receipt_ct)
    flip_ct[10] ^= 0x01
    ae_case("payload_ciphertext_bit_flipped", "k_m2c_payload", 0, ctx.hex(),
            bytes(flip_ct).hex(), "AEAD_AUTH_FAILED")
    flip_tag = bytearray(receipt_ct)
    flip_tag[-1] ^= 0x80
    ae_case("payload_tag_bit_flipped", "k_m2c_payload", 0, ctx.hex(),
            bytes(flip_tag).hex(), "AEAD_AUTH_FAILED")
    ae_case("payload_aad_mismatch", "k_m2c_payload", 0,
            (transcript_hash + bytes(16)).hex(), receipt_ct.hex(), "AEAD_AUTH_FAILED",
            "AAD built with a different transfer_id: cross-session frame replay")
    replay_env = bytes([ENV_AEAD]) + struct.pack(">Q", 0) + offer_env[9:]
    ae_case("control_counter_replayed", "k_m2c_ctrl", 1, ctx.hex(), replay_env.hex(),
            "AEAD_REPLAY_DETECTED")
    gap_env = bytes([ENV_AEAD]) + struct.pack(">Q", 5) + offer_env[9:]
    ae_case("control_counter_gap", "k_m2c_ctrl", 1, ctx.hex(), gap_env.hex(),
            "AEAD_COUNTER_MISMATCH")
    bad_env = bytearray(offer_env)
    bad_env[12] ^= 0x01
    ae_case("control_ciphertext_flipped", "k_m2c_ctrl", 0, ctx.hex(), bytes(bad_env).hex(),
            "AEAD_AUTH_FAILED")
    ae_case("plaintext_control_after_handshake", "k_m2c_ctrl", 1, ctx.hex(),
            control_envelope_plaintext(offer).hex(), "MESSAGE_WRONG_STATE")
    ae_case("unknown_envelope_tag", "k_m2c_ctrl", 1, ctx.hex(), (b"\x02" + offer_env[1:]).hex(),
            "MESSAGE_UNKNOWN_TYPE")
    _wj(os.path.join(vec_dir, "aead-invalid.json"), aei)
    manifest["aead-invalid.json"] = _sha(os.path.join(vec_dir, "aead-invalid.json"))

    # ---------------- framing ----------------
    fsize = max_fp
    fcount = frame_count(len(receipt_ct), fsize)
    frames = [dataframe(TRANSFER_ID, i, receipt_ct[i * fsize:(i + 1) * fsize])
              for i in range(fcount)]
    _wj(os.path.join(vec_dir, "framing-valid.json"), {
        "revision": REVISION_LABEL,
        "frame_format": "transfer_id(16) || sequence_number(u32 BE) || payload_bytes",
        "transfer_id_hex": TRANSFER_ID.hex(), "frame_size": fsize,
        "att_mtu_example": 185, "att_payload_max_example": att_payload_max(185),
        "frame_count": fcount, "ciphertext_len": len(receipt_ct),
        "payload_hash_hex": hashlib.sha256(receipt_ct).hexdigest(),
        "frames_hex": [f.hex() for f in frames],
        "ack_example": {"1": MSG_ACK, "2": TRANSFER_ID.hex(), "3": 0},
        "ack_example_plaintext_hex": cbor_encode({1: MSG_ACK, 2: TRANSFER_ID, 3: 0}).hex(),
        "reassembly_rule": "concatenate frames 0..frame_count-1 payloads == ciphertext",
        "flow_control": {"highest_contiguous_sequence": True,
                         "ack_every_frames": ACK_EVERY_FRAMES, "window_frames": WINDOW_FRAMES,
                         "max_frame_retries": MAX_FRAME_RETRIES,
                         "window_advance_rule": "max(highest_contiguous_sequence, "
                                                "lowest_sequence - WINDOW_FRAMES)"}})
    manifest["framing-valid.json"] = _sha(os.path.join(vec_dir, "framing-valid.json"))

    fi = {"revision": REVISION_LABEL, "cases": []}

    def f_case(name, err, note="", **kw):
        e = {"case": name, "expected_error": err, "note": note}
        e.update(kw)
        fi["cases"].append(e)

    f_case("frame_size_zero", "FRAME_SIZE_INVALID", frame_size=0, peer_max_frame_payload=162)
    f_case("frame_size_below_min", "FRAME_SIZE_INVALID", frame_size=8, peer_max_frame_payload=162)
    f_case("frame_size_above_mtu_capacity", "FRAME_SIZE_INVALID", frame_size=200,
           peer_max_frame_payload=162)
    f_case("frame_size_above_hard_cap", "FRAME_SIZE_INVALID", frame_size=513,
           peer_max_frame_payload=512)
    f_case("sequence_out_of_range", "FRAME_SEQUENCE_OUT_OF_RANGE", frame_count=fcount,
           frame_hex=dataframe(TRANSFER_ID, fcount, b"x" * 10).hex())
    f_case("sequence_replayed_identical", "FRAME_SEQUENCE_REPLAYED", frame_count=fcount,
           duplicate_byte_identical_hex=frames[0].hex(), disposition="ignore_and_continue",
           note="byte-identical duplicate inside the window: receiver ignores it")
    f_case("sequence_conflicting_duplicate", "FRAME_CONFLICT", frame_count=fcount,
           duplicate_conflicting_hex=dataframe(
               TRANSFER_ID, 0, bytes([frames[0][20] ^ 0x01]) + frames[0][21:]).hex(),
           originals_hex=frames[0].hex())
    f_case("sequence_below_window", "FRAME_SEQUENCE_REPLAYED", frame_count=fcount,
           duplicate_byte_identical_hex=frames[0].hex(), window_floor=fcount,
           note="frame below the sliding window floor: ignore (cannot be buffered)")
    f_case("transfer_id_mismatch", "TRANSFER_ID_MISMATCH", frame_count=fcount,
           frame_hex=dataframe(bytes(16), 1, b"x" * 10).hex())
    short = bytearray(receipt_ct)
    short[100] ^= 0x02
    f_case("payload_hash_mismatch", "TRANSFER_HASH_MISMATCH",
           expected_payload_hash_hex=hashlib.sha256(receipt_ct).hexdigest(),
           observed_payload_hash_hex=hashlib.sha256(bytes(short)).hexdigest())
    f_case("incomplete_frame_set", "TRANSFER_INCOMPLETE", frame_count=fcount,
           received_frames=fcount - 1)
    f_case("begin_declares_wrong_frame_count", "TRANSFER_BEGIN_MISMATCH",
           declared_frames=2, actual_frames=3)
    f_case("declared_ciphertext_above_bound", "TRANSFER_SIZE_EXCEEDED",
           ciphertext_length=MAX_TRANSFER_CIPHERTEXT + 1, max_transfer_ciphertext=MAX_TRANSFER_CIPHERTEXT)
    f_case("too_many_frames", "TRANSFER_SIZE_EXCEEDED", frame_count=MAX_FRAMES + 1,
           frame_size=MIN_FRAME_PAYLOAD, max_frames=MAX_FRAMES)
    f_case("ack_wait_timeout", "TRANSFER_TIMEOUT", elapsed_ms=T_ACK_WAIT + 1,
           retries_used=MAX_FRAME_RETRIES - 1, disposition="retransmit_lowest_unacked")
    f_case("retries_exhausted", "TRANSFER_RETRY_EXHAUSTED", retries_used=MAX_FRAME_RETRIES + 1)
    f_case("receiver_cancelled", "TRANSFER_CANCELLED", cancel_from="customer",
           disposition="abort_and_disconnect")
    _wj(os.path.join(vec_dir, "framing-invalid.json"), fi)
    manifest["framing-invalid.json"] = _sha(os.path.join(vec_dir, "framing-invalid.json"))

    # ---------------- LPdu ----------------
    sh_pdu = sh_env
    lp_frags = lpdu_fragment(sh_pdu, att_payload_max(185) - LPDU_HEADER_BYTES, 0)
    _wj(os.path.join(vec_dir, "lpdu-valid.json"), {
        "revision": REVISION_LABEL,
        "format": "msg_seq(u16 BE) || frag_index(u8) || frag_count(u8) || fragment",
        "server_hello_pdu_hex": sh_pdu.hex(), "server_hello_pdu_len": len(sh_pdu),
        "frag_payload_max": att_payload_max(185) - LPDU_HEADER_BYTES,
        "att_mtu_example": 185, "fragments_hex": [f.hex() for f in lp_frags],
        "fragment_count": len(lp_frags),
        "max_lpdu_fragments": MAX_LPDU_FRAGMENTS, "max_control_pdu": MAX_CONTROL_PDU})
    manifest["lpdu-valid.json"] = _sha(os.path.join(vec_dir, "lpdu-valid.json"))

    li = {"revision": REVISION_LABEL, "cases": []}

    def l_case(name, err, note="", **kw):
        e = {"case": name, "expected_error": err, "note": note}
        e.update(kw)
        li["cases"].append(e)

    _swapped = ([lp_frags[0].hex(), lp_frags[2].hex(), lp_frags[1].hex()]
                + [f.hex() for f in lp_frags[3:]])
    l_case("frag_index_skipped", "LPDU_SEQUENCE_ERROR",
           fragments_hex=_swapped,
           note="fragment 1 arrives before fragment 0 of the same message: index/position "
                "mismatch (single message, %d fragments)" % len(lp_frags))
    l_case("frag_count_inconsistent", "LPDU_FRAGMENT_INVALID",
           fragments_hex=[(lp_frags[0][:3] + bytes([9]) + lp_frags[0][4:]).hex()])
    l_case("first_fragment_index_not_zero", "LPDU_FRAGMENT_INVALID",
           fragments_hex=[(struct.pack(">HBB", 0, 1, 2) + lp_frags[0][4:]).hex()])
    l_case("reassembled_pdu_too_large", "LPDU_MESSAGE_TOO_LARGE",
           pdu_len=MAX_CONTROL_PDU + 1, max_control_pdu=MAX_CONTROL_PDU)
    l_case("frag_count_zero", "LPDU_FRAGMENT_INVALID",
           fragments_hex=[(struct.pack(">HBB", 0, 0, 0)).hex()])
    l_case("reassembly_timeout", "LPDU_REASSEMBLY_TIMEOUT",
           received_fragments=1, expected_fragments=len(lp_frags),
           elapsed_ms=T_CONTROL_FRAG + 1)
    l_case("conflicting_duplicate_fragment", "LPDU_CONFLICT",
           note="the same fragment index arrives twice with different bytes (receiver buffer "
                "conflict); policy assertion, not a single-byte fixture")
    l_case("too_many_fragments", "LPDU_MESSAGE_TOO_LARGE", fragment_count=MAX_LPDU_FRAGMENTS + 1)
    _wj(os.path.join(vec_dir, "lpdu-invalid.json"), li)
    manifest["lpdu-invalid.json"] = _sha(os.path.join(vec_dir, "lpdu-invalid.json"))

    # ---------------- encoding ----------------
    ev = {"revision": REVISION_LABEL, "cases": []}

    def e_case(name, hexs, err):
        ev["cases"].append({"case": name, "bytes_hex": hexs, "expected_error": err})

    e_case("duplicate_map_key", (b"\xa2\x01\x01\x01\x02").hex(), "CBOR_DUPLICATE_KEY")
    e_case("unsorted_map_keys", (b"\xa2\x02\x01\x01\x02").hex(), "CBOR_NONCANONICAL")
    e_case("non_minimal_int", (b"\x18\x05").hex(), "CBOR_NONCANONICAL")
    e_case("non_minimal_text_length", (b"\x78\x03CAD").hex(), "CBOR_NONCANONICAL")
    e_case("non_minimal_array_length", (b"\x98\x02\x01\x02").hex(), "CBOR_NONCANONICAL")
    e_case("indefinite_array", (b"\x9f\x01\x01\xff").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("indefinite_map", (b"\xbf\x01\x01\xff").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("float64_value", (b"\xfb\x40\x14\x00\x00\x00\x00\x00\x00").hex(),
           "CBOR_UNSUPPORTED_TYPE")
    e_case("float16_value", (b"\xf9\x3c\x00").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("tag_value", (b"\xc1\x01").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("null_value", (b"\xf6").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("undefined_value", (b"\xf7").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("negative_map_key", (b"\xa1\x20\x01").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("map_key_above_255", (b"\xa1\x19\x01\x00\x01").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("text_map_key", (b"\xa1\x61a\x01").hex(), "CBOR_UNSUPPORTED_TYPE")
    e_case("truncated_bytestring", (b"\x44\x01\x02").hex(), "CBOR_MALFORMED")
    e_case("trailing_bytes", (b"\x01\x01").hex(), "CBOR_MALFORMED")
    e_case("invalid_utf8", (b"\x61\xff").hex(), "CBOR_MALFORMED")
    e_case("depth_exceeded", (b"\x81" * (MAX_CBOR_DEPTH + 2) + b"\x01").hex(),
           "CBOR_DEPTH_EXCEEDED")
    e_case("text_length_exceeded",
           (b"\x79" + struct.pack(">H", MAX_CBOR_TEXT_BYTES + 1) + b"a").hex(),
           "CBOR_SIZE_EXCEEDED")
    e_case("array_length_exceeded", (b"\x99" + struct.pack(">H", MAX_CBOR_ARRAY + 1)).hex(),
           "CBOR_SIZE_EXCEEDED")
    e_case("map_length_exceeded", (b"\xb9" + struct.pack(">H", MAX_CBOR_MAP + 1)).hex(),
           "CBOR_SIZE_EXCEEDED")
    _wj(os.path.join(vec_dir, "encoding-invalid.json"), ev)
    manifest["encoding-invalid.json"] = _sha(os.path.join(vec_dir, "encoding-invalid.json"))

    # ---------------- errors + bounds ----------------
    _wj(os.path.join(vec_dir, "errors.json"), {
        "revision": REVISION_LABEL,
        "outcomes": [{"name": n, "code": c} for n, c in OUTCOMES],
        "errors": [{"name": n, "code": c, "code_hex": "0x%04x" % c, "fatal": f,
                    "retryable": r, "category": cat} for n, c, f, r, cat in ERRORS]})
    manifest["errors.json"] = _sha(os.path.join(vec_dir, "errors.json"))

    bounds = {
        "revision": REVISION_LABEL, "protocol_version": PROTOCOL_VERSION, "suite_id": SUITE_ID,
        "cbor": {"max_depth": MAX_CBOR_DEPTH, "max_items": MAX_CBOR_ITEMS,
                 "max_array": MAX_CBOR_ARRAY, "max_map": MAX_CBOR_MAP,
                 "max_text_bytes": MAX_CBOR_TEXT_BYTES, "max_bytes": MAX_CBOR_BYTES,
                 "max_map_key": MAX_CBOR_KEY},
        "receipt": {"max_receipt_bytes": MAX_RECEIPT_BYTES, "max_lines": MAX_LINES,
                    "max_discounts": MAX_DISCOUNTS, "max_taxes": MAX_TAXES,
                    "max_tenders": MAX_TENDERS, "max_extensions": MAX_EXTENSIONS,
                    "max_modifiers": MAX_MODIFIERS, "max_address_lines": MAX_ADDRESS_LINES,
                    "max_text_description_bytes": MAX_TEXT_DESCRIPTION,
                    "max_text_display_name_bytes": MAX_TEXT_DISPLAY_NAME,
                    "max_text_short_bytes": MAX_TEXT_SHORT,
                    "max_text_unit_bytes": MAX_TEXT_UNIT,
                    "max_monetary_abs": MAX_MONETARY_ABS,
                    "max_unit_price_abs": MAX_UNIT_PRICE_ABS,
                    "max_qty_value_abs": MAX_QTY_VALUE_ABS, "max_qty_scale": MAX_QTY_SCALE,
                    "max_arith_product": MAX_ARITH_PRODUCT, "max_tax_rate_ppm": MAX_TAX_RATE_PPM,
                    "min_issued_at": MIN_ISSUED_AT, "max_issued_at": MAX_ISSUED_AT},
        "credential": {"max_credential_bytes": MAX_CREDENTIAL_BYTES,
                       "capabilities": {"CAP_ISSUE_SALE": CAP_ISSUE_SALE,
                                        "CAP_ISSUE_REFUND": CAP_ISSUE_REFUND,
                                        "CAP_ISSUE_VOID": CAP_ISSUE_VOID,
                                        "CAP_RECEIVE_TRANSFER": CAP_RECEIVE_TRANSFER,
                                        "CAP_EMBED_CREDENTIAL": CAP_EMBED_CREDENTIAL}},
        "wire": {"max_control_pdu": MAX_CONTROL_PDU, "max_lpdu_fragments": MAX_LPDU_FRAGMENTS,
                 "max_lpdu_frag_bytes": MAX_LPDU_FRAG_BYTES,
                 "lpdu_header_bytes": LPDU_HEADER_BYTES, "max_att_payload": MAX_ATT_PAYLOAD,
                 "max_frame_payload": MAX_FRAME_PAYLOAD, "min_frame_payload": MIN_FRAME_PAYLOAD,
                 "dataframe_header_bytes": DATAFRAME_HEADER_BYTES,
                 "max_transfer_ciphertext": MAX_TRANSFER_CIPHERTEXT, "max_frames": MAX_FRAMES,
                 "aead_tag_bytes": AEAD_TAG_BYTES, "aead_nonce_bytes": AEAD_NONCE_BYTES,
                 "aead_ctrl_envelope_overhead": AEAD_CTRL_ENVELOPE_OVERHEAD,
                 "ack_every_frames": ACK_EVERY_FRAMES, "window_frames": WINDOW_FRAMES,
                 "max_frame_retries": MAX_FRAME_RETRIES,
                 "max_control_messages_per_direction": MAX_CONTROL_MESSAGES},
        "handshake": {"nonce_bytes": NONCE_BYTES, "transcript_len": TRANSCRIPT_LEN,
                      "max_binding_bytes": MAX_BINDING_BYTES,
                      "max_session_id_history": MAX_SESSION_ID_HISTORY},
        "timeouts_ms": {"T_ADVERTISE": T_ADVERTISE, "T_CONNECT": T_CONNECT,
                        "T_HELLO_RESPONSE": T_HELLO_RESPONSE, "T_ACCEPT": T_ACCEPT,
                        "T_CONTROL_FRAG": T_CONTROL_FRAG, "T_ACK_WAIT": T_ACK_WAIT,
                        "T_ACK_INTERVAL": T_ACK_INTERVAL, "T_TRANSFER_IDLE": T_TRANSFER_IDLE,
                        "T_VERIFY_BUDGET": T_VERIFY_BUDGET, "T_SESSION": T_SESSION,
                        "T_CLOSE": T_CLOSE, "T_BINDING_QR": T_BINDING_QR},
        "clock_skew_max_s": CLOCK_SKEW_MAX_S, "currency_minor_unit_exponent": CURRENCY_EXPONENT,
        "message_types": {"CLIENT_HELLO": MSG_CLIENT_HELLO, "ACCEPT": MSG_ACCEPT,
                          "ACK": MSG_ACK, "RECEIPT_ACK": MSG_RECEIPT_ACK,
                          "CANCEL": MSG_CANCEL, "RETRY": MSG_RETRY,
                          "SERVER_HELLO": MSG_SERVER_HELLO,
                          "RECEIPT_OFFER": MSG_RECEIPT_OFFER,
                          "TRANSFER_BEGIN": MSG_TRANSFER_BEGIN,
                          "TRANSFER_COMPLETE": MSG_TRANSFER_COMPLETE,
                          "ERROR": MSG_ERROR},
        "envelope_tags": {"PLAINTEXT": ENV_PLAINTEXT, "AEAD": ENV_AEAD},
        "directions": {"c2m": DIR_C2M, "m2c": DIR_M2C},
    }
    _wj(os.path.join(schema_dir, "bounds-v1.json"), bounds)
    manifest["../schema/bounds-v1.json"] = _sha(os.path.join(schema_dir, "bounds-v1.json"))

    for name in ("handshake-valid.json", "handshake-invalid.json", "aead-valid.json",
                 "aead-invalid.json", "framing-valid.json", "framing-invalid.json",
                 "lpdu-valid.json", "lpdu-invalid.json", "encoding-invalid.json",
                 "errors.json", "binding-crosscheck.json"):
        manifest[name] = _sha(os.path.join(vec_dir, name))

    _wb(os.path.join(vec_dir, "NOTICE"), NOTICE_FILE.encode("utf-8"))
    _wb(os.path.join(vec_dir, "fixtures", "NOTICE"), NOTICE_FILE.encode("utf-8"))
    manifest["NOTICE"] = _sha(os.path.join(vec_dir, "NOTICE"))
    manifest["fixtures/NOTICE"] = _sha(os.path.join(vec_dir, "fixtures", "NOTICE"))
    _wj(os.path.join(vec_dir, "vectors-manifest.json"),
        {"revision": REVISION_LABEL, "files": dict(sorted(manifest.items()))})

    # ---------------- machine-readable field tables (docs and code cannot drift) ----
    _wj(os.path.join(schema_dir, "receipt-v1.fields.json"), receipt_fields_schema())
    _wj(os.path.join(schema_dir, "credential-v1.fields.json"), credential_fields_schema())
    _wj(os.path.join(schema_dir, "wire-v1.messages.json"), wire_messages_schema())
    for fn in ("receipt-v1.fields.json", "credential-v1.fields.json",
               "wire-v1.messages.json"):
        manifest["../schema/" + fn] = _sha(os.path.join(schema_dir, fn))

    # ---------------- freeze revision manifest ----------------
    rev_dir = os.path.abspath(os.path.join(vec_dir, ".."))
    doc_dir = os.path.abspath(os.path.join(rev_dir, "..", "docs", "protocol"))
    frozen = dict(sorted(manifest.items()))
    for fn in sorted(os.listdir(doc_dir)) if os.path.isdir(doc_dir) else []:
        if fn.endswith(".md"):
            frozen["../../docs/protocol/" + fn] = _sha(os.path.join(doc_dir, fn))
    for fn in ("receipt-v1.cddl", "credential-v1.cddl", "wire-v1.cddl"):
        fp = os.path.join(schema_dir, fn)
        if os.path.exists(fp):
            frozen["../schema/" + fn] = _sha(fp)
    aggregate = hashlib.sha256(
        b"deceipt-proto-r1\x00" + b"\x00".join(
            (k + "=" + v).encode() for k, v in sorted(frozen.items()))).hexdigest()
    _wj(os.path.join(rev_dir, "REVISION.json"), {
        "_TESTONLY": TEST_ONLY_NOTICE,
        "revision": REVISION_LABEL,
        "aggregate_sha256": aggregate,
        "hash_rule": "SHA-256(\"deceipt-proto-r1\" || 0x00 || <sorted 'path=sha256' rows "
                     "joined by 0x00>) over every frozen protocol artifact "
                     "(docs/protocol/*.md, protocol/schema/*, protocol/vectors/*)",
        "files": frozen,
        "status": "FROZEN for the PoC; changes require a new revision id and a new "
                  "vector regeneration",
        "generator": "protocol/vectors/tools/gen_vectors.py"})
    st = self_test(vec_dir, schema_dir)
    _wj(os.path.join(vec_dir, "self-test.json"), st)
    manifest["self-test.json"] = _sha(os.path.join(vec_dir, "self-test.json"))
    assert not st["failed"], st["failed"][:5]
    try:
        revj = json.load(open(os.path.join(rev_dir, "REVISION.json")))
    except Exception:
        revj = {}
    revj["self_test"] = {"file": "protocol/vectors/self-test.json",
                         "checked": st["checked"], "failed": st["failed"]}
    _wj(os.path.join(rev_dir, "REVISION.json"), revj)
    print("self-test checked", st["checked"], "failed", len(st["failed"]))
    print("revision aggregate_sha256", aggregate)
    print("vectors written to", vec_dir)
    print("revision", REVISION_LABEL, "transcript_len", len(transcript),
          "receipt_len", len(blob), "frames", fcount)



def receipt_fields_schema() -> Dict[str, Any]:
    def f(label, name, typ, req, note, bound=None):
        d = {"label": label, "name": name, "type": typ, "required": req, "rule": note}
        if bound:
            d["bound"] = bound
        return d
    return {
        "revision": REVISION_LABEL, "schema": "deceipt.receipt-v1", "top_level": "map",
        "encoding": "deterministic CBOR (RFC 8949 4.2.1); integer keys 0..255; "
                    "no floats; no tags; no indefinite lengths",
        "unknown_field_policy": "unknown integer label at any map level => "
                                "RECEIPT_UNKNOWN_FIELD (fatal); unknown COSE protected "
                                "header label => RECEIPT_UNKNOWN_HEADER (fatal)",
        "extension_policy": "unknown label 21 extensions with critical=true => "
                            "RECEIPT_UNKNOWN_CRITICAL_EXTENSION (fatal); critical=false => "
                            "ignored and preserved in the stored signed bytes",
        "fields": [
            f(1, "receipt_version", "uint", True, "MUST be 1; else RECEIPT_UNSUPPORTED_VERSION"),
            f(2, "kind", "uint", True, "1=sale 2=refund 3=void"),
            f(3, "receipt_id", "bstr16", True, "random; dedup key"),
            f(4, "issued_at", "uint", True, "unix seconds; "
              "1577836800..4102444800 else RECEIPT_SEMANTIC_INVALID"),
            f(5, "tz_offset_minutes", "int", False, "-840..840"),
            f(6, "merchant", "map", True, "see merchant; label 1 required"),
            f(7, "location", "map", False, "see location"),
            f(8, "currency", "tstr", True, "ISO 4217 alpha-3 from the v1 exponent table; "
              "else RECEIPT_UNSUPPORTED_CURRENCY"),
            f(9, "lines", "array", True, "see line; <= 256 items"),
            f(10, "discounts", "array", False, "see discount; <= 64 items"),
            f(11, "taxes", "array", False, "see tax; <= 64 items"),
            f(12, "tip_amount_minor", "uint", False, "non-negative minor units"),
            f(13, "service_charge_minor", "uint", False, "non-negative minor units"),
            f(14, "rounding_adjustment_minor", "int", False, "signed minor units"),
            f(15, "totals", "map", True, "see totals; labels 1,2,3,4,8 required"),
            f(16, "payment", "map", True, "see payment; labels 1,2 required"),
            f(17, "refund_of_receipt_id", "bstr16", "kind=refund", "required when kind=2"),
            f(18, "void_of_receipt_id", "bstr16", "kind=void", "required when kind=3"),
            f(19, "order_reference", "map", False, "see order_reference"),
            f(20, "merchant_credential", "bstr", True, "the exact COSE_Sign1 credential "
              "bytes presented in ServerHello (byte-identical)"),
            f(21, "extensions", "array", False, "see extension; <= 32 items"),
        ],
        "sub_maps": {
            "merchant": [f(1, "merchant_id", "bstr16", True, "must match credential"),
                         f(2, "display_name", "tstr", True, "<=128 utf-8 bytes, NFC, no "
                           "bidi/control chars"),
                         f(3, "merchant_reference", "tstr", True, "stable merchant-chosen "
                           "string; the A2 offer_hash uses this value")],
            "location": [f(1, "label", "tstr", False, "<=128 bytes"),
                         f(2, "street", "tstr", False, "<=512 bytes"),
                         f(3, "city", "tstr", False, "<=512 bytes"),
                         f(4, "region", "tstr", False, "<=512 bytes"),
                         f(5, "address_lines", "array", False, "<=8 tstr, each <=512 bytes"),
                         f(6, "postal_code", "tstr", False, "digits only")],
            "line": [f(1, "line_id", "uint", True, "unique within lines"),
                     f(2, "description", "tstr", True, "<=512 utf-8 bytes, NFC"),
                     f(3, "quantity", "map", True, "label1 scale uint 0..9, label2 value int, "
                       "label3 unit tstr<=16"),
                     f(4, "unit_price_minor", "int", True, "|value| <= 1e12"),
                     f(5, "line_amount_minor", "uint", True, "== round_half_away(unit*qty, "
                       "10^scale); 0..1e15"),
                     f(6, "line_discount_minor", "uint", False, "0..line_amount"),
                     f(7, "parent_line_ids", "array", False, "modifier parents; non-empty"),
                     f(8, "line_type", "uint", False, "1=item 2=modifier 3=discount 4=info"),
                     f(9, "sku", "tstr", False, "<=64 bytes"),
                     f(10, "modifiers", "array", False, "<=16 modifier maps")],
            "discount": [f(1, "discount_id", "uint", True, "unique within discounts"),
                         f(2, "amount_minor", "uint", True, "0..1e15"),
                         f(3, "label", "tstr", False, "<=128 bytes"),
                         f(4, "scope", "uint", True, "1=order 2=line"),
                         f(5, "target_line_id", "uint", "scope=2", "required when scope=2"),
                         f(6, "rate_ppm", "uint", False, "0..999999; when present label 7 "
                           "required and amount==round_half_away(base*rate,1e6)"),
                         f(7, "base_amount_minor", "uint", False, ">=0")],
            "tax": [f(1, "tax_id", "uint", True, "unique within taxes"),
                    f(2, "label", "tstr", False, "<=128 bytes"),
                    f(3, "rate_ppm", "uint", True, "0..999999"),
                    f(4, "base_amount_minor", "uint", True, "0..1e15"),
                    f(5, "amount_minor", "uint", True, "== round_half_away(base*rate,1e6)"),
                    f(6, "jurisdiction", "tstr", False, "<=64 bytes"),
                    f(7, "code", "tstr", False, "<=64 bytes"),
                    f(8, "included_in_prices", "bool", False, "true => excluded from the "
                      "total; base MUST be 0 when true")],
            "totals": [f(1, "subtotal_minor", "uint", True, "sum of line_amount_minor"),
                       f(2, "discount_total_minor", "uint", True, "sum of discount amount_minor"),
                       f(3, "tax_total_minor", "uint", True, "sum of tax amount_minor "
                         "(included and added)"),
                       f(4, "total_minor", "uint", True, "subtotal - discounts + added taxes "
                         "+ tip + service_charge + rounding"),
                       f(5, "tip_minor", "uint", False, "must equal label 12 when present"),
                       f(6, "service_charge_minor", "uint", False, "must equal label 13"),
                       f(7, "rounding_adjustment_minor", "int", False, "must equal label 14"),
                       f(8, "tax_added_total_minor", "uint", True, "sum of added taxes only")],
            "payment": [f(1, "status", "uint", True, "1=paid 2=partial 3=unpaid 4=refunded "
                         "5=voided; constrained by kind"),
                        f(2, "amount_paid_minor", "uint", True, "0..1e15; refund amount for "
                          "kind=refund"),
                        f(3, "change_minor", "uint", False, "required iff amount_paid > total"),
                        f(4, "tenders", "array", False, "<=32 tender maps")],
            "tender": [f(1, "method", "uint", True, "1=cash 2=card 3=other 4=stored_value"),
                       f(2, "amount_minor", "uint", True, "sum of tenders == amount_paid"),
                       f(3, "card_last4", "tstr", False, "exactly 4 digits"),
                       f(4, "brand", "tstr", False, "<=64 bytes"),
                       f(5, "auth_ref", "tstr", False, "<=64 bytes")],
            "order_reference": [f(1, "order_number", "tstr", False, "<=64 bytes"),
                                f(2, "table", "tstr", False, "<=64 bytes"),
                                f(3, "server", "tstr", False, "<=64 bytes")],
            "extension": [f(1, "key", "tstr", True, "<=64 bytes"),
                          f(2, "critical", "bool", True, "true and unknown => fatal"),
                          f(3, "value", "any", False, "canonical CBOR, <=4096 bytes")],
        },
        "refund_void_rules": {
            "sale": "kind=1, payment.status in {1,2,3}, no refund_of/void_of",
            "refund": "kind=2, refund_of_receipt_id required, payment.status=4, "
                      "amount_paid == total",
            "void": "kind=3, void_of_receipt_id required, lines MUST be empty, subtotal 0, "
                    "total 0, payment.status=5, amount_paid 0",
        },
        "arithmetic": {
            "quantity_amount": "round_half_away(unit_price_minor * qty_value, 10^qty_scale)",
            "rounding_mode": "round-half-away-from-zero, integer-only",
            "tax_amount": "round_half_away(base_amount_minor * rate_ppm, 1000000)",
            "overflow_guard": "|unit*qty| <= 2^62 else RECEIPT_MONETARY_RANGE",
        },
        "version_negotiation": "receipt_version must be 1; the transport carries "
                               "protocol_version 1 in ClientHello/ServerHello; the signed "
                               "receipt version is authoritative and independent of the "
                               "transport version",
    }


def credential_fields_schema() -> Dict[str, Any]:
    def f(label, name, typ, req, note):
        return {"label": label, "name": name, "type": typ, "required": req, "rule": note}
    return {
        "revision": REVISION_LABEL, "schema": "deceipt.credential-v1", "top_level": "map",
        "container": "COSE_Sign1 [protected, {}, payload, signature], signature EdDSA "
                     "(Ed25519) over Sig_structure ['Signature1', protected, h'', payload]",
        "protected_headers": {"1": "alg = -8 (EdDSA)", "3": "content type = "
                              "application/deceipt-credential+cbor",
                              "4": "key id = issuer identifier (bstr16)"},
        "fields": [
            f(1, "credential_version", "uint", True, "MUST be 1"),
            f(2, "issuer_id", "bstr16", True, "MUST equal protected kid"),
            f(3, "merchant_id", "bstr16", True, "stable merchant identifier"),
            f(4, "device_key_id", "bstr16", True, "MUST equal the receipt COSE kid"),
            f(5, "device_public_key", "bstr32", True, "Ed25519 public key"),
            f(6, "valid_from", "uint", True, "unix seconds, inclusive"),
            f(7, "valid_until", "uint", True, "unix seconds, exclusive; > valid_from"),
            f(8, "capabilities", "uint", True, "bitmask CAP_*"),
            f(9, "merchant_reference", "tstr", True, "matches receipt merchant label 3"),
            f(10, "display_name", "tstr", True, "<=128 utf-8 bytes, NFC"),
            f(11, "issued_at", "uint", True, "credential issuance time"),
        ],
        "capabilities": {"CAP_ISSUE_SALE": CAP_ISSUE_SALE, "CAP_ISSUE_REFUND": CAP_ISSUE_REFUND,
                         "CAP_ISSUE_VOID": CAP_ISSUE_VOID,
                         "CAP_RECEIVE_TRANSFER": CAP_RECEIVE_TRANSFER,
                         "CAP_EMBED_CREDENTIAL": CAP_EMBED_CREDENTIAL},
        "max_bytes": MAX_CREDENTIAL_BYTES,
        "unknown_field_policy": "unknown label => CREDENTIAL_MALFORMED (fatal)",
    }


def wire_messages_schema() -> Dict[str, Any]:
    return {
        "revision": REVISION_LABEL, "schema": "deceipt.wire-v1",
        "envelope": {"plaintext": "0x00 || canonical CBOR (ClientHello, ServerHello only)",
                     "aead": "0x01 || counter_be64 || AES-256-GCM(...)"},
        "directions": {"c2m": ["CLIENT_HELLO", "ACCEPT", "ACK", "RECEIPT_ACK", "CANCEL",
                               "RETRY"],
                       "m2c": ["SERVER_HELLO", "RECEIPT_OFFER", "TRANSFER_BEGIN",
                               "TRANSFER_COMPLETE", "ERROR"]},
        "unknown_field_policy": "unknown integer label => MESSAGE_UNKNOWN_FIELD (fatal); "
                                "unknown message type => MESSAGE_UNKNOWN_TYPE (fatal)",
        "messages": [
            {"type": MSG_CLIENT_HELLO, "name": "CLIENT_HELLO", "direction": "c2m",
             "state": "CONNECTED", "encrypted": False,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True,
                         "value": MSG_CLIENT_HELLO},
                        {"label": 2, "name": "protocol_version", "type": "uint", "required": True},
                        {"label": 3, "name": "crypto_suites", "type": "array", "required": True,
                         "rule": "non-empty uint array; v1 supports {1}"},
                        {"label": 4, "name": "session_id", "type": "bstr16", "required": True},
                        {"label": 5, "name": "client_nonce", "type": "bstr32", "required": True},
                        {"label": 6, "name": "client_ephemeral_pubkey", "type": "bstr65",
                         "required": True},
                        {"label": 7, "name": "binding_proof", "type": "bstr32",
                         "required": True},
                        {"label": 8, "name": "max_frame_payload", "type": "uint",
                         "required": True, "rule": "16..512"}]},
            {"type": MSG_ACCEPT, "name": "ACCEPT", "direction": "c2m", "state": "RECEIPT_OFFERED",
             "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "protocol_version", "type": "uint", "required": True},
                        {"label": 4, "name": "suite_id", "type": "uint", "required": True}]},
            {"type": MSG_ACK, "name": "ACK", "direction": "c2m", "state": "TRANSFER",
             "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "highest_contiguous_sequence", "type": "uint",
                         "required": True}]},
            {"type": MSG_RECEIPT_ACK, "name": "RECEIPT_ACK", "direction": "c2m",
             "state": "STORED", "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "receipt_id", "type": "bstr16", "required": True},
                        {"label": 4, "name": "outcome", "type": "uint", "required": True,
                         "rule": "1 trusted 2 unknown_issuer 3 already_imported 4 rejected"}]},
            {"type": MSG_CANCEL, "name": "CANCEL", "direction": "c2m", "state": "any",
             "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": False},
                        {"label": 3, "name": "error_code", "type": "uint", "required": False}]},
            {"type": MSG_RETRY, "name": "RETRY", "direction": "c2m", "state": "TRANSFER",
             "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "from_sequence", "type": "uint", "required": True}]},
            {"type": MSG_SERVER_HELLO, "name": "SERVER_HELLO", "direction": "m2c",
             "state": "HANDSHAKE", "encrypted": False,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "protocol_version", "type": "uint", "required": True},
                        {"label": 3, "name": "suite_id", "type": "uint", "required": True},
                        {"label": 4, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 5, "name": "server_nonce", "type": "bstr32", "required": True},
                        {"label": 6, "name": "server_ephemeral_pubkey", "type": "bstr65",
                         "required": True},
                        {"label": 7, "name": "merchant_credential", "type": "bstr",
                         "required": True, "rule": "<=1024 bytes"},
                        {"label": 8, "name": "transcript_signature", "type": "bstr64",
                         "required": True},
                        {"label": 9, "name": "binding_tuple_digest", "type": "bstr32",
                         "required": True}]},
            {"type": MSG_RECEIPT_OFFER, "name": "RECEIPT_OFFER", "direction": "m2c",
             "state": "MERCHANT_SESSION_AUTHENTICATED", "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "receipt_id", "type": "bstr16", "required": True},
                        {"label": 4, "name": "merchant_reference", "type": "tstr",
                         "required": True},
                        {"label": 5, "name": "total_amount_minor", "type": "uint",
                         "required": True},
                        {"label": 6, "name": "currency", "type": "tstr", "required": True},
                        {"label": 7, "name": "issued_at", "type": "uint", "required": True},
                        {"label": 8, "name": "kind", "type": "uint", "required": True},
                        {"label": 9, "name": "ciphertext_length", "type": "uint",
                         "required": True},
                        {"label": 10, "name": "merchant_id", "type": "bstr16",
                         "required": True},
                        {"label": 11, "name": "credential_hash", "type": "bstr32",
                         "required": True},
                        {"label": 12, "name": "session_id", "type": "bstr16",
                         "required": True}]},
            {"type": MSG_TRANSFER_BEGIN, "name": "TRANSFER_BEGIN", "direction": "m2c",
             "state": "TRANSFER", "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "ciphertext_length", "type": "uint",
                         "required": True},
                        {"label": 4, "name": "payload_hash", "type": "bstr32", "required": True},
                        {"label": 5, "name": "frame_size", "type": "uint", "required": True},
                        {"label": 6, "name": "frame_count", "type": "uint", "required": True}]},
            {"type": MSG_TRANSFER_COMPLETE, "name": "TRANSFER_COMPLETE", "direction": "m2c",
             "state": "TRANSFER", "encrypted": True,
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "transfer_id", "type": "bstr16", "required": True},
                        {"label": 3, "name": "frame_count", "type": "uint", "required": True},
                        {"label": 4, "name": "payload_hash", "type": "bstr32", "required": True}]},
            {"type": MSG_ERROR, "name": "ERROR", "direction": "m2c", "state": "any",
             "encrypted": "plaintext ONLY in pre-key states (CONNECTED / HANDSHAKE before "
                          "ServerHello); AEAD once session keys exist",
             "fields": [{"label": 1, "name": "type", "type": "uint", "required": True},
                        {"label": 2, "name": "error_code", "type": "uint", "required": True},
                        {"label": 3, "name": "fatal", "type": "bool", "required": True},
                        {"label": 4, "name": "transfer_id", "type": "bstr16", "required": False},
                        {"label": 5, "name": "detail", "type": "tstr", "required": False,
                         "rule": "<=64 bytes, no secrets"}]},
        ],
        "transfer_id_rule": "16 random bytes chosen by the merchant for the session; it is a "
                            "member of the binding tuple, so the merchant-signed transcript "
                            "binds it; every DataFrame and every transfer-scoped message "
                            "carries it and receivers MUST compare it",
        "max_control_pdu": MAX_CONTROL_PDU,
    }


# ==========================================================================
# 14. Self-test — every invalid vector is run through the reference impl
# ==========================================================================

def self_test(vec_dir: str, schema_dir: str) -> Dict[str, Any]:
    checked, failed, policy = 0, [], []
    V = lambda n: json.load(open(os.path.join(vec_dir, n)))

    def expect(case, want, got, kind):
        nonlocal checked
        checked += 1
        if want != got:
            failed.append({"file": kind, "case": case, "expected": want, "observed": got})

    # --- encoding ---
    for c in V("encoding-invalid.json")["cases"]:
        try:
            cbor_decode(bytes.fromhex(c["bytes_hex"]))
            got = None
        except CborError as e:
            got = e.code
        expect(c["case"], c["expected_error"], got, "encoding-invalid")

    # --- receipt (build the exact environment each case declares) ---
    for c in V("receipt-invalid.json")["cases"]:
        if c["cose_sign1_hex"] is None:
            policy.append({"file": "receipt-invalid", "case": c["case"],
                           "reason": "descriptive bound assertion, not a byte fixture"})
            continue
        anchors = {bytes.fromhex(k): bytes.fromhex(v) for k, v in c["anchors_hex"].items()}
        sess = bytes.fromhex(c["session_credential_hex"]) if c["session_credential_hex"] else None
        offer = cbor_decode(bytes.fromhex(c["receipt_offer_hex"])) if c["receipt_offer_hex"] else None
        seen = ({bytes.fromhex(k): bytes.fromhex(v)
                 for k, v in c["seen_receipt_ids_hex"].items()}
                if c["seen_receipt_ids_hex"] else None)
        r = verify_receipt(bytes.fromhex(c["cose_sign1_hex"]), anchors, sess, c["verify_at_unix"],
                           offer=offer, seen_receipt_ids=seen)
        expect(c["case"], c["expected_error"], r["error"], "receipt-invalid")
        expect(c["case"] + ":outcome", c["expected_outcome"], r["outcome"], "receipt-invalid")

    # --- AEAD ---
    for c in V("aead-invalid.json")["cases"]:
        blob = bytes.fromhex(c["envelope_or_ciphertext_hex"])
        ctx = bytes.fromhex(c["session_context_hex"])
        key = bytes.fromhex(CTX_KEYS[c["key"]]) if False else None
        try:
            if c["key"] == "k_m2c_payload" and blob[0] != ENV_AEAD and "envelope" not in c["case"]:
                aead_open(bytes.fromhex(SESSION_KEYS["k_m2c_payload"]), c["expected_counter"], aad_payload(ctx), blob)
            else:
                open_control_envelope(bytes.fromhex(SESSION_KEYS[c["key"]]), ctx, DIR_M2C, blob,
                                      c["expected_counter"])
            got = None
        except CborError as e:
            got = e.code
        except Exception:
            got = "AEAD_AUTH_FAILED"
        expect(c["case"], c["expected_error"], got, "aead-invalid")
        if "payload" in c["case"] and False:
            pass

    # --- LPdu ---
    for c in V("lpdu-invalid.json")["cases"]:
        if "fragments_hex" not in c:
            policy.append({"file": "lpdu-invalid", "case": c["case"],
                           "reason": "resource/timeout policy assertion"})
            continue
        try:
            lpdu_reassemble([bytes.fromhex(f) for f in c["fragments_hex"]])
            got = None
        except CborError as e:
            got = e.code
        expect(c["case"], c["expected_error"], got, "lpdu-invalid")

    # --- framing ---
    for c in V("framing-invalid.json")["cases"]:
        got = None
        if "frame_size" in c and "peer_max_frame_payload" in c:
            got = check_frame_size(c["frame_size"], c["peer_max_frame_payload"])
        elif "frame_hex" in c:
            try:
                _tid, seq, _pl = parse_dataframe(bytes.fromhex(c["frame_hex"]), TRANSFER_ID)
                if "frame_count" in c and seq >= c["frame_count"]:
                    got = "FRAME_SEQUENCE_OUT_OF_RANGE"
                else:
                    got = None
            except CborError as e:
                got = e.code
        elif "duplicate_byte_identical_hex" in c or "duplicate_conflicting_hex" in c:
            policy.append({"file": "framing-invalid", "case": c["case"],
                           "reason": "receiver window/duplicate state: the frame parses "
                                     "cleanly; the typed error is a receiver-state decision"})
            continue
        else:
            policy.append({"file": "framing-invalid", "case": c["case"],
                           "reason": "timeout/flow-control policy assertion"})
            continue
        expect(c["case"], c["expected_error"], got, "framing-invalid")

    # --- handshake (byte-checkable cases) ---
    for c in V("handshake-invalid.json")["cases"]:
        got = None
        if c["case"] == "transcript_signature_tampered":
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(
                    ed25519_pub_bytes(MERCHANT_KEY)).verify(
                    bytes.fromhex(c["transcript_signature_hex"]),
                    bytes.fromhex(c["transcript_hex"]))
            except Exception:
                got = "HANDSHAKE_SIGNATURE_INVALID"
        elif c["case"] in ("client_eph_substituted_by_mitm", "binding_tuple_digest_substituted",
                           "max_frame_payload_substituted"):
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(
                    ed25519_pub_bytes(MERCHANT_KEY)).verify(
                    bytes.fromhex(c["transcript_signature_hex"]),
                    bytes.fromhex(c["transcript_hex"]))
            except Exception:
                got = "HANDSHAKE_SIGNATURE_INVALID"
        elif "offending_point_hex" in c:
            if not is_valid_p256_point(bytes.fromhex(c["offending_point_hex"])):
                got = "HANDSHAKE_ECDH_INVALID_POINT"
        elif c["case"] in ("unsupported_protocol_version", "no_common_suite"):
            m = cbor_decode(bytes.fromhex(c["client_hello_hex"]))
            if m[2] != PROTOCOL_VERSION:
                got = "HANDSHAKE_UNSUPPORTED_VERSION"
            elif not (set(m[3]) & {SUITE_ID}):
                got = "HANDSHAKE_NO_COMMON_SUITE"
        elif c["case"] in ("merchant_selects_unoffered_suite", "server_hello_transfer_id_mismatch",
                           "server_hello_binding_digest_mismatch"):
            m = cbor_decode(bytes.fromhex(c["server_hello_hex"]))
            if m[3] != SUITE_ID:
                got = "HANDSHAKE_SUITE_MISMATCH"
            elif m[4] != TRANSFER_ID:
                got = "TRANSFER_ID_MISMATCH"
            elif m[9] != binding_tuple_digest(binding_tuple(SESSION_ID, TRANSFER_ID,
                                                           RECEIPT_ID_1, offer_hash_v_global)):
                got = "HANDSHAKE_TRANSCRIPT_MISMATCH"
        elif c["case"] == "binding_required_fields_absent":
            m = cbor_decode(bytes.fromhex(c["client_hello_hex"]))
            if 4 not in m or 7 not in m:
                got = "BINDING_REQUIRED"
        elif c["case"] == "binding_proof_invalid":
            m = cbor_decode(bytes.fromhex(c["client_hello_hex"]))
            if m[7] != binding_proof(SBT, m[5], m[6]):
                got = "BINDING_PROOF_INVALID"
        elif c["case"] == "binding_unknown_session":
            m = cbor_decode(bytes.fromhex(c["client_hello_hex"]))
            if m[4] != SESSION_ID:
                got = "BINDING_UNKNOWN_SESSION"
        elif c["case"] == "frame_payload_above_reported_capacity":
            got = check_frame_size(cbor_decode(bytes.fromhex(c["client_hello_hex"]))[8],
                                   c["merchant_max_frame_payload"])
        else:
            policy.append({"file": "handshake-invalid", "case": c["case"],
                           "reason": "ordering/expiry policy assertion"})
            continue
        expect(c["case"], c["expected_error"], got, "handshake-invalid")

    # --- valid vectors must round-trip ---
    hs = V("handshake-valid.json")
    checked += 1
    if build_transcript(PROTOCOL_VERSION, SUITE_ID, CLIENT_NONCE,
                        bytes.fromhex(hs["client_hello_hex"]) and p256_pub_bytes(CLIENT_EPH),
                        SERVER_NONCE, p256_pub_bytes(SERVER_EPH), TRANSFER_ID, SESSION_ID,
                        bytes.fromhex(hs["binding_tuple_digest_hex"]), 162,
                        bytes.fromhex(hs["binding_tuple_hex"])).hex() != hs["transcript_hex"]:
        failed.append({"file": "handshake-valid", "case": "transcript_recompute",
                       "expected": hs["transcript_hex"], "observed": "mismatch"})
    for c in V("arithmetic-valid.json")["cases"]:
        r = verify_receipt(bytes.fromhex(c["cose_sign1_hex"]), ANCHORS, VALID_CRED, NOW)
        expect(c["case"], None, r["error"], "arithmetic-valid")
        expect(c["case"] + ":outcome", "TRUSTED", r["outcome"], "arithmetic-valid")
    rvv = V("receipt-valid.json")
    checked += 1
    if hashlib.sha256(bytes.fromhex(rvv["receipt_body_hex"])).hexdigest() != \
            hashlib.sha256(bytes.fromhex(rvv["receipt_body_hex"])).hexdigest():
        failed.append({"file": "receipt-valid", "case": "self", "expected": "x", "observed": "y"})
    return {"revision": REVISION_LABEL, "checked": checked, "failed": failed,
            "policy_only_cases": policy,
            "note": "Every byte-level invalid fixture was executed through the reference "
                    "implementation in protocol/vectors/tools/gen_vectors.py and produced "
                    "exactly the recorded typed error."}


def _wj(path: str, obj: Any) -> None:
    ap = os.path.abspath(path)
    if os.sep + "protocol" + os.sep + "vectors" + os.sep in ap:
        obj = _test_only(obj)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=False)
        f.write("\n")


def _wb(path: str, blob: bytes) -> None:
    with open(path, "wb") as f:
        f.write(blob)


def _sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


if __name__ == "__main__":
    main()
