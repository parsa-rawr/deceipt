"""Independent DeceiptReceiptV1 / COSE_Sign1 verifier.

Implements the normative rules of `docs/protocol/receipt-v1.md`,
`docs/protocol/trust.md` §4 and `docs/protocol/verification.md` §§1-3 directly,
with no reference to the implementation under test. Returns a typed error name
(from `protocol/vectors/errors.json`) or an outcome name, matching the frozen
fixtures.

The verifier reports the FIRST failing gate in the verification order, so it can
be compared to `expected_error` on the frozen cases.
"""

from __future__ import annotations

import unicodedata
from typing import Any, Optional

from . import cbor as C
from . import crypto
from .cbor import DEFAULT_LIMITS, CborError

RECEIPT_CONTENT_TYPE = "application/deceipt-receipt+cbor"
MAX_RECEIPT_BYTES = 65536
MAX_CRED_BYTES = 1024
CLOCK_SKEW_MAX_S = 300
KNOWN_EXTENSIONS: set[str] = set()

# bounds-v1 receipt block
MAX_MONETARY_ABS = 1_000_000_000_000_000
MAX_UNIT_PRICE_ABS = 1_000_000_000_000
MAX_QTY_VALUE_ABS = 1_000_000
MAX_QTY_SCALE = 9
MAX_ARITH_PRODUCT = 4611686018427387904
MAX_TAX_RATE_PPM = 999_999
MIN_ISSUED_AT = 1_577_836_800
MAX_ISSUED_AT = 4_102_444_800
MAX_LINES = 256
MAX_DISCOUNTS = 64
MAX_TAXES = 64
MAX_TENDERS = 32
MAX_EXTENSIONS = 32
MAX_MODIFIERS = 16
MAX_ADDRESS_LINES = 8
TEXT_LIMITS = {
    "description": 512,
    "display_name": 128,
    "short": 64,
    "unit": 16,
}

BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
CURRENCY_EXPONENT = {
    "CAD": 2, "USD": 2, "EUR": 2, "GBP": 2, "AUD": 2, "NZD": 2, "CHF": 2,
    "MXN": 2, "BRL": 2, "SGD": 2, "HKD": 2, "SEK": 2, "NOK": 2, "DKK": 2,
    "PLN": 2, "CZK": 2, "TRY": 2, "ZAR": 2, "INR": 2, "CNY": 2, "HUF": 2,
    "JPY": 0, "KRW": 0, "VND": 0, "CLP": 0, "ISK": 0,
    "KWD": 3, "BHD": 3, "OMR": 3, "JOD": 3, "TND": 3, "IQD": 3, "LYD": 3,
}


class ReceiptError(Exception):
    def __init__(self, name: str, detail: str = "") -> None:
        self.name = name
        self.detail = detail
        super().__init__(name)


def round_half_away(n: int, d: int) -> int:
    """round_half_away(n, d) = sign(n) * floor((2|n| + d) / (2d)), d > 0."""
    sign = -1 if n < 0 else 1
    return sign * ((2 * abs(n) + d) // (2 * d))


def check_text(value: str, limit: int) -> None:
    if len(value.encode("utf-8")) > limit:
        raise ReceiptError("RECEIPT_TEXT_INVALID")
    if unicodedata.normalize("NFC", value) != value:
        raise ReceiptError("RECEIPT_TEXT_INVALID")
    for ch in value:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            raise ReceiptError("RECEIPT_TEXT_INVALID")
        if cp in BIDI_CONTROLS:
            raise ReceiptError("RECEIPT_TEXT_INVALID")
        if 0xD800 <= cp <= 0xDFFF:
            raise ReceiptError("RECEIPT_TEXT_INVALID")


def _require(cond: bool, name: str) -> None:
    if not cond:
        raise ReceiptError(name)


# ---------------------------------------------------------------------------
# COSE_Sign1 container (steps 8-9)
# ---------------------------------------------------------------------------


def parse_container(raw: bytes) -> tuple[dict, dict, bytes, bytes]:
    """Parse the 4-element COSE_Sign1 array, enforcing container rules.

    Raises CBOR_* errors from the codec and RECEIPT_* container errors.
    """
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("RECEIPT_SIZE_EXCEEDED")
    # Structural parse with the PERMISSIVE decoder so we can tell a detached
    # payload (CBOR null, CBOR_UNSUPPORTED_TYPE under strict rules) from a
    # non-canonical container; the canonical check below is separate.
    try:
        arr, consumed = C.decode_lenient_prefix(raw)
    except CborError as e:
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if consumed != len(raw):
        raise ReceiptError("CBOR_MALFORMED")
    if not isinstance(arr, list):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if any(e is C._Permissive.NULL or e is C._Permissive.UNDEFINED for e in arr):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if len(arr) != 4:
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")

    protected_bstr, unprotected, payload, signature = arr
    if not isinstance(protected_bstr, bytes):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if not isinstance(payload, bytes):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if not isinstance(unprotected, dict):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    if len(unprotected) != 0:
        raise ReceiptError("RECEIPT_UNKNOWN_HEADER")

    # Container canonicality: the parsed array MUST re-encode to the received
    # bytes. Checked before signature; a payload whose *content* is
    # non-canonical is reported later as RECEIPT_NONCANONICAL at body decode.
    if not C.is_canonical(raw):
        raise ReceiptError("RECEIPT_NONCANONICAL")

    try:
        prot = C.decode(protected_bstr)
    except CborError as e:
        raise ReceiptError(e.name)
    if not isinstance(prot, dict):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    kid = prot.get(4)
    _require(isinstance(kid, bytes) and len(kid) == 16, "RECEIPT_CONTAINER_MALFORMED")
    return prot, unprotected, payload, signature


def check_protected_header(prot: dict) -> None:
    """Step 9: supported suite and critical headers."""
    for label in prot:
        if label not in (1, 3, 4):
            raise ReceiptError("RECEIPT_UNKNOWN_HEADER")
    _require(2 not in prot, "RECEIPT_UNKNOWN_HEADER")  # crit
    if prot.get(1) != -8:
        raise ReceiptError("RECEIPT_UNSUPPORTED_ALGORITHM")
    if prot.get(3) != RECEIPT_CONTENT_TYPE:
        raise ReceiptError("RECEIPT_UNSUPPORTED_ALGORITHM")


def decode_body(payload: bytes) -> dict:
    """Step 8: strict canonical decode of the receipt body (non-canonical ->
    RECEIPT_NONCANONICAL)."""
    try:
        body = C.decode(payload)
    except CborError as e:
        if e.name == "CBOR_NONCANONICAL":
            raise ReceiptError("RECEIPT_NONCANONICAL")
        raise ReceiptError(e.name)
    if not isinstance(body, dict):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    return body


def sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    return C.encode(["Signature1", protected_bstr, b"", payload])


# ---------------------------------------------------------------------------
# Receipt body validation (step 12)
# ---------------------------------------------------------------------------


def _validate_body(body: dict) -> None:
    if not isinstance(body, dict):
        raise ReceiptError("RECEIPT_CONTAINER_MALFORMED")
    known = set(range(1, 22))
    for k in body:
        if not isinstance(k, int) or k not in known:
            raise ReceiptError("RECEIPT_UNKNOWN_FIELD")
    for req in (1, 2, 3, 4, 6, 8, 9, 15, 16):
        _require(req in body, "RECEIPT_SEMANTIC_INVALID")
    _require(body[1] == 1, "RECEIPT_UNSUPPORTED_VERSION")
    kind = body[2]
    _require(kind in (1, 2, 3), "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(body[3], bytes) and len(body[3]) == 16, "RECEIPT_SEMANTIC_INVALID")
    issued = body[4]
    _require(isinstance(issued, int) and MIN_ISSUED_AT <= issued <= MAX_ISSUED_AT, "RECEIPT_SEMANTIC_INVALID")
    if 5 in body:
        # NOTE (A6 finding F-05): receipt-v1.md/CDDL/fields say "-840..840"
        # (minutes), but the frozen valid vectors carry -14400 (seconds) and
        # A3 enforces +/-50400; the vector is authoritative for the runner.
        _require(isinstance(body[5], int) and -50400 <= body[5] <= 50400, "RECEIPT_SEMANTIC_INVALID")
    # merchant
    m = body[6]
    _require(isinstance(m, dict) and {1, 2, 3} <= set(m), "RECEIPT_SEMANTIC_INVALID")
    for k in m:
        _require(k in (1, 2, 3), "RECEIPT_UNKNOWN_FIELD")
    _require(isinstance(m[1], bytes) and len(m[1]) == 16, "RECEIPT_SEMANTIC_INVALID")
    check_text(m[2], TEXT_LIMITS["display_name"])
    check_text(m[3], TEXT_LIMITS["short"])
    # currency
    cur = body[8]
    _require(isinstance(cur, str) and len(cur) == 3, "RECEIPT_UNSUPPORTED_CURRENCY")
    _require(cur in CURRENCY_EXPONENT, "RECEIPT_UNSUPPORTED_CURRENCY")
    # lines
    lines = body[9]
    _require(isinstance(lines, list) and len(lines) <= MAX_LINES, "RECEIPT_SEMANTIC_INVALID")
    for ln in lines:
        _validate_line(ln)
    if 10 in body:
        _require(isinstance(body[10], list) and len(body[10]) <= MAX_DISCOUNTS, "RECEIPT_SEMANTIC_INVALID")
        for d in body[10]:
            _validate_discount(d)
    if 11 in body:
        _require(isinstance(body[11], list) and len(body[11]) <= MAX_TAXES, "RECEIPT_SEMANTIC_INVALID")
        for t in body[11]:
            _validate_tax(t)
    for lbl in (12, 13):
        if lbl in body:
            _require(isinstance(body[lbl], int) and body[lbl] >= 0 and abs(body[lbl]) <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    if 14 in body:
        _require(isinstance(body[14], int) and abs(body[14]) <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    if 21 in body:
        exts = body[21]
        _require(isinstance(exts, list) and len(exts) <= MAX_EXTENSIONS, "RECEIPT_SEMANTIC_INVALID")
        for e in exts:
            _validate_extension(e)
    _validate_totals(body)
    _validate_payment(body)


def _validate_line(ln: dict) -> None:
    _require(isinstance(ln, dict), "RECEIPT_SEMANTIC_INVALID")
    for k in ln:
        _require(k in range(1, 11), "RECEIPT_UNKNOWN_FIELD")
    for req in (1, 2, 3, 4, 5):
        _require(req in ln, "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(ln[1], int) and ln[1] >= 1, "RECEIPT_SEMANTIC_INVALID")
    check_text(ln[2], TEXT_LIMITS["description"])
    q = ln[3]
    _require(isinstance(q, dict) and {1, 2} <= set(q), "RECEIPT_SEMANTIC_INVALID")
    scale, value = q[1], q[2]
    _require(isinstance(scale, int) and 0 <= scale <= MAX_QTY_SCALE, "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(value, int) and abs(value) <= MAX_QTY_VALUE_ABS, "RECEIPT_SEMANTIC_INVALID")
    if 3 in q:
        check_text(q[3], TEXT_LIMITS["unit"])
    unit = ln[4]
    _require(isinstance(unit, int) and abs(unit) <= MAX_UNIT_PRICE_ABS, "RECEIPT_MONETARY_RANGE")
    amount = ln[5]
    _require(isinstance(amount, int) and 0 <= amount <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    product = unit * value
    _require(abs(product) <= MAX_ARITH_PRODUCT, "RECEIPT_MONETARY_RANGE")
    expected = round_half_away(product, 10 ** scale)
    _require(amount == expected, "RECEIPT_ARITHMETIC_MISMATCH")
    if 6 in ln:
        _require(isinstance(ln[6], int) and 0 <= ln[6] <= amount, "RECEIPT_SEMANTIC_INVALID")
    if 9 in ln:
        check_text(ln[9], TEXT_LIMITS["short"])
    if 10 in ln:
        _require(isinstance(ln[10], list) and len(ln[10]) <= MAX_MODIFIERS, "RECEIPT_SEMANTIC_INVALID")


def _validate_discount(d: dict) -> None:
    _require(isinstance(d, dict), "RECEIPT_SEMANTIC_INVALID")
    for k in d:
        _require(k in range(1, 8), "RECEIPT_UNKNOWN_FIELD")
    for req in (1, 2, 4):
        _require(req in d, "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(d[2], int) and 0 <= d[2] <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    _require(d[4] in (1, 2), "RECEIPT_SEMANTIC_INVALID")
    if 3 in d:
        check_text(d[3], TEXT_LIMITS["display_name"])
    if 6 in d:
        _require(7 in d, "RECEIPT_SEMANTIC_INVALID")
        _require(0 <= d[6] <= MAX_TAX_RATE_PPM, "RECEIPT_SEMANTIC_INVALID")
        _require(d[2] == round_half_away(d[7] * d[6], 1_000_000), "RECEIPT_ARITHMETIC_MISMATCH")


def _validate_tax(t: dict) -> None:
    _require(isinstance(t, dict), "RECEIPT_SEMANTIC_INVALID")
    for k in t:
        _require(k in range(1, 9), "RECEIPT_UNKNOWN_FIELD")
    for req in (1, 3, 4, 5):
        _require(req in t, "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(t[3], int) and 0 <= t[3] <= MAX_TAX_RATE_PPM, "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(t[4], int) and 0 <= t[4] <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    _require(isinstance(t[5], int) and 0 <= t[5] <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    _require(t[5] == round_half_away(t[4] * t[3], 1_000_000), "RECEIPT_ARITHMETIC_MISMATCH")
    if 8 in t:
        _require(isinstance(t[8], bool), "RECEIPT_SEMANTIC_INVALID")
        if t[8]:
            _require(t[4] == 0, "RECEIPT_ARITHMETIC_MISMATCH")


def _validate_extension(e: dict) -> None:
    _require(isinstance(e, dict) and {1, 2} <= set(e), "RECEIPT_SEMANTIC_INVALID")
    for k in e:
        _require(k in (1, 2, 3), "RECEIPT_UNKNOWN_FIELD")
    key = e[1]
    _require(isinstance(key, str), "RECEIPT_SEMANTIC_INVALID")
    check_text(key, TEXT_LIMITS["short"])
    critical = e[2]
    _require(isinstance(critical, bool), "RECEIPT_SEMANTIC_INVALID")
    if 3 in e:
        _require(
            isinstance(e[3], (bytes, str, int, list, dict)) and not isinstance(e[3], bool),
            "RECEIPT_SEMANTIC_INVALID",
        )
    if critical and key not in KNOWN_EXTENSIONS:
        raise ReceiptError("RECEIPT_UNKNOWN_CRITICAL_EXTENSION")


def _validate_totals(body: dict) -> None:
    tot = body[15]
    _require(isinstance(tot, dict), "RECEIPT_SEMANTIC_INVALID")
    for k in tot:
        _require(k in range(1, 9), "RECEIPT_UNKNOWN_FIELD")
    for req in (1, 2, 3, 4, 8):
        _require(req in tot, "RECEIPT_SEMANTIC_INVALID")
    subtotal = sum(ln[5] for ln in body[9])
    discount_total = sum(d[2] for d in body.get(10, []))
    taxes = body.get(11, [])
    tax_total = sum(t[5] for t in taxes)
    tax_added = sum(t[5] for t in taxes if t.get(8) is not True)
    tip = body.get(12, 0)
    service = body.get(13, 0)
    rounding = body.get(14, 0)
    _require(tot[1] == subtotal, "RECEIPT_ARITHMETIC_MISMATCH")
    _require(tot[2] == discount_total, "RECEIPT_ARITHMETIC_MISMATCH")
    _require(tot[3] == tax_total, "RECEIPT_ARITHMETIC_MISMATCH")
    _require(tot[8] == tax_added, "RECEIPT_ARITHMETIC_MISMATCH")
    total = subtotal - discount_total + tax_added + tip + service + rounding
    _require(tot[4] == total, "RECEIPT_ARITHMETIC_MISMATCH")
    _require(tot[4] >= 0, "RECEIPT_SEMANTIC_INVALID")
    if 5 in tot:
        _require(tot[5] == tip, "RECEIPT_ARITHMETIC_MISMATCH")
    if 6 in tot:
        _require(tot[6] == service, "RECEIPT_ARITHMETIC_MISMATCH")
    if 7 in tot:
        _require(tot[7] == rounding, "RECEIPT_ARITHMETIC_MISMATCH")
    for k in (1, 2, 3, 4):
        _require(isinstance(tot[k], int) and 0 <= tot[k] <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")


def _validate_payment(body: dict) -> None:
    pay = body[16]
    _require(isinstance(pay, dict), "RECEIPT_SEMANTIC_INVALID")
    for k in pay:
        _require(k in range(1, 6), "RECEIPT_UNKNOWN_FIELD")
    _require(1 in pay and 2 in pay, "RECEIPT_SEMANTIC_INVALID")
    status = pay[1]
    _require(status in (1, 2, 3, 4, 5), "RECEIPT_SEMANTIC_INVALID")
    _require(isinstance(pay[2], int) and 0 <= pay[2] <= MAX_MONETARY_ABS, "RECEIPT_MONETARY_RANGE")
    total = body[15][4]
    if 3 in pay:
        _require(pay[3] == max(0, pay[2] - total), "RECEIPT_ARITHMETIC_MISMATCH")
    tenders = pay.get(4, [])
    _require(isinstance(tenders, list) and len(tenders) <= MAX_TENDERS, "RECEIPT_SEMANTIC_INVALID")
    if tenders:
        _require(sum(t[2] for t in tenders) == pay[2], "RECEIPT_ARITHMETIC_MISMATCH")
    kind = body[2]
    if kind == 1:
        _require(status in (1, 2, 3), "RECEIPT_SEMANTIC_INVALID")
        if status == 1:
            _require(pay[2] >= total, "RECEIPT_ARITHMETIC_MISMATCH")
        elif status == 2:
            _require(pay[2] < total, "RECEIPT_ARITHMETIC_MISMATCH")
        else:
            _require(pay[2] == 0, "RECEIPT_ARITHMETIC_MISMATCH")
    elif kind == 2:
        _require(status == 4, "RECEIPT_SEMANTIC_INVALID")
        _require(not tenders, "RECEIPT_SEMANTIC_INVALID")
        _require(pay[2] == total, "RECEIPT_ARITHMETIC_MISMATCH")
        _require(17 in body, "RECEIPT_SEMANTIC_INVALID")
    elif kind == 3:
        _require(status == 5, "RECEIPT_SEMANTIC_INVALID")
        _require(not tenders, "RECEIPT_SEMANTIC_INVALID")
        _require(pay[2] == 0, "RECEIPT_ARITHMETIC_MISMATCH")
        _require(18 in body, "RECEIPT_SEMANTIC_INVALID")


# ---------------------------------------------------------------------------
# Credential verification (trust.md §4)
# ---------------------------------------------------------------------------


def _cose_container(raw: bytes, max_bytes: int, size_err: str, bad_err: str):
    """Structural COSE_Sign1 parse for either receipt or credential.

    Enforces size, 4-element array, bstr types, empty unprotected, canonical
    container. Raises ReceiptError(size_err|bad_err|...) accordingly.
    """
    if len(raw) > max_bytes:
        raise ReceiptError(size_err)
    try:
        arr, consumed = C.decode_lenient_prefix(raw)
    except CborError:
        raise ReceiptError(bad_err)
    if consumed != len(raw) or not isinstance(arr, list) or len(arr) != 4:
        raise ReceiptError(bad_err)
    if any(e is C._Permissive.NULL or e is C._Permissive.UNDEFINED for e in arr):
        raise ReceiptError(bad_err)
    protected_bstr, unprotected, payload, signature = arr
    if not isinstance(protected_bstr, bytes) or not isinstance(payload, bytes):
        raise ReceiptError(bad_err)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ReceiptError(bad_err)
    if not isinstance(unprotected, dict) or len(unprotected) != 0:
        raise ReceiptError(bad_err)
    if not C.is_canonical(raw):
        raise ReceiptError(bad_err)
    if not C.is_canonical(protected_bstr):
        raise ReceiptError(bad_err)
    prot = C.decode(protected_bstr)
    if not isinstance(prot, dict):
        raise ReceiptError(bad_err)
    return prot, payload, signature, protected_bstr


def verify_credential(cred_bytes: bytes, anchors: dict[str, bytes], now: int) -> tuple[Optional[str], str]:
    """Return (error_name_or_None, trust) where trust in {authenticated, unknown_issuer, none}."""
    try:
        prot, payload_bstr, sig, prot_bstr = _cose_container(
            cred_bytes, MAX_CRED_BYTES, "CREDENTIAL_MALFORMED", "CREDENTIAL_MALFORMED"
        )
    except ReceiptError:
        return "CREDENTIAL_MALFORMED", "none"
    if prot.get(3) != "application/deceipt-credential+cbor":
        return "CREDENTIAL_MALFORMED", "none"
    kid = prot.get(4)
    try:
        body = C.decode(payload_bstr)
    except CborError:
        return "CREDENTIAL_MALFORMED", "none"
    if not isinstance(body, dict):
        return "CREDENTIAL_MALFORMED", "none"
    for k in body:
        if k not in range(1, 12):
            return "CREDENTIAL_MALFORMED", "none"
    if body.get(1) != 1 or kid != body.get(2):
        return "CREDENTIAL_MALFORMED", "none"
    if not (isinstance(body.get(3), bytes) and len(body[3]) == 16):
        return "CREDENTIAL_MALFORMED", "none"
    if not (isinstance(body.get(4), bytes) and len(body[4]) == 16):
        return "CREDENTIAL_MALFORMED", "none"
    if not (isinstance(body.get(5), bytes) and len(body[5]) == 32):
        return "CREDENTIAL_MALFORMED", "none"
    for lbl in (6, 7, 8, 11):
        if not isinstance(body.get(lbl), int):
            return "CREDENTIAL_MALFORMED", "none"
    if body[7] <= body[6]:
        return "CREDENTIAL_MALFORMED", "none"
    for lbl in (9, 10):
        try:
            check_text(body[lbl], TEXT_LIMITS["display_name"])
        except ReceiptError:
            return "CREDENTIAL_MALFORMED", "none"
    issuer_id = body[2]
    if issuer_id not in anchors:
        return "CREDENTIAL_UNKNOWN_ISSUER", "unknown_issuer"
    anchor_pub = anchors[issuer_id]
    ss = sig_structure(prot_bstr, payload_bstr)
    if not crypto.ed25519_verify(anchor_pub, sig, ss):
        return "CREDENTIAL_SIGNATURE_INVALID", "none"
    if now < body[6] - CLOCK_SKEW_MAX_S:
        return "CREDENTIAL_NOT_YET_VALID", "authenticated"
    if now >= body[7] + CLOCK_SKEW_MAX_S:
        return "CREDENTIAL_EXPIRED", "authenticated"
    return None, "authenticated"


def credential_body(cred_bytes: bytes) -> Optional[dict]:
    try:
        _, payload_bstr, _, _ = _cose_container(
            cred_bytes, MAX_CRED_BYTES, "CREDENTIAL_MALFORMED", "CREDENTIAL_MALFORMED"
        )
        b = C.decode(payload_bstr)
        return b if isinstance(b, dict) else None
    except (ReceiptError, CborError):
        return None


CAPABILITY_BIT = {1: 0x01, 2: 0x02, 3: 0x04}


# ---------------------------------------------------------------------------
# Full receipt verification (steps 8-15)
# ---------------------------------------------------------------------------


def decode_receipt(raw: bytes) -> tuple[bytes, dict, dict, bytes, bytes]:
    """Parse only; returns (protected_bstr, prot, body, payload, signature)."""
    prot, unprot, payload, sig = parse_container(raw)
    body = decode_body(payload)
    arr, _ = C.decode_lenient_prefix(raw)
    return arr[0], prot, body, payload, sig


def verify_receipt(
    raw: bytes,
    anchors: dict[str, bytes],
    now: int,
    session_credential: Optional[bytes] = None,
    offer: Optional[bytes] = None,
    seen_receipt_ids: Optional[dict[bytes, bytes]] = None,
) -> dict:
    """Return {'outcome', 'error', 'signature_valid', 'key_authorized', ...}."""
    result = {
        "signature_valid": False,
        "key_authorized": False,
        "credential_temporally_acceptable": False,
        "semantically_valid": False,
        "unique_locally": True,
        "outcome": "REJECTED",
        "error": None,
    }
    try:
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ReceiptError("RECEIPT_SIZE_EXCEEDED")
        prot, unprot, payload, sig = parse_container(raw)
        check_protected_header(prot)
        body = decode_body(payload)
        _validate_body(body)
        result["semantically_valid"] = True

        cred_bytes = body.get(20)
        if not isinstance(cred_bytes, bytes):
            cred_bytes = b""
        sess_ok = session_credential is None or cred_bytes == session_credential

        # step 10/11: verify credential, then receipt signature vs device key
        cred_err, trust = verify_credential(cred_bytes, anchors, now)
        cbody = credential_body(cred_bytes)
        _arr, _ = C.decode_lenient_prefix(raw)
        prot_bstr = _arr[0]
        ss = sig_structure(prot_bstr, payload)

        if cred_err == "CREDENTIAL_UNKNOWN_ISSUER":
            if cbody is None:
                raise ReceiptError("RECEIPT_CREDENTIAL_MISMATCH")
            if not crypto.ed25519_verify(cbody[5], sig, ss):
                raise ReceiptError("RECEIPT_SIGNATURE_INVALID")
            if not sess_ok:
                raise ReceiptError("RECEIPT_CREDENTIAL_MISMATCH")
            result["signature_valid"] = True
            result["outcome"] = "UNVERIFIED_UNKNOWN_ISSUER"
            result["error"] = "CREDENTIAL_UNKNOWN_ISSUER"
            return result
        if cred_err is not None:
            if cred_err == "CREDENTIAL_MALFORMED" and (cbody is None or not sess_ok):
                raise ReceiptError("RECEIPT_CREDENTIAL_MISMATCH")
            raise ReceiptError(cred_err)
        if cbody is None:
            raise ReceiptError("RECEIPT_CREDENTIAL_MISMATCH")
        if not crypto.ed25519_verify(cbody[5], sig, ss):
            raise ReceiptError("RECEIPT_SIGNATURE_INVALID")
        if not sess_ok:
            raise ReceiptError("RECEIPT_CREDENTIAL_MISMATCH")
        result["signature_valid"] = True
        result["credential_temporally_acceptable"] = True
        if prot[4] != cbody[4]:
            raise ReceiptError("RECEIPT_KEY_NOT_AUTHORIZED")
        if body[6][1] != cbody[3]:
            raise ReceiptError("RECEIPT_KEY_NOT_AUTHORIZED")
        needed = CAPABILITY_BIT.get(body[2])
        if needed is not None and not (cbody[8] & needed):
            raise ReceiptError("CREDENTIAL_CAPABILITY_MISSING")
        result["key_authorized"] = True
        if body[4] > now + CLOCK_SKEW_MAX_S:
            raise ReceiptError("RECEIPT_ISSUED_IN_FUTURE")
        if not (cbody[6] <= body[4] < cbody[7]):
            raise ReceiptError("RECEIPT_OUTSIDE_KEY_VALIDITY")
        rid = body[3]
        if seen_receipt_ids and rid in seen_receipt_ids:
            if seen_receipt_ids[rid] == payload:
                result["outcome"] = "ALREADY_IMPORTED_IDENTICAL"
                return result
            result["unique_locally"] = False
            raise ReceiptError("RECEIPT_DUPLICATE_CONFLICT")
        if offer is not None and not _offer_matches(body, offer):
            raise ReceiptError("WRONG_TRANSACTION")
        result["outcome"] = "TRUSTED"
        result["error"] = None
        return result
    except ReceiptError as e:
        result["error"] = e.name
        result["outcome"] = "REJECTED"
        return result
    except CborError as e:
        result["error"] = e.name
        result["outcome"] = "REJECTED"
        return result


def _offer_matches(body: dict, offer_bytes: bytes) -> bool:
    """framing.md section 7 rule 3: the verified receipt MUST match the offer on
    receipt_id, kind, total_minor, currency, issued_at, merchant_id,
    merchant_reference. (The receipt carries no transfer_id; that is a session
    member, not a receipt member.)"""
    offer = C.decode(offer_bytes)
    if not isinstance(offer, dict):
        return False
    checks = [
        (offer.get(3), body[3]),               # receipt_id
        (offer.get(4), body[6][3]),            # merchant_reference
        (offer.get(5), body[15][4]),           # total_amount_minor vs totals.total
        (offer.get(6), body[8]),               # currency
        (offer.get(7), body[4]),               # issued_at
        (offer.get(8), body[2]),               # kind
        (offer.get(10), body[6][1]),           # merchant_id
    ]
    for a, b in checks:
        if a != b:
            return False
    return True
