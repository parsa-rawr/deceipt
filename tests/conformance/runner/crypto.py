"""Independent crypto primitives for the conformance runner.

Thin wrappers over `cryptography` (OpenSSL) so every expectation is recomputed
from frozen inputs with an implementation wholly independent of A3/A4/A5.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def ed25519_public_from_seed(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def p256_valid_point(point: bytes) -> bool:
    """True iff `point` is a valid uncompressed P-256 point (0x04 || X || Y)."""
    if len(point) != 65 or point[0] != 0x04:
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        return True
    except Exception:
        return False


def p256_ecdh(private_scalar: bytes, peer_point: bytes) -> Optional[bytes]:
    """Return the 32-byte X coordinate of the ECDH shared secret, or None."""
    try:
        priv = ec.derive_private_key(int.from_bytes(private_scalar, "big"), ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_point)
        return priv.exchange(ec.ECDH(), peer)
    except Exception:
        return None


def p256_public_from_scalar(private_scalar: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    priv = ec.derive_private_key(int.from_bytes(private_scalar, "big"), ec.SECP256R1())
    return priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aes_gcm_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_open(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> Optional[bytes]:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception:
        return None


def nonce_from_counter(counter: int) -> bytes:
    """nonce = 00000000 (4 reserved zero bytes) || u64_be(counter)."""
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")
