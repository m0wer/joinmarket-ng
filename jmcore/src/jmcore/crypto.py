"""
Cryptographic primitives for JoinMarket.
"""

import binascii
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14


class CryptoError(Exception):
    pass


def base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")

    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = BASE58_ALPHABET[remainder] + result

    for byte in data:
        if byte == 0:
            result = BASE58_ALPHABET[0] + result
        else:
            break

    return result


def generate_jm_nick(version: int = 5) -> str:
    privkey = secrets.token_bytes(32)
    private_key = ec.derive_private_key(int.from_bytes(privkey, "big"), ec.SECP256K1())
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
    )

    pubkey_hex = binascii.hexlify(pubkey_bytes)
    nick_pkh_raw = hashlib.sha256(pubkey_hex).digest()[:NICK_HASH_LENGTH]
    nick_pkh = base58_encode(nick_pkh_raw)

    nick_pkh += "O" * (NICK_MAX_ENCODED - len(nick_pkh))

    return f"J{version}{nick_pkh}"


class KeyPair:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None):
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256K1())
        self.private_key = private_key
        self.public_key = private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint
        )

    def public_key_hex(self) -> str:
        return self.public_key_bytes().hex()


def verify_signature(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key_bytes)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
