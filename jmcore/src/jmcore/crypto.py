"""
Cryptographic primitives for JoinMarket.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class CryptoError(Exception):
    pass


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
