"""
BIP32 HD key derivation for JoinMarket wallets.
Implements BIP84 (Native SegWit) derivation paths.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class HDKey:
    """
    Hierarchical Deterministic Key for Bitcoin.
    Implements BIP32 derivation.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, chain_code: bytes, depth: int = 0):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.chain_code = chain_code
        self.depth = depth

    @classmethod
    def from_seed(cls, seed: bytes) -> HDKey:
        """Create master HD key from seed"""
        hmac_result = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key_bytes = hmac_result[:32]
        chain_code = hmac_result[32:]

        key_int = int.from_bytes(key_bytes, "big")
        private_key = ec.derive_private_key(key_int, ec.SECP256K1())

        return cls(private_key, chain_code, depth=0)

    def derive(self, path: str) -> HDKey:
        """
        Derive child key from path notation (e.g., "m/84'/0'/0'/0/0")
        ' indicates hardened derivation
        """
        if not path.startswith("m"):
            raise ValueError("Path must start with 'm'")

        parts = path.split("/")[1:]
        key = self

        for part in parts:
            if not part:
                continue

            hardened = part.endswith("'") or part.endswith("h")
            index_str = part.rstrip("'h")
            index = int(index_str)

            if hardened:
                index += 0x80000000

            key = key._derive_child(index)

        return key

    def _derive_child(self, index: int) -> HDKey:
        """Derive a child key at the given index"""
        hardened = index >= 0x80000000

        if hardened:
            priv_bytes = self.private_key.private_numbers().private_value.to_bytes(32, "big")
            data = b"\x00" + priv_bytes + index.to_bytes(4, "big")
        else:
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
            data = pub_bytes + index.to_bytes(4, "big")

        hmac_result = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        key_offset = hmac_result[:32]
        child_chain = hmac_result[32:]

        parent_key_int = self.private_key.private_numbers().private_value
        offset_int = int.from_bytes(key_offset, "big")

        n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        child_key_int = (parent_key_int + offset_int) % n

        if child_key_int == 0:
            raise ValueError("Invalid child key")

        child_private_key = ec.derive_private_key(child_key_int, ec.SECP256K1())

        return HDKey(child_private_key, child_chain, depth=self.depth + 1)

    def get_private_key_bytes(self) -> bytes:
        """Get private key as 32 bytes"""
        return self.private_key.private_numbers().private_value.to_bytes(32, "big")

    def get_public_key_bytes(self, compressed: bool = True) -> bytes:
        """Get public key bytes"""
        if compressed:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
        else:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

    def get_address(self, network: str = "mainnet") -> str:
        """Get P2WPKH (Native SegWit) address for this key"""
        from jmwallet.wallet.address import pubkey_to_p2wpkh_address

        pubkey_hex = self.get_public_key_bytes(compressed=True).hex()
        return pubkey_to_p2wpkh_address(pubkey_hex, network)

    def sign(self, message: bytes) -> bytes:
        """Sign a message with this key"""
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert BIP39 mnemonic to seed.
    Simple implementation - for production use python-mnemonic library.
    """
    from hashlib import pbkdf2_hmac

    mnemonic_bytes = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")

    seed = pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048, dklen=64)
    return seed
