"""
End-to-end encryption wrapper using NaCl public-key authenticated encryption.

This implements the JoinMarket encryption protocol using Diffie-Hellman
key exchange to set up symmetric encryption between makers and takers.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING

from libnacl import public
from loguru import logger

if TYPE_CHECKING:
    from libnacl.public import Box, PublicKey, SecretKey


class NaclError(Exception):
    """Exception for NaCl encryption errors."""

    pass


def init_keypair() -> SecretKey:
    """
    Create a new encryption keypair.

    Returns:
        A NaCl SecretKey object containing the keypair.
    """
    return public.SecretKey()


def get_pubkey(keypair: SecretKey, as_hex: bool = False) -> bytes | str:
    """
    Get the public key from a keypair.

    Args:
        keypair: NaCl keypair object.
        as_hex: Return as hex string if True, otherwise raw bytes.

    Returns:
        Public key as hex string or bytes.
    """
    if not isinstance(keypair, public.SecretKey):
        raise NaclError("Object is not a nacl keypair")
    if as_hex:
        return keypair.hex_pk().decode("ascii")
    return keypair.pk


def init_pubkey(hexpk: str) -> PublicKey:
    """
    Create a public key object from a hex-encoded string.

    Args:
        hexpk: Hex-encoded 32-byte public key.

    Returns:
        NaCl PublicKey object.
    """
    try:
        bin_pk = binascii.unhexlify(hexpk)
    except (TypeError, binascii.Error) as exc:
        raise NaclError("Invalid hex format") from exc
    if len(bin_pk) != 32:
        raise NaclError("Public key must be 32 bytes")
    return public.PublicKey(bin_pk)


def create_encryption_box(keypair: SecretKey, counterparty_pk: PublicKey) -> Box:
    """
    Create an encryption box for communicating with a counterparty.

    Args:
        keypair: Our NaCl keypair.
        counterparty_pk: Counterparty's public key.

    Returns:
        NaCl Box object for encryption/decryption.
    """
    if not isinstance(counterparty_pk, public.PublicKey):
        raise NaclError("Object is not a public key")
    if not isinstance(keypair, public.SecretKey):
        raise NaclError("Object is not a nacl keypair")
    return public.Box(keypair.sk, counterparty_pk)


def encrypt_encode(message: bytes | str, box: Box) -> str:
    """
    Encrypt a message and encode as base64 for transmission.

    Args:
        message: Plaintext message (bytes or string).
        box: NaCl encryption box.

    Returns:
        Base64-encoded ciphertext.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    encrypted = box.encrypt(message)
    return base64.b64encode(encrypted).decode("ascii")


def decode_decrypt(message: str, box: Box) -> bytes:
    """
    Decode and decrypt a message received from counterparty.

    Args:
        message: Base64-encoded ciphertext.
        box: NaCl encryption box.

    Returns:
        Decrypted plaintext as bytes.
    """
    decoded = base64.b64decode(message)
    return box.decrypt(decoded)


class CryptoSession:
    """
    Manages encryption state for a coinjoin session with a taker.
    """

    def __init__(self) -> None:
        """Initialize a new crypto session with a fresh keypair."""
        self.keypair: SecretKey = init_keypair()
        self.box: Box | None = None
        self.counterparty_pubkey: str = ""

    def get_pubkey_hex(self) -> str:
        """Get our public key as hex string."""
        pk = get_pubkey(self.keypair, as_hex=True)
        assert isinstance(pk, str)
        return pk

    def setup_encryption(self, counterparty_pubkey_hex: str) -> None:
        """
        Set up encryption with a counterparty's public key.

        Args:
            counterparty_pubkey_hex: Counterparty's public key in hex.
        """
        try:
            counterparty_pk = init_pubkey(counterparty_pubkey_hex)
            self.box = create_encryption_box(self.keypair, counterparty_pk)
            self.counterparty_pubkey = counterparty_pubkey_hex
            logger.debug("Set up encryption box with counterparty")
        except NaclError as e:
            logger.error(f"Failed to set up encryption: {e}")
            raise

    def encrypt(self, message: str) -> str:
        """
        Encrypt a message for the counterparty.

        Args:
            message: Plaintext message.

        Returns:
            Base64-encoded encrypted message.
        """
        if self.box is None:
            raise NaclError("Encryption not set up - call setup_encryption first")
        return encrypt_encode(message, self.box)

    def decrypt(self, message: str) -> str:
        """
        Decrypt a message from the counterparty.

        Args:
            message: Base64-encoded encrypted message.

        Returns:
            Decrypted plaintext.
        """
        if self.box is None:
            raise NaclError("Encryption not set up - call setup_encryption first")
        decrypted = decode_decrypt(message, self.box)
        return decrypted.decode("utf-8")

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption has been set up."""
        return self.box is not None
