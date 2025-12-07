"""
Pytest configuration and fixtures for maker tests.
"""

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


@pytest.fixture
def test_mnemonic() -> str:
    """Test mnemonic (BIP39 test vector)"""
    return (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )


@pytest.fixture
def test_network() -> str:
    """Test network"""
    return "regtest"


@pytest.fixture
def test_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a test ECDSA private key for fidelity bond tests."""
    return ec.generate_private_key(ec.SECP256K1(), default_backend())


@pytest.fixture
def test_pubkey(test_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Get compressed public key from test private key."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = test_private_key.public_key()
    uncompressed = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    # Compress: 02 if y is even, 03 if y is odd
    x = uncompressed[1:33]
    y_last_byte = uncompressed[-1]
    prefix = b"\x02" if y_last_byte % 2 == 0 else b"\x03"
    return prefix + x
