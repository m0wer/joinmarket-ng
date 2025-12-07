"""
Pytest configuration and fixtures for jmwallet tests.
"""

import pytest


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
