"""
Pytest configuration and fixtures for jmwallet tests.
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from _jmwallet_test_helpers import TEST_MNEMONIC

from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
from jmwallet.wallet.service import WalletService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def test_mnemonic() -> str:
    """Test mnemonic (BIP39 test vector)."""
    return TEST_MNEMONIC


@pytest.fixture
def test_network() -> str:
    """Test network."""
    return "regtest"


@pytest.fixture
def temp_data_dir() -> Generator[Path, None, None]:
    """Create a temporary data directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_backend() -> DescriptorWalletBackend:
    """Create a DescriptorWalletBackend with _wallet_loaded=True."""
    backend = DescriptorWalletBackend(wallet_name="test_wallet")
    backend._wallet_loaded = True
    return backend


@pytest.fixture
def mock_backend_imported(mock_backend: DescriptorWalletBackend) -> DescriptorWalletBackend:
    """Create a DescriptorWalletBackend with both _wallet_loaded and _descriptors_imported."""
    mock_backend._descriptors_imported = True
    return mock_backend


@pytest.fixture
def wallet_service(
    test_mnemonic: str, mock_backend_imported: DescriptorWalletBackend
) -> WalletService:
    """Create a WalletService with default test config (mainnet, 5 mixdepths)."""
    return WalletService(
        mnemonic=test_mnemonic,
        backend=mock_backend_imported,
        network="mainnet",
        mixdepth_count=5,
    )
