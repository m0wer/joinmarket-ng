"""
Tests for wallet address info functionality.

Tests the extended wallet info feature that shows detailed address
information including derivation paths, statuses, and xpubs.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, Mock

import pytest

from jmwallet.history import (
    TransactionHistoryEntry,
    append_history_entry,
    get_address_history_types,
)
from jmwallet.wallet.models import UTXOInfo
from jmwallet.wallet.service import WalletService


class TestAddressStatusDetermination:
    """Tests for address status determination logic."""

    @pytest.fixture
    def mock_backend(self):
        """Create a mock backend."""
        backend = Mock()
        backend.get_utxos = AsyncMock(return_value=[])
        backend.close = AsyncMock()
        return backend

    @pytest.fixture
    def wallet(self, mock_backend, test_mnemonic, test_network):
        """Create a wallet for testing."""
        return WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network=test_network,
            mixdepth_count=5,
        )

    def test_determine_status_deposit(self, wallet):
        """Test deposit status for external address with funds."""
        status = wallet._determine_address_status(
            address="bc1q_external",
            balance=100000,
            is_external=True,
            used_addresses=set(),
            history_addresses={},
        )
        assert status == "deposit"

    def test_determine_status_cj_out(self, wallet):
        """Test cj-out status for CoinJoin output address with funds."""
        status = wallet._determine_address_status(
            address="bc1q_internal",
            balance=50000,
            is_external=False,
            used_addresses={"bc1q_internal"},
            history_addresses={"bc1q_internal": "cj_out"},
        )
        assert status == "cj-out"

    def test_determine_status_non_cj_change(self, wallet):
        """Test non-cj-change status for change address not from CJ."""
        status = wallet._determine_address_status(
            address="bc1q_change",
            balance=30000,
            is_external=False,
            used_addresses={},
            history_addresses={},
        )
        assert status == "non-cj-change"

    def test_determine_status_new(self, wallet):
        """Test new status for unused address."""
        status = wallet._determine_address_status(
            address="bc1q_new",
            balance=0,
            is_external=True,
            used_addresses=set(),
            history_addresses={},
        )
        assert status == "new"

    def test_determine_status_used_empty(self, wallet):
        """Test used-empty status for address that had funds."""
        status = wallet._determine_address_status(
            address="bc1q_spent",
            balance=0,
            is_external=True,
            used_addresses={"bc1q_spent"},
            history_addresses={"bc1q_spent": "cj_out"},
        )
        assert status == "used-empty"

    def test_determine_status_flagged(self, wallet):
        """Test flagged status for address shared but tx failed."""
        status = wallet._determine_address_status(
            address="bc1q_flagged",
            balance=0,
            is_external=True,
            used_addresses={"bc1q_flagged"},
            history_addresses={"bc1q_flagged": "flagged"},
        )
        assert status == "flagged"


class TestNextUnusedUnflaggedAddress:
    """Tests for get_next_unused_unflagged_address method."""

    @pytest.fixture
    def mock_backend(self):
        """Create a mock backend."""
        backend = Mock()
        backend.get_utxos = AsyncMock(return_value=[])
        backend.close = AsyncMock()
        return backend

    @pytest.fixture
    def wallet(self, mock_backend, test_mnemonic, test_network):
        """Create a wallet for testing."""
        return WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network=test_network,
            mixdepth_count=5,
        )

    def test_get_next_address_no_history(self, wallet):
        """Test getting next address with no history."""
        address, index = wallet.get_next_unused_unflagged_address(0, set())
        assert index == 0
        assert address  # Should return valid address

    def test_get_next_address_skips_used(self, wallet):
        """Test that used addresses are skipped."""
        # Get address at index 0
        addr_0 = wallet.get_receive_address(0, 0)
        addr_1 = wallet.get_receive_address(0, 1)
        addr_2 = wallet.get_receive_address(0, 2)

        # Mark addresses 0 and 1 as used
        used = {addr_0, addr_1}

        address, index = wallet.get_next_unused_unflagged_address(0, used)
        assert index == 2
        assert address == addr_2

    def test_get_next_address_different_mixdepths(self, wallet):
        """Test getting next address from different mixdepths."""
        # Get some addresses
        addr_m0_0 = wallet.get_receive_address(0, 0)
        addr_m1_0 = wallet.get_receive_address(1, 0)

        # Mark mixdepth 0 address as used
        used = {addr_m0_0}

        # Mixdepth 0 should skip to index 1
        addr, idx = wallet.get_next_unused_unflagged_address(0, used)
        assert idx == 1

        # Mixdepth 1 should still be at index 0
        addr, idx = wallet.get_next_unused_unflagged_address(1, used)
        assert idx == 0
        assert addr == addr_m1_0


class TestAddressHistoryTypes:
    """Tests for get_address_history_types function."""

    def test_empty_history(self):
        """Test with no history."""
        with TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            result = get_address_history_types(data_dir)
            assert result == {}

    def test_successful_coinjoin_addresses(self):
        """Test addresses from successful CoinJoin."""
        with TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            entry = TransactionHistoryEntry(
                timestamp="2024-01-01T00:00:00",
                role="maker",
                success=True,
                txid="abc123",
                cj_amount=100000,
                destination_address="bc1q_cj_out",
                change_address="bc1q_change",
            )
            append_history_entry(entry, data_dir)

            result = get_address_history_types(data_dir)
            assert result["bc1q_cj_out"] == "cj_out"
            assert result["bc1q_change"] == "change"

    def test_failed_coinjoin_addresses_flagged(self):
        """Test addresses from failed CoinJoin are flagged."""
        with TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            entry = TransactionHistoryEntry(
                timestamp="2024-01-01T00:00:00",
                role="taker",
                success=False,
                failure_reason="Timed out",
                txid="",
                cj_amount=100000,
                destination_address="bc1q_failed_dest",
                change_address="bc1q_failed_change",
            )
            append_history_entry(entry, data_dir)

            result = get_address_history_types(data_dir)
            assert result["bc1q_failed_dest"] == "flagged"
            assert result["bc1q_failed_change"] == "flagged"

    def test_mixed_history(self):
        """Test with both successful and failed entries."""
        with TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)

            # Successful CoinJoin
            entry1 = TransactionHistoryEntry(
                timestamp="2024-01-01T00:00:00",
                role="maker",
                success=True,
                txid="abc123",
                cj_amount=100000,
                destination_address="bc1q_success",
                change_address="bc1q_success_change",
            )
            append_history_entry(entry1, data_dir)

            # Failed CoinJoin
            entry2 = TransactionHistoryEntry(
                timestamp="2024-01-02T00:00:00",
                role="taker",
                success=False,
                failure_reason="Error",
                txid="",
                cj_amount=50000,
                destination_address="bc1q_failed",
                change_address="",
            )
            append_history_entry(entry2, data_dir)

            result = get_address_history_types(data_dir)
            assert result["bc1q_success"] == "cj_out"
            assert result["bc1q_success_change"] == "change"
            assert result["bc1q_failed"] == "flagged"


class TestAddressInfoForMixdepth:
    """Tests for get_address_info_for_mixdepth method."""

    @pytest.fixture
    def mock_backend(self):
        """Create a mock backend."""
        backend = Mock()
        backend.get_utxos = AsyncMock(return_value=[])
        backend.close = AsyncMock()
        return backend

    @pytest.fixture
    def wallet(self, mock_backend, test_mnemonic, test_network):
        """Create a wallet for testing."""
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network=test_network,
            mixdepth_count=5,
        )
        # Initialize empty UTXO cache
        wallet.utxo_cache = {i: [] for i in range(5)}
        return wallet

    def test_empty_mixdepth(self, wallet):
        """Test getting addresses for empty mixdepth."""
        addresses = wallet.get_address_info_for_mixdepth(
            mixdepth=0,
            change=0,
            gap_limit=3,
            used_addresses=set(),
            history_addresses={},
        )
        # Should return gap_limit addresses (no used addresses)
        assert len(addresses) == 3
        for addr_info in addresses:
            assert addr_info.status == "new"
            assert addr_info.balance == 0
            assert addr_info.is_external is True

    def test_mixdepth_with_utxos(self, wallet):
        """Test getting addresses when there are UTXOs."""
        # Add a UTXO at index 5
        addr_5 = wallet.get_receive_address(0, 5)
        utxo = UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address=addr_5,
            confirmations=6,
            scriptpubkey="0014" + "00" * 20,
            path=f"{wallet.root_path}/0'/0/5",
            mixdepth=0,
        )
        wallet.utxo_cache[0] = [utxo]

        addresses = wallet.get_address_info_for_mixdepth(
            mixdepth=0,
            change=0,
            gap_limit=3,
            used_addresses=set(),
            history_addresses={},
        )
        # Should return addresses 0 through 5 + gap_limit = 0-8
        assert len(addresses) == 9  # 0-5 (funded at 5) + 3 gap = 9

        # Address at index 5 should have balance
        addr_5_info = addresses[5]
        assert addr_5_info.balance == 100000
        assert addr_5_info.status == "deposit"

        # Earlier addresses should be "new"
        assert addresses[0].status == "new"
        assert addresses[0].balance == 0

    def test_internal_addresses(self, wallet):
        """Test getting internal (change) addresses."""
        addresses = wallet.get_address_info_for_mixdepth(
            mixdepth=0,
            change=1,
            gap_limit=2,
            used_addresses=set(),
            history_addresses={},
        )
        for addr_info in addresses:
            assert addr_info.is_external is False
            assert "/1/" in addr_info.path  # Internal branch

    def test_addresses_with_history(self, wallet):
        """Test address status reflects history."""
        # Get address and mark it as CJ output
        addr = wallet.get_change_address(0, 0)

        # Add UTXO
        utxo = UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=50000,
            address=addr,
            confirmations=6,
            scriptpubkey="0014" + "00" * 20,
            path=f"{wallet.root_path}/0'/1/0",
            mixdepth=0,
        )
        wallet.utxo_cache[0] = [utxo]

        addresses = wallet.get_address_info_for_mixdepth(
            mixdepth=0,
            change=1,
            gap_limit=2,
            used_addresses={addr},
            history_addresses={addr: "cj_out"},
        )

        # First address should be cj-out with balance
        assert addresses[0].status == "cj-out"
        assert addresses[0].balance == 50000


class TestAccountXpub:
    """Tests for xpub generation."""

    @pytest.fixture
    def mock_backend(self):
        """Create a mock backend."""
        backend = Mock()
        backend.close = AsyncMock()
        return backend

    @pytest.fixture
    def wallet(self, mock_backend, test_mnemonic, test_network):
        """Create a wallet for testing."""
        return WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network=test_network,
            mixdepth_count=5,
        )

    def test_get_account_xpub_mainnet(self, mock_backend, test_mnemonic):
        """Test xpub generation for mainnet."""
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network="mainnet",
            mixdepth_count=5,
        )
        xpub = wallet.get_account_xpub(0)
        assert xpub.startswith("xpub")

    def test_get_account_xpub_testnet(self, mock_backend, test_mnemonic):
        """Test xpub generation for testnet."""
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network="testnet",
            mixdepth_count=5,
        )
        xpub = wallet.get_account_xpub(0)
        assert xpub.startswith("tpub")

    def test_different_mixdepths_different_xpubs(self, wallet):
        """Test that different mixdepths produce different xpubs."""
        xpub_0 = wallet.get_account_xpub(0)
        xpub_1 = wallet.get_account_xpub(1)
        xpub_2 = wallet.get_account_xpub(2)

        assert xpub_0 != xpub_1
        assert xpub_1 != xpub_2
        assert xpub_0 != xpub_2
