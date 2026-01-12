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


class TestGetNextAddressIndex:
    """Tests for get_next_address_index method."""

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
        wallet.utxo_cache = {i: [] for i in range(5)}
        return wallet

    def test_returns_zero_when_no_addresses_used(self, wallet):
        """Test that index 0 is returned when no addresses are used."""
        index = wallet.get_next_address_index(mixdepth=0, change=0)
        assert index == 0

    def test_returns_next_after_utxo(self, wallet):
        """Test that next index after UTXO address is returned."""
        addr_2 = wallet.get_receive_address(0, 2)
        utxo = UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address=addr_2,
            confirmations=6,
            scriptpubkey="0014" + "00" * 20,
            path=f"{wallet.root_path}/0'/0/2",
            mixdepth=0,
        )
        wallet.utxo_cache[0] = [utxo]

        index = wallet.get_next_address_index(mixdepth=0, change=0)
        assert index == 3

    def test_uses_addresses_with_history_after_spend(self, wallet):
        """
        Test that addresses_with_history is used to prevent reuse after spend.

        This is the key bug scenario: an address receives funds (index 0),
        then funds are spent (internal send). After the spend, UTXO cache
        no longer has the address, but addresses_with_history should track it
        to prevent reuse.
        """
        # Simulate: address at index 0 received funds, then was spent
        addr_0 = wallet.get_receive_address(0, 0)
        wallet.addresses_with_history.add(addr_0)
        # No UTXOs remain (all spent)
        wallet.utxo_cache[0] = []

        index = wallet.get_next_address_index(mixdepth=0, change=0)
        # Should return 1, not 0, because addr_0 was used
        assert index == 1

    def test_uses_highest_index_from_addresses_with_history(self, wallet):
        """Test that the highest index from addresses_with_history is used."""
        # Addresses 0, 2, and 5 had history (1, 3, 4 were skipped for some reason)
        wallet.get_receive_address(0, 0)  # Cache address
        wallet.get_receive_address(0, 2)  # Cache address
        addr_5 = wallet.get_receive_address(0, 5)  # Cache address

        wallet.addresses_with_history.add(wallet.get_receive_address(0, 0))
        wallet.addresses_with_history.add(wallet.get_receive_address(0, 2))
        wallet.addresses_with_history.add(addr_5)

        index = wallet.get_next_address_index(mixdepth=0, change=0)
        # Should return 6, the next after the highest used (5)
        assert index == 6

    def test_combines_utxo_cache_and_addresses_with_history(self, wallet):
        """Test that both UTXO cache and addresses_with_history are considered."""
        # Address at index 3 is in UTXO cache (current balance)
        addr_3 = wallet.get_receive_address(0, 3)
        utxo = UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address=addr_3,
            confirmations=6,
            scriptpubkey="0014" + "00" * 20,
            path=f"{wallet.root_path}/0'/0/3",
            mixdepth=0,
        )
        wallet.utxo_cache[0] = [utxo]

        # Address at index 7 was spent (in history but no UTXO)
        addr_7 = wallet.get_receive_address(0, 7)
        wallet.addresses_with_history.add(addr_7)

        index = wallet.get_next_address_index(mixdepth=0, change=0)
        # Should return 8, the next after the highest (7 from history)
        assert index == 8

    def test_respects_mixdepth_separation(self, wallet):
        """Test that different mixdepths have independent indices."""
        # Mixdepth 0 has used address at index 5
        addr_m0 = wallet.get_receive_address(0, 5)
        wallet.addresses_with_history.add(addr_m0)

        # Mixdepth 1 should still return 0
        index_m1 = wallet.get_next_address_index(mixdepth=1, change=0)
        assert index_m1 == 0

        # Mixdepth 0 should return 6
        index_m0 = wallet.get_next_address_index(mixdepth=0, change=0)
        assert index_m0 == 6

    def test_respects_change_separation(self, wallet):
        """Test that external and internal addresses have independent indices."""
        # External (change=0) has used address at index 3
        addr_ext = wallet.get_receive_address(0, 3)
        wallet.addresses_with_history.add(addr_ext)

        # Internal (change=1) should still return 0
        index_int = wallet.get_next_address_index(mixdepth=0, change=1)
        assert index_int == 0

        # External should return 4
        index_ext = wallet.get_next_address_index(mixdepth=0, change=0)
        assert index_ext == 4


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


class TestAccountZpub:
    """Tests for zpub generation."""

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

    def test_get_account_zpub_mainnet(self, mock_backend, test_mnemonic):
        """Test zpub generation for mainnet."""
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network="mainnet",
            mixdepth_count=5,
        )
        zpub = wallet.get_account_zpub(0)
        assert zpub.startswith("zpub")

    def test_get_account_zpub_testnet(self, mock_backend, test_mnemonic):
        """Test zpub generation for testnet."""
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=mock_backend,
            network="testnet",
            mixdepth_count=5,
        )
        zpub = wallet.get_account_zpub(0)
        assert zpub.startswith("vpub")

    def test_different_mixdepths_different_zpubs(self, wallet):
        """Test that different mixdepths produce different zpubs."""
        zpub_0 = wallet.get_account_zpub(0)
        zpub_1 = wallet.get_account_zpub(1)
        zpub_2 = wallet.get_account_zpub(2)

        assert zpub_0 != zpub_1
        assert zpub_1 != zpub_2
        assert zpub_0 != zpub_2

    def test_zpub_xpub_different_same_key(self, wallet):
        """Test that zpub and xpub are different for the same account."""
        zpub = wallet.get_account_zpub(0)
        xpub = wallet.get_account_xpub(0)

        assert zpub != xpub
        assert zpub.startswith("zpub") or zpub.startswith("vpub")
        assert xpub.startswith("xpub") or xpub.startswith("tpub")
