"""
Tests for UTXO selection algorithms in WalletService.

Tests cover:
- Basic select_utxos() - minimum UTXOs needed
- get_all_utxos() - all UTXOs from a mixdepth (for sweep)
- select_utxos_with_merge() - maker merge algorithms
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from jmwallet.wallet.models import UTXOInfo
from jmwallet.wallet.service import WalletService


@pytest.fixture
def mock_backend():
    """Create a mock blockchain backend."""
    backend = MagicMock()
    backend.get_utxos = AsyncMock(return_value=[])
    backend.close = AsyncMock()
    return backend


@pytest.fixture
def wallet_service(test_mnemonic: str, mock_backend) -> WalletService:
    """Create a WalletService with mock backend and pre-populated UTXO cache."""
    ws = WalletService(
        mnemonic=test_mnemonic,
        backend=mock_backend,
        network="regtest",
        mixdepth_count=5,
        gap_limit=20,
    )

    # Pre-populate UTXO cache for testing
    ws.utxo_cache = {
        0: [
            UTXOInfo(
                txid="a" * 64,
                vout=0,
                value=100_000,
                address="bcrt1test1",
                confirmations=10,
                scriptpubkey="0014" + "aa" * 20,
                path="m/84'/0'/0'/0/0",
                mixdepth=0,
            ),
            UTXOInfo(
                txid="b" * 64,
                vout=0,
                value=50_000,
                address="bcrt1test2",
                confirmations=5,
                scriptpubkey="0014" + "bb" * 20,
                path="m/84'/0'/0'/0/1",
                mixdepth=0,
            ),
            UTXOInfo(
                txid="c" * 64,
                vout=0,
                value=30_000,
                address="bcrt1test3",
                confirmations=3,
                scriptpubkey="0014" + "cc" * 20,
                path="m/84'/0'/0'/0/2",
                mixdepth=0,
            ),
            UTXOInfo(
                txid="d" * 64,
                vout=0,
                value=20_000,
                address="bcrt1test4",
                confirmations=2,
                scriptpubkey="0014" + "dd" * 20,
                path="m/84'/0'/0'/0/3",
                mixdepth=0,
            ),
            UTXOInfo(
                txid="e" * 64,
                vout=0,
                value=10_000,
                address="bcrt1test5",
                confirmations=1,
                scriptpubkey="0014" + "ee" * 20,
                path="m/84'/0'/0'/0/4",
                mixdepth=0,
            ),
        ],
        1: [],
    }

    return ws


class TestSelectUtxos:
    """Tests for basic select_utxos() - minimum UTXOs needed."""

    def test_select_single_utxo_sufficient(self, wallet_service: WalletService):
        """When one UTXO is enough, select only one."""
        selected = wallet_service.select_utxos(0, 80_000, min_confirmations=1)
        assert len(selected) == 1
        assert selected[0].value == 100_000  # Largest UTXO

    def test_select_multiple_utxos_needed(self, wallet_service: WalletService):
        """When multiple UTXOs needed, select minimum count."""
        selected = wallet_service.select_utxos(0, 140_000, min_confirmations=1)
        assert len(selected) == 2
        assert sum(u.value for u in selected) >= 140_000

    def test_select_respects_confirmations(self, wallet_service: WalletService):
        """UTXOs below min confirmations are excluded."""
        selected = wallet_service.select_utxos(0, 80_000, min_confirmations=6)
        # Only 100k UTXO has 10 confirms
        assert len(selected) == 1
        assert all(u.confirmations >= 6 for u in selected)

    def test_select_insufficient_funds_raises(self, wallet_service: WalletService):
        """Raises ValueError when insufficient funds."""
        with pytest.raises(ValueError, match="Insufficient funds"):
            wallet_service.select_utxos(0, 500_000, min_confirmations=1)

    def test_select_with_include_utxos(self, wallet_service: WalletService):
        """Mandatory UTXOs are always included."""
        mandatory = [wallet_service.utxo_cache[0][2]]  # 30k UTXO
        selected = wallet_service.select_utxos(
            0, 50_000, min_confirmations=1, include_utxos=mandatory
        )

        # Mandatory UTXO should be included
        assert mandatory[0] in selected
        assert sum(u.value for u in selected) >= 50_000


class TestGetAllUtxos:
    """Tests for get_all_utxos() - used for sweep operations."""

    def test_get_all_returns_all_eligible(self, wallet_service: WalletService):
        """Returns all UTXOs meeting confirmation requirement."""
        all_utxos = wallet_service.get_all_utxos(0, min_confirmations=1)
        assert len(all_utxos) == 5  # All 5 UTXOs

    def test_get_all_respects_confirmations(self, wallet_service: WalletService):
        """Filters by confirmation requirement."""
        all_utxos = wallet_service.get_all_utxos(0, min_confirmations=5)
        # Only UTXOs with 5+ confirms: 100k (10), 50k (5)
        assert len(all_utxos) == 2

    def test_get_all_empty_mixdepth(self, wallet_service: WalletService):
        """Empty mixdepth returns empty list."""
        all_utxos = wallet_service.get_all_utxos(1, min_confirmations=1)
        assert len(all_utxos) == 0


class TestSelectUtxosWithMerge:
    """Tests for select_utxos_with_merge() - maker merge algorithms."""

    def test_default_algorithm_minimum_utxos(self, wallet_service: WalletService):
        """Default algorithm selects minimum UTXOs needed."""
        selected = wallet_service.select_utxos_with_merge(
            0, 80_000, min_confirmations=1, merge_algorithm="default"
        )
        # Should select just 1 UTXO (100k is enough)
        assert len(selected) == 1
        assert selected[0].value == 100_000

    def test_gradual_algorithm_adds_one(self, wallet_service: WalletService):
        """Gradual algorithm adds exactly one extra UTXO."""
        selected = wallet_service.select_utxos_with_merge(
            0, 80_000, min_confirmations=1, merge_algorithm="gradual"
        )
        # Should select 1 (minimum) + 1 (gradual) = 2 UTXOs
        assert len(selected) == 2
        # Extra should be smallest remaining (10k)
        values = sorted([u.value for u in selected])
        assert 10_000 in values  # Smallest was added

    def test_greedy_algorithm_selects_all(self, wallet_service: WalletService):
        """Greedy algorithm selects all eligible UTXOs."""
        selected = wallet_service.select_utxos_with_merge(
            0, 80_000, min_confirmations=1, merge_algorithm="greedy"
        )
        # Should select all 5 UTXOs
        assert len(selected) == 5
        assert sum(u.value for u in selected) == 210_000  # Total of all

    def test_random_algorithm_adds_zero_to_two(self, wallet_service: WalletService):
        """Random algorithm adds 0-2 extra UTXOs."""
        # Run multiple times to check range
        counts = set()
        for _ in range(50):
            selected = wallet_service.select_utxos_with_merge(
                0, 80_000, min_confirmations=1, merge_algorithm="random"
            )
            counts.add(len(selected))

        # Should see counts between 1 (min) and 3 (min + 2 random)
        assert min(counts) >= 1
        assert max(counts) <= 3

    def test_greedy_respects_confirmations(self, wallet_service: WalletService):
        """Greedy algorithm still respects confirmation requirement."""
        selected = wallet_service.select_utxos_with_merge(
            0, 50_000, min_confirmations=5, merge_algorithm="greedy"
        )
        # Only 2 UTXOs have 5+ confirms
        assert len(selected) == 2
        assert all(u.confirmations >= 5 for u in selected)

    def test_merge_insufficient_funds_raises(self, wallet_service: WalletService):
        """Raises ValueError when insufficient funds."""
        with pytest.raises(ValueError, match="Insufficient funds"):
            wallet_service.select_utxos_with_merge(
                0, 500_000, min_confirmations=1, merge_algorithm="greedy"
            )

    def test_gradual_no_remaining_acts_like_default(self, wallet_service: WalletService):
        """Gradual with no remaining UTXOs doesn't add any."""
        # Request almost all funds - needs all UTXOs
        selected = wallet_service.select_utxos_with_merge(
            0, 200_000, min_confirmations=1, merge_algorithm="gradual"
        )
        # All 5 UTXOs needed to meet 200k (total is 210k)
        # No remaining to add, so same as default
        assert len(selected) == 5


class TestFindUTXOByAddress:
    """Tests for find_utxo_by_address method."""

    def test_find_utxo_by_address_found(self, wallet_service: WalletService):
        """Test finding a UTXO by address."""
        # Use an address from the pre-populated cache
        utxo = wallet_service.find_utxo_by_address("bcrt1test1")

        assert utxo is not None
        assert utxo.address == "bcrt1test1"
        assert utxo.txid == "a" * 64
        assert utxo.vout == 0
        assert utxo.value == 100_000

    def test_find_utxo_by_address_not_found(self, wallet_service: WalletService):
        """Test finding a UTXO by address that doesn't exist."""
        utxo = wallet_service.find_utxo_by_address("bc1qnonexistent123456")

        assert utxo is None

    def test_find_utxo_by_address_across_mixdepths(self, wallet_service: WalletService):
        """Test that find_utxo_by_address searches all mixdepths."""
        # Add a UTXO in mixdepth 1 to test cross-mixdepth search
        wallet_service.utxo_cache[1] = [
            UTXOInfo(
                txid="f" * 64,
                vout=0,
                value=200_000,
                address="bcrt1test_md1",
                confirmations=5,
                scriptpubkey="0014" + "ff" * 20,
                path="m/84'/0'/1'/0/0",
                mixdepth=1,
            )
        ]

        # Find address from mixdepth 1
        utxo = wallet_service.find_utxo_by_address("bcrt1test_md1")

        assert utxo is not None
        assert utxo.address == "bcrt1test_md1"
        assert utxo.value == 200_000
        assert utxo.mixdepth == 1

    def test_find_utxo_by_address_returns_first_match(self, wallet_service: WalletService):
        """Test that find_utxo_by_address returns the first match if duplicates exist."""
        # Add a duplicate address to a different mixdepth (edge case)
        duplicate_utxo = UTXOInfo(
            txid="z" * 64,
            vout=5,
            value=999_999,
            address="bcrt1test1",  # Same address as mixdepth 0
            confirmations=20,
            scriptpubkey="0014" + "zz" * 20,
            path="m/84'/0'/2'/0/0",
            mixdepth=2,
        )
        wallet_service.utxo_cache[2] = [duplicate_utxo]

        # Should find the first one (from mixdepth 0)
        utxo = wallet_service.find_utxo_by_address("bcrt1test1")

        assert utxo is not None
        assert utxo.address == "bcrt1test1"
        # Should be the first match from mixdepth 0
        assert utxo.value == 100_000
        assert utxo.txid == "a" * 64
        assert utxo.mixdepth == 0


@pytest.fixture
def wallet_with_timelocked(test_mnemonic: str, mock_backend) -> WalletService:
    """Create a WalletService with timelocked (fidelity bond) UTXOs."""
    ws = WalletService(
        mnemonic=test_mnemonic,
        backend=mock_backend,
        network="regtest",
        mixdepth_count=5,
        gap_limit=20,
    )

    # Pre-populate UTXO cache with a mix of regular and timelocked UTXOs
    ws.utxo_cache = {
        0: [
            # Regular UTXO (P2WPKH)
            UTXOInfo(
                txid="a" * 64,
                vout=0,
                value=100_000,
                address="bcrt1test1",
                confirmations=10,
                scriptpubkey="0014" + "aa" * 20,  # P2WPKH
                path="m/84'/0'/0'/0/0",
                mixdepth=0,
            ),
            # Timelocked fidelity bond UTXO (P2WSH with locktime)
            UTXOInfo(
                txid="b" * 64,
                vout=0,
                value=500_000,  # Large timelocked bond
                address="bcrt1timelocked",
                confirmations=100,
                scriptpubkey="0020" + "bb" * 32,  # P2WSH
                path="m/84'/0'/0'/2/0:1893456000",  # Branch 2 with locktime
                mixdepth=0,
                locktime=1893456000,  # Future locktime
            ),
            # Regular UTXO (P2WPKH)
            UTXOInfo(
                txid="c" * 64,
                vout=0,
                value=50_000,
                address="bcrt1test3",
                confirmations=5,
                scriptpubkey="0014" + "cc" * 20,  # P2WPKH
                path="m/84'/0'/0'/0/2",
                mixdepth=0,
            ),
        ],
        1: [
            # Regular UTXO in mixdepth 1
            UTXOInfo(
                txid="d" * 64,
                vout=0,
                value=200_000,
                address="bcrt1test4",
                confirmations=10,
                scriptpubkey="0014" + "dd" * 20,  # P2WPKH
                path="m/84'/0'/1'/0/0",
                mixdepth=1,
            ),
        ],
    }

    return ws


class TestFidelityBondUTXOFiltering:
    """Tests for fidelity bond UTXO filtering in balance and selection."""

    @pytest.mark.asyncio
    async def test_get_balance_includes_fidelity_bonds_by_default(
        self, wallet_with_timelocked: WalletService
    ):
        """get_balance() includes fidelity bond UTXOs by default."""
        balance = await wallet_with_timelocked.get_balance(0)
        # Should include all: 100k + 500k + 50k = 650k
        assert balance == 650_000

    @pytest.mark.asyncio
    async def test_get_balance_exclude_fidelity_bonds(self, wallet_with_timelocked: WalletService):
        """get_balance(include_fidelity_bonds=False) excludes fidelity bond UTXOs."""
        balance = await wallet_with_timelocked.get_balance(0, include_fidelity_bonds=False)
        # Should exclude 500k fidelity bond: 100k + 50k = 150k
        assert balance == 150_000

    @pytest.mark.asyncio
    async def test_get_balance_for_offers_excludes_fidelity_bonds(
        self, wallet_with_timelocked: WalletService
    ):
        """get_balance_for_offers() excludes fidelity bond UTXOs."""
        balance = await wallet_with_timelocked.get_balance_for_offers(0)
        # Same as get_balance(include_fidelity_bonds=False)
        assert balance == 150_000

    @pytest.mark.asyncio
    async def test_get_fidelity_bond_balance(self, wallet_with_timelocked: WalletService):
        """get_fidelity_bond_balance() returns only fidelity bond UTXOs."""
        balance = await wallet_with_timelocked.get_fidelity_bond_balance(0)
        # Should only include the 500k fidelity bond UTXO
        assert balance == 500_000

    @pytest.mark.asyncio
    async def test_get_fidelity_bond_balance_empty_mixdepth(
        self, wallet_with_timelocked: WalletService
    ):
        """get_fidelity_bond_balance() returns 0 for mixdepth without fidelity bonds."""
        balance = await wallet_with_timelocked.get_fidelity_bond_balance(1)
        # Mixdepth 1 has no fidelity bond UTXOs
        assert balance == 0

    @pytest.mark.asyncio
    async def test_get_total_balance_includes_fidelity_bonds_by_default(
        self, wallet_with_timelocked: WalletService
    ):
        """get_total_balance() includes fidelity bonds by default."""
        balance = await wallet_with_timelocked.get_total_balance()
        # MD0: 650k, MD1: 200k = 850k
        assert balance == 850_000

    @pytest.mark.asyncio
    async def test_get_total_balance_exclude_fidelity_bonds(
        self, wallet_with_timelocked: WalletService
    ):
        """get_total_balance(include_fidelity_bonds=False) excludes fidelity bonds."""
        balance = await wallet_with_timelocked.get_total_balance(include_fidelity_bonds=False)
        # MD0: 150k, MD1: 200k = 350k
        assert balance == 350_000

    def test_select_utxos_excludes_fidelity_bonds_by_default(
        self, wallet_with_timelocked: WalletService
    ):
        """select_utxos() excludes fidelity bond UTXOs by default."""
        selected = wallet_with_timelocked.select_utxos(0, 100_000, min_confirmations=1)
        # Should select 100k UTXO, not the 500k fidelity bond
        assert len(selected) == 1
        assert selected[0].value == 100_000
        assert not selected[0].is_fidelity_bond

    def test_select_utxos_cannot_reach_fidelity_bond_amount(
        self, wallet_with_timelocked: WalletService
    ):
        """select_utxos() fails when needing fidelity bond funds to reach target."""
        # Request 200k - more than non-FB 150k, but less than total 650k
        with pytest.raises(ValueError, match="Insufficient funds"):
            wallet_with_timelocked.select_utxos(0, 200_000, min_confirmations=1)

    def test_get_all_utxos_excludes_fidelity_bonds_by_default(
        self, wallet_with_timelocked: WalletService
    ):
        """get_all_utxos() excludes fidelity bond UTXOs by default."""
        all_utxos = wallet_with_timelocked.get_all_utxos(0, min_confirmations=1)
        # Should only include 2 regular UTXOs, not the fidelity bond
        assert len(all_utxos) == 2
        assert all(not u.is_fidelity_bond for u in all_utxos)

    def test_get_all_utxos_include_fidelity_bonds(self, wallet_with_timelocked: WalletService):
        """get_all_utxos(include_fidelity_bonds=True) includes fidelity bond UTXOs."""
        all_utxos = wallet_with_timelocked.get_all_utxos(
            0, min_confirmations=1, include_fidelity_bonds=True
        )
        # Should include all 3 UTXOs
        assert len(all_utxos) == 3
        assert any(u.is_fidelity_bond for u in all_utxos)

    def test_select_utxos_with_merge_excludes_fidelity_bonds_by_default(
        self, wallet_with_timelocked: WalletService
    ):
        """select_utxos_with_merge() excludes fidelity bond UTXOs by default."""
        # Use greedy to get all eligible UTXOs
        selected = wallet_with_timelocked.select_utxos_with_merge(
            0, 50_000, min_confirmations=1, merge_algorithm="greedy"
        )
        # Should only include 2 regular UTXOs
        assert len(selected) == 2
        assert all(not u.is_fidelity_bond for u in selected)
        assert sum(u.value for u in selected) == 150_000

    def test_select_utxos_with_merge_include_fidelity_bonds(
        self, wallet_with_timelocked: WalletService
    ):
        """select_utxos_with_merge(include_fidelity_bonds=True) includes fidelity bonds."""
        selected = wallet_with_timelocked.select_utxos_with_merge(
            0, 50_000, min_confirmations=1, merge_algorithm="greedy", include_fidelity_bonds=True
        )
        # Should include all 3 UTXOs
        assert len(selected) == 3
        assert any(u.is_fidelity_bond for u in selected)
        assert sum(u.value for u in selected) == 650_000
