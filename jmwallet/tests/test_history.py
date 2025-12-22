"""
Tests for transaction history tracking.
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from jmwallet.history import (
    TransactionHistoryEntry,
    append_history_entry,
    create_maker_history_entry,
    create_taker_history_entry,
    get_history_stats,
    read_history,
)


@pytest.fixture
def temp_data_dir() -> Generator[Path]:
    """Create a temporary data directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestTransactionHistoryEntry:
    """Tests for TransactionHistoryEntry dataclass."""

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        entry = TransactionHistoryEntry(timestamp="2024-01-01T00:00:00")
        assert entry.role == "taker"
        assert entry.success is True
        assert entry.cj_amount == 0
        assert entry.net_fee == 0
        assert entry.network == "mainnet"

    def test_maker_entry(self) -> None:
        """Test maker entry creation."""
        entry = TransactionHistoryEntry(
            timestamp="2024-01-01T00:00:00",
            role="maker",
            txid="abc123" * 10 + "abcd",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=100,
            net_fee=150,
        )
        assert entry.role == "maker"
        assert entry.fee_received == 250
        assert entry.net_fee == 150

    def test_taker_entry(self) -> None:
        """Test taker entry creation."""
        entry = TransactionHistoryEntry(
            timestamp="2024-01-01T00:00:00",
            role="taker",
            txid="def456" * 10 + "defg",
            cj_amount=500_000,
            total_maker_fees_paid=1000,
            mining_fee_paid=500,
            net_fee=-1500,
        )
        assert entry.role == "taker"
        assert entry.total_maker_fees_paid == 1000
        assert entry.net_fee == -1500


class TestAppendAndReadHistory:
    """Tests for appending and reading history."""

    def test_append_and_read_single_entry(self, temp_data_dir: Path) -> None:
        """Test appending and reading a single entry."""
        entry = TransactionHistoryEntry(
            timestamp="2024-01-01T00:00:00",
            role="taker",
            txid="abc123def456" * 5 + "abcd",
            cj_amount=1_000_000,
        )

        append_history_entry(entry, temp_data_dir)
        entries = read_history(temp_data_dir)

        assert len(entries) == 1
        assert entries[0].txid == entry.txid
        assert entries[0].cj_amount == 1_000_000

    def test_append_multiple_entries(self, temp_data_dir: Path) -> None:
        """Test appending multiple entries."""
        for i in range(3):
            entry = TransactionHistoryEntry(
                timestamp=f"2024-01-0{i + 1}T00:00:00",
                role="maker" if i % 2 == 0 else "taker",
                txid=f"txid{i}" * 16,
                cj_amount=(i + 1) * 100_000,
            )
            append_history_entry(entry, temp_data_dir)

        entries = read_history(temp_data_dir)
        assert len(entries) == 3

    def test_read_with_role_filter(self, temp_data_dir: Path) -> None:
        """Test reading with role filter."""
        # Add maker entry
        maker_entry = TransactionHistoryEntry(
            timestamp="2024-01-01T00:00:00",
            role="maker",
            txid="maker_tx" * 8,
            cj_amount=500_000,
        )
        append_history_entry(maker_entry, temp_data_dir)

        # Add taker entry
        taker_entry = TransactionHistoryEntry(
            timestamp="2024-01-02T00:00:00",
            role="taker",
            txid="taker_tx" * 8,
            cj_amount=600_000,
        )
        append_history_entry(taker_entry, temp_data_dir)

        # Read only maker entries
        maker_entries = read_history(temp_data_dir, role_filter="maker")
        assert len(maker_entries) == 1
        assert maker_entries[0].role == "maker"

        # Read only taker entries
        taker_entries = read_history(temp_data_dir, role_filter="taker")
        assert len(taker_entries) == 1
        assert taker_entries[0].role == "taker"

    def test_read_with_limit(self, temp_data_dir: Path) -> None:
        """Test reading with limit."""
        for i in range(5):
            entry = TransactionHistoryEntry(
                timestamp=f"2024-01-0{i + 1}T00:00:00",
                txid=f"txid{i}" * 16,
                cj_amount=(i + 1) * 100_000,
            )
            append_history_entry(entry, temp_data_dir)

        entries = read_history(temp_data_dir, limit=3)
        assert len(entries) == 3
        # Most recent first
        assert entries[0].timestamp == "2024-01-05T00:00:00"

    def test_read_empty_history(self, temp_data_dir: Path) -> None:
        """Test reading when no history exists."""
        entries = read_history(temp_data_dir)
        assert entries == []


class TestHistoryStats:
    """Tests for aggregate statistics."""

    def test_empty_stats(self, temp_data_dir: Path) -> None:
        """Test stats with no history."""
        stats = get_history_stats(temp_data_dir)
        assert stats["total_coinjoins"] == 0
        assert stats["maker_coinjoins"] == 0
        assert stats["taker_coinjoins"] == 0
        assert stats["total_volume"] == 0

    def test_stats_with_entries(self, temp_data_dir: Path) -> None:
        """Test stats with multiple entries."""
        # Add maker entry
        maker_entry = TransactionHistoryEntry(
            timestamp="2024-01-01T00:00:00",
            role="maker",
            txid="maker_tx" * 8,
            cj_amount=1_000_000,
            fee_received=500,
            success=True,
        )
        append_history_entry(maker_entry, temp_data_dir)

        # Add taker entry
        taker_entry = TransactionHistoryEntry(
            timestamp="2024-01-02T00:00:00",
            role="taker",
            txid="taker_tx" * 8,
            cj_amount=2_000_000,
            total_maker_fees_paid=1000,
            mining_fee_paid=200,
            success=True,
        )
        append_history_entry(taker_entry, temp_data_dir)

        stats = get_history_stats(temp_data_dir)
        assert stats["total_coinjoins"] == 2
        assert stats["maker_coinjoins"] == 1
        assert stats["taker_coinjoins"] == 1
        assert stats["total_volume"] == 3_000_000
        assert stats["total_fees_earned"] == 500
        assert stats["total_fees_paid"] == 1200
        assert stats["success_rate"] == 100.0


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_maker_history_entry(self) -> None:
        """Test create_maker_history_entry helper."""
        entry = create_maker_history_entry(
            taker_nick="J6testuser123456",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            our_utxos=[("abc123", 0), ("def456", 1)],
            txid="txid" * 16,
            network="regtest",
        )

        assert entry.role == "maker"
        assert entry.cj_amount == 1_000_000
        assert entry.fee_received == 250
        assert entry.txfee_contribution == 50
        assert entry.net_fee == 200  # 250 - 50
        assert entry.counterparty_nicks == "J6testuser123456"
        assert entry.peer_count == 1
        assert "abc123:0" in entry.utxos_used
        assert entry.network == "regtest"

    def test_create_taker_history_entry(self) -> None:
        """Test create_taker_history_entry helper."""
        entry = create_taker_history_entry(
            maker_nicks=["J6maker1", "J6maker2", "J6maker3"],
            cj_amount=2_000_000,
            total_maker_fees=900,
            mining_fee=300,
            destination="bc1qdest...",
            source_mixdepth=0,
            selected_utxos=[("utxo1", 0), ("utxo2", 1)],
            txid="txid" * 16,
            broadcast_method="self",
            network="mainnet",
        )

        assert entry.role == "taker"
        assert entry.cj_amount == 2_000_000
        assert entry.total_maker_fees_paid == 900
        assert entry.mining_fee_paid == 300
        assert entry.net_fee == -1200  # -(900 + 300)
        assert entry.peer_count == 3
        assert "J6maker1" in entry.counterparty_nicks
        assert entry.destination_address == "bc1qdest..."
        assert entry.source_mixdepth == 0
        assert entry.broadcast_method == "self"

    def test_create_taker_history_entry_failed(self) -> None:
        """Test create_taker_history_entry for failed CoinJoin."""
        entry = create_taker_history_entry(
            maker_nicks=["J6maker1"],
            cj_amount=500_000,
            total_maker_fees=0,
            mining_fee=0,
            destination="bc1qdest...",
            source_mixdepth=0,
            selected_utxos=[],
            txid="",
            success=False,
            failure_reason="Maker timeout",
        )

        assert entry.success is False
        assert entry.failure_reason == "Maker timeout"
        assert entry.txid == ""
