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
    get_pending_transactions,
    get_used_addresses,
    read_history,
    update_pending_transaction_txid,
    update_transaction_confirmation,
)


@pytest.fixture
def temp_data_dir() -> Generator[Path, None, None]:
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
            taker_nick="J5testuser123456",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0), ("def456", 1)],
            txid="txid" * 16,
            network="regtest",
        )

        assert entry.role == "maker"
        assert entry.cj_amount == 1_000_000
        assert entry.fee_received == 250
        assert entry.txfee_contribution == 50
        assert entry.net_fee == 200  # 250 - 50
        assert entry.counterparty_nicks == "J5testuser123456"
        assert entry.peer_count is None  # Makers don't know peer count
        assert "abc123:0" in entry.utxos_used
        assert entry.network == "regtest"

    def test_create_taker_history_entry(self) -> None:
        """Test create_taker_history_entry helper."""
        entry = create_taker_history_entry(
            maker_nicks=["J5maker1", "J5maker2", "J5maker3"],
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
        assert "J5maker1" in entry.counterparty_nicks
        assert entry.destination_address == "bc1qdest..."
        assert entry.source_mixdepth == 0
        assert entry.broadcast_method == "self"

    def test_create_taker_history_entry_failed(self) -> None:
        """Test create_taker_history_entry for failed CoinJoin."""
        entry = create_taker_history_entry(
            maker_nicks=["J5maker1"],
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


class TestPendingTransactions:
    """Tests for pending transaction functionality."""

    def test_create_maker_entry_is_pending(self) -> None:
        """Test that newly created maker entries are marked as pending."""
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="test_txid_123",
        )

        # Should be marked as pending initially
        assert entry.success is False
        assert entry.failure_reason == "Pending confirmation"
        assert entry.confirmations == 0
        assert entry.confirmed_at == ""
        assert entry.completed_at == ""

    def test_create_taker_entry_is_pending(self) -> None:
        """Test that newly created taker entries are marked as pending by default."""
        entry = create_taker_history_entry(
            maker_nicks=["J5maker1"],
            cj_amount=1_000_000,
            total_maker_fees=500,
            mining_fee=100,
            destination="bc1qdest...",
            source_mixdepth=0,
            selected_utxos=[("utxo1", 0)],
            txid="test_txid_456",
        )

        # Should be pending by default
        assert entry.success is False
        assert entry.failure_reason == "Pending confirmation"
        assert entry.confirmations == 0
        assert entry.confirmed_at == ""
        assert entry.completed_at == ""

    def test_get_pending_transactions(self, temp_data_dir: Path) -> None:
        """Test retrieving pending transactions."""
        # Add a pending entry
        pending_entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="pending_tx",
        )
        append_history_entry(pending_entry, temp_data_dir)

        # Add a confirmed entry
        confirmed_entry = TransactionHistoryEntry(
            timestamp="2024-01-02T00:00:00",
            role="maker",
            txid="confirmed_tx",
            cj_amount=2_000_000,
            success=True,
            confirmations=6,
        )
        append_history_entry(confirmed_entry, temp_data_dir)

        # Get pending transactions
        pending = get_pending_transactions(temp_data_dir)

        assert len(pending) == 1
        assert pending[0].txid == "pending_tx"
        assert pending[0].success is False

    def test_update_transaction_confirmation(self, temp_data_dir: Path) -> None:
        """Test updating transaction confirmation status."""
        # Create and save a pending entry
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="test_tx_update",
        )
        append_history_entry(entry, temp_data_dir)

        # Verify it's pending
        pending = get_pending_transactions(temp_data_dir)
        assert len(pending) == 1

        # Update with 1 confirmation
        result = update_transaction_confirmation("test_tx_update", 1, temp_data_dir)
        assert result is True

        # Verify it's no longer pending
        pending = get_pending_transactions(temp_data_dir)
        assert len(pending) == 0

        # Read the entry and verify it's marked as successful
        entries = read_history(temp_data_dir)
        assert len(entries) == 1
        assert entries[0].success is True
        assert entries[0].confirmations == 1
        assert entries[0].confirmed_at != ""
        assert entries[0].completed_at != ""
        assert entries[0].failure_reason == ""

    def test_update_transaction_confirmation_incremental(self, temp_data_dir: Path) -> None:
        """Test updating confirmations incrementally."""
        # Create and save a pending entry
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest...",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="test_tx_incremental",
        )
        append_history_entry(entry, temp_data_dir)

        # Update with 1 confirmation
        update_transaction_confirmation("test_tx_incremental", 1, temp_data_dir)

        # Update with 6 confirmations
        update_transaction_confirmation("test_tx_incremental", 6, temp_data_dir)

        # Verify confirmations were updated
        entries = read_history(temp_data_dir)
        assert len(entries) == 1
        assert entries[0].confirmations == 6
        assert entries[0].success is True

    def test_update_nonexistent_transaction(self, temp_data_dir: Path) -> None:
        """Test updating a transaction that doesn't exist."""
        result = update_transaction_confirmation("nonexistent_tx", 1, temp_data_dir)
        assert result is False


class TestUsedAddressTracking:
    """Tests for used address tracking and txid discovery."""

    def test_get_used_addresses_empty(self, temp_data_dir: Path) -> None:
        """Test get_used_addresses with no history."""

        used = get_used_addresses(temp_data_dir)
        assert len(used) == 0
        assert isinstance(used, set)

    def test_get_used_addresses_with_history(self, temp_data_dir: Path) -> None:
        """Test get_used_addresses returns addresses from history."""

        # Add entries with different addresses
        entry1 = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qtest1address111111",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="txid1" * 16,
        )
        append_history_entry(entry1, temp_data_dir)

        entry2 = create_taker_history_entry(
            maker_nicks=["J5maker1"],
            cj_amount=2_000_000,
            total_maker_fees=500,
            mining_fee=100,
            destination="bc1qtest2address222222",
            source_mixdepth=0,
            selected_utxos=[("utxo1", 0)],
            txid="txid2" * 16,
        )
        append_history_entry(entry2, temp_data_dir)

        # Get used addresses
        used = get_used_addresses(temp_data_dir)

        assert len(used) == 3  # 2 CJ addresses (maker+taker) + 1 change address (maker only)
        assert "bc1qtest1address111111" in used
        assert "bc1qtest2address222222" in used

    def test_get_used_addresses_deduplication(self, temp_data_dir: Path) -> None:
        """Test that get_used_addresses deduplicates addresses."""

        # Add two entries with the same destination address
        entry1 = create_maker_history_entry(
            taker_nick="J5taker1",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qsameaddress123456",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="txid1" * 16,
        )
        append_history_entry(entry1, temp_data_dir)

        entry2 = create_maker_history_entry(
            taker_nick="J5taker2",
            cj_amount=2_000_000,
            fee_received=500,
            txfee_contribution=100,
            cj_address="bc1qsameaddress123456",
            change_address="bc1qchange...",
            our_utxos=[("def456", 0)],
            txid="txid2" * 16,
        )
        append_history_entry(entry2, temp_data_dir)

        # Should only have one address despite two entries
        used = get_used_addresses(temp_data_dir)
        assert len(used) == 2  # CJ address + change address
        assert "bc1qsameaddress123456" in used

    def test_get_used_addresses_includes_pending(self, temp_data_dir: Path) -> None:
        """Test that get_used_addresses includes pending transactions."""

        # Add a pending entry (no txid)
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qpending12345678",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="",  # No txid yet - pending
        )
        append_history_entry(entry, temp_data_dir)

        # Address should still be marked as used (privacy!)
        used = get_used_addresses(temp_data_dir)
        assert len(used) == 2  # CJ address + change address
        assert "bc1qpending12345678" in used

    def test_update_pending_transaction_txid(self, temp_data_dir: Path) -> None:
        """Test updating pending transaction with discovered txid."""

        # Create a pending entry without txid
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qdiscovered123456",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="",  # No txid initially
        )
        append_history_entry(entry, temp_data_dir)

        # Verify it's pending without txid
        pending = get_pending_transactions(temp_data_dir)
        assert len(pending) == 1
        assert pending[0].txid == ""
        assert pending[0].destination_address == "bc1qdiscovered123456"

        # Update with discovered txid
        result = update_pending_transaction_txid(
            destination_address="bc1qdiscovered123456",
            txid="discovered_txid_12345678",
            data_dir=temp_data_dir,
        )
        assert result is True

        # Verify txid was updated
        pending = get_pending_transactions(temp_data_dir)
        assert len(pending) == 1
        assert pending[0].txid == "discovered_txid_12345678"
        assert pending[0].destination_address == "bc1qdiscovered123456"

    def test_update_pending_transaction_txid_nonexistent(self, temp_data_dir: Path) -> None:
        """Test update_pending_transaction_txid with nonexistent address."""

        result = update_pending_transaction_txid(
            destination_address="bc1qnonexistent1234",
            txid="some_txid",
            data_dir=temp_data_dir,
        )
        assert result is False

    def test_update_pending_transaction_txid_already_has_txid(self, temp_data_dir: Path) -> None:
        """Test that update_pending_transaction_txid only updates entries without txid."""

        # Create entry that already has a txid
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qalreadyhas123456",
            change_address="bc1qchange...",
            our_utxos=[("abc123", 0)],
            txid="original_txid_12345678",
        )
        append_history_entry(entry, temp_data_dir)

        # Try to update - should not match (entry has txid)
        result = update_pending_transaction_txid(
            destination_address="bc1qalreadyhas123456",
            txid="new_txid_different",
            data_dir=temp_data_dir,
        )
        assert result is False

        # Verify original txid unchanged
        entries = read_history(temp_data_dir)
        assert len(entries) == 1
        assert entries[0].txid == "original_txid_12345678"

    def test_get_used_addresses_includes_change_addresses(self, temp_data_dir: Path) -> None:
        """Test that get_used_addresses includes both CJ and change addresses."""
        from jmwallet.history import get_used_addresses

        # Add entry with both cj_address and change_address
        entry = create_maker_history_entry(
            taker_nick="J5taker",
            cj_amount=1_000_000,
            fee_received=250,
            txfee_contribution=50,
            cj_address="bc1qcoinjoin123456",
            change_address="bc1qchange789012345",
            our_utxos=[("abc123", 0)],
            txid="txid1" * 16,
        )
        append_history_entry(entry, temp_data_dir)

        # Both addresses should be in the used set
        used = get_used_addresses(temp_data_dir)
        assert len(used) == 2  # 1 CJ address + 1 change address
        assert "bc1qcoinjoin123456" in used
        assert "bc1qchange789012345" in used
