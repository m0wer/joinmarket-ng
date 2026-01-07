"""
Tests for offer deduplication and cleanup logic.

These tests verify that:
1. Offers with the same fidelity bond UTXO are deduplicated (keeping newest)
2. Offers from disconnected makers are removed on peerlist refresh
3. Bond-based deduplication works correctly across nick changes
"""

from __future__ import annotations

import time

from jmcore.directory_client import DirectoryClient, OfferWithTimestamp
from jmcore.models import Offer, OfferType


class TestOfferWithTimestamp:
    """Tests for OfferWithTimestamp wrapper class."""

    def test_offer_with_timestamp_stores_metadata(self) -> None:
        """Test that OfferWithTimestamp stores offer, timestamp, and bond key."""
        offer = Offer(
            counterparty="J5test1",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        timestamp = time.time()
        bond_key = "abc123:0"

        offer_ts = OfferWithTimestamp(offer, timestamp, bond_key)

        assert offer_ts.offer == offer
        assert offer_ts.received_at == timestamp
        assert offer_ts.bond_utxo_key == bond_key

    def test_offer_with_timestamp_none_bond_key(self) -> None:
        """Test that bond_utxo_key can be None for offers without bonds."""
        offer = Offer(
            counterparty="J5test1",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        offer_ts = OfferWithTimestamp(offer, time.time())

        assert offer_ts.bond_utxo_key is None


class TestDirectoryClientBondDeduplication:
    """Tests for bond-based offer deduplication in DirectoryClient."""

    def test_store_offer_replaces_old_offer_with_same_bond(self) -> None:
        """When a new nick uses the same bond UTXO, old offers should be removed."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store first offer with bond
        offer1 = Offer(
            counterparty="J5oldnick",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        bond_utxo = "abc123def456:0"
        client._store_offer(("J5oldnick", 0), offer1, bond_utxo)

        # Verify first offer is stored
        assert len(client.offers) == 1
        assert ("J5oldnick", 0) in client.offers

        # Store second offer with SAME bond but different nick (simulating maker restart)
        offer2 = Offer(
            counterparty="J5newnick",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        client._store_offer(("J5newnick", 0), offer2, bond_utxo)

        # Verify old offer is removed and new one is stored
        assert len(client.offers) == 1
        assert ("J5oldnick", 0) not in client.offers
        assert ("J5newnick", 0) in client.offers

    def test_store_offer_keeps_different_bonds_separate(self) -> None:
        """Offers with different bond UTXOs should not affect each other."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store first offer with bond A
        offer1 = Offer(
            counterparty="J5maker1",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        client._store_offer(("J5maker1", 0), offer1, "bondA:0")

        # Store second offer with bond B
        offer2 = Offer(
            counterparty="J5maker2",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        client._store_offer(("J5maker2", 0), offer2, "bondB:0")

        # Both offers should exist
        assert len(client.offers) == 2
        assert ("J5maker1", 0) in client.offers
        assert ("J5maker2", 0) in client.offers

    def test_store_offer_without_bond(self) -> None:
        """Offers without bonds should be stored normally."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        offer = Offer(
            counterparty="J5nobond",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        client._store_offer(("J5nobond", 0), offer, None)

        assert len(client.offers) == 1
        assert ("J5nobond", 0) in client.offers


class TestDirectoryClientNickLeave:
    """Tests for nick leave handling (offer cleanup)."""

    def test_remove_offers_for_nick_removes_all_offers(self) -> None:
        """All offers from a nick should be removed when nick leaves."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store multiple offers from same nick
        for oid in range(3):
            offer = Offer(
                counterparty="J5leaving",
                oid=oid,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=30000,
                maxsize=1000000,
                txfee=500,
                cjfee="0.001",
            )
            client._store_offer(("J5leaving", oid), offer, None)

        # Store offer from different nick
        other_offer = Offer(
            counterparty="J5staying",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        client._store_offer(("J5staying", 0), other_offer, None)

        # Verify all 4 offers exist
        assert len(client.offers) == 4

        # Remove offers for leaving nick
        removed = client.remove_offers_for_nick("J5leaving")

        # Verify 3 offers were removed, 1 remains
        assert removed == 3
        assert len(client.offers) == 1
        assert ("J5staying", 0) in client.offers

    def test_remove_offers_cleans_up_bond_mapping(self) -> None:
        """Bond mapping should be cleaned up when nick's offers are removed."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store offer with bond
        offer = Offer(
            counterparty="J5leaving",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        bond_key = "bondutxo:0"
        client._store_offer(("J5leaving", 0), offer, bond_key)

        # Verify bond mapping exists
        assert bond_key in client._bond_to_offers
        assert ("J5leaving", 0) in client._bond_to_offers[bond_key]

        # Remove nick's offers
        client.remove_offers_for_nick("J5leaving")

        # Verify bond mapping is cleaned
        assert bond_key not in client._bond_to_offers or len(client._bond_to_offers[bond_key]) == 0


class TestDirectoryClientActiveNicks:
    """Tests for active nick tracking."""

    def test_get_active_nicks_returns_empty_initially(self) -> None:
        """Active nicks should be empty before peerlist refresh."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )
        assert client.get_active_nicks() == set()

    def test_get_current_offers_returns_offers_list(self) -> None:
        """get_current_offers should return list of Offer objects."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store some offers
        for i in range(3):
            offer = Offer(
                counterparty=f"J5maker{i}",
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=30000,
                maxsize=1000000,
                txfee=500,
                cjfee="0.001",
            )
            client._store_offer((f"J5maker{i}", 0), offer, None)

        # Get offers
        offers = client.get_current_offers()

        # Verify we get Offer objects, not OfferWithTimestamp
        assert len(offers) == 3
        assert all(isinstance(o, Offer) for o in offers)

    def test_get_offers_with_timestamps_returns_metadata(self) -> None:
        """get_offers_with_timestamps should return OfferWithTimestamp objects."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Store offer with bond
        offer = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        client._store_offer(("J5maker", 0), offer, "bond:0")

        # Get offers with timestamps
        offers_ts = client.get_offers_with_timestamps()

        assert len(offers_ts) == 1
        assert isinstance(offers_ts[0], OfferWithTimestamp)
        assert offers_ts[0].bond_utxo_key == "bond:0"
        assert offers_ts[0].received_at > 0


class TestDirectoryClientStalenessCleanup:
    """Tests for staleness-based offer cleanup."""

    def test_cleanup_stale_offers_removes_old_offers(self) -> None:
        """Offers older than max_age_seconds should be removed."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Manually create an old offer by backdating the timestamp
        offer = Offer(
            counterparty="J5stale",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        old_timestamp = time.time() - 2000  # 33+ minutes ago
        client.offers[("J5stale", 0)] = OfferWithTimestamp(offer, old_timestamp)

        # Add a fresh offer
        fresh_offer = Offer(
            counterparty="J5fresh",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        client._store_offer(("J5fresh", 0), fresh_offer, None)

        # Verify both exist
        assert len(client.offers) == 2

        # Run cleanup with 30 minute threshold
        removed = client.cleanup_stale_offers(max_age_seconds=1800.0)

        # Verify stale offer was removed, fresh one remains
        assert removed == 1
        assert len(client.offers) == 1
        assert ("J5stale", 0) not in client.offers
        assert ("J5fresh", 0) in client.offers

    def test_cleanup_stale_offers_cleans_bond_mapping(self) -> None:
        """Bond mapping should be cleaned up when stale offers are removed."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Create an old offer with a bond
        offer = Offer(
            counterparty="J5stale",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        bond_key = "stalebond:0"
        old_timestamp = time.time() - 2000  # 33+ minutes ago
        client.offers[("J5stale", 0)] = OfferWithTimestamp(offer, old_timestamp, bond_key)
        client._bond_to_offers[bond_key] = {("J5stale", 0)}

        # Verify bond mapping exists
        assert bond_key in client._bond_to_offers

        # Run cleanup
        removed = client.cleanup_stale_offers(max_age_seconds=1800.0)

        # Verify offer removed and bond mapping cleaned
        assert removed == 1
        assert bond_key not in client._bond_to_offers or len(client._bond_to_offers[bond_key]) == 0

    def test_cleanup_stale_offers_respects_threshold(self) -> None:
        """Offers younger than max_age_seconds should NOT be removed."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        # Create an offer just under the threshold
        offer = Offer(
            counterparty="J5recent",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        recent_timestamp = time.time() - 1700  # 28+ minutes ago (under 30 min threshold)
        client.offers[("J5recent", 0)] = OfferWithTimestamp(offer, recent_timestamp)

        # Run cleanup with 30 minute threshold
        removed = client.cleanup_stale_offers(max_age_seconds=1800.0)

        # Verify offer was NOT removed
        assert removed == 0
        assert len(client.offers) == 1
        assert ("J5recent", 0) in client.offers

    def test_cleanup_stale_offers_returns_zero_when_empty(self) -> None:
        """Cleanup on empty offers dict should return 0."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        removed = client.cleanup_stale_offers(max_age_seconds=1800.0)
        assert removed == 0
