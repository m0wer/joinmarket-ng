"""
Tests for offer deduplication and cleanup logic.

These tests verify that:
1. Offers with the same fidelity bond UTXO are deduplicated (keeping newest)
2. Offers from disconnected makers are removed on peerlist refresh
3. Bond-based deduplication works correctly across nick changes
4. directory_nodes tracks all directories that announced an offer
"""

from __future__ import annotations

import time

from jmcore.directory_client import DirectoryClient, OfferWithTimestamp
from jmcore.models import FidelityBond, Offer, OfferType, OrderBook


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

    def test_store_offer_same_maker_multiple_oids_same_bond(self) -> None:
        """Same maker can have multiple offers (different oids) with the same bond."""
        client = DirectoryClient(
            host="test.onion",
            port=5222,
            network="regtest",
        )

        bond_utxo = "abc123def456:0"

        # Store first offer from maker
        offer1 = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
        )
        client._store_offer(("J5maker", 0), offer1, bond_utxo)

        # Store second offer from SAME maker, different oid, same bond
        offer2 = Offer(
            counterparty="J5maker",
            oid=1,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=50000,
            maxsize=2000000,
            txfee=500,
            cjfee="150",
        )
        client._store_offer(("J5maker", 1), offer2, bond_utxo)

        # Both offers should coexist (same maker, different oids)
        assert len(client.offers) == 2
        assert ("J5maker", 0) in client.offers
        assert ("J5maker", 1) in client.offers

        # Both should be tracked in the bond mapping
        assert bond_utxo in client._bond_to_offers
        assert ("J5maker", 0) in client._bond_to_offers[bond_utxo]
        assert ("J5maker", 1) in client._bond_to_offers[bond_utxo]


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


class TestOfferDirectoryNodesTracking:
    """Tests for tracking multiple directory nodes per offer."""

    def test_offer_directory_nodes_default_empty(self) -> None:
        """Offer.directory_nodes should default to empty list."""
        offer = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        assert offer.directory_nodes == []

    def test_offer_directory_nodes_can_be_set(self) -> None:
        """Offer.directory_nodes can be set to a list of directory nodes."""
        offer = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222"],
        )
        assert offer.directory_nodes == ["dir1.onion:5222", "dir2.onion:5222"]

    def test_orderbook_get_offers_by_directory_uses_directory_nodes(self) -> None:
        """OrderBook.get_offers_by_directory() should use directory_nodes list."""
        # Create an offer announced by multiple directories
        offer = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222", "dir3.onion:5222"],
        )

        orderbook = OrderBook()
        orderbook.offers.append(offer)

        offers_by_dir = orderbook.get_offers_by_directory()

        # The offer should appear under each directory it was announced on
        assert "dir1.onion:5222" in offers_by_dir
        assert "dir2.onion:5222" in offers_by_dir
        assert "dir3.onion:5222" in offers_by_dir
        assert len(offers_by_dir["dir1.onion:5222"]) == 1
        assert len(offers_by_dir["dir2.onion:5222"]) == 1
        assert len(offers_by_dir["dir3.onion:5222"]) == 1
        assert offers_by_dir["dir1.onion:5222"][0] == offer
        assert offers_by_dir["dir2.onion:5222"][0] == offer
        assert offers_by_dir["dir3.onion:5222"][0] == offer

    def test_orderbook_get_offers_by_directory_fallback_to_directory_node(self) -> None:
        """OrderBook.get_offers_by_directory() should fallback to directory_node if list empty."""
        # Create an offer with only directory_node set (not directory_nodes)
        offer = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_node="dir1.onion:5222",
        )

        orderbook = OrderBook()
        orderbook.offers.append(offer)

        offers_by_dir = orderbook.get_offers_by_directory()

        # Should fallback to directory_node (singular)
        assert "dir1.onion:5222" in offers_by_dir
        assert len(offers_by_dir["dir1.onion:5222"]) == 1

    def test_orderbook_get_offers_by_directory_unknown_when_no_directory(self) -> None:
        """OrderBook.get_offers_by_directory() should use 'unknown' if no directory info."""
        offer = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )

        orderbook = OrderBook()
        orderbook.offers.append(offer)

        offers_by_dir = orderbook.get_offers_by_directory()

        assert "unknown" in offers_by_dir
        assert len(offers_by_dir["unknown"]) == 1


class TestBondDirectoryNodesTracking:
    """Tests for tracking multiple directory nodes per fidelity bond.

    Bonds inherit directory_nodes from their associated offers - a bond is
    counted in all directories where the maker's offers appeared.
    """

    def test_bond_directory_nodes_default_empty(self) -> None:
        """FidelityBond.directory_nodes should default to empty list."""
        bond = FidelityBond(
            counterparty="J5test",
            utxo_txid="0" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
        )
        assert bond.directory_nodes == []

    def test_bond_directory_nodes_can_be_set(self) -> None:
        """FidelityBond.directory_nodes can be set to a list of directory nodes."""
        bond = FidelityBond(
            counterparty="J5test",
            utxo_txid="0" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222"],
        )
        assert bond.directory_nodes == ["dir1.onion:5222", "dir2.onion:5222"]

    def test_bond_inherits_directory_nodes_from_offers(self) -> None:
        """Bond directory_nodes should be populated from associated offers.

        This simulates the aggregator's logic where bonds inherit directory_nodes
        from all offers of the same counterparty.
        """
        # Create a bond
        bond = FidelityBond(
            counterparty="J5test",
            utxo_txid="a" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
        )

        # Create offers from the same maker seen on different directories
        offer1 = Offer(
            counterparty="J5test",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222"],
        )

        offer2 = Offer(
            counterparty="J5test",
            oid=1,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_nodes=["dir2.onion:5222", "dir3.onion:5222"],
        )

        # Simulate aggregator logic: populate bond directory_nodes from offers
        maker_offers = [offer1, offer2]
        all_directories: set[str] = set()
        for offer in maker_offers:
            all_directories.update(offer.directory_nodes)
        bond.directory_nodes = sorted(all_directories)

        # Bond should be counted in all directories where offers appeared
        assert len(bond.directory_nodes) == 3
        assert "dir1.onion:5222" in bond.directory_nodes
        assert "dir2.onion:5222" in bond.directory_nodes
        assert "dir3.onion:5222" in bond.directory_nodes


class TestBondDeduplicationAcrossDirectories:
    """Tests for bond deduplication logic in the aggregator.

    This tests the scenario where the same maker with the same bond appears
    on multiple directories, and ensures we don't lose directory tracking.
    """

    def test_same_maker_same_bond_across_directories_merges_nodes(self) -> None:
        """When same maker+bond appears on multiple directories, merge directory_nodes.

        This simulates the aggregator's get_live_orderbook() logic processing offers
        from multiple directories where the same maker is present.
        """
        # Aggregator uses (bond_utxo, oid) as key to preserve multiple offers per bond
        bond_utxo_key = "abc123def456:0"
        bond_oid_to_best_offer: dict[
            tuple[str, int], tuple[Offer, float, list[str], str]
        ] = {}  # (bond_utxo, oid) -> (offer, timestamp, directory_nodes, counterparty)

        # First directory announces the offer
        offer1 = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir1.onion:5222",
        )
        timestamp1 = 1000.0
        dedup_key = (bond_utxo_key, offer1.oid)
        directory_nodes = [offer1.directory_node] if offer1.directory_node else []
        bond_oid_to_best_offer[dedup_key] = (
            offer1,
            timestamp1,
            directory_nodes,
            offer1.counterparty,
        )

        # Second directory announces the SAME offer (same maker, same oid, same bond)
        offer2 = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir2.onion:5222",
        )
        timestamp2 = 1005.0  # Slightly newer

        # Simulate aggregator logic
        existing = bond_oid_to_best_offer.get(dedup_key)
        if existing:
            _old_offer, old_timestamp, directory_nodes, old_counterparty = existing
            is_same_maker = old_counterparty == offer2.counterparty

            if is_same_maker:
                # Merge directory_nodes
                if offer2.directory_node and offer2.directory_node not in directory_nodes:
                    directory_nodes.append(offer2.directory_node)
                # Keep newer timestamp
                if timestamp2 > old_timestamp:
                    bond_oid_to_best_offer[dedup_key] = (
                        offer2,
                        timestamp2,
                        directory_nodes,
                        offer2.counterparty,
                    )

        # Verify: Should have merged directory_nodes
        _final_offer, _final_timestamp, final_directories, _ = bond_oid_to_best_offer[dedup_key]
        assert len(final_directories) == 2
        assert "dir1.onion:5222" in final_directories
        assert "dir2.onion:5222" in final_directories

    def test_different_maker_same_bond_with_large_time_diff_replaces(self) -> None:
        """When different maker uses same bond after >60s, treat as legitimate restart."""
        bond_utxo_key = "abc123def456:0"
        bond_oid_to_best_offer: dict[tuple[str, int], tuple[Offer, float, list[str], str]] = {}

        # First maker with bond
        offer1 = Offer(
            counterparty="J5oldnick",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir1.onion:5222",
        )
        timestamp1 = 1000.0
        dedup_key = (bond_utxo_key, offer1.oid)
        directory_nodes = [offer1.directory_node] if offer1.directory_node else []
        bond_oid_to_best_offer[dedup_key] = (
            offer1,
            timestamp1,
            directory_nodes,
            offer1.counterparty,
        )

        # Second maker with SAME bond, 120 seconds later
        offer2 = Offer(
            counterparty="J5newnick",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir1.onion:5222",
        )
        timestamp2 = 1120.0  # 120s later

        # Simulate aggregator logic
        existing = bond_oid_to_best_offer.get(dedup_key)
        if existing:
            _old_offer, old_timestamp, directory_nodes, old_counterparty = existing
            is_same_maker = old_counterparty == offer2.counterparty

            if not is_same_maker:
                time_diff = timestamp2 - old_timestamp
                # Only replace if time difference suggests legitimate restart (>60s)
                if time_diff > 60:
                    # Reset directory_nodes for new maker
                    new_directory_nodes = [offer2.directory_node] if offer2.directory_node else []
                    bond_oid_to_best_offer[dedup_key] = (
                        offer2,
                        timestamp2,
                        new_directory_nodes,
                        offer2.counterparty,
                    )

        # Verify: Should have replaced with new maker
        final_offer, _final_timestamp, final_directories, _ = bond_oid_to_best_offer[dedup_key]
        assert final_offer.counterparty == "J5newnick"
        assert len(final_directories) == 1
        assert "dir1.onion:5222" in final_directories

    def test_different_maker_same_bond_with_small_time_diff_ignored(self) -> None:
        """When different maker uses same bond with <60s diff, likely clock skew - ignore."""
        bond_utxo_key = "abc123def456:0"
        bond_oid_to_best_offer: dict[tuple[str, int], tuple[Offer, float, list[str], str]] = {}

        # First maker with bond
        offer1 = Offer(
            counterparty="J5maker1",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir1.onion:5222",
        )
        timestamp1 = 1000.0
        dedup_key = (bond_utxo_key, offer1.oid)
        directory_nodes = [offer1.directory_node] if offer1.directory_node else []
        bond_oid_to_best_offer[dedup_key] = (
            offer1,
            timestamp1,
            directory_nodes,
            offer1.counterparty,
        )

        # Second maker with SAME bond, only 5 seconds later (likely clock skew)
        offer2 = Offer(
            counterparty="J5maker2",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir2.onion:5222",
        )
        timestamp2 = 1005.0  # 5s later

        # Simulate aggregator logic
        existing = bond_oid_to_best_offer.get(dedup_key)
        if existing:
            _old_offer, old_timestamp, directory_nodes, old_counterparty = existing
            is_same_maker = old_counterparty == offer2.counterparty

            if not is_same_maker:
                time_diff = timestamp2 - old_timestamp
                # Ignore if time difference is too small (<60s) - likely clock skew
                if abs(time_diff) >= 60:
                    new_directory_nodes = [offer2.directory_node] if offer2.directory_node else []
                    bond_oid_to_best_offer[dedup_key] = (
                        offer2,
                        timestamp2,
                        new_directory_nodes,
                        offer2.counterparty,
                    )
                # else: ignore, keep old offer

        # Verify: Should have kept the original maker (not replaced)
        final_offer, _final_timestamp, final_directories, _ = bond_oid_to_best_offer[dedup_key]
        assert final_offer.counterparty == "J5maker1"
        assert len(final_directories) == 1
        assert "dir1.onion:5222" in final_directories


class TestBondDeduplicationDirectoryTracking:
    """Tests for bond deduplication tracking directory_nodes.

    Bonds can be announced on multiple directories, and should track all of them
    independently of whether the maker has offers.
    """

    def test_bond_deduplication_merges_directory_nodes(self) -> None:
        """When same bond appears on multiple directories, merge directory_nodes."""
        # Simulate bond deduplication logic
        unique_bonds: dict[str, FidelityBond] = {}

        # First directory announces bond
        bond1 = FidelityBond(
            counterparty="J5maker",
            utxo_txid="a" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
            directory_node="dir1.onion:5222",
        )
        cache_key = f"{bond1.utxo_txid}:{bond1.utxo_vout}"

        if cache_key not in unique_bonds:
            if bond1.directory_node:
                bond1.directory_nodes = [bond1.directory_node]
            unique_bonds[cache_key] = bond1

        # Second directory announces SAME bond
        bond2 = FidelityBond(
            counterparty="J5maker",
            utxo_txid="a" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
            directory_node="dir2.onion:5222",
        )

        if cache_key not in unique_bonds:
            if bond2.directory_node:
                bond2.directory_nodes = [bond2.directory_node]
            unique_bonds[cache_key] = bond2
        else:
            # Merge directory_nodes
            existing_bond = unique_bonds[cache_key]
            if bond2.directory_node and bond2.directory_node not in existing_bond.directory_nodes:
                existing_bond.directory_nodes.append(bond2.directory_node)

        # Verify: Should have merged both directories
        final_bond = unique_bonds[cache_key]
        assert len(final_bond.directory_nodes) == 2
        assert "dir1.onion:5222" in final_bond.directory_nodes
        assert "dir2.onion:5222" in final_bond.directory_nodes

    def test_bond_without_offers_keeps_announcement_directories(self) -> None:
        """Bond announced on directories should track them even without offers.

        This tests the scenario where a maker has a bond but no active offers.
        The bond should still be counted in the directory statistics.
        """
        # Create bond announced on multiple directories (from deduplication)
        bond = FidelityBond(
            counterparty="J5maker",
            utxo_txid="a" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222"],
        )

        # No offers from this maker
        maker_offers: list[Offer] = []

        # Simulate aggregator's bond directory_nodes population
        if maker_offers:
            all_directories: set[str] = set(bond.directory_nodes)
            for offer in maker_offers:
                all_directories.update(offer.directory_nodes)
            bond.directory_nodes = sorted(all_directories)
        # else: Keep bond's existing directory_nodes

        # Verify: Bond should keep its announcement directories
        assert len(bond.directory_nodes) == 2
        assert "dir1.onion:5222" in bond.directory_nodes
        assert "dir2.onion:5222" in bond.directory_nodes

    def test_bond_merges_announcement_and_offer_directories(self) -> None:
        """Bond should track BOTH announcement directories AND offer directories.

        A bond might be announced on directory A and B, while the maker's offers
        appear on directory B and C. The bond should be counted in all three.
        """
        # Bond announced on dir1 and dir2 (from deduplication)
        bond = FidelityBond(
            counterparty="J5maker",
            utxo_txid="a" * 64,
            utxo_vout=0,
            locktime=500000,
            amount=10000000,
            script="0014abcd",
            utxo_confirmations=100,
            cert_expiry=1700000000,
            directory_nodes=["dir1.onion:5222", "dir2.onion:5222"],
        )

        # Maker has offers on dir2 and dir3
        offer = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_nodes=["dir2.onion:5222", "dir3.onion:5222"],
        )
        maker_offers = [offer]

        # Simulate aggregator's bond directory_nodes population
        if maker_offers:
            all_directories: set[str] = set(bond.directory_nodes)  # Start with bond's own
            for offer in maker_offers:
                all_directories.update(offer.directory_nodes)
            bond.directory_nodes = sorted(all_directories)

        # Verify: Bond should be in all three directories (merged)
        assert len(bond.directory_nodes) == 3
        assert "dir1.onion:5222" in bond.directory_nodes
        assert "dir2.onion:5222" in bond.directory_nodes
        assert "dir3.onion:5222" in bond.directory_nodes


class TestOfferDeduplicationPreservesDirectoryNodes:
    """Tests that the second deduplication pass preserves directory_nodes.

    The aggregator has two deduplication passes:
    1. Bond-based: groups by bond UTXO, accumulates directory_nodes
    2. Offer-based: groups by (counterparty, oid), merges directory_nodes

    The bug was that the second pass would reset directory_nodes to just
    [offer.directory_node] for the first occurrence, discarding the
    accumulated list from the bond deduplication.
    """

    def test_bond_offer_preserves_directory_nodes_in_second_pass(self) -> None:
        """Bond offer with accumulated directory_nodes should not be reset in second pass."""
        # Simulate bond deduplication output: offer with multiple directory_nodes
        offer = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="100",
            directory_node="dir1.onion:5222",  # Original directory_node
            directory_nodes=[
                "dir1.onion:5222",
                "dir2.onion:5222",
                "dir3.onion:5222",
            ],  # Accumulated
        )

        # Simulate second pass deduplication
        offer_key_to_offer: dict[tuple[str, int], Offer] = {}
        key = (offer.counterparty, offer.oid)

        if key not in offer_key_to_offer:
            # First time seeing this offer
            # BUG: Old code would reset directory_nodes here
            # FIX: Preserve existing directory_nodes (from bond deduplication) or initialize
            if not offer.directory_nodes and offer.directory_node:
                offer.directory_nodes = [offer.directory_node]
            offer_key_to_offer[key] = offer

        # Verify: directory_nodes should NOT be reset to single item
        result_offer = offer_key_to_offer[key]
        assert len(result_offer.directory_nodes) == 3
        assert "dir1.onion:5222" in result_offer.directory_nodes
        assert "dir2.onion:5222" in result_offer.directory_nodes
        assert "dir3.onion:5222" in result_offer.directory_nodes

    def test_non_bond_offer_still_initializes_directory_nodes(self) -> None:
        """Non-bond offer without directory_nodes should initialize from directory_node."""
        # Non-bond offer: has directory_node but not directory_nodes
        offer = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_node="dir1.onion:5222",
            # directory_nodes is empty by default
        )
        assert offer.directory_nodes == []

        # Simulate second pass deduplication
        offer_key_to_offer: dict[tuple[str, int], Offer] = {}
        key = (offer.counterparty, offer.oid)

        if key not in offer_key_to_offer:
            # Preserve existing directory_nodes or initialize from directory_node
            if not offer.directory_nodes and offer.directory_node:
                offer.directory_nodes = [offer.directory_node]
            offer_key_to_offer[key] = offer

        # Verify: directory_nodes should be initialized from directory_node
        result_offer = offer_key_to_offer[key]
        assert len(result_offer.directory_nodes) == 1
        assert "dir1.onion:5222" in result_offer.directory_nodes


class TestMultipleOidsPerMakerWithSameBond:
    """Tests that multiple offers (different oids) from same maker with same bond are preserved.

    A maker can have multiple offer types (e.g., oid=0 for relative fee, oid=1 for absolute fee)
    all backed by the same fidelity bond. The bond deduplication should keep ALL of these offers,
    not just the most recent one.
    """

    def test_same_maker_multiple_oids_same_bond_all_preserved(self) -> None:
        """All offers from same maker with same bond but different oids should be kept."""
        # New key structure: (bond_utxo_key, oid) instead of just bond_utxo_key
        bond_oid_to_best_offer: dict[
            tuple[str, int], tuple[Offer, float, list[str], str]
        ] = {}  # (bond_utxo, oid) -> (offer, timestamp, directory_nodes, counterparty)

        bond_utxo_key = "abc123def456:0"

        # First offer: oid=0 (relative fee)
        offer0 = Offer(
            counterparty="J5maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
            directory_node="dir1.onion:5222",
        )
        timestamp0 = 1000.0
        key0 = (bond_utxo_key, offer0.oid)
        bond_oid_to_best_offer[key0] = (
            offer0,
            timestamp0,
            [offer0.directory_node] if offer0.directory_node else [],
            offer0.counterparty,
        )

        # Second offer: oid=1 (absolute fee) - same maker, same bond, different oid
        offer1 = Offer(
            counterparty="J5maker",
            oid=1,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=50000,
            maxsize=500000,
            txfee=1000,
            cjfee="500",
            directory_node="dir1.onion:5222",
        )
        timestamp1 = 1001.0
        key1 = (bond_utxo_key, offer1.oid)
        bond_oid_to_best_offer[key1] = (
            offer1,
            timestamp1,
            [offer1.directory_node] if offer1.directory_node else [],
            offer1.counterparty,
        )

        # Verify: BOTH offers should be present (different keys due to different oids)
        assert len(bond_oid_to_best_offer) == 2
        assert key0 in bond_oid_to_best_offer
        assert key1 in bond_oid_to_best_offer

        # Verify offer details
        result_offer0, _, _, _ = bond_oid_to_best_offer[key0]
        result_offer1, _, _, _ = bond_oid_to_best_offer[key1]
        assert result_offer0.oid == 0
        assert result_offer0.ordertype == OfferType.SW0_RELATIVE
        assert result_offer1.oid == 1
        assert result_offer1.ordertype == OfferType.SW0_ABSOLUTE

    def test_maker_restart_replaces_only_matching_oid(self) -> None:
        """When maker restarts with new nick, only replace offers with matching oid."""
        bond_oid_to_best_offer: dict[tuple[str, int], tuple[Offer, float, list[str], str]] = {}

        bond_utxo_key = "abc123def456:0"

        # Original maker has two offers
        offer0_old = Offer(
            counterparty="J5oldnick",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        offer1_old = Offer(
            counterparty="J5oldnick",
            oid=1,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=50000,
            maxsize=500000,
            txfee=1000,
            cjfee="500",
        )
        timestamp_old = 1000.0
        bond_oid_to_best_offer[(bond_utxo_key, 0)] = (offer0_old, timestamp_old, [], "J5oldnick")
        bond_oid_to_best_offer[(bond_utxo_key, 1)] = (offer1_old, timestamp_old, [], "J5oldnick")

        # New maker (restarted) announces oid=0 with same bond, 120s later
        offer0_new = Offer(
            counterparty="J5newnick",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=30000,
            maxsize=1000000,
            txfee=500,
            cjfee="0.001",
        )
        timestamp_new = 1120.0

        # Simulate aggregator logic for the new offer
        dedup_key = (bond_utxo_key, offer0_new.oid)
        existing = bond_oid_to_best_offer.get(dedup_key)
        if existing:
            _, old_timestamp, _, old_counterparty = existing
            is_same_maker = old_counterparty == offer0_new.counterparty
            if not is_same_maker:
                time_diff = timestamp_new - old_timestamp
                if time_diff > 60:  # Legitimate restart
                    bond_oid_to_best_offer[dedup_key] = (
                        offer0_new,
                        timestamp_new,
                        [],
                        offer0_new.counterparty,
                    )

        # Verify: oid=0 should be replaced, oid=1 should be KEPT (even though it's from old nick)
        # This is because the new maker hasn't announced oid=1 yet
        assert len(bond_oid_to_best_offer) == 2

        result_offer0, _, _, counterparty0 = bond_oid_to_best_offer[(bond_utxo_key, 0)]
        assert result_offer0.counterparty == "J5newnick"
        assert counterparty0 == "J5newnick"

        result_offer1, _, _, counterparty1 = bond_oid_to_best_offer[(bond_utxo_key, 1)]
        assert result_offer1.counterparty == "J5oldnick"  # Still the old nick
        assert counterparty1 == "J5oldnick"
