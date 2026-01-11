"""
Tests for handling partial PEERLIST responses from directory servers.

Some directory servers send multiple partial PEERLIST responses (one per peer)
instead of a single complete list. This test verifies that we handle this correctly
by only removing offers for nicks explicitly marked as disconnected, not for nicks
that are simply absent from a specific response.
"""

from __future__ import annotations

from jmcore.directory_client import DirectoryClient
from jmcore.models import Offer, OfferType


class TestPartialPeerlistResponses:
    """Test handling of partial PEERLIST responses."""

    def test_partial_peerlist_does_not_remove_absent_nicks(self) -> None:
        """
        Partial peerlist responses should not remove offers from nicks not in that response.

        Scenario:
        1. Client has offers from 3 makers: Alice, Bob, Charlie
        2. Directory sends partial peerlist with only Alice
        3. Offers from Bob and Charlie should NOT be removed
        4. Only if Bob/Charlie are explicitly marked as disconnected should they be removed
        """
        client = DirectoryClient("test", 5222, "testnet")

        # Store offers from 3 different makers
        alice_offer = Offer(
            counterparty="J5alice",
            oid=0,
            ordertype=OfferType("sw0absoffer"),
            minsize=100000,
            maxsize=1000000,
            txfee=1000,
            cjfee="1000",
            fidelity_bond_value=0,
        )
        bob_offer = Offer(
            counterparty="J5bob",
            oid=0,
            ordertype=OfferType("sw0absoffer"),
            minsize=100000,
            maxsize=1000000,
            txfee=1000,
            cjfee="1000",
            fidelity_bond_value=0,
        )
        charlie_offer = Offer(
            counterparty="J5charlie",
            oid=0,
            ordertype=OfferType("sw0absoffer"),
            minsize=100000,
            maxsize=1000000,
            txfee=1000,
            cjfee="1000",
            fidelity_bond_value=0,
        )

        client._store_offer(("J5alice", 0), alice_offer, None)
        client._store_offer(("J5bob", 0), bob_offer, None)
        client._store_offer(("J5charlie", 0), charlie_offer, None)

        assert len(client.offers) == 3

        # Simulate partial peerlist response with only Alice (no disconnect markers)
        partial_peerlist = "J5alice;onion1.onion:5222"
        peers = client._handle_peerlist_response(partial_peerlist)

        # Should have parsed Alice as active peer
        assert len(peers) == 1
        assert peers[0][0] == "J5alice"

        # Should NOT have removed Bob and Charlie's offers
        assert len(client.offers) == 3
        assert ("J5alice", 0) in client.offers
        assert ("J5bob", 0) in client.offers
        assert ("J5charlie", 0) in client.offers

        # Alice should be in active peers
        assert "J5alice" in client._active_peers

    def test_explicit_disconnect_removes_offers(self) -> None:
        """
        Nicks explicitly marked as disconnected (;D suffix) should have offers removed.
        """
        client = DirectoryClient("test", 5222, "testnet")

        # Store offers from 2 makers
        alice_offer = Offer(
            counterparty="J5alice",
            oid=0,
            ordertype=OfferType("sw0absoffer"),
            minsize=100000,
            maxsize=1000000,
            txfee=1000,
            cjfee="1000",
            fidelity_bond_value=0,
        )
        bob_offer = Offer(
            counterparty="J5bob",
            oid=0,
            ordertype=OfferType("sw0absoffer"),
            minsize=100000,
            maxsize=1000000,
            txfee=1000,
            cjfee="1000",
            fidelity_bond_value=0,
        )

        client._store_offer(("J5alice", 0), alice_offer, None)
        client._store_offer(("J5bob", 0), bob_offer, None)

        assert len(client.offers) == 2

        # Peerlist shows Alice connected, Bob explicitly disconnected
        peerlist = "J5alice;onion1.onion:5222,J5bob;onion2.onion:5222;D"
        peers = client._handle_peerlist_response(peerlist)

        # Should have parsed Alice as active, Bob as disconnected
        assert len(peers) == 1
        assert peers[0][0] == "J5alice"

        # Bob's offers should be removed
        assert len(client.offers) == 1
        assert ("J5alice", 0) in client.offers
        assert ("J5bob", 0) not in client.offers

        # Only Alice should be in active peers
        assert "J5alice" in client._active_peers
        assert "J5bob" not in client._active_peers

    def test_multiple_partial_responses_accumulate(self) -> None:
        """
        Multiple partial peerlist responses should accumulate active peers.
        """
        client = DirectoryClient("test", 5222, "testnet")

        # First partial response with Alice
        peerlist1 = "J5alice;onion1.onion:5222"
        client._handle_peerlist_response(peerlist1)

        assert "J5alice" in client._active_peers
        assert len(client._active_peers) == 1

        # Second partial response with Bob
        peerlist2 = "J5bob;onion2.onion:5222"
        client._handle_peerlist_response(peerlist2)

        # Both should be in active peers now
        assert "J5alice" in client._active_peers
        assert "J5bob" in client._active_peers
        assert len(client._active_peers) == 2

        # Third partial response with Charlie and Alice disconnected
        peerlist3 = "J5charlie;onion3.onion:5222,J5alice;onion1.onion:5222;D"
        client._handle_peerlist_response(peerlist3)

        # Alice should be removed, Bob and Charlie should remain
        assert "J5alice" not in client._active_peers
        assert "J5bob" in client._active_peers
        assert "J5charlie" in client._active_peers
        assert len(client._active_peers) == 2
