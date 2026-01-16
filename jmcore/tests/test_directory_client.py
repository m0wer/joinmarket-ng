import contextlib
import json
from unittest.mock import AsyncMock, patch

import pytest

from jmcore.directory_client import DirectoryClient, MessageType
from jmcore.protocol import FEATURE_PEERLIST_FEATURES


@pytest.mark.asyncio
async def test_get_peerlist_with_features_logs_correctly():
    """Test that get_peerlist_with_features logs the correct message."""
    from loguru import logger

    # Capture logs
    logs = []
    logger.add(lambda msg: logs.append(msg))

    # Mock the connection
    mock_connection = AsyncMock()

    # Setup the response
    response_data = {
        "type": MessageType.PEERLIST.value,
        "line": f"nick1;location1;F:{FEATURE_PEERLIST_FEATURES}",
    }
    mock_connection.receive.return_value = json.dumps(response_data).encode("utf-8")

    # Initialize client
    client = DirectoryClient("host", 1234, "mainnet")
    client.connection = mock_connection

    # Run the method
    peers = await client.get_peerlist_with_features()

    # Verify the log message
    log_text = "".join(str(log) for log in logs)
    assert "Sending GETPEERLIST request" in log_text
    assert "with features support" not in log_text

    # Verify the request was sent
    mock_connection.send.assert_called_once()
    sent_msg = json.loads(mock_connection.send.call_args[0][0].decode("utf-8"))
    assert sent_msg["type"] == MessageType.GETPEERLIST.value
    assert sent_msg["line"] == ""

    # Verify return value
    assert len(peers) == 1
    nick, loc, features = peers[0]
    assert nick == "nick1"
    assert loc == "location1"
    assert features.supports_peerlist_features()


@pytest.mark.asyncio
async def test_peerlist_timeout_with_announced_features_does_not_disable():
    """
    Test that when directory announced peerlist_features during handshake,
    timeout does not permanently disable peerlist requests (it may just be slow).
    """
    # Mock the connection
    mock_connection = AsyncMock()
    mock_connection.receive.side_effect = TimeoutError("simulated timeout")

    # Initialize client with directory that announced peerlist_features
    client = DirectoryClient("host", 1234, "mainnet")
    client.connection = mock_connection
    client.directory_peerlist_features = True  # Directory announced feature
    client._peerlist_timeout = 0.1  # Very short timeout for test

    # First request - should timeout but NOT disable peerlist
    peers = await client.get_peerlist_with_features()
    assert peers == []
    assert client._peerlist_supported is not False  # Should NOT be disabled
    assert client._peerlist_timeout_count == 1

    # Reset rate limit to allow another request
    client._last_peerlist_request_time = 0

    # Second request - should also timeout but still NOT disable peerlist
    peers = await client.get_peerlist_with_features()
    assert peers == []
    assert client._peerlist_supported is not False  # Still NOT disabled
    assert client._peerlist_timeout_count == 2


@pytest.mark.asyncio
async def test_peerlist_timeout_without_announced_features_disables():
    """
    Test that when directory did NOT announce peerlist_features,
    timeout permanently disables peerlist requests (likely reference impl).
    """
    # Mock the connection
    mock_connection = AsyncMock()
    mock_connection.receive.side_effect = TimeoutError("simulated timeout")

    # Initialize client without peerlist_features announcement
    client = DirectoryClient("host", 1234, "mainnet")
    client.connection = mock_connection
    client.directory_peerlist_features = False  # Directory did NOT announce feature
    client.timeout = 0.1  # Very short timeout for test

    # First request - should timeout AND disable peerlist
    peers = await client.get_peerlist_with_features()
    assert peers == []
    assert client._peerlist_supported is False  # Should be disabled

    # Reset rate limit
    client._last_peerlist_request_time = 0

    # Second request - should be skipped because peerlist is disabled
    mock_connection.send.reset_mock()
    peers = await client.get_peerlist_with_features()
    assert peers == []
    mock_connection.send.assert_not_called()  # Should skip the request entirely


@pytest.mark.asyncio
async def test_peerlist_success_resets_timeout_count():
    """Test that successful peerlist response resets the timeout counter."""
    # Mock the connection
    mock_connection = AsyncMock()

    # Initialize client
    client = DirectoryClient("host", 1234, "mainnet")
    client.connection = mock_connection
    client.directory_peerlist_features = True
    client._peerlist_timeout_count = 5  # Simulate previous timeouts

    # Setup successful response
    response_data = {
        "type": MessageType.PEERLIST.value,
        "line": "nick1;location1",
    }
    mock_connection.receive.return_value = json.dumps(response_data).encode("utf-8")

    # Run the method
    await client.get_peerlist_with_features()

    # Verify timeout count was reset
    assert client._peerlist_timeout_count == 0
    assert client._peerlist_supported is True


@pytest.mark.asyncio
async def test_privmsg_fidelity_bond_taker_nick():
    """
    Test that when receiving an offer via PRIVMSG, the fidelity bond is verified
    against the recipient's nick (us), not the maker's nick.
    """
    import asyncio

    # Setup
    client = DirectoryClient("host", 1234, "mainnet")
    client.nick = "MyNick"
    client.connection = AsyncMock()

    # Maker sending the offer
    maker_nick = "MakerNick"
    offer_msg = f"{maker_nick}!MyNick!sw0reloffer 0 1000 100000 500 0.001!tbond BOND_PROOF_BASE64"

    msg_data = {"type": MessageType.PRIVMSG.value, "line": offer_msg}

    # Mock receive to return the message then raise CancelledError to stop loop
    client.connection.receive.side_effect = [
        json.dumps(msg_data).encode("utf-8"),
        asyncio.CancelledError("Stop"),
    ]

    # Mock get_peerlist_with_features to do nothing
    client.get_peerlist_with_features = AsyncMock()

    # Mock parse_fidelity_bond_proof to verify arguments
    with patch("jmcore.directory_client.parse_fidelity_bond_proof") as mock_parse:
        # Pre-populate peer features
        client.peer_features = {maker_nick: {}}

        # Return a dummy bond dict so the code proceeds
        mock_parse.return_value = {
            "utxo_txid": "a" * 64,
            "utxo_vout": 0,
            "locktime": 1234567890,
            "utxo_pub": "02" + "a" * 64,
            "cert_expiry": 1000,
            "maker_nick": maker_nick,
            "taker_nick": "MyNick",
        }

        # Run listen_continuously for a short time
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(client.listen_continuously(request_orderbook=False), timeout=0.1)

        # Verify parse_fidelity_bond_proof was called with correct arguments
        # args: (proof_base64, maker_nick, taker_nick)
        # We expect taker_nick to be "MyNick" because it was a PRIVMSG to us
        mock_parse.assert_called_with("BOND_PROOF_BASE64", maker_nick, "MyNick")


def test_update_offer_features_updates_cached_offers():
    """
    Test that _update_offer_features correctly updates features on cached offers.

    This tests the fix for the race condition where offers are stored before
    peerlist response arrives with features.
    """
    from jmcore.directory_client import OfferWithTimestamp
    from jmcore.models import Offer, OfferType

    client = DirectoryClient("host", 1234, "mainnet")

    # Create some cached offers with empty features
    offer1 = Offer(
        counterparty="maker1",
        oid=0,
        ordertype=OfferType.SW0_RELATIVE,
        minsize=1000,
        maxsize=100000,
        txfee=500,
        cjfee="0.001",
        features={},  # Empty features
    )
    offer2 = Offer(
        counterparty="maker1",
        oid=1,
        ordertype=OfferType.SW0_ABSOLUTE,
        minsize=2000,
        maxsize=200000,
        txfee=600,
        cjfee="1000",
        features={},  # Empty features
    )
    offer3 = Offer(
        counterparty="maker2",  # Different maker
        oid=0,
        ordertype=OfferType.SW0_RELATIVE,
        minsize=3000,
        maxsize=300000,
        txfee=700,
        cjfee="0.002",
        features={},  # Empty features
    )

    # Store offers in cache
    client.offers[("maker1", 0)] = OfferWithTimestamp(offer=offer1, received_at=1.0)
    client.offers[("maker1", 1)] = OfferWithTimestamp(offer=offer2, received_at=2.0)
    client.offers[("maker2", 0)] = OfferWithTimestamp(offer=offer3, received_at=3.0)

    # Update features for maker1
    updated_count = client._update_offer_features(
        "maker1", {"neutrino_compat": True, "other_feature": True}
    )

    # Verify count
    assert updated_count == 2

    # Verify maker1's offers have updated features
    assert offer1.features == {"neutrino_compat": True, "other_feature": True}
    assert offer2.features == {"neutrino_compat": True, "other_feature": True}

    # Verify maker2's offer is unchanged
    assert offer3.features == {}


def test_update_offer_features_no_matching_offers():
    """Test _update_offer_features when no offers match the nick."""
    client = DirectoryClient("host", 1234, "mainnet")

    # No offers cached
    updated_count = client._update_offer_features("nonexistent_maker", {"neutrino_compat": True})

    assert updated_count == 0


def test_update_offer_features_only_sets_true_values():
    """Test that _update_offer_features only sets features with True values."""
    from jmcore.directory_client import OfferWithTimestamp
    from jmcore.models import Offer, OfferType

    client = DirectoryClient("host", 1234, "mainnet")

    # Create offer with one existing feature
    offer = Offer(
        counterparty="maker1",
        oid=0,
        ordertype=OfferType.SW0_RELATIVE,
        minsize=1000,
        maxsize=100000,
        txfee=500,
        cjfee="0.001",
        features={"existing_feature": True},
    )
    client.offers[("maker1", 0)] = OfferWithTimestamp(offer=offer, received_at=1.0)

    # Update with mixed true/false features
    client._update_offer_features("maker1", {"neutrino_compat": True, "disabled_feature": False})

    # Only true features should be added
    assert offer.features == {"existing_feature": True, "neutrino_compat": True}
    assert "disabled_feature" not in offer.features


def test_peerlist_response_updates_cached_offer_features():
    """
    Integration test: verify that processing a peerlist response updates
    features on previously cached offers.

    This tests the full fix for the race condition bug.
    """
    from jmcore.directory_client import OfferWithTimestamp
    from jmcore.models import Offer, OfferType
    from jmcore.protocol import FEATURE_NEUTRINO_COMPAT

    client = DirectoryClient("host", 1234, "mainnet")

    # Create an offer with empty features (simulating race condition)
    offer = Offer(
        counterparty="J57wPBk1VfjSP5Te",
        oid=0,
        ordertype=OfferType.SW0_RELATIVE,
        minsize=30000,
        maxsize=643786,
        txfee=0,
        cjfee="0.0001",
        features={},  # Empty - offer stored before peerlist arrived
    )
    client.offers[("J57wPBk1VfjSP5Te", 0)] = OfferWithTimestamp(offer=offer, received_at=1.0)

    # Simulate peerlist response with features
    peerlist_str = f"J57wPBk1VfjSP5Te;maker.onion:62780;F:{FEATURE_NEUTRINO_COMPAT}"

    # Process peerlist response
    peers = client._handle_peerlist_response(peerlist_str)

    # Verify peer was parsed
    assert len(peers) == 1
    nick, location, features = peers[0]
    assert nick == "J57wPBk1VfjSP5Te"
    assert features.supports_neutrino_compat()

    # Verify peer_features cache was updated
    assert client.peer_features["J57wPBk1VfjSP5Te"] == {"neutrino_compat": True}

    # Verify cached offer's features were updated (THE FIX)
    assert offer.features == {"neutrino_compat": True}
