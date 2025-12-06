from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from jmcore.models import Offer, OfferType
from jmcore.nostr import OfferEventFactory

from orderbook_watcher.nostr_adapter import NostrWatcherClient

TEST_PRIV_KEY = "5c85b63076f752676735261313398c775604100657579899386d9a04a3f4e242"


@pytest.fixture
def sample_offer() -> Offer:
    return Offer(
        counterparty="test_counterparty",
        oid=123,
        ordertype=OfferType.SW0_ABSOLUTE,
        minsize=1000,
        maxsize=10000,
        txfee=100,
        cjfee=500,
        fidelity_bond_value=1000000,
    )


async def test_fetch_offers(sample_offer: Offer) -> None:
    event = OfferEventFactory.create_offer_event(sample_offer, TEST_PRIV_KEY)

    with patch("jmcore.nostr_client.NostrClient.query", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = [event]

        watcher_client = NostrWatcherClient(["ws://relay.test"])
        offers, bonds = await watcher_client.fetch_offers()

        assert len(offers) == 1
        expected_offer = sample_offer.model_copy()
        expected_offer.fidelity_bond_value = 0
        expected_offer.fidelity_bond_data = None

        assert offers[0] == expected_offer
        assert len(bonds) == 0


async def test_listen_continuously_stores_offers(sample_offer: Offer) -> None:
    """Test that listen_continuously correctly processes events via callback."""
    event = OfferEventFactory.create_offer_event(sample_offer, TEST_PRIV_KEY)

    async def invoke_callback(_filters: list[dict[str, Any]], callback: Callable) -> None:
        await callback(event)

    with patch("jmcore.nostr_client.NostrClient.subscribe", new_callable=AsyncMock) as mock_sub:
        mock_sub.side_effect = invoke_callback

        watcher_client = NostrWatcherClient(["ws://relay.test"])
        await watcher_client.listen_continuously()

        offers = watcher_client.get_current_offers()
        assert len(offers) == 1
        assert offers[0].oid == sample_offer.oid
