"""
Adapter for fetching offers from Nostr relays.
"""

import asyncio
import time

from jmcore.models import FidelityBond, Offer
from jmcore.nostr import NostrEvent, OfferEventFactory
from jmcore.nostr_client import NostrClient
from loguru import logger
from pydantic import BaseModel, Field


class NostrWatcherConfig(BaseModel):
    """Configuration for NostrWatcherClient."""

    relays: list[str] = Field(default_factory=list)
    offer_timeout: int = Field(default=3600, description="Offer expiration in seconds")


class NostrWatcherClient:
    """Client for watching JoinMarket offers on Nostr relays."""

    def __init__(self, relays: list[str], offer_timeout: int = 3600) -> None:
        self.config = NostrWatcherConfig(relays=relays, offer_timeout=offer_timeout)
        self.client = NostrClient(relays)
        self.offers: dict[str, tuple[Offer, int]] = {}
        self.bonds: list[FidelityBond] = []
        self._subscription_task: asyncio.Task | None = None

    @classmethod
    def from_config(cls, config: NostrWatcherConfig) -> "NostrWatcherClient":
        return cls(relays=config.relays, offer_timeout=config.offer_timeout)

    async def fetch_offers(self) -> tuple[list[Offer], list[FidelityBond]]:
        """
        Fetch offers from configured Nostr relays.
        Returns a tuple of (offers, bonds).
        """
        filters = [{"kinds": [OfferEventFactory.KIND_JM_OFFER]}]

        events = await self.client.query(filters)
        offers: list[Offer] = []
        bonds: list[FidelityBond] = []
        now = int(time.time())

        for event in events:
            if now - event.created_at > self.config.offer_timeout:
                continue

            try:
                offer = Offer.model_validate_json(event.content)
                offer.fidelity_bond_value = 0
                offer.fidelity_bond_data = None
                offers.append(offer)
            except Exception as e:
                logger.warning(f"Failed to parse offer from event {event.id}: {e}")

        return offers, bonds

    async def listen_continuously(self) -> None:
        """Subscribe to Nostr relays and update offers continuously."""
        logger.info(f"Starting continuous Nostr listener on {self.config.relays}")
        filters = [{"kinds": [OfferEventFactory.KIND_JM_OFFER]}]

        async def on_event(event: NostrEvent) -> None:
            now = int(time.time())
            if now - event.created_at > self.config.offer_timeout:
                return

            try:
                offer = Offer.model_validate_json(event.content)
                offer.fidelity_bond_value = 0
                offer.fidelity_bond_data = None

                self.offers[event.id] = (offer, event.created_at)
                logger.debug(f"Received Nostr offer: {offer.oid} from {offer.counterparty}")
            except Exception as e:
                logger.warning(f"Failed to parse offer from Nostr event {event.id}: {e}")

        await self.client.subscribe(filters, on_event)

    def stop(self) -> None:
        """Cancel the subscription task if running."""
        if self._subscription_task and not self._subscription_task.done():
            self._subscription_task.cancel()

    def get_current_offers(self) -> list[Offer]:
        now = int(time.time())
        active_offers = []
        expired_ids = []

        for event_id, (offer, created_at) in self.offers.items():
            if now - created_at > self.config.offer_timeout:
                expired_ids.append(event_id)
            else:
                active_offers.append(offer)

        for event_id in expired_ids:
            del self.offers[event_id]

        return active_offers

    def get_current_bonds(self) -> list[FidelityBond]:
        return self.bonds
