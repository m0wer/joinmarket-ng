import asyncio
import secrets
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent / "jmcore/src"))

from jmcore.models import Offer, OfferType
from jmcore.nostr import OfferEventFactory
from jmcore.nostr_client import NostrClient


async def main():
    # 1. Setup
    relay_url = "ws://localhost:7777"
    client = NostrClient([relay_url])

    # 2. Generate Identity
    priv_key = secrets.token_bytes(32)
    priv_key_hex = priv_key.hex()
    print(f"Generated Identity: {priv_key_hex}")

    # 3. Create Offer
    offer = Offer(
        counterparty="J5...dummy...",
        oid=0,
        ordertype=OfferType.SW0_ABSOLUTE,
        minsize=10000,
        maxsize=1000000,
        txfee=500,
        cjfee=1000,
        fidelity_bond_value=500000000,
    )

    print(f"Creating Offer: {offer}")

    # 4. Create Event
    event = OfferEventFactory.create_offer_event(offer, priv_key_hex)
    print(f"Created Event: {event.id}")
    print(f"Event Content: {event.content}")

    # 5. Publish
    print(f"Publishing to {relay_url}...")
    await client.publish(event)
    print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
