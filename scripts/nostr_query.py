import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent / "jmcore/src"))

from jmcore.nostr import OfferEventFactory
from jmcore.nostr_client import NostrClient


async def main():
    # 1. Setup
    relay_url = "ws://localhost:7777"
    client = NostrClient([relay_url])

    # 2. Query
    print(f"Querying offers from {relay_url}...")
    filters = [{"kinds": [OfferEventFactory.KIND_JM_OFFER], "limit": 10}]

    events = await client.query(filters)

    print(f"Found {len(events)} events.")
    for event in events:
        print(f"\nEvent ID: {event.id}")
        print(f"Pubkey: {event.pubkey}")
        print(f"Content: {event.content}")
        # Verify signature
        if event.verify():
            print("Signature: VALID")
        else:
            print("Signature: INVALID")


if __name__ == "__main__":
    asyncio.run(main())
