#!/usr/bin/env python
"""Test orderbook watcher feature detection."""

import asyncio
import sys

sys.path.insert(0, "/home/m0u/code/bitcoin/joinmarket-ng/jmcore/src")
sys.path.insert(0, "/home/m0u/code/bitcoin/joinmarket-ng/orderbook_watcher/src")

from jmcore.settings import JoinMarketSettings
from orderbook_watcher.aggregator import OrderbookAggregator


async def main():
    # Override settings to use only NG directory
    settings = JoinMarketSettings(network="mainnet")
    settings.network_config.directory_servers = [
        "jmv2dirze66rwxsq7xv7frhmaufyicd3yz5if6obtavsskczjkndn6yd.onion:5222"
    ]

    print(f"Using directories: {settings.get_directory_servers()}")

    # Create aggregator
    directory_nodes = [
        (host_port.split(":")[0], int(host_port.split(":")[1]))
        for host_port in settings.get_directory_servers()
    ]
    aggregator = OrderbookAggregator(
        directory_nodes=directory_nodes,
        network=settings.network_config.network,
        socks_host=settings.tor.socks_host,
        socks_port=settings.tor.socks_port,
    )

    # Start listening
    await aggregator.start_continuous_listening()

    # Wait for initial connection and peerlist
    print("\nWaiting 30 seconds for connection and peerlist...")
    await asyncio.sleep(30)

    # Get orderbook
    orderbook = await aggregator.get_live_orderbook()

    print(
        f"\nCollected {len(orderbook.offers)} offers from {len(aggregator.clients)} directories"
    )

    # Check for J57wPBk1VfjSP5Te
    target_nick = "J57wPBk1VfjSP5Te"
    for offer in orderbook.offers:
        if offer.counterparty == target_nick:
            print(f"\nFound offer from {target_nick}:")
            print(f"  OrderID: {offer.oid}")
            print(f"  Type: {offer.ordertype}")
            print(f"  Features: {offer.features}")
            break
    else:
        print(f"\nMaker {target_nick} not found in orderbook")

    # Check feature cache in directory client
    for node_str, client in aggregator.clients.items():
        print(f"\nDirectory {node_str}:")
        print(f"  peerlist_features_supported: {client.peerlist_features_supported}")
        print(f"  peer_features cache size: {len(client.peer_features)}")
        if target_nick in client.peer_features:
            print(f"  Features for {target_nick}: {client.peer_features[target_nick]}")

    # Stop listening
    await aggregator.stop_listening()


if __name__ == "__main__":
    asyncio.run(main())
