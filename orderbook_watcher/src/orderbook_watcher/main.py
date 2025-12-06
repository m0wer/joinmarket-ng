"""
Main entry point for the orderbook watcher.
"""

import asyncio
import signal
import sys

from loguru import logger

from orderbook_watcher.aggregator import OrderbookAggregator
from orderbook_watcher.config import get_settings
from orderbook_watcher.server import OrderbookServer


def setup_logging(level: str) -> None:
    logger.remove()

    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
        colorize=True,
    )


async def run_watcher() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)

    logger.info("Starting JoinMarket Orderbook Watcher")
    logger.info(f"Network: {settings.network}")
    logger.info(f"HTTP server: {settings.http_host}:{settings.http_port}")
    logger.info(f"Update interval: {settings.update_interval}s")
    logger.info(f"Mempool API: {settings.mempool_api_url}")

    directory_nodes = settings.get_directory_nodes()
    nostr_relays = settings.get_nostr_relays()

    if not directory_nodes and not nostr_relays:
        logger.error("No directory nodes or Nostr relays configured.")
        logger.error("Set DIRECTORY_NODES environment variable.")
        logger.error("Example: DIRECTORY_NODES=node1.onion:5222,node2.onion:5222")
        logger.error("Or set NOSTR_RELAYS environment variable.")
        logger.error("Example: NOSTR_RELAYS=wss://relay.damus.io")
        sys.exit(1)

    logger.info(f"Directory nodes: {len(directory_nodes)}")
    for node in directory_nodes:
        logger.info(f"  - {node[0]}:{node[1]}")

    logger.info(f"Nostr relays: {len(nostr_relays)}")
    for relay in nostr_relays:
        logger.info(f"  - {relay}")

    aggregator = OrderbookAggregator(
        directory_nodes=directory_nodes,
        network=settings.network,
        socks_host=settings.tor_socks_host,
        socks_port=settings.tor_socks_port,
        timeout=settings.connection_timeout,
        mempool_api_url=settings.mempool_api_url,
        max_message_size=settings.max_message_size,
        nostr_relays=settings.get_nostr_relays(),
    )

    server = OrderbookServer(settings, aggregator)

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def shutdown_handler() -> None:
        logger.info("Received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_handler)

    try:
        await server.start()
        await shutdown_event.wait()
    except asyncio.CancelledError:
        logger.info("Watcher cancelled")
    except Exception as e:
        logger.error(f"Watcher error: {e}")
        raise
    finally:
        await server.stop()


def main() -> None:
    try:
        asyncio.run(run_watcher())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
