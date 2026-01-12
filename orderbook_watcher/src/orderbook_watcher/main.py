"""
Main entry point for the orderbook watcher.
"""

import asyncio
import os
import signal
import sys

from jmcore.notifications import get_notifier
from jmcore.settings import get_settings
from loguru import logger

from orderbook_watcher.aggregator import OrderbookAggregator
from orderbook_watcher.config import get_directory_nodes
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
    setup_logging(settings.logging.level)

    network = settings.network_config.network
    watcher_settings = settings.orderbook_watcher

    logger.info("=" * 80)
    logger.info("Starting JoinMarket Orderbook Watcher")
    logger.info(f"Network: {network.value}")
    logger.info(f"HTTP server: {watcher_settings.http_host}:{watcher_settings.http_port}")
    logger.info(f"Update interval: {watcher_settings.update_interval}s")
    logger.info(f"Mempool API: {watcher_settings.mempool_api_url}")

    # Directory nodes from env var (DIRECTORY_NODES) or config
    directory_nodes_str = os.environ.get("DIRECTORY_NODES", "")
    if not directory_nodes_str:
        # Fall back to directory servers from network config
        if settings.network_config.directory_servers:
            directory_nodes_str = ",".join(settings.network_config.directory_servers)
        else:
            # Use default directory servers
            directory_nodes_str = ",".join(settings.get_directory_servers())

    directory_nodes = get_directory_nodes(directory_nodes_str)
    if not directory_nodes:
        logger.error("No directory nodes configured. Set DIRECTORY_NODES environment variable.")
        logger.error("Example: DIRECTORY_NODES=node1.onion:5222,node2.onion:5222")
        sys.exit(1)

    logger.info(f"Directory nodes: {len(directory_nodes)}")
    for node in directory_nodes:
        logger.info(f"  - {node[0]}:{node[1]}")
    logger.info("=" * 80)

    aggregator = OrderbookAggregator(
        directory_nodes=directory_nodes,
        network=network.value,
        socks_host=settings.tor.socks_host,
        socks_port=settings.tor.socks_port,
        timeout=watcher_settings.connection_timeout,
        mempool_api_url=watcher_settings.mempool_api_url,
        max_message_size=watcher_settings.max_message_size,
        uptime_grace_period=watcher_settings.uptime_grace_period,
    )

    server = OrderbookServer(watcher_settings, aggregator)

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def shutdown_handler() -> None:
        logger.info("Received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_handler)

    try:
        # Send startup notification immediately
        notifier = get_notifier()
        await notifier.notify_startup(
            component="Orderbook Watcher",
            network=network.value,
        )
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
