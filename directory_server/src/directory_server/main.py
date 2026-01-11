"""
Main entry point for the directory server.
"""

import asyncio
import signal
import sys

from loguru import logger

from directory_server.config import get_settings
from directory_server.server import DirectoryServer


def setup_logging(level: str) -> None:
    logger.remove()

    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
        colorize=True,
    )


async def run_server() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)

    server_nick = f"directory-{settings.network}"

    logger.info("=" * 80)
    logger.info("Starting JoinMarket Directory Server")
    logger.info(f"Network: {settings.network}")
    logger.info(f"Server nick: {server_nick}")
    logger.info(f"Port: {settings.port}")
    logger.info(f"Max peers: {settings.max_peers}")
    logger.info("=" * 80)

    server = DirectoryServer(settings)

    loop = asyncio.get_running_loop()

    def shutdown_handler() -> None:
        logger.info("Received shutdown signal")
        asyncio.create_task(server.stop())

    def status_handler() -> None:
        logger.info("Received status signal")
        server.log_status()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_handler)

    loop.add_signal_handler(signal.SIGUSR1, status_handler)

    try:
        await server.start()
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        await server.stop()


def main() -> None:
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
