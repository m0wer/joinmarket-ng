"""
Main entry point for the directory server.
"""

import asyncio
import signal
import sys

from loguru import logger

from directory_server.config import get_settings
from directory_server.server import DirectoryServer


def setup_logging(level: str, log_file: str) -> None:
    logger.remove()

    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=level,
        colorize=True,
    )

    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=level,
        rotation="10 MB",
        retention="7 days",
        compression="gz",
    )


async def run_server() -> None:
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_file)

    logger.info("Starting JoinMarket Directory Server")
    logger.info(f"Network: {settings.network}")
    logger.info(f"Port: {settings.port}")
    logger.info(f"Max peers: {settings.max_peers}")

    server = DirectoryServer(settings)

    loop = asyncio.get_running_loop()

    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(server.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

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
