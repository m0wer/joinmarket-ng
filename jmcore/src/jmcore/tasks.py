"""
Shared async task utilities for JoinMarket components.

Provides common patterns for periodic background tasks used by
both maker and taker components.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any

from loguru import logger


async def run_periodic_task(
    name: str,
    callback: Callable[[], Coroutine[Any, Any, None]],
    interval: float,
    initial_delay: float = 0.0,
    running_check: Callable[[], bool] | None = None,
) -> None:
    """
    Run a callback periodically until cancelled or running_check returns False.

    Args:
        name: Human-readable task name for logging
        callback: Async function to call each interval
        interval: Seconds between invocations
        initial_delay: Seconds to wait before first invocation
        running_check: Optional callable returning False to stop the task
    """
    if initial_delay > 0:
        await asyncio.sleep(initial_delay)

    while running_check is None or running_check():
        try:
            await asyncio.sleep(interval)
            await callback()
        except asyncio.CancelledError:
            logger.info(f"{name} task cancelled")
            break
        except Exception as e:
            logger.error(f"Error in {name}: {e}")

    logger.info(f"{name} task stopped")


def parse_directory_address(server: str, default_port: int = 5222) -> tuple[str, int]:
    """
    Parse a directory server address string into host and port.

    Args:
        server: Server address in "host:port" or "host" format
        default_port: Port to use if not specified (default: 5222)

    Returns:
        Tuple of (host, port)
    """
    parts = server.split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else default_port
    return host, port
