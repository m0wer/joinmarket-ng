"""
Configuration management using unified JoinMarket settings.
"""

from jmcore.settings import OrderbookWatcherSettings, get_settings


def get_orderbook_watcher_settings() -> OrderbookWatcherSettings:
    """Get orderbook watcher settings from unified config."""
    settings = get_settings()
    return settings.orderbook_watcher


def get_directory_nodes(directory_nodes: str) -> list[tuple[str, int]]:
    """Parse directory nodes string into list of (host, port) tuples."""
    if not directory_nodes:
        return []
    nodes = []
    for node in directory_nodes.split(","):
        node = node.strip()
        if not node:
            continue
        if ":" in node:
            host, port_str = node.rsplit(":", 1)
            nodes.append((host, int(port_str)))
        else:
            nodes.append((node, 5222))
    return nodes
