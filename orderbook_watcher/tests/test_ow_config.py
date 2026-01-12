"""
Tests for configuration management.
"""

from jmcore.settings import OrderbookWatcherSettings

from orderbook_watcher.config import get_directory_nodes


def test_default_settings() -> None:
    settings = OrderbookWatcherSettings()
    assert settings.http_port == 8000
    assert settings.update_interval == 60


def test_directory_nodes_parsing() -> None:
    nodes = get_directory_nodes("node1.onion:5222,node2.onion:5223")
    assert len(nodes) == 2
    assert nodes[0] == ("node1.onion", 5222)
    assert nodes[1] == ("node2.onion", 5223)


def test_directory_nodes_default_port() -> None:
    nodes = get_directory_nodes("node1.onion")
    assert len(nodes) == 1
    assert nodes[0] == ("node1.onion", 5222)


def test_empty_directory_nodes() -> None:
    nodes = get_directory_nodes("")
    assert len(nodes) == 0


def test_mempool_urls() -> None:
    settings = OrderbookWatcherSettings(
        mempool_api_url="https://api.example.com",
        mempool_web_url="https://web.example.com",
    )
    assert settings.mempool_api_url == "https://api.example.com"
    assert settings.mempool_web_url == "https://web.example.com"
