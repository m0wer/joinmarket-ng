"""
Tests for configuration management.
"""

from orderbook_watcher.config import Settings


def test_default_settings() -> None:
    settings = Settings()
    assert settings.network == "mainnet"
    assert settings.http_port == 8000
    assert settings.update_interval == 60


def test_directory_nodes_parsing() -> None:
    settings = Settings(directory_nodes="node1.onion:5222,node2.onion:5223")
    nodes = settings.get_directory_nodes()
    assert len(nodes) == 2
    assert nodes[0] == ("node1.onion", 5222)
    assert nodes[1] == ("node2.onion", 5223)


def test_directory_nodes_default_port() -> None:
    settings = Settings(directory_nodes="node1.onion")
    nodes = settings.get_directory_nodes()
    assert len(nodes) == 1
    assert nodes[0] == ("node1.onion", 5222)


def test_empty_directory_nodes() -> None:
    settings = Settings(directory_nodes="")
    nodes = settings.get_directory_nodes()
    assert len(nodes) == 0


def test_mempool_urls() -> None:
    settings = Settings(
        mempool_api_url="https://api.example.com",
        mempool_web_url="https://web.example.com",
        mempool_web_onion_url="http://onion.example.com",
    )
    assert settings.mempool_api_url == "https://api.example.com"
    assert settings.mempool_web_url == "https://web.example.com"
    assert settings.mempool_web_onion_url == "http://onion.example.com"
