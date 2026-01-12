"""
Tests for monitoring functionality including signal handlers and stats.
"""

from unittest.mock import MagicMock, patch

import pytest
from jmcore.models import NetworkType, PeerInfo, PeerStatus
from jmcore.settings import DirectoryServerSettings

from directory_server.server import DirectoryServer


@pytest.fixture
def server():
    settings = DirectoryServerSettings(
        host="127.0.0.1",
        port=5223,
        health_check_host="127.0.0.1",
        health_check_port=18083,
    )
    srv = DirectoryServer(settings, NetworkType.MAINNET)
    srv.server = MagicMock()
    return srv


def test_server_is_healthy(server):
    server._shutdown = False
    assert server.is_healthy() is True


def test_server_is_unhealthy_when_shutdown(server):
    server._shutdown = True
    assert server.is_healthy() is False


def test_server_is_unhealthy_when_no_server(server):
    server.server = None
    assert server.is_healthy() is False


def test_server_is_unhealthy_when_max_peers_reached(server):
    for i in range(10001):
        peer = PeerInfo(
            nick=f"peer{i}",
            onion_address="NOT-SERVING-ONION",
            port=-1,
            network=NetworkType.MAINNET,
            status=PeerStatus.HANDSHAKED,
        )
        try:
            server.peer_registry.register(peer)
        except ValueError:
            break

    assert server.is_healthy() is False


def test_get_stats(server):
    stats = server.get_stats()

    assert "network" in stats
    assert "connected_peers" in stats
    assert "max_peers" in stats
    assert "active_connections" in stats

    assert stats["network"] == "mainnet"
    assert stats["max_peers"] == 10000


def test_get_detailed_stats(server):
    stats = server.get_detailed_stats()

    assert "network" in stats
    assert "uptime_seconds" in stats
    assert "server_status" in stats
    assert "max_peers" in stats
    assert "stats" in stats
    assert "connected_peers" in stats
    assert "passive_peers" in stats
    assert "active_peers" in stats
    assert "active_connections" in stats

    assert stats["network"] == "mainnet"
    assert stats["server_status"] == "running"
    assert isinstance(stats["uptime_seconds"], float)


def test_get_detailed_stats_with_peers(server):
    passive_peer = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    active_peer = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    server.peer_registry.register(passive_peer)
    server.peer_registry.register(active_peer)

    stats = server.get_detailed_stats()

    assert stats["stats"]["connected_peers"] == 2
    assert stats["stats"]["passive_peers"] == 1
    assert stats["stats"]["active_peers"] == 1

    assert stats["connected_peers"]["total"] == 2
    assert "taker1" in stats["connected_peers"]["nicks"]
    assert "maker1" in stats["connected_peers"]["nicks"]

    assert stats["passive_peers"]["total"] == 1
    assert "taker1" in stats["passive_peers"]["nicks"]

    assert stats["active_peers"]["total"] == 1
    assert "maker1" in stats["active_peers"]["nicks"]


def test_log_status(server):
    passive_peer = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    active_peer = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    server.peer_registry.register(passive_peer)
    server.peer_registry.register(active_peer)

    with patch("directory_server.server.logger") as mock_logger:
        server.log_status()

        call_args = [call[0][0] for call in mock_logger.info.call_args_list]
        log_output = " ".join(call_args)

        assert "Directory Server Status" in log_output
        assert "mainnet" in log_output
        assert "Connected peers: 2/10000" in log_output
        assert "Passive peers (orderbook watchers): 1" in log_output
        assert "Active peers (makers): 1" in log_output
        assert "taker1" in log_output
        assert "maker1" in log_output


@pytest.mark.asyncio
async def test_signal_handler_for_status():
    settings = DirectoryServerSettings(
        host="127.0.0.1",
        port=5224,
        health_check_host="127.0.0.1",
        health_check_port=18084,
    )
    server = DirectoryServer(settings, NetworkType.MAINNET)

    with patch("directory_server.server.logger") as mock_logger:
        server.log_status()

        assert mock_logger.info.called
        call_args = [call[0][0] for call in mock_logger.info.call_args_list]
        log_output = " ".join(call_args)

        assert "Directory Server Status" in log_output


def test_server_uptime_increases(server):
    import time

    stats1 = server.get_detailed_stats()
    uptime1 = stats1["uptime_seconds"]

    time.sleep(0.1)

    stats2 = server.get_detailed_stats()
    uptime2 = stats2["uptime_seconds"]

    assert uptime2 > uptime1


def test_server_status_stopping_when_shutdown(server):
    server._shutdown = True

    stats = server.get_detailed_stats()
    assert stats["server_status"] == "stopping"
