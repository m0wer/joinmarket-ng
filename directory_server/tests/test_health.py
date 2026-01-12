"""
Tests for health check HTTP server and monitoring.
"""

import json
from http.client import HTTPConnection
from unittest.mock import MagicMock

import pytest
from jmcore.models import NetworkType
from jmcore.settings import DirectoryServerSettings

from directory_server.health import HealthCheckServer
from directory_server.server import DirectoryServer


@pytest.fixture
def mock_server():
    settings = DirectoryServerSettings(
        host="127.0.0.1",
        port=5222,
        health_check_host="127.0.0.1",
        health_check_port=18080,
    )
    server = DirectoryServer(settings, NetworkType.MAINNET)
    return server


@pytest.fixture
def health_server(mock_server):
    health = HealthCheckServer(host="127.0.0.1", port=18080)
    health.start(mock_server)
    yield health
    health.stop()


def test_health_endpoint_healthy(health_server, mock_server):
    mock_server.server = MagicMock()
    mock_server._shutdown = False

    conn = HTTPConnection("127.0.0.1", 18080, timeout=5)
    try:
        conn.request("GET", "/health")
        response = conn.getresponse()

        assert response.status == 200
        data = json.loads(response.read().decode())
        assert data["status"] == "healthy"
    finally:
        conn.close()


def test_health_endpoint_unhealthy(health_server, mock_server):
    mock_server.server = None

    conn = HTTPConnection("127.0.0.1", 18080, timeout=5)
    try:
        conn.request("GET", "/health")
        response = conn.getresponse()

        assert response.status == 503
    finally:
        conn.close()


def test_status_endpoint(health_server, mock_server):
    mock_server.server = MagicMock()
    mock_server._shutdown = False

    conn = HTTPConnection("127.0.0.1", 18080, timeout=5)
    try:
        conn.request("GET", "/status")
        response = conn.getresponse()

        assert response.status == 200
        data = json.loads(response.read().decode())

        assert "network" in data
        assert "uptime_seconds" in data
        assert "server_status" in data
        assert "connected_peers" in data
        assert "passive_peers" in data
        assert "active_peers" in data
        assert "active_connections" in data

        assert data["network"] == "mainnet"
        assert data["server_status"] in ["running", "stopping"]
    finally:
        conn.close()


def test_status_endpoint_includes_peer_stats(health_server, mock_server):
    from jmcore.models import NetworkType, PeerInfo, PeerStatus

    mock_server.server = MagicMock()
    mock_server._shutdown = False

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

    mock_server.peer_registry.register(passive_peer)
    mock_server.peer_registry.register(active_peer)

    conn = HTTPConnection("127.0.0.1", 18080, timeout=5)
    try:
        conn.request("GET", "/status")
        response = conn.getresponse()

        assert response.status == 200
        data = json.loads(response.read().decode())

        assert data["stats"]["passive_peers"] == 1
        assert data["stats"]["active_peers"] == 1
        assert data["stats"]["connected_peers"] == 2

        assert "taker1" in data["passive_peers"]["nicks"]
        assert "maker1" in data["active_peers"]["nicks"]
    finally:
        conn.close()


def test_health_endpoint_404_for_unknown_path():
    mock_server = MagicMock()
    health = HealthCheckServer(host="127.0.0.1", port=18085)
    health.start(mock_server)

    try:
        conn = HTTPConnection("127.0.0.1", 18085, timeout=5)
        try:
            conn.request("GET", "/unknown")
            response = conn.getresponse()

            assert response.status == 404
        finally:
            conn.close()
    finally:
        health.stop()


def test_health_server_start_stop():
    health = HealthCheckServer(host="127.0.0.1", port=18081)
    mock_server = MagicMock()

    health.start(mock_server)
    assert health.httpd is not None
    assert health.thread is not None
    assert health.thread.is_alive()

    health.stop()
