"""
Tests for CLI commands.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

from directory_server.cli import format_status_output, health_command, status_command


class MockHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            health_response = {"status": "healthy"}
            self.wfile.write(json.dumps(health_response).encode())
        elif self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            status_response: dict[str, object] = {
                "network": "mainnet",
                "uptime_seconds": 3600,
                "server_status": "running",
                "max_peers": 10000,
                "stats": {
                    "total_peers": 10,
                    "connected_peers": 10,
                    "passive_peers": 3,
                    "active_peers": 7,
                },
                "connected_peers": {"total": 10, "nicks": ["peer1", "peer2"]},
                "passive_peers": {"total": 3, "nicks": ["taker1", "taker2"]},
                "active_peers": {"total": 7, "nicks": ["maker1", "maker2"]},
                "active_connections": 10,
            }
            self.wfile.write(json.dumps(status_response).encode())
        elif self.path == "/health_unhealthy":
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            unhealthy_response = {"status": "unhealthy"}
            self.wfile.write(json.dumps(unhealthy_response).encode())
        else:
            self.send_error(404)


@pytest.fixture
def mock_http_server():
    httpd = HTTPServer(("127.0.0.1", 18082), MockHTTPHandler)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()  # Explicitly close the socket


def test_status_command_success(mock_http_server):
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 18082
    args.json = False

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = status_command(args)

    assert result == 0
    output = fake_out.getvalue()
    assert "Directory Server Status" in output
    assert "mainnet" in output
    assert "Connected peers: 10/1000" in output


def test_status_command_json_output(mock_http_server):
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 18082
    args.json = True

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = status_command(args)

    assert result == 0
    output = fake_out.getvalue()
    data = json.loads(output)
    assert data["network"] == "mainnet"
    assert data["stats"]["passive_peers"] == 3
    assert data["stats"]["active_peers"] == 7


def test_status_command_connection_error():
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 19999
    args.json = False

    with patch("sys.stderr", new=StringIO()) as fake_err:
        result = status_command(args)

    assert result == 1
    error = fake_err.getvalue()
    assert "Could not connect" in error


def test_health_command_healthy(mock_http_server):
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 18082
    args.json = False

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = health_command(args)

    assert result == 0
    output = fake_out.getvalue()
    assert "healthy" in output


def test_health_command_json_output(mock_http_server):
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 18082
    args.json = True

    with patch("sys.stdout", new=StringIO()) as fake_out:
        result = health_command(args)

    assert result == 0
    output = fake_out.getvalue()
    data = json.loads(output)
    assert data["status"] == "healthy"


def test_health_command_connection_error():
    args = MagicMock()
    args.host = "127.0.0.1"
    args.port = 19999
    args.json = False

    with patch("sys.stderr", new=StringIO()) as fake_err:
        result = health_command(args)

    assert result == 1
    error = fake_err.getvalue()
    assert "unhealthy or unreachable" in error


def test_format_status_output():
    stats = {
        "network": "mainnet",
        "uptime_seconds": 3600,
        "server_status": "running",
        "max_peers": 10000,
        "connected_peers": {"total": 10, "nicks": ["peer1", "peer2"]},
        "passive_peers": {"total": 3, "nicks": ["taker1", "taker2", "taker3"]},
        "active_peers": {"total": 7, "nicks": ["maker1", "maker2"]},
        "active_connections": 10,
    }

    output = format_status_output(stats)

    assert "Directory Server Status" in output
    assert "Network: mainnet" in output
    assert "Uptime: 3600s (1.0h)" in output
    assert "Connected peers: 10/1000" in output
    assert "Passive peers (orderbook watchers): 3" in output
    assert "Active peers (makers): 7" in output
    assert "taker1" in output
    assert "maker1" in output


def test_format_status_output_with_many_peers():
    nicks = [f"peer{i}" for i in range(50)]
    stats = {
        "network": "testnet",
        "uptime_seconds": 7200,
        "server_status": "running",
        "max_peers": 10000,
        "connected_peers": {"total": 50, "nicks": nicks},
        "passive_peers": {"total": 25, "nicks": nicks[:25]},
        "active_peers": {"total": 25, "nicks": nicks[25:]},
        "active_connections": 50,
    }

    output = format_status_output(stats)

    assert "... and 30 more" in output
    assert "... and 5 more" in output
