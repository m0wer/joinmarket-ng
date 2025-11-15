"""
Tests for handshake handler.
"""

import json

import pytest
from jmcore.models import NetworkType
from jmcore.protocol import JM_VERSION

from directory_server.handshake_handler import HandshakeError, HandshakeHandler


@pytest.fixture
def handler():
    return HandshakeHandler(
        network=NetworkType.MAINNET, server_nick="test_directory", motd="Test Server"
    )


def test_valid_handshake(handler):
    handshake_data = json.dumps(
        {
            "app-name": "joinmarket",
            "directory": False,
            "location-string": "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:5222",
            "proto-ver": JM_VERSION,
            "features": {},
            "nick": "test_client",
            "network": "mainnet",
        }
    )

    peer_info, response = handler.process_handshake(handshake_data, "127.0.0.1:12345")

    assert peer_info.nick == "test_client"
    assert peer_info.network == NetworkType.MAINNET
    assert response["accepted"] is True
    assert response["app-name"] == "joinmarket"


def test_handshake_wrong_app_name(handler):
    handshake_data = json.dumps(
        {
            "app-name": "WrongApp",
            "directory": False,
            "location-string": "test.onion:5222",
            "proto-ver": JM_VERSION,
            "features": {},
            "nick": "test",
            "network": "mainnet",
        }
    )

    with pytest.raises(HandshakeError, match="Invalid app name"):
        handler.process_handshake(handshake_data, "127.0.0.1:12345")


def test_handshake_wrong_protocol_version(handler):
    handshake_data = json.dumps(
        {
            "app-name": "joinmarket",
            "directory": False,
            "location-string": "test.onion:5222",
            "proto-ver": 999,
            "features": {},
            "nick": "test",
            "network": "mainnet",
        }
    )

    with pytest.raises(HandshakeError, match="Protocol version mismatch"):
        handler.process_handshake(handshake_data, "127.0.0.1:12345")


def test_handshake_wrong_network(handler):
    handshake_data = json.dumps(
        {
            "app-name": "joinmarket",
            "directory": False,
            "location-string": "test.onion:5222",
            "proto-ver": JM_VERSION,
            "features": {},
            "nick": "test",
            "network": "testnet",
        }
    )

    with pytest.raises(HandshakeError, match="Network mismatch"):
        handler.process_handshake(handshake_data, "127.0.0.1:12345")


def test_handshake_directory_client_rejected(handler):
    handshake_data = json.dumps(
        {
            "app-name": "joinmarket",
            "directory": True,
            "location-string": "test.onion:5222",
            "proto-ver": JM_VERSION,
            "features": {},
            "nick": "test",
            "network": "mainnet",
        }
    )

    with pytest.raises(HandshakeError, match="Directory nodes not accepted"):
        handler.process_handshake(handshake_data, "127.0.0.1:12345")


def test_handshake_not_serving(handler):
    handshake_data = json.dumps(
        {
            "app-name": "joinmarket",
            "directory": False,
            "location-string": "NOT-SERVING-ONION",
            "proto-ver": JM_VERSION,
            "features": {},
            "nick": "test_client",
            "network": "mainnet",
        }
    )

    peer_info, response = handler.process_handshake(handshake_data, "127.0.0.1:12345")

    assert peer_info.onion_address == "NOT-SERVING-ONION"
    assert peer_info.port == -1


def test_handshake_invalid_json(handler):
    with pytest.raises(HandshakeError, match="Invalid handshake format"):
        handler.process_handshake("not json", "127.0.0.1:12345")


def test_handshake_missing_fields(handler):
    handshake_data = json.dumps({"app-name": "joinmarket", "proto-ver": JM_VERSION})

    with pytest.raises(HandshakeError, match="Missing required"):
        handler.process_handshake(handshake_data, "127.0.0.1:12345")


def test_create_rejection_response(handler):
    response = handler.create_rejection_response("Test rejection")

    assert response["accepted"] is False
    assert "Rejected: Test rejection" in response["motd"]
