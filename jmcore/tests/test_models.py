"""
Tests for jmcore.models
"""

import pytest

from jmcore.models import (
    HandshakeRequest,
    HandshakeResponse,
    MessageEnvelope,
    NetworkType,
    PeerInfo,
    PeerStatus,
)


def test_peer_info_valid():
    peer = PeerInfo(
        nick="test_peer",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        port=5222,
        network=NetworkType.MAINNET,
    )
    assert peer.nick == "test_peer"
    assert peer.status == PeerStatus.UNCONNECTED
    assert not peer.is_directory


def test_peer_info_location_string():
    peer = PeerInfo(
        nick="test",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        port=5222,
    )
    assert (
        peer.location_string()
        == "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:5222"
    )


def test_peer_info_not_serving():
    peer = PeerInfo(nick="test", onion_address="NOT-SERVING-ONION", port=-1)
    assert peer.location_string() == "NOT-SERVING-ONION"


def test_peer_info_invalid_port():
    with pytest.raises(ValueError):
        PeerInfo(
            nick="test",
            onion_address="example1234567890abcdefghijklmnopqrstuvwxyz234567890abcd.onion",
            port=0,
        )


def test_message_envelope_serialization():
    envelope = MessageEnvelope(message_type=793, payload="test message")
    data = envelope.to_bytes()
    assert b'"type": 793' in data
    assert b'"line": "test message"' in data

    restored = MessageEnvelope.from_bytes(data)
    assert restored.message_type == envelope.message_type
    assert restored.payload == envelope.payload


def test_handshake_request():
    hs = HandshakeRequest(
        location_string="test.onion:5222", proto_ver=9, nick="tester", network=NetworkType.MAINNET
    )
    assert hs.app_name == "JoinMarket"
    assert not hs.directory
    assert hs.proto_ver == 9


def test_handshake_response():
    hs = HandshakeResponse(
        proto_ver_min=9,
        proto_ver_max=9,
        accepted=True,
        nick="directory",
        network=NetworkType.MAINNET,
    )
    assert hs.app_name == "JoinMarket"
    assert hs.directory
    assert hs.accepted
