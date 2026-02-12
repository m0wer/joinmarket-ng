"""
Tests for jmcore.models
"""

from typing import Any

import pytest

from jmcore.models import (
    HandshakeRequest,
    HandshakeResponse,
    MessageEnvelope,
    MessageParsingError,
    NetworkType,
    PeerInfo,
    PeerStatus,
    validate_json_nesting_depth,
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
        peer.location_string
        == "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:5222"
    )


def test_peer_info_not_serving():
    peer = PeerInfo(nick="test", onion_address="NOT-SERVING-ONION", port=-1)
    assert peer.location_string == "NOT-SERVING-ONION"


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


def test_message_envelope_line_length_limit():
    """Test that messages exceeding max_line_length are rejected."""
    # Create a message that's too long (default limit is 64KB)
    long_payload = "x" * 70000
    envelope = MessageEnvelope(message_type=793, payload=long_payload)
    data = envelope.to_bytes()

    # Should raise MessageParsingError with default limit (65536 bytes)
    with pytest.raises(MessageParsingError, match="exceeds maximum"):
        MessageEnvelope.from_bytes(data)

    # Should succeed with higher limit
    result = MessageEnvelope.from_bytes(data, max_line_length=100000)
    assert result.payload == long_payload


def test_message_envelope_nesting_depth_limit():
    """Test that deeply nested JSON is rejected."""
    import json

    # Create deeply nested JSON (15 levels)
    nested: dict[str, Any] = {"a": {}}
    current = nested["a"]
    for _ in range(14):
        current["b"] = {}
        current = current["b"]

    data = json.dumps({"type": 793, "line": "test", "nested": nested}).encode()

    # Should raise MessageParsingError with default limit (10 levels)
    with pytest.raises(MessageParsingError, match="nesting depth exceeds"):
        MessageEnvelope.from_bytes(data)

    # Should succeed with higher limit
    result = MessageEnvelope.from_bytes(data, max_json_nesting_depth=20)
    assert result.message_type == 793


def test_validate_json_nesting_depth_dict():
    """Test nesting depth validation for dictionaries."""
    # Shallow structure (3 levels) - should pass
    shallow = {"a": {"b": {"c": 1}}}
    validate_json_nesting_depth(shallow, max_depth=5)

    # Deep structure (6 levels) - should fail with max_depth=5
    deep = {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}
    with pytest.raises(MessageParsingError):
        validate_json_nesting_depth(deep, max_depth=5)


def test_validate_json_nesting_depth_list():
    """Test nesting depth validation for lists."""
    # Shallow structure (3 levels) - should pass
    shallow = [[[1, 2, 3]]]
    validate_json_nesting_depth(shallow, max_depth=5)

    # Deep structure (6 levels) - should fail with max_depth=5
    deep = [[[[[[1]]]]]]
    with pytest.raises(MessageParsingError):
        validate_json_nesting_depth(deep, max_depth=5)


def test_validate_json_nesting_depth_mixed():
    """Test nesting depth validation for mixed dict/list structures."""
    # Mixed structure (5 levels)
    mixed = {"a": [{"b": [{"c": 1}]}]}

    # Should pass with max_depth=5
    validate_json_nesting_depth(mixed, max_depth=5)

    # Should fail with max_depth=3
    with pytest.raises(MessageParsingError):
        validate_json_nesting_depth(mixed, max_depth=3)


def test_message_envelope_parsing_order():
    """Test that line length is checked before JSON parsing."""
    # Create invalid JSON that's too long
    long_invalid_json = b'{"type": 793, "invalid' + b"x" * 70000

    # Should raise MessageParsingError (line length), not JSONDecodeError
    with pytest.raises(MessageParsingError, match="line length"):
        MessageEnvelope.from_bytes(long_invalid_json)
