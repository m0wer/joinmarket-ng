"""
Tests for jmcore.protocol
"""

import pytest

from jmcore.protocol import (
    NOT_SERVING_ONION_HOSTNAME,
    MessageType,
    ProtocolMessage,
    create_peerlist_entry,
    format_jm_message,
    parse_jm_message,
    parse_peer_location,
    parse_peerlist_entry,
)


def test_protocol_message_serialization():
    msg = ProtocolMessage(type=MessageType.HANDSHAKE, payload={"test": "data"})
    json_str = msg.to_json()
    assert "793" in json_str or '"type": 793' in json_str

    restored = ProtocolMessage.from_json(json_str)
    assert restored.type == MessageType.HANDSHAKE
    assert restored.payload == {"test": "data"}


def test_parse_peer_location_valid():
    host, port = parse_peer_location("test.onion:5222")
    assert host == "test.onion"
    assert port == 5222


def test_parse_peer_location_not_serving():
    host, port = parse_peer_location(NOT_SERVING_ONION_HOSTNAME)
    assert host == NOT_SERVING_ONION_HOSTNAME
    assert port == -1


def test_parse_peer_location_invalid():
    with pytest.raises(ValueError):
        parse_peer_location("invalid")

    with pytest.raises(ValueError):
        parse_peer_location("test.onion:99999")


def test_peerlist_entry_creation():
    entry = create_peerlist_entry("nick1", "test.onion:5222", disconnected=False)
    assert entry == "nick1;test.onion:5222"

    entry_disco = create_peerlist_entry("nick2", "test.onion:5222", disconnected=True)
    assert entry_disco == "nick2;test.onion:5222;D"


def test_peerlist_entry_parsing():
    nick, location, disco = parse_peerlist_entry("nick1;test.onion:5222")
    assert nick == "nick1"
    assert location == "test.onion:5222"
    assert not disco

    nick, location, disco = parse_peerlist_entry("nick2;test.onion:5222;D")
    assert nick == "nick2"
    assert disco


def test_jm_message_formatting():
    msg = format_jm_message("alice", "bob", "fill", "12345 100 pubkey")
    assert msg == "alice!bob!fill 12345 100 pubkey"


def test_jm_message_parsing():
    result = parse_jm_message("alice!bob!fill 12345")
    assert result is not None
    from_nick, to_nick, rest = result
    assert from_nick == "alice"
    assert to_nick == "bob"
    assert rest == "fill 12345"


def test_jm_message_public():
    result = parse_jm_message("alice!PUBLIC!absorder 12345")
    assert result is not None
    from_nick, to_nick, rest = result
    assert from_nick == "alice"
    assert to_nick == "PUBLIC"
