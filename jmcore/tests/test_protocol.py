"""
Tests for jmcore.protocol
"""

import pytest

from jmcore.protocol import (
    FEATURE_NEUTRINO_COMPAT,
    JM_VERSION,
    JM_VERSION_MIN,
    NOT_SERVING_ONION_HOSTNAME,
    MessageType,
    ProtocolMessage,
    UTXOMetadata,
    create_handshake_request,
    create_handshake_response,
    create_peerlist_entry,
    format_jm_message,
    format_utxo_list,
    get_nick_version,
    is_v6_nick,
    parse_jm_message,
    parse_peer_location,
    parse_peerlist_entry,
    parse_utxo_list,
    peer_supports_neutrino_compat,
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


# ==============================================================================
# Protocol v6 Tests - UTXO Metadata
# ==============================================================================


class TestUTXOMetadata:
    """Tests for UTXOMetadata class."""

    def test_legacy_format_parse(self):
        """Parse legacy txid:vout format."""
        utxo = UTXOMetadata.from_str("abc123def456:0")
        assert utxo.txid == "abc123def456"
        assert utxo.vout == 0
        assert utxo.scriptpubkey is None
        assert utxo.blockheight is None
        assert not utxo.has_neutrino_metadata()

    def test_extended_format_parse(self):
        """Parse extended txid:vout:scriptpubkey:blockheight format."""
        utxo = UTXOMetadata.from_str("abc123def456:1:0014a1b2c3d4e5f6:750000")
        assert utxo.txid == "abc123def456"
        assert utxo.vout == 1
        assert utxo.scriptpubkey == "0014a1b2c3d4e5f6"
        assert utxo.blockheight == 750000
        assert utxo.has_neutrino_metadata()

    def test_legacy_format_output(self):
        """Output legacy format."""
        utxo = UTXOMetadata(txid="abc123", vout=2)
        assert utxo.to_legacy_str() == "abc123:2"

    def test_extended_format_output(self):
        """Output extended format."""
        utxo = UTXOMetadata(txid="abc123", vout=2, scriptpubkey="0014deadbeef", blockheight=800000)
        assert utxo.to_extended_str() == "abc123:2:0014deadbeef:800000"

    def test_extended_format_fallback_to_legacy(self):
        """Extended format falls back to legacy when metadata missing."""
        utxo = UTXOMetadata(txid="abc123", vout=2)
        assert utxo.to_extended_str() == "abc123:2"

        utxo_partial = UTXOMetadata(txid="abc123", vout=2, scriptpubkey="0014deadbeef")
        assert utxo_partial.to_extended_str() == "abc123:2"

    def test_invalid_format_raises(self):
        """Invalid formats raise ValueError."""
        with pytest.raises(ValueError):
            UTXOMetadata.from_str("invalid")

        with pytest.raises(ValueError):
            UTXOMetadata.from_str("abc:1:2")  # 3 parts

        with pytest.raises(ValueError):
            UTXOMetadata.from_str("abc:1:2:3:4")  # 5 parts

    def test_scriptpubkey_validation(self):
        """Validate scriptPubKey format."""
        # Valid P2WPKH (22 bytes = 44 hex chars)
        assert UTXOMetadata.is_valid_scriptpubkey("0014" + "a" * 40)

        # Valid P2WSH (34 bytes = 68 hex chars)
        assert UTXOMetadata.is_valid_scriptpubkey("0020" + "b" * 64)

        # Invalid: not hex
        assert not UTXOMetadata.is_valid_scriptpubkey("0014xyz123")

        # Invalid: too short
        assert not UTXOMetadata.is_valid_scriptpubkey("00")

        # Invalid: empty
        assert not UTXOMetadata.is_valid_scriptpubkey("")

    def test_roundtrip_legacy(self):
        """Round-trip legacy format."""
        original = "abc123def456789012345678901234567890123456789012345678901234:5"
        utxo = UTXOMetadata.from_str(original)
        assert utxo.to_legacy_str() == original

    def test_roundtrip_extended(self):
        """Round-trip extended format."""
        original = (
            "abc123def456789012345678901234567890123456789012345678901234:5:0014deadbeef1234:850000"
        )
        utxo = UTXOMetadata.from_str(original)
        assert utxo.to_extended_str() == original


class TestParseUtxoList:
    """Tests for parse_utxo_list function."""

    def test_empty_string(self):
        """Empty string returns empty list."""
        assert parse_utxo_list("") == []

    def test_single_legacy_utxo(self):
        """Parse single legacy UTXO."""
        utxos = parse_utxo_list("abc123:0")
        assert len(utxos) == 1
        assert utxos[0].txid == "abc123"
        assert utxos[0].vout == 0

    def test_multiple_legacy_utxos(self):
        """Parse multiple legacy UTXOs."""
        utxos = parse_utxo_list("abc123:0,def456:1,ghi789:2")
        assert len(utxos) == 3
        assert utxos[1].txid == "def456"
        assert utxos[2].vout == 2

    def test_multiple_extended_utxos(self):
        """Parse multiple extended UTXOs."""
        utxos = parse_utxo_list("abc123:0:0014aaa:100,def456:1:0014bbb:200,ghi789:2:0014ccc:300")
        assert len(utxos) == 3
        assert all(u.has_neutrino_metadata() for u in utxos)
        assert utxos[0].blockheight == 100
        assert utxos[2].scriptpubkey == "0014ccc"

    def test_mixed_formats(self):
        """Parse mixed legacy and extended UTXOs."""
        utxos = parse_utxo_list("abc123:0,def456:1:0014bbb:200")
        assert len(utxos) == 2
        assert not utxos[0].has_neutrino_metadata()
        assert utxos[1].has_neutrino_metadata()

    def test_require_metadata_success(self):
        """require_metadata=True succeeds when all have metadata."""
        utxos = parse_utxo_list("abc123:0:0014aaa:100,def456:1:0014bbb:200", require_metadata=True)
        assert len(utxos) == 2

    def test_require_metadata_failure(self):
        """require_metadata=True raises when metadata missing."""
        with pytest.raises(ValueError, match="missing Neutrino metadata"):
            parse_utxo_list("abc123:0,def456:1:0014bbb:200", require_metadata=True)


class TestFormatUtxoList:
    """Tests for format_utxo_list function."""

    def test_format_legacy(self):
        """Format UTXOs in legacy format."""
        utxos = [
            UTXOMetadata(txid="abc123", vout=0, scriptpubkey="0014aaa", blockheight=100),
            UTXOMetadata(txid="def456", vout=1, scriptpubkey="0014bbb", blockheight=200),
        ]
        result = format_utxo_list(utxos, extended=False)
        assert result == "abc123:0,def456:1"

    def test_format_extended(self):
        """Format UTXOs in extended format."""
        utxos = [
            UTXOMetadata(txid="abc123", vout=0, scriptpubkey="0014aaa", blockheight=100),
            UTXOMetadata(txid="def456", vout=1, scriptpubkey="0014bbb", blockheight=200),
        ]
        result = format_utxo_list(utxos, extended=True)
        assert result == "abc123:0:0014aaa:100,def456:1:0014bbb:200"


# ==============================================================================
# Protocol v6 Tests - Handshake and Feature Negotiation
# ==============================================================================


class TestProtocolVersion:
    """Tests for protocol version constants."""

    def test_version_numbers(self):
        """Verify version constants."""
        assert JM_VERSION == 6
        assert JM_VERSION_MIN == 5

    def test_feature_flag_constant(self):
        """Verify feature flag constant."""
        assert FEATURE_NEUTRINO_COMPAT == "neutrino_compat"


class TestHandshakeRequest:
    """Tests for create_handshake_request function."""

    def test_basic_handshake(self):
        """Create basic handshake without neutrino_compat."""
        hs = create_handshake_request(
            nick="J5TestNick", location="test.onion:5222", network="mainnet"
        )
        assert hs["nick"] == "J5TestNick"
        assert hs["proto-ver"] == 6
        assert hs["features"] == {}
        assert hs["directory"] is False

    def test_handshake_with_neutrino_compat(self):
        """Create handshake with neutrino_compat feature."""
        hs = create_handshake_request(
            nick="J5TestNick",
            location="test.onion:5222",
            network="mainnet",
            neutrino_compat=True,
        )
        assert hs["features"][FEATURE_NEUTRINO_COMPAT] is True

    def test_directory_handshake(self):
        """Create directory server handshake."""
        hs = create_handshake_request(
            nick="J5DirServer",
            location="dir.onion:5222",
            network="mainnet",
            directory=True,
        )
        assert hs["directory"] is True


class TestHandshakeResponse:
    """Tests for create_handshake_response function."""

    def test_basic_response(self):
        """Create basic handshake response."""
        hs = create_handshake_response(nick="J5DirServer", network="mainnet")
        assert hs["proto-ver-min"] == 5
        assert hs["proto-ver-max"] == 6
        assert hs["accepted"] is True
        assert hs["features"] == {}

    def test_response_with_neutrino_compat(self):
        """Create response with neutrino_compat feature."""
        hs = create_handshake_response(nick="J5DirServer", network="mainnet", neutrino_compat=True)
        assert hs["features"][FEATURE_NEUTRINO_COMPAT] is True


class TestPeerSupportsNeutrinoCompat:
    """Tests for peer_supports_neutrino_compat function."""

    def test_v5_peer_no_support(self):
        """v5 peer does not support neutrino_compat."""
        handshake = {"proto-ver": 5, "features": {}}
        assert peer_supports_neutrino_compat(handshake) is False

    def test_v6_peer_without_feature(self):
        """v6 peer without feature flag does not support."""
        handshake = {"proto-ver": 6, "features": {}}
        assert peer_supports_neutrino_compat(handshake) is False

    def test_v6_peer_with_feature(self):
        """v6 peer with feature flag supports."""
        handshake = {"proto-ver": 6, "features": {FEATURE_NEUTRINO_COMPAT: True}}
        assert peer_supports_neutrino_compat(handshake) is True

    def test_missing_features_key(self):
        """Handle missing features key gracefully."""
        handshake = {"proto-ver": 6}
        assert peer_supports_neutrino_compat(handshake) is False

    def test_missing_proto_ver(self):
        """Handle missing proto-ver (defaults to 5)."""
        handshake = {"features": {FEATURE_NEUTRINO_COMPAT: True}}
        assert peer_supports_neutrino_compat(handshake) is False


class TestNickVersionDetection:
    """Tests for nick-based version detection functions."""

    def test_get_nick_version_v5(self):
        """Detect v5 from J5 nick."""
        assert get_nick_version("J5abc123defOOOO") == 5

    def test_get_nick_version_v6(self):
        """Detect v6 from J6 nick."""
        assert get_nick_version("J6xyz789ghiOOOO") == 6

    def test_get_nick_version_v7(self):
        """Detect future v7 from J7 nick."""
        assert get_nick_version("J7future123OOOO") == 7

    def test_get_nick_version_empty(self):
        """Empty nick returns default."""
        assert get_nick_version("") == JM_VERSION_MIN

    def test_get_nick_version_too_short(self):
        """Too short nick returns default."""
        assert get_nick_version("J") == JM_VERSION_MIN

    def test_get_nick_version_no_j_prefix(self):
        """Nick without J prefix returns default."""
        assert get_nick_version("X6abcdef") == JM_VERSION_MIN

    def test_get_nick_version_non_digit(self):
        """Nick with non-digit version returns default."""
        assert get_nick_version("JXabcdef") == JM_VERSION_MIN

    def test_is_v6_nick_true(self):
        """J6 nick is v6."""
        assert is_v6_nick("J6abcdef123OOOO") is True

    def test_is_v6_nick_higher(self):
        """J7+ nick is also v6 compatible."""
        assert is_v6_nick("J7future123OOOO") is True

    def test_is_v6_nick_false(self):
        """J5 nick is not v6."""
        assert is_v6_nick("J5oldmaker12OOO") is False

    def test_is_v6_nick_invalid(self):
        """Invalid nick is not v6."""
        assert is_v6_nick("") is False
        assert is_v6_nick("invalid") is False
        assert is_v6_nick("J") is False
