"""
JoinMarket protocol definitions, message types, and serialization.

Protocol Version History:
- v5: Original JoinMarket protocol (reference implementation compatible)
- v6: Extended UTXO metadata for Neutrino/light client support
      - Adds neutrino_compat feature flag in handshake
      - Extended !auth format: txid:vout:scriptpubkey:blockheight
      - Extended !ioauth format: includes scriptpubkey:blockheight per UTXO

Nick Format and Version Detection:
=================================
JoinMarket nicks encode the protocol version: J{version}{hash}
- J5xxx: Protocol v5 (JAM compatible, legacy UTXO format only)
- J6xxx: Protocol v6 (supports extended UTXO format for Neutrino)

This allows peers to determine each other's capabilities without negotiation.

Cross-Version CoinJoin Compatibility:
====================================
Version compatibility is determined by nick prefix, enabling backward compatibility:

**Makers (sending !ioauth):**
- To J6 taker: Send extended UTXO format (txid:vout:scriptpubkey:blockheight)
- To J5 taker: Send legacy UTXO format (txid:vout)

**Takers (sending !auth):**
- To J6 maker: Send extended revelation format
- To J5 maker: Send legacy revelation format

**Takers with Neutrino backend:**
- Can ONLY work with J6 makers (need extended UTXO format in !ioauth)
- Filter orderbook to exclude J5 makers during maker selection

**Takers with full node backend:**
- Can work with both J5 and J6 makers
- Send appropriate format based on maker's nick

This ensures:
- Full backward compatibility with JAM (v5) implementations
- Extended format only used when both peers support v6
- Neutrino takers automatically select compatible makers
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pydantic import BaseModel

# Protocol version: v6 adds Neutrino-compatible UTXO metadata
JM_VERSION = 6
JM_VERSION_MIN = 5  # Minimum version for backward compatibility

COMMAND_PREFIX = "!"
NICK_PEERLOCATOR_SEPARATOR = ";"
ONION_VIRTUAL_PORT = 5222
NOT_SERVING_ONION_HOSTNAME = "NOT-SERVING-ONION"
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14

# Feature flags for capability negotiation
FEATURE_NEUTRINO_COMPAT = "neutrino_compat"


def get_nick_version(nick: str) -> int:
    """
    Extract protocol version from a JoinMarket nick.

    Nick format: J{version}{hash} where version is a single digit.
    Examples: J5abc123... (v5), J6xyz789... (v6)

    Returns JM_VERSION_MIN if version cannot be determined.
    """
    if nick and len(nick) >= 2 and nick[0] == "J" and nick[1].isdigit():
        return int(nick[1])
    return JM_VERSION_MIN


def is_v6_nick(nick: str) -> bool:
    """Check if a nick indicates protocol version 6 or higher."""
    return get_nick_version(nick) >= 6


@dataclass
class UTXOMetadata:
    """
    Extended UTXO metadata for Neutrino-compatible verification.

    This allows light clients to verify UTXOs without arbitrary blockchain queries
    by providing the scriptPubKey (for Neutrino watch list) and block height
    (for efficient rescan starting point).
    """

    txid: str
    vout: int
    scriptpubkey: str | None = None  # Hex-encoded scriptPubKey
    blockheight: int | None = None  # Block height where UTXO was confirmed

    def to_legacy_str(self) -> str:
        """Format as legacy v5 string: txid:vout"""
        return f"{self.txid}:{self.vout}"

    def to_extended_str(self) -> str:
        """Format as extended v6 string: txid:vout:scriptpubkey:blockheight"""
        if self.scriptpubkey is None or self.blockheight is None:
            return self.to_legacy_str()
        return f"{self.txid}:{self.vout}:{self.scriptpubkey}:{self.blockheight}"

    @classmethod
    def from_str(cls, s: str) -> UTXOMetadata:
        """
        Parse UTXO string in either legacy or extended format.

        Legacy format: txid:vout
        Extended format: txid:vout:scriptpubkey:blockheight
        """
        parts = s.split(":")
        if len(parts) == 2:
            # Legacy format
            return cls(txid=parts[0], vout=int(parts[1]))
        elif len(parts) == 4:
            # Extended format
            return cls(
                txid=parts[0],
                vout=int(parts[1]),
                scriptpubkey=parts[2],
                blockheight=int(parts[3]),
            )
        else:
            raise ValueError(f"Invalid UTXO format: {s}")

    def has_neutrino_metadata(self) -> bool:
        """Check if this UTXO has the metadata needed for Neutrino verification."""
        return self.scriptpubkey is not None and self.blockheight is not None

    @staticmethod
    def is_valid_scriptpubkey(scriptpubkey: str) -> bool:
        """Validate scriptPubKey format (hex string)."""
        if not scriptpubkey:
            return False
        # Must be valid hex
        if not re.match(r"^[0-9a-fA-F]+$", scriptpubkey):
            return False
        # Common scriptPubKey lengths (in hex chars):
        # P2PKH: 50 (25 bytes), P2SH: 46 (23 bytes)
        # P2WPKH: 44 (22 bytes), P2WSH: 68 (34 bytes)
        # P2TR: 68 (34 bytes)
        return not (len(scriptpubkey) < 4 or len(scriptpubkey) > 200)


def parse_utxo_list(utxo_list_str: str, require_metadata: bool = False) -> list[UTXOMetadata]:
    """
    Parse a comma-separated list of UTXOs.

    Args:
        utxo_list_str: Comma-separated UTXOs (legacy or extended format)
        require_metadata: If True, raise error if any UTXO lacks Neutrino metadata

    Returns:
        List of UTXOMetadata objects
    """
    if not utxo_list_str:
        return []

    utxos = []
    for utxo_str in utxo_list_str.split(","):
        utxo = UTXOMetadata.from_str(utxo_str.strip())
        if require_metadata and not utxo.has_neutrino_metadata():
            raise ValueError(f"UTXO {utxo.to_legacy_str()} missing Neutrino metadata")
        utxos.append(utxo)
    return utxos


def format_utxo_list(utxos: list[UTXOMetadata], extended: bool = False) -> str:
    """
    Format a list of UTXOs as comma-separated string.

    Args:
        utxos: List of UTXOMetadata objects
        extended: If True, use extended format with scriptpubkey:blockheight

    Returns:
        Comma-separated UTXO string
    """
    if extended:
        return ",".join(u.to_extended_str() for u in utxos)
    else:
        return ",".join(u.to_legacy_str() for u in utxos)


class MessageType(IntEnum):
    PRIVMSG = 685
    PUBMSG = 687
    PEERLIST = 789
    GETPEERLIST = 791
    HANDSHAKE = 793
    DN_HANDSHAKE = 795
    PING = 797
    PONG = 799
    DISCONNECT = 801

    CONNECT = 785
    CONNECT_IN = 797


class ProtocolMessage(BaseModel):
    type: MessageType
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps({"type": self.type.value, "data": self.payload})

    @classmethod
    def from_json(cls, data: str) -> ProtocolMessage:
        obj = json.loads(data)
        return cls(type=MessageType(obj["type"]), payload=obj["data"])

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> ProtocolMessage:
        return cls.from_json(data.decode("utf-8"))


def create_handshake_request(
    nick: str,
    location: str,
    network: str,
    directory: bool = False,
    neutrino_compat: bool = False,
) -> dict[str, Any]:
    """
    Create a handshake request message.

    Args:
        nick: Bot nickname
        location: Onion address or NOT-SERVING-ONION
        network: Bitcoin network (mainnet, testnet, signet, regtest)
        directory: True if this is a directory server
        neutrino_compat: True to advertise Neutrino-compatible UTXO metadata support

    Returns:
        Handshake request payload dict
    """
    features: dict[str, Any] = {}
    if neutrino_compat:
        features[FEATURE_NEUTRINO_COMPAT] = True

    return {
        "app-name": "joinmarket",
        "directory": directory,
        "location-string": location,
        "proto-ver": JM_VERSION,
        "features": features,
        "nick": nick,
        "network": network,
    }


def create_handshake_response(
    nick: str,
    network: str,
    accepted: bool = True,
    motd: str = "JoinMarket Directory Server",
    neutrino_compat: bool = False,
) -> dict[str, Any]:
    """
    Create a handshake response message.

    Args:
        nick: Directory server nickname
        network: Bitcoin network
        accepted: Whether the connection is accepted
        motd: Message of the day
        neutrino_compat: True to advertise Neutrino-compatible UTXO metadata support

    Returns:
        Handshake response payload dict
    """
    features: dict[str, Any] = {}
    if neutrino_compat:
        features[FEATURE_NEUTRINO_COMPAT] = True

    return {
        "app-name": "joinmarket",
        "directory": True,
        "proto-ver-min": JM_VERSION_MIN,
        "proto-ver-max": JM_VERSION,
        "features": features,
        "accepted": accepted,
        "nick": nick,
        "network": network,
        "motd": motd,
    }


def peer_supports_neutrino_compat(handshake_data: dict[str, Any]) -> bool:
    """
    Check if a peer supports Neutrino-compatible UTXO metadata.

    Args:
        handshake_data: Handshake payload from peer

    Returns:
        True if peer advertises neutrino_compat feature
    """
    proto_ver = handshake_data.get("proto-ver", 5)
    if proto_ver < 6:
        return False

    features = handshake_data.get("features", {})
    return features.get(FEATURE_NEUTRINO_COMPAT, False)


def parse_peer_location(location: str) -> tuple[str, int]:
    if location == NOT_SERVING_ONION_HOSTNAME:
        return (location, -1)
    try:
        host, port_str = location.split(":")
        port = int(port_str)
        if port <= 0 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
        return (host, port)
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid location string: {location}") from e


def create_peerlist_entry(nick: str, location: str, disconnected: bool = False) -> str:
    entry = f"{nick}{NICK_PEERLOCATOR_SEPARATOR}{location}"
    if disconnected:
        entry += f"{NICK_PEERLOCATOR_SEPARATOR}D"
    return entry


def parse_peerlist_entry(entry: str) -> tuple[str, str, bool]:
    parts = entry.split(NICK_PEERLOCATOR_SEPARATOR)
    if len(parts) == 2:
        return (parts[0], parts[1], False)
    elif len(parts) == 3 and parts[2] == "D":
        return (parts[0], parts[1], True)
    raise ValueError(f"Invalid peerlist entry: {entry}")


def format_jm_message(from_nick: str, to_nick: str, cmd: str, message: str) -> str:
    return f"{from_nick}{COMMAND_PREFIX}{to_nick}{COMMAND_PREFIX}{cmd} {message}"


def parse_jm_message(msg: str) -> tuple[str, str, str] | None:
    try:
        parts = msg.split(COMMAND_PREFIX)
        if len(parts) < 3:
            return None
        from_nick = parts[0]
        to_nick = parts[1]
        rest = COMMAND_PREFIX.join(parts[2:])
        return (from_nick, to_nick, rest)
    except Exception:
        return None
