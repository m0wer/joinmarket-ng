"""
jmcore - Core library for JoinMarket components

Provides shared functionality for protocol, crypto, and networking.
"""

__version__ = "2.2.0"

from jmcore.directory_client import DirectoryClient, DirectoryClientError
from jmcore.encryption import CryptoSession, NaclError
from jmcore.models import MessageEnvelope, PeerInfo
from jmcore.podle import (
    PoDLECommitment,
    PoDLEError,
    deserialize_revelation,
    generate_podle,
    parse_podle_revelation,
    serialize_revelation,
    verify_podle,
)
from jmcore.protocol import (
    FEATURE_NEUTRINO_COMPAT,
    JM_VERSION,
    JM_VERSION_MIN,
    MessageType,
    ProtocolMessage,
    UTXOMetadata,
    format_utxo_list,
    get_nick_version,
    is_v6_nick,
    parse_utxo_list,
    peer_supports_neutrino_compat,
)

__all__ = [
    "CryptoSession",
    "DirectoryClient",
    "DirectoryClientError",
    "FEATURE_NEUTRINO_COMPAT",
    "JM_VERSION",
    "JM_VERSION_MIN",
    "MessageEnvelope",
    "MessageType",
    "NaclError",
    "PeerInfo",
    "PoDLECommitment",
    "PoDLEError",
    "ProtocolMessage",
    "UTXOMetadata",
    "deserialize_revelation",
    "format_utxo_list",
    "generate_podle",
    "get_nick_version",
    "is_v6_nick",
    "parse_podle_revelation",
    "parse_utxo_list",
    "peer_supports_neutrino_compat",
    "serialize_revelation",
    "verify_podle",
]
