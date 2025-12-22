"""
jmcore - Core library for JoinMarket components

Provides shared functionality for protocol, crypto, and networking.
"""

__version__ = "2.2.0"

from jmcore.directory_client import DirectoryClient, DirectoryClientError
from jmcore.encryption import CryptoSession, NaclError
from jmcore.models import (
    DIRECTORY_NODES_MAINNET,
    DIRECTORY_NODES_SIGNET,
    DIRECTORY_NODES_TESTNET,
    MessageEnvelope,
    PeerInfo,
    get_default_directory_nodes,
)
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
    FEATURE_PUSH_ENCRYPTED,
    JM_VERSION,
    JM_VERSION_MIN,
    FeatureSet,
    MessageType,
    ProtocolMessage,
    RequiredFeatures,
    UTXOMetadata,
    format_utxo_list,
    get_nick_version,
    is_v6_nick,
    parse_utxo_list,
    peer_supports_neutrino_compat,
)

__all__ = [
    "CryptoSession",
    "DIRECTORY_NODES_MAINNET",
    "DIRECTORY_NODES_SIGNET",
    "DIRECTORY_NODES_TESTNET",
    "DirectoryClient",
    "DirectoryClientError",
    "FEATURE_NEUTRINO_COMPAT",
    "FEATURE_PUSH_ENCRYPTED",
    "FeatureSet",
    "JM_VERSION",
    "JM_VERSION_MIN",
    "MessageEnvelope",
    "MessageType",
    "NaclError",
    "PeerInfo",
    "PoDLECommitment",
    "PoDLEError",
    "ProtocolMessage",
    "RequiredFeatures",
    "UTXOMetadata",
    "deserialize_revelation",
    "format_utxo_list",
    "generate_podle",
    "get_default_directory_nodes",
    "get_nick_version",
    "is_v6_nick",
    "parse_podle_revelation",
    "parse_utxo_list",
    "peer_supports_neutrino_compat",
    "serialize_revelation",
    "verify_podle",
]
