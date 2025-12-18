"""
jmcore - Core library for JoinMarket components

Provides shared functionality for protocol, crypto, and networking.
"""

__version__ = "2.1.0"

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
from jmcore.protocol import JM_VERSION, MessageType, ProtocolMessage

__all__ = [
    "CryptoSession",
    "DirectoryClient",
    "DirectoryClientError",
    "JM_VERSION",
    "MessageEnvelope",
    "MessageType",
    "NaclError",
    "PeerInfo",
    "PoDLECommitment",
    "PoDLEError",
    "ProtocolMessage",
    "deserialize_revelation",
    "generate_podle",
    "parse_podle_revelation",
    "serialize_revelation",
    "verify_podle",
]
