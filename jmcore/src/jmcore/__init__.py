"""
jmcore - Core library for JoinMarket components

Provides shared functionality for protocol, crypto, and networking.
"""

__version__ = "2.1.0"

from jmcore.models import MessageEnvelope, PeerInfo
from jmcore.protocol import JM_VERSION, MessageType, ProtocolMessage

__all__ = [
    "PeerInfo",
    "MessageEnvelope",
    "MessageType",
    "ProtocolMessage",
    "JM_VERSION",
]
