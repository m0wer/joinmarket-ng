"""
Core data models using Pydantic for validation and serialization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class PeerStatus(str, Enum):
    UNCONNECTED = "unconnected"
    CONNECTED = "connected"
    HANDSHAKED = "handshaked"
    DISCONNECTED = "disconnected"


class NetworkType(str, Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"
    SIGNET = "signet"
    REGTEST = "regtest"


class PeerInfo(BaseModel):
    nick: str = Field(..., min_length=1, max_length=64)
    onion_address: str = Field(..., pattern=r"^[a-z2-7]{56}\.onion$|^NOT-SERVING-ONION$")
    port: int = Field(..., ge=-1, le=65535)
    status: PeerStatus = PeerStatus.UNCONNECTED
    is_directory: bool = False
    network: NetworkType = NetworkType.MAINNET
    last_seen: datetime | None = None
    features: dict[str, Any] = Field(default_factory=dict)

    @field_validator("onion_address")
    @classmethod
    def validate_onion(cls, v: str) -> str:
        if v == "NOT-SERVING-ONION":
            return v
        if not v.endswith(".onion"):
            raise ValueError("Invalid onion address")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int, info) -> int:
        if v == -1 and info.data.get("onion_address") == "NOT-SERVING-ONION":
            return v
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

    def location_string(self) -> str:
        if self.onion_address == "NOT-SERVING-ONION":
            return "NOT-SERVING-ONION"
        return f"{self.onion_address}:{self.port}"

    model_config = {"frozen": False}


class MessageEnvelope(BaseModel):
    message_type: int = Field(..., ge=0)
    payload: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    def to_bytes(self) -> bytes:
        import json

        result = json.dumps({"type": self.message_type, "line": self.payload}).encode("utf-8")
        return result

    @classmethod
    def from_bytes(cls, data: bytes) -> MessageEnvelope:
        import json

        obj = json.loads(data)
        return cls(message_type=obj["type"], payload=obj["line"])


class HandshakeRequest(BaseModel):
    app_name: str = "JoinMarket"
    directory: bool = False
    location_string: str
    proto_ver: int
    features: dict[str, Any] = Field(default_factory=dict)
    nick: str = Field(..., min_length=1)
    network: NetworkType


class HandshakeResponse(BaseModel):
    app_name: str = "JoinMarket"
    directory: bool = True
    proto_ver_min: int
    proto_ver_max: int
    features: dict[str, Any] = Field(default_factory=dict)
    accepted: bool
    nick: str = Field(..., min_length=1)
    network: NetworkType
    motd: str = "JoinMarket Directory Server"
