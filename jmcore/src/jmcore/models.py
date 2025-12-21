"""
Core data models using Pydantic for validation and serialization.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from functools import cached_property
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
    protocol_version: int = Field(default=5, ge=5, le=10)  # Negotiated protocol version
    neutrino_compat: bool = False  # True if peer supports extended UTXO metadata

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

    @cached_property
    def location_string(self) -> str:
        if self.onion_address == "NOT-SERVING-ONION":
            return "NOT-SERVING-ONION"
        return f"{self.onion_address}:{self.port}"

    def supports_extended_utxo(self) -> bool:
        """Check if this peer supports extended UTXO format."""
        return self.protocol_version >= 6 and self.neutrino_compat

    model_config = {"frozen": False}


class MessageEnvelope(BaseModel):
    message_type: int = Field(..., ge=0)
    payload: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

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


class OfferType(str, Enum):
    SW0_ABSOLUTE = "sw0absoffer"
    SW0_RELATIVE = "sw0reloffer"
    SWA_ABSOLUTE = "swabsoffer"
    SWA_RELATIVE = "swreloffer"


class Offer(BaseModel):
    counterparty: str = Field(..., min_length=1)
    oid: int = Field(..., ge=0)
    ordertype: OfferType
    minsize: int = Field(..., ge=0)
    maxsize: int = Field(..., ge=0)
    txfee: int = Field(..., ge=0)
    cjfee: str | int
    fidelity_bond_value: int = Field(default=0, ge=0)
    directory_node: str | None = None
    fidelity_bond_data: dict[str, Any] | None = None

    @field_validator("cjfee")
    @classmethod
    def validate_cjfee(cls, v: str | int, info) -> str | int:
        ordertype = info.data.get("ordertype")
        if ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
            return int(v)
        return str(v)

    def is_absolute_fee(self) -> bool:
        return self.ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE)

    def calculate_fee(self, amount: int) -> int:
        if self.is_absolute_fee():
            return int(self.cjfee)
        else:
            from decimal import Decimal

            return int(Decimal(self.cjfee) * Decimal(amount))


class FidelityBond(BaseModel):
    counterparty: str
    utxo_txid: str = Field(..., pattern=r"^[0-9a-fA-F]{64}$")
    utxo_vout: int = Field(..., ge=0)
    bond_value: int | None = Field(default=None, ge=0)
    locktime: int = Field(..., ge=0)
    amount: int = Field(default=0, ge=0)
    script: str
    utxo_confirmations: int = Field(..., ge=0)
    utxo_confirmation_timestamp: int = Field(default=0, ge=0)
    cert_expiry: int = Field(..., ge=0)
    directory_node: str | None = None
    fidelity_bond_data: dict[str, Any] | None = None


class OrderBook(BaseModel):
    offers: list[Offer] = Field(default_factory=list)
    fidelity_bonds: list[FidelityBond] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    directory_nodes: list[str] = Field(default_factory=list)

    def add_offers(self, offers: list[Offer], directory_node: str) -> None:
        for offer in offers:
            offer.directory_node = directory_node
        self.offers.extend(offers)
        if directory_node not in self.directory_nodes:
            self.directory_nodes.append(directory_node)

    def add_fidelity_bonds(self, bonds: list[FidelityBond], directory_node: str) -> None:
        for bond in bonds:
            bond.directory_node = directory_node
        self.fidelity_bonds.extend(bonds)

    def get_offers_by_directory(self) -> dict[str, list[Offer]]:
        result: dict[str, list[Offer]] = {}
        for offer in self.offers:
            node = offer.directory_node or "unknown"
            if node not in result:
                result[node] = []
            result[node].append(offer)
        return result
