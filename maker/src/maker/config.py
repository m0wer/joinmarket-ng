"""
Maker bot configuration.
"""

from __future__ import annotations

from typing import Any

from jmcore.models import NetworkType, OfferType
from pydantic import BaseModel, Field, model_validator


class MakerConfig(BaseModel):
    mnemonic: str
    # Protocol network - used for directory server handshakes
    # Reference JoinMarket uses "testnet" for both testnet and regtest
    network: NetworkType = NetworkType.MAINNET
    # Bitcoin network - used for address generation (bcrt1 vs tb1 vs bc1)
    # If not specified, defaults to the same as network
    bitcoin_network: NetworkType | None = None

    backend_type: str = "bitcoin_core"
    backend_config: dict[str, Any] = Field(default_factory=dict)

    directory_servers: list[str] = Field(default_factory=list)

    offer_type: OfferType = OfferType.SW0_RELATIVE
    min_size: int = 100_000
    cj_fee_relative: str = "0.0002"
    cj_fee_absolute: int = 1000
    tx_fee_contribution: int = 10_000

    mixdepth_count: int = 5
    gap_limit: int = 20

    min_confirmations: int = 1

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def set_bitcoin_network_default(self) -> MakerConfig:
        """If bitcoin_network is not set, default to the protocol network."""
        if self.bitcoin_network is None:
            # Use object.__setattr__ since model might be frozen
            object.__setattr__(self, "bitcoin_network", self.network)
        return self
