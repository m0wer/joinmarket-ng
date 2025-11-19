"""
Maker bot configuration.
"""

from __future__ import annotations

from typing import Any

from jmcore.models import NetworkType, OfferType
from pydantic import BaseModel, Field


class MakerConfig(BaseModel):
    mnemonic: str
    network: NetworkType = NetworkType.MAINNET

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
