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

    backend_type: str = "full_node"  # full_node or neutrino
    backend_config: dict[str, Any] = Field(default_factory=dict)

    directory_servers: list[str] = Field(default_factory=list)

    # Tor/SOCKS configuration for outgoing connections
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050

    # Hidden service configuration for direct peer connections
    # If onion_host is set, maker will serve on a hidden service
    onion_host: str | None = None  # e.g., "mymaker...onion"
    onion_serving_host: str = "127.0.0.1"  # Local address Tor forwards to
    onion_serving_port: int = 27183  # Default JoinMarket port

    offer_type: OfferType = OfferType.SW0_RELATIVE
    min_size: int = 100_000
    cj_fee_relative: str = "0.001"  # 0.1% - matches taker max_rel_fee default
    cj_fee_absolute: int = 500  # sats - matches taker max_abs_fee default
    tx_fee_contribution: int = 0  # sats

    mixdepth_count: int = 5
    gap_limit: int = 20

    min_confirmations: int = 1

    # Fidelity bond configuration
    # List of locktimes (Unix timestamps) to scan for fidelity bonds
    # These should match locktimes used when creating bond UTXOs
    fidelity_bond_locktimes: list[int] = Field(default_factory=list)

    # Selected fidelity bond (txid, vout) - if not set, largest bond is used automatically
    selected_fidelity_bond: tuple[str, int] | None = None

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def set_bitcoin_network_default(self) -> MakerConfig:
        """If bitcoin_network is not set, default to the protocol network."""
        if self.bitcoin_network is None:
            # Use object.__setattr__ since model might be frozen
            object.__setattr__(self, "bitcoin_network", self.network)
        return self
