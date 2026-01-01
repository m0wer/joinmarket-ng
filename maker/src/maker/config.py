"""
Maker bot configuration.
"""

from __future__ import annotations

from enum import Enum

from jmcore.config import TorControlConfig, WalletConfig
from jmcore.models import OfferType
from pydantic import Field, model_validator


class MergeAlgorithm(str, Enum):
    """
    UTXO selection algorithm for makers.

    Determines how many UTXOs to use when participating in a CoinJoin.
    Since takers pay all tx fees, makers can add extra inputs "for free"
    which helps consolidate UTXOs and improves taker privacy.

    - default: Select minimum UTXOs needed (frugal)
    - gradual: Select 1 additional UTXO beyond minimum
    - greedy: Select ALL UTXOs from the mixdepth (max consolidation)
    - random: Select between 0-2 additional UTXOs randomly

    Reference: joinmarket-clientserver policy.py merge_algorithm
    """

    DEFAULT = "default"
    GRADUAL = "gradual"
    GREEDY = "greedy"
    RANDOM = "random"


class MakerConfig(WalletConfig):
    """
    Configuration for maker bot.

    Inherits base wallet configuration from jmcore.config.WalletConfig
    and adds maker-specific settings for offers, hidden services, and
    UTXO selection.
    """

    # Hidden service configuration for direct peer connections
    # If onion_host is set, maker will serve on a hidden service
    # If tor_control is enabled and onion_host is None, it will be auto-generated
    onion_host: str | None = Field(
        default=None, description="Hidden service address (e.g., 'mymaker...onion')"
    )
    onion_serving_host: str = Field(
        default="127.0.0.1", description="Local address Tor forwards to"
    )
    onion_serving_port: int = Field(
        default=5222, ge=0, le=65535, description="Default JoinMarket port (0 = auto-assign)"
    )

    # Tor control port configuration for dynamic hidden service creation
    tor_control: TorControlConfig = Field(
        default_factory=TorControlConfig,
        description="Tor control port configuration",
    )

    # Offer configuration
    offer_type: OfferType = Field(
        default=OfferType.SW0_RELATIVE, description="Offer type (relative/absolute fee)"
    )
    min_size: int = Field(default=100_000, ge=0, description="Minimum CoinJoin amount in satoshis")
    cj_fee_relative: str = Field(default="0.001", description="Relative CJ fee (0.001 = 0.1%)")
    cj_fee_absolute: int = Field(default=500, ge=0, description="Absolute CJ fee in satoshis")
    tx_fee_contribution: int = Field(
        default=0, ge=0, description="Transaction fee contribution in satoshis"
    )

    # Minimum confirmations for UTXOs
    min_confirmations: int = Field(default=1, ge=0, description="Minimum confirmations for UTXOs")

    # Fidelity bond configuration
    # List of locktimes (Unix timestamps) to scan for fidelity bonds
    # These should match locktimes used when creating bond UTXOs
    fidelity_bond_locktimes: list[int] = Field(
        default_factory=list, description="List of locktimes to scan for fidelity bonds"
    )

    # Selected fidelity bond (txid, vout) - if not set, largest bond is used automatically
    selected_fidelity_bond: tuple[str, int] | None = Field(
        default=None, description="Selected fidelity bond UTXO (txid, vout)"
    )

    # Timeouts
    session_timeout_sec: int = Field(
        default=300,
        ge=60,
        description="Maximum time for a CoinJoin session to complete (all states)",
    )

    # Wallet rescan configuration
    post_coinjoin_rescan_delay: int = Field(
        default=60,
        ge=5,
        description="Seconds to wait before rescanning wallet after CoinJoin completion",
    )
    rescan_interval_sec: int = Field(
        default=600,
        ge=60,
        description="Interval in seconds for periodic wallet rescans (default: 10 minutes)",
    )

    # UTXO merge algorithm - how many UTXOs to use
    merge_algorithm: MergeAlgorithm = Field(
        default=MergeAlgorithm.DEFAULT,
        description=(
            "UTXO selection strategy: default (minimum), gradual (+1), "
            "greedy (all), random (0-2 extra)"
        ),
    )

    # Generic message rate limiting (protects against spam/DoS)
    message_rate_limit: int = Field(
        default=10,
        ge=1,
        description="Maximum messages per second per peer (sustained)",
    )
    message_burst_limit: int = Field(
        default=100,
        ge=1,
        description="Maximum burst messages per peer (default: 100, allows ~10s at max rate)",
    )

    # Rate limiting for orderbook requests (protects against spam attacks)
    orderbook_rate_limit: int = Field(
        default=1,
        ge=1,
        description="Maximum orderbook responses per peer per interval",
    )
    orderbook_rate_interval: float = Field(
        default=10.0,
        ge=1.0,
        description="Interval in seconds for orderbook rate limiting (default: 10s)",
    )

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def validate_config(self) -> MakerConfig:
        """Validate configuration after initialization."""
        # Set bitcoin_network default (handled by parent WalletConfig)
        if self.bitcoin_network is None:
            object.__setattr__(self, "bitcoin_network", self.network)

        # Validate cj_fee_relative for relative offer types
        if self.offer_type in (OfferType.SW0_RELATIVE, OfferType.SWA_RELATIVE):
            try:
                cj_fee_float = float(self.cj_fee_relative)
                if cj_fee_float <= 0:
                    raise ValueError(
                        f"cj_fee_relative must be > 0 for relative offer types, "
                        f"got {self.cj_fee_relative}"
                    )
            except ValueError as e:
                if "could not convert" in str(e):
                    raise ValueError(
                        f"cj_fee_relative must be a valid number, got {self.cj_fee_relative}"
                    ) from e
                raise

        return self
