"""
Maker bot configuration.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from jmcore.constants import DUST_THRESHOLD
from jmcore.models import NetworkType, OfferType
from pydantic import BaseModel, Field, model_validator


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


class TorControlConfig(BaseModel):
    """
    Configuration for Tor control port connection.

    When enabled, the maker will dynamically create an ephemeral hidden
    service at startup using Tor's control port. This allows generating
    a new .onion address each time the maker starts without needing
    to pre-configure the hidden service in torrc.

    Requires Tor to be configured with:
        ControlPort 127.0.0.1:9051
        CookieAuthentication 1
        CookieAuthFile /var/lib/tor/control_auth_cookie
    """

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 9051
    cookie_path: Path | None = Field(
        default=None,
        description="Path to Tor cookie auth file (e.g., /var/lib/tor/control_auth_cookie)",
    )
    password: str | None = Field(
        default=None,
        description="Password for HASHEDPASSWORD auth (not recommended, use cookie auth)",
    )

    model_config = {"frozen": False}


class MakerConfig(BaseModel):
    mnemonic: str
    # Protocol network - used for directory server handshakes
    # Reference JoinMarket uses "testnet" for both testnet and regtest
    network: NetworkType = NetworkType.MAINNET
    # Bitcoin network - used for address generation (bcrt1 vs tb1 vs bc1)
    # If not specified, defaults to the same as network
    bitcoin_network: NetworkType | None = None

    # Data directory for JoinMarket files (commitment blacklist, history, etc.)
    # Defaults to ~/.joinmarket-ng or $JOINMARKET_DATA_DIR if set
    # For Docker compatibility with reference JM, set to /root/.joinmarket
    data_dir: Path | None = None

    backend_type: str = "full_node"  # full_node or neutrino
    backend_config: dict[str, Any] = Field(default_factory=dict)

    directory_servers: list[str] = Field(default_factory=list)

    # Tor/SOCKS configuration for outgoing connections
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050

    # Hidden service configuration for direct peer connections
    # If onion_host is set, maker will serve on a hidden service
    # If tor_control is enabled and onion_host is None, it will be auto-generated
    onion_host: str | None = None  # e.g., "mymaker...onion"
    onion_serving_host: str = "127.0.0.1"  # Local address Tor forwards to
    onion_serving_port: int = 27183  # Default JoinMarket port

    # Tor control port configuration for dynamic hidden service creation
    tor_control: TorControlConfig = Field(default_factory=TorControlConfig)

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

    # Timeouts
    session_timeout_sec: int = Field(
        default=300,
        ge=60,
        description="Maximum time for a CoinJoin session to complete (all states)",
    )

    # Dust threshold for change outputs
    dust_threshold: int = Field(
        default=DUST_THRESHOLD,
        ge=0,
        description="Dust threshold in satoshis for change outputs (default: 27300)",
    )

    # UTXO merge algorithm - how many UTXOs to use
    merge_algorithm: MergeAlgorithm = Field(
        default=MergeAlgorithm.DEFAULT,
        description=(
            "UTXO selection strategy: default (minimum), gradual (+1), "
            "greedy (all), random (0-2 extra)"
        ),
    )

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def validate_config(self) -> MakerConfig:
        """Validate configuration after initialization."""
        # Set bitcoin_network default
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
