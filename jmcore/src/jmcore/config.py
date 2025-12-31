"""
Base configuration classes for JoinMarket components.

This module provides Pydantic BaseModel classes that can be inherited
by specific components (maker, taker, etc.) to reduce duplication and
ensure consistency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from jmcore.constants import DUST_THRESHOLD
from jmcore.models import NetworkType


class TorConfig(BaseModel):
    """
    Configuration for Tor SOCKS proxy connection.

    Used for outgoing connections to directory servers and peers.
    """

    socks_host: str = Field(default="127.0.0.1", description="Tor SOCKS5 proxy host address")
    socks_port: int = Field(default=9050, ge=1, le=65535, description="Tor SOCKS5 proxy port")

    model_config = {"frozen": False}


class TorControlConfig(BaseModel):
    """
    Configuration for Tor control port connection.

    When enabled, allows dynamic creation of ephemeral hidden services
    at startup using Tor's control port. This allows generating a new
    .onion address each time without needing to pre-configure the hidden
    service in torrc.

    Requires Tor to be configured with:
        ControlPort 127.0.0.1:9051
        CookieAuthentication 1
        CookieAuthFile /var/lib/tor/control_auth_cookie

    Auto-detects configuration from environment variables:
        TOR_CONTROL_HOST - Tor control host (default: 127.0.0.1)
        TOR_CONTROL_PORT - Tor control port (default: 9051)
        TOR_COOKIE_PATH - Cookie auth file path
        TOR_PASSWORD - Tor control password (not recommended)
    """

    enabled: bool = Field(default=True, description="Enable Tor control port integration")
    host: str = Field(default="127.0.0.1", description="Tor control port host")
    port: int = Field(default=9051, ge=1, le=65535, description="Tor control port")
    cookie_path: Path | None = Field(
        default=None,
        description="Path to Tor cookie auth file (e.g., /var/lib/tor/control_auth_cookie)",
    )
    password: str | None = Field(
        default=None,
        description="Password for HASHEDPASSWORD auth (not recommended, use cookie auth)",
    )

    model_config = {"frozen": False}


def create_tor_control_config_from_env() -> TorControlConfig:
    """
    Create TorControlConfig from environment variables with smart defaults.

    Environment variables:
        TOR_CONTROL_HOST - Tor control host (default: 127.0.0.1 or tor if exists)
        TOR_CONTROL_PORT - Tor control port (default: 9051)
        TOR_COOKIE_PATH - Cookie auth file path
        TOR_PASSWORD - Tor control password

    Auto-detection:
        - If TOR_COOKIE_PATH is set, use it
        - Otherwise try common paths: /var/lib/tor/control_auth_cookie, /run/tor/control.authcookie
    """
    import os

    # Try to detect if we're in a docker environment with a tor container
    host = os.environ.get("TOR_CONTROL_HOST", "127.0.0.1")
    # If TOR_SOCKS_HOST is set to "tor", likely docker - try that for control too
    if not os.environ.get("TOR_CONTROL_HOST") and os.environ.get("TOR_SOCKS_HOST") == "tor":
        host = "tor"

    port = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
    password = os.environ.get("TOR_PASSWORD")

    # Try to find cookie path
    cookie_path_str = os.environ.get("TOR_COOKIE_PATH")
    cookie_path: Path | None = None

    if cookie_path_str:
        cookie_path = Path(cookie_path_str)
    else:
        # Try common paths
        common_paths = [
            Path("/var/lib/tor/control_auth_cookie"),
            Path("/run/tor/control.authcookie"),
            Path("/var/run/tor/control.authcookie"),
        ]
        for path in common_paths:
            if path.exists():
                cookie_path = path
                break

    return TorControlConfig(
        enabled=True,
        host=host,
        port=port,
        cookie_path=cookie_path,
        password=password,
    )


class BackendConfig(BaseModel):
    """
    Configuration for Bitcoin backend connection.

    Supports different backend types:
    - full_node: Bitcoin Core RPC
    - neutrino: Light client using BIP 157/158
    """

    backend_type: str = Field(
        default="full_node",
        description="Backend type: 'full_node' or 'neutrino'",
    )
    backend_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Backend-specific configuration (RPC credentials, neutrino peers, etc.)",
    )

    model_config = {"frozen": False}


class WalletConfig(BaseModel):
    """
    Base wallet configuration shared by all JoinMarket wallet users.

    Includes wallet seed, network settings, HD wallet structure, and
    backend connection details.
    """

    # Wallet seed
    mnemonic: str = Field(..., description="BIP39 mnemonic phrase for wallet seed")

    # Network settings
    network: NetworkType = Field(
        default=NetworkType.MAINNET,
        description="Protocol network for directory server handshakes",
    )
    bitcoin_network: NetworkType | None = Field(
        default=None,
        description="Bitcoin network for address generation (defaults to same as network)",
    )

    # Data directory
    data_dir: Path | None = Field(
        default=None,
        description=(
            "Data directory for JoinMarket files (commitment blacklist, history, etc.). "
            "Defaults to ~/.joinmarket-ng or $JOINMARKET_DATA_DIR if set"
        ),
    )

    # Backend configuration
    backend_type: str = Field(
        default="full_node",
        description="Backend type: 'full_node' or 'neutrino'",
    )
    backend_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Backend-specific configuration",
    )

    # Directory servers
    directory_servers: list[str] = Field(
        default_factory=list,
        description="List of directory server URLs (e.g., ['onion_host:port', ...])",
    )

    # Tor/SOCKS configuration
    socks_host: str = Field(default="127.0.0.1", description="Tor SOCKS5 proxy host")
    socks_port: int = Field(default=9050, ge=1, le=65535, description="Tor SOCKS5 proxy port")

    # HD wallet structure
    mixdepth_count: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Number of mixdepths in the wallet (privacy compartments)",
    )
    gap_limit: int = Field(default=20, ge=6, description="BIP44 gap limit for address scanning")

    # Dust threshold
    dust_threshold: int = Field(
        default=DUST_THRESHOLD,
        ge=0,
        description="Dust threshold in satoshis for change outputs (default: 27300)",
    )

    model_config = {"frozen": False}

    @model_validator(mode="after")
    def set_bitcoin_network_default(self) -> WalletConfig:
        """If bitcoin_network is not set, default to the protocol network."""
        if self.bitcoin_network is None:
            object.__setattr__(self, "bitcoin_network", self.network)
        return self


class DirectoryServerConfig(BaseModel):
    """
    Configuration for directory server instances.

    Used by standalone directory servers, not by clients.
    """

    network: NetworkType = Field(
        default=NetworkType.MAINNET, description="Network type for the directory server"
    )
    host: str = Field(default="127.0.0.1", description="Host address to bind to")
    port: int = Field(default=5222, ge=1, le=65535, description="Port to listen on")

    # Limits
    max_peers: int = Field(default=10000, ge=1, description="Maximum number of connected peers")
    max_message_size: int = Field(
        default=2097152, ge=1024, description="Maximum message size in bytes (default: 2MB)"
    )
    max_line_length: int = Field(
        default=65536, ge=1024, description="Maximum JSON-line message length (default: 64KB)"
    )
    max_json_nesting_depth: int = Field(
        default=10, ge=1, le=100, description="Maximum nesting depth for JSON parsing"
    )

    # Rate limiting
    # Higher limits to accommodate makers responding to orderbook requests
    # A single maker might send multiple offer messages + bond proofs rapidly
    message_rate_limit: int = Field(
        default=500, ge=1, description="Messages per second (sustained)"
    )
    message_burst_limit: int = Field(default=1000, ge=1, description="Maximum burst size")
    rate_limit_disconnect_threshold: int = Field(
        default=200, ge=1, description="Disconnect after N violations"
    )

    # Broadcasting
    broadcast_batch_size: int = Field(
        default=50,
        ge=1,
        description="Batch size for concurrent broadcasts (lower = less memory)",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    # Server info
    motd: str = Field(
        default="JoinMarket Directory Server https://github.com/m0wer/joinmarket-ng",
        description="Message of the day sent to clients",
    )

    # Health check
    health_check_host: str = Field(
        default="127.0.0.1", description="Host for health check endpoint"
    )
    health_check_port: int = Field(
        default=8080, ge=1, le=65535, description="Port for health check endpoint"
    )

    model_config = {"frozen": False}


__all__ = [
    "TorConfig",
    "TorControlConfig",
    "create_tor_control_config_from_env",
    "BackendConfig",
    "WalletConfig",
    "DirectoryServerConfig",
]
