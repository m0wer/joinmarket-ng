"""
Unified settings management for JoinMarket components.

This module provides a centralized configuration system using pydantic-settings
that supports:
1. TOML configuration file (~/.joinmarket-ng/config.toml)
2. Environment variables
3. CLI arguments (via typer, handled by components)

Priority (highest to lowest):
1. CLI arguments
2. Environment variables
3. Config file
4. Default values

The config file is auto-generated on first run with all settings commented out,
allowing users to selectively override only the settings they want to change.
This approach facilitates software updates since unchanged defaults can be
updated without user intervention.

Usage:
    from jmcore.settings import get_settings, JoinMarketSettings

    # Get settings (loads from all sources with proper priority)
    settings = get_settings()

    # Access common settings
    print(settings.tor.socks_host)
    print(settings.bitcoin.rpc_url)

Environment Variable Naming:
    - Use uppercase with underscores
    - Nested settings use double underscore: TOR__SOCKS_HOST, BITCOIN__RPC_URL
    - Maps to TOML sections: TOR__SOCKS_HOST -> [tor] socks_host
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, ClassVar

from loguru import logger
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from jmcore.models import NetworkType
from jmcore.paths import get_default_data_dir

# Default directory servers per network
DEFAULT_DIRECTORY_SERVERS: dict[str, list[str]] = {
    "mainnet": [
        "satoshi2vcg5e2ept7tjkzlkpomkobqmgtsjzegg6wipnoajadissead.onion:5222",
        "coinjointovy3eq5fjygdwpkbcdx63d7vd4g32mw7y553uj3kjjzkiqd.onion:5222",
        "nakamotourflxwjnjpnrk7yc2nhkf6r62ed4gdfxmmn5f4saw5q5qoyd.onion:5222",
        "shssats5ucnwdpbticbb4dymjzf2o27tdecpes35ededagjpdmpxm6yd.onion:5222",
        "odpwaf67rs5226uabcamvypg3y4bngzmfk7255flcdodesqhsvkptaid.onion:5222",
        "jmv2dirze66rwxsq7xv7frhmaufyicd3yz5if6obtavsskczjkndn6yd.onion:5222",
        "jmarketxf5wc4aldf3slm5u6726zsky52bqnfv6qyxe5hnafgly6yuyd.onion:5222",
    ],
    "signet": [],
    "testnet": [],
    "regtest": [],
}


class TorSettings(BaseModel):
    """Tor proxy configuration."""

    socks_host: str = Field(
        default="127.0.0.1",
        description="Tor SOCKS5 proxy host",
    )
    socks_port: int = Field(
        default=9050,
        ge=1,
        le=65535,
        description="Tor SOCKS5 proxy port",
    )


class TorControlSettings(BaseModel):
    """Tor control port configuration for hidden service management."""

    enabled: bool = Field(
        default=True,
        description="Enable Tor control port integration for ephemeral hidden services",
    )
    port: int = Field(
        default=9051,
        ge=1,
        le=65535,
        description="Tor control port",
    )
    cookie_path: str | None = Field(
        default=None,
        description="Path to Tor cookie auth file",
    )
    password: SecretStr | None = Field(
        default=None,
        description="Tor control port password (use cookie auth instead if possible)",
    )


class BitcoinSettings(BaseModel):
    """Bitcoin backend configuration."""

    backend_type: str = Field(
        default="descriptor_wallet",
        description="Backend type: full_node, descriptor_wallet, or neutrino",
    )
    rpc_url: str = Field(
        default="http://127.0.0.1:8332",
        description="Bitcoin Core RPC URL",
    )
    rpc_user: str = Field(
        default="",
        description="Bitcoin Core RPC username",
    )
    rpc_password: SecretStr = Field(
        default=SecretStr(""),
        description="Bitcoin Core RPC password",
    )
    neutrino_url: str = Field(
        default="http://127.0.0.1:8334",
        description="Neutrino REST API URL (for neutrino backend)",
    )


class NetworkSettings(BaseModel):
    """Network configuration."""

    network: NetworkType = Field(
        default=NetworkType.MAINNET,
        description="JoinMarket protocol network (mainnet, testnet, signet, regtest)",
    )
    bitcoin_network: NetworkType | None = Field(
        default=None,
        description="Bitcoin network for address generation (defaults to network)",
    )
    directory_servers: list[str] = Field(
        default_factory=list,
        description="Directory server addresses (host:port). Uses defaults if empty.",
    )


class WalletSettings(BaseModel):
    """Wallet configuration."""

    mixdepth_count: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Number of mixdepths (privacy compartments)",
    )
    gap_limit: int = Field(
        default=20,
        ge=6,
        description="BIP44 gap limit for address scanning",
    )
    dust_threshold: int = Field(
        default=27300,
        ge=0,
        description="Dust threshold in satoshis",
    )
    smart_scan: bool = Field(
        default=True,
        description="Use smart scan for fast startup",
    )
    background_full_rescan: bool = Field(
        default=True,
        description="Run full blockchain rescan in background",
    )
    scan_lookback_blocks: int = Field(
        default=52560,
        ge=0,
        description="Blocks to look back for smart scan (~1 year default)",
    )
    default_fee_block_target: int = Field(
        default=3,
        ge=1,
        le=1008,
        description="Default block target for fee estimation in wallet transactions",
    )
    mnemonic_file: str | None = Field(
        default=None,
        description="Default path to mnemonic file",
    )
    mnemonic_password: SecretStr | None = Field(
        default=None,
        description="Password for encrypted mnemonic file",
    )


class NotificationSettings(BaseModel):
    """Notification system configuration."""

    enabled: bool = Field(
        default=False,
        description="Enable notifications (requires urls to be set)",
    )
    urls: list[str] = Field(
        default_factory=list,
        description='Apprise notification URLs (e.g., ["tgram://bottoken/ChatID", "gotify://hostname/token"])',
    )
    title_prefix: str = Field(
        default="JoinMarket NG",
        description="Prefix for notification titles",
    )
    include_amounts: bool = Field(
        default=True,
        description="Include amounts in notifications",
    )
    include_txids: bool = Field(
        default=False,
        description="Include transaction IDs in notifications (privacy risk)",
    )
    include_nick: bool = Field(
        default=True,
        description="Include peer nicks in notifications",
    )
    use_tor: bool = Field(
        default=True,
        description="Route notifications through Tor SOCKS proxy",
    )
    # Event type toggles
    notify_fill: bool = Field(default=True, description="Notify on !fill requests")
    notify_rejection: bool = Field(default=True, description="Notify on rejections")
    notify_signing: bool = Field(default=True, description="Notify on transaction signing")
    notify_mempool: bool = Field(default=True, description="Notify on mempool detection")
    notify_confirmed: bool = Field(default=True, description="Notify on confirmation")
    notify_nick_change: bool = Field(default=True, description="Notify on nick change")
    notify_disconnect: bool = Field(default=True, description="Notify on directory disconnect")
    notify_coinjoin_start: bool = Field(default=True, description="Notify on CoinJoin start")
    notify_coinjoin_complete: bool = Field(default=True, description="Notify on CoinJoin complete")
    notify_coinjoin_failed: bool = Field(default=True, description="Notify on CoinJoin failure")
    notify_peer_events: bool = Field(default=False, description="Notify on peer connect/disconnect")
    notify_rate_limit: bool = Field(default=True, description="Notify on rate limit bans")
    notify_startup: bool = Field(default=True, description="Notify on component startup")


class MakerSettings(BaseModel):
    """Maker-specific settings."""

    min_size: int = Field(
        default=100000,
        ge=0,
        description="Minimum CoinJoin amount in satoshis",
    )
    cj_fee_relative: str = Field(
        default="0.001",
        description="Relative CoinJoin fee (0.001 = 0.1%)",
    )
    cj_fee_absolute: int = Field(
        default=500,
        ge=0,
        description="Absolute CoinJoin fee in satoshis",
    )
    tx_fee_contribution: int = Field(
        default=0,
        ge=0,
        description="Transaction fee contribution in satoshis",
    )
    min_confirmations: int = Field(
        default=1,
        ge=0,
        description="Minimum confirmations for UTXOs",
    )
    merge_algorithm: str = Field(
        default="default",
        description="UTXO selection: default, gradual, greedy, random",
    )
    session_timeout_sec: int = Field(
        default=300,
        ge=60,
        description="Maximum time for a CoinJoin session",
    )
    rescan_interval_sec: int = Field(
        default=600,
        ge=60,
        description="Interval for periodic wallet rescans",
    )
    # Hidden service settings
    onion_serving_host: str = Field(
        default="127.0.0.1",
        description="Bind address for incoming connections",
    )
    onion_serving_port: int = Field(
        default=5222,
        ge=0,
        le=65535,
        description="Port for incoming onion connections",
    )
    tor_target_host: str = Field(
        default="127.0.0.1",
        description="Target host for Tor hidden service",
    )
    # Rate limiting
    message_rate_limit: int = Field(
        default=10,
        ge=1,
        description="Messages per second per peer (sustained)",
    )
    message_burst_limit: int = Field(
        default=100,
        ge=1,
        description="Maximum burst messages per peer",
    )


class TakerSettings(BaseModel):
    """Taker-specific settings."""

    counterparty_count: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Number of makers to select for CoinJoin",
    )
    max_cj_fee_abs: int = Field(
        default=500,
        ge=0,
        description="Maximum absolute CoinJoin fee in satoshis",
    )
    max_cj_fee_rel: str = Field(
        default="0.001",
        description="Maximum relative CoinJoin fee (0.001 = 0.1%)",
    )
    tx_fee_factor: float = Field(
        default=3.0,
        ge=1.0,
        description="Multiply estimated fee by this factor",
    )
    fee_block_target: int | None = Field(
        default=None,
        ge=1,
        le=1008,
        description="Target blocks for fee estimation",
    )
    bondless_makers_allowance: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Fraction of time to choose makers randomly",
    )
    bond_value_exponent: float = Field(
        default=1.3,
        gt=0.0,
        description="Exponent for fidelity bond value calculation",
    )
    bondless_require_zero_fee: bool = Field(
        default=True,
        description="Require zero absolute fee for bondless maker spots",
    )
    maker_timeout_sec: int = Field(
        default=60,
        ge=10,
        description="Timeout for maker responses",
    )
    order_wait_time: float = Field(
        default=10.0,
        ge=1.0,
        description="Seconds to wait for orderbook",
    )
    tx_broadcast: str = Field(
        default="random-peer",
        description="Broadcast policy: self, random-peer, multiple-peers, not-self",
    )
    broadcast_peer_count: int = Field(
        default=3,
        ge=1,
        description="Number of peers for multiple-peers broadcast",
    )
    minimum_makers: int = Field(
        default=2,
        ge=1,
        description="Minimum number of makers required",
    )
    rescan_interval_sec: int = Field(
        default=600,
        ge=60,
        description="Interval for periodic wallet rescans",
    )


class DirectoryServerSettings(BaseModel):
    """Directory server specific settings."""

    host: str = Field(
        default="127.0.0.1",
        description="Host address to bind to",
    )
    port: int = Field(
        default=5222,
        ge=0,
        le=65535,
        description="Port to listen on (0 = let OS assign)",
    )
    max_peers: int = Field(
        default=10000,
        ge=1,
        description="Maximum number of connected peers",
    )
    max_message_size: int = Field(
        default=2097152,
        ge=1024,
        description="Maximum message size in bytes (2MB default)",
    )
    max_line_length: int = Field(
        default=65536,
        ge=1024,
        description="Maximum JSON-line message length (64KB default)",
    )
    max_json_nesting_depth: int = Field(
        default=10,
        ge=1,
        description="Maximum nesting depth for JSON parsing",
    )
    message_rate_limit: int = Field(
        default=500,
        ge=1,
        description="Messages per second (sustained)",
    )
    message_burst_limit: int = Field(
        default=1000,
        ge=1,
        description="Maximum burst size",
    )
    rate_limit_disconnect_threshold: int = Field(
        default=0,
        ge=0,
        description="Disconnect after N rate limit violations (0 = never disconnect)",
    )
    broadcast_batch_size: int = Field(
        default=50,
        ge=1,
        description="Batch size for concurrent broadcasts",
    )
    health_check_host: str = Field(
        default="127.0.0.1",
        description="Host for health check endpoint",
    )
    health_check_port: int = Field(
        default=8080,
        ge=0,
        le=65535,
        description="Port for health check endpoint (0 = let OS assign)",
    )
    motd: str = Field(
        default="JoinMarket NG Directory Server https://github.com/m0wer/joinmarket-ng/tree/master",
        description="Message of the day sent to clients",
    )


class OrderbookWatcherSettings(BaseModel):
    """Orderbook watcher specific settings."""

    http_host: str = Field(
        default="0.0.0.0",
        description="HTTP server bind address",
    )
    http_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="HTTP server port",
    )
    update_interval: int = Field(
        default=60,
        ge=10,
        description="Update interval in seconds",
    )
    mempool_api_url: str = Field(
        default="http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion/api",
        description="Mempool API URL for transaction lookups",
    )
    mempool_web_url: str | None = Field(
        default="https://mempool.sgn.space",
        description="Mempool web URL for human-readable links",
    )
    uptime_grace_period: int = Field(
        default=60,
        ge=0,
        description="Grace period before tracking uptime",
    )
    max_message_size: int = Field(
        default=2097152,
        ge=1024,
        description="Maximum message size in bytes (2MB default)",
    )
    connection_timeout: float = Field(
        default=30.0,
        gt=0.0,
        description="Connection timeout in seconds",
    )


class LoggingSettings(BaseModel):
    """Logging configuration."""

    level: str = Field(
        default="INFO",
        description="Log level: DEBUG, INFO, WARNING, ERROR",
    )
    sensitive: bool = Field(
        default=False,
        description="Enable sensitive logging (mnemonics, keys)",
    )


class JoinMarketSettings(BaseSettings):
    """
    Main JoinMarket settings class.

    Loads configuration from multiple sources with the following priority:
    1. CLI arguments (not handled here, passed to component __init__)
    2. Environment variables
    3. TOML config file (~/.joinmarket-ng/config.toml)
    4. Default values
    """

    model_config = SettingsConfigDict(
        env_prefix="",  # No prefix by default, use env_nested_delimiter for nested
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",  # Ignore unknown fields (for forward compatibility)
    )

    # Marker for config file path discovery
    _config_file_path: ClassVar[Path | None] = None

    # Core settings
    data_dir: Path | None = Field(
        default=None,
        description="Data directory (defaults to ~/.joinmarket-ng)",
    )

    # Nested settings groups
    tor: TorSettings = Field(default_factory=TorSettings)
    tor_control: TorControlSettings = Field(default_factory=TorControlSettings)
    bitcoin: BitcoinSettings = Field(default_factory=BitcoinSettings)
    network_config: NetworkSettings = Field(default_factory=NetworkSettings)
    wallet: WalletSettings = Field(default_factory=WalletSettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # Component-specific settings
    maker: MakerSettings = Field(default_factory=MakerSettings)
    taker: TakerSettings = Field(default_factory=TakerSettings)
    directory_server: DirectoryServerSettings = Field(default_factory=DirectoryServerSettings)
    orderbook_watcher: OrderbookWatcherSettings = Field(default_factory=OrderbookWatcherSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """
        Customize settings sources and their priority.

        Priority (highest to lowest):
        1. init_settings (CLI arguments passed to constructor)
        2. env_settings (environment variables)
        3. toml_settings (config.toml file)
        4. defaults (in field definitions)
        """
        toml_source = TomlConfigSettingsSource(settings_cls)
        return (
            init_settings,
            env_settings,
            toml_source,
        )

    def get_data_dir(self) -> Path:
        """Get the data directory, using default if not set."""
        if self.data_dir is not None:
            return self.data_dir
        return get_default_data_dir()

    def get_directory_servers(self) -> list[str]:
        """Get directory servers, using network defaults if not set."""
        if self.network_config.directory_servers:
            return self.network_config.directory_servers
        network_name = self.network_config.network.value
        return DEFAULT_DIRECTORY_SERVERS.get(network_name, [])


class TomlConfigSettingsSource(PydanticBaseSettingsSource):
    """
    Custom settings source that reads from a TOML config file.

    The config file is expected at ~/.joinmarket-ng/config.toml or
    $JOINMARKET_DATA_DIR/config.toml if the environment variable is set.
    """

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        self._config: dict[str, Any] = {}
        self._load_config()

    def _get_config_path(self) -> Path:
        """Determine the config file path."""
        # Check for explicit config path in environment
        env_path = os.environ.get("JOINMARKET_CONFIG_FILE")
        if env_path:
            return Path(env_path)

        # Use data directory
        data_dir_env = os.environ.get("JOINMARKET_DATA_DIR")
        data_dir = Path(data_dir_env) if data_dir_env else Path.home() / ".joinmarket-ng"

        return data_dir / "config.toml"

    def _load_config(self) -> None:
        """Load configuration from TOML file."""
        config_path = self._get_config_path()

        if not config_path.exists():
            logger.debug(f"Config file not found at {config_path}, using defaults")
            return

        try:
            import tomllib

            with open(config_path, "rb") as f:
                self._config = tomllib.load(f)

            logger.info(f"Loaded config from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        """Get field value from TOML config."""
        # Handle nested fields by looking up in nested dicts
        value = self._config.get(field_name)
        return value, field_name, value is not None

    def __call__(self) -> dict[str, Any]:
        """Return all config values as a flat dict for pydantic-settings."""
        return self._config


def get_config_path() -> Path:
    """Get the path to the config file."""
    data_dir_env = os.environ.get("JOINMARKET_DATA_DIR")
    data_dir = Path(data_dir_env) if data_dir_env else Path.home() / ".joinmarket-ng"
    return data_dir / "config.toml"


def generate_config_template() -> str:
    """
    Generate a config file template with all settings commented out.

    This allows users to see all available settings with their defaults
    and descriptions, while only uncommenting what they want to change.
    """
    lines: list[str] = []

    lines.append("# JoinMarket NG Configuration")
    lines.append("#")
    lines.append("# This file contains all available settings with their default values.")
    lines.append("# Settings are commented out by default - uncomment to override.")
    lines.append("#")
    lines.append("# Priority (highest to lowest):")
    lines.append("#   1. CLI arguments")
    lines.append("#   2. Environment variables")
    lines.append("#   3. This config file")
    lines.append("#   4. Built-in defaults")
    lines.append("#")
    lines.append("# Environment variables use uppercase with double underscore for nesting:")
    lines.append("#   TOR__SOCKS_HOST=127.0.0.1")
    lines.append("#   BITCOIN__RPC_URL=http://localhost:8332")
    lines.append("#")
    lines.append("")

    # Generate sections for each nested model
    def add_section(title: str, model_cls: type[BaseModel], prefix: str = "") -> None:
        lines.append(f"# {'=' * 60}")
        lines.append(f"# {title}")
        lines.append(f"# {'=' * 60}")
        lines.append(f"[{prefix}]" if prefix else "")
        lines.append("")

        for field_name, field_info in model_cls.model_fields.items():
            # Get description
            desc = field_info.description or ""
            if desc:
                lines.append(f"# {desc}")

            # Get default value
            default = field_info.default
            factory = field_info.default_factory
            if factory is not None:
                # default_factory can be Callable[[], Any] or Callable[[dict], Any]
                # We call with no args for the common case
                try:
                    default = factory()  # type: ignore[call-arg]
                except TypeError:
                    default = factory({})  # type: ignore[call-arg]

            # Format the value for TOML
            if isinstance(default, bool):
                value_str = str(default).lower()
            elif isinstance(default, str):
                value_str = f'"{default}"'
            elif isinstance(default, list):
                # For directory_servers, show example from defaults
                if field_name == "directory_servers" and prefix == "network_config":
                    lines.append("# directory_servers = [")
                    for server in DEFAULT_DIRECTORY_SERVERS["mainnet"]:
                        lines.append(f'#   "{server}",')
                    lines.append("# ]")
                    lines.append("")
                    continue
                value_str = "[]" if not default else str(default).replace("'", '"')
            elif isinstance(default, SecretStr):
                value_str = '""'
            elif default is None:
                # Skip None values with a comment
                lines.append(f"# {field_name} = ")
                lines.append("")
                continue
            elif hasattr(default, "value"):  # Enum - use string value
                value_str = f'"{default.value}"'
            else:
                value_str = str(default)

            lines.append(f"# {field_name} = {value_str}")
            lines.append("")

    # Data directory (top-level)
    lines.append("# Data directory for JoinMarket files")
    lines.append("# Defaults to ~/.joinmarket-ng or $JOINMARKET_DATA_DIR")
    lines.append("# data_dir = ")
    lines.append("")

    # Add all sections
    add_section("Tor Proxy Settings", TorSettings, "tor")
    add_section("Tor Control Port Settings", TorControlSettings, "tor_control")
    add_section("Bitcoin Backend Settings", BitcoinSettings, "bitcoin")
    add_section("Network Settings", NetworkSettings, "network_config")
    add_section("Wallet Settings", WalletSettings, "wallet")
    add_section("Notification Settings", NotificationSettings, "notifications")
    add_section("Logging Settings", LoggingSettings, "logging")
    add_section("Maker Settings", MakerSettings, "maker")
    add_section("Taker Settings", TakerSettings, "taker")
    add_section("Directory Server Settings", DirectoryServerSettings, "directory_server")
    add_section("Orderbook Watcher Settings", OrderbookWatcherSettings, "orderbook_watcher")

    return "\n".join(lines)


def ensure_config_file(data_dir: Path | None = None) -> Path:
    """
    Ensure the config file exists, creating a template if it doesn't.

    Args:
        data_dir: Optional data directory path. Uses default if not provided.

    Returns:
        Path to the config file.
    """
    if data_dir is None:
        data_dir = get_default_data_dir()

    config_path = data_dir / "config.toml"

    if not config_path.exists():
        logger.info(f"Creating config file template at {config_path}")
        data_dir.mkdir(parents=True, exist_ok=True)
        config_path.write_text(generate_config_template())

    return config_path


# Global settings instance (lazy-loaded)
_settings: JoinMarketSettings | None = None


def get_settings(**overrides: Any) -> JoinMarketSettings:
    """
    Get the JoinMarket settings instance.

    On first call, loads settings from all sources. Subsequent calls
    return the cached instance unless reset_settings() is called.

    Args:
        **overrides: Optional settings overrides (highest priority)

    Returns:
        JoinMarketSettings instance
    """
    global _settings
    if _settings is None or overrides:
        _settings = JoinMarketSettings(**overrides)
    return _settings


def reset_settings() -> None:
    """Reset the global settings instance (useful for testing)."""
    global _settings
    _settings = None


__all__ = [
    "JoinMarketSettings",
    "TorSettings",
    "TorControlSettings",
    "BitcoinSettings",
    "NetworkSettings",
    "WalletSettings",
    "NotificationSettings",
    "MakerSettings",
    "TakerSettings",
    "DirectoryServerSettings",
    "OrderbookWatcherSettings",
    "LoggingSettings",
    "get_settings",
    "reset_settings",
    "get_config_path",
    "generate_config_template",
    "ensure_config_file",
    "DEFAULT_DIRECTORY_SERVERS",
]
