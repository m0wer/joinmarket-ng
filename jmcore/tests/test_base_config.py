"""
Tests for jmcore configuration classes.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from jmcore.config import (
    BackendConfig,
    DirectoryServerConfig,
    TorConfig,
    TorControlConfig,
    WalletConfig,
)
from jmcore.models import NetworkType


class TestTorConfig:
    def test_default_values(self):
        config = TorConfig()
        assert config.socks_host == "127.0.0.1"
        assert config.socks_port == 9050

    def test_custom_values(self):
        config = TorConfig(socks_host="192.168.1.1", socks_port=9150)
        assert config.socks_host == "192.168.1.1"
        assert config.socks_port == 9150

    def test_invalid_port(self):
        with pytest.raises(ValidationError):
            TorConfig(socks_port=0)
        with pytest.raises(ValidationError):
            TorConfig(socks_port=70000)


class TestTorControlConfig:
    def test_default_values(self):
        config = TorControlConfig()
        assert config.enabled is True
        assert config.host == "127.0.0.1"
        assert config.port == 9051
        assert config.cookie_path is None
        assert config.password is None

    def test_cookie_auth(self):
        config = TorControlConfig(
            enabled=True,
            cookie_path=Path("/var/lib/tor/control_auth_cookie"),
        )
        assert config.enabled is True
        assert config.cookie_path == Path("/var/lib/tor/control_auth_cookie")
        assert config.password is None

    def test_password_auth(self):
        config = TorControlConfig(enabled=True, password="secret")
        assert config.enabled is True
        assert config.password == "secret"
        assert config.cookie_path is None


class TestBackendConfig:
    def test_default_values(self):
        config = BackendConfig()
        assert config.backend_type == "full_node"
        assert config.backend_config == {}

    def test_custom_config(self):
        backend_cfg = {
            "rpc_host": "localhost",
            "rpc_port": 18443,
            "rpc_user": "user",
            "rpc_password": "pass",
        }
        config = BackendConfig(backend_type="full_node", backend_config=backend_cfg)
        assert config.backend_type == "full_node"
        assert config.backend_config == backend_cfg


class TestWalletConfig:
    def test_minimal_config(self):
        config = WalletConfig(mnemonic="abandon " * 11 + "about")
        assert config.mnemonic == "abandon " * 11 + "about"
        assert config.network == NetworkType.MAINNET
        assert config.bitcoin_network == NetworkType.MAINNET  # Auto-set

    def test_network_defaults(self):
        """Test that bitcoin_network defaults to network if not specified."""
        config = WalletConfig(
            mnemonic="test " * 12,
            network=NetworkType.TESTNET,
        )
        assert config.network == NetworkType.TESTNET
        assert config.bitcoin_network == NetworkType.TESTNET

    def test_explicit_bitcoin_network(self):
        """Test setting bitcoin_network explicitly (e.g., regtest with testnet protocol)."""
        config = WalletConfig(
            mnemonic="test " * 12,
            network=NetworkType.TESTNET,
            bitcoin_network=NetworkType.REGTEST,
        )
        assert config.network == NetworkType.TESTNET
        assert config.bitcoin_network == NetworkType.REGTEST

    def test_full_config(self):
        config = WalletConfig(
            mnemonic="test " * 12,
            network=NetworkType.REGTEST,
            bitcoin_network=NetworkType.REGTEST,
            data_dir=Path("/tmp/jm"),
            backend_type="neutrino",
            backend_config={"peer": "localhost:18444"},
            directory_servers=["onion1:5222", "onion2:5222"],
            socks_host="127.0.0.1",
            socks_port=9050,
            mixdepth_count=5,
            gap_limit=20,
            dust_threshold=27300,
        )
        assert config.network == NetworkType.REGTEST
        assert config.bitcoin_network == NetworkType.REGTEST
        assert config.data_dir == Path("/tmp/jm")
        assert config.backend_type == "neutrino"
        assert len(config.directory_servers) == 2
        assert config.mixdepth_count == 5
        assert config.gap_limit == 20

    def test_mixdepth_count_bounds(self):
        # Valid range: 1-10
        config = WalletConfig(mnemonic="test " * 12, mixdepth_count=1)
        assert config.mixdepth_count == 1

        config = WalletConfig(mnemonic="test " * 12, mixdepth_count=10)
        assert config.mixdepth_count == 10

        # Invalid: < 1
        with pytest.raises(ValidationError):
            WalletConfig(mnemonic="test " * 12, mixdepth_count=0)

        # Invalid: > 10
        with pytest.raises(ValidationError):
            WalletConfig(mnemonic="test " * 12, mixdepth_count=11)

    def test_gap_limit_minimum(self):
        # Valid: >= 6
        config = WalletConfig(mnemonic="test " * 12, gap_limit=6)
        assert config.gap_limit == 6

        # Invalid: < 6
        with pytest.raises(ValidationError):
            WalletConfig(mnemonic="test " * 12, gap_limit=5)


class TestDirectoryServerConfig:
    def test_default_values(self):
        config = DirectoryServerConfig()
        assert config.network == NetworkType.MAINNET
        assert config.host == "127.0.0.1"
        assert config.port == 5222
        assert config.max_peers == 10000
        assert config.log_level == "INFO"

    def test_custom_values(self):
        config = DirectoryServerConfig(
            network=NetworkType.TESTNET,
            host="0.0.0.0",
            port=5223,
            max_peers=5000,
            message_rate_limit=50,
        )
        assert config.network == NetworkType.TESTNET
        assert config.host == "0.0.0.0"
        assert config.port == 5223
        assert config.max_peers == 5000
        assert config.message_rate_limit == 50

    def test_rate_limiting_config(self):
        config = DirectoryServerConfig(
            message_rate_limit=100,
            message_burst_limit=200,
            rate_limit_disconnect_threshold=50,
        )
        assert config.message_rate_limit == 100
        assert config.message_burst_limit == 200
        assert config.rate_limit_disconnect_threshold == 50


class TestWalletConfigInheritance:
    """Test that config classes can be properly inherited."""

    def test_can_inherit_wallet_config(self):
        """Test that WalletConfig can be inherited (like MakerConfig/TakerConfig do)."""

        class CustomConfig(WalletConfig):
            custom_field: str = "custom"

        config = CustomConfig(mnemonic="test " * 12)
        assert config.mnemonic == "test " * 12
        assert config.network == NetworkType.MAINNET
        assert config.custom_field == "custom"

    def test_inheritance_preserves_validation(self):
        """Test that inherited configs still run parent validation."""

        class CustomConfig(WalletConfig):
            custom_field: int = 42

        config = CustomConfig(
            mnemonic="test " * 12,
            network=NetworkType.TESTNET,
        )
        # bitcoin_network should be auto-set by parent validator
        assert config.bitcoin_network == NetworkType.TESTNET
