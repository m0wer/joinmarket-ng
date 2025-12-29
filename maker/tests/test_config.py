"""
Tests for maker configuration validation.
"""

from pathlib import Path

import pytest
from jmcore.models import OfferType
from pydantic import ValidationError

from maker.config import MakerConfig, MergeAlgorithm, TorControlConfig

# Test mnemonic (BIP39 test vector)
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def test_valid_config() -> None:
    """Test that valid configuration is accepted."""
    config = MakerConfig(
        mnemonic=TEST_MNEMONIC,
        cj_fee_relative="0.001",
        offer_type=OfferType.SW0_RELATIVE,
    )
    assert config.cj_fee_relative == "0.001"


def test_zero_cj_fee_relative_fails() -> None:
    """Test that zero cj_fee_relative fails for relative offer types."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be > 0"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="0",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_negative_cj_fee_relative_fails() -> None:
    """Test that negative cj_fee_relative fails for relative offer types."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be > 0"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="-0.001",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_invalid_cj_fee_relative_string_fails() -> None:
    """Test that invalid string for cj_fee_relative fails."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be a valid number"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="not_a_number",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_zero_cj_fee_relative_ok_for_absolute_offers() -> None:
    """Test that zero cj_fee_relative is OK for absolute offer types."""
    config = MakerConfig(
        mnemonic=TEST_MNEMONIC,
        cj_fee_relative="0",
        offer_type=OfferType.SW0_ABSOLUTE,
        cj_fee_absolute=500,
    )
    assert config.cj_fee_relative == "0"
    assert config.offer_type == OfferType.SW0_ABSOLUTE


class TestTorControlConfig:
    """Tests for TorControlConfig."""

    def test_default_values(self) -> None:
        """Test default values are applied."""
        config = TorControlConfig()
        assert config.enabled is False
        assert config.host == "127.0.0.1"
        assert config.port == 9051
        assert config.cookie_path is None
        assert config.password is None

    def test_with_cookie_path(self, tmp_path: Path) -> None:
        """Test configuration with cookie path."""
        cookie_path = tmp_path / "control_auth_cookie"
        config = TorControlConfig(
            enabled=True,
            cookie_path=cookie_path,
        )
        assert config.enabled is True
        assert config.cookie_path == cookie_path

    def test_with_password(self) -> None:
        """Test configuration with password."""
        config = TorControlConfig(
            enabled=True,
            password="mysecret",
        )
        assert config.enabled is True
        assert config.password == "mysecret"


class TestMakerConfigTorControl:
    """Tests for MakerConfig tor_control integration."""

    def test_default_tor_control(self) -> None:
        """Test that tor_control defaults to disabled."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
        )
        assert config.tor_control.enabled is False

    def test_tor_control_enabled(self, tmp_path: Path) -> None:
        """Test enabling tor_control via nested config."""
        cookie_path = tmp_path / "control_auth_cookie"
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            tor_control=TorControlConfig(
                enabled=True,
                host="127.0.0.1",
                port=9051,
                cookie_path=cookie_path,
            ),
        )
        assert config.tor_control.enabled is True
        assert config.tor_control.port == 9051
        assert config.tor_control.cookie_path == cookie_path

    def test_tor_control_from_dict(self) -> None:
        """Test creating config from dict (JSON/YAML parsing)."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            tor_control={
                "enabled": True,
                "host": "tor",
                "port": 9051,
                "cookie_path": "/var/lib/tor/control_auth_cookie",
            },  # type: ignore[arg-type]
        )
        assert config.tor_control.enabled is True
        assert config.tor_control.host == "tor"
        assert config.tor_control.cookie_path == Path("/var/lib/tor/control_auth_cookie")


class TestMergeAlgorithm:
    """Tests for MergeAlgorithm configuration."""

    def test_default_merge_algorithm(self) -> None:
        """Test that default merge algorithm is 'default'."""
        config = MakerConfig(mnemonic=TEST_MNEMONIC)
        assert config.merge_algorithm == MergeAlgorithm.DEFAULT

    def test_set_merge_algorithm_gradual(self) -> None:
        """Test setting merge algorithm to gradual."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            merge_algorithm=MergeAlgorithm.GRADUAL,
        )
        assert config.merge_algorithm == MergeAlgorithm.GRADUAL

    def test_set_merge_algorithm_greedy(self) -> None:
        """Test setting merge algorithm to greedy."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            merge_algorithm=MergeAlgorithm.GREEDY,
        )
        assert config.merge_algorithm == MergeAlgorithm.GREEDY

    def test_set_merge_algorithm_random(self) -> None:
        """Test setting merge algorithm to random."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            merge_algorithm=MergeAlgorithm.RANDOM,
        )
        assert config.merge_algorithm == MergeAlgorithm.RANDOM

    def test_merge_algorithm_from_string(self) -> None:
        """Test creating config with string value (JSON/YAML parsing)."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            merge_algorithm="greedy",  # type: ignore[arg-type]
        )
        assert config.merge_algorithm == MergeAlgorithm.GREEDY

    def test_merge_algorithm_value(self) -> None:
        """Test accessing the string value of the enum."""
        config = MakerConfig(
            mnemonic=TEST_MNEMONIC,
            merge_algorithm=MergeAlgorithm.GRADUAL,
        )
        assert config.merge_algorithm.value == "gradual"

    def test_invalid_merge_algorithm(self) -> None:
        """Test that invalid merge algorithm raises error."""
        with pytest.raises(ValidationError):
            MakerConfig(
                mnemonic=TEST_MNEMONIC,
                merge_algorithm="invalid_algo",  # type: ignore[arg-type]
            )
