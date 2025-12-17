"""
Tests for maker bot offer announcements with fidelity bond proofs.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest
from jmcore.models import NetworkType, Offer, OfferType

from maker.bot import MakerBot
from maker.config import MakerConfig
from maker.fidelity import FidelityBondInfo


class TestOfferAnnouncement:
    """Tests for _format_offer_announcement method."""

    @pytest.fixture
    def mock_wallet(self):
        """Create a mock wallet service."""
        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.utxo_cache = {}
        return wallet

    @pytest.fixture
    def mock_backend(self):
        """Create a mock blockchain backend."""
        return MagicMock()

    @pytest.fixture
    def config(self):
        """Create a test maker config."""
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
        )

    @pytest.fixture
    def maker_bot(self, mock_wallet, mock_backend, config):
        """Create a MakerBot instance for testing."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )
        return bot

    @pytest.fixture
    def sample_offer(self, maker_bot):
        """Create a sample offer for testing."""
        return Offer(
            counterparty=maker_bot.nick,
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.0003",
            fidelity_bond_value=0,
        )

    def test_format_offer_without_bond(self, maker_bot, sample_offer):
        """Test offer formatting without fidelity bond."""
        msg = maker_bot._format_offer_announcement(sample_offer)

        # Should not contain !tbond
        assert "!tbond" not in msg

        # Check format: <ordertype> <oid> <minsize> <maxsize> <txfee> <cjfee>
        parts = msg.split()
        assert parts[0] == "sw0reloffer"
        assert parts[1] == "0"  # oid
        assert parts[2] == "100000"  # minsize
        assert parts[3] == "10000000"  # maxsize
        assert parts[4] == "1000"  # txfee
        assert parts[5] == "0.0003"  # cjfee

    def test_format_offer_with_bond(self, maker_bot, sample_offer, test_private_key, test_pubkey):
        """Test offer formatting with fidelity bond attached."""
        # Set up fidelity bond
        maker_bot.fidelity_bond = FidelityBondInfo(
            txid="ab" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=1000,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )

        msg = maker_bot._format_offer_announcement(sample_offer)

        # Should contain !tbond
        assert "!tbond " in msg

        # Parse the message
        parts = msg.split("!tbond ")
        assert len(parts) == 2

        # Check offer part
        offer_parts = parts[0].split()
        assert offer_parts[0] == "sw0reloffer"

        # Check bond proof is valid base64 and 252 bytes when decoded
        bond_proof = parts[1].strip()
        decoded = base64.b64decode(bond_proof)
        assert len(decoded) == 252

    def test_format_absolute_offer_without_bond(self, maker_bot):
        """Test absolute offer formatting."""
        offer = Offer(
            counterparty=maker_bot.nick,
            oid=1,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=50_000,
            maxsize=5_000_000,
            txfee=500,
            cjfee="1000",  # Absolute fee in sats
            fidelity_bond_value=0,
        )

        msg = maker_bot._format_offer_announcement(offer)

        parts = msg.split()
        assert parts[0] == "sw0absoffer"
        assert parts[1] == "1"  # oid
        assert parts[5] == "1000"  # cjfee (absolute)

    def test_bond_proof_without_private_key_skipped(self, maker_bot, sample_offer, test_pubkey):
        """Test that bond proof is skipped if private key is missing."""
        # Set up fidelity bond without private key
        maker_bot.fidelity_bond = FidelityBondInfo(
            txid="cd" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=1000,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=None,  # Missing!
        )

        msg = maker_bot._format_offer_announcement(sample_offer)

        # Should not contain !tbond when signing fails
        assert "!tbond" not in msg

    def test_bond_proof_without_pubkey_skipped(self, maker_bot, sample_offer, test_private_key):
        """Test that bond proof is skipped if pubkey is missing."""
        # Set up fidelity bond without pubkey
        maker_bot.fidelity_bond = FidelityBondInfo(
            txid="ef" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=1000,
            bond_value=50_000,
            pubkey=None,  # Missing!
            private_key=test_private_key,
        )

        msg = maker_bot._format_offer_announcement(sample_offer)

        # Should not contain !tbond when signing fails
        assert "!tbond" not in msg


class TestBotInitialization:
    """Tests for MakerBot initialization."""

    @pytest.fixture
    def mock_wallet(self):
        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.utxo_cache = {}
        return wallet

    @pytest.fixture
    def mock_backend(self):
        return MagicMock()

    @pytest.fixture
    def config(self):
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
        )

    def test_bot_initializes_without_bond(self, mock_wallet, mock_backend, config):
        """Test that bot initializes with no fidelity bond."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )

        assert bot.fidelity_bond is None

    def test_bot_has_nick(self, mock_wallet, mock_backend, config):
        """Test that bot generates a nick."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )

        assert bot.nick is not None
        assert len(bot.nick) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
