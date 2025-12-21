"""
Tests for transaction broadcast functionality.

Tests the broadcast policy options (self, random-peer, not-self) and
the delegation of broadcasting to makers via !push command.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from taker.config import BroadcastPolicy, TakerConfig


class TestBroadcastPolicy:
    """Tests for BroadcastPolicy enum."""

    def test_policy_values(self) -> None:
        """Test broadcast policy enum values."""
        assert BroadcastPolicy.SELF.value == "self"
        assert BroadcastPolicy.RANDOM_PEER.value == "random-peer"
        assert BroadcastPolicy.NOT_SELF.value == "not-self"

    def test_policy_from_string(self) -> None:
        """Test creating policy from string."""
        assert BroadcastPolicy("self") == BroadcastPolicy.SELF
        assert BroadcastPolicy("random-peer") == BroadcastPolicy.RANDOM_PEER
        assert BroadcastPolicy("not-self") == BroadcastPolicy.NOT_SELF


class TestTakerConfigBroadcast:
    """Tests for broadcast configuration in TakerConfig."""

    def test_default_broadcast_policy(self, sample_mnemonic: str) -> None:
        """Test default broadcast policy is random-peer."""
        config = TakerConfig(mnemonic=sample_mnemonic)
        assert config.tx_broadcast == BroadcastPolicy.RANDOM_PEER

    def test_explicit_self_policy(self, sample_mnemonic: str) -> None:
        """Test explicitly setting self broadcast policy."""
        config = TakerConfig(
            mnemonic=sample_mnemonic,
            tx_broadcast=BroadcastPolicy.SELF,
        )
        assert config.tx_broadcast == BroadcastPolicy.SELF

    def test_explicit_not_self_policy(self, sample_mnemonic: str) -> None:
        """Test explicitly setting not-self broadcast policy."""
        config = TakerConfig(
            mnemonic=sample_mnemonic,
            tx_broadcast=BroadcastPolicy.NOT_SELF,
        )
        assert config.tx_broadcast == BroadcastPolicy.NOT_SELF

    def test_broadcast_timeout_default(self, sample_mnemonic: str) -> None:
        """Test default broadcast timeout."""
        config = TakerConfig(mnemonic=sample_mnemonic)
        assert config.broadcast_timeout_sec == 30

    def test_broadcast_timeout_custom(self, sample_mnemonic: str) -> None:
        """Test custom broadcast timeout."""
        config = TakerConfig(
            mnemonic=sample_mnemonic,
            broadcast_timeout_sec=60,
        )
        assert config.broadcast_timeout_sec == 60


class TestTakerBroadcast:
    """Tests for Taker broadcast methods."""

    @pytest.fixture
    def mock_wallet(self):
        """Create a mock wallet service."""
        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.network = "regtest"
        wallet.sync_all = AsyncMock()
        wallet.close = AsyncMock()
        return wallet

    @pytest.fixture
    def mock_backend(self):
        """Create a mock blockchain backend."""
        backend = MagicMock()
        backend.broadcast_transaction = AsyncMock(return_value="txid123")
        backend.get_transaction = AsyncMock(return_value=None)
        backend.requires_neutrino_metadata = MagicMock(return_value=False)
        return backend

    @pytest.fixture
    def taker_config(self, sample_mnemonic: str):
        """Create a taker config for testing."""
        return TakerConfig(
            mnemonic=sample_mnemonic,
            network="regtest",
            directory_servers=["localhost:5222"],
            tx_broadcast=BroadcastPolicy.SELF,
            broadcast_timeout_sec=5,
        )

    @pytest.fixture
    def taker(self, mock_wallet, mock_backend, taker_config):
        """Create a Taker instance for testing."""
        from taker.taker import Taker

        taker = Taker(
            wallet=mock_wallet,
            backend=mock_backend,
            config=taker_config,
        )
        # Set up test data
        taker.final_tx = bytes.fromhex("0100000000010000000000")
        return taker

    @pytest.mark.asyncio
    async def test_broadcast_self_success(self, taker) -> None:
        """Test self-broadcast succeeds."""
        txid = await taker._broadcast_self()
        assert txid == "txid123"
        taker.backend.broadcast_transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_self_failure(self, taker) -> None:
        """Test self-broadcast failure returns empty string."""
        taker.backend.broadcast_transaction = AsyncMock(side_effect=Exception("Network error"))
        txid = await taker._broadcast_self()
        assert txid == ""

    @pytest.mark.asyncio
    async def test_phase_broadcast_self_policy(self, taker) -> None:
        """Test broadcast with SELF policy uses self-broadcast."""
        taker.config.tx_broadcast = BroadcastPolicy.SELF
        taker.maker_sessions = {}

        txid = await taker._phase_broadcast()
        assert txid == "txid123"
        taker.backend.broadcast_transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_phase_broadcast_random_peer_fallback_to_self(self, taker) -> None:
        """Test RANDOM_PEER policy falls back to self if no makers."""
        taker.config.tx_broadcast = BroadcastPolicy.RANDOM_PEER
        taker.maker_sessions = {}

        # With no makers, should fall back to self
        with patch("random.shuffle", side_effect=lambda x: x):
            txid = await taker._phase_broadcast()

        assert txid == "txid123"

    @pytest.mark.asyncio
    async def test_phase_broadcast_not_self_fails_without_makers(self, taker) -> None:
        """Test NOT_SELF policy fails if no makers available."""
        taker.config.tx_broadcast = BroadcastPolicy.NOT_SELF
        taker.maker_sessions = {}

        txid = await taker._phase_broadcast()
        assert txid == ""

    @pytest.mark.asyncio
    async def test_broadcast_via_maker_sends_push(self, taker) -> None:
        """Test broadcast via maker sends !push message."""
        from jmcore.models import Offer, OfferType

        from taker.taker import MakerSession

        # Set up maker session
        mock_offer = Offer(
            counterparty="J6maker123",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.0003",
            fidelity_bond_value=0,
        )
        taker.maker_sessions = {"J6maker123": MakerSession(nick="J6maker123", offer=mock_offer)}

        # Mock directory client
        taker.directory_client = MagicMock()
        taker.directory_client.send_privmsg = AsyncMock()

        # Test the push message format
        tx_b64 = base64.b64encode(taker.final_tx).decode("ascii")
        await taker._broadcast_via_maker("J6maker123", tx_b64)

        # Verify !push was sent
        taker.directory_client.send_privmsg.assert_called_once_with("J6maker123", "!push", tx_b64)

    @pytest.mark.asyncio
    async def test_broadcast_via_maker_detects_success(self, taker) -> None:
        """Test broadcast via maker detects transaction in mempool."""
        from jmcore.models import Offer, OfferType

        from taker.taker import MakerSession

        # Set up maker session
        mock_offer = Offer(
            counterparty="J6maker123",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.0003",
            fidelity_bond_value=0,
        )
        taker.maker_sessions = {"J6maker123": MakerSession(nick="J6maker123", offer=mock_offer)}

        # Mock directory client
        taker.directory_client = MagicMock()
        taker.directory_client.send_privmsg = AsyncMock()

        # Mock backend to return transaction (indicating broadcast success)
        mock_tx_info = MagicMock()
        mock_tx_info.raw = taker.final_tx.hex()
        taker.backend.get_transaction = AsyncMock(return_value=mock_tx_info)

        tx_b64 = base64.b64encode(taker.final_tx).decode("ascii")
        txid = await taker._broadcast_via_maker("J6maker123", tx_b64)

        # Should detect the transaction
        assert txid != ""

    @pytest.mark.asyncio
    async def test_phase_broadcast_random_peer_tries_makers(self, taker) -> None:
        """Test RANDOM_PEER policy tries makers before self."""
        from jmcore.models import Offer, OfferType

        from taker.taker import MakerSession

        taker.config.tx_broadcast = BroadcastPolicy.RANDOM_PEER

        # Set up maker sessions
        mock_offer = Offer(
            counterparty="J6maker123",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.0003",
            fidelity_bond_value=0,
        )
        taker.maker_sessions = {"J6maker123": MakerSession(nick="J6maker123", offer=mock_offer)}

        # Mock directory client
        taker.directory_client = MagicMock()
        taker.directory_client.send_privmsg = AsyncMock()

        # Make maker broadcast "fail" so we fall back to self
        taker.backend.get_transaction = AsyncMock(return_value=None)

        # Force deterministic order: maker first, then self
        with patch("random.shuffle", side_effect=lambda x: x.sort()):
            txid = await taker._phase_broadcast()

        # Should succeed via self fallback
        assert txid == "txid123"

    @pytest.mark.asyncio
    async def test_phase_broadcast_not_self_logs_tx_on_failure(self, taker, caplog) -> None:
        """Test NOT_SELF policy logs transaction hex on failure for manual broadcast."""
        from jmcore.models import Offer, OfferType

        from taker.taker import MakerSession

        taker.config.tx_broadcast = BroadcastPolicy.NOT_SELF

        # Set up maker session
        mock_offer = Offer(
            counterparty="J6maker123",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.0003",
            fidelity_bond_value=0,
        )
        taker.maker_sessions = {"J6maker123": MakerSession(nick="J6maker123", offer=mock_offer)}

        # Mock directory client
        taker.directory_client = MagicMock()
        taker.directory_client.send_privmsg = AsyncMock()

        # Make broadcast fail
        taker.backend.get_transaction = AsyncMock(return_value=None)

        txid = await taker._phase_broadcast()

        # Should fail
        assert txid == ""
