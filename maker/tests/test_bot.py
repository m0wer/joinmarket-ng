"""
Tests for maker bot offer announcements with fidelity bond proofs.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

import pytest
from jmcore.models import NetworkType, Offer, OfferType
from jmcore.network import TCPConnection

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
        """Test offer formatting with fidelity bond attached for PRIVMSG.

        Bonds should ONLY be included when include_bond=True (for PRIVMSG responses).
        Public broadcasts should never include bonds.
        """
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

        # Test 1: Public announcement should NOT include bond (default)
        msg_public = maker_bot._format_offer_announcement(sample_offer)
        assert "!tbond" not in msg_public, "Public announcements should not include bond"

        # Test 2: PRIVMSG should include bond when explicitly requested
        msg_privmsg = maker_bot._format_offer_announcement(sample_offer, include_bond=True)
        assert "!tbond " in msg_privmsg, "PRIVMSG should include bond when include_bond=True"

        # Parse the PRIVMSG message
        parts = msg_privmsg.split("!tbond ")
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

    def test_bot_initializes_without_hidden_service(self, mock_wallet, mock_backend, config):
        """Test that bot initializes without hidden service listener by default."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )

        assert bot.hidden_service_listener is None
        assert bot.direct_connections == {}

    def test_bot_config_with_onion_host(self, mock_wallet, mock_backend):
        """Test that bot can be configured with onion host."""
        config = MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            onion_host="test1234567890abcdef.onion",
            onion_serving_host="127.0.0.1",
            onion_serving_port=5222,
            socks_host="127.0.0.1",
            socks_port=9050,
        )

        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )

        # Hidden service listener is created during start(), not init
        assert bot.hidden_service_listener is None
        assert config.onion_host == "test1234567890abcdef.onion"
        assert config.onion_serving_port == 5222


class TestHiddenServiceListener:
    """Tests for hidden service listener functionality."""

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
    def config_with_onion(self):
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            onion_host="test1234567890abcdef.onion",
            onion_serving_host="127.0.0.1",
            onion_serving_port=0,  # Auto-assign port for tests
        )

    def test_direct_connection_tracking(self, mock_wallet, mock_backend, config_with_onion):
        """Test that direct connections are tracked by nick."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config_with_onion,
        )

        # Simulate adding a direct connection
        mock_conn = MagicMock(spec=TCPConnection)
        bot.direct_connections["J5test123"] = mock_conn

        assert "J5test123" in bot.direct_connections
        assert bot.direct_connections["J5test123"] == mock_conn

    @pytest.mark.asyncio
    async def test_on_direct_connection_invalid_json(
        self, mock_wallet, mock_backend, config_with_onion
    ):
        """Test that invalid JSON messages are handled gracefully."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config_with_onion,
        )
        bot.running = True

        # Create a mock connection that returns invalid JSON then disconnects
        mock_conn = MagicMock(spec=TCPConnection)
        mock_conn.is_connected.side_effect = [True, False]  # Connected once, then disconnect

        async def mock_receive() -> bytes:
            return b"not valid json"

        mock_conn.receive = mock_receive

        async def mock_close() -> None:
            pass

        mock_conn.close = mock_close

        # This should handle the invalid JSON gracefully
        await bot._on_direct_connection(mock_conn, "127.0.0.1:12345")

    @pytest.mark.asyncio
    async def test_on_direct_connection_fill_command(
        self, mock_wallet, mock_backend, config_with_onion
    ):
        """Test that direct connection fill command is routed correctly."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config_with_onion,
        )
        bot.running = True

        # Track if _handle_fill was called and verify connection tracking
        fill_called = False
        connection_was_tracked = False

        async def mock_handle_fill(taker_nick: str, msg: str) -> None:
            nonlocal fill_called, connection_was_tracked
            fill_called = True
            # At this point, the connection should be tracked
            connection_was_tracked = taker_nick in bot.direct_connections
            assert taker_nick == "J5taker123"
            assert "fill" in msg

        bot._handle_fill = mock_handle_fill

        # Create a mock connection that sends a fill command then disconnects
        fill_msg = json.dumps(
            {"nick": "J5taker123", "cmd": "fill", "data": "0 1000000 abc123 Pcommitment"}
        )

        async def mock_receive() -> bytes:
            return fill_msg.encode()

        async def mock_close() -> None:
            pass

        mock_conn = MagicMock(spec=TCPConnection)
        mock_conn.is_connected.side_effect = [True, False]
        mock_conn.receive = mock_receive
        mock_conn.close = mock_close

        await bot._on_direct_connection(mock_conn, "127.0.0.1:12345")

        assert fill_called, "_handle_fill should have been called"
        # Connection is tracked during processing but cleaned up on disconnect
        assert connection_was_tracked, "Connection should be tracked during message handling"
        # After cleanup, connection should be removed
        assert "J5taker123" not in bot.direct_connections, "Connection should be cleaned up"


class TestHandlePush:
    """Tests for _handle_push method."""

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
        from unittest.mock import AsyncMock

        backend = MagicMock()
        backend.broadcast_transaction = AsyncMock(return_value="txid123abc")
        backend.get_block_height = AsyncMock(return_value=930000)
        return backend

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

    @pytest.mark.asyncio
    async def test_handle_push_broadcasts_transaction(self, maker_bot):
        """Test that !push broadcasts the transaction."""
        import base64

        # Create a dummy transaction (minimal valid format)
        tx_bytes = bytes.fromhex("0100000000010000000000")
        tx_b64 = base64.b64encode(tx_bytes).decode("ascii")

        await maker_bot._handle_push("J5taker123", f"push {tx_b64}")

        # Verify broadcast was called with the decoded transaction
        maker_bot.backend.broadcast_transaction.assert_called_once_with(tx_bytes.hex())

    @pytest.mark.asyncio
    async def test_handle_push_invalid_format(self, maker_bot):
        """Test that invalid !push format is handled gracefully."""
        # Missing transaction data
        await maker_bot._handle_push("J5taker123", "push")

        # Should not call broadcast
        maker_bot.backend.broadcast_transaction.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_push_invalid_base64(self, maker_bot):
        """Test that invalid base64 is handled gracefully."""
        await maker_bot._handle_push("J5taker123", "push not_valid_base64!!!")

        # Should not call broadcast (decoding fails)
        maker_bot.backend.broadcast_transaction.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_push_broadcast_failure_logged(self, maker_bot, caplog):
        """Test that broadcast failure is logged but doesn't raise."""
        import base64
        from unittest.mock import AsyncMock

        # Make broadcast fail
        maker_bot.backend.broadcast_transaction = AsyncMock(side_effect=Exception("Network error"))

        tx_bytes = bytes.fromhex("0100000000010000000000")
        tx_b64 = base64.b64encode(tx_bytes).decode("ascii")

        # Should not raise
        await maker_bot._handle_push("J5taker123", f"push {tx_b64}")

        # Broadcast was attempted
        maker_bot.backend.broadcast_transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_push_via_privmsg(self, maker_bot):
        """Test that !push is routed correctly from privmsg."""
        import base64

        # Set up the bot with a mock _handle_push
        push_called = False

        async def mock_handle_push(taker_nick: str, msg: str) -> None:
            nonlocal push_called
            push_called = True
            assert taker_nick == "J5taker123"
            assert "push" in msg

        maker_bot._handle_push = mock_handle_push

        # Simulate a privmsg with !push
        tx_bytes = bytes.fromhex("0100000000010000000000")
        tx_b64 = base64.b64encode(tx_bytes).decode("ascii")
        line = f"J5taker123!{maker_bot.nick}!!push {tx_b64}"

        await maker_bot._handle_privmsg(line)

        assert push_called, "_handle_push should have been called"


class TestWalletRescanAndOfferUpdate:
    """Tests for wallet rescan and automatic offer update functionality."""

    @pytest.fixture
    def mock_wallet(self):
        """Create a mock wallet service."""
        from unittest.mock import AsyncMock

        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.utxo_cache = {}
        wallet.sync_all = AsyncMock()
        wallet.get_total_balance = AsyncMock(return_value=1_000_000)
        wallet.get_balance = AsyncMock(return_value=500_000)
        return wallet

    @pytest.fixture
    def mock_backend(self):
        """Create a mock blockchain backend."""
        from unittest.mock import AsyncMock

        backend = MagicMock()
        backend.can_provide_neutrino_metadata = MagicMock(return_value=True)
        backend.get_block_height = AsyncMock(return_value=930000)
        return backend

    @pytest.fixture
    def config(self):
        """Create a test maker config."""
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            post_coinjoin_rescan_delay=5,  # Minimum value for testing
            rescan_interval_sec=60,
        )

    @pytest.fixture
    def maker_bot(self, mock_wallet, mock_backend, config):
        """Create a MakerBot instance for testing."""
        bot = MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )
        # Set up current offers
        bot.current_offers = [
            Offer(
                counterparty=bot.nick,
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=100_000,
                maxsize=400_000,  # Initial maxsize
                txfee=1000,
                cjfee="0.001",
            )
        ]
        return bot

    @pytest.mark.asyncio
    async def test_resync_wallet_updates_offers_on_balance_change(self, maker_bot, mock_wallet):
        """Test that offers are updated when max balance changes."""
        from unittest.mock import AsyncMock

        # Set up balances: first return old balance, then new balance
        old_balance = 400_000
        new_balance = 600_000
        balance_calls = [old_balance] * 5 + [new_balance] * 5
        mock_wallet.get_balance = AsyncMock(side_effect=balance_calls)

        # Mock offer creation
        new_offer = Offer(
            counterparty=maker_bot.nick,
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=550_000,  # New maxsize after balance increase
            txfee=1000,
            cjfee="0.001",
        )
        maker_bot.offer_manager.create_offers = AsyncMock(return_value=[new_offer])
        maker_bot._announce_offers = AsyncMock()

        await maker_bot._resync_wallet_and_update_offers()

        # Wallet should have been synced
        mock_wallet.sync_all.assert_called_once()

        # Offers should have been updated (balance changed)
        maker_bot.offer_manager.create_offers.assert_called_once()
        maker_bot._announce_offers.assert_called_once()
        assert maker_bot.current_offers[0].maxsize == 550_000

    @pytest.mark.asyncio
    async def test_resync_wallet_no_update_when_balance_unchanged(self, maker_bot, mock_wallet):
        """Test that offers are not updated when balance doesn't change."""
        from unittest.mock import AsyncMock

        # Same balance before and after sync
        mock_wallet.get_balance = AsyncMock(return_value=400_000)

        maker_bot.offer_manager.create_offers = AsyncMock()
        maker_bot._announce_offers = AsyncMock()

        await maker_bot._resync_wallet_and_update_offers()

        # Wallet should have been synced
        mock_wallet.sync_all.assert_called_once()

        # Offers should NOT have been updated (balance unchanged)
        maker_bot.offer_manager.create_offers.assert_not_called()
        maker_bot._announce_offers.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_offers_keeps_old_if_create_fails(self, maker_bot):
        """Test that old offers are kept if new offer creation fails."""
        from unittest.mock import AsyncMock

        old_maxsize = maker_bot.current_offers[0].maxsize
        maker_bot.offer_manager.create_offers = AsyncMock(return_value=[])  # No offers created
        maker_bot._announce_offers = AsyncMock()

        await maker_bot._update_offers()

        # Old offers should be kept
        assert maker_bot.current_offers[0].maxsize == old_maxsize
        maker_bot._announce_offers.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_offers_skips_if_maxsize_unchanged(self, maker_bot):
        """Test that re-announcement is skipped if maxsize didn't change."""
        from unittest.mock import AsyncMock

        old_maxsize = maker_bot.current_offers[0].maxsize
        new_offer = Offer(
            counterparty=maker_bot.nick,
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=old_maxsize,  # Same maxsize
            txfee=1000,
            cjfee="0.001",
        )
        maker_bot.offer_manager.create_offers = AsyncMock(return_value=[new_offer])
        maker_bot._announce_offers = AsyncMock()

        await maker_bot._update_offers()

        # Announcement should be skipped (no change)
        maker_bot._announce_offers.assert_not_called()

    def test_config_has_rescan_settings(self, config):
        """Test that maker config includes rescan settings."""
        assert hasattr(config, "post_coinjoin_rescan_delay")
        assert hasattr(config, "rescan_interval_sec")
        assert config.post_coinjoin_rescan_delay == 5
        assert config.rescan_interval_sec == 60

    def test_config_default_rescan_values(self):
        """Test default values for rescan settings."""
        default_config = MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
        )
        assert default_config.post_coinjoin_rescan_delay == 60
        assert default_config.rescan_interval_sec == 600


class TestPeerCountDetection:
    """Tests for peer count detection after CoinJoin confirmation."""

    @pytest.fixture
    def mock_wallet(self):
        """Create a mock wallet service."""
        from unittest.mock import AsyncMock

        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.utxo_cache = {}
        wallet.sync_all = AsyncMock()
        wallet.get_total_balance = AsyncMock(return_value=1_000_000)
        return wallet

    @pytest.fixture
    def mock_backend(self):
        """Create a mock blockchain backend with transaction data."""
        from unittest.mock import AsyncMock

        from jmwallet.backends.base import Transaction

        backend = MagicMock()
        backend.get_block_height = AsyncMock(return_value=930000)

        # Mock transaction with 3 equal-value outputs (peer count = 3)
        mock_tx = Transaction(
            txid="test_txid_123",
            confirmations=1,
            raw="01000000...",  # Minimal mock
        )
        backend.get_transaction = AsyncMock(return_value=mock_tx)

        return backend

    @pytest.fixture
    def config(self, tmp_path):
        """Create a test maker config with temp data dir."""
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            data_dir=tmp_path,
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

    @pytest.mark.asyncio
    async def test_update_pending_history_calls_detection_function(
        self, maker_bot, mock_backend, config, tmp_path
    ):
        """Test that _update_pending_history uses update_transaction_confirmation_with_detection.

        This ensures that makers can automatically detect peer count after transaction
        confirmation, since they don't know the full transaction until it's broadcast.
        """
        from jmwallet.history import append_history_entry, create_maker_history_entry

        # Create a pending history entry
        entry = create_maker_history_entry(
            taker_nick="J5TakerNick",
            cj_amount=91554,
            fee_received=0,
            txfee_contribution=0,
            cj_address="bc1qtest",
            change_address="bc1qchange",
            our_utxos=[("abcd1234" * 8, 0)],
            txid="test_txid_123",
            network="regtest",
        )
        append_history_entry(entry, data_dir=tmp_path)

        # Mock the detection function to verify it's called
        from unittest.mock import AsyncMock, patch

        with patch("jmwallet.history.detect_coinjoin_peer_count", new=AsyncMock(return_value=3)):
            # Run the update
            await maker_bot._update_pending_history()

            # Read the history back
            from jmwallet.history import read_history

            entries = read_history(data_dir=tmp_path)
            assert len(entries) == 1

            # Transaction should be marked as confirmed
            assert entries[0].confirmations == 1
            assert entries[0].success is True

            # Peer count should be detected and set
            assert entries[0].peer_count == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
