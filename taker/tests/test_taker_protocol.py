"""
Unit tests for Taker protocol handling.

Tests:
- NaCl encryption setup and message exchange
- PoDLE commitment generation and revelation
- Fill, Auth, TX phases
- Signature collection
- Multi-maker coordination
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, Mock

import pytest
from jmcore.encryption import CryptoSession
from jmcore.models import Offer, OfferType
from jmwallet.wallet.models import UTXOInfo

from taker.podle_manager import PoDLEManager
from taker.taker import MakerSession, Taker, TakerState


@pytest.fixture
def mock_wallet():
    """Mock wallet service."""
    wallet = AsyncMock()
    wallet.mixdepth_count = 5
    wallet.sync_all = AsyncMock()
    wallet.get_total_balance = AsyncMock(return_value=100_000_000)
    wallet.get_balance = AsyncMock(return_value=50_000_000)
    wallet.get_utxos = AsyncMock(
        return_value=[
            UTXOInfo(
                txid="a" * 64,
                vout=0,
                value=25_000_000,
                address="bcrt1qtest1",
                confirmations=10,
                scriptpubkey="001400" * 10,
                path="m/84'/1'/0'/0/0",
                mixdepth=0,
            ),
            UTXOInfo(
                txid="b" * 64,
                vout=0,
                value=25_000_000,
                address="bcrt1qtest2",
                confirmations=10,
                scriptpubkey="001400" * 10,
                path="m/84'/1'/0'/0/1",
                mixdepth=0,
            ),
        ]
    )
    wallet.get_next_address_index = Mock(return_value=0)
    wallet.get_receive_address = Mock(return_value="bcrt1qdest")
    wallet.get_change_address = Mock(return_value="bcrt1qchange")
    wallet.get_key_for_address = Mock()
    wallet.select_utxos = Mock(
        return_value=[
            UTXOInfo(
                txid="a" * 64,
                vout=0,
                value=25_000_000,
                address="bcrt1qtest1",
                confirmations=10,
                scriptpubkey="001400" * 10,
                path="m/84'/1'/0'/0/0",
                mixdepth=0,
            )
        ]
    )
    wallet.close = AsyncMock()
    return wallet


@pytest.fixture
def mock_backend():
    """Mock blockchain backend."""
    backend = AsyncMock()
    backend.get_utxo = AsyncMock(
        return_value=UTXOInfo(
            txid="c" * 64,
            vout=0,
            value=10_000_000,
            address="bcrt1qmaker",
            confirmations=10,
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/0",
            mixdepth=0,
        )
    )
    backend.get_transaction = AsyncMock()
    backend.broadcast_transaction = AsyncMock(return_value="txid123")
    # can_provide_neutrino_metadata is a synchronous method, not async
    backend.can_provide_neutrino_metadata = Mock(return_value=True)
    return backend


@pytest.fixture
def mock_config():
    """Mock taker config."""
    from jmcore.models import NetworkType

    from taker.config import TakerConfig

    config = TakerConfig(
        mnemonic="abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about",
        network=NetworkType.REGTEST,
        directory_servers=["localhost:5222"],
        counterparty_count=2,
        minimum_makers=2,
        taker_utxo_age=1,
        taker_utxo_amtpercent=20,
        tx_fee_factor=1.0,
        maker_timeout_sec=30.0,
        order_wait_time=10.0,
    )
    return config


@pytest.fixture
def sample_offer():
    """Sample maker offer."""
    return Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=100_000_000,
        txfee=500,
        cjfee=250,  # 0.00025 relative
        counterparty="J5TestMaker",
    )


@pytest.fixture
def sample_offer2():
    """Second sample maker offer."""
    return Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=1,
        minsize=10000,
        maxsize=100_000_000,
        txfee=500,
        cjfee=300,  # 0.0003 relative
        counterparty="J5TestMaker2",
    )


@pytest.mark.asyncio
async def test_taker_initialization(mock_wallet, mock_backend, mock_config):
    """Test taker initialization."""
    taker = Taker(mock_wallet, mock_backend, mock_config)

    assert taker.wallet == mock_wallet
    assert taker.backend == mock_backend
    assert taker.config == mock_config
    assert taker.state == TakerState.IDLE
    # v5 nicks for reference implementation compatibility
    assert taker.nick.startswith("J5")
    assert len(taker.maker_sessions) == 0


@pytest.mark.asyncio
async def test_encryption_session_setup():
    """Test NaCl encryption session setup between taker and maker."""
    # Taker creates a crypto session
    taker_crypto = CryptoSession()
    taker_pubkey = taker_crypto.get_pubkey_hex()

    # Maker creates a crypto session and sends their pubkey
    maker_crypto = CryptoSession()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    # Taker sets up encryption with maker's pubkey
    taker_crypto.setup_encryption(maker_pubkey)

    # Maker sets up encryption with taker's pubkey
    maker_crypto.setup_encryption(taker_pubkey)

    # Test encryption/decryption
    plaintext = "test message"
    encrypted = taker_crypto.encrypt(plaintext)
    assert encrypted != plaintext

    # Maker decrypts
    decrypted = maker_crypto.decrypt(encrypted)
    assert decrypted == plaintext

    # Test reverse direction
    plaintext2 = "response message"
    encrypted2 = maker_crypto.encrypt(plaintext2)
    decrypted2 = taker_crypto.decrypt(encrypted2)
    assert decrypted2 == plaintext2


@pytest.mark.asyncio
async def test_podle_generation(mock_wallet, tmp_path):
    """Test PoDLE commitment generation using PoDLEManager."""
    # Create sample UTXOs
    utxos = [
        UTXOInfo(
            txid="a" * 64,
            vout=0,
            value=25_000_000,
            address="bcrt1qtest1",
            confirmations=10,
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/0",
            mixdepth=0,
        ),
        UTXOInfo(
            txid="b" * 64,
            vout=1,
            value=30_000_000,
            address="bcrt1qtest2",
            confirmations=10,
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/1",
            mixdepth=0,
        ),
    ]

    # Mock private key getter
    def get_private_key(addr: str) -> bytes | None:
        # Return a dummy private key
        return b"\x01" * 32

    # Use PoDLEManager with temporary data directory
    manager = PoDLEManager(data_dir=tmp_path)

    # Generate PoDLE commitment
    commitment = manager.generate_fresh_commitment(
        wallet_utxos=utxos,
        cj_amount=10_000_000,
        private_key_getter=get_private_key,
        min_confirmations=1,
        min_percent=20,
    )

    assert commitment is not None
    assert commitment.p is not None
    assert commitment.p2 is not None
    assert commitment.sig is not None
    assert commitment.e is not None
    assert len(commitment.utxo) > 0

    # Test commitment serialization
    # Format: 'P' + 64 hex chars = 65 chars (P prefix for standard PoDLE)
    commitment_str = commitment.to_commitment_str()
    assert len(commitment_str) == 65  # 'P' + 32 bytes in hex
    assert commitment_str.startswith("P")

    # Test revelation serialization
    revelation = commitment.to_revelation()
    assert "utxo" in revelation
    assert "P" in revelation
    assert "P2" in revelation
    assert "sig" in revelation
    assert "e" in revelation

    # Verify commitment was tracked
    assert len(manager.used_commitments) == 1
    assert commitment.to_commitment_str()[1:] in manager.used_commitments  # Strip 'P' prefix


@pytest.mark.asyncio
async def test_podle_retry_limit(mock_wallet, tmp_path):
    """Test that PoDLE respects max_retries limit."""
    # Create a single UTXO
    utxos = [
        UTXOInfo(
            txid="a" * 64,
            vout=0,
            value=25_000_000,
            address="bcrt1qtest1",
            confirmations=10,
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/0",
            mixdepth=0,
        ),
    ]

    def get_private_key(addr: str) -> bytes | None:
        return b"\x01" * 32

    from taker.podle_manager import PoDLEManager

    manager = PoDLEManager(data_dir=tmp_path)

    # Generate 3 commitments with max_retries=3 (indices 0,1,2)
    for i in range(3):
        commitment = manager.generate_fresh_commitment(
            wallet_utxos=utxos,
            cj_amount=10_000_000,
            private_key_getter=get_private_key,
            min_confirmations=1,
            min_percent=20,
            max_retries=3,
        )
        assert commitment is not None
        assert commitment.index == i

    # 4th attempt should fail - UTXO exhausted
    commitment = manager.generate_fresh_commitment(
        wallet_utxos=utxos,
        cj_amount=10_000_000,
        private_key_getter=get_private_key,
        min_confirmations=1,
        min_percent=20,
        max_retries=3,
    )
    assert commitment is None  # No fresh commitment available


@pytest.mark.asyncio
async def test_podle_utxo_deprioritization(mock_wallet, tmp_path):
    """Test that fresh UTXOs are naturally preferred via lazy evaluation.

    The implementation uses lazy evaluation: it tries UTXOs in order (sorted by
    confirmations/value) and for each UTXO tries indices 0..max_retries-1 until
    finding an unused commitment. Fresh UTXOs succeed faster (at index 0).
    """
    # Create two UTXOs: UTXO_B has more confirmations, so it's tried first
    utxos = [
        UTXOInfo(
            txid="a" * 64,
            vout=0,
            value=25_000_000,
            address="bcrt1qtest1",
            confirmations=10,
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/0",
            mixdepth=0,
        ),
        UTXOInfo(
            txid="b" * 64,
            vout=1,
            value=25_000_000,
            address="bcrt1qtest2",
            confirmations=20,  # Higher confirmations = tried first
            scriptpubkey="001400" * 10,
            path="m/84'/1'/0'/0/1",
            mixdepth=0,
        ),
    ]

    # Use different private keys for different addresses
    def get_private_key(addr: str) -> bytes | None:
        if addr == "bcrt1qtest1":
            return b"\x01" * 32
        elif addr == "bcrt1qtest2":
            return b"\x02" * 32
        return None

    from taker.podle_manager import PoDLEManager

    manager = PoDLEManager(data_dir=tmp_path)

    # Use UTXO_B twice (indices 0, 1) - higher confirmations means tried first
    for _ in range(2):
        commitment = manager.generate_fresh_commitment(
            wallet_utxos=[utxos[1]],  # Only UTXO_B (higher confs)
            cj_amount=10_000_000,
            private_key_getter=get_private_key,
            min_confirmations=1,
            min_percent=20,
            max_retries=3,
        )
        assert commitment is not None
        assert commitment.utxo.startswith("bbbb")

    # Now with both UTXOs, UTXO_B is still tried first (higher confs)
    # But indices 0,1 are used, so it will use index 2
    commitment = manager.generate_fresh_commitment(
        wallet_utxos=utxos,  # Both UTXOs
        cj_amount=10_000_000,
        private_key_getter=get_private_key,
        min_confirmations=1,
        min_percent=20,
        max_retries=3,
    )
    assert commitment is not None
    # UTXO_B should still be selected (higher confirmations, uses index 2)
    assert commitment.utxo.startswith("bbbb")
    assert commitment.index == 2


@pytest.mark.asyncio
async def test_fill_phase_encryption():
    """Test !fill phase with encryption setup."""
    # Simulate taker sending !fill with pubkey
    taker_crypto = CryptoSession()
    taker_pubkey = taker_crypto.get_pubkey_hex()

    # Taker builds fill message

    # Maker receives fill and creates crypto session
    maker_crypto = CryptoSession()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    # Maker sets up encryption with taker's pubkey
    maker_crypto.setup_encryption(taker_pubkey)

    # Taker receives !pubkey response and sets up encryption
    taker_crypto.setup_encryption(maker_pubkey)

    # Now both can communicate securely
    test_msg = "encrypted test"
    encrypted = taker_crypto.encrypt(test_msg)
    decrypted = maker_crypto.decrypt(encrypted)
    assert decrypted == test_msg


@pytest.mark.asyncio
async def test_auth_phase_encryption():
    """Test !auth phase with encrypted revelation."""
    # Setup encryption (from fill phase)
    taker_crypto = CryptoSession()
    maker_crypto = CryptoSession()

    taker_pubkey = taker_crypto.get_pubkey_hex()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    taker_crypto.setup_encryption(maker_pubkey)
    maker_crypto.setup_encryption(taker_pubkey)

    # Taker creates revelation and encrypts it
    revelation_str = "txid:vout|P_hex|P2_hex|sig_hex|e_hex"
    encrypted_revelation = taker_crypto.encrypt(revelation_str)

    # Maker receives and decrypts
    decrypted_revelation = maker_crypto.decrypt(encrypted_revelation)
    assert decrypted_revelation == revelation_str

    # Maker creates ioauth response
    ioauth_data = "txid1:0,txid2:1 auth_pub cj_addr change_addr btc_sig"
    encrypted_ioauth = maker_crypto.encrypt(ioauth_data)

    # Taker decrypts ioauth
    decrypted_ioauth = taker_crypto.decrypt(encrypted_ioauth)
    assert decrypted_ioauth == ioauth_data


@pytest.mark.asyncio
async def test_tx_phase_encryption():
    """Test !tx phase with encrypted transaction."""
    # Setup encryption
    taker_crypto = CryptoSession()
    maker_crypto = CryptoSession()

    taker_pubkey = taker_crypto.get_pubkey_hex()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    taker_crypto.setup_encryption(maker_pubkey)
    maker_crypto.setup_encryption(taker_pubkey)

    # Taker encodes and encrypts transaction
    tx_bytes = b"\x01\x00\x00\x00" * 10  # Dummy transaction
    tx_b64 = base64.b64encode(tx_bytes).decode("ascii")
    encrypted_tx = taker_crypto.encrypt(tx_b64)

    # Maker decrypts and decodes
    decrypted_tx_b64 = maker_crypto.decrypt(encrypted_tx)
    decoded_tx = base64.b64decode(decrypted_tx_b64)
    assert decoded_tx == tx_bytes

    # Maker creates signature
    sig_bytes = b"\x30\x44" + b"\x00" * 70  # Dummy DER signature
    pub_bytes = b"\x02" + b"\x00" * 33  # Dummy compressed pubkey

    # Encode signature: varint(sig_len) + sig + varint(pub_len) + pub
    sig_len = len(sig_bytes)
    pub_len = len(pub_bytes)
    sig_data = bytes([sig_len]) + sig_bytes + bytes([pub_len]) + pub_bytes
    sig_b64 = base64.b64encode(sig_data).decode("ascii")

    # Encrypt signature
    encrypted_sig = maker_crypto.encrypt(sig_b64)

    # Taker decrypts
    decrypted_sig_b64 = taker_crypto.decrypt(encrypted_sig)
    assert decrypted_sig_b64 == sig_b64


@pytest.mark.asyncio
async def test_maker_session_tracking():
    """Test tracking multiple maker sessions."""
    offer1 = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=100_000_000,
        txfee=500,
        cjfee=250,
        counterparty="J5Maker1",
    )

    offer2 = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=1,
        minsize=10000,
        maxsize=100_000_000,
        txfee=500,
        cjfee=300,
        counterparty="J5Maker2",
    )

    # Create sessions
    session1 = MakerSession(nick="J5Maker1", offer=offer1)
    session2 = MakerSession(nick="J5Maker2", offer=offer2)

    # Simulate fill phase responses
    session1.pubkey = "aabb" * 16
    session1.responded_fill = True

    session2.pubkey = "ccdd" * 16
    session2.responded_fill = True

    # Simulate auth phase responses
    session1.utxos = [{"txid": "tx1", "vout": 0, "value": 10000000, "address": "addr1"}]
    session1.cj_address = "bcrt1qmaker1cj"
    session1.change_address = "bcrt1qmaker1change"
    session1.responded_auth = True

    session2.utxos = [{"txid": "tx2", "vout": 0, "value": 10000000, "address": "addr2"}]
    session2.cj_address = "bcrt1qmaker2cj"
    session2.change_address = "bcrt1qmaker2change"
    session2.responded_auth = True

    # Verify session state
    assert session1.responded_fill
    assert session1.responded_auth
    assert len(session1.utxos) == 1

    assert session2.responded_fill
    assert session2.responded_auth
    assert len(session2.utxos) == 1


@pytest.mark.asyncio
async def test_message_encryption_roundtrip():
    """Test complete message encryption/decryption roundtrip."""
    # Simulate taker-maker communication
    sessions = {}

    # Maker 1
    taker_crypto1 = CryptoSession()
    maker_crypto1 = CryptoSession()
    taker_crypto1.setup_encryption(maker_crypto1.get_pubkey_hex())
    maker_crypto1.setup_encryption(taker_crypto1.get_pubkey_hex())
    sessions["maker1"] = (taker_crypto1, maker_crypto1)

    # Maker 2
    taker_crypto2 = CryptoSession()
    maker_crypto2 = CryptoSession()
    taker_crypto2.setup_encryption(maker_crypto2.get_pubkey_hex())
    maker_crypto2.setup_encryption(taker_crypto2.get_pubkey_hex())
    sessions["maker2"] = (taker_crypto2, maker_crypto2)

    # Test auth messages to both makers
    revelation = "utxo|P|P2|sig|e"

    for maker_id, (taker_crypto, maker_crypto) in sessions.items():
        # Taker encrypts and sends
        encrypted = taker_crypto.encrypt(revelation)

        # Maker decrypts
        decrypted = maker_crypto.decrypt(encrypted)
        assert decrypted == revelation

        # Maker responds with ioauth
        ioauth = f"{maker_id}_utxo:0 pubkey cj_addr change_addr sig"
        encrypted_ioauth = maker_crypto.encrypt(ioauth)

        # Taker decrypts
        decrypted_ioauth = taker_crypto.decrypt(encrypted_ioauth)
        assert decrypted_ioauth == ioauth


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# --- Tests for PhaseResult and Maker Replacement Logic ---


class TestPhaseResult:
    """Tests for PhaseResult dataclass."""

    def test_phase_result_success(self):
        """Test successful phase result."""
        from taker.taker import PhaseResult

        result = PhaseResult(success=True)
        assert result.success
        assert result.failed_makers == []
        assert not result.blacklist_error
        assert not result.needs_replacement

    def test_phase_result_failure_with_failed_makers(self):
        """Test failed phase result with failed makers."""
        from taker.taker import PhaseResult

        result = PhaseResult(
            success=False, failed_makers=["maker1", "maker2"], blacklist_error=False
        )
        assert not result.success
        assert result.failed_makers == ["maker1", "maker2"]
        assert not result.blacklist_error
        assert result.needs_replacement  # Has failed makers, so needs replacement

    def test_phase_result_blacklist_error(self):
        """Test phase result with blacklist error."""
        from taker.taker import PhaseResult

        result = PhaseResult(success=False, failed_makers=["maker1"], blacklist_error=True)
        assert not result.success
        assert result.blacklist_error
        assert result.needs_replacement

    def test_phase_result_success_with_some_failures(self):
        """Test successful phase even with some failed makers (but enough remaining)."""
        from taker.taker import PhaseResult

        # Success can have failed makers if enough responded
        result = PhaseResult(success=True, failed_makers=["maker1"])
        assert result.success
        assert result.failed_makers == ["maker1"]
        # Even though we have failed makers, we don't need replacement since we succeeded
        assert not result.needs_replacement


class TestMakerReplacementConfig:
    """Tests for maker replacement configuration."""

    def test_max_maker_replacement_default(self):
        """Test default max_maker_replacement_attempts value."""
        from jmcore.models import NetworkType

        from taker.config import TakerConfig

        config = TakerConfig(
            mnemonic="abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            network=NetworkType.REGTEST,
            directory_servers=["localhost:5222"],
        )
        assert config.max_maker_replacement_attempts == 3

    def test_max_maker_replacement_custom(self):
        """Test custom max_maker_replacement_attempts value."""
        from jmcore.models import NetworkType

        from taker.config import TakerConfig

        config = TakerConfig(
            mnemonic="abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            network=NetworkType.REGTEST,
            directory_servers=["localhost:5222"],
            max_maker_replacement_attempts=5,
        )
        assert config.max_maker_replacement_attempts == 5

    def test_max_maker_replacement_disabled(self):
        """Test disabled maker replacement (set to 0)."""
        from jmcore.models import NetworkType

        from taker.config import TakerConfig

        config = TakerConfig(
            mnemonic="abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            network=NetworkType.REGTEST,
            directory_servers=["localhost:5222"],
            max_maker_replacement_attempts=0,
        )
        assert config.max_maker_replacement_attempts == 0

    def test_max_maker_replacement_bounds(self):
        """Test max_maker_replacement_attempts bounds validation."""
        from jmcore.models import NetworkType

        from taker.config import TakerConfig

        # Should accept max value of 10
        config = TakerConfig(
            mnemonic="abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            network=NetworkType.REGTEST,
            directory_servers=["localhost:5222"],
            max_maker_replacement_attempts=10,
        )
        assert config.max_maker_replacement_attempts == 10

        # Should reject value > 10
        import pytest

        with pytest.raises(ValueError):
            TakerConfig(
                mnemonic="abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about",
                network=NetworkType.REGTEST,
                directory_servers=["localhost:5222"],
                max_maker_replacement_attempts=11,
            )


# --- Tests for MultiDirectoryClient Direct Peer Connections ---


class TestMultiDirectoryClientDirectConnections:
    """Tests for MultiDirectoryClient direct peer connection feature."""

    def test_direct_connections_enabled_by_default(self):
        """Test that direct connections are enabled by default."""
        from jmcore.crypto import NickIdentity

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
        )

        assert client.prefer_direct_connections is True
        assert client.our_location == "NOT-SERVING-ONION"
        assert client._peer_connections == {}

    def test_direct_connections_can_be_disabled(self):
        """Test that direct connections can be disabled."""
        from jmcore.crypto import NickIdentity

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
            prefer_direct_connections=False,
        )

        assert client.prefer_direct_connections is False

    def test_get_peer_location_returns_none_when_not_found(self):
        """Test _get_peer_location returns None for unknown nicks."""
        from jmcore.crypto import NickIdentity

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
        )

        location = client._get_peer_location("J5unknown")
        assert location is None

    def test_should_try_direct_connect_disabled(self):
        """Test _should_try_direct_connect returns False when disabled."""
        from jmcore.crypto import NickIdentity

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
            prefer_direct_connections=False,
        )

        assert not client._should_try_direct_connect("J5maker")

    def test_get_connected_peer_returns_none_when_not_connected(self):
        """Test _get_connected_peer returns None when no connection exists."""
        from jmcore.crypto import NickIdentity

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
        )

        peer = client._get_connected_peer("J5maker")
        assert peer is None

    @pytest.mark.asyncio
    async def test_cleanup_peer_connections(self):
        """Test that peer connections are cleaned up on close."""
        from unittest.mock import AsyncMock

        from jmcore.crypto import NickIdentity
        from jmcore.network import OnionPeer

        from taker.taker import MultiDirectoryClient

        nick_identity = NickIdentity(5)
        client = MultiDirectoryClient(
            directory_servers=["localhost:5222"],
            network="regtest",
            nick_identity=nick_identity,
        )

        # Add a mock peer
        mock_peer = Mock(spec=OnionPeer)
        mock_peer.disconnect = AsyncMock()
        client._peer_connections["J5maker"] = mock_peer

        # Cleanup
        await client._cleanup_peer_connections()

        mock_peer.disconnect.assert_called_once()
        assert client._peer_connections == {}


# --- Tests for Sweep Mode CJ Amount Preservation ---


class TestSweepCjAmountPreservation:
    """Tests for sweep mode cj_amount preservation.

    This tests a critical bug fix: in sweep mode, the cj_amount sent in the
    !fill message must be preserved in _phase_build_tx. If we recalculate
    cj_amount when actual maker inputs differ from our estimate, the maker
    will reject the transaction with "wrong change" because they calculate
    their expected change based on the original cj_amount from !fill.

    See: https://github.com/JoinMarket-Org/joinmarket-clientserver maker.py
    verify_unsigned_tx() - maker calculates expected_change based on the
    amount from !fill, not a recalculated amount.
    """

    @pytest.fixture
    def mock_wallet_for_sweep(self):
        """Mock wallet service configured for sweep mode."""
        wallet = AsyncMock()
        wallet.mixdepth_count = 5
        wallet.sync_all = AsyncMock()
        wallet.get_total_balance = AsyncMock(return_value=100_000_000)
        wallet.get_balance = AsyncMock(return_value=50_000_000)

        # Two UTXOs for sweep (147,483 sats total, matching the bug report)
        sweep_utxos = [
            UTXOInfo(
                txid="1111111111111111111111111111111111111111111111111111111111111111",
                vout=2,
                value=68_874,
                address="bcrt1qtest1",
                confirmations=1244,
                scriptpubkey="0014" + "00" * 20,
                path="m/84'/1'/0'/0/0",
                mixdepth=3,
            ),
            UTXOInfo(
                txid="2222222222222222222222222222222222222222222222222222222222222222",
                vout=15,
                value=78_609,
                address="bcrt1qtest2",
                confirmations=1000,
                scriptpubkey="0014" + "00" * 20,
                path="m/84'/1'/0'/0/1",
                mixdepth=3,
            ),
        ]
        wallet.get_utxos = AsyncMock(return_value=sweep_utxos)
        wallet.get_all_utxos = Mock(return_value=sweep_utxos)
        wallet.get_next_address_index = Mock(return_value=0)
        wallet.get_receive_address = Mock(return_value="bcrt1qdest")
        wallet.get_change_address = Mock(return_value="bcrt1qchange")
        wallet.get_key_for_address = Mock()
        wallet.select_utxos = Mock(return_value=sweep_utxos)
        wallet.close = AsyncMock()
        return wallet

    @pytest.fixture
    def mock_backend_for_sweep(self):
        """Mock blockchain backend."""
        backend = AsyncMock()
        # Maker's UTXO
        backend.get_utxo = AsyncMock(
            return_value=UTXOInfo(
                txid="3333333333333333333333333333333333333333333333333333333333333333",
                vout=18,
                value=467_555,
                address="bcrt1qmaker",
                confirmations=100,
                scriptpubkey="0014" + "00" * 20,
                path="m/84'/1'/0'/0/0",
                mixdepth=0,
            )
        )
        backend.get_transaction = AsyncMock()
        backend.broadcast_transaction = AsyncMock(return_value="txid123")
        backend.can_provide_neutrino_metadata = Mock(return_value=False)
        backend.requires_neutrino_metadata = Mock(return_value=False)
        return backend

    @pytest.fixture
    def taker_config_for_sweep(self):
        """Taker config for sweep mode test."""
        from jmcore.models import NetworkType

        from taker.config import TakerConfig

        return TakerConfig(
            mnemonic="abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about",
            network=NetworkType.REGTEST,
            directory_servers=["localhost:5222"],
            counterparty_count=1,
            minimum_makers=1,
            taker_utxo_age=1,
            taker_utxo_amtpercent=20,
            tx_fee_factor=1.0,
            maker_timeout_sec=30.0,
            order_wait_time=10.0,
            fee_rate=1.0,  # 1 sat/vB
        )

    @pytest.mark.asyncio
    async def test_sweep_preserves_cj_amount_from_fill(
        self, mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep
    ):
        """Test that sweep mode preserves cj_amount from !fill message.

        This is the exact scenario from the bug report:
        - Taker estimates 2 maker inputs per maker during initial calculation
        - Maker actually has 1 input
        - Without the fix, taker would recalculate cj_amount with lower tx_fee
        - This causes maker to reject tx with "wrong change"

        The fix ensures cj_amount is NOT recalculated in _phase_build_tx.
        """
        taker = Taker(mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep)

        # Simulate sweep mode setup
        taker.is_sweep = True
        taker.preselected_utxos = mock_wallet_for_sweep.get_all_utxos()

        # Initial cj_amount calculated during do_coinjoin (before !fill)
        # This is the amount that will be sent to makers in !fill
        initial_cj_amount = 146_339  # From the bug report

        taker.cj_amount = initial_cj_amount

        # Set up a mock maker session with offer
        maker_offer = Offer(
            ordertype=OfferType.SW0_ABSOLUTE,  # Absolute fee = 0
            oid=0,
            minsize=10000,
            maxsize=1_000_000_000,
            txfee=500,  # Maker contributes 500 sats to tx fee
            cjfee=0,  # Zero fee
            counterparty="J55Jha4vGPR5fTFv",
        )

        # Simulate !ioauth response - maker has only 1 input (not 2 as estimated)
        maker_session = MakerSession(nick="J55Jha4vGPR5fTFv", offer=maker_offer)
        maker_session.pubkey = "e131e3bb667eb124" + "00" * 24
        maker_session.responded_fill = True
        maker_session.responded_auth = True
        # Maker has 1 UTXO (we estimated 2)
        maker_session.utxos = [
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 18,
                "value": 467_555,
                "address": "bcrt1qmaker",
            }
        ]
        maker_session.cj_address = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
        maker_session.change_address = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa"
        maker_session.crypto = CryptoSession()

        taker.maker_sessions = {"J55Jha4vGPR5fTFv": maker_session}

        # Set fee rate (must be done before _phase_build_tx)
        taker._fee_rate = 1.0

        # Call _phase_build_tx - this is where the bug occurred
        result = await taker._phase_build_tx(
            destination="bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu",
            mixdepth=3,
        )

        # The transaction should build successfully
        assert result is True

        # CRITICAL: cj_amount must NOT have changed
        # Before the fix, it would be recalculated to a different value
        assert taker.cj_amount == initial_cj_amount, (
            f"cj_amount was modified from {initial_cj_amount} to {taker.cj_amount}. "
            "This would cause maker to reject tx with 'wrong change'!"
        )

    @pytest.mark.asyncio
    async def test_sweep_handles_tx_fee_difference_as_residual(
        self, mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep
    ):
        """Test that tx_fee difference becomes residual (extra miner fee), not cj_amount change.

        When actual maker inputs differ from estimate:
        - Old behavior: recalculate cj_amount -> maker rejects with "wrong change"
        - New behavior: keep cj_amount, excess becomes additional miner fee (residual)
        """
        taker = Taker(mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep)

        # Simulate sweep mode
        taker.is_sweep = True
        taker.preselected_utxos = mock_wallet_for_sweep.get_all_utxos()

        # Set cj_amount as if it was calculated with estimated 2 maker inputs
        # (higher tx_fee estimate -> lower cj_amount)
        taker.cj_amount = 146_339
        taker._fee_rate = 1.0

        # Maker with only 1 input (lower tx_fee than estimated)
        maker_offer = Offer(
            ordertype=OfferType.SW0_ABSOLUTE,
            oid=0,
            minsize=10000,
            maxsize=1_000_000_000,
            txfee=500,
            cjfee=0,
            counterparty="J55Jha4vGPR5fTFv",
        )

        maker_session = MakerSession(nick="J55Jha4vGPR5fTFv", offer=maker_offer)
        maker_session.pubkey = "e131e3bb667eb124" + "00" * 24
        maker_session.responded_fill = True
        maker_session.responded_auth = True
        maker_session.utxos = [
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 18,
                "value": 467_555,
                "address": "bcrt1qmaker",
            }
        ]
        maker_session.cj_address = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
        maker_session.change_address = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa"
        maker_session.crypto = CryptoSession()

        taker.maker_sessions = {"J55Jha4vGPR5fTFv": maker_session}

        result = await taker._phase_build_tx(
            destination="bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu",
            mixdepth=3,
        )

        assert result is True

        # Verify cj_amount unchanged
        assert taker.cj_amount == 146_339

        # Calculate what the residual should be:
        # residual = total_input - cj_amount - maker_fees - actual_tx_fee
        # The residual represents the difference between estimated and actual tx_fee
        # (It's positive because actual tx_fee < estimated tx_fee due to fewer inputs)
        # This extra value goes to miners as additional fee, which is acceptable

    @pytest.mark.asyncio
    async def test_sweep_fails_on_negative_residual(
        self, mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep
    ):
        """Test that sweep mode fails if residual is negative.

        A negative residual occurs when actual tx_fee > estimated tx_fee,
        typically because a maker provided more UTXOs than we estimated.
        We cannot reduce cj_amount as it was already sent in !fill.
        """
        taker = Taker(mock_wallet_for_sweep, mock_backend_for_sweep, taker_config_for_sweep)

        taker.is_sweep = True
        taker.preselected_utxos = mock_wallet_for_sweep.get_all_utxos()
        taker._fee_rate = 1.0

        # Set cj_amount from !fill (calculated with estimated 2 maker inputs + 5 buffer)
        # From bug report: cj_amount = 146,340 sats
        # We increase it slightly to ensure negative residual with our fake inputs/tx size
        taker.cj_amount = 147_000

        # Maker with MANY UTXOs (6 inputs instead of estimated 2+buffer/n_makers)
        # This causes actual tx_fee to be much higher than estimated
        maker_offer = Offer(
            ordertype=OfferType.SW0_ABSOLUTE,
            oid=0,
            minsize=10000,
            maxsize=1_000_000_000,
            txfee=500,
            cjfee=0,
            counterparty="J597qgx3bTJBCAP7",
        )

        maker_session = MakerSession(nick="J597qgx3bTJBCAP7", offer=maker_offer)
        maker_session.pubkey = "c143f23bdecb05a9" + "00" * 24
        maker_session.responded_fill = True
        maker_session.responded_auth = True
        # Maker has 6 UTXOs - more than our 2+buffer/n_makers estimate!
        # 2 taker + 6 maker = 8 inputs -> higher tx_fee
        maker_session.utxos = [
            {
                "txid": "4444444444444444444444444444444444444444444444444444444444444444",
                "vout": 11,
                "value": 55_000,
                "address": "bcrt1qmaker",
            },
            {
                "txid": "5555555555555555555555555555555555555555555555555555555555555555",
                "vout": 12,
                "value": 30_161,
                "address": "bcrt1qmaker",
            },
            {
                "txid": "6666666666666666666666666666666666666666666666666666666666666666",
                "vout": 8,
                "value": 30_749,
                "address": "bcrt1qmaker",
            },
            {
                "txid": "7777777777777777777777777777777777777777777777777777777777777777",
                "vout": 2,
                "value": 30_983,
                "address": "bcrt1qmaker",
            },
            {
                "txid": "8888888888888888888888888888888888888888888888888888888888888888",
                "vout": 12,
                "value": 33_000,
                "address": "bcrt1qmaker",
            },
            {
                "txid": "9999999999999999999999999999999999999999999999999999999999999999",
                "vout": 3,
                "value": 45_921,
                "address": "bcrt1qmaker",
            },
        ]
        maker_session.cj_address = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
        maker_session.change_address = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa"
        maker_session.crypto = CryptoSession()

        taker.maker_sessions = {"J597qgx3bTJBCAP7": maker_session}

        result = await taker._phase_build_tx(
            destination="bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu",
            mixdepth=3,
        )

        # Should fail with negative residual
        # From bug report: residual = 147483 - 146340 - 0 - 1970 = -827 (negative!)
        # The tx_fee with 8 inputs is ~1970 sats (from actual log)
        assert result is False


@pytest.mark.asyncio
async def test_blacklist_rejection_doesnt_ignore_maker(
    mock_wallet, mock_backend, mock_config, tmp_path
):
    """Test that makers aren't permanently ignored when they reject a blacklisted commitment.

    When a maker rejects a taker's commitment because it's blacklisted, the taker should
    retry with a different commitment (different NUMS index or UTXO), not permanently
    ignore the maker. The maker might accept a different commitment.
    """
    from taker.orderbook import OrderbookManager
    from taker.taker import PhaseResult

    taker = Taker(mock_wallet, mock_backend, mock_config)
    taker.orderbook_manager = OrderbookManager(
        data_dir=tmp_path,  # Use tmp_path to avoid conflicts with other tests
        max_cj_fee=mock_config.max_cj_fee,
        bondless_makers_allowance=mock_config.bondless_makers_allowance,
        bondless_require_zero_fee=mock_config.bondless_makers_allowance_require_zero_fee,
    )

    # Simulate a blacklist error from a maker
    maker_nick = "J5TestMaker"
    blacklist_result = PhaseResult(
        success=False,
        failed_makers=[maker_nick],
        blacklist_error=True,
        needs_replacement=False,
    )

    # Before processing the result, maker should not be ignored
    assert maker_nick not in taker.orderbook_manager.ignored_makers

    # Process the blacklist rejection (simulating the logic in do_coinjoin)
    if blacklist_result.blacklist_error:
        # Don't add makers to ignored list when commitment is blacklisted
        pass
    elif blacklist_result.failed_makers:
        # Add failed makers to ignore list for non-blacklist failures
        for failed_nick in blacklist_result.failed_makers:
            taker.orderbook_manager.add_ignored_maker(failed_nick)

    # After processing blacklist error, maker should still NOT be ignored
    assert maker_nick not in taker.orderbook_manager.ignored_makers

    # Now test that non-blacklist failures DO ignore the maker
    non_blacklist_result = PhaseResult(
        success=False,
        failed_makers=[maker_nick],
        blacklist_error=False,
        needs_replacement=True,
    )

    if non_blacklist_result.blacklist_error:
        pass
    elif non_blacklist_result.failed_makers:
        for failed_nick in non_blacklist_result.failed_makers:
            taker.orderbook_manager.add_ignored_maker(failed_nick)

    # Now maker should be ignored for non-blacklist failures
    assert maker_nick in taker.orderbook_manager.ignored_makers


class TestUpdatePendingTransactionNow:
    """Tests for immediate pending transaction update on coinjoin completion."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create a temporary data directory."""
        return tmp_path

    @pytest.fixture
    def taker_with_backend(self, mock_wallet, mock_backend, mock_config, temp_data_dir):
        """Create a taker with a mock backend and temp data dir."""
        mock_config.data_dir = temp_data_dir
        mock_backend.has_mempool_access = Mock(return_value=True)
        return Taker(mock_wallet, mock_backend, mock_config)

    @pytest.mark.asyncio
    async def test_update_pending_tx_with_mempool_access(self, taker_with_backend, temp_data_dir):
        """Test that pending transaction is updated when mempool access is available."""
        from jmwallet.backends.base import Transaction
        from jmwallet.history import (
            append_history_entry,
            create_taker_history_entry,
            get_pending_transactions,
            read_history,
        )

        taker = taker_with_backend
        txid = "a" * 64
        destination = "bcrt1qdest"

        # Create and append a pending history entry
        entry = create_taker_history_entry(
            maker_nicks=["J5TestMaker"],
            cj_amount=100000,
            total_maker_fees=250,
            mining_fee=500,
            destination=destination,
            source_mixdepth=0,
            selected_utxos=[("b" * 64, 0)],
            txid=txid,
        )
        append_history_entry(entry, data_dir=temp_data_dir)

        # Verify it's pending
        pending = get_pending_transactions(data_dir=temp_data_dir)
        assert len(pending) == 1
        assert pending[0].txid == txid

        # Mock backend to return transaction in mempool (0 confirmations)
        taker.backend.get_transaction = AsyncMock(
            return_value=Transaction(
                txid=txid,
                raw="",
                confirmations=0,
            )
        )

        # Call the update method
        await taker._update_pending_transaction_now(txid, destination)

        # Verify transaction is no longer pending
        pending = get_pending_transactions(data_dir=temp_data_dir)
        assert len(pending) == 0

        # Verify history shows it as confirmed
        history = read_history(data_dir=temp_data_dir)
        assert len(history) == 1
        assert history[0].success is True
        assert history[0].confirmations >= 1

    @pytest.mark.asyncio
    async def test_update_pending_tx_with_confirmations(self, taker_with_backend, temp_data_dir):
        """Test that confirmation count is properly recorded."""
        from jmwallet.backends.base import Transaction
        from jmwallet.history import (
            append_history_entry,
            create_taker_history_entry,
            read_history,
        )

        taker = taker_with_backend
        txid = "c" * 64
        destination = "bcrt1qdest2"

        # Create and append a pending history entry
        entry = create_taker_history_entry(
            maker_nicks=["J5TestMaker"],
            cj_amount=200000,
            total_maker_fees=500,
            mining_fee=1000,
            destination=destination,
            source_mixdepth=1,
            selected_utxos=[("d" * 64, 1)],
            txid=txid,
        )
        append_history_entry(entry, data_dir=temp_data_dir)

        # Mock backend to return transaction with 3 confirmations
        taker.backend.get_transaction = AsyncMock(
            return_value=Transaction(
                txid=txid,
                raw="",
                confirmations=3,
            )
        )

        # Call the update method
        await taker._update_pending_transaction_now(txid, destination)

        # Verify history shows correct confirmation count
        history = read_history(data_dir=temp_data_dir)
        assert len(history) == 1
        assert history[0].confirmations == 3
        assert history[0].success is True

    @pytest.mark.asyncio
    async def test_update_pending_tx_without_mempool_access(
        self, mock_wallet, mock_backend, mock_config, temp_data_dir
    ):
        """Test behavior when backend has no mempool access (Neutrino)."""
        from jmwallet.history import (
            append_history_entry,
            create_taker_history_entry,
            get_pending_transactions,
        )

        mock_config.data_dir = temp_data_dir
        mock_backend.has_mempool_access = Mock(return_value=False)
        mock_backend.get_block_height = AsyncMock(return_value=100)
        # Simulate unconfirmed transaction (verify_tx_output returns False)
        mock_backend.verify_tx_output = AsyncMock(return_value=False)

        taker = Taker(mock_wallet, mock_backend, mock_config)
        txid = "e" * 64
        destination = "bcrt1qdest3"

        # Create and append a pending history entry
        entry = create_taker_history_entry(
            maker_nicks=["J5TestMaker"],
            cj_amount=50000,
            total_maker_fees=100,
            mining_fee=200,
            destination=destination,
            source_mixdepth=0,
            selected_utxos=[("f" * 64, 0)],
            txid=txid,
        )
        append_history_entry(entry, data_dir=temp_data_dir)

        # Call the update method - should not update since not confirmed
        await taker._update_pending_transaction_now(txid, destination)

        # Transaction should still be pending (Neutrino can't see mempool)
        pending = get_pending_transactions(data_dir=temp_data_dir)
        assert len(pending) == 1

    @pytest.mark.asyncio
    async def test_update_pending_tx_neutrino_confirmed(
        self, mock_wallet, mock_backend, mock_config, temp_data_dir
    ):
        """Test Neutrino backend with confirmed transaction."""
        from jmwallet.history import (
            append_history_entry,
            create_taker_history_entry,
            get_pending_transactions,
            read_history,
        )

        mock_config.data_dir = temp_data_dir
        mock_backend.has_mempool_access = Mock(return_value=False)
        mock_backend.get_block_height = AsyncMock(return_value=100)
        # Simulate confirmed transaction (verify_tx_output returns True)
        mock_backend.verify_tx_output = AsyncMock(return_value=True)

        taker = Taker(mock_wallet, mock_backend, mock_config)
        txid = "g" * 64
        destination = "bcrt1qdest4"

        # Create and append a pending history entry
        entry = create_taker_history_entry(
            maker_nicks=["J5TestMaker"],
            cj_amount=75000,
            total_maker_fees=150,
            mining_fee=300,
            destination=destination,
            source_mixdepth=2,
            selected_utxos=[("h" * 64, 0)],
            txid=txid,
        )
        append_history_entry(entry, data_dir=temp_data_dir)

        # Call the update method
        await taker._update_pending_transaction_now(txid, destination)

        # Verify transaction is no longer pending
        pending = get_pending_transactions(data_dir=temp_data_dir)
        assert len(pending) == 0

        # Verify history shows it as confirmed
        history = read_history(data_dir=temp_data_dir)
        assert len(history) == 1
        assert history[0].success is True
        assert history[0].confirmations == 1
