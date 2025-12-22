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

from taker.podle import generate_podle_for_coinjoin
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
async def test_podle_generation(mock_wallet):
    """Test PoDLE commitment generation."""
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

    # Generate PoDLE commitment
    commitment = generate_podle_for_coinjoin(
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
    commitment_str = commitment.to_commitment_str()
    assert len(commitment_str) == 64  # Should be 32 bytes in hex

    # Test revelation serialization
    revelation = commitment.to_revelation()
    assert "utxo" in revelation
    assert "P" in revelation
    assert "P2" in revelation
    assert "sig" in revelation
    assert "e" in revelation


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
