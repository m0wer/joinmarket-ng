"""
End-to-end integration tests for complete JoinMarket system.

Tests all components working together:
- Bitcoin regtest node
- Directory server
- Orderbook watcher
- Maker bot
- Taker client
- Wallet synchronization
"""

import asyncio

import pytest
import pytest_asyncio

from jmcore.models import NetworkType
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService
from maker.bot import MakerBot
from maker.config import MakerConfig
from taker.config import TakerConfig
from taker.taker import Taker, TakerState


@pytest.fixture
def bitcoin_backend():
    """Bitcoin Core backend for regtest"""
    return BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test",
    )


@pytest_asyncio.fixture
async def funded_wallet(bitcoin_backend):
    """Create and fund a test wallet"""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=bitcoin_backend,
        network="regtest",
        mixdepth_count=5,
    )

    await wallet.sync_all()

    total_balance = await wallet.get_total_balance()
    if total_balance == 0:
        funding_address = wallet.get_receive_address(0, 0)
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if funded:
            await wallet.sync_all()
            total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.skip("Wallet has no funds. Auto-funding failed; please fund manually.")

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest.fixture
def maker_config():
    """Maker bot configuration"""
    return MakerConfig(
        mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        network=NetworkType.REGTEST,
        backend_type="bitcoin_core",
        backend_config={
            "rpc_url": "http://127.0.0.1:18443",
            "rpc_user": "test",
            "rpc_password": "test",
        },
        directory_servers=["127.0.0.1:5222"],
        min_size=10_000,
        cj_fee_relative="0.0002",
        tx_fee_contribution=10_000,
    )


@pytest.fixture
def taker_config():
    """Taker configuration for tests."""
    # Use a different mnemonic for taker to have different wallet
    return TakerConfig(
        mnemonic="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        network=NetworkType.REGTEST,
        backend_type="bitcoin_core",
        backend_config={
            "rpc_url": "http://127.0.0.1:18443",
            "rpc_user": "test",
            "rpc_password": "test",
        },
        directory_servers=["127.0.0.1:5222"],
        counterparty_count=2,
        minimum_makers=1,
        maker_timeout_sec=30,
        order_wait_time=5.0,
    )


@pytest_asyncio.fixture
async def mined_chain(bitcoin_backend):
    """Ensure blockchain has minimum height."""
    from tests.e2e.rpc_utils import mine_blocks

    height = await bitcoin_backend.get_block_height()
    if height < 101:
        # Mine to a fixed valid address (P2WPKH) since node runs wallet-free
        addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        await mine_blocks(101 - height + 10, addr)
    return True


@pytest.mark.asyncio
async def test_bitcoin_connection(bitcoin_backend, mined_chain):
    """Test Bitcoin Core connection"""
    height = await bitcoin_backend.get_block_height()
    assert height > 100

    fee = await bitcoin_backend.estimate_fee(6)
    assert fee > 0


@pytest.mark.asyncio
async def test_wallet_sync(funded_wallet: WalletService):
    """Test wallet synchronization"""
    balance = await funded_wallet.get_total_balance()
    assert balance > 0

    utxos_dict = await funded_wallet.sync_all()
    assert len(utxos_dict) > 0


@pytest.mark.asyncio
async def test_wallet_address_generation(funded_wallet: WalletService):
    """Test address generation"""
    addr1 = funded_wallet.get_receive_address(0, 0)
    addr2 = funded_wallet.get_receive_address(0, 1)

    assert addr1.startswith("bcrt1")
    assert addr2.startswith("bcrt1")
    assert addr1 != addr2


@pytest.mark.asyncio
async def test_wallet_multiple_mixdepths(funded_wallet: WalletService):
    """Test multiple mixdepth balances"""
    for mixdepth in range(5):
        balance = await funded_wallet.get_balance(mixdepth)
        assert balance >= 0


@pytest.mark.asyncio
async def test_maker_bot_initialization(bitcoin_backend, maker_config):
    """Test maker bot initialization"""
    wallet = WalletService(
        mnemonic=maker_config.mnemonic,
        backend=bitcoin_backend,
        network="regtest",
    )

    bot = MakerBot(wallet, bitcoin_backend, maker_config)

    assert bot.nick.startswith("J5")
    assert len(bot.nick) == 16

    await wallet.close()


@pytest.mark.asyncio
async def test_maker_bot_connect_directory(bitcoin_backend, maker_config):
    """Test maker bot connecting to directory server"""
    wallet = WalletService(
        mnemonic=maker_config.mnemonic,
        backend=bitcoin_backend,
        network="regtest",
    )

    bot = MakerBot(wallet, bitcoin_backend, maker_config)

    # Start the bot in the background
    start_task = asyncio.create_task(bot.start())

    try:
        # Wait for connection to establish (wallet sync takes ~2s, connection ~0.5s)
        await asyncio.sleep(10)

        # Skip if no directory server is running
        if not bot.directory_clients:
            await wallet.close()
            pytest.skip("Directory server not running")

        # Check that bot connected
        assert len(bot.directory_clients) > 0, (
            "Should have connected to directory server. "
            f"Connections: {bot.directory_clients}, Running: {bot.running}"
        )
        assert bot.running, "Bot should be running"

    finally:
        # Stop the bot
        await bot.stop()
        # Cancel the start task if still running
        start_task.cancel()
        try:
            await start_task
        except asyncio.CancelledError:
            pass
        await wallet.close()


@pytest.mark.asyncio
async def test_offer_creation(
    funded_wallet: WalletService, bitcoin_backend, maker_config
):
    """Test offer creation based on wallet balance"""
    from maker.offers import OfferManager

    offer_manager = OfferManager(funded_wallet, maker_config, "J5TestMaker")

    offers = await offer_manager.create_offers()

    if offers:
        offer = offers[0]
        assert offer.minsize <= offer.maxsize
        assert offer.txfee == maker_config.tx_fee_contribution
        assert offer.counterparty == "J5TestMaker"


@pytest.mark.asyncio
async def test_coin_selection(funded_wallet: WalletService):
    """Test UTXO selection for CoinJoin"""
    balance = await funded_wallet.get_balance(0)

    if balance > 50_000:
        utxos = funded_wallet.select_utxos(0, 50_000, min_confirmations=1)
        assert len(utxos) > 0
        total = sum(u.value for u in utxos)
        assert total >= 50_000


@pytest.mark.asyncio
async def test_system_health_check(bitcoin_backend, mined_chain):
    """Test overall system health"""
    try:
        height = await bitcoin_backend.get_block_height()
        assert height > 100

        fee = await bitcoin_backend.estimate_fee(6)
        assert fee > 0

        logger_info = "System health check passed ✓"
        print(logger_info)

    except Exception as e:
        pytest.fail(f"System health check failed: {e}")


# ==============================================================================
# Taker Tests
# ==============================================================================


@pytest_asyncio.fixture
async def funded_taker_wallet(bitcoin_backend):
    """Create and fund a taker wallet with different mnemonic."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    # Use different mnemonic for taker
    mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=bitcoin_backend,
        network="regtest",
        mixdepth_count=5,
    )

    await wallet.sync_all()

    total_balance = await wallet.get_total_balance()
    if total_balance == 0:
        funding_address = wallet.get_receive_address(0, 0)
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if funded:
            await wallet.sync_all()
            total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.skip(
            "Taker wallet has no funds. Auto-funding failed; please fund manually."
        )

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest.mark.asyncio
async def test_taker_initialization(bitcoin_backend, taker_config):
    """Test taker initialization and nick generation."""
    wallet = WalletService(
        mnemonic=taker_config.mnemonic,
        backend=bitcoin_backend,
        network="regtest",
    )

    taker = Taker(wallet, bitcoin_backend, taker_config)

    # Check nick is generated correctly (J5 prefix for version 5)
    assert taker.nick.startswith("J5")
    assert len(taker.nick) == 16

    # Check initial state
    assert taker.state == TakerState.IDLE

    await wallet.close()


@pytest.mark.asyncio
async def test_taker_connect_directory(bitcoin_backend, taker_config):
    """Test taker connecting to directory server."""
    wallet = WalletService(
        mnemonic=taker_config.mnemonic,
        backend=bitcoin_backend,
        network="regtest",
    )

    taker = Taker(wallet, bitcoin_backend, taker_config)

    try:
        # Start taker (connects to directory servers)
        await taker.start()

        # Check wallet was synced
        total_balance = await wallet.get_total_balance()
        assert total_balance >= 0, "Wallet should have synced"

        # Directory client should have connected
        # Note: connection count depends on whether directory server is running
        print(f"Taker nick: {taker.nick}")
        print(f"Taker state: {taker.state}")

    except RuntimeError as e:
        # If directory server is not running, skip test
        if "Failed to connect" in str(e):
            pytest.skip("Directory server not running")
        raise

    finally:
        await taker.stop()


@pytest.mark.asyncio
async def test_taker_orderbook_fetch(bitcoin_backend, taker_config):
    """Test taker fetching orderbook from directory."""
    wallet = WalletService(
        mnemonic=taker_config.mnemonic,
        backend=bitcoin_backend,
        network="regtest",
    )

    taker = Taker(wallet, bitcoin_backend, taker_config)

    try:
        await taker.start()

        # Fetch orderbook - may be empty if no makers are running
        offers = await taker.directory_client.fetch_orderbook(
            timeout=taker_config.order_wait_time
        )

        # Offers should be a list (may be empty)
        assert isinstance(offers, list), "Offers should be a list"
        print(f"Found {len(offers)} offers in orderbook")

        # Update orderbook manager
        taker.orderbook_manager.update_offers(offers)

    except RuntimeError as e:
        if "Failed to connect" in str(e):
            pytest.skip("Directory server not running")
        raise

    finally:
        await taker.stop()


@pytest.mark.asyncio
async def test_taker_config_validation(taker_config):
    """Test taker configuration validation."""
    from taker.config import MaxCjFee, TakerConfig

    # Test default MaxCjFee
    max_fee = MaxCjFee()
    assert max_fee.abs_fee == 50_000
    assert max_fee.rel_fee == "0.001"

    # Test custom config
    config = TakerConfig(
        mnemonic="abandon " * 11 + "about",
        counterparty_count=5,
        minimum_makers=3,
        mixdepth=2,
    )
    assert config.counterparty_count == 5
    assert config.minimum_makers == 3
    assert config.mixdepth == 2

    # Test bounds validation
    with pytest.raises(ValueError):
        TakerConfig(
            mnemonic="abandon " * 11 + "about",
            counterparty_count=25,  # Max is 20
        )


@pytest.mark.asyncio
async def test_taker_orderbook_manager(bitcoin_backend, taker_config):
    """Test taker orderbook manager functionality."""
    from jmcore.models import Offer, OfferType
    from taker.orderbook import OrderbookManager, calculate_cj_fee

    max_fee = taker_config.max_cj_fee
    manager = OrderbookManager(max_fee)

    # Create some test offers
    test_offers = [
        Offer(
            counterparty="J5TestMaker1",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=10_000_000,
            txfee=500,
            cjfee="0.0002",
        ),
        Offer(
            counterparty="J5TestMaker2",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=10_000,
            maxsize=5_000_000,
            txfee=1000,
            cjfee="100",
        ),
    ]

    manager.update_offers(test_offers)
    assert len(manager.offers) == 2

    # Test fee calculation
    cj_amount = 1_000_000
    fee1 = calculate_cj_fee(test_offers[0], cj_amount)
    assert fee1 == 200  # 0.02% of 1M = 200 sats

    fee2 = calculate_cj_fee(test_offers[1], cj_amount)
    assert fee2 == 100  # absolute 100 sats


@pytest.mark.asyncio
async def test_taker_podle_generation(funded_taker_wallet: WalletService):
    """Test PoDLE commitment generation for taker."""
    from taker.podle import select_podle_utxo

    # Get UTXOs from wallet
    utxos = await funded_taker_wallet.get_utxos(0)

    if not utxos:
        pytest.skip("No UTXOs available for PoDLE test")

    cj_amount = 100_000

    # Test UTXO selection
    selected = select_podle_utxo(
        utxos=utxos,
        cj_amount=cj_amount,
        min_confirmations=1,
        min_percent=10,
    )

    if selected:
        print(f"Selected UTXO: {selected.txid}:{selected.vout}")
        print(f"Value: {selected.value}, Confirmations: {selected.confirmations}")
        assert selected.confirmations >= 1
        assert selected.value >= cj_amount * 0.1


@pytest.mark.asyncio
async def test_taker_tx_builder():
    """Test taker transaction builder utilities."""
    from taker.tx_builder import (
        TxInput,
        TxOutput,
        address_to_scriptpubkey,
        calculate_tx_fee,
        varint,
    )

    # Test varint encoding
    assert varint(0) == b"\x00"
    assert varint(252) == b"\xfc"
    assert varint(253) == b"\xfd\xfd\x00"

    # Test fee calculation
    # calculate_tx_fee(num_taker_inputs, num_maker_inputs, num_outputs, fee_rate)
    fee = calculate_tx_fee(1, 2, 5, fee_rate=10)
    # 3 P2WPKH inputs (~68 vbytes each) + 5 outputs (~31 vbytes each) + overhead
    expected_vsize = 3 * 68 + 5 * 31 + 11
    assert fee == expected_vsize * 10

    # Test TxInput/TxOutput dataclasses
    tx_in = TxInput(
        txid="a" * 64,
        vout=0,
        value=100_000,
        scriptpubkey="0014" + "b" * 40,
    )
    assert tx_in.sequence == 0xFFFFFFFF  # Default sequence (final)

    tx_out = TxOutput(
        address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        value=50_000,
    )
    assert tx_out.value == 50_000

    # Test address to scriptpubkey (P2WPKH)
    testnet_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    script = address_to_scriptpubkey(testnet_addr)
    assert script.startswith(bytes.fromhex("0014"))  # P2WPKH prefix (OP_0 PUSH20)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
