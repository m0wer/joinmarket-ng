"""
End-to-end integration tests for complete JoinMarket system.

Tests all components working together:
- Bitcoin regtest node
- Directory server
- Orderbook watcher
- Maker bot
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


@pytest.mark.asyncio
async def test_bitcoin_connection(bitcoin_backend):
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

        # Check that bot connected
        assert len(bot.directory_connections) > 0, (
            "Should have connected to directory server. "
            f"Connections: {bot.directory_connections}, Running: {bot.running}"
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
async def test_system_health_check(bitcoin_backend):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
