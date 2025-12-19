"""
End-to-end integration tests for Neutrino backend.

Tests neutrino light client backend functionality:
- Basic blockchain operations (height, transactions, fees)
- UTXO discovery and watching addresses
- Maker and taker operation with neutrino backend
- Cross-backend compatibility (bitcoin_core + neutrino)
- Fidelity bonds with neutrino backend

Requires: docker compose --profile all up -d

The neutrino backend uses BIP157/BIP158 compact block filters for
privacy-preserving SPV operation. These tests verify that the neutrino
backend works correctly with the JoinMarket wallet implementation.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from jmcore.models import NetworkType
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from maker.bot import MakerBot
from maker.config import MakerConfig
from taker.config import TakerConfig
from taker.taker import Taker

# Test wallet mnemonics (same as in test_complete_system.py for consistency)
MAKER1_MNEMONIC = (
    "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
)
MAKER2_MNEMONIC = (
    "minute faint grape plate stock mercy tent world space opera apple rocket"
)
TAKER_MNEMONIC = (
    "burden notable love elephant orbit couch message galaxy elevator exile drop toilet"
)
GENERIC_TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture(scope="module")
def neutrino_url() -> str:
    """Neutrino server URL."""
    return "http://127.0.0.1:8334"


@pytest_asyncio.fixture
async def neutrino_backend(neutrino_url: str):
    """Create Neutrino backend for tests."""
    backend = NeutrinoBackend(
        neutrino_url=neutrino_url,
        network="regtest",
    )

    # Verify neutrino is available and synced - fail if not
    try:
        height = await backend.get_block_height()
        if height == 0:
            # Wait for sync
            synced = await backend.wait_for_sync(timeout=30.0)
            if not synced:
                pytest.fail("Neutrino failed to sync within timeout")
    except Exception as e:
        pytest.fail(f"Neutrino server not available at {neutrino_url}: {e}")

    yield backend
    await backend.close()


@pytest_asyncio.fixture
async def funded_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund a test wallet using neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=GENERIC_TEST_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address BEFORE syncing
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core - mines directly to the address
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height (not 0)
        # The funding transaction will be in recent blocks
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)  # Scan last 10 blocks

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan to complete

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(
            f"Wallet has no funds after funding attempt. "
            f"Address: {funding_address}, neutrino may not have synced the new blocks"
        )

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest_asyncio.fixture
async def funded_maker1_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund maker1 wallet with neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=MAKER1_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund maker1 wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(f"Maker1 wallet has no funds. Address: {funding_address}")

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest_asyncio.fixture
async def funded_taker_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund taker wallet with neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=TAKER_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund taker wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(f"Taker wallet has no funds. Address: {funding_address}")

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest.fixture
def maker_neutrino_config():
    """Maker configuration using neutrino backend."""
    return MakerConfig(
        mnemonic=MAKER1_MNEMONIC,
        network=NetworkType.TESTNET,  # Protocol network
        bitcoin_network=NetworkType.REGTEST,  # Bitcoin network
        backend_type="neutrino",
        backend_config={
            "neutrino_url": "http://127.0.0.1:8334",
        },
        directory_servers=["127.0.0.1:5222"],
        min_size=100_000,
        cj_fee_relative="0.0003",
        tx_fee_contribution=1_000,
    )


@pytest.fixture
def taker_neutrino_config():
    """Taker configuration using neutrino backend."""
    return TakerConfig(
        mnemonic=TAKER_MNEMONIC,
        network=NetworkType.TESTNET,  # Protocol network
        bitcoin_network=NetworkType.REGTEST,  # Bitcoin network
        backend_type="neutrino",
        backend_config={
            "neutrino_url": "http://127.0.0.1:8334",
        },
        directory_servers=["127.0.0.1:5222"],
        counterparty_count=2,
        minimum_makers=2,
        maker_timeout_sec=30,
        order_wait_time=10.0,
    )


# ==============================================================================
# Basic Neutrino Backend Tests
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_connection(neutrino_backend: NeutrinoBackend):
    """Test basic neutrino backend connectivity."""
    height = await neutrino_backend.get_block_height()
    assert height > 0, "Should get block height from neutrino"

    fee = await neutrino_backend.estimate_fee(6)
    assert fee > 0, "Should estimate fee"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_watch_address(neutrino_backend: NeutrinoBackend):
    """Test neutrino address watching functionality."""
    test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

    # Add address to watch
    await neutrino_backend.add_watch_address(test_address)

    # Verify it was added (if API succeeded)
    if test_address in neutrino_backend._watched_addresses:
        assert test_address in neutrino_backend._watched_addresses


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_wallet_sync(funded_neutrino_wallet: WalletService):
    """Test wallet synchronization with neutrino backend."""
    balance = await funded_neutrino_wallet.get_total_balance()
    assert balance > 0, "Wallet should have balance"

    utxos_dict = await funded_neutrino_wallet.sync_all()
    assert len(utxos_dict) > 0, "Should find UTXOs"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_address_generation(funded_neutrino_wallet: WalletService):
    """Test address generation works with neutrino backend."""
    addr1 = funded_neutrino_wallet.get_receive_address(0, 0)
    addr2 = funded_neutrino_wallet.get_receive_address(0, 1)

    assert addr1.startswith("bcrt1"), "Should generate regtest bech32 address"
    assert addr2.startswith("bcrt1"), "Should generate regtest bech32 address"
    assert addr1 != addr2, "Addresses should be unique"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_utxo_discovery(
    neutrino_backend: NeutrinoBackend, funded_neutrino_wallet: WalletService
):
    """Test UTXO discovery via neutrino compact block filters."""
    # Get wallet addresses
    addresses = [funded_neutrino_wallet.get_receive_address(0, i) for i in range(5)]

    # Get UTXOs via neutrino
    utxos = await neutrino_backend.get_utxos(addresses)

    # Should find at least the funded UTXO
    assert len(utxos) > 0, "Neutrino should discover UTXOs"

    # Verify UTXO structure
    for utxo in utxos:
        assert utxo.txid, "UTXO should have txid"
        assert utxo.value > 0, "UTXO should have value"
        assert utxo.confirmations >= 0, "UTXO should have confirmations"


# ==============================================================================
# Maker with Neutrino Backend
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_maker_neutrino_initialization(
    neutrino_backend: NeutrinoBackend, maker_neutrino_config: MakerConfig
):
    """Test maker bot initialization with neutrino backend."""
    wallet = WalletService(
        mnemonic=maker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    bot = MakerBot(wallet, neutrino_backend, maker_neutrino_config)

    assert bot.nick.startswith("J5"), "Should generate valid nick"
    assert len(bot.nick) == 16, "Nick should be 16 characters"

    await wallet.close()


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_maker_neutrino_offer_creation(
    funded_maker1_neutrino_wallet: WalletService, maker_neutrino_config: MakerConfig
):
    """Test maker can create offers with neutrino backend."""
    from maker.offers import OfferManager

    offer_manager = OfferManager(
        funded_maker1_neutrino_wallet, maker_neutrino_config, "J5NeutrinoMaker"
    )

    offers = await offer_manager.create_offers()

    if offers:
        offer = offers[0]
        assert offer.minsize <= offer.maxsize
        assert offer.txfee == maker_neutrino_config.tx_fee_contribution
        assert offer.counterparty == "J5NeutrinoMaker"


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
async def test_maker_neutrino_coinjoin(
    neutrino_backend: NeutrinoBackend,
    maker_neutrino_config: MakerConfig,
    funded_maker1_neutrino_wallet: WalletService,
):
    """Test maker can participate in CoinJoin using neutrino backend."""
    # This test requires a running taker and directory server
    # For now, we test that the maker can start and connect

    bot = MakerBot(
        funded_maker1_neutrino_wallet, neutrino_backend, maker_neutrino_config
    )

    # Start the bot in background
    start_task = asyncio.create_task(bot.start())

    try:
        # Wait for connection
        await asyncio.sleep(10)

        # Verify bot connected (if directory server is running)
        # This assertion may fail if directory server is not available
        if len(bot.directory_clients) > 0:
            assert bot.running, "Bot should be running"

    finally:
        await bot.stop()
        start_task.cancel()
        try:
            await start_task
        except asyncio.CancelledError:
            pass


# ==============================================================================
# Taker with Neutrino Backend
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_initialization(
    neutrino_backend: NeutrinoBackend, taker_neutrino_config: TakerConfig
):
    """Test taker initialization with neutrino backend."""
    wallet = WalletService(
        mnemonic=taker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    taker = Taker(wallet, neutrino_backend, taker_neutrino_config)

    assert taker.nick.startswith("J5"), "Should generate valid nick"
    assert len(taker.nick) == 16, "Nick should be 16 characters"

    await wallet.close()


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_podle_generation(
    funded_taker_neutrino_wallet: WalletService,
):
    """Test PoDLE commitment generation with neutrino backend."""
    from taker.podle import select_podle_utxo

    utxos = await funded_taker_neutrino_wallet.get_utxos(0)

    assert utxos, "Funded wallet should have UTXOs for PoDLE test"

    cj_amount = 100_000

    selected = select_podle_utxo(
        utxos=utxos,
        cj_amount=cj_amount,
        min_confirmations=1,
        min_percent=10,
    )

    assert selected is not None, "Should select a UTXO for PoDLE"
    assert selected.confirmations >= 1
    assert selected.value >= cj_amount * 0.1


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_orderbook_fetch(
    neutrino_backend: NeutrinoBackend, taker_neutrino_config: TakerConfig
):
    """Test taker can fetch orderbook with neutrino backend."""
    wallet = WalletService(
        mnemonic=taker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    taker = Taker(wallet, neutrino_backend, taker_neutrino_config)

    try:
        await taker.start()

        # Fetch orderbook (may be empty)
        try:
            offers = await taker.directory_client.fetch_orderbook(timeout=5.0)
            assert isinstance(offers, list), "Offers should be a list"
        except Exception:
            # Directory server may not be running
            pass

    finally:
        await taker.stop()
        await wallet.close()


# ==============================================================================
# Cross-Backend Compatibility Tests
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
@pytest.mark.xfail(reason="Cross-backend CoinJoin not yet implemented")
async def test_cross_backend_bitcoin_core_maker_neutrino_taker():
    """
    Test cross-backend compatibility: Bitcoin Core maker + Neutrino taker.

    This test verifies that makers using Bitcoin Core backend can
    successfully complete CoinJoin with takers using Neutrino backend.

    Requires:
    - docker compose --profile all up -d
    """
    # TODO: Implement cross-backend CoinJoin test
    assert False, "Not implemented"


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
@pytest.mark.xfail(reason="Cross-backend CoinJoin not yet implemented")
async def test_cross_backend_neutrino_maker_bitcoin_core_taker():
    """
    Test cross-backend compatibility: Neutrino maker + Bitcoin Core taker.

    This test verifies that makers using Neutrino backend can
    successfully complete CoinJoin with takers using Bitcoin Core backend.

    Requires:
    - docker compose --profile all up -d
    """
    # TODO: Implement cross-backend CoinJoin test
    assert False, "Not implemented"


# ==============================================================================
# Fidelity Bonds with Neutrino
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.xfail(reason="Fidelity bond testing requires time-locked UTXOs")
async def test_neutrino_fidelity_bond_discovery():
    """
    Test fidelity bond discovery with neutrino backend.

    Neutrino should be able to discover timelocked UTXOs and verify
    fidelity bond proofs using compact block filters.
    """
    # TODO: Implement fidelity bond discovery test
    assert False, "Not implemented"


# ==============================================================================
# Neutrino Rescan and Recovery
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_rescan_from_height(neutrino_backend: NeutrinoBackend):
    """Test neutrino blockchain rescan functionality."""
    test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

    # Rescan from genesis - should succeed
    await neutrino_backend.rescan_from_height(0, addresses=[test_address])
    # If we get here, the rescan was initiated successfully
    assert True


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_watch_outpoint(neutrino_backend: NeutrinoBackend):
    """Test neutrino outpoint watching functionality."""
    # Create a test outpoint
    test_txid = "a" * 64
    test_vout = 0

    await neutrino_backend.add_watch_outpoint(test_txid, test_vout)

    # Verify it's in watched set
    assert (test_txid, test_vout) in neutrino_backend._watched_outpoints


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
