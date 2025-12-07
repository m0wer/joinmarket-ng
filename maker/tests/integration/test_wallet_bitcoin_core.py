"""
Integration tests for wallet with Bitcoin Core regtest.

These tests require a running Bitcoin Core regtest node.
Run: docker-compose up -d bitcoin
"""

import httpx
import pytest
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService


def check_bitcoin_available():
    """Check if Bitcoin Core is available"""
    try:
        client = httpx.Client(timeout=2.0)
        response = client.post(
            "http://127.0.0.1:18443",
            auth=("test", "test"),
            json={"jsonrpc": "1.0", "id": "test", "method": "getblockchaininfo", "params": []},
        )
        client.close()
        return response.status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not check_bitcoin_available(),
    reason="Bitcoin Core regtest node not running. Start with: docker-compose up -d bitcoin",
)


@pytest.fixture
def bitcoin_backend():
    """Bitcoin Core backend connected to regtest"""
    return BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test",
    )


@pytest.fixture
def test_wallet(bitcoin_backend):
    """Test wallet"""
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    return WalletService(
        mnemonic=mnemonic,
        backend=bitcoin_backend,
        network="regtest",
        mixdepth_count=5,
        gap_limit=20,
    )


@pytest.mark.asyncio
async def test_bitcoin_core_connection(bitcoin_backend):
    """Test connection to Bitcoin Core"""
    height = await bitcoin_backend.get_block_height()
    assert height >= 0


@pytest.mark.asyncio
async def test_wallet_sync_empty(test_wallet):
    """Test syncing empty wallet"""
    utxos = await test_wallet.sync_mixdepth(0)

    assert isinstance(utxos, list)


@pytest.mark.asyncio
async def test_wallet_address_generation(test_wallet):
    """Test address generation"""
    addr1 = test_wallet.get_receive_address(0, 0)
    assert addr1.startswith("bcrt1")

    addr2 = test_wallet.get_receive_address(0, 1)
    assert addr2.startswith("bcrt1")
    assert addr1 != addr2

    change_addr = test_wallet.get_change_address(0, 0)
    assert change_addr.startswith("bcrt1")
    assert change_addr != addr1


@pytest.mark.asyncio
async def test_wallet_balance_zero(test_wallet):
    """Test balance of empty wallet"""
    await test_wallet.sync_mixdepth(0)
    balance = await test_wallet.get_balance(0)

    assert balance == 0


@pytest.mark.asyncio
async def test_fee_estimation(bitcoin_backend):
    """Test fee estimation"""
    fee_rate = await bitcoin_backend.estimate_fee(6)
    assert fee_rate > 0
    assert fee_rate < 1000


@pytest.mark.asyncio
async def test_multiple_mixdepths(test_wallet):
    """Test multiple mixdepth sync"""
    result = await test_wallet.sync_all()

    assert len(result) == 5
    for mixdepth in range(5):
        assert mixdepth in result
        assert isinstance(result[mixdepth], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
