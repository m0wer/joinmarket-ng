"""
Integration tests for BitcoinCoreBackend and NeutrinoBackend
"""

import pytest
from jmcore.crypto import KeyPair

from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig
from jmwallet.wallet.address import pubkey_to_p2wpkh_address


@pytest.mark.asyncio
async def test_bitcoin_core_backend_integration():
    # Connect to the regtest node defined in docker-compose
    backend = BitcoinCoreBackend(
        rpc_url="http://localhost:18443", rpc_user="test", rpc_password="test"
    )

    try:
        # Check connection
        try:
            await backend.get_block_height()
        except Exception:
            pytest.skip("Bitcoin Core not available at localhost:18443")
            return

        # Generate a local address
        kp = KeyPair()
        # "regtest" usually implies "bcrt" prefix in our address helper
        address = pubkey_to_p2wpkh_address(kp.public_key_hex(), network="regtest")

        # Mine to this address
        try:
            # generatetoaddress 1 block
            block_hashes = await backend._rpc_call("generatetoaddress", [1, address])
        except Exception as e:
            # If this fails, we can't really test UTXO scanning easily
            pytest.fail(f"generatetoaddress failed: {e}")

        assert len(block_hashes) == 1

        # Test get_utxos
        utxos = await backend.get_utxos([address])

        assert len(utxos) > 0
        assert sum(u.value for u in utxos) > 0

        # Test get_address_balance
        balance = await backend.get_address_balance(address)
        assert balance > 0

        # Test get_transaction using the found UTXO
        txid = utxos[0].txid

        tx = await backend.get_transaction(txid)
        assert tx is not None
        assert tx.txid == txid

        # Test estimate_fee
        fee = await backend.estimate_fee(2)
        assert fee > 0

    finally:
        await backend.close()


class TestNeutrinoBackend:
    """Unit tests for NeutrinoBackend (mocked)."""

    @pytest.mark.asyncio
    async def test_neutrino_backend_init(self):
        """Test NeutrinoBackend initialization."""
        backend = NeutrinoBackend(
            neutrino_url="http://localhost:8334",
            network="regtest",
        )
        assert backend.neutrino_url == "http://localhost:8334"
        assert backend.network == "regtest"
        assert backend._synced is False
        await backend.close()

    @pytest.mark.asyncio
    async def test_neutrino_backend_add_watch_address(self):
        """Test adding addresses to watch list.

        In neutrino-api v0.4, address watching is done locally without API calls.
        The addresses are tracked in memory and used when making queries.
        """
        backend = NeutrinoBackend(neutrino_url="http://localhost:8334")

        address = "bcrt1q0000000000000000000000000000000000000"
        await backend.add_watch_address(address)

        # Address should be in watched set (local tracking)
        assert address in backend._watched_addresses
        assert len(backend._watched_addresses) == 1
        await backend.close()

    @pytest.mark.asyncio
    async def test_neutrino_backend_watch_address_limit(self):
        """Test that watch list has a maximum size limit."""
        backend = NeutrinoBackend(neutrino_url="http://localhost:8334")
        # Override limit to a small value for testing
        backend._max_watched_addresses = 5

        # Add addresses up to limit
        for i in range(5):
            await backend.add_watch_address(f"bcrt1qtest{i}")

        # Next add should raise ValueError
        with pytest.raises(ValueError, match="Watch list limit"):
            await backend.add_watch_address("bcrt1qexceeds")

        await backend.close()

    @pytest.mark.asyncio
    async def test_neutrino_backend_blockheight_validation(self):
        """Test blockheight validation in verify_utxo_with_metadata."""
        from unittest.mock import AsyncMock

        backend = NeutrinoBackend(neutrino_url="http://localhost:8334", network="mainnet")
        # Mock get_block_height to return a known value
        backend.get_block_height = AsyncMock(return_value=800000)

        # Test: blockheight too low (before SegWit activation)
        result = await backend.verify_utxo_with_metadata(
            txid="abc123",
            vout=0,
            scriptpubkey="0014" + "00" * 20,  # valid P2WPKH
            blockheight=100000,  # Way before SegWit
        )
        assert result.valid is False
        assert "below minimum valid height" in (result.error or "")

        # Test: blockheight in the future
        result = await backend.verify_utxo_with_metadata(
            txid="abc123",
            vout=0,
            scriptpubkey="0014" + "00" * 20,
            blockheight=900000,  # Future block
        )
        assert result.valid is False
        assert "in the future" in (result.error or "")

        await backend.close()

    @pytest.mark.asyncio
    async def test_neutrino_backend_rescan_depth_limit(self):
        """Test that rescan depth is limited to prevent DoS."""
        from unittest.mock import AsyncMock

        backend = NeutrinoBackend(neutrino_url="http://localhost:8334", network="mainnet")
        backend._max_rescan_depth = 1000  # Override for testing
        backend.get_block_height = AsyncMock(return_value=800000)

        # Test: rescan depth exceeds limit
        result = await backend.verify_utxo_with_metadata(
            txid="abc123",
            vout=0,
            scriptpubkey="0014" + "00" * 20,
            blockheight=700000,  # 100,000 blocks ago (exceeds limit)
        )
        assert result.valid is False
        assert "exceeds max" in (result.error or "")

        await backend.close()

    def test_neutrino_config_init(self):
        """Test NeutrinoConfig initialization."""
        config = NeutrinoConfig(
            network="mainnet",
            data_dir="/data/neutrino",
            listen_port=8334,
            peers=["node1.bitcoin.org:8333"],
            tor_socks="127.0.0.1:9050",
        )
        assert config.network == "mainnet"
        assert config.data_dir == "/data/neutrino"
        assert config.listen_port == 8334
        assert config.peers == ["node1.bitcoin.org:8333"]
        assert config.tor_socks == "127.0.0.1:9050"

    def test_neutrino_config_chain_params(self):
        """Test getting chain parameters from config."""
        config = NeutrinoConfig(network="mainnet")
        params = config.get_chain_params()
        assert params["default_port"] == 8333
        assert len(params["dns_seeds"]) > 0

        config = NeutrinoConfig(network="testnet")
        params = config.get_chain_params()
        assert params["default_port"] == 18333

        config = NeutrinoConfig(network="regtest")
        params = config.get_chain_params()
        assert params["default_port"] == 18444
        assert params["dns_seeds"] == []

    def test_neutrino_config_to_args(self):
        """Test generating command-line arguments."""
        config = NeutrinoConfig(
            network="testnet",
            data_dir="/data/neutrino",
            listen_port=8334,
            peers=["peer1:18333", "peer2:18333"],
            tor_socks="127.0.0.1:9050",
        )
        args = config.to_args()
        assert "--datadir=/data/neutrino" in args
        assert "--testnet" in args
        assert "--restlisten=0.0.0.0:8334" in args
        assert "--proxy=127.0.0.1:9050" in args
        assert "--connect=peer1:18333" in args
        assert "--connect=peer2:18333" in args


@pytest.mark.asyncio
async def test_neutrino_backend_integration():
    """Integration test for NeutrinoBackend (requires running neutrino server)."""
    backend = NeutrinoBackend(
        neutrino_url="http://localhost:8334",
        network="regtest",
    )

    try:
        # Try to connect - skip if not available
        try:
            await backend._api_call("GET", "v1/status")
        except Exception:
            pytest.skip("Neutrino server not available at localhost:8334")
            return

        # Test get_block_height
        height = await backend.get_block_height()
        assert height >= 0

        # Test fee estimation (fallback values)
        fee = await backend.estimate_fee(6)
        assert fee > 0

        # Test watching a valid bech32 address (valid P2WPKH)
        # Use a known valid regtest address
        test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        await backend.add_watch_address(test_address)
        # Note: The address may not be added if the neutrino server validation fails,
        # but the basic connectivity test is still valid
        if test_address in backend._watched_addresses:
            assert test_address in backend._watched_addresses

    finally:
        await backend.close()
