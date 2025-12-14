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
        """Test adding addresses to watch list (without server)."""
        backend = NeutrinoBackend(neutrino_url="http://localhost:8334")

        # Without a running server, the API call will fail and address won't be added
        # This test verifies the method handles failures gracefully
        address = "bcrt1q0000000000000000000000000000000000000"
        try:
            await backend.add_watch_address(address)
        except Exception:
            pass  # Expected to fail without server

        # Address should NOT be in watched set because API call failed
        # The actual addition happens only on successful API response
        assert len(backend._watched_addresses) == 0
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

        # Test watching an address
        test_address = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmkwh5m"
        await backend.add_watch_address(test_address)
        assert test_address in backend._watched_addresses

    finally:
        await backend.close()
