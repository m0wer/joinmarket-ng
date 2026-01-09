"""
Tests for DescriptorWalletBackend.

Unit tests mock Bitcoin Core RPC responses.
Integration tests (marked with @pytest.mark.docker) require a running Bitcoin Core instance.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from jmwallet.backends.descriptor_wallet import (
    DescriptorWalletBackend,
    generate_wallet_name,
    get_mnemonic_fingerprint,
)


class TestDescriptorWalletBackendUnit:
    """Unit tests for DescriptorWalletBackend (no Docker required)."""

    def test_init(self):
        """Test backend initialization."""
        backend = DescriptorWalletBackend(
            rpc_url="http://localhost:18443",
            rpc_user="test",
            rpc_password="test",
            wallet_name="test_wallet",
        )
        assert backend.rpc_url == "http://localhost:18443"
        assert backend.wallet_name == "test_wallet"
        assert backend._wallet_loaded is False
        assert backend._descriptors_imported is False

    def test_get_wallet_url(self):
        """Test wallet-specific URL generation."""
        backend = DescriptorWalletBackend(
            rpc_url="http://localhost:18443",
            wallet_name="my_wallet",
        )
        assert backend._get_wallet_url() == "http://localhost:18443/wallet/my_wallet"

    @pytest.mark.asyncio
    async def test_create_wallet_already_loaded(self):
        """Test create_wallet when wallet is already loaded."""
        backend = DescriptorWalletBackend(wallet_name="existing_wallet")
        backend._rpc_call = AsyncMock(return_value=["existing_wallet", "other_wallet"])

        result = await backend.create_wallet()

        assert result is True
        assert backend._wallet_loaded is True
        backend._rpc_call.assert_called_once_with("listwallets", use_wallet=False)

    @pytest.mark.asyncio
    async def test_create_wallet_load_existing(self):
        """Test create_wallet loading an existing wallet file."""
        backend = DescriptorWalletBackend(wallet_name="stored_wallet")

        call_count = 0

        async def mock_rpc(method, params=None, use_wallet=None, client=None):
            nonlocal call_count
            call_count += 1
            if method == "listwallets":
                return []  # Not loaded
            elif method == "loadwallet":
                return {"name": "stored_wallet"}
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        result = await backend.create_wallet()

        assert result is True
        assert backend._wallet_loaded is True

    @pytest.mark.asyncio
    async def test_create_wallet_new(self):
        """Test create_wallet creating a new wallet."""
        backend = DescriptorWalletBackend(wallet_name="new_wallet")

        async def mock_rpc(method, params=None, use_wallet=None, client=None):
            if method == "listwallets":
                return []
            elif method == "loadwallet":
                raise ValueError("Wallet not found")
            elif method == "createwallet":
                # Verify descriptor wallet params
                assert params[0] == "new_wallet"  # wallet_name
                assert params[1] is True  # disable_private_keys
                assert params[2] is True  # blank
                assert params[5] is True  # descriptors (MUST be True)
                return {"name": "new_wallet", "warning": ""}
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        result = await backend.create_wallet()

        assert result is True
        assert backend._wallet_loaded is True

    @pytest.mark.asyncio
    async def test_import_descriptors(self):
        """Test importing descriptors into wallet."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        descriptors = [
            {"desc": "wpkh(xpub.../0/*)", "range": [0, 999]},
            {"desc": "wpkh(xpub.../1/*)", "range": [0, 999]},
        ]

        async def mock_rpc(method, params=None, use_wallet=None, client=None):
            if method == "getdescriptorinfo":
                # Return descriptor with checksum
                desc = params[0]
                return {"descriptor": f"{desc}#abcd1234"}
            elif method == "importdescriptors":
                import_reqs = params[0]
                # Return success for all
                return [{"success": True} for _ in import_reqs]
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        result = await backend.import_descriptors(descriptors)

        assert result["success_count"] == 2
        assert result["error_count"] == 0
        assert backend._descriptors_imported is True

    @pytest.mark.asyncio
    async def test_import_descriptors_partial_failure(self):
        """Test importing descriptors with some failures."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        descriptors = ["desc1", "desc2", "desc3"]

        async def mock_rpc(method, params=None, use_wallet=None, client=None):
            if method == "getdescriptorinfo":
                return {"descriptor": f"{params[0]}#check"}
            elif method == "importdescriptors":
                return [
                    {"success": True},
                    {"success": False, "error": {"message": "Invalid descriptor"}},
                    {"success": True},
                ]
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        result = await backend.import_descriptors(descriptors)

        assert result["success_count"] == 2
        assert result["error_count"] == 1

    @pytest.mark.asyncio
    async def test_import_descriptors_wallet_not_loaded(self):
        """Test import_descriptors raises error if wallet not loaded."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = False

        with pytest.raises(RuntimeError, match="Wallet not loaded"):
            await backend.import_descriptors(["desc1"])

    @pytest.mark.asyncio
    async def test_get_utxos(self):
        """Test getting UTXOs via listunspent."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        mock_utxos = [
            {
                "txid": "abc123",
                "vout": 0,
                "amount": 0.01,
                "address": "bc1qtest1",
                "confirmations": 6,
                "scriptPubKey": "0014...",
            },
            {
                "txid": "def456",
                "vout": 1,
                "amount": 0.02,
                "address": "bc1qtest2",
                "confirmations": 0,  # Unconfirmed
                "scriptPubKey": "0014...",
            },
        ]

        backend._rpc_call = AsyncMock(return_value=mock_utxos)

        utxos = await backend.get_utxos(["bc1qtest1", "bc1qtest2"])

        assert len(utxos) == 2
        assert utxos[0].txid == "abc123"
        assert utxos[0].value == 1_000_000  # 0.01 BTC in sats
        assert utxos[0].confirmations == 6
        assert utxos[1].txid == "def456"
        assert utxos[1].value == 2_000_000
        assert utxos[1].confirmations == 0  # Unconfirmed visible

    @pytest.mark.asyncio
    async def test_get_utxos_filter_addresses(self):
        """Test that get_utxos filters by address when provided."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        mock_utxos = [
            {"txid": "abc", "vout": 0, "amount": 0.01, "address": "bc1qtest1", "confirmations": 1},
            {"txid": "def", "vout": 0, "amount": 0.02, "address": "bc1qtest2", "confirmations": 1},
            {"txid": "ghi", "vout": 0, "amount": 0.03, "address": "bc1qtest3", "confirmations": 1},
        ]

        backend._rpc_call = AsyncMock(return_value=mock_utxos)

        # Filter to only bc1qtest1
        utxos = await backend.get_utxos(["bc1qtest1"])

        assert len(utxos) == 1
        assert utxos[0].address == "bc1qtest1"

    @pytest.mark.asyncio
    async def test_get_wallet_balance(self):
        """Test getting wallet balance."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        mock_balances = {
            "mine": {
                "trusted": 1.5,
                "untrusted_pending": 0.1,
            }
        }

        backend._rpc_call = AsyncMock(return_value=mock_balances)

        balance = await backend.get_wallet_balance()

        assert balance["confirmed"] == 150_000_000  # 1.5 BTC in sats
        assert balance["unconfirmed"] == 10_000_000  # 0.1 BTC in sats
        assert balance["total"] == 160_000_000

    @pytest.mark.asyncio
    async def test_get_transaction_from_wallet(self):
        """Test getting transaction that exists in wallet."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        mock_tx = {
            "confirmations": 10,
            "blockheight": 800000,
            "blocktime": 1700000000,
            "hex": "0100000001...",
        }

        backend._rpc_call = AsyncMock(return_value=mock_tx)

        tx = await backend.get_transaction("txid123")

        assert tx is not None
        assert tx.txid == "txid123"
        assert tx.confirmations == 10
        assert tx.block_height == 800000

    @pytest.mark.asyncio
    async def test_rescan_blockchain(self):
        """Test blockchain rescan."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        backend._rpc_call = AsyncMock(return_value={"start_height": 0, "stop_height": 800000})

        result = await backend.rescan_blockchain(start_height=700000)

        assert result["start_height"] == 0
        backend._rpc_call.assert_called()

    def test_can_provide_neutrino_metadata(self):
        """Test that backend can provide Neutrino metadata."""
        backend = DescriptorWalletBackend()
        assert backend.can_provide_neutrino_metadata() is True


class TestWalletNameGeneration:
    """Tests for wallet name generation utilities."""

    def test_get_mnemonic_fingerprint(self):
        """Test mnemonic fingerprint generation."""
        mnemonic = "abandon " * 11 + "about"
        fp = get_mnemonic_fingerprint(mnemonic)

        assert len(fp) == 8
        assert fp.isalnum()

        # Same mnemonic should give same fingerprint
        assert get_mnemonic_fingerprint(mnemonic) == fp

        # Different mnemonic should give different fingerprint
        other = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        assert get_mnemonic_fingerprint(other) != fp

    def test_generate_wallet_name(self):
        """Test wallet name generation."""
        name = generate_wallet_name("abc12345", "mainnet")
        assert name == "jm_abc12345_mainnet"

        name = generate_wallet_name("def67890", "testnet")
        assert name == "jm_def67890_testnet"

        name = generate_wallet_name("xyz00000", "regtest")
        assert name == "jm_xyz00000_regtest"


@pytest.mark.docker
@pytest.mark.docker
@pytest.mark.asyncio
async def test_descriptor_wallet_backend_integration():
    """Integration test requiring Docker Bitcoin Core service."""
    import uuid

    # Use unique wallet name to avoid conflicts
    wallet_name = f"jm_test_{uuid.uuid4().hex[:8]}"

    backend = DescriptorWalletBackend(
        rpc_url="http://localhost:18443",
        rpc_user="test",
        rpc_password="test",
        wallet_name=wallet_name,
    )

    try:
        # Check connection first
        try:
            height = await backend.get_block_height()
            assert height >= 0
        except Exception:
            pytest.skip(
                "Bitcoin Core not available at localhost:18443. "
                "Start with: docker compose up -d bitcoin"
            )
            return

        # Create wallet
        result = await backend.create_wallet(disable_private_keys=True)
        assert result is True
        assert backend._wallet_loaded is True

        # Import a simple descriptor
        # Using a test xpub (this won't have funds, just testing the import)
        test_xpub = (
            "tpubDDXgATYzdQkHHhZZCMcNJj2GbJEvT2SL9cneXCAP9MkLB9YZovvAfTpPN82"
            "PmFqpU72KcYwzACvnwBmUVPF7rtYKPwjsb1vSazJJGMjv2LT"
        )
        descriptors = [
            {"desc": f"wpkh({test_xpub}/0/*)", "range": [0, 10]},
        ]

        import_result = await backend.import_descriptors(descriptors, rescan=False)
        assert import_result["success_count"] >= 1

        # Test listunspent (should return empty for this test wallet)
        utxos = await backend.get_utxos([])
        assert isinstance(utxos, list)

        # Test balance
        balance = await backend.get_wallet_balance()
        assert "total" in balance

        # Test fee estimation
        fee = await backend.estimate_fee(6)
        assert isinstance(fee, float)

    finally:
        # Cleanup: unload wallet
        try:
            await backend.unload_wallet()
        except Exception:
            pass
        await backend.close()


@pytest.mark.docker
@pytest.mark.asyncio
async def test_descriptor_wallet_with_funds():
    """Test descriptor wallet with actual funded addresses.

    This test:
    1. Creates a descriptor wallet
    2. Generates an address
    3. Mines to that address
    4. Verifies UTXO is visible via listunspent
    """
    import uuid

    wallet_name = f"jm_funded_{uuid.uuid4().hex[:8]}"

    # Create backend WITHOUT disable_private_keys so we can generate addresses
    backend = DescriptorWalletBackend(
        rpc_url="http://localhost:18443",
        rpc_user="test",
        rpc_password="test",
        wallet_name=wallet_name,
    )

    try:
        # Check connection
        try:
            await backend.get_block_height()
        except Exception:
            pytest.skip("Bitcoin Core not available")
            return

        # Create wallet with private keys enabled for address generation
        await backend._rpc_call(
            "createwallet",
            [wallet_name, False, False, "", False, True],  # descriptors=True
            use_wallet=False,
        )
        backend._wallet_loaded = True

        # Generate a new address from the wallet
        address = await backend.get_new_address("bech32")
        assert address.startswith("bcrt1")

        # Mine a block to this address
        await backend._rpc_call("generatetoaddress", [1, address], use_wallet=False)

        # Mine more blocks to make UTXO spendable (100 confirmations for coinbase)
        # For this test, we just need 1 block, the UTXO should be visible
        await backend._rpc_call(
            "generatetoaddress",
            [100, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"],
            use_wallet=False,
        )

        # Check UTXOs
        utxos = await backend.get_utxos([address])
        assert len(utxos) >= 1
        assert utxos[0].address == address
        assert utxos[0].value > 0  # Should have coinbase reward

        # Check balance
        balance = await backend.get_wallet_balance()
        assert balance["total"] > 0

    finally:
        try:
            await backend.unload_wallet()
        except Exception:
            pass
        await backend.close()
