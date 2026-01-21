"""
Tests for DescriptorWalletBackend.

Unit tests mock Bitcoin Core RPC responses.
Integration tests (marked with @pytest.mark.docker) require a running Bitcoin Core instance.
"""

from __future__ import annotations

from typing import Any
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

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
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

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
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
    async def test_create_wallet_http_500_with_rpc_error(self):
        """Test create_wallet handles HTTP 500 with JSON-RPC error correctly."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")

        call_count = 0

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
            nonlocal call_count
            call_count += 1
            if method == "listwallets":
                return []
            elif method == "loadwallet":
                # Simulate Bitcoin Core returning 500 status but with valid JSON-RPC error
                # This should be converted to ValueError by the fixed _rpc_call
                raise ValueError("RPC error -18: Wallet file verification failed")
            elif method == "createwallet":
                return {"name": "test_wallet", "warning": ""}
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        result = await backend.create_wallet()

        assert result is True
        assert backend._wallet_loaded is True
        # Should have called: listwallets, loadwallet (failed), createwallet
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_import_descriptors(self):
        """Test importing descriptors into wallet."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        descriptors = [
            {"desc": "wpkh(xpub.../0/*)", "range": [0, 999]},
            {"desc": "wpkh(xpub.../1/*)", "range": [0, 999]},
        ]

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
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

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
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
    async def test_import_descriptors_rescan_timestamps(self):
        """Test that rescan parameter correctly sets timestamp."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        captured_requests = []

        async def mock_rpc(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "getdescriptorinfo":
                return {"descriptor": f"{params[0]}#check"}  # type: ignore
            elif method == "importdescriptors":
                # Capture the import requests to verify timestamp
                captured_requests.extend(params[0])  # type: ignore
                return [{"success": True} for _ in params[0]]  # type: ignore
            elif method == "listdescriptors":
                return {"descriptors": [{"desc": "test"}]}
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc  # type: ignore

        # Test rescan=True (should use timestamp=0)
        captured_requests.clear()
        await backend.import_descriptors(["desc1"], rescan=True)
        assert len(captured_requests) == 1
        assert captured_requests[0]["timestamp"] == 0, "rescan=True should use timestamp=0"

        # Test rescan=False (should use timestamp="now")
        captured_requests.clear()
        await backend.import_descriptors(["desc2"], rescan=False)
        assert len(captured_requests) == 1
        assert captured_requests[0]["timestamp"] == "now", "rescan=False should use timestamp='now'"

        # Test explicit timestamp override
        captured_requests.clear()
        await backend.import_descriptors(["desc3"], rescan=True, timestamp=1234567890)
        assert len(captured_requests) == 1
        assert captured_requests[0]["timestamp"] == 1234567890, (
            "explicit timestamp should override rescan"
        )

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

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
            if method == "getblockchaininfo":
                return {"blocks": 1000}
            elif method == "listunspent":
                return mock_utxos
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        utxos = await backend.get_utxos(["bc1qtest1", "bc1qtest2"])

        assert len(utxos) == 2
        assert utxos[0].txid == "abc123"
        assert utxos[0].value == 1_000_000  # 0.01 BTC in sats
        assert utxos[0].confirmations == 6
        # height = tip (1000) - confirmations (6) + 1 = 995
        assert utxos[0].height == 995

        assert utxos[1].txid == "def456"
        assert utxos[1].value == 2_000_000
        assert utxos[1].confirmations == 0  # Unconfirmed visible
        assert utxos[1].height is None

    @pytest.mark.asyncio
    async def test_get_utxos_filter_addresses(self):
        """Test that get_utxos passes addresses to Bitcoin Core for filtering.

        When addresses are provided, we pass them to listunspent RPC and Bitcoin Core
        does the filtering. The mock simulates Bitcoin Core's behavior of returning
        only matching UTXOs.
        """
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        # Simulate Bitcoin Core returning only the filtered UTXO
        # (Bitcoin Core does the filtering when addresses are provided)
        filtered_utxos = [
            {"txid": "abc", "vout": 0, "amount": 0.01, "address": "bc1qtest1", "confirmations": 1},
        ]

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
            if method == "getblockchaininfo":
                return {"blocks": 1000}
            elif method == "listunspent":
                # Verify that addresses are passed to Bitcoin Core
                assert params is not None
                assert len(params) >= 3, "Should have minconf, maxconf, addresses"
                addresses = params[2]
                assert addresses == ["bc1qtest1"], "Should pass addresses to Bitcoin Core"
                return filtered_utxos
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        # Filter to only bc1qtest1
        utxos = await backend.get_utxos(["bc1qtest1"])

        assert len(utxos) == 1
        assert utxos[0].address == "bc1qtest1"
        assert utxos[0].height == 1000  # 1000 - 1 + 1

    @pytest.mark.asyncio
    async def test_get_utxos_no_filter(self):
        """Test that get_utxos returns all UTXOs when no addresses provided.

        When addresses list is empty, we omit the addresses parameter entirely
        so Bitcoin Core returns all wallet UTXOs.
        """
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._wallet_loaded = True

        all_utxos = [
            {"txid": "abc", "vout": 0, "amount": 0.01, "address": "bc1qtest1", "confirmations": 1},
            {"txid": "def", "vout": 0, "amount": 0.02, "address": "bc1qtest2", "confirmations": 1},
            {"txid": "ghi", "vout": 0, "amount": 0.03, "address": "bc1qtest3", "confirmations": 1},
        ]

        async def mock_rpc(method, params=None, client=None, use_wallet=True):
            if method == "getblockchaininfo":
                return {"blocks": 1000}
            elif method == "listunspent":
                # When no addresses, params should only have minconf and maxconf
                assert params is not None
                assert len(params) == 2, f"Should only have minconf, maxconf but got {params}"
                return all_utxos
            raise ValueError(f"Unexpected method: {method}")

        backend._rpc_call = mock_rpc

        # Get all UTXOs (empty address list)
        utxos = await backend.get_utxos([])

        assert len(utxos) == 3

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

    @pytest.mark.asyncio
    async def test_list_descriptors(self):
        """Test listing descriptors from wallet."""
        backend = DescriptorWalletBackend()
        backend._wallet_loaded = True
        backend._rpc_call = AsyncMock(
            return_value={
                "descriptors": [
                    {"desc": "wpkh(xpub.../0/*)#checksum", "active": True},
                    {"desc": "wpkh(xpub.../1/*)#checksum", "active": True},
                ]
            }
        )

        descriptors = await backend.list_descriptors()
        assert len(descriptors) == 2
        assert descriptors[0]["desc"].startswith("wpkh")
        assert descriptors[0]["active"] is True

    @pytest.mark.asyncio
    async def test_is_wallet_setup_true(self):
        """Test checking if wallet is set up (positive case)."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._rpc_call = AsyncMock(
            side_effect=[
                ["test_wallet"],  # listwallets
                {
                    "descriptors": [
                        {"desc": "wpkh(xpub.../0/*)#checksum", "active": True},
                        {"desc": "wpkh(xpub.../1/*)#checksum", "active": True},
                    ]
                },  # listdescriptors
            ]
        )

        is_ready = await backend.is_wallet_setup(expected_descriptor_count=2)
        assert is_ready is True

    @pytest.mark.asyncio
    async def test_is_wallet_setup_false_no_wallet(self):
        """Test checking if wallet is set up (wallet doesn't exist)."""
        backend = DescriptorWalletBackend(wallet_name="nonexistent")
        backend._rpc_call = AsyncMock(
            side_effect=[
                [],  # listwallets - wallet not loaded
                ValueError("Wallet file verification failed"),  # loadwallet fails
            ]
        )

        is_ready = await backend.is_wallet_setup()
        assert is_ready is False

    @pytest.mark.asyncio
    async def test_is_wallet_setup_false_no_descriptors(self):
        """Test checking if wallet is set up (wallet exists but no descriptors)."""
        backend = DescriptorWalletBackend(wallet_name="test_wallet")
        backend._rpc_call = AsyncMock(
            side_effect=[
                ["test_wallet"],  # listwallets
                {"descriptors": []},  # listdescriptors - empty
            ]
        )

        is_ready = await backend.is_wallet_setup()
        assert is_ready is False


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
        # Using a known valid testnet xpub from BIP32 test vectors
        # This won't have funds, just testing the import mechanism
        test_xpub = (
            "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1Rh"
            "GjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"
        )
        # Bitcoin Core will add checksum automatically via getdescriptorinfo
        descriptors = [
            {"desc": f"wpkh({test_xpub}/0/*)", "range": [0, 10], "timestamp": "now"},
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


@pytest.mark.docker
@pytest.mark.asyncio
async def test_descriptor_wallet_service_integration():
    """Test WalletService with DescriptorWalletBackend - full workflow.

    This test validates the complete flow:
    1. Create a WalletService with DescriptorWalletBackend
    2. Check if descriptor wallet is ready
    3. Setup descriptor wallet (import descriptors)
    4. Verify descriptors were imported
    5. Sync wallet and find UTXOs
    """
    import uuid

    from jmwallet.backends.descriptor_wallet import (
        get_mnemonic_fingerprint,
    )
    from jmwallet.wallet.service import WalletService

    # Use the standard test mnemonic which has funds in regtest
    mnemonic = "abandon " * 11 + "about"
    network = "regtest"

    # Generate deterministic wallet name
    fingerprint = get_mnemonic_fingerprint(mnemonic, "")
    # Use unique suffix to avoid conflicts with other tests
    wallet_name = f"jm_{fingerprint}_{uuid.uuid4().hex[:8]}_test"

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

        # Create wallet service
        wallet = WalletService(
            mnemonic=mnemonic,
            backend=backend,
            network=network,
            mixdepth_count=5,
            passphrase="",
        )

        # Check initial state - wallet should not be ready
        is_ready = await wallet.is_descriptor_wallet_ready()
        assert is_ready is False, "Fresh wallet should not be ready"

        # Setup descriptor wallet
        setup_result = await wallet.setup_descriptor_wallet(rescan=False)
        assert setup_result is True

        # Verify wallet is now ready
        is_ready = await wallet.is_descriptor_wallet_ready()
        assert is_ready is True, "Wallet should be ready after setup"

        # Verify descriptors were actually imported
        descriptors = await backend.list_descriptors()
        assert len(descriptors) >= 10, (
            f"Expected 10 descriptors (5 mixdepths x 2), got {len(descriptors)}"
        )

        # Sync wallet using descriptor wallet method
        await wallet.sync_with_descriptor_wallet()

        # The test mnemonic should have UTXOs in mixdepth 0 (from regtest funder)
        total_balance = await wallet.get_total_balance()
        # Note: May or may not have funds depending on test order
        # Just verify the sync completed without error
        assert total_balance >= 0

        # Verify first address matches expected derivation
        first_addr = wallet.get_receive_address(0, 0)
        assert first_addr.startswith("bcrt1"), f"Expected regtest address, got {first_addr}"

    finally:
        try:
            await backend.unload_wallet()
        except Exception:
            pass
        await backend.close()


# =============================================================================
# Smart Scan Tests
# =============================================================================


class TestSmartScan:
    """Tests for smart scan timestamp calculation."""

    @pytest.mark.asyncio
    async def test_smart_scan_timestamp_calculation(self) -> None:
        """Test that smart scan calculates timestamp correctly."""
        backend = DescriptorWalletBackend(wallet_name="test_smart_scan")

        rpc_calls: list[tuple[str, list[Any] | None]] = []

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            rpc_calls.append((method, params))
            if method == "getblockchaininfo":
                return {"blocks": 100_000, "headers": 100_000}
            elif method == "getblockhash":
                return "000000000000abcd1234"
            elif method == "getblockheader":
                return {"time": 1700000000}
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        # Default lookback is 52,560 blocks (~1 year)
        # Current height: 100,000, lookback: 52,560 -> target: 47,440
        timestamp = await backend._get_smart_scan_timestamp()

        # Verify the RPC calls
        method_names = [call[0] for call in rpc_calls]
        assert "getblockchaininfo" in method_names
        assert "getblockhash" in method_names
        assert "getblockheader" in method_names
        # Check getblockhash was called with correct height
        getblockhash_calls = [call for call in rpc_calls if call[0] == "getblockhash"]
        assert getblockhash_calls[0][1] == [47_440]
        assert timestamp == 1700000000

    @pytest.mark.asyncio
    async def test_smart_scan_clamps_to_zero(self) -> None:
        """Test that smart scan clamps to block 0 for short chains."""
        backend = DescriptorWalletBackend(wallet_name="test_clamp")

        rpc_calls: list[tuple[str, list[Any] | None]] = []

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            rpc_calls.append((method, params))
            if method == "getblockchaininfo":
                return {"blocks": 1000, "headers": 1000}
            elif method == "getblockhash":
                return "0000000000genesis"
            elif method == "getblockheader":
                return {"time": 1231006505}  # Genesis time
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        timestamp = await backend._get_smart_scan_timestamp()

        # 1000 - 52560 = negative, should clamp to 0
        getblockhash_calls = [call for call in rpc_calls if call[0] == "getblockhash"]
        assert getblockhash_calls[0][1] == [0]
        assert timestamp == 1231006505


# =============================================================================
# Background Rescan Tests
# =============================================================================


class TestBackgroundRescan:
    """Tests for background rescan functionality."""

    @pytest.mark.asyncio
    async def test_start_background_rescan(self) -> None:
        """Test that background rescan is started correctly."""
        backend = DescriptorWalletBackend(wallet_name="test_rescan")
        backend._wallet_loaded = True

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "rescanblockchain":
                return {"start_height": 0, "stop_height": 100000}
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        await backend.start_background_rescan()

        assert backend.is_background_rescan_pending() is True

    @pytest.mark.asyncio
    async def test_rescan_status_not_scanning(self) -> None:
        """Test rescan status when not scanning."""
        backend = DescriptorWalletBackend(wallet_name="test_status")
        backend._wallet_loaded = True

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "getwalletinfo":
                return {"scanning": False, "walletname": "test_wallet"}
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        status = await backend.get_rescan_status()

        assert status is not None
        assert status["in_progress"] is False

    @pytest.mark.asyncio
    async def test_rescan_status_while_scanning(self) -> None:
        """Test rescan status during active scan."""
        backend = DescriptorWalletBackend(wallet_name="test_scanning")
        backend._wallet_loaded = True

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "getwalletinfo":
                return {
                    "scanning": {"duration": 120, "progress": 0.45},
                    "walletname": "test_wallet",
                }
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        status = await backend.get_rescan_status()

        assert status is not None
        assert status["in_progress"] is True
        assert status["progress"] == 0.45
        assert status["duration"] == 120

    @pytest.mark.asyncio
    async def test_import_with_smart_scan_and_background_rescan(self) -> None:
        """Test import_descriptors with smart scan and background rescan enabled."""
        backend = DescriptorWalletBackend(wallet_name="test_smart_background")
        backend._wallet_loaded = True

        rpc_calls: list[tuple[str, list[Any] | None]] = []

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            rpc_calls.append((method, params))
            if method == "getblockchaininfo":
                return {"blocks": 100_000, "headers": 100_000}
            elif method == "getblockhash":
                return "00000000hash"
            elif method == "getblock":
                return {"time": 1700000000}
            elif method == "importdescriptors":
                return [{"success": True}]
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        await backend.import_descriptors(
            descriptors=[
                {
                    "desc": "wpkh([fingerprint/84'/1'/0'/0/0]xpub...)#checksum",
                    "active": True,
                    "range": [0, 999],
                    "timestamp": "now",
                }
            ],
            smart_scan=True,
            background_full_rescan=True,
        )

        # Should have called getblockchaininfo for smart scan
        method_names = [call[0] for call in rpc_calls]
        assert "getblockchaininfo" in method_names

        # Background rescan should be pending
        assert backend.is_background_rescan_pending() is True


# =============================================================================
# Fidelity Bond Sync Tests
# =============================================================================


class TestFidelityBondSync:
    """Tests for syncing fidelity bonds with descriptor wallet backend."""

    @pytest.mark.asyncio
    async def test_sync_with_fidelity_bonds(self) -> None:
        """Test that sync_with_descriptor_wallet correctly handles fidelity bond addresses."""
        from jmwallet.backends.base import UTXO
        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
        from jmwallet.wallet.service import WalletService

        # Create backend with mock
        backend = DescriptorWalletBackend(wallet_name="test_fb_sync")
        backend._wallet_loaded = True
        backend._descriptors_imported = True

        # Mock the bond address and UTXO
        bond_address = "bc1qxl3vzaf0cxwl9c0jsyyphwdekc6j0xh48qlfv8ja39qzqn92u7ws5arznw"
        bond_locktime = 1736899200  # 2025-01-15 00:00:00 UTC
        bond_index = 0
        bond_value = 29890

        # Mock get_all_utxos to return both regular and bond UTXOs
        async def mock_get_all_utxos() -> list[UTXO]:
            return [
                # Regular wallet UTXO
                UTXO(
                    txid="abc123" * 10 + "ab",
                    vout=0,
                    value=100000,
                    address="bc1qregularaddress123",
                    confirmations=100,
                    scriptpubkey="0014regular",
                ),
                # Fidelity bond UTXO (P2WSH)
                UTXO(
                    txid="def456" * 10 + "de",
                    vout=1,
                    value=bond_value,
                    address=bond_address,
                    confirmations=50,
                    scriptpubkey="0020" + "a" * 64,  # P2WSH scriptPubKey
                ),
            ]

        backend.get_all_utxos = mock_get_all_utxos  # type: ignore[method-assign]

        # Create wallet service with test mnemonic
        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Sync with fidelity bond addresses
        fidelity_bond_addresses = [(bond_address, bond_locktime, bond_index)]
        result = await wallet.sync_with_descriptor_wallet(fidelity_bond_addresses)

        # Verify that the bond UTXO was found in mixdepth 0
        mixdepth_0_utxos = result.get(0, [])

        # Find the bond UTXO in the results
        bond_utxos = [u for u in mixdepth_0_utxos if u.address == bond_address]
        assert len(bond_utxos) == 1, f"Expected 1 bond UTXO, found {len(bond_utxos)}"

        bond_utxo = bond_utxos[0]
        assert bond_utxo.value == bond_value
        assert bond_utxo.locktime == bond_locktime
        assert bond_utxo.is_timelocked is True

    @pytest.mark.asyncio
    async def test_sync_without_fidelity_bonds(self) -> None:
        """Test that sync_with_descriptor_wallet works without fidelity bonds."""
        from jmwallet.backends.base import UTXO
        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_no_fb")
        backend._wallet_loaded = True
        backend._descriptors_imported = True

        # Mock get_all_utxos to return regular UTXOs only
        async def mock_get_all_utxos() -> list[UTXO]:
            return [
                UTXO(
                    txid="abc123" * 10 + "ab",
                    vout=0,
                    value=100000,
                    address="bc1qregularaddress123",
                    confirmations=100,
                    scriptpubkey="0014regular",
                ),
            ]

        backend.get_all_utxos = mock_get_all_utxos  # type: ignore[method-assign]

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Sync without fidelity bonds
        result = await wallet.sync_with_descriptor_wallet()

        # Should complete without error
        assert result is not None

    @pytest.mark.asyncio
    async def test_setup_descriptor_wallet_with_fidelity_bonds(self) -> None:
        """Test that setup_descriptor_wallet imports fidelity bond addresses."""
        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_setup_fb")

        imported_descriptors: list[dict[str, Any]] = []

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listwallets":
                return ["test_setup_fb"]
            elif method == "listdescriptors":
                return {"descriptors": []}  # No descriptors yet
            elif method == "importdescriptors":
                if params:
                    imported_descriptors.extend(params[0])
                return [{"success": True} for _ in params[0]] if params else []
            elif method == "getblockchaininfo":
                return {"blocks": 100000}
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]
        backend._wallet_loaded = True

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Setup with fidelity bond addresses
        bond_address = "bc1qxl3vzaf0cxwl9c0jsyyphwdekc6j0xh48qlfv8ja39qzqn92u7ws5arznw"
        bond_locktime = 1736899200
        bond_index = 0
        fidelity_bond_addresses = [(bond_address, bond_locktime, bond_index)]

        await wallet.setup_descriptor_wallet(
            rescan=False,
            fidelity_bond_addresses=fidelity_bond_addresses,
            check_existing=False,
        )

        # Verify that bond address was imported
        imported_descs_strs = [str(d.get("desc", "")) for d in imported_descriptors]
        bond_desc_imported = any(bond_address in desc for desc in imported_descs_strs)
        assert bond_desc_imported, (
            f"Bond address {bond_address} not found in imported descriptors: {imported_descs_strs}"
        )


# =============================================================================
# Address History Tests
# =============================================================================


class TestAddressHistory:
    """Tests for tracking address history including spent addresses."""

    @pytest.mark.asyncio
    async def test_get_addresses_with_history(self) -> None:
        """Test that get_addresses_with_history returns all addresses with transaction history."""
        backend = DescriptorWalletBackend(wallet_name="test_addr_history")
        backend._wallet_loaded = True

        mock_transactions = [
            {
                "address": "bc1qtest1",
                "category": "receive",
                "amount": 0.01,
                "txid": "abc123",
            },
            {
                "address": "bc1qtest2",
                "category": "receive",
                "amount": 0.02,
                "txid": "def456",
            },
            {
                "address": "bc1qtest1",  # Same address, second tx
                "category": "send",
                "amount": -0.01,
                "txid": "ghi789",
            },
            {
                "address": "bc1qtest3",
                "category": "receive",
                "amount": 0.03,
                "txid": "jkl012",
            },
        ]

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listtransactions":
                return mock_transactions
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        addresses = await backend.get_addresses_with_history()

        # Should have 3 unique addresses
        assert len(addresses) == 3
        assert "bc1qtest1" in addresses
        assert "bc1qtest2" in addresses
        assert "bc1qtest3" in addresses

    @pytest.mark.asyncio
    async def test_get_addresses_with_history_empty(self) -> None:
        """Test get_addresses_with_history with no transactions."""
        backend = DescriptorWalletBackend(wallet_name="test_empty_history")
        backend._wallet_loaded = True

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listtransactions":
                return []
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        addresses = await backend.get_addresses_with_history()

        assert len(addresses) == 0

    @pytest.mark.asyncio
    async def test_get_addresses_with_history_filters_categories(self) -> None:
        """Test that get_addresses_with_history only includes receive/send/generate."""
        backend = DescriptorWalletBackend(wallet_name="test_filter_history")
        backend._wallet_loaded = True

        mock_transactions = [
            {
                "address": "bc1qreceive",
                "category": "receive",
                "amount": 0.01,
                "txid": "abc",
            },
            {
                "address": "bc1qsend",
                "category": "send",
                "amount": -0.01,
                "txid": "def",
            },
            {
                "address": "bc1qgenerate",
                "category": "generate",
                "amount": 50.0,
                "txid": "ghi",
            },
            {
                "address": "bc1qimmature",
                "category": "immature",  # Should be excluded
                "amount": 50.0,
                "txid": "jkl",
            },
            {
                "category": "orphan",  # No address, should be skipped
                "amount": 0,
                "txid": "mno",
            },
        ]

        async def mock_rpc(
            method: str,
            params: list[Any] | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listtransactions":
                return mock_transactions
            return {}

        backend._rpc_call = mock_rpc  # type: ignore[method-assign]

        addresses = await backend.get_addresses_with_history()

        # Should have 3 addresses (receive, send, generate) but not immature/orphan
        assert len(addresses) == 3
        assert "bc1qreceive" in addresses
        assert "bc1qsend" in addresses
        assert "bc1qgenerate" in addresses
        assert "bc1qimmature" not in addresses

    @pytest.mark.asyncio
    async def test_sync_populates_addresses_with_history(self) -> None:
        """Test that sync_with_descriptor_wallet populates addresses_with_history."""
        from jmwallet.backends.base import UTXO
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_sync_history")
        backend._wallet_loaded = True
        backend._descriptors_imported = True

        # Address that HAS a UTXO
        addr_with_utxo = "bc1qcurrentutxo"
        # Address that WAS used but now has 0 balance (fully spent)
        addr_spent = "bc1qspentaddr"

        async def mock_get_all_utxos() -> list[UTXO]:
            return [
                UTXO(
                    txid="abc123" * 10 + "ab",
                    vout=0,
                    value=100000,
                    address=addr_with_utxo,
                    confirmations=100,
                    scriptpubkey="0014current",
                ),
            ]

        async def mock_get_addresses_with_history() -> set[str]:
            return {addr_with_utxo, addr_spent}

        backend.get_all_utxos = mock_get_all_utxos  # type: ignore[method-assign]
        backend.get_addresses_with_history = mock_get_addresses_with_history  # type: ignore

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Pre-populate address cache with our test addresses
        # This simulates what _populate_address_cache would do for real addresses
        wallet.address_cache[addr_with_utxo] = (0, 0, 0)
        wallet.address_cache[addr_spent] = (0, 0, 1)

        await wallet.sync_with_descriptor_wallet()

        # Both addresses should be in addresses_with_history
        assert addr_with_utxo in wallet.addresses_with_history
        assert addr_spent in wallet.addresses_with_history


class TestDescriptorRangeUpgrade:
    """Tests for descriptor range detection and upgrade functionality."""

    @pytest.mark.asyncio
    async def test_get_descriptor_ranges(self) -> None:
        """Test getting descriptor ranges from wallet."""
        backend = DescriptorWalletBackend(wallet_name="test_ranges")
        backend._wallet_loaded = True

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listdescriptors":
                return {
                    "descriptors": [
                        {
                            "desc": "wpkh(xpub.../0/*)#checksum",
                            "range": [0, 999],
                        },
                        {
                            "desc": "wpkh(xpub.../1/*)#checksum",
                            "range": [0, 999],
                        },
                        {
                            "desc": "addr(bc1q...)#checksum",
                            # No range for addr() descriptors
                        },
                    ]
                }
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        ranges = await backend.get_descriptor_ranges()

        assert len(ranges) == 2  # Only ranged descriptors
        assert ranges["wpkh(xpub.../0/*)"] == (0, 999)
        assert ranges["wpkh(xpub.../1/*)"] == (0, 999)

    @pytest.mark.asyncio
    async def test_get_max_descriptor_range(self) -> None:
        """Test getting maximum descriptor range."""
        backend = DescriptorWalletBackend(wallet_name="test_max_range")
        backend._wallet_loaded = True

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listdescriptors":
                return {
                    "descriptors": [
                        {"desc": "wpkh(xpub.../0/*)#abc", "range": [0, 4999]},
                        {"desc": "wpkh(xpub.../1/*)#def", "range": [0, 2999]},
                    ]
                }
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        max_range = await backend.get_max_descriptor_range()

        assert max_range == 4999

    @pytest.mark.asyncio
    async def test_get_max_descriptor_range_empty(self) -> None:
        """Test max range returns default when no descriptors."""
        backend = DescriptorWalletBackend(wallet_name="test_empty_range")
        backend._wallet_loaded = True

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listdescriptors":
                return {"descriptors": []}
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        max_range = await backend.get_max_descriptor_range()

        # Should return DEFAULT_GAP_LIMIT
        from jmwallet.backends.descriptor_wallet import DEFAULT_GAP_LIMIT

        assert max_range == DEFAULT_GAP_LIMIT

    @pytest.mark.asyncio
    async def test_upgrade_descriptor_ranges(self) -> None:
        """Test upgrading descriptor ranges."""
        backend = DescriptorWalletBackend(wallet_name="test_upgrade")
        backend._wallet_loaded = True

        import_calls: list[dict] = []

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "getdescriptorinfo":
                desc = params[0] if params else ""
                return {"descriptor": f"{desc}#mockchecksum"}
            if method == "importdescriptors":
                import_calls.append({"method": method, "params": params})
                return [{"success": True}]
            if method == "listdescriptors":
                return {"descriptors": [{"desc": "test", "range": [0, 999]}]}
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        descriptors = [
            {"desc": "wpkh(xpub.../0/*)", "range": [0, 999]},
            {"desc": "wpkh(xpub.../1/*)", "range": [0, 999]},
        ]

        result = await backend.upgrade_descriptor_ranges(descriptors, 4999, rescan=False)

        assert result["success_count"] == 1
        assert len(import_calls) == 1

        # Check that ranges were updated
        imported = import_calls[0]["params"][0]
        assert imported[0]["range"] == [0, 4999]
        assert imported[1]["range"] == [0, 4999]

    @pytest.mark.asyncio
    async def test_check_and_upgrade_descriptor_range_no_upgrade_needed(self) -> None:
        """Test that no upgrade happens when range is sufficient."""
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_no_upgrade")
        backend._wallet_loaded = True
        backend._descriptors_imported = True

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            if method == "listdescriptors":
                return {
                    "descriptors": [
                        {"desc": "wpkh(xpub.../0/*)#abc", "range": [0, 999]},
                    ]
                }
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Set up addresses_with_history with low indices
        wallet.address_cache["bc1q_test1"] = (0, 0, 50)
        wallet.address_cache["bc1q_test2"] = (0, 1, 100)
        wallet.addresses_with_history = {"bc1q_test1", "bc1q_test2"}

        # Current range (999) > highest used (100) + gap_limit (100)
        upgraded = await wallet.check_and_upgrade_descriptor_range(gap_limit=100)

        assert upgraded is False

    @pytest.mark.asyncio
    async def test_check_and_upgrade_descriptor_range_upgrade_needed(self) -> None:
        """Test that upgrade happens when range is insufficient."""
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_upgrade_needed")
        backend._wallet_loaded = True
        backend._descriptors_imported = True

        upgrade_called = False
        new_range_used = 0

        async def mock_rpc_call(
            method: str,
            params: list | None = None,
            client: Any = None,
            use_wallet: bool = True,
        ) -> Any:
            nonlocal upgrade_called, new_range_used
            if method == "listdescriptors":
                return {
                    "descriptors": [
                        {"desc": "wpkh(xpub.../0/*)#abc", "range": [0, 999]},
                    ]
                }
            if method == "getdescriptorinfo":
                desc = params[0] if params else ""
                return {"descriptor": f"{desc}#mockchecksum"}
            if method == "importdescriptors":
                upgrade_called = True
                # Extract the new range
                if params and params[0]:
                    new_range_used = params[0][0].get("range", [0, 0])[1]
                return [{"success": True} for _ in (params[0] if params else [])]
            raise ValueError(f"Unexpected RPC: {method}")

        backend._rpc_call = mock_rpc_call  # type: ignore[method-assign]

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Set up addresses_with_history with HIGH indices (beyond current range)
        wallet.address_cache["bc1q_high_idx"] = (0, 0, 950)
        wallet.addresses_with_history = {"bc1q_high_idx"}

        # With gap_limit=100, we need range >= 950 + 100 + 1 = 1051
        # Current range is 999, so upgrade should be triggered
        upgraded = await wallet.check_and_upgrade_descriptor_range(gap_limit=100)

        assert upgraded is True
        assert upgrade_called is True
        assert new_range_used >= 1051

    @pytest.mark.asyncio
    async def test_populate_address_cache(self) -> None:
        """Test pre-populating address cache."""
        from jmwallet.wallet.service import WalletService

        backend = DescriptorWalletBackend(wallet_name="test_cache")
        backend._wallet_loaded = True

        test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        wallet = WalletService(
            mnemonic=test_mnemonic,
            backend=backend,
            network="mainnet",
            mixdepth_count=5,
        )

        # Should start empty
        assert len(wallet.address_cache) == 0

        # Populate for small range
        await wallet._populate_address_cache(10)

        # Should have 5 mixdepths * 2 branches * 10 indices = 100 addresses
        assert len(wallet.address_cache) == 100

        # Verify addresses are properly cached
        addr = wallet.get_address(0, 0, 5)
        assert addr in wallet.address_cache
        assert wallet.address_cache[addr] == (0, 0, 5)
