"""
Tests for taker transaction signing functionality.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.models import UTXOInfo
from jmwallet.wallet.signing import (
    deserialize_transaction,
)

from taker.tx_builder import CoinJoinTxBuilder, CoinJoinTxData, TxInput, TxOutput


@pytest.fixture
def test_mnemonic() -> str:
    """Test mnemonic (BIP39 test vector)."""
    return (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )


@pytest.fixture
def test_seed(test_mnemonic: str) -> bytes:
    """Get test seed from mnemonic."""
    return mnemonic_to_seed(test_mnemonic)


@pytest.fixture
def test_master_key(test_seed: bytes) -> HDKey:
    """Get test master key."""
    return HDKey.from_seed(test_seed)


@pytest.fixture
def taker_utxos(test_master_key: HDKey) -> list[UTXOInfo]:
    """Create test taker UTXOs with known addresses."""
    # Derive addresses for regtest (coin_type=1)
    key0 = test_master_key.derive("m/84'/1'/0'/0/0")
    addr0 = key0.get_address("regtest")

    key1 = test_master_key.derive("m/84'/1'/0'/0/1")
    addr1 = key1.get_address("regtest")

    return [
        UTXOInfo(
            txid="a" * 64,
            vout=0,
            value=1_000_000,
            address=addr0,
            confirmations=10,
            scriptpubkey="0014" + "00" * 20,  # P2WPKH placeholder
            path="m/84'/1'/0'/0/0",
            mixdepth=0,
        ),
        UTXOInfo(
            txid="b" * 64,
            vout=1,
            value=500_000,
            address=addr1,
            confirmations=5,
            scriptpubkey="0014" + "11" * 20,  # P2WPKH placeholder
            path="m/84'/1'/0'/0/1",
            mixdepth=0,
        ),
    ]


@pytest.fixture
def maker_utxos() -> list[dict[str, Any]]:
    """Create test maker UTXOs."""
    return [
        {"txid": "c" * 64, "vout": 0, "value": 1_200_000},
        {"txid": "d" * 64, "vout": 2, "value": 800_000},
    ]


@pytest.fixture
def sample_coinjoin_tx_data(
    taker_utxos: list[UTXOInfo], maker_utxos: list[dict[str, Any]]
) -> CoinJoinTxData:
    """Create sample CoinJoin transaction data."""
    return CoinJoinTxData(
        taker_inputs=[TxInput(txid=u.txid, vout=u.vout, value=u.value) for u in taker_utxos],
        taker_cj_output=TxOutput(
            address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            value=1_000_000,
        ),
        taker_change_output=TxOutput(
            address="bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
            value=490_000,
        ),
        maker_inputs={
            "maker1": [
                TxInput(txid=u["txid"], vout=u["vout"], value=u["value"]) for u in maker_utxos
            ],
        },
        maker_cj_outputs={
            "maker1": TxOutput(
                address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                value=1_000_000,
            ),
        },
        maker_change_outputs={
            "maker1": TxOutput(
                address="bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
                value=990_000,
            ),
        },
        cj_amount=1_000_000,
        total_maker_fee=10_000,
        tx_fee=5_000,
    )


class TestTakerInputIndexMapping:
    """Tests for correct input index mapping in shuffled transactions."""

    def test_input_index_map_creation(self, sample_coinjoin_tx_data: CoinJoinTxData) -> None:
        """Test that we can correctly map UTXOs to transaction input indices."""
        builder = CoinJoinTxBuilder(network="regtest")
        tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)

        # Deserialize the transaction
        tx = deserialize_transaction(tx_bytes)

        # Build the input index map like _sign_our_inputs does
        input_index_map: dict[tuple[str, int], int] = {}
        for idx, tx_input in enumerate(tx.inputs):
            txid_hex = tx_input.txid_le[::-1].hex()
            input_index_map[(txid_hex, tx_input.vout)] = idx

        # Verify all taker inputs are in the map
        taker_txids = [("a" * 64, 0), ("b" * 64, 1)]
        for txid, vout in taker_txids:
            assert (txid, vout) in input_index_map, f"Taker UTXO {txid}:{vout} not found in map"

        # Verify maker inputs are also in the map
        maker_txids = [("c" * 64, 0), ("d" * 64, 2)]
        for txid, vout in maker_txids:
            assert (txid, vout) in input_index_map, f"Maker UTXO {txid}:{vout} not found in map"

    def test_input_owners_match_metadata(self, sample_coinjoin_tx_data: CoinJoinTxData) -> None:
        """Test that input owners in metadata correctly identify taker vs maker."""
        builder = CoinJoinTxBuilder(network="regtest")
        tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)

        input_owners = metadata["input_owners"]

        # Should have 4 inputs total (2 taker + 2 maker)
        assert len(input_owners) == 4

        # Count owners
        taker_count = sum(1 for owner in input_owners if owner == "taker")
        maker_count = sum(1 for owner in input_owners if owner == "maker1")

        assert taker_count == 2, f"Expected 2 taker inputs, got {taker_count}"
        assert maker_count == 2, f"Expected 2 maker inputs, got {maker_count}"


class TestTakerSigning:
    """Tests for the taker signing implementation."""

    @pytest.fixture
    def mock_wallet(self, test_master_key: HDKey) -> MagicMock:
        """Create a mock wallet service."""
        wallet = MagicMock()
        wallet.network = "regtest"
        wallet.mixdepth_count = 5

        # Mock get_key_for_address to return proper HD keys
        def get_key_for_address(address: str) -> HDKey | None:
            # Map test addresses to their derivation paths
            key0 = test_master_key.derive("m/84'/1'/0'/0/0")
            key1 = test_master_key.derive("m/84'/1'/0'/0/1")

            if address == key0.get_address("regtest"):
                return key0
            elif address == key1.get_address("regtest"):
                return key1
            return None

        wallet.get_key_for_address = get_key_for_address
        return wallet

    @pytest.fixture
    def mock_backend(self) -> AsyncMock:
        """Create a mock blockchain backend."""
        backend = AsyncMock()
        backend.broadcast = AsyncMock(return_value="txid123")
        return backend

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create a mock taker config."""
        from jmcore.models import NetworkType

        config = MagicMock()
        config.network = NetworkType.REGTEST
        config.directory_servers = ["localhost:5222"]
        config.max_cj_fee = 0.01
        config.counterparty_count = 4
        config.minimum_makers = 2
        config.maker_timeout_sec = 60
        config.order_wait_time = 120
        config.taker_utxo_age = 5
        config.taker_utxo_amtpercent = 20
        config.tx_fee_factor = 1.0
        return config

    @pytest.mark.asyncio
    async def test_sign_our_inputs_basic(
        self,
        mock_wallet: MagicMock,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
        taker_utxos: list[UTXOInfo],
        sample_coinjoin_tx_data: CoinJoinTxData,
    ) -> None:
        """Test that _sign_our_inputs produces valid signatures."""
        from taker.taker import Taker

        # Create taker instance
        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = mock_wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = taker_utxos

            # Build the transaction
            builder = CoinJoinTxBuilder(network="regtest")
            tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)
            taker.unsigned_tx = tx_bytes
            taker.tx_metadata = metadata

            # Sign the inputs
            signatures = await taker._sign_our_inputs()

            # Should have 2 signatures (one per taker UTXO)
            assert len(signatures) == 2

            # Verify signature structure
            for sig_info in signatures:
                assert "txid" in sig_info
                assert "vout" in sig_info
                assert "signature" in sig_info
                assert "pubkey" in sig_info
                assert "witness" in sig_info

                # Witness should have 2 items: signature and pubkey
                assert len(sig_info["witness"]) == 2

                # Signature should be hex string
                assert all(c in "0123456789abcdef" for c in sig_info["signature"])

                # Pubkey should be 33 bytes compressed (66 hex chars)
                assert len(sig_info["pubkey"]) == 66

    @pytest.mark.asyncio
    async def test_sign_our_inputs_correct_indices(
        self,
        mock_wallet: MagicMock,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
        taker_utxos: list[UTXOInfo],
        sample_coinjoin_tx_data: CoinJoinTxData,
    ) -> None:
        """Test that signatures are created for correct input indices."""
        from taker.taker import Taker

        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = mock_wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = taker_utxos

            builder = CoinJoinTxBuilder(network="regtest")
            tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)
            taker.unsigned_tx = tx_bytes
            taker.tx_metadata = metadata

            signatures = await taker._sign_our_inputs()

            # Verify each signature corresponds to a taker UTXO
            signed_utxos = {(s["txid"], s["vout"]) for s in signatures}
            expected_utxos = {(u.txid, u.vout) for u in taker_utxos}

            assert signed_utxos == expected_utxos

    @pytest.mark.asyncio
    async def test_sign_our_inputs_empty_utxos(
        self,
        mock_wallet: MagicMock,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
    ) -> None:
        """Test that signing with no UTXOs returns empty list."""
        from taker.taker import Taker

        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = mock_wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = []
            taker.unsigned_tx = b"\x02\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"

            signatures = await taker._sign_our_inputs()

            assert signatures == []

    @pytest.mark.asyncio
    async def test_sign_our_inputs_no_transaction(
        self,
        mock_wallet: MagicMock,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
        taker_utxos: list[UTXOInfo],
    ) -> None:
        """Test that signing with no transaction returns empty list."""
        from taker.taker import Taker

        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = mock_wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = taker_utxos
            taker.unsigned_tx = b""

            signatures = await taker._sign_our_inputs()

            assert signatures == []


class TestSignatureIntegration:
    """Integration tests for signature creation and application."""

    def test_signatures_can_be_added_to_transaction(
        self,
        test_master_key: HDKey,
        sample_coinjoin_tx_data: CoinJoinTxData,
    ) -> None:
        """Test that created signatures can be added to the transaction."""
        from jmwallet.wallet.signing import (
            create_p2wpkh_script_code,
            create_witness_stack,
            deserialize_transaction,
            sign_p2wpkh_input,
        )

        builder = CoinJoinTxBuilder(network="regtest")
        tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)

        tx = deserialize_transaction(tx_bytes)

        # Build input index map
        input_index_map: dict[tuple[str, int], int] = {}
        for idx, tx_input in enumerate(tx.inputs):
            txid_hex = tx_input.txid_le[::-1].hex()
            input_index_map[(txid_hex, tx_input.vout)] = idx

        # Get taker key and sign
        key0 = test_master_key.derive("m/84'/1'/0'/0/0")
        pubkey_bytes = key0.get_public_key_bytes(compressed=True)
        script_code = create_p2wpkh_script_code(pubkey_bytes)

        # Find the first taker input (txid "a" * 64)
        taker_txid = "a" * 64
        if (taker_txid, 0) in input_index_map:
            input_index = input_index_map[(taker_txid, 0)]

            signature = sign_p2wpkh_input(
                tx=tx,
                input_index=input_index,
                script_code=script_code,
                value=1_000_000,
                private_key=key0.private_key,
            )

            witness = create_witness_stack(signature, pubkey_bytes)

            # Signature should be valid DER + sighash
            assert len(signature) > 64
            assert signature[-1] == 1  # SIGHASH_ALL

            # Witness stack should have 2 items
            assert len(witness) == 2

            # Prepare signature info for add_signatures
            signatures = {
                "taker": [
                    {
                        "txid": taker_txid,
                        "vout": 0,
                        "signature": signature.hex(),
                        "pubkey": pubkey_bytes.hex(),
                        "witness": [item.hex() for item in witness],
                    }
                ]
            }

            # This should not raise an error
            signed_tx = builder.add_signatures(tx_bytes, signatures, metadata)

            # Signed tx should be different (has witness data)
            assert signed_tx != tx_bytes
            assert len(signed_tx) > len(tx_bytes)


class TestEdgeCases:
    """Edge case tests for taker signing."""

    @pytest.mark.asyncio
    async def test_sign_with_missing_key(
        self,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
        sample_coinjoin_tx_data: CoinJoinTxData,
    ) -> None:
        """Test handling when wallet doesn't have key for an address."""
        from taker.taker import Taker

        # Create wallet that returns None for get_key_for_address
        wallet = MagicMock()
        wallet.get_key_for_address = MagicMock(return_value=None)

        utxos = [
            UTXOInfo(
                txid="a" * 64,
                vout=0,
                value=1_000_000,
                address="unknown_address",
                confirmations=10,
                scriptpubkey="0014" + "00" * 20,
                path="m/84'/1'/0'/0/0",
                mixdepth=0,
            )
        ]

        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = utxos

            builder = CoinJoinTxBuilder(network="regtest")
            tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)
            taker.unsigned_tx = tx_bytes
            taker.tx_metadata = metadata

            # Should return empty list when key not found (error logged)
            signatures = await taker._sign_our_inputs()

            # Should return empty due to missing key
            assert signatures == []

    @pytest.mark.asyncio
    async def test_sign_utxo_not_in_transaction(
        self,
        test_master_key: HDKey,
        mock_backend: AsyncMock,
        mock_config: MagicMock,
        sample_coinjoin_tx_data: CoinJoinTxData,
    ) -> None:
        """Test handling when UTXO is not found in transaction inputs."""
        from taker.taker import Taker

        key0 = test_master_key.derive("m/84'/1'/0'/0/0")
        addr0 = key0.get_address("regtest")

        # Create UTXO that won't be in the transaction
        utxos = [
            UTXOInfo(
                txid="z" * 64,  # Not in the transaction
                vout=99,
                value=1_000_000,
                address=addr0,
                confirmations=10,
                scriptpubkey="0014" + "00" * 20,
                path="m/84'/1'/0'/0/0",
                mixdepth=0,
            )
        ]

        wallet = MagicMock()
        wallet.get_key_for_address = MagicMock(return_value=key0)

        with patch.object(Taker, "__init__", lambda self, *args, **kwargs: None):
            taker = Taker.__new__(Taker)
            taker.wallet = wallet
            taker.backend = mock_backend
            taker.config = mock_config
            taker.selected_utxos = utxos

            builder = CoinJoinTxBuilder(network="regtest")
            tx_bytes, metadata = builder.build_unsigned_tx(sample_coinjoin_tx_data)
            taker.unsigned_tx = tx_bytes
            taker.tx_metadata = metadata

            # Should return empty list (UTXO not found in transaction)
            signatures = await taker._sign_our_inputs()

            assert signatures == []


# Re-export fixtures for use in conftest
@pytest.fixture
def mock_backend() -> AsyncMock:
    """Create a mock blockchain backend."""
    backend = AsyncMock()
    backend.broadcast = AsyncMock(return_value="txid123")
    return backend


@pytest.fixture
def mock_config() -> MagicMock:
    """Create a mock taker config."""
    from jmcore.models import NetworkType

    config = MagicMock()
    config.network = NetworkType.REGTEST
    config.directory_servers = ["localhost:5222"]
    config.max_cj_fee = 0.01
    config.counterparty_count = 4
    config.minimum_makers = 2
    config.maker_timeout_sec = 60
    config.order_wait_time = 120
    config.taker_utxo_age = 5
    config.taker_utxo_amtpercent = 20
    config.tx_fee_factor = 1.0
    return config
