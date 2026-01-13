"""
Unit tests for fidelity bond verification in Taker.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, Mock

import pytest
from jmcore.models import NetworkType, Offer, OfferType
from jmwallet.wallet.models import UTXOInfo

from taker.config import TakerConfig
from taker.taker import Taker


@pytest.fixture
def mock_wallet():
    """Mock wallet service."""
    wallet = AsyncMock()
    wallet.mixdepth_count = 5
    return wallet


@pytest.fixture
def mock_backend():
    """Mock blockchain backend."""
    backend = AsyncMock()
    # Default to mainnet-like behavior
    backend.can_provide_neutrino_metadata = Mock(return_value=True)
    return backend


@pytest.fixture
def mock_config():
    """Mock taker config."""
    config = TakerConfig(
        mnemonic="abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about",
        network=NetworkType.REGTEST,
        directory_servers=["localhost:5222"],
    )
    return config


@pytest.mark.asyncio
async def test_update_offers_with_bond_values(mock_wallet, mock_backend, mock_config):
    """Test that fidelity bond values are correctly calculated and updated."""

    # Setup Taker
    taker = Taker(mock_wallet, mock_backend, mock_config)

    # Mock current time and block height
    current_time = int(time.time())
    current_height = 800000
    mock_backend.get_block_height = AsyncMock(return_value=current_height)

    # Create bond data
    # Bond 1: Valid bond, locked for 1 year in future
    txid1 = "a" * 64
    vout1 = 0
    locktime1 = current_time + 31536000  # +1 year
    bond_data1 = {
        "utxo_txid": txid1,
        "utxo_vout": vout1,
        "locktime": locktime1,
        "utxo_pub": "pubkey1",
        "cert_expiry": current_time + 100000,
    }

    # Bond 2: Expired bond (locktime in past) - should still have value if burned?
    # Actually checking the formula:
    # if current_time > locktime, the second term subtracts value.
    # But for this test, we just want to ensure it calculates *something* if valid.

    # Create Offers
    offer1 = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=1000000,
        txfee=1000,
        cjfee="0.001",
        counterparty="Maker1",
        fidelity_bond_data=bond_data1,
    )

    offer2 = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=1000000,
        txfee=1000,
        cjfee="0.001",
        counterparty="Maker2",
        # No bond data
        fidelity_bond_data=None,
    )

    offers = [offer1, offer2]

    # Mock Backend Responses

    # UTXO for Bond 1
    # 10 BTC value, 10000 confirmations
    utxo1 = UTXOInfo(
        txid=txid1,
        vout=vout1,
        value=1_000_000_000,
        address="addr1",
        confirmations=10000,
        scriptpubkey="script1",
        path="path1",
        mixdepth=0,
    )

    # UTXO lookup side effect
    async def get_utxo_side_effect(txid, vout):
        if txid == txid1 and vout == vout1:
            return utxo1
        return None

    mock_backend.get_utxo = AsyncMock(side_effect=get_utxo_side_effect)

    # Block time lookup (for confirmation time calculation)
    # confirmation height = current - 10000 + 1
    conf_time = current_time - (10000 * 600)  # approx 10000 blocks ago
    mock_backend.get_block_time = AsyncMock(return_value=conf_time)

    # Run the method
    await taker._update_offers_with_bond_values(offers)

    # Assertions

    # Offer 1 should have updated fidelity_bond_value
    assert offer1.fidelity_bond_value > 0
    print(f"Calculated bond value: {offer1.fidelity_bond_value}")

    # Offer 2 should remain 0
    assert offer2.fidelity_bond_value == 0

    # Verify backend calls
    mock_backend.get_block_height.assert_called_once()
    # Should have called get_utxo for the bond
    mock_backend.get_utxo.assert_called_with(txid1, vout1)


@pytest.mark.asyncio
async def test_update_offers_bond_missing_utxo(mock_wallet, mock_backend, mock_config):
    """Test handling of missing UTXO (spent or invalid)."""
    taker = Taker(mock_wallet, mock_backend, mock_config)

    mock_backend.get_block_height = AsyncMock(return_value=800000)

    txid = "b" * 64
    bond_data = {
        "utxo_txid": txid,
        "utxo_vout": 0,
        "locktime": int(time.time()) + 10000,
        "utxo_pub": "pubkey",
        "cert_expiry": 0,
    }

    offer = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=1000000,
        txfee=1000,
        cjfee="0.001",
        counterparty="Maker1",
        fidelity_bond_data=bond_data,
    )

    # Backend returns None for UTXO
    mock_backend.get_utxo = AsyncMock(return_value=None)

    await taker._update_offers_with_bond_values([offer])

    assert offer.fidelity_bond_value == 0


@pytest.mark.asyncio
async def test_update_offers_bond_unconfirmed_utxo(mock_wallet, mock_backend, mock_config):
    """Test handling of unconfirmed UTXO."""
    taker = Taker(mock_wallet, mock_backend, mock_config)

    mock_backend.get_block_height = AsyncMock(return_value=800000)

    txid = "c" * 64
    bond_data = {
        "utxo_txid": txid,
        "utxo_vout": 0,
        "locktime": int(time.time()) + 10000,
        "utxo_pub": "pubkey",
        "cert_expiry": 0,
    }

    offer = Offer(
        ordertype=OfferType.SW0_RELATIVE,
        oid=0,
        minsize=10000,
        maxsize=1000000,
        txfee=1000,
        cjfee="0.001",
        counterparty="Maker1",
        fidelity_bond_data=bond_data,
    )

    # Backend returns unconfirmed UTXO
    utxo = UTXOInfo(
        txid=txid,
        vout=0,
        value=100000000,
        address="addr",
        confirmations=0,  # Unconfirmed
        scriptpubkey="script",
        path="path",
        mixdepth=0,
    )
    mock_backend.get_utxo = AsyncMock(return_value=utxo)

    await taker._update_offers_with_bond_values([offer])

    assert offer.fidelity_bond_value == 0
