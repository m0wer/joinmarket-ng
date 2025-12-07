"""
Tests for transaction verification - MOST CRITICAL security component!
"""

from unittest.mock import patch

import pytest
from jmcore.models import OfferType
from jmwallet.wallet.models import UTXOInfo

from maker.tx_verification import (
    calculate_cj_fee,
    verify_unsigned_transaction,
)


def test_calculate_cj_fee_absolute():
    """Test absolute fee calculation"""
    fee = calculate_cj_fee(OfferType.SW0_ABSOLUTE, 1000, 100_000_000)
    assert fee == 1000

    fee = calculate_cj_fee(OfferType.SWA_ABSOLUTE, "2000", 50_000_000)
    assert fee == 2000


def test_calculate_cj_fee_relative():
    """Test relative fee calculation"""
    fee = calculate_cj_fee(OfferType.SW0_RELATIVE, "0.0001", 100_000_000)
    assert fee == 10_000

    fee = calculate_cj_fee(OfferType.SWA_RELATIVE, "0.0002", 50_000_000)
    assert fee == 10_000


def test_verify_transaction_negative_profit():
    """
    CRITICAL TEST: Ensure negative profit is rejected.

    This prevents the maker from losing money!
    """
    our_utxos = {
        ("abc123", 0): UTXOInfo(
            txid="abc123",
            vout=0,
            value=100_000_000,
            address="bcrt1qtest1",
            confirmations=10,
            scriptpubkey="",
            path="m/84'/0'/0'/0/0",
            mixdepth=0,
        )
    }

    mock_parsed_tx = {
        "inputs": [{"txid": "abc123", "vout": 0}],
        "outputs": [
            {"value": 50_000_000, "address": "bcrt1qcj"},
            {"value": 49_999_000, "address": "bcrt1qchange"},
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=1000,
            txfee=2000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "Negative profit" in error


def test_verify_transaction_missing_utxo():
    """
    CRITICAL TEST: Ensure all our UTXOs must be in the transaction.
    """
    our_utxos = {
        ("abc123", 0): UTXOInfo(
            txid="abc123",
            vout=0,
            value=100_000_000,
            address="bcrt1qtest1",
            confirmations=10,
            scriptpubkey="",
            path="m/84'/0'/0'/0/0",
            mixdepth=0,
        ),
        ("def456", 1): UTXOInfo(
            txid="def456",
            vout=1,
            value=50_000_000,
            address="bcrt1qtest2",
            confirmations=10,
            scriptpubkey="",
            path="m/84'/0'/0'/0/1",
            mixdepth=0,
        ),
    }

    mock_parsed_tx = {
        "inputs": [{"txid": "abc123", "vout": 0}],
        "outputs": [
            {"value": 50_000_000, "address": "bcrt1qcj"},
            {"value": 49_990_000, "address": "bcrt1qchange"},
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee="0.001",
            txfee=10_000,
            offer_type=OfferType.SW0_RELATIVE,
        )

    assert not is_valid
    assert "Our UTXOs not included" in error


def test_calculate_expected_change():
    """
    Test change calculation formula:
    expected_change = my_total_in - amount - txfee + real_cjfee
    """
    my_total_in = 100_000_000
    amount = 50_000_000
    txfee = 10_000
    real_cjfee = 50_000

    expected_change = my_total_in - amount - txfee + real_cjfee

    assert expected_change == 50_040_000


def test_profit_calculation():
    """
    Test profit calculation:
    profit = real_cjfee - txfee

    Must be positive!
    """
    real_cjfee = 50_000
    txfee = 10_000
    profit = real_cjfee - txfee

    assert profit == 40_000
    assert profit > 0

    negative_case_cjfee = 5_000
    negative_case_txfee = 10_000
    negative_profit = negative_case_cjfee - negative_case_txfee

    assert negative_profit == -5_000
    assert negative_profit < 0


def test_script_to_address_network_hrp():
    """Test that script_to_address uses correct HRP for each network."""
    from jmcore.models import NetworkType

    from maker.tx_verification import get_bech32_hrp, script_to_address

    # P2WPKH script: OP_0 <20-byte-hash>
    # Using known hash for testing
    witness_program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    p2wpkh_script = bytes([0x00, 0x14]) + witness_program

    # Test HRP mapping
    assert get_bech32_hrp(NetworkType.MAINNET) == "bc"
    assert get_bech32_hrp(NetworkType.TESTNET) == "tb"
    assert get_bech32_hrp(NetworkType.SIGNET) == "tb"
    assert get_bech32_hrp(NetworkType.REGTEST) == "bcrt"

    # Test address generation for different networks
    mainnet_addr = script_to_address(p2wpkh_script, NetworkType.MAINNET)
    testnet_addr = script_to_address(p2wpkh_script, NetworkType.TESTNET)
    regtest_addr = script_to_address(p2wpkh_script, NetworkType.REGTEST)

    assert mainnet_addr.startswith("bc1")
    assert testnet_addr.startswith("tb1")
    assert regtest_addr.startswith("bcrt1")

    # Verify known address (BIP 173 test vector for mainnet)
    # bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 is the address for this witness program
    assert mainnet_addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
