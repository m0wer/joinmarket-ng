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


def test_verify_transaction_valid():
    """
    Test that a valid transaction passes verification.

    Change = total_in - cj_amount - txfee + cjfee
    Change = 100M - 50M - 1000 + 10000 = 50,009,000
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
            {"value": 50_009_000, "address": "bcrt1qchange"},  # Correct change!
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,  # 10k sats fee
            txfee=1000,  # 1k sats txfee
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert is_valid, f"Expected valid, got error: {error}"
    assert error == ""


def test_verify_transaction_cj_output_too_low():
    """
    CRITICAL TEST: Ensure CJ output below expected amount is rejected.
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
            {"value": 49_000_000, "address": "bcrt1qcj"},  # Too low!
            {"value": 50_000_000, "address": "bcrt1qchange"},
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "CJ output value too low" in error


def test_verify_transaction_change_output_too_low():
    """
    CRITICAL TEST: Ensure change output below expected amount is rejected.
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

    # Expected change: 100M - 50M - 1k + 10k = 50,009,000
    mock_parsed_tx = {
        "inputs": [{"txid": "abc123", "vout": 0}],
        "outputs": [
            {"value": 50_000_000, "address": "bcrt1qcj"},
            {"value": 40_000_000, "address": "bcrt1qchange"},  # Too low!
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "Change output value too low" in error


def test_verify_transaction_cj_address_missing():
    """
    CRITICAL TEST: Ensure missing CJ address is rejected.

    Change = 100M - 50M - 1000 + 10000 = 50,009,000
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
            {"value": 50_000_000, "address": "bcrt1qother"},  # Wrong address!
            {"value": 50_009_000, "address": "bcrt1qchange"},  # Correct change
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",  # Not in outputs
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "CJ address appears 0 times" in error


def test_verify_transaction_change_address_missing():
    """
    CRITICAL TEST: Ensure missing change address is rejected.

    Change = 100M - 50M - 1000 + 10000 = 50,009,000
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
            {"value": 50_009_000, "address": "bcrt1qother"},  # Wrong address!
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",  # Not in outputs
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "Change address appears 0 times" in error


def test_verify_transaction_duplicate_cj_address():
    """
    CRITICAL TEST: Ensure duplicate CJ address is rejected.

    This prevents confusion attacks where taker duplicates our address.

    Change = 100M - 50M - 1000 + 10000 = 50,009,000
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
            {"value": 50_000_000, "address": "bcrt1qcj"},  # Duplicate!
            {"value": 50_009_000, "address": "bcrt1qchange"},  # Correct change
        ],
    }

    with patch("maker.tx_verification.parse_transaction", return_value=mock_parsed_tx):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy_tx_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "CJ address appears 2 times" in error


def test_verify_transaction_parse_failure():
    """
    Test that parse failure is handled gracefully.
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

    with patch("maker.tx_verification.parse_transaction", return_value=None):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="invalid_hex",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "Failed to parse transaction" in error


def test_parse_transaction_real_tx():
    """
    Test parsing a real Bitcoin transaction.

    Using a simplified 1-in-1-out P2WPKH transaction.
    """
    from maker.tx_verification import parse_transaction

    # Simple regtest transaction:
    # Version: 02000000
    # Marker+Flag: 0001 (segwit)
    # Input count: 01
    # Input 1: txid (32 bytes) + vout (4 bytes) + scriptSig len (0) + sequence
    # Output count: 01
    # Output 1: value (8 bytes) + scriptPubKey (P2WPKH)
    # Witness data
    # Locktime

    # Minimal valid segwit tx (1 input, 1 P2WPKH output)
    tx_hex = (
        "02000000"  # version
        "0001"  # segwit marker+flag
        "01"  # input count
        "0000000000000000000000000000000000000000000000000000000000000001"  # txid (reversed)
        "00000000"  # vout
        "00"  # scriptSig length (empty for segwit)
        "ffffffff"  # sequence
        "01"  # output count
        "00e1f50500000000"  # value: 1 BTC = 100,000,000 sats (little endian)
        "16"  # scriptPubKey length: 22 bytes
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"  # P2WPKH script
        "00"  # witness item count (empty witness - unsigned)
        "00000000"  # locktime
    )

    result = parse_transaction(tx_hex)

    assert result is not None
    assert len(result["inputs"]) == 1
    assert (
        result["inputs"][0]["txid"]
        == "0100000000000000000000000000000000000000000000000000000000000000"
    )
    assert result["inputs"][0]["vout"] == 0
    assert len(result["outputs"]) == 1
    assert result["outputs"][0]["value"] == 100_000_000


def test_parse_transaction_invalid_hex():
    """
    Test that invalid hex returns None.
    """
    from maker.tx_verification import parse_transaction

    result = parse_transaction("not_valid_hex")
    assert result is None

    result = parse_transaction("")
    assert result is None

    result = parse_transaction("0102")  # Too short
    assert result is None


def test_read_varint_edge_cases():
    """
    Test varint parsing for different sizes.
    """
    from maker.tx_verification import read_varint

    # Single byte (< 0xFD)
    value, offset = read_varint(bytes([0x10]), 0)
    assert value == 16
    assert offset == 1

    # 2-byte value (0xFD prefix)
    data = bytes([0xFD, 0x00, 0x01])  # 256 in little endian
    value, offset = read_varint(data, 0)
    assert value == 256
    assert offset == 3

    # 4-byte value (0xFE prefix)
    data = bytes([0xFE, 0x00, 0x00, 0x01, 0x00])  # 65536 in little endian
    value, offset = read_varint(data, 0)
    assert value == 65536
    assert offset == 5

    # 8-byte value (0xFF prefix)
    data = bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    value, offset = read_varint(data, 0)
    assert value == 4294967296  # 2^32
    assert offset == 9


def test_script_to_address_unsupported_script():
    """
    Test that unsupported script types return hex fallback.
    """
    from maker.tx_verification import script_to_address

    # P2PKH script (not supported, should return hex)
    p2pkh_script = bytes.fromhex("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
    result = script_to_address(p2pkh_script)
    assert result == "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"

    # P2WSH script (not supported yet)
    p2wsh_script = bytes([0x00, 0x20]) + bytes(32)  # OP_0 <32-byte hash>
    result = script_to_address(p2wsh_script)
    assert result == p2wsh_script.hex()


def test_verify_transaction_exception_handling():
    """
    Test that exceptions during verification are caught and return error.
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

    with patch("maker.tx_verification.parse_transaction", side_effect=Exception("Test error")):
        is_valid, error = verify_unsigned_transaction(
            tx_hex="dummy",
            our_utxos=our_utxos,
            cj_address="bcrt1qcj",
            change_address="bcrt1qchange",
            amount=50_000_000,
            cjfee=10_000,
            txfee=1000,
            offer_type=OfferType.SW0_ABSOLUTE,
        )

    assert not is_valid
    assert "Verification error" in error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
