"""
Test fidelity bond parsing from network messages.

Note: These tests use dummy/mock proofs that don't have valid signatures.
We pass verify=False to skip signature verification and test only parsing logic.
For signature verification tests, see jmcore/tests/test_crypto.py.
"""

import base64
import struct

from orderbook_watcher.directory_client import parse_fidelity_bond_proof


def test_parse_real_bond_proof() -> None:
    """Test parsing actual bond proof from network (parsing only, no sig verification)"""
    proof_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKhssPU5fanuMnQ4fKjtMXW5/ipsMHS4/SltsfY6fCh9AEDAqGyw9Tl9qe4ydDh8qO0xdbn+KmwwdLj9KW2x9jp8KEBI0VniavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEAAAAAsz9x"

    # Skip signature verification for parsing test (dummy proof has no valid sigs)
    result = parse_fidelity_bond_proof(proof_b64, "TestMakerNick123", "testtaker", verify=False)

    assert result is not None, "Should parse valid bond proof"

    assert result["utxo_txid"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert result["utxo_vout"] == 1
    assert result["locktime"] == 1900000000
    assert result["cert_expiry"] == 1008000


def test_parse_bond_proof_format() -> None:
    """Test the structure of bond proof parsing"""
    # Create a mock 252-byte proof
    proof_data = b"\x00" * 252
    proof_b64 = base64.b64encode(proof_data).decode("ascii")

    # Skip signature verification for parsing test
    result = parse_fidelity_bond_proof(proof_b64, "maker", "taker", verify=False)

    assert result is not None
    assert "utxo_txid" in result
    assert "utxo_vout" in result
    assert "locktime" in result
    assert "cert_expiry" in result


def test_parse_bond_proof_invalid_length() -> None:
    """Test that invalid length proofs are rejected"""
    # Too short
    proof_data = b"\x00" * 100
    proof_b64 = base64.b64encode(proof_data).decode("ascii")

    # Even with verify=False, wrong length should be rejected
    result = parse_fidelity_bond_proof(proof_b64, "maker", "taker", verify=False)
    assert result is None


def test_parse_bond_proof_invalid_base64() -> None:
    """Test that invalid base64 is rejected"""
    result = parse_fidelity_bond_proof("not-valid-base64!!!", "maker", "taker", verify=False)
    assert result is None


def test_extract_bond_from_message() -> None:
    """Test extracting bond proof from full message line"""
    # This is what we receive from the directory server
    full_line = "TestMaker123!TestTaker456!sw0absoffer 0 100000 5000000 0 200!tbond AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKhssPU5fanuMnQ4fKjtMXW5/ipsMHS4/SltsfY6fCh9AEDAqGyw9Tl9qe4ydDh8qO0xdbn+KmwwdLj9KW2x9jp8KEBI0VniavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEAAAAAsz9x 02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 MEQCIDtest1test2test3test4test5test6test7test8test9testAtestBtestC"

    # Extract the bond section
    parts = full_line.split("!")
    assert len(parts) >= 4

    # The bond section is after "!tbond "
    bond_section = parts[3]  # "tbond ..."
    assert bond_section.startswith("tbond ")

    # Extract just the base64 proof (first part after "tbond ")
    bond_parts = bond_section[6:].split()  # Remove "tbond " prefix and split
    bond_proof_b64 = bond_parts[0]

    # Skip verification for parsing test (dummy proof)
    result = parse_fidelity_bond_proof(bond_proof_b64, "TestMaker123", "test", verify=False)

    assert result is not None
    assert result["utxo_txid"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert result["utxo_vout"] == 1


def test_bond_proof_byte_order() -> None:
    """Test that txid is correctly extracted without reversal"""
    test_txid = bytes.fromhex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

    packed = struct.pack(
        "<72s72s33sH33s32sII",
        b"\x00" * 72,
        b"\x00" * 72,
        b"\x03" + b"\x00" * 32,
        500,
        b"\x03" + b"\x00" * 32,
        test_txid,
        2,
        1850000000,
    )

    assert len(packed) == 252

    proof_b64 = base64.b64encode(packed).decode("ascii")
    # Skip verification for parsing test (dummy proof)
    result = parse_fidelity_bond_proof(proof_b64, "maker", "taker", verify=False)

    assert result is not None
    assert result["utxo_txid"] == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert result["cert_expiry"] == 1008000
