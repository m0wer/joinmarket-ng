"""
Test fidelity bond redeem script generation.

Note: These tests use dummy proofs without valid signatures.
We pass verify=False to skip signature verification.
"""

from orderbook_watcher.directory_client import parse_fidelity_bond_proof


def test_parse_bond_with_redeem_script() -> None:
    """Test that redeem script is generated correctly"""
    proof_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKhssPU5fanuMnQ4fKjtMXW5/ipsMHS4/SltsfY6fCh9AEDAqGyw9Tl9qe4ydDh8qO0xdbn+KmwwdLj9KW2x9jp8KEBI0VniavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEAAAAAsz9x"

    # Skip verification for parsing test (dummy proof)
    result = parse_fidelity_bond_proof(proof_b64, "TestMakerNick123", "testtaker", verify=False)

    assert result is not None
    assert "redeem_script" in result
    assert "p2wsh_script" in result

    assert len(result["redeem_script"]) > 0
    assert len(result["p2wsh_script"]) == 68

    assert result["p2wsh_script"].startswith("0020")


def test_redeem_script_matches_expected_format() -> None:
    """Test that redeem script has correct opcodes"""
    proof_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKhssPU5fanuMnQ4fKjtMXW5/ipsMHS4/SltsfY6fCh9AEDAqGyw9Tl9qe4ydDh8qO0xdbn+KmwwdLj9KW2x9jp8KEBI0VniavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEAAAAAsz9x"

    # Skip verification for parsing test (dummy proof)
    result = parse_fidelity_bond_proof(proof_b64, "TestMakerNick123", "testtaker", verify=False)

    assert result is not None

    redeem_script_bytes = bytes.fromhex(result["redeem_script"])

    assert 0xB1 in redeem_script_bytes
    assert 0x75 in redeem_script_bytes
    assert 0xAC in redeem_script_bytes


def test_p2wsh_script_format() -> None:
    """Test P2WSH script has correct format (OP_0 + 32-byte hash)"""
    proof_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKhssPU5fanuMnQ4fKjtMXW5/ipsMHS4/SltsfY6fCh9AEDAqGyw9Tl9qe4ydDh8qO0xdbn+KmwwdLj9KW2x9jp8KEBI0VniavN7wEjRWeJq83vASNFZ4mrze8BI0VniavN7wEAAAAAsz9x"

    # Skip verification for parsing test (dummy proof)
    result = parse_fidelity_bond_proof(proof_b64, "TestMakerNick123", "testtaker", verify=False)

    assert result is not None

    p2wsh_bytes = bytes.fromhex(result["p2wsh_script"])

    assert len(p2wsh_bytes) == 34
    assert p2wsh_bytes[0] == 0x00
    assert p2wsh_bytes[1] == 0x20
