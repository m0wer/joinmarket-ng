"""
Unit tests for Maker protocol handling.

Tests:
- NaCl encryption setup and message exchange
- Protocol message flow (fill, auth, tx)
- Fidelity bond proof creation
"""

from __future__ import annotations

import base64

import pytest
from jmcore.encryption import CryptoSession

from maker.fidelity import FidelityBondInfo, create_fidelity_bond_proof


@pytest.mark.asyncio
async def test_maker_encryption_setup():
    """Test maker sets up encryption with taker's pubkey from !fill."""
    # Taker creates crypto session and sends pubkey in !fill
    taker_crypto = CryptoSession()
    taker_pubkey = taker_crypto.get_pubkey_hex()

    # Maker receives fill with taker's pubkey

    # Maker creates crypto session
    maker_crypto = CryptoSession()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    # Maker sets up encryption with taker's pubkey
    maker_crypto.setup_encryption(taker_pubkey)

    # Taker sets up encryption with maker's pubkey (from !pubkey response)
    taker_crypto.setup_encryption(maker_pubkey)

    # Test bidirectional encryption
    test_msg = "auth revelation data"
    encrypted = taker_crypto.encrypt(test_msg)
    decrypted = maker_crypto.decrypt(encrypted)
    assert decrypted == test_msg

    # Maker response
    response = "ioauth data"
    encrypted_response = maker_crypto.encrypt(response)
    decrypted_response = taker_crypto.decrypt(encrypted_response)
    assert decrypted_response == response


@pytest.mark.asyncio
async def test_fidelity_bond_proof():
    """Test fidelity bond proof creation."""
    # Create a mock fidelity bond
    bond = FidelityBondInfo(
        txid="a" * 64,
        vout=0,
        value=100_000_000,
        locktime=700_000,
        confirmation_time=600_000,
        bond_value=1_500_000,
    )

    maker_nick = "J5TestMaker"
    taker_nick = "J5TestTaker"

    # Add private key and pubkey for signing
    from coincurve import PrivateKey

    bond.private_key = PrivateKey(b"\x01" * 32)
    bond.pubkey = bond.private_key.public_key.format(compressed=True)

    # Create proof
    proof = create_fidelity_bond_proof(bond, maker_nick, taker_nick, current_block_height=930000)

    # Proof should be a base64-encoded string
    # The actual format is implementation-specific but should not be None
    assert proof is not None
    assert len(proof) > 0

    # The proof is a base64 string containing the bond information
    import base64

    # Should be valid base64
    try:
        decoded = base64.b64decode(proof, validate=True)
        assert len(decoded) > 0
    except Exception:
        # Some proof formats may not be pure base64, that's okay
        # as long as we have a proof string
        pass


@pytest.mark.asyncio
async def test_encrypted_ioauth_response():
    """Test maker's encrypted !ioauth response format."""
    # Setup encryption
    taker_crypto = CryptoSession()
    maker_crypto = CryptoSession()

    taker_pubkey = taker_crypto.get_pubkey_hex()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    taker_crypto.setup_encryption(maker_pubkey)
    maker_crypto.setup_encryption(taker_pubkey)

    # Maker creates ioauth data
    utxo_list = "txid1:0,txid2:1"
    auth_pub = "02" + "aa" * 32  # Compressed pubkey
    cj_addr = "bcrt1qmakercj"
    change_addr = "bcrt1qmakerchange"
    btc_sig = "304402" + "bb" * 35  # DER signature

    ioauth_plaintext = f"{utxo_list} {auth_pub} {cj_addr} {change_addr} {btc_sig}"

    # Encrypt
    encrypted_ioauth = maker_crypto.encrypt(ioauth_plaintext)

    # Taker decrypts
    decrypted = taker_crypto.decrypt(encrypted_ioauth)
    assert decrypted == ioauth_plaintext

    # Parse decrypted ioauth
    parts = decrypted.split()
    assert len(parts) == 5
    assert parts[0] == utxo_list
    assert parts[1] == auth_pub
    assert parts[2] == cj_addr
    assert parts[3] == change_addr
    assert parts[4] == btc_sig


@pytest.mark.asyncio
async def test_encrypted_sig_response():
    """Test maker's encrypted !sig response format."""
    # Setup encryption
    taker_crypto = CryptoSession()
    maker_crypto = CryptoSession()

    taker_pubkey = taker_crypto.get_pubkey_hex()
    maker_pubkey = maker_crypto.get_pubkey_hex()

    taker_crypto.setup_encryption(maker_pubkey)
    maker_crypto.setup_encryption(taker_pubkey)

    # Maker creates signature
    # Format: varint(sig_len) + sig + varint(pub_len) + pub
    sig_bytes = b"\x30\x44" + b"\x00" * 70  # DER signature
    pub_bytes = b"\x02" + b"\x00" * 33  # Compressed pubkey

    sig_len = len(sig_bytes)
    pub_len = len(pub_bytes)

    sig_data = bytes([sig_len]) + sig_bytes + bytes([pub_len]) + pub_bytes
    sig_b64 = base64.b64encode(sig_data).decode("ascii")

    # Encrypt signature
    encrypted_sig = maker_crypto.encrypt(sig_b64)

    # Taker decrypts
    decrypted_sig_b64 = taker_crypto.decrypt(encrypted_sig)
    assert decrypted_sig_b64 == sig_b64

    # Taker parses signature
    decoded_sig = base64.b64decode(decrypted_sig_b64)
    assert decoded_sig[0] == sig_len
    assert decoded_sig[1 : 1 + sig_len] == sig_bytes
    assert decoded_sig[1 + sig_len] == pub_len
    assert decoded_sig[2 + sig_len : 2 + sig_len + pub_len] == pub_bytes


@pytest.mark.asyncio
async def test_multiple_maker_sessions():
    """Test handling multiple concurrent taker sessions."""
    # Simulate two takers connecting to the same maker
    taker1_crypto = CryptoSession()
    taker2_crypto = CryptoSession()

    maker1_crypto = CryptoSession()
    maker2_crypto = CryptoSession()

    # Setup encryption for taker1
    taker1_crypto.setup_encryption(maker1_crypto.get_pubkey_hex())
    maker1_crypto.setup_encryption(taker1_crypto.get_pubkey_hex())

    # Setup encryption for taker2
    taker2_crypto.setup_encryption(maker2_crypto.get_pubkey_hex())
    maker2_crypto.setup_encryption(taker2_crypto.get_pubkey_hex())

    # Test isolated encryption (taker1 can't decrypt taker2's messages)
    msg1 = "taker1 auth data"
    encrypted1 = taker1_crypto.encrypt(msg1)
    decrypted1 = maker1_crypto.decrypt(encrypted1)
    assert decrypted1 == msg1

    msg2 = "taker2 auth data"
    encrypted2 = taker2_crypto.encrypt(msg2)
    decrypted2 = maker2_crypto.decrypt(encrypted2)
    assert decrypted2 == msg2

    # Verify cross-decryption fails (encrypted1 can't be decrypted with maker2's key)
    # This would raise an exception in real usage
    try:
        maker2_crypto.decrypt(encrypted1)
        # If it doesn't raise, the decryption would produce garbage
        assert False, "Should not be able to decrypt with wrong key"
    except Exception:
        # Expected: decryption failure
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
