"""
Tests for jmcore.crypto
"""

import hashlib

from coincurve import PrivateKey

from jmcore.crypto import (
    KeyPair,
    base58_encode,
    generate_jm_nick,
    verify_fidelity_bond_proof,
    verify_raw_ecdsa,
    verify_signature,
)


def test_base58_encode():
    # Simple test case
    # "hello" in hex is 68656c6c6f
    # 0x68656c6c6f = 448378203247
    # 448378203247 in base58 is Cn8eVZg
    assert base58_encode(b"hello") == "Cn8eVZg"

    # Empty bytes -> ""
    assert base58_encode(b"") == ""

    # Null bytes
    assert base58_encode(b"\x00") == "1"
    assert base58_encode(b"\x00\x00") == "11"


def test_generate_jm_nick():
    nick = generate_jm_nick()
    # v5 nicks for reference implementation compatibility
    assert nick.startswith("J5")
    # Check general structure if possible, but it's hash based


def test_keypair_signing():
    kp = KeyPair()
    msg = b"hello world"
    sig = kp.sign(msg)

    assert kp.verify(msg, sig)
    assert not kp.verify(b"other msg", sig)

    # Verify with another key
    kp2 = KeyPair()
    assert not kp2.verify(msg, sig)


def test_verify_signature_utility():
    kp = KeyPair()
    msg = b"test message"
    sig = kp.sign(msg)
    pub_hex = kp.public_key_hex()

    assert verify_signature(pub_hex, msg, sig)
    assert not verify_signature(pub_hex, b"wrong", sig)

    # Invalid pubkey
    assert not verify_signature("invalidhex", msg, sig)


def test_verify_raw_ecdsa():
    """Test raw ECDSA verification with pre-hashed message."""
    priv_key = PrivateKey()
    pub_key_bytes = priv_key.public_key.format(compressed=True)

    # Create a message hash
    message = b"test message for raw ecdsa"
    msg_hash = hashlib.sha256(message).digest()

    # Sign without additional hashing
    sig = priv_key.sign(msg_hash, hasher=None)

    # Verify should succeed
    assert verify_raw_ecdsa(msg_hash, sig, pub_key_bytes)

    # Different message should fail
    wrong_hash = hashlib.sha256(b"wrong message").digest()
    assert not verify_raw_ecdsa(wrong_hash, sig, pub_key_bytes)


def test_verify_raw_ecdsa_with_padding():
    """Test raw ECDSA verification with padded signature."""
    priv_key = PrivateKey()
    pub_key_bytes = priv_key.public_key.format(compressed=True)

    message = b"padded signature test"
    msg_hash = hashlib.sha256(message).digest()
    sig = priv_key.sign(msg_hash, hasher=None)

    # Pad signature to 72 bytes (like bond proofs use)
    padded_sig = sig + b"\x00" * (72 - len(sig))

    # Should still verify
    assert verify_raw_ecdsa(msg_hash, padded_sig, pub_key_bytes)


def test_verify_fidelity_bond_proof_invalid_base64():
    """Test bond verification with invalid base64."""
    is_valid, data, error = verify_fidelity_bond_proof("not valid base64!!!", "J5maker", "J5taker")
    assert not is_valid
    assert data is None
    assert "base64" in error.lower()


def test_verify_fidelity_bond_proof_wrong_length():
    """Test bond verification with wrong length."""
    import base64

    wrong_len_data = base64.b64encode(b"x" * 100).decode()
    is_valid, data, error = verify_fidelity_bond_proof(wrong_len_data, "J5maker", "J5taker")
    assert not is_valid
    assert data is None
    assert "length" in error.lower()


def test_verify_fidelity_bond_proof_roundtrip():
    """Test creating and verifying a bond proof."""
    import base64
    import struct

    # Generate keys
    priv_key = PrivateKey()
    pub_key = priv_key.public_key.format(compressed=True)

    maker_nick = "J5testmaker123"
    taker_nick = "J5testtaker456"
    cert_expiry_encoded = 52  # 52 * 2016 = ~1 year

    # Create ownership signature (signs SHA256(taker_nick))
    ownership_msg = hashlib.sha256(taker_nick.encode("utf-8")).digest()
    ownership_sig = priv_key.sign(ownership_msg, hasher=None)

    # Create certificate signature (signs SHA256(cert_pub || expiry || maker_nick))
    cert_preimage = pub_key + cert_expiry_encoded.to_bytes(2, "little") + maker_nick.encode("utf-8")
    cert_msg = hashlib.sha256(cert_preimage).digest()
    cert_sig = priv_key.sign(cert_msg, hasher=None)

    # Pad signatures to 72 bytes
    ownership_sig_padded = ownership_sig + b"\x00" * (72 - len(ownership_sig))
    cert_sig_padded = cert_sig + b"\x00" * (72 - len(cert_sig))

    # Create proof
    txid = b"a" * 32
    vout = 0
    locktime = 800000

    proof_data = struct.pack(
        "<72s72s33sH33s32sII",
        ownership_sig_padded,
        cert_sig_padded,
        pub_key,  # cert_pub (same as utxo_pub for self-signed)
        cert_expiry_encoded,
        pub_key,  # utxo_pub
        txid,
        vout,
        locktime,
    )

    proof_b64 = base64.b64encode(proof_data).decode()

    # Verify the proof
    is_valid, data, error = verify_fidelity_bond_proof(proof_b64, maker_nick, taker_nick)

    assert is_valid, f"Verification failed: {error}"
    assert data is not None
    assert data["maker_nick"] == maker_nick
    assert data["taker_nick"] == taker_nick
    assert data["utxo_pub"] == pub_key.hex()
    assert data["locktime"] == locktime
    assert data["utxo_vout"] == vout


def test_verify_fidelity_bond_proof_wrong_taker():
    """Test that verification fails with wrong taker nick."""
    import base64
    import struct

    priv_key = PrivateKey()
    pub_key = priv_key.public_key.format(compressed=True)

    maker_nick = "J5maker"
    correct_taker = "J5correct"
    wrong_taker = "J5wrong"
    cert_expiry_encoded = 52

    # Create signatures for correct_taker
    ownership_msg = hashlib.sha256(correct_taker.encode("utf-8")).digest()
    ownership_sig = priv_key.sign(ownership_msg, hasher=None)

    cert_preimage = pub_key + cert_expiry_encoded.to_bytes(2, "little") + maker_nick.encode("utf-8")
    cert_msg = hashlib.sha256(cert_preimage).digest()
    cert_sig = priv_key.sign(cert_msg, hasher=None)

    ownership_sig_padded = ownership_sig + b"\x00" * (72 - len(ownership_sig))
    cert_sig_padded = cert_sig + b"\x00" * (72 - len(cert_sig))

    proof_data = struct.pack(
        "<72s72s33sH33s32sII",
        ownership_sig_padded,
        cert_sig_padded,
        pub_key,
        cert_expiry_encoded,
        pub_key,
        b"b" * 32,
        0,
        800000,
    )

    proof_b64 = base64.b64encode(proof_data).decode()

    # Verification should fail with wrong taker
    is_valid, data, error = verify_fidelity_bond_proof(proof_b64, maker_nick, wrong_taker)
    assert not is_valid
    assert "ownership signature" in error.lower()
