"""
Tests for jmcore.crypto
"""

from jmcore.crypto import (
    KeyPair,
    base58_encode,
    generate_jm_nick,
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
