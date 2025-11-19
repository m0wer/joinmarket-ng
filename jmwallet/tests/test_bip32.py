"""
Tests for BIP32 HD key derivation.
"""

from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed


def test_mnemonic_to_seed(test_mnemonic):
    seed = mnemonic_to_seed(test_mnemonic)
    assert len(seed) == 64
    assert isinstance(seed, bytes)


def test_hdkey_from_seed(test_mnemonic):
    seed = mnemonic_to_seed(test_mnemonic)
    master_key = HDKey.from_seed(seed)

    assert master_key.depth == 0
    assert len(master_key.chain_code) == 32
    assert master_key.private_key is not None


def test_hdkey_derivation(test_mnemonic):
    seed = mnemonic_to_seed(test_mnemonic)
    master_key = HDKey.from_seed(seed)

    child = master_key.derive("m/84'/0'/0'/0/0")

    assert child.depth == 5
    assert child.private_key is not None

    privkey_bytes = child.get_private_key_bytes()
    assert len(privkey_bytes) == 32

    pubkey_bytes = child.get_public_key_bytes(compressed=True)
    assert len(pubkey_bytes) == 33


def test_hardened_derivation(test_mnemonic):
    seed = mnemonic_to_seed(test_mnemonic)
    master_key = HDKey.from_seed(seed)

    hardened = master_key.derive("m/84'")
    assert hardened.depth == 1

    combined = master_key.derive("m/84'/0")
    assert combined.depth == 2


def test_address_generation(test_mnemonic):
    seed = mnemonic_to_seed(test_mnemonic)
    master_key = HDKey.from_seed(seed)

    key = master_key.derive("m/84'/0'/0'/0/0")
    address = key.get_address("regtest")

    assert address.startswith("bcrt1")
    assert len(address) > 20
