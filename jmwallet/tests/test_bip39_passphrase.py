"""
Test BIP39 passphrase support (13th/25th word).
"""

from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed


def test_mnemonic_to_seed_with_passphrase():
    """Test that mnemonic_to_seed produces different seeds with different passphrases."""
    test_mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    # Same mnemonic, no passphrase
    seed1 = mnemonic_to_seed(test_mnemonic, "")
    seed2 = mnemonic_to_seed(test_mnemonic, "")
    assert seed1 == seed2, "Same mnemonic + passphrase should produce same seed"

    # Same mnemonic, different passphrase
    seed_no_pass = mnemonic_to_seed(test_mnemonic, "")
    seed_with_pass = mnemonic_to_seed(test_mnemonic, "mypassphrase")
    assert seed_no_pass != seed_with_pass, "Different passphrases should produce different seeds"

    # Different passphrases produce different seeds
    seed_pass1 = mnemonic_to_seed(test_mnemonic, "passphrase1")
    seed_pass2 = mnemonic_to_seed(test_mnemonic, "passphrase2")
    assert seed_pass1 != seed_pass2, "Different passphrases should produce different seeds"


def test_wallet_derivation_with_passphrase():
    """Test that wallet derivation works correctly with BIP39 passphrase."""
    test_mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    # Create master keys with different passphrases
    seed_no_pass = mnemonic_to_seed(test_mnemonic, "")
    seed_with_pass = mnemonic_to_seed(test_mnemonic, "test")

    master_no_pass = HDKey.from_seed(seed_no_pass)
    master_with_pass = HDKey.from_seed(seed_with_pass)

    # Derive same path
    path = "m/84'/0'/0'/0/0"
    key_no_pass = master_no_pass.derive(path)
    key_with_pass = master_with_pass.derive(path)

    # Should produce different addresses
    addr_no_pass = key_no_pass.get_address("mainnet")
    addr_with_pass = key_with_pass.get_address("mainnet")

    assert addr_no_pass != addr_with_pass, (
        "Different passphrases should produce different addresses"
    )

    # Verify addresses are valid bech32
    assert addr_no_pass.startswith("bc1"), "Should be valid bech32 address"
    assert addr_with_pass.startswith("bc1"), "Should be valid bech32 address"


def test_passphrase_compatibility():
    """Test that passphrase implementation is compatible with BIP39 standard."""
    # Test vector from BIP39 spec (TREZOR test)
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    passphrase = "TREZOR"

    seed = mnemonic_to_seed(mnemonic, passphrase)

    # BIP39 test vector expects this seed for the above mnemonic+passphrase
    expected_seed_hex = (
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2"
        "cf141630c7a3c4ab7c81b2f001698e7463b04"
    )

    assert seed.hex() == expected_seed_hex, "Should match BIP39 test vector"


def test_bip39_mnemonic_import_with_passphrase():
    """Test importing a specific BIP39 mnemonic with passphrase and verify zpub and address."""
    # 24-word mnemonic
    mnemonic = (
        "actress inmate filter october eagle floor conduct issue rail nominee mixture kid "
        "tunnel thought list tower lobster route ghost cigar bundle oak fiscal pulse"
    )
    passphrase = "test"

    # Generate seed from mnemonic with passphrase
    seed = mnemonic_to_seed(mnemonic, passphrase)
    master_key = HDKey.from_seed(seed)

    # Derive BIP84 account key (m/84'/0'/0')
    account_key = master_key.derive("m/84'/0'/0'")

    # Verify zpub matches expected value
    zpub = account_key.get_zpub("mainnet")
    expected_zpub = (
        "zpub6s3NLrmr3UN8Z5oWuFMozCWGHNKYPvHNB15pmjaVvHhniwa8fxoBwZmtEGro74sk8affDh"
        "hrehteRWW48DXBTZbUDsutkmTXsGru1TTuNy1"
    )
    assert zpub == expected_zpub, f"zpub mismatch: got {zpub}"

    # Derive first receiving address (m/84'/0'/0'/0/0)
    first_address_key = account_key.derive("m/0/0")
    first_address = first_address_key.get_address("mainnet")

    # Verify first address matches expected value
    expected_address = "bc1qw90s2z6etu728elvs0hxh6tda35p465phy9qz4"
    assert first_address == expected_address, f"Address mismatch: got {first_address}"
