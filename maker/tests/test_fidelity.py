"""
Tests for fidelity bond utilities.
"""

import base64
import hashlib
import struct
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import utils

from maker.fidelity import (
    CERT_EXPIRY_BLOCKS,
    FIDELITY_BOND_MIXDEPTH,
    FidelityBondInfo,
    _pad_signature,
    _sign_message,
    create_fidelity_bond_proof,
    find_fidelity_bonds,
    get_best_fidelity_bond,
)


class TestFidelityBondInfo:
    """Tests for the FidelityBondInfo dataclass."""

    def test_basic_creation(self):
        bond = FidelityBondInfo(
            txid="a" * 64,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
        )
        assert bond.txid == "a" * 64
        assert bond.vout == 0
        assert bond.value == 100_000_000
        assert bond.locktime == 800000
        assert bond.pubkey is None
        assert bond.private_key is None

    def test_with_key_material(self, test_private_key, test_pubkey):
        bond = FidelityBondInfo(
            txid="b" * 64,
            vout=1,
            value=50_000_000,
            locktime=850000,
            confirmation_time=200,
            bond_value=25_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )
        assert bond.pubkey == test_pubkey
        assert bond.private_key == test_private_key


class TestPadSignature:
    """Tests for signature padding utility."""

    def test_pad_short_signature(self):
        sig = b"\x30\x44" + b"\x00" * 68  # 70 bytes
        padded = _pad_signature(sig, 72)
        assert len(padded) == 72
        assert padded[:70] == sig
        assert padded[70:] == b"\x00\x00"

    def test_exact_length_no_padding(self):
        sig = b"\x00" * 72
        padded = _pad_signature(sig, 72)
        assert padded == sig

    def test_too_long_raises(self):
        sig = b"\x00" * 73
        with pytest.raises(ValueError, match="Signature too long"):
            _pad_signature(sig, 72)


class TestSignMessage:
    """Tests for ECDSA message signing."""

    def test_sign_produces_der(self, test_private_key):
        message = hashlib.sha256(b"test message").digest()
        sig = _sign_message(test_private_key, message)

        # DER signatures start with 0x30
        assert sig[0] == 0x30
        # Length is second byte
        assert len(sig) == sig[1] + 2

    def test_sign_different_messages_different_sigs(self, test_private_key):
        msg1 = hashlib.sha256(b"message 1").digest()
        msg2 = hashlib.sha256(b"message 2").digest()

        sig1 = _sign_message(test_private_key, msg1)
        sig2 = _sign_message(test_private_key, msg2)

        assert sig1 != sig2

    def test_sign_low_s_value(self, test_private_key):
        """Verify BIP 62 low-S requirement."""
        message = hashlib.sha256(b"test low-s").digest()
        sig = _sign_message(test_private_key, message)

        # Decode and verify S is low
        r, s = utils.decode_dss_signature(sig)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert s <= n // 2


class TestCreateFidelityBondProof:
    """Tests for bond proof generation."""

    def test_create_proof_returns_base64(self, test_private_key, test_pubkey):
        bond = FidelityBondInfo(
            txid="ab" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick="maker123",
            taker_nick="taker456",
        )

        assert proof is not None
        # Should be valid base64
        decoded = base64.b64decode(proof)
        assert len(decoded) == 252

    def test_proof_structure(self, test_private_key, test_pubkey):
        bond = FidelityBondInfo(
            txid="cd" * 32,
            vout=5,
            value=200_000_000,
            locktime=900000,
            confirmation_time=500,
            bond_value=100_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick="maker_test",
            taker_nick="taker_test",
        )

        assert proof is not None
        decoded = base64.b64decode(proof)

        # Unpack and verify structure
        (
            ownership_sig,
            cert_sig,
            cert_pub,
            cert_expiry,
            utxo_pub,
            txid,
            vout,
            locktime,
        ) = struct.unpack("<72s72s33sH33s32sII", decoded)

        # Verify fixed-length fields
        assert len(ownership_sig) == 72
        assert len(cert_sig) == 72
        assert len(cert_pub) == 33
        assert len(utxo_pub) == 33
        assert len(txid) == 32

        # For self-signed, cert_pub == utxo_pub
        assert cert_pub == utxo_pub
        assert cert_pub == test_pubkey

        # Verify UTXO details
        assert txid == bytes.fromhex("cd" * 32)
        assert vout == 5
        assert locktime == 900000

        # Cert expiry should be blocks / 2016
        expected_expiry = CERT_EXPIRY_BLOCKS // 2016
        assert cert_expiry == expected_expiry

    def test_missing_private_key_returns_none(self, test_pubkey):
        bond = FidelityBondInfo(
            txid="aa" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=None,  # Missing!
        )

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick="maker",
            taker_nick="taker",
        )

        assert proof is None

    def test_missing_pubkey_returns_none(self, test_private_key):
        bond = FidelityBondInfo(
            txid="bb" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
            pubkey=None,  # Missing!
            private_key=test_private_key,
        )

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick="maker",
            taker_nick="taker",
        )

        assert proof is None

    def test_invalid_txid_returns_none(self, test_private_key, test_pubkey):
        bond = FidelityBondInfo(
            txid="short",  # Invalid - not 64 hex chars
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick="maker",
            taker_nick="taker",
        )

        assert proof is None

    def test_different_takers_different_ownership_sig(self, test_private_key, test_pubkey):
        """Ownership signature should vary with taker_nick."""
        bond = FidelityBondInfo(
            txid="ff" * 32,
            vout=0,
            value=100_000_000,
            locktime=800000,
            confirmation_time=100,
            bond_value=50_000,
            pubkey=test_pubkey,
            private_key=test_private_key,
        )

        proof1 = create_fidelity_bond_proof(bond, "maker", "taker1")
        proof2 = create_fidelity_bond_proof(bond, "maker", "taker2")

        # Different proofs (ownership sig differs)
        assert proof1 is not None
        assert proof2 is not None
        assert proof1 != proof2

        # But same static fields (txid, vout, locktime, pubkeys)
        decoded1 = base64.b64decode(proof1)
        decoded2 = base64.b64decode(proof2)

        # UTXO details at the end should match
        assert decoded1[180:] == decoded2[180:]


class TestFindFidelityBonds:
    """Tests for bond discovery from wallet."""

    def test_no_utxos_returns_empty(self):
        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {}

        bonds = find_fidelity_bonds(mock_wallet)
        assert bonds == []

    def test_wrong_mixdepth_returns_empty(self):
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/0'/1/0"  # Wrong mixdepth (0, not 4)
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid1"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            0: [mock_utxo],  # In mixdepth 0, not 4
        }

        bonds = find_fidelity_bonds(mock_wallet, mixdepth=FIDELITY_BOND_MIXDEPTH)
        assert bonds == []

    def test_finds_bond_in_correct_mixdepth(self, test_private_key, test_pubkey):
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/4'/1/0"  # mixdepth 4, internal
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid123"
        mock_utxo.vout = 0

        mock_key = MagicMock()
        mock_key.get_public_key_bytes.return_value = test_pubkey
        mock_key.private_key = test_private_key

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }
        mock_wallet.get_key_for_address.return_value = mock_key

        with patch("maker.fidelity.calculate_timelocked_fidelity_bond_value", return_value=50000):
            bonds = find_fidelity_bonds(mock_wallet)

        assert len(bonds) == 1
        assert bonds[0].txid == "txid123"
        assert bonds[0].vout == 0
        assert bonds[0].value == 100_000_000
        assert bonds[0].bond_value == 50000

    def test_skips_external_addresses(self):
        """Only internal addresses (path ends with /1/index) should be considered."""
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/4'/0/0"  # External address (not /1/)
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid456"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }

        bonds = find_fidelity_bonds(mock_wallet)
        assert bonds == []


class TestGetBestFidelityBond:
    """Tests for selecting the highest-value bond."""

    def test_no_bonds_returns_none(self):
        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {}

        result = get_best_fidelity_bond(mock_wallet)
        assert result is None

    def test_returns_highest_bond_value(self, test_private_key, test_pubkey):
        mock_utxo1 = MagicMock()
        mock_utxo1.path = "m/84'/0'/4'/1/0"
        mock_utxo1.value = 100_000_000
        mock_utxo1.confirmations = 1000
        mock_utxo1.address = "bcrt1qtest1"
        mock_utxo1.txid = "txid_low"
        mock_utxo1.vout = 0

        mock_utxo2 = MagicMock()
        mock_utxo2.path = "m/84'/0'/4'/1/1"
        mock_utxo2.value = 200_000_000
        mock_utxo2.confirmations = 2000
        mock_utxo2.address = "bcrt1qtest2"
        mock_utxo2.txid = "txid_high"
        mock_utxo2.vout = 1

        mock_key = MagicMock()
        mock_key.get_public_key_bytes.return_value = test_pubkey
        mock_key.private_key = test_private_key

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo1, mock_utxo2],
        }
        mock_wallet.get_key_for_address.return_value = mock_key

        # Return different bond values based on confirmations
        def mock_bond_value(utxo_value, confirmation_time, locktime):
            return confirmation_time * 100  # Simple mock

        with patch(
            "maker.fidelity.calculate_timelocked_fidelity_bond_value",
            side_effect=mock_bond_value,
        ):
            best = get_best_fidelity_bond(mock_wallet)

        assert best is not None
        assert best.txid == "txid_high"
        assert best.bond_value == 200_000  # 2000 * 100


class TestConstants:
    """Verify module constants are sensible."""

    def test_fidelity_bond_mixdepth(self):
        assert FIDELITY_BOND_MIXDEPTH == 4

    def test_cert_expiry_blocks(self):
        # Should be approximately 1 year in blocks
        blocks_per_week = 2016
        weeks_per_year = 52
        assert CERT_EXPIRY_BLOCKS == blocks_per_week * weeks_per_year


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
