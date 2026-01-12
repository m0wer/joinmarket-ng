"""
Tests for fidelity bond utilities.
"""

import base64
import hashlib
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from maker.fidelity import (
    CERT_EXPIRY_BLOCKS,
    FIDELITY_BOND_INTERNAL_BRANCH,
    FIDELITY_BOND_MIXDEPTH,
    FidelityBondInfo,
    _bitcoin_message_hash,
    _pad_signature,
    _parse_locktime_from_path,
    _sign_message_bitcoin,
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


class TestParseLocktime:
    """Tests for locktime extraction from path."""

    def test_parse_locktime_valid(self):
        path = "m/84'/0'/0'/2/0:1748736000"
        locktime = _parse_locktime_from_path(path)
        assert locktime == 1748736000

    def test_parse_locktime_no_colon(self):
        path = "m/84'/0'/0'/1/0"
        locktime = _parse_locktime_from_path(path)
        assert locktime is None

    def test_parse_locktime_invalid_value(self):
        path = "m/84'/0'/0'/2/0:invalid"
        locktime = _parse_locktime_from_path(path)
        assert locktime is None


class TestPadSignature:
    """Tests for signature padding utility."""

    def test_pad_short_signature(self):
        """Padding should use leading 0xff bytes (reference implementation format)."""
        sig = b"\x30\x44" + b"\x00" * 68  # 70 bytes
        padded = _pad_signature(sig, 72)
        assert len(padded) == 72
        # Leading 0xff padding
        assert padded[:2] == b"\xff\xff"
        assert padded[2:] == sig

    def test_exact_length_no_padding(self):
        sig = b"\x00" * 72
        padded = _pad_signature(sig, 72)
        assert padded == sig

    def test_too_long_raises(self):
        sig = b"\x00" * 73
        with pytest.raises(ValueError, match="Signature too long"):
            _pad_signature(sig, 72)


class TestSignMessageBitcoin:
    """Tests for Bitcoin message signing."""

    def test_sign_produces_der(self, test_private_key):
        """Signing should produce a valid DER signature."""
        message = b"test message"
        sig = _sign_message_bitcoin(test_private_key, message)

        # DER signatures start with 0x30
        assert sig[0] == 0x30
        # Length is second byte
        assert len(sig) == sig[1] + 2

    def test_sign_different_messages_different_sigs(self, test_private_key):
        msg1 = b"message 1"
        msg2 = b"message 2"

        sig1 = _sign_message_bitcoin(test_private_key, msg1)
        sig2 = _sign_message_bitcoin(test_private_key, msg2)

        assert sig1 != sig2

    def test_sign_low_s_value(self, test_private_key):
        """Verify BIP 62 low-S requirement.

        coincurve always produces low-S signatures by default.
        """
        message = b"test low-s"
        sig = _sign_message_bitcoin(test_private_key, message)

        # DER decode the signature to verify low-S
        # DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        assert sig[0] == 0x30
        assert sig[2] == 0x02  # r marker
        r_len = sig[3]
        s_marker_pos = 4 + r_len
        assert sig[s_marker_pos] == 0x02  # s marker
        s_len = sig[s_marker_pos + 1]
        s = int.from_bytes(sig[s_marker_pos + 2 : s_marker_pos + 2 + s_len], "big")

        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert s <= n // 2

    def test_bitcoin_message_hash_format(self):
        """Verify Bitcoin message hash format."""
        message = b"test"
        msg_hash = _bitcoin_message_hash(message)

        # Result should be a 32-byte hash
        assert len(msg_hash) == 32

        # Manually verify the format
        prefix = b"\x18Bitcoin Signed Message:\n"
        varint = bytes([len(message)])
        full_msg = prefix + varint + message
        expected = hashlib.sha256(hashlib.sha256(full_msg).digest()).digest()
        assert msg_hash == expected


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
            current_block_height=930000,
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
            current_block_height=930000,
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

        # Cert expiry should be calculated from block height
        # Formula: ((block_height + 2) // 2016) + 1
        expected_expiry = ((930000 + 2) // 2016) + 1
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
            current_block_height=930000,
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
            current_block_height=930000,
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
            current_block_height=930000,
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

        proof1 = create_fidelity_bond_proof(bond, "maker", "taker1", current_block_height=930000)
        proof2 = create_fidelity_bond_proof(bond, "maker", "taker2", current_block_height=930000)

        # Different proofs (ownership sig differs)
        assert proof1 is not None
        assert proof2 is not None
        assert proof1 != proof2

        # But same static fields (txid, vout, locktime, pubkeys)
        decoded1 = base64.b64decode(proof1)
        decoded2 = base64.b64decode(proof2)

        # UTXO details at the end should match
        assert decoded1[180:] == decoded2[180:]

    def test_proof_verifiable_by_jmcore(self, test_private_key, test_pubkey):
        """
        Generated proofs should be verifiable by jmcore.crypto.verify_fidelity_bond_proof.

        This ensures maker proofs are compatible with the reference implementation format.
        """
        from jmcore.crypto import verify_fidelity_bond_proof

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

        maker_nick = "J5testmaker"
        taker_nick = "J5testtaker"

        proof = create_fidelity_bond_proof(
            bond=bond,
            maker_nick=maker_nick,
            taker_nick=taker_nick,
            current_block_height=930000,
        )

        assert proof is not None

        # Verify the proof using jmcore
        is_valid, bond_data, error = verify_fidelity_bond_proof(
            proof_base64=proof,
            maker_nick=maker_nick,
            taker_nick=taker_nick,
        )

        assert is_valid, f"Proof verification failed: {error}"
        assert bond_data is not None
        assert bond_data["utxo_txid"] == "ab" * 32
        assert bond_data["utxo_vout"] == 0
        assert bond_data["locktime"] == 800000
        assert bond_data["maker_nick"] == maker_nick
        assert bond_data["taker_nick"] == taker_nick


class TestFindFidelityBonds:
    """Tests for bond discovery from wallet."""

    @pytest.mark.asyncio
    async def test_no_utxos_returns_empty(self):
        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {}

        bonds = await find_fidelity_bonds(mock_wallet)
        assert bonds == []

    @pytest.mark.asyncio
    async def test_wrong_branch_returns_empty(self):
        """UTXOs on branch 1 (regular change) should not be found."""
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/0'/1/0"  # Branch 1 (change), not 2 (fidelity bonds)
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid1"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }

        bonds = await find_fidelity_bonds(mock_wallet)
        assert bonds == []

    @pytest.mark.asyncio
    async def test_no_locktime_in_path_returns_empty(self):
        """UTXOs without locktime in path should not be found."""
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/0'/2/0"  # Branch 2 but no locktime
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid1"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }

        bonds = await find_fidelity_bonds(mock_wallet)
        assert bonds == []

    @pytest.mark.asyncio
    async def test_finds_bond_with_correct_path(self, test_private_key, test_pubkey):
        """Fidelity bonds are on branch 2 with locktime in path."""
        mock_utxo = MagicMock()
        # Correct format: mixdepth 0, branch 2, index 0, locktime 1748736000
        mock_utxo.path = "m/84'/0'/0'/2/0:1748736000"
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.height = 850000  # Block height
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid123"
        mock_utxo.vout = 0

        mock_key = MagicMock()
        mock_key.get_public_key_bytes.return_value = test_pubkey
        mock_key.private_key = test_private_key

        mock_backend = AsyncMock()
        mock_backend.get_block_time.return_value = 1700000000  # Unix timestamp

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }
        mock_wallet.get_key_for_address.return_value = mock_key
        mock_wallet.backend = mock_backend

        with patch("maker.fidelity.calculate_timelocked_fidelity_bond_value", return_value=50000):
            bonds = await find_fidelity_bonds(mock_wallet)

        assert len(bonds) == 1
        assert bonds[0].txid == "txid123"
        assert bonds[0].vout == 0
        assert bonds[0].value == 100_000_000
        assert bonds[0].locktime == 1748736000
        assert bonds[0].confirmation_time == 1700000000
        assert bonds[0].bond_value == 50000

    @pytest.mark.asyncio
    async def test_skips_external_addresses(self):
        """External addresses (branch 0) should not be considered."""
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/0'/0/0:1748736000"  # Branch 0 (external)
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 1000
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid456"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }

        bonds = await find_fidelity_bonds(mock_wallet)
        assert bonds == []

    @pytest.mark.asyncio
    async def test_skips_unconfirmed_bonds(self):
        """Unconfirmed bonds (height=None) should be skipped."""
        mock_utxo = MagicMock()
        mock_utxo.path = "m/84'/0'/0'/2/0:1748736000"
        mock_utxo.value = 100_000_000
        mock_utxo.confirmations = 0
        mock_utxo.height = None  # Unconfirmed
        mock_utxo.address = "bcrt1qtest"
        mock_utxo.txid = "txid_unconfirmed"
        mock_utxo.vout = 0

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo],
        }

        bonds = await find_fidelity_bonds(mock_wallet)
        assert bonds == []


class TestGetBestFidelityBond:
    """Tests for selecting the highest-value bond."""

    @pytest.mark.asyncio
    async def test_no_bonds_returns_none(self):
        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {}

        result = await get_best_fidelity_bond(mock_wallet)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_highest_bond_value(self, test_private_key, test_pubkey):
        mock_utxo1 = MagicMock()
        mock_utxo1.path = "m/84'/0'/0'/2/0:1748736000"  # Branch 2 with locktime
        mock_utxo1.value = 100_000_000
        mock_utxo1.confirmations = 1000
        mock_utxo1.height = 850000
        mock_utxo1.address = "bcrt1qtest1"
        mock_utxo1.txid = "txid_low"
        mock_utxo1.vout = 0

        mock_utxo2 = MagicMock()
        mock_utxo2.path = "m/84'/0'/0'/2/1:1780272000"  # Branch 2 with locktime
        mock_utxo2.value = 200_000_000
        mock_utxo2.confirmations = 2000
        mock_utxo2.height = 840000  # Earlier block = earlier confirmation
        mock_utxo2.address = "bcrt1qtest2"
        mock_utxo2.txid = "txid_high"
        mock_utxo2.vout = 1

        mock_key = MagicMock()
        mock_key.get_public_key_bytes.return_value = test_pubkey
        mock_key.private_key = test_private_key

        # Return different block times based on height
        async def mock_get_block_time(height):
            if height == 850000:
                return 1700000000  # Later confirmation
            return 1600000000  # Earlier confirmation

        mock_backend = AsyncMock()
        mock_backend.get_block_time.side_effect = mock_get_block_time

        mock_wallet = MagicMock()
        mock_wallet.utxo_cache = {
            FIDELITY_BOND_MIXDEPTH: [mock_utxo1, mock_utxo2],
        }
        mock_wallet.get_key_for_address.return_value = mock_key
        mock_wallet.backend = mock_backend

        # Mock bond calculation - higher value for longer time locked
        # utxo2 has earlier confirmation + later locktime = higher bond value
        def mock_bond_value(utxo_value, confirmation_time, locktime):
            time_locked = locktime - confirmation_time
            return int(utxo_value * (time_locked / 1000000000))

        with patch(
            "maker.fidelity.calculate_timelocked_fidelity_bond_value",
            side_effect=mock_bond_value,
        ):
            best = await get_best_fidelity_bond(mock_wallet)

        assert best is not None
        assert best.txid == "txid_high"
        # utxo2: 200M * (1780272000 - 1600000000) / 1B = 200M * 0.180272 = 36,054,400
        assert best.bond_value > 36_000_000


class TestConstants:
    """Verify module constants are sensible."""

    def test_fidelity_bond_mixdepth(self):
        # Fidelity bonds are stored in mixdepth 0
        assert FIDELITY_BOND_MIXDEPTH == 0

    def test_fidelity_bond_internal_branch(self):
        # Fidelity bonds use internal branch 2
        assert FIDELITY_BOND_INTERNAL_BRANCH == 2

    def test_cert_expiry_blocks(self):
        # Should be approximately 1 year in blocks
        blocks_per_week = 2016
        weeks_per_year = 52
        assert CERT_EXPIRY_BLOCKS == blocks_per_week * weeks_per_year


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
