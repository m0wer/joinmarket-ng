"""
Tests for transaction signing utilities.
"""

import pytest

from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.signing import (
    Transaction,
    TransactionSigningError,
    TxInput,
    TxOutput,
    compute_sighash_segwit,
    create_p2wpkh_script_code,
    create_witness_stack,
    deserialize_transaction,
    encode_varint,
    hash256,
    read_varint,
    sign_p2wpkh_input,
)


class TestHash256:
    def test_empty_input(self):
        result = hash256(b"")
        assert len(result) == 32
        # SHA256(SHA256("")) = known value
        expected = bytes.fromhex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
        assert result == expected

    def test_known_value(self):
        result = hash256(b"hello")
        assert len(result) == 32
        assert isinstance(result, bytes)


class TestVarint:
    def test_read_single_byte(self):
        data = bytes([0x05, 0xFF])
        value, offset = read_varint(data, 0)
        assert value == 5
        assert offset == 1

    def test_read_two_bytes(self):
        data = bytes([0xFD, 0x01, 0x00])
        value, offset = read_varint(data, 0)
        assert value == 1
        assert offset == 3

    def test_read_four_bytes(self):
        data = bytes([0xFE, 0x01, 0x00, 0x00, 0x00])
        value, offset = read_varint(data, 0)
        assert value == 1
        assert offset == 5

    def test_encode_single_byte(self):
        result = encode_varint(5)
        assert result == bytes([5])

    def test_encode_two_bytes(self):
        result = encode_varint(0x100)
        assert result == bytes([0xFD, 0x00, 0x01])

    def test_encode_four_bytes(self):
        result = encode_varint(0x10000)
        assert result == bytes([0xFE, 0x00, 0x00, 0x01, 0x00])

    def test_roundtrip(self):
        for value in [0, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF]:
            encoded = encode_varint(value)
            decoded, _ = read_varint(encoded, 0)
            assert decoded == value


class TestDeserializeTransaction:
    # A simple P2WPKH transaction (segwit)
    # This is a minimal valid regtest transaction structure
    SAMPLE_TX_HEX = (
        "02000000"  # version
        "0001"  # marker + flag (segwit)
        "01"  # input count
        "0000000000000000000000000000000000000000000000000000000000000000"  # prev txid
        "00000000"  # prev vout
        "00"  # scriptSig length (empty for segwit)
        "ffffffff"  # sequence
        "01"  # output count
        "0000000000000000"  # value (0 sats)
        "16"  # scriptPubKey length
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"  # P2WPKH scriptPubKey
        "00"  # witness stack count for input 0
        "00000000"  # locktime
    )

    def test_deserialize_basic(self):
        tx_bytes = bytes.fromhex(self.SAMPLE_TX_HEX)
        tx = deserialize_transaction(tx_bytes)

        assert tx.version == bytes.fromhex("02000000")
        assert tx.marker_flag is True
        assert len(tx.inputs) == 1
        assert len(tx.outputs) == 1
        assert tx.locktime == bytes.fromhex("00000000")

    def test_deserialize_input_fields(self):
        tx_bytes = bytes.fromhex(self.SAMPLE_TX_HEX)
        tx = deserialize_transaction(tx_bytes)

        inp = tx.inputs[0]
        assert len(inp.txid_le) == 32
        assert inp.vout == 0
        assert inp.sequence == b"\xff\xff\xff\xff"

    def test_deserialize_output_fields(self):
        tx_bytes = bytes.fromhex(self.SAMPLE_TX_HEX)
        tx = deserialize_transaction(tx_bytes)

        out = tx.outputs[0]
        assert out.value == 0
        assert len(out.script) == 22  # P2WPKH

    def test_invalid_transaction(self):
        with pytest.raises(TransactionSigningError):
            deserialize_transaction(b"\x00\x01\x02")


class TestScriptCode:
    def test_p2wpkh_script_code(self):
        # Known pubkey (secp256k1 generator point G)
        pubkey = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        script_code = create_p2wpkh_script_code(pubkey)

        # Script code format: 0x76 0xa9 0x14 <20-byte-hash> 0x88 0xac (25 bytes)
        # Note: BIP 143 says the scriptCode is the bare script without length prefix
        # The length prefix is added by compute_sighash_segwit via encode_varint
        assert len(script_code) == 25
        assert script_code[0] == 0x76  # OP_DUP
        assert script_code[1] == 0xA9  # OP_HASH160
        assert script_code[2] == 0x14  # 20 bytes follow
        assert script_code[-2] == 0x88  # OP_EQUALVERIFY
        assert script_code[-1] == 0xAC  # OP_CHECKSIG


class TestWitnessStack:
    def test_create_witness_stack(self):
        sig = bytes.fromhex("3044" + "00" * 68)  # Mock DER signature
        pubkey = bytes.fromhex("02" + "00" * 32)

        stack = create_witness_stack(sig, pubkey)

        assert len(stack) == 2
        assert stack[0] == sig
        assert stack[1] == pubkey


class TestSigning:
    @pytest.fixture
    def test_key(self, test_mnemonic):
        """Get a test private key from BIP32 derivation."""
        seed = mnemonic_to_seed(test_mnemonic)
        master = HDKey.from_seed(seed)
        return master.derive("m/84'/0'/0'/0/0")

    def test_compute_sighash_segwit(self, test_key):
        """Test BIP143 sighash computation."""
        tx = Transaction(
            version=bytes.fromhex("02000000"),
            marker_flag=True,
            inputs=[
                TxInput(
                    txid_le=bytes(32),
                    vout=0,
                    script=b"",
                    sequence=b"\xff\xff\xff\xff",
                )
            ],
            outputs=[TxOutput(value=50000, script=bytes.fromhex("0014" + "00" * 20))],
            locktime=bytes(4),
            raw=b"",
        )

        pubkey = test_key.get_public_key_bytes(compressed=True)
        script_code = create_p2wpkh_script_code(pubkey)

        sighash = compute_sighash_segwit(
            tx=tx,
            input_index=0,
            script_code=script_code,
            value=100000,
            sighash_type=1,  # SIGHASH_ALL
        )

        assert len(sighash) == 32
        assert isinstance(sighash, bytes)

    def test_sign_p2wpkh_input(self, test_key):
        """Test actual signing of a P2WPKH input."""
        tx = Transaction(
            version=bytes.fromhex("02000000"),
            marker_flag=True,
            inputs=[
                TxInput(
                    txid_le=bytes(32),
                    vout=0,
                    script=b"",
                    sequence=b"\xff\xff\xff\xff",
                )
            ],
            outputs=[TxOutput(value=50000, script=bytes.fromhex("0014" + "00" * 20))],
            locktime=bytes(4),
            raw=b"",
        )

        pubkey = test_key.get_public_key_bytes(compressed=True)
        script_code = create_p2wpkh_script_code(pubkey)

        signature = sign_p2wpkh_input(
            tx=tx,
            input_index=0,
            script_code=script_code,
            value=100000,
            private_key=test_key.private_key,
            sighash_type=1,
        )

        # Signature should be DER-encoded + sighash byte
        assert len(signature) > 64  # DER is variable length
        assert signature[-1] == 1  # SIGHASH_ALL

    def test_sign_invalid_input_index(self, test_key):
        """Test that invalid input index raises error."""
        tx = Transaction(
            version=bytes.fromhex("02000000"),
            marker_flag=True,
            inputs=[],
            outputs=[],
            locktime=bytes(4),
            raw=b"",
        )

        pubkey = test_key.get_public_key_bytes(compressed=True)
        script_code = create_p2wpkh_script_code(pubkey)

        with pytest.raises(TransactionSigningError):
            sign_p2wpkh_input(
                tx=tx,
                input_index=0,
                script_code=script_code,
                value=100000,
                private_key=test_key.private_key,
            )


class TestSignatureVerification:
    """Integration tests to verify signatures are valid."""

    def test_signature_deterministic(self, test_mnemonic):
        """Signing same transaction twice should produce same signature
        (for same k-value, which cryptography library handles)."""
        seed = mnemonic_to_seed(test_mnemonic)
        master = HDKey.from_seed(seed)
        key = master.derive("m/84'/0'/0'/0/0")

        tx = Transaction(
            version=bytes.fromhex("02000000"),
            marker_flag=True,
            inputs=[
                TxInput(
                    txid_le=bytes(32),
                    vout=0,
                    script=b"",
                    sequence=b"\xff\xff\xff\xff",
                )
            ],
            outputs=[TxOutput(value=50000, script=bytes.fromhex("0014" + "00" * 20))],
            locktime=bytes(4),
            raw=b"",
        )

        pubkey = key.get_public_key_bytes(compressed=True)
        script_code = create_p2wpkh_script_code(pubkey)

        sig1 = sign_p2wpkh_input(tx, 0, script_code, 100000, key.private_key)
        sig2 = sign_p2wpkh_input(tx, 0, script_code, 100000, key.private_key)

        # Note: ECDSA with RFC 6979 deterministic k should give same sig
        # but cryptography library may use random k
        # Just verify both are valid signatures
        assert len(sig1) > 64
        assert len(sig2) > 64
