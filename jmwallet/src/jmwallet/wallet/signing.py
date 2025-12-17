"""
Bitcoin transaction signing utilities for P2WPKH inputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


class TransactionSigningError(Exception):
    pass


@dataclass
class TxInput:
    txid_le: bytes
    vout: int
    script: bytes
    sequence: bytes


@dataclass
class TxOutput:
    value: int
    script: bytes


@dataclass
class Transaction:
    version: bytes
    marker_flag: bool
    inputs: list[TxInput]
    outputs: list[TxOutput]
    locktime: bytes
    raw: bytes


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1

    if first < 0xFD:
        return first, offset
    if first == 0xFD:
        value = int.from_bytes(data[offset : offset + 2], "little")
        return value, offset + 2
    if first == 0xFE:
        value = int.from_bytes(data[offset : offset + 4], "little")
        return value, offset + 4
    value = int.from_bytes(data[offset : offset + 8], "little")
    return value, offset + 8


def encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def deserialize_transaction(tx_bytes: bytes) -> Transaction:
    try:
        offset = 0
        version = tx_bytes[offset : offset + 4]
        offset += 4

        marker_flag = False
        if tx_bytes[offset] == 0x00 and tx_bytes[offset + 1] == 0x01:
            marker_flag = True
            offset += 2

        input_count, offset = read_varint(tx_bytes, offset)
        inputs: list[TxInput] = []

        for _ in range(input_count):
            txid_le = tx_bytes[offset : offset + 32]
            offset += 32

            vout = int.from_bytes(tx_bytes[offset : offset + 4], "little")
            offset += 4

            script_len, offset = read_varint(tx_bytes, offset)
            script = tx_bytes[offset : offset + script_len]
            offset += script_len

            sequence = tx_bytes[offset : offset + 4]
            offset += 4

            inputs.append(TxInput(txid_le, vout, script, sequence))

        output_count, offset = read_varint(tx_bytes, offset)
        outputs: list[TxOutput] = []

        for _ in range(output_count):
            value = int.from_bytes(tx_bytes[offset : offset + 8], "little")
            offset += 8

            script_len, offset = read_varint(tx_bytes, offset)
            script = tx_bytes[offset : offset + script_len]
            offset += script_len

            outputs.append(TxOutput(value, script))

        if marker_flag:
            for _ in range(input_count):
                stack_count, offset = read_varint(tx_bytes, offset)
                for _ in range(stack_count):
                    item_len, offset = read_varint(tx_bytes, offset)
                    offset += item_len

        locktime = tx_bytes[offset : offset + 4]
        return Transaction(version, marker_flag, inputs, outputs, locktime, tx_bytes)

    except Exception as e:
        raise TransactionSigningError(f"Failed to parse transaction: {e}") from e


def compute_sighash_segwit(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    value: int,
    sighash_type: int,
) -> bytes:
    try:
        if input_index >= len(tx.inputs):
            raise TransactionSigningError("Input index out of range")

        hash_prevouts = hash256(
            b"".join(inp.txid_le + inp.vout.to_bytes(4, "little") for inp in tx.inputs)
        )
        hash_sequence = hash256(b"".join(inp.sequence for inp in tx.inputs))
        hash_outputs = hash256(
            b"".join(
                out.value.to_bytes(8, "little") + encode_varint(len(out.script)) + out.script
                for out in tx.outputs
            )
        )

        target_input = tx.inputs[input_index]

        preimage = (
            tx.version
            + hash_prevouts
            + hash_sequence
            + target_input.txid_le
            + target_input.vout.to_bytes(4, "little")
            + encode_varint(len(script_code))
            + script_code
            + value.to_bytes(8, "little")
            + target_input.sequence
            + hash_outputs
            + tx.locktime
            + sighash_type.to_bytes(4, "little")
        )

        return hash256(preimage)

    except Exception as e:
        raise TransactionSigningError(f"Failed to compute sighash: {e}") from e


def sign_p2wpkh_input(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    value: int,
    private_key: ec.EllipticCurvePrivateKey,
    sighash_type: int = 1,
) -> bytes:
    sighash = compute_sighash_segwit(tx, input_index, script_code, value, sighash_type)

    # Sign the pre-hashed sighash (it's already SHA256d)
    # Use Prehashed to prevent the library from hashing again
    signature = private_key.sign(sighash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(signature)

    # Normalize s to low-S form (BIP 62/BIP 146)
    # secp256k1 curve order
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    secp256k1_half_order = secp256k1_order // 2

    if s > secp256k1_half_order:
        s = secp256k1_order - s

    der_signature = utils.encode_dss_signature(r, s)
    return der_signature + bytes([sighash_type])


def create_p2wpkh_script_code(pubkey_bytes: bytes) -> bytes:
    """Create the scriptCode for P2WPKH signing (BIP 143).

    For P2WPKH, the scriptCode is the P2PKH script:
    OP_DUP OP_HASH160 <20-byte-pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

    Returns 25 bytes (without length prefix - the preimage serialization adds that).
    """
    pubkey_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey_bytes).digest()).digest()
    # OP_DUP OP_HASH160 PUSH20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"


def create_witness_stack(signature: bytes, pubkey_bytes: bytes) -> list[bytes]:
    return [signature, pubkey_bytes]
