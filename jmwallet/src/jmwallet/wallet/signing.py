"""
Bitcoin transaction signing utilities for P2WPKH and P2WSH inputs.
"""

from __future__ import annotations

from coincurve import PrivateKey
from jmcore.bitcoin import create_p2wpkh_script_code, decode_varint, encode_varint, hash256
from pydantic.dataclasses import dataclass

# Alias for backward compatibility
read_varint = decode_varint


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


def deserialize_transaction(tx_bytes: bytes) -> Transaction:
    try:
        offset = 0
        version = tx_bytes[offset : offset + 4]
        offset += 4

        marker_flag = False
        if tx_bytes[offset] == 0x00 and tx_bytes[offset + 1] == 0x01:
            marker_flag = True
            offset += 2

        input_count, offset = decode_varint(tx_bytes, offset)
        inputs: list[TxInput] = []

        for _ in range(input_count):
            txid_le = tx_bytes[offset : offset + 32]
            offset += 32

            vout = int.from_bytes(tx_bytes[offset : offset + 4], "little")
            offset += 4

            script_len, offset = decode_varint(tx_bytes, offset)
            script = tx_bytes[offset : offset + script_len]
            offset += script_len

            sequence = tx_bytes[offset : offset + 4]
            offset += 4

            inputs.append(TxInput(txid_le, vout, script, sequence))

        output_count, offset = decode_varint(tx_bytes, offset)
        outputs: list[TxOutput] = []

        for _ in range(output_count):
            value = int.from_bytes(tx_bytes[offset : offset + 8], "little")
            offset += 8

            script_len, offset = decode_varint(tx_bytes, offset)
            script = tx_bytes[offset : offset + script_len]
            offset += script_len

            outputs.append(TxOutput(value, script))

        if marker_flag:
            for _ in range(input_count):
                stack_count, offset = decode_varint(tx_bytes, offset)
                for _ in range(stack_count):
                    item_len, offset = decode_varint(tx_bytes, offset)
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
    private_key: PrivateKey,
    sighash_type: int = 1,
) -> bytes:
    """Sign a P2WPKH input using coincurve.

    Args:
        tx: The transaction to sign
        input_index: Index of the input to sign
        script_code: The scriptCode for signing (P2PKH script for P2WPKH)
        value: The value of the input being spent (in satoshis)
        private_key: coincurve PrivateKey instance
        sighash_type: Sighash type (default SIGHASH_ALL = 1)

    Returns:
        DER-encoded signature with sighash type byte appended
    """
    sighash = compute_sighash_segwit(tx, input_index, script_code, value, sighash_type)

    # Sign the pre-hashed sighash (it's already SHA256d)
    # coincurve's sign() with hasher=None skips hashing
    signature = private_key.sign(sighash, hasher=None)

    return signature + bytes([sighash_type])


def create_witness_stack(signature: bytes, pubkey_bytes: bytes) -> list[bytes]:
    return [signature, pubkey_bytes]


def sign_p2wsh_input(
    tx: Transaction,
    input_index: int,
    witness_script: bytes,
    value: int,
    private_key: PrivateKey,
    sighash_type: int = 1,
) -> bytes:
    """Sign a P2WSH input using coincurve.

    For P2WSH, the scriptCode in BIP143 signing is the witness script itself.

    Args:
        tx: The transaction to sign
        input_index: Index of the input to sign
        witness_script: The witness script (e.g., timelocked freeze script)
        value: The value of the input being spent (in satoshis)
        private_key: coincurve PrivateKey instance
        sighash_type: Sighash type (default SIGHASH_ALL = 1)

    Returns:
        DER-encoded signature with sighash type byte appended
    """
    # For P2WSH, the scriptCode is the witness script itself
    sighash = compute_sighash_segwit(tx, input_index, witness_script, value, sighash_type)

    # Sign the pre-hashed sighash (it's already SHA256d)
    signature = private_key.sign(sighash, hasher=None)

    return signature + bytes([sighash_type])


def create_p2wsh_witness_stack(signature: bytes, witness_script: bytes) -> list[bytes]:
    """Create witness stack for P2WSH input.

    For timelocked scripts (CLTV), the witness is: [signature, witness_script]

    Args:
        signature: DER signature with sighash byte
        witness_script: The witness script (e.g., freeze script)

    Returns:
        Witness stack: [signature, witness_script]
    """
    return [signature, witness_script]


# Re-export from jmcore for backward compatibility
__all__ = [
    "Transaction",
    "TransactionSigningError",
    "TxInput",
    "TxOutput",
    "compute_sighash_segwit",
    "create_p2wpkh_script_code",
    "create_p2wsh_witness_stack",
    "create_witness_stack",
    "deserialize_transaction",
    "encode_varint",
    "hash256",
    "read_varint",
    "sign_p2wpkh_input",
    "sign_p2wsh_input",
]
