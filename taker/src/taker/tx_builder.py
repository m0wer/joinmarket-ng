"""
Transaction builder for CoinJoin transactions.

Builds the unsigned CoinJoin transaction from:
- Taker's UTXOs and change address
- Maker UTXOs, CJ addresses, and change addresses
- CoinJoin amount and fees
"""

from __future__ import annotations

import logging
import struct
from typing import Any

from jmcore.bitcoin import (
    address_to_scriptpubkey,
    decode_varint,
    encode_varint,
    hash256,
    serialize_outpoint,
)
from pydantic.dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TxInput:
    """Transaction input."""

    txid: str
    vout: int
    value: int
    scriptpubkey: str = ""
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOutput:
    """Transaction output."""

    address: str
    value: int
    scriptpubkey: str = ""


@dataclass
class CoinJoinTxData:
    """Data for building a CoinJoin transaction."""

    # Taker data
    taker_inputs: list[TxInput]
    taker_cj_output: TxOutput
    taker_change_output: TxOutput | None

    # Maker data (by nick)
    maker_inputs: dict[str, list[TxInput]]
    maker_cj_outputs: dict[str, TxOutput]
    maker_change_outputs: dict[str, TxOutput]

    # Amounts
    cj_amount: int
    total_maker_fee: int
    tx_fee: int


# Alias for backward compatibility
varint = encode_varint


def serialize_input(inp: TxInput) -> bytes:
    """Serialize a transaction input for unsigned tx."""
    result = serialize_outpoint(inp.txid, inp.vout)
    # Empty scriptSig for unsigned SegWit
    result += bytes([0x00])
    result += struct.pack("<I", inp.sequence)
    return result


def serialize_output(out: TxOutput) -> bytes:
    """Serialize a transaction output."""
    result = struct.pack("<Q", out.value)
    scriptpubkey = (
        bytes.fromhex(out.scriptpubkey)
        if out.scriptpubkey
        else address_to_scriptpubkey(out.address)
    )
    result += encode_varint(len(scriptpubkey))
    result += scriptpubkey
    return result


class CoinJoinTxBuilder:
    """
    Builds CoinJoin transactions.

    The transaction structure:
    - Inputs: Taker inputs + Maker inputs (shuffled)
    - Outputs: Equal CJ outputs + Change outputs (shuffled)
    """

    def __init__(self, network: str = "mainnet"):
        self.network = network

    def build_unsigned_tx(self, tx_data: CoinJoinTxData) -> tuple[bytes, dict[str, Any]]:
        """
        Build an unsigned CoinJoin transaction.

        Args:
            tx_data: Transaction data with all inputs and outputs

        Returns:
            (tx_bytes, metadata) where metadata maps inputs/outputs to owners
        """
        import random

        # Collect all inputs with owner info
        all_inputs: list[tuple[TxInput, str]] = []

        for inp in tx_data.taker_inputs:
            all_inputs.append((inp, "taker"))

        for nick, inputs in tx_data.maker_inputs.items():
            for inp in inputs:
                all_inputs.append((inp, nick))

        # Collect all outputs with owner info
        all_outputs: list[tuple[TxOutput, str, str]] = []  # (output, owner, type)

        # CJ outputs (equal amounts)
        all_outputs.append((tx_data.taker_cj_output, "taker", "cj"))
        for nick, out in tx_data.maker_cj_outputs.items():
            all_outputs.append((out, nick, "cj"))

        # Change outputs
        if tx_data.taker_change_output:
            all_outputs.append((tx_data.taker_change_output, "taker", "change"))
        for nick, out in tx_data.maker_change_outputs.items():
            all_outputs.append((out, nick, "change"))

        # Shuffle for privacy
        random.shuffle(all_inputs)
        random.shuffle(all_outputs)

        # Build metadata
        metadata = {
            "input_owners": [owner for _, owner in all_inputs],
            "output_owners": [(owner, out_type) for _, owner, out_type in all_outputs],
            "input_values": [inp.value for inp, _ in all_inputs],
            "fee": tx_data.tx_fee,
        }

        # Serialize transaction
        tx_bytes = self._serialize_tx(
            inputs=[inp for inp, _ in all_inputs],
            outputs=[out for out, _, _ in all_outputs],
        )

        return tx_bytes, metadata

    def _serialize_tx(self, inputs: list[TxInput], outputs: list[TxOutput]) -> bytes:
        """Serialize transaction to bytes.

        For unsigned transactions, we use non-SegWit format (no marker/flag/witness).
        The SegWit marker (0x00, 0x01) is only added when witnesses are present.
        """
        # Version (4 bytes, little-endian)
        result = struct.pack("<I", 2)

        # NO SegWit marker/flag for unsigned transactions!
        # The marker is only added when there's actual witness data.

        # Input count
        result += encode_varint(len(inputs))

        # Inputs
        for inp in inputs:
            result += serialize_input(inp)

        # Output count
        result += encode_varint(len(outputs))

        # Outputs
        for out in outputs:
            result += serialize_output(out)

        # NO witness data for unsigned transactions

        # Locktime
        result += struct.pack("<I", 0)

        return result

    def add_signatures(
        self,
        tx_bytes: bytes,
        signatures: dict[str, list[dict[str, Any]]],
        metadata: dict[str, Any],
    ) -> bytes:
        """
        Add signatures to transaction.

        Args:
            tx_bytes: Unsigned transaction
            signatures: Dict of nick -> list of signature info
            metadata: Transaction metadata with input owners

        Returns:
            Signed transaction bytes
        """
        from loguru import logger as log

        # Parse unsigned tx
        version, marker, flag, inputs, outputs, witnesses, locktime = self._parse_tx(tx_bytes)

        log.debug(f"add_signatures: {len(inputs)} inputs, {len(outputs)} outputs")
        log.debug(f"input_owners: {metadata.get('input_owners', [])}")
        log.debug(f"signatures keys: {list(signatures.keys())}")

        # Build witness data
        new_witnesses: list[list[bytes]] = []
        input_owners = metadata["input_owners"]

        for i, owner in enumerate(input_owners):
            inp = inputs[i]
            log.debug(f"Input {i}: owner={owner}, txid={inp['txid'][:16]}..., vout={inp['vout']}")

            if owner in signatures:
                # Find matching signature
                for sig_info in signatures[owner]:
                    if sig_info.get("txid") == inp["txid"] and sig_info.get("vout") == inp["vout"]:
                        witness = sig_info.get("witness", [])
                        new_witnesses.append([bytes.fromhex(w) for w in witness])
                        log.debug(f"  -> Found matching signature, witness len={len(witness)}")
                        break
                else:
                    new_witnesses.append([])
                    log.warning(f"  -> No matching signature found for {owner}")
            else:
                new_witnesses.append([])
                log.warning(f"  -> Owner {owner} not in signatures dict")

        # Reserialize with witnesses
        return self._serialize_with_witnesses(version, inputs, outputs, new_witnesses, locktime)

    def _parse_tx(
        self, tx_bytes: bytes
    ) -> tuple[int, int, int, list[dict[str, Any]], list[dict[str, Any]], list[list[bytes]], int]:
        """Parse a transaction from bytes.

        Handles both SegWit (with marker/flag/witness) and non-SegWit formats.
        Returns marker=0, flag=0 for non-SegWit transactions.
        """
        offset = 0

        # Version
        version = struct.unpack("<I", tx_bytes[offset : offset + 4])[0]
        offset += 4

        # Check for SegWit marker (0x00 followed by 0x01)
        # Note: In non-SegWit, byte 4 is the input count which can't be 0x00
        # (a transaction must have at least one input)
        marker = tx_bytes[offset]
        flag = tx_bytes[offset + 1]
        if marker == 0x00 and flag == 0x01:
            offset += 2
            has_witness = True
        else:
            # Non-SegWit format - reset marker/flag to 0
            marker = 0
            flag = 0
            has_witness = False

        # Input count
        input_count, offset = decode_varint(tx_bytes, offset)

        # Inputs
        inputs = []
        for _ in range(input_count):
            txid = tx_bytes[offset : offset + 32][::-1].hex()
            offset += 32
            vout = struct.unpack("<I", tx_bytes[offset : offset + 4])[0]
            offset += 4
            script_len, offset = decode_varint(tx_bytes, offset)
            scriptsig = tx_bytes[offset : offset + script_len].hex()
            offset += script_len
            sequence = struct.unpack("<I", tx_bytes[offset : offset + 4])[0]
            offset += 4
            inputs.append(
                {"txid": txid, "vout": vout, "scriptsig": scriptsig, "sequence": sequence}
            )

        # Output count
        output_count, offset = decode_varint(tx_bytes, offset)

        # Outputs
        outputs = []
        for _ in range(output_count):
            value = struct.unpack("<Q", tx_bytes[offset : offset + 8])[0]
            offset += 8
            script_len, offset = decode_varint(tx_bytes, offset)
            scriptpubkey = tx_bytes[offset : offset + script_len].hex()
            offset += script_len
            outputs.append({"value": value, "scriptpubkey": scriptpubkey})

        # Witness data
        witnesses: list[list[bytes]] = []
        if has_witness:
            for _ in range(input_count):
                wit_count, offset = decode_varint(tx_bytes, offset)
                wit_items = []
                for _ in range(wit_count):
                    item_len, offset = decode_varint(tx_bytes, offset)
                    wit_items.append(tx_bytes[offset : offset + item_len])
                    offset += item_len
                witnesses.append(wit_items)

        # Locktime
        locktime = struct.unpack("<I", tx_bytes[offset : offset + 4])[0]

        return version, marker, flag, inputs, outputs, witnesses, locktime

    def _serialize_with_witnesses(
        self,
        version: int,
        inputs: list[dict[str, Any]],
        outputs: list[dict[str, Any]],
        witnesses: list[list[bytes]],
        locktime: int,
    ) -> bytes:
        """Serialize transaction with witness data."""
        result = struct.pack("<I", version)
        result += bytes([0x00, 0x01])  # SegWit marker and flag

        # Inputs
        result += encode_varint(len(inputs))
        for inp in inputs:
            result += bytes.fromhex(inp["txid"])[::-1]
            result += struct.pack("<I", inp["vout"])
            scriptsig = bytes.fromhex(inp["scriptsig"])
            result += encode_varint(len(scriptsig))
            result += scriptsig
            result += struct.pack("<I", inp["sequence"])

        # Outputs
        result += encode_varint(len(outputs))
        for out in outputs:
            result += struct.pack("<Q", out["value"])
            scriptpubkey = bytes.fromhex(out["scriptpubkey"])
            result += encode_varint(len(scriptpubkey))
            result += scriptpubkey

        # Witnesses
        for witness in witnesses:
            result += encode_varint(len(witness))
            for item in witness:
                result += encode_varint(len(item))
                result += item

        result += struct.pack("<I", locktime)
        return result

    def get_txid(self, tx_bytes: bytes) -> str:
        """Calculate txid (double SHA256 of non-witness data)."""
        # For SegWit, txid excludes witness data
        version, marker, flag, inputs, outputs, witnesses, locktime = self._parse_tx(tx_bytes)

        # Serialize without witness
        data = struct.pack("<I", version)
        data += encode_varint(len(inputs))
        for inp in inputs:
            data += bytes.fromhex(inp["txid"])[::-1]
            data += struct.pack("<I", inp["vout"])
            scriptsig = bytes.fromhex(inp["scriptsig"])
            data += encode_varint(len(scriptsig))
            data += scriptsig
            data += struct.pack("<I", inp["sequence"])

        data += encode_varint(len(outputs))
        for out in outputs:
            data += struct.pack("<Q", out["value"])
            scriptpubkey = bytes.fromhex(out["scriptpubkey"])
            data += encode_varint(len(scriptpubkey))
            data += scriptpubkey

        data += struct.pack("<I", locktime)

        # Double SHA256
        return hash256(data)[::-1].hex()


def calculate_tx_fee(
    num_taker_inputs: int,
    num_maker_inputs: int,
    num_outputs: int,
    fee_rate: float,
) -> int:
    """
    Calculate transaction fee based on estimated vsize.

    SegWit P2WPKH inputs: ~68 vbytes each
    P2WPKH outputs: 31 vbytes each
    Overhead: ~11 vbytes

    Args:
        fee_rate: Fee rate in sat/vB (can be fractional, e.g. 0.5)

    Returns:
        Fee in satoshis (rounded up to ensure minimum relay fee)
    """
    # Estimate virtual size
    input_vsize = (num_taker_inputs + num_maker_inputs) * 68
    output_vsize = num_outputs * 31
    overhead = 11

    vsize = input_vsize + output_vsize + overhead

    # Round up to ensure we pay at least the minimum
    import math

    return math.ceil(vsize * fee_rate)


def build_coinjoin_tx(
    # Taker data
    taker_utxos: list[dict[str, Any]],
    taker_cj_address: str,
    taker_change_address: str,
    taker_total_input: int,
    # Maker data
    maker_data: dict[str, dict[str, Any]],  # nick -> {utxos, cj_addr, change_addr, cjfee, txfee}
    # Amounts
    cj_amount: int,
    tx_fee: int,
    network: str = "mainnet",
    dust_threshold: int = 27300,  # Default to DUST_THRESHOLD from jmcore.constants
) -> tuple[bytes, dict[str, Any]]:
    """
    Build a complete CoinJoin transaction.

    Args:
        taker_utxos: List of taker's UTXOs
        taker_cj_address: Taker's CJ output address
        taker_change_address: Taker's change address
        taker_total_input: Total value of taker's inputs
        maker_data: Dict of maker nick -> {utxos, cj_addr, change_addr, cjfee, txfee}
        cj_amount: Equal CoinJoin output amount
        tx_fee: Total transaction fee
        network: Network name
        dust_threshold: Minimum output value in satoshis (default: 27300)

    Returns:
        (tx_bytes, metadata)
    """
    builder = CoinJoinTxBuilder(network)

    # Build taker inputs
    taker_inputs = [
        TxInput(
            txid=u["txid"],
            vout=u["vout"],
            value=u["value"],
            scriptpubkey=u.get("scriptpubkey", ""),
        )
        for u in taker_utxos
    ]

    # Calculate taker's fees paid to makers
    total_maker_fee = sum(m["cjfee"] for m in maker_data.values())

    # Taker's change = total_input - cj_amount - maker_fees - tx_fee
    taker_change = taker_total_input - cj_amount - total_maker_fee - tx_fee

    # Taker CJ output
    taker_cj_output = TxOutput(address=taker_cj_address, value=cj_amount)

    # Taker change output (if any)
    taker_change_output = None
    if taker_change > dust_threshold:
        taker_change_output = TxOutput(address=taker_change_address, value=taker_change)
    elif taker_change > 0:
        logger.warning(
            f"Taker change {taker_change} sats is below dust threshold ({dust_threshold}), "
            "no change output will be created"
        )

    # Build maker data
    maker_inputs: dict[str, list[TxInput]] = {}
    maker_cj_outputs: dict[str, TxOutput] = {}
    maker_change_outputs: dict[str, TxOutput] = {}

    for nick, data in maker_data.items():
        # Maker inputs
        maker_inputs[nick] = [
            TxInput(
                txid=u["txid"],
                vout=u["vout"],
                value=u["value"],
                scriptpubkey=u.get("scriptpubkey", ""),
            )
            for u in data["utxos"]
        ]

        # Maker CJ output (cj_amount)
        maker_cj_outputs[nick] = TxOutput(address=data["cj_addr"], value=cj_amount)

        # Maker change output
        # Formula: change = inputs - cj_amount - txfee + cjfee
        # (Maker pays txfee, receives cjfee from taker)
        maker_total_input = sum(u["value"] for u in data["utxos"])
        maker_txfee = data.get("txfee", 0)
        maker_change = maker_total_input - cj_amount - maker_txfee + data["cjfee"]

        logger.debug(
            f"Maker {nick} change calculation: "
            f"inputs={maker_total_input}, cj_amount={cj_amount}, "
            f"cjfee={data['cjfee']}, txfee={maker_txfee}, change={maker_change}, "
            f"dust_threshold={dust_threshold}"
        )

        if maker_change < 0:
            # Negative change means maker's UTXOs are insufficient
            # This can happen if UTXO verification failed (value=0) or if UTXOs were spent
            raise ValueError(
                f"Maker {nick} has insufficient funds: inputs={maker_total_input} sats, "
                f"required={cj_amount + maker_txfee - data['cjfee']} sats, "
                f"change={maker_change} sats. Maker's UTXOs may have been spent."
            )
        elif maker_change > dust_threshold:
            maker_change_outputs[nick] = TxOutput(address=data["change_addr"], value=maker_change)
        else:
            logger.warning(
                f"Maker {nick} change {maker_change} sats is below dust threshold "
                f"({dust_threshold}), "
                "no change output will be created"
            )

    tx_data = CoinJoinTxData(
        taker_inputs=taker_inputs,
        taker_cj_output=taker_cj_output,
        taker_change_output=taker_change_output,
        maker_inputs=maker_inputs,
        maker_cj_outputs=maker_cj_outputs,
        maker_change_outputs=maker_change_outputs,
        cj_amount=cj_amount,
        total_maker_fee=total_maker_fee,
        tx_fee=tx_fee,
    )

    return builder.build_unsigned_tx(tx_data)
