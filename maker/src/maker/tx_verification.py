"""
Transaction verification for makers.

This is THE MOST CRITICAL security component. Any bug here can result in loss of funds!

The maker must verify that the unsigned CoinJoin transaction proposed by the taker:
1. Includes all maker's UTXOs as inputs
2. Pays the correct CoinJoin amount to maker's CJ address
3. Pays the correct change amount to maker's change address
4. Results in positive profit for maker (cjfee - txfee > 0)
5. Contains no unexpected outputs
6. Is well-formed and valid

Reference: joinmarket-clientserver/src/jmclient/maker.py:verify_unsigned_tx()
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from jmcore.models import OfferType
from jmwallet.wallet.models import UTXOInfo
from loguru import logger


class TransactionVerificationError(Exception):
    """Raised when transaction verification fails"""

    pass


def calculate_cj_fee(offer_type: OfferType, cjfee: str | int, amount: int) -> int:
    """
    Calculate actual CoinJoin fee based on offer type.

    Args:
        offer_type: Absolute or relative offer type
        cjfee: Fee (int for absolute, string decimal for relative)
        amount: CoinJoin amount in satoshis

    Returns:
        Actual fee in satoshis
    """
    if offer_type in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
        return int(cjfee)
    else:
        return int(Decimal(str(cjfee)) * Decimal(amount))


def verify_unsigned_transaction(
    tx_hex: str,
    our_utxos: dict[tuple[str, int], UTXOInfo],
    cj_address: str,
    change_address: str,
    amount: int,
    cjfee: str | int,
    txfee: int,
    offer_type: OfferType,
) -> tuple[bool, str]:
    """
    Verify unsigned CoinJoin transaction proposed by taker.

    CRITICAL SECURITY FUNCTION - Any bug can result in loss of funds!

    Args:
        tx_hex: Unsigned transaction hex
        our_utxos: Our UTXOs that should be in the transaction
        cj_address: Our CoinJoin output address
        change_address: Our change output address
        amount: CoinJoin amount (satoshis)
        cjfee: CoinJoin fee (format depends on offer_type)
        txfee: Transaction fee we're contributing (satoshis)
        offer_type: Offer type (absolute or relative fee)

    Returns:
        (is_valid, error_message)
    """
    try:
        tx = parse_transaction(tx_hex)

        if tx is None:
            return False, "Failed to parse transaction"

        tx_inputs = tx["inputs"]
        tx_outputs = tx["outputs"]

        our_utxo_set = set(our_utxos.keys())
        tx_utxo_set = {(inp["txid"], inp["vout"]) for inp in tx_inputs}

        if not tx_utxo_set.issuperset(our_utxo_set):
            missing = our_utxo_set - tx_utxo_set
            return False, f"Our UTXOs not included in transaction: {missing}"

        my_total_in = sum(utxo.value for utxo in our_utxos.values())

        real_cjfee = calculate_cj_fee(offer_type, cjfee, amount)

        expected_change_value = my_total_in - amount - txfee + real_cjfee

        potentially_earned = real_cjfee - txfee

        if potentially_earned < 0:
            return (
                False,
                f"Negative profit calculated: {potentially_earned} sats "
                f"(cjfee={real_cjfee}, txfee={txfee})",
            )

        logger.info(f"Potentially earned: {potentially_earned} sats")
        logger.info(f"Expected change value: {expected_change_value} sats")
        logger.info(f"CJ address: {cj_address}, Change address: {change_address}")

        times_seen_cj_addr = 0
        times_seen_change_addr = 0

        for output in tx_outputs:
            output_addr = output["address"]
            output_value = output["value"]

            if output_addr == cj_address:
                times_seen_cj_addr += 1
                if output_value < amount:
                    return (
                        False,
                        f"CJ output value too low: {output_value} < {amount}",
                    )

            if output_addr == change_address:
                times_seen_change_addr += 1
                if output_value < expected_change_value:
                    return (
                        False,
                        f"Change output value too low: {output_value} < {expected_change_value}",
                    )

        if times_seen_cj_addr != 1:
            return (
                False,
                f"CJ address appears {times_seen_cj_addr} times (expected 1)",
            )

        if times_seen_change_addr != 1:
            return (
                False,
                f"Change address appears {times_seen_change_addr} times (expected 1)",
            )

        logger.info("Transaction verification PASSED ✓")
        return True, ""

    except Exception as e:
        logger.error(f"Transaction verification exception: {e}")
        return False, f"Verification error: {e}"


def parse_transaction(tx_hex: str) -> dict[str, Any] | None:
    """
    Parse Bitcoin transaction hex.

    This is a simplified parser for CoinJoin transactions.
    For production, use a proper Bitcoin library.

    Returns:
        {
            'inputs': [{'txid': str, 'vout': int}, ...],
            'outputs': [{'address': str, 'value': int}, ...],
        }
    """
    try:
        tx_bytes = bytes.fromhex(tx_hex)

        offset = 0

        version = int.from_bytes(tx_bytes[offset : offset + 4], "little")
        offset += 4

        segwit = False
        if tx_bytes[offset] == 0x00:
            marker = tx_bytes[offset]
            flag = tx_bytes[offset + 1]
            if marker == 0x00 and flag == 0x01:
                segwit = True
                offset += 2

        input_count, offset = read_varint(tx_bytes, offset)

        inputs = []
        for _ in range(input_count):
            txid = tx_bytes[offset : offset + 32][::-1].hex()
            offset += 32

            vout = int.from_bytes(tx_bytes[offset : offset + 4], "little")
            offset += 4

            script_len, offset = read_varint(tx_bytes, offset)
            offset += script_len

            sequence = int.from_bytes(tx_bytes[offset : offset + 4], "little")
            offset += 4

            inputs.append({"txid": txid, "vout": vout})

        output_count, offset = read_varint(tx_bytes, offset)

        outputs = []
        for _ in range(output_count):
            value = int.from_bytes(tx_bytes[offset : offset + 8], "little")
            offset += 8

            script_len, offset = read_varint(tx_bytes, offset)
            script_pubkey = tx_bytes[offset : offset + script_len]
            offset += script_len

            address = script_to_address(script_pubkey)

            outputs.append({"value": value, "address": address})

        return {"inputs": inputs, "outputs": outputs}

    except Exception as e:
        logger.error(f"Failed to parse transaction: {e}")
        return None


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read variable-length integer from bytes"""
    first_byte = data[offset]
    offset += 1

    if first_byte < 0xFD:
        return first_byte, offset
    elif first_byte == 0xFD:
        value = int.from_bytes(data[offset : offset + 2], "little")
        return value, offset + 2
    elif first_byte == 0xFE:
        value = int.from_bytes(data[offset : offset + 4], "little")
        return value, offset + 4
    else:
        value = int.from_bytes(data[offset : offset + 8], "little")
        return value, offset + 8


def script_to_address(script: bytes) -> str:
    """
    Convert scriptPubKey to address.

    Simplified implementation - only handles P2WPKH for now.
    For production, use proper Bitcoin library.
    """
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        from jmwallet.wallet.address import bech32_encode, convertbits

        witness_program = script[2:]
        data = convertbits(witness_program, 8, 5)

        hrp = "bcrt"
        address = bech32_encode(hrp, [0] + data)
        return address

    return script.hex()
