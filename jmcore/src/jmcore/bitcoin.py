"""
Bitcoin utilities for JoinMarket.

This module provides consolidated Bitcoin operations:
- Address encoding/decoding (bech32, base58)
- Hash functions (hash160, hash256)
- Transaction parsing/serialization
- Varint encoding/decoding

Uses external libraries for security-critical operations:
- bech32: BIP173 bech32 encoding
- base58: Base58Check encoding
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

import base58
import bech32 as bech32_lib

from jmcore.constants import SATS_PER_BTC


class NetworkType(str, Enum):
    """Bitcoin network types."""

    MAINNET = "mainnet"
    TESTNET = "testnet"
    SIGNET = "signet"
    REGTEST = "regtest"


# Network prefixes for address encoding
HRP_MAP = {
    NetworkType.MAINNET: "bc",
    NetworkType.TESTNET: "tb",
    NetworkType.SIGNET: "tb",
    NetworkType.REGTEST: "bcrt",
}

# Base58 version bytes
P2PKH_VERSION = {
    NetworkType.MAINNET: 0x00,
    NetworkType.TESTNET: 0x6F,
    NetworkType.SIGNET: 0x6F,
    NetworkType.REGTEST: 0x6F,
}

P2SH_VERSION = {
    NetworkType.MAINNET: 0x05,
    NetworkType.TESTNET: 0xC4,
    NetworkType.SIGNET: 0xC4,
    NetworkType.REGTEST: 0xC4,
}


# =============================================================================
# Amount Utilities
# =============================================================================


def btc_to_sats(btc: float) -> int:
    """
    Convert BTC to satoshis safely.

    Uses round() instead of int() to avoid floating point precision errors
    that can truncate values (e.g. 0.0003 * 1e8 = 29999.999...).

    Args:
        btc: Amount in BTC

    Returns:
        Amount in satoshis
    """
    return round(btc * SATS_PER_BTC)


def sats_to_btc(sats: int) -> float:
    """
    Convert satoshis to BTC. Only use for display/output.

    Args:
        sats: Amount in satoshis

    Returns:
        Amount in BTC
    """
    return sats / SATS_PER_BTC


def format_amount(sats: int, include_unit: bool = True) -> str:
    """
    Format satoshi amount as string.
    Default: '1,000,000 sats (0.01000000 BTC)'

    Args:
        sats: Amount in satoshis
        include_unit: Whether to include units and BTC conversion

    Returns:
        Formatted string
    """
    if include_unit:
        btc_val = sats_to_btc(sats)
        return f"{sats:,} sats ({btc_val:.8f} BTC)"
    return f"{sats:,}"


def validate_satoshi_amount(sats: int) -> None:
    """
    Validate that amount is a non-negative integer.

    Args:
        sats: Amount to validate

    Raises:
        TypeError: If amount is not an integer
        ValueError: If amount is negative
    """
    if not isinstance(sats, int):
        raise TypeError(f"Amount must be an integer (satoshis), got {type(sats)}")
    if sats < 0:
        raise ValueError(f"Amount cannot be negative, got {sats}")


def calculate_relative_fee(amount_sats: int, fee_rate: str) -> int:
    """
    Calculate relative fee in satoshis from a fee rate string.

    Args:
        amount_sats: Amount in satoshis
        fee_rate: Fee rate as decimal string (e.g., "0.001" = 0.1%)

    Returns:
        Fee in satoshis (rounded down)

    Examples:
        >>> calculate_relative_fee(100_000_000, "0.001")
        100000  # 0.1% of 1 BTC
        >>> calculate_relative_fee(50_000_000, "0.002")
        100000  # 0.2% of 0.5 BTC
    """
    validate_satoshi_amount(amount_sats)

    # Parse fee rate as numerator/denominator (avoids float/Decimal)
    if "." not in fee_rate:
        try:
            # Handle integer strings like "0" or "1"
            val = int(fee_rate)
            return int(amount_sats * val)
        except ValueError as e:
            raise ValueError(f"Fee rate must be decimal string or integer, got {fee_rate}") from e

    parts = fee_rate.split(".")
    if len(parts) != 2:
        raise ValueError(f"Invalid fee rate format: {fee_rate}")

    numerator = int(parts[0] + parts[1])  # "0.001" -> 1
    denominator = 10 ** len(parts[1])  # 3 decimals -> 1000

    # Integer division (rounds down)
    return (amount_sats * numerator) // denominator


def calculate_sweep_amount(available_sats: int, relative_fees: list[str]) -> int:
    """
    Calculate CoinJoin amount for a sweep (no change output).

    The taker must pay maker fees from the swept amount:
    available = cj_amount + fees
    fees = sum(fee_rate * cj_amount for each maker)

    Solving for cj_amount:
    available = cj_amount * (1 + sum(fee_rates))
    cj_amount = available / (1 + sum(fee_rates))

    Args:
        available_sats: Total available balance in satoshis
        relative_fees: List of relative fee strings (e.g., ["0.001", "0.002"])

    Returns:
        CoinJoin amount in satoshis (maximum amount after paying all fees)
    """
    validate_satoshi_amount(available_sats)

    if not relative_fees:
        return available_sats

    # Parse all fee rates as fractions with common denominator
    # Example: ["0.001", "0.0015"] -> numerators=[1, 15], denominator=10000
    try:
        max_decimals = 0
        for fee in relative_fees:
            if "." in fee:
                max_decimals = max(max_decimals, len(fee.split(".")[1]))
    except IndexError as e:
        raise ValueError(f"Invalid fee format in {relative_fees}") from e

    denominator = 10**max_decimals

    sum_numerators = 0
    for fee_rate in relative_fees:
        if "." in fee_rate:
            parts = fee_rate.split(".")
            # Normalize to common denominator
            # "0.001" with max_decimals=4 -> 10 (because 0.001 = 10/10000)
            numerator = int(parts[0] + parts[1]) * (10 ** (max_decimals - len(parts[1])))
            sum_numerators += numerator
        else:
            # Handle integer fee rates (unlikely for relative fees but good for robustness)
            numerator = int(fee_rate) * denominator
            sum_numerators += numerator

    # cj_amount = available / (1 + sum_rel_fees)
    #           = available / ((denominator + sum_numerators) / denominator)
    #           = (available * denominator) / (denominator + sum_numerators)
    return (available_sats * denominator) // (denominator + sum_numerators)


# =============================================================================
# Hash Functions
# =============================================================================


def hash160(data: bytes) -> bytes:
    """
    RIPEMD160(SHA256(data)) - Used for Bitcoin addresses.

    Args:
        data: Input data to hash

    Returns:
        20-byte hash
    """
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def hash256(data: bytes) -> bytes:
    """
    SHA256(SHA256(data)) - Used for Bitcoin txids and block hashes.

    Args:
        data: Input data to hash

    Returns:
        32-byte hash
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def sha256(data: bytes) -> bytes:
    """
    Single SHA256 hash.

    Args:
        data: Input data to hash

    Returns:
        32-byte hash
    """
    return hashlib.sha256(data).digest()


# =============================================================================
# Varint Encoding/Decoding
# =============================================================================


def encode_varint(n: int) -> bytes:
    """
    Encode integer as Bitcoin varint.

    Args:
        n: Integer to encode

    Returns:
        Encoded bytes
    """
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return bytes([0xFD]) + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return bytes([0xFE]) + struct.pack("<I", n)
    else:
        return bytes([0xFF]) + struct.pack("<Q", n)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode Bitcoin varint from bytes.

    Args:
        data: Input bytes
        offset: Starting offset in data

    Returns:
        (value, new_offset) tuple
    """
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack("<H", data[offset + 1 : offset + 3])[0], offset + 3
    elif first == 0xFE:
        return struct.unpack("<I", data[offset + 1 : offset + 5])[0], offset + 5
    else:
        return struct.unpack("<Q", data[offset + 1 : offset + 9])[0], offset + 9


# =============================================================================
# Address Encoding/Decoding
# =============================================================================


def get_hrp(network: str | NetworkType) -> str:
    """
    Get bech32 human-readable part for network.

    Args:
        network: Network type (string or enum)

    Returns:
        HRP string (bc, tb, bcrt)
    """
    if isinstance(network, str):
        network = NetworkType(network)
    return HRP_MAP[network]


def pubkey_to_p2wpkh_address(pubkey: bytes | str, network: str | NetworkType = "mainnet") -> str:
    """
    Convert compressed public key to P2WPKH (native SegWit) address.

    Args:
        pubkey: 33-byte compressed public key (bytes or hex string)
        network: Network type

    Returns:
        Bech32 P2WPKH address
    """
    if isinstance(pubkey, str):
        pubkey = bytes.fromhex(pubkey)

    if len(pubkey) != 33:
        raise ValueError(f"Invalid compressed pubkey length: {len(pubkey)}")

    pubkey_hash = hash160(pubkey)
    hrp = get_hrp(network)

    result = bech32_lib.encode(hrp, 0, pubkey_hash)
    if result is None:
        raise ValueError("Failed to encode bech32 address")
    return result


def pubkey_to_p2wpkh_script(pubkey: bytes | str) -> bytes:
    """
    Create P2WPKH scriptPubKey from public key.

    Args:
        pubkey: 33-byte compressed public key (bytes or hex string)

    Returns:
        22-byte P2WPKH scriptPubKey (OP_0 <20-byte-hash>)
    """
    if isinstance(pubkey, str):
        pubkey = bytes.fromhex(pubkey)

    pubkey_hash = hash160(pubkey)
    return bytes([0x00, 0x14]) + pubkey_hash


def script_to_p2wsh_address(script: bytes, network: str | NetworkType = "mainnet") -> str:
    """
    Convert witness script to P2WSH address.

    Args:
        script: Witness script bytes
        network: Network type

    Returns:
        Bech32 P2WSH address
    """
    script_hash = sha256(script)
    hrp = get_hrp(network)

    result = bech32_lib.encode(hrp, 0, script_hash)
    if result is None:
        raise ValueError("Failed to encode bech32 address")
    return result


def script_to_p2wsh_scriptpubkey(script: bytes) -> bytes:
    """
    Create P2WSH scriptPubKey from witness script.

    Args:
        script: Witness script bytes

    Returns:
        34-byte P2WSH scriptPubKey (OP_0 <32-byte-hash>)
    """
    script_hash = sha256(script)
    return bytes([0x00, 0x20]) + script_hash


def address_to_scriptpubkey(address: str) -> bytes:
    """
    Convert Bitcoin address to scriptPubKey.

    Supports:
    - P2WPKH (bc1q..., tb1q..., bcrt1q...)
    - P2WSH (bc1q... 62 chars)
    - P2TR (bc1p... taproot)
    - P2PKH (1..., m..., n...)
    - P2SH (3..., 2...)

    Args:
        address: Bitcoin address string

    Returns:
        scriptPubKey bytes
    """
    # Bech32 (SegWit) addresses
    if address.startswith(("bc1", "tb1", "bcrt1")):
        hrp_end = 4 if address.startswith("bcrt") else 2
        hrp = address[:hrp_end]

        bech32_decoded = bech32_lib.decode(hrp, address)
        if bech32_decoded[0] is None or bech32_decoded[1] is None:
            raise ValueError(f"Invalid bech32 address: {address}")

        witver = bech32_decoded[0]
        witprog = bytes(bech32_decoded[1])

        if witver == 0:
            if len(witprog) == 20:
                # P2WPKH: OP_0 <20-byte-pubkeyhash>
                return bytes([0x00, 0x14]) + witprog
            elif len(witprog) == 32:
                # P2WSH: OP_0 <32-byte-scripthash>
                return bytes([0x00, 0x20]) + witprog
        elif witver == 1 and len(witprog) == 32:
            # P2TR: OP_1 <32-byte-pubkey>
            return bytes([0x51, 0x20]) + witprog

        raise ValueError(f"Unsupported witness version: {witver}")

    # Base58 addresses (legacy)
    decoded = base58.b58decode_check(address)
    version = decoded[0]
    payload = decoded[1:]

    if version in (0x00, 0x6F):  # Mainnet/Testnet P2PKH
        # P2PKH: OP_DUP OP_HASH160 <20-byte-pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        return bytes([0x76, 0xA9, 0x14]) + payload + bytes([0x88, 0xAC])
    elif version in (0x05, 0xC4):  # Mainnet/Testnet P2SH
        # P2SH: OP_HASH160 <20-byte-scripthash> OP_EQUAL
        return bytes([0xA9, 0x14]) + payload + bytes([0x87])

    raise ValueError(f"Unknown address version: {version}")


def scriptpubkey_to_address(scriptpubkey: bytes, network: str | NetworkType = "mainnet") -> str:
    """
    Convert scriptPubKey to address.

    Supports P2WPKH, P2WSH, P2TR, P2PKH, P2SH.

    Args:
        scriptpubkey: scriptPubKey bytes
        network: Network type

    Returns:
        Bitcoin address string
    """
    if isinstance(network, str):
        network = NetworkType(network)

    hrp = get_hrp(network)

    # P2WPKH
    if len(scriptpubkey) == 22 and scriptpubkey[0] == 0x00 and scriptpubkey[1] == 0x14:
        result = bech32_lib.encode(hrp, 0, scriptpubkey[2:])
        if result is None:
            raise ValueError(f"Failed to encode P2WPKH address: {scriptpubkey.hex()}")
        return result

    # P2WSH
    if len(scriptpubkey) == 34 and scriptpubkey[0] == 0x00 and scriptpubkey[1] == 0x20:
        result = bech32_lib.encode(hrp, 0, scriptpubkey[2:])
        if result is None:
            raise ValueError(f"Failed to encode P2WSH address: {scriptpubkey.hex()}")
        return result

    # P2TR
    if len(scriptpubkey) == 34 and scriptpubkey[0] == 0x51 and scriptpubkey[1] == 0x20:
        result = bech32_lib.encode(hrp, 1, scriptpubkey[2:])
        if result is None:
            raise ValueError(f"Failed to encode P2TR address: {scriptpubkey.hex()}")
        return result

    # P2PKH
    if (
        len(scriptpubkey) == 25
        and scriptpubkey[0] == 0x76
        and scriptpubkey[1] == 0xA9
        and scriptpubkey[2] == 0x14
        and scriptpubkey[23] == 0x88
        and scriptpubkey[24] == 0xAC
    ):
        payload = bytes([P2PKH_VERSION[network]]) + scriptpubkey[3:23]
        return base58.b58encode_check(payload).decode("ascii")

    # P2SH
    if (
        len(scriptpubkey) == 23
        and scriptpubkey[0] == 0xA9
        and scriptpubkey[1] == 0x14
        and scriptpubkey[22] == 0x87
    ):
        payload = bytes([P2SH_VERSION[network]]) + scriptpubkey[2:22]
        return base58.b58encode_check(payload).decode("ascii")

    raise ValueError(f"Unsupported scriptPubKey: {scriptpubkey.hex()}")


# =============================================================================
# Transaction Models
# =============================================================================


@dataclass
class TxInput:
    """Transaction input."""

    txid: str  # In RPC format (big-endian hex)
    vout: int
    value: int = 0
    scriptpubkey: str = ""
    scriptsig: str = ""
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOutput:
    """Transaction output."""

    address: str
    value: int
    scriptpubkey: str = ""


@dataclass
class ParsedTransaction:
    """Parsed Bitcoin transaction."""

    version: int
    inputs: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    witnesses: list[list[bytes]]
    locktime: int
    has_witness: bool


# =============================================================================
# Transaction Serialization/Parsing
# =============================================================================


def serialize_outpoint(txid: str, vout: int) -> bytes:
    """
    Serialize outpoint (txid:vout).

    Args:
        txid: Transaction ID in RPC format (big-endian hex)
        vout: Output index

    Returns:
        36-byte outpoint (little-endian txid + 4-byte vout)
    """
    txid_bytes = bytes.fromhex(txid)[::-1]
    return txid_bytes + struct.pack("<I", vout)


def serialize_input(inp: TxInput, include_scriptsig: bool = True) -> bytes:
    """
    Serialize a transaction input.

    Args:
        inp: Transaction input
        include_scriptsig: Whether to include scriptSig

    Returns:
        Serialized input bytes
    """
    result = serialize_outpoint(inp.txid, inp.vout)

    if include_scriptsig and inp.scriptsig:
        scriptsig = bytes.fromhex(inp.scriptsig)
        result += encode_varint(len(scriptsig)) + scriptsig
    else:
        result += bytes([0x00])  # Empty scriptSig

    result += struct.pack("<I", inp.sequence)
    return result


def serialize_output(out: TxOutput) -> bytes:
    """
    Serialize a transaction output.

    Args:
        out: Transaction output

    Returns:
        Serialized output bytes
    """
    result = struct.pack("<Q", out.value)

    scriptpubkey = (
        bytes.fromhex(out.scriptpubkey)
        if out.scriptpubkey
        else address_to_scriptpubkey(out.address)
    )
    result += encode_varint(len(scriptpubkey))
    result += scriptpubkey
    return result


def parse_transaction(tx_hex: str) -> ParsedTransaction:
    """
    Parse a Bitcoin transaction from hex.

    Handles both SegWit and non-SegWit formats.

    Args:
        tx_hex: Transaction hex string

    Returns:
        ParsedTransaction object
    """
    tx_bytes = bytes.fromhex(tx_hex)
    offset = 0

    # Version
    version = struct.unpack("<I", tx_bytes[offset : offset + 4])[0]
    offset += 4

    # Check for SegWit marker
    marker = tx_bytes[offset]
    flag = tx_bytes[offset + 1]
    has_witness = marker == 0x00 and flag == 0x01
    if has_witness:
        offset += 2

    # Inputs
    input_count, offset = decode_varint(tx_bytes, offset)
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
        inputs.append({"txid": txid, "vout": vout, "scriptsig": scriptsig, "sequence": sequence})

    # Outputs
    output_count, offset = decode_varint(tx_bytes, offset)
    outputs = []
    for _ in range(output_count):
        value = struct.unpack("<Q", tx_bytes[offset : offset + 8])[0]
        offset += 8
        script_len, offset = decode_varint(tx_bytes, offset)
        scriptpubkey = tx_bytes[offset : offset + script_len].hex()
        offset += script_len
        outputs.append({"value": value, "scriptpubkey": scriptpubkey})

    # Witnesses
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

    return ParsedTransaction(
        version=version,
        inputs=inputs,
        outputs=outputs,
        witnesses=witnesses,
        locktime=locktime,
        has_witness=has_witness,
    )


def serialize_transaction(
    version: int,
    inputs: list[dict[str, Any]],
    outputs: list[dict[str, Any]],
    locktime: int,
    witnesses: list[list[bytes]] | None = None,
) -> bytes:
    """
    Serialize a Bitcoin transaction.

    Args:
        version: Transaction version
        inputs: List of input dicts
        outputs: List of output dicts
        locktime: Transaction locktime
        witnesses: Optional list of witness stacks

    Returns:
        Serialized transaction bytes
    """
    has_witness = witnesses is not None and any(w for w in witnesses)

    result = struct.pack("<I", version)

    if has_witness:
        result += bytes([0x00, 0x01])  # SegWit marker and flag

    # Inputs
    result += encode_varint(len(inputs))
    for inp in inputs:
        result += bytes.fromhex(inp["txid"])[::-1]
        result += struct.pack("<I", inp["vout"])
        scriptsig = bytes.fromhex(inp.get("scriptsig", ""))
        result += encode_varint(len(scriptsig))
        result += scriptsig
        result += struct.pack("<I", inp.get("sequence", 0xFFFFFFFF))

    # Outputs
    result += encode_varint(len(outputs))
    for out in outputs:
        result += struct.pack("<Q", out["value"])
        scriptpubkey = bytes.fromhex(out["scriptpubkey"])
        result += encode_varint(len(scriptpubkey))
        result += scriptpubkey

    # Witnesses
    if has_witness and witnesses:
        for witness in witnesses:
            result += encode_varint(len(witness))
            for item in witness:
                result += encode_varint(len(item))
                result += item

    result += struct.pack("<I", locktime)
    return result


def get_txid(tx_hex: str) -> str:
    """
    Calculate transaction ID (double SHA256 of non-witness data).

    Args:
        tx_hex: Transaction hex

    Returns:
        Transaction ID as hex string
    """
    parsed = parse_transaction(tx_hex)

    # Serialize without witness for txid calculation
    data = serialize_transaction(
        version=parsed.version,
        inputs=parsed.inputs,
        outputs=parsed.outputs,
        locktime=parsed.locktime,
        witnesses=None,  # No witnesses for txid
    )

    return hash256(data)[::-1].hex()


# =============================================================================
# Script Code (for signing)
# =============================================================================


def create_p2wpkh_script_code(pubkey: bytes | str) -> bytes:
    """
    Create scriptCode for P2WPKH signing (BIP143).

    For P2WPKH, the scriptCode is the P2PKH script:
    OP_DUP OP_HASH160 <20-byte-pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

    Args:
        pubkey: Public key bytes or hex

    Returns:
        25-byte scriptCode
    """
    if isinstance(pubkey, str):
        pubkey = bytes.fromhex(pubkey)

    pubkey_hash = hash160(pubkey)
    # OP_DUP OP_HASH160 PUSH20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
