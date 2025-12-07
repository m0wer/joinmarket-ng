"""
Bitcoin address generation utilities.
"""

from __future__ import annotations

import hashlib


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    h = hashlib.new("ripemd160")
    h.update(hashlib.sha256(data).digest())
    return h.digest()


def bech32_polymod(values: list[int]) -> int:
    """Bech32 checksum polymod"""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand HRP for bech32"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    """Create bech32 checksum"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int]) -> str:
    """Encode bech32 string"""
    combined = data + bech32_create_checksum(hrp, data)
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join([charset[d] for d in combined])


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """Convert between bit groups"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid bits")

    return ret


def pubkey_to_p2wpkh_address(pubkey_hex: str, network: str = "mainnet") -> str:
    """
    Convert compressed public key to P2WPKH (native segwit) address.
    BIP173 bech32 encoding.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    if len(pubkey_bytes) != 33:
        raise ValueError(f"Invalid compressed pubkey length: {len(pubkey_bytes)}")

    pubkey_hash = hash160(pubkey_bytes)

    hrp = "bc" if network == "mainnet" else "tb" if network == "testnet" else "bcrt"

    witness_version = 0
    witness_program = convertbits(pubkey_hash, 8, 5)

    address = bech32_encode(hrp, [witness_version] + witness_program)
    return address


def pubkey_to_p2wpkh_script(pubkey_hex: str) -> bytes:
    """Create P2WPKH scriptPubKey (OP_0 <20-byte-hash>)"""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    pubkey_hash = hash160(pubkey_bytes)

    return bytes([0x00, 0x14]) + pubkey_hash
