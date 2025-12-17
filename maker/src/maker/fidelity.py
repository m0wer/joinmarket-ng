"""Fidelity bond utilities for maker bot."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from coincurve import PrivateKey
from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmwallet.wallet.service import WalletService
from loguru import logger

# Fidelity bonds are stored in mixdepth 0, internal branch 2
# Path format: m/84'/coin'/0'/2/index:locktime
FIDELITY_BOND_MIXDEPTH = 0
FIDELITY_BOND_INTERNAL_BRANCH = 2
CERT_EXPIRY_BLOCKS = 2016 * 52  # ~1 year in blocks


@dataclass
class FidelityBondInfo:
    txid: str
    vout: int
    value: int
    locktime: int
    confirmation_time: int
    bond_value: int
    pubkey: bytes | None = None
    private_key: PrivateKey | None = None


def _parse_locktime_from_path(path: str) -> int | None:
    """
    Extract locktime from a fidelity bond path.

    Fidelity bond paths have format: m/84'/coin'/0'/2/index:locktime
    where locktime is Unix timestamp.

    Args:
        path: BIP32 derivation path

    Returns:
        Locktime as Unix timestamp, or None if not a fidelity bond path
    """
    if ":" not in path:
        return None

    try:
        # Split on colon to get locktime
        locktime_str = path.split(":")[-1]
        return int(locktime_str)
    except (ValueError, IndexError):
        return None


def find_fidelity_bonds(
    wallet: WalletService, mixdepth: int = FIDELITY_BOND_MIXDEPTH
) -> list[FidelityBondInfo]:
    """
    Find fidelity bonds in the wallet.

    Fidelity bonds are timelocked UTXOs in mixdepth 0, internal branch 2.
    Path format: m/84'/coin'/0'/2/index:locktime
    They use a CLTV script: <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG

    Args:
        wallet: WalletService instance
        mixdepth: Mixdepth to search for bonds (default 0)

    Returns:
        List of FidelityBondInfo for each bond found
    """
    bonds: list[FidelityBondInfo] = []

    utxos = wallet.utxo_cache.get(mixdepth, [])
    if not utxos:
        return bonds

    for utxo_info in utxos:
        # Fidelity bonds are on internal branch 2 with locktime in path
        # Path format: m/84'/coin'/0'/2/index:locktime
        path_parts = utxo_info.path.split("/")
        if len(path_parts) < 5:
            continue

        # Check if this is internal branch 2 (fidelity bond branch)
        # path_parts[-2] is the branch (0=external, 1=internal change, 2=fidelity bonds)
        branch_part = path_parts[-2]
        if branch_part != str(FIDELITY_BOND_INTERNAL_BRANCH):
            continue

        # Extract locktime from path (format: index:locktime)
        locktime = _parse_locktime_from_path(utxo_info.path)
        if locktime is None:
            # Not a timelocked UTXO
            continue

        # Get the key for this address
        key = wallet.get_key_for_address(utxo_info.address)
        pubkey = key.get_public_key_bytes(compressed=True) if key else None
        private_key = key.private_key if key else None

        confirmation_time = utxo_info.confirmations

        bond_value = calculate_timelocked_fidelity_bond_value(
            utxo_value=utxo_info.value,
            confirmation_time=confirmation_time,
            locktime=locktime,
        )

        bonds.append(
            FidelityBondInfo(
                txid=utxo_info.txid,
                vout=utxo_info.vout,
                value=utxo_info.value,
                locktime=locktime,
                confirmation_time=confirmation_time,
                bond_value=bond_value,
                pubkey=pubkey,
                private_key=private_key,
            )
        )

    return bonds


def _pad_signature(sig_der: bytes, target_len: int = 72) -> bytes:
    """Pad DER signature to fixed length for wire format."""
    if len(sig_der) > target_len:
        raise ValueError(f"Signature too long: {len(sig_der)} > {target_len}")
    return sig_der + b"\x00" * (target_len - len(sig_der))


def _sign_message(private_key: PrivateKey, message: bytes) -> bytes:
    """Sign a message with ECDSA and return DER-encoded signature.

    coincurve.sign() returns a DER-encoded signature with low-S by default.
    It uses SHA256 hashing internally.
    """
    # coincurve sign() uses sha256 by default and returns low-S DER signature
    return private_key.sign(message)


def create_fidelity_bond_proof(
    bond: FidelityBondInfo,
    maker_nick: str,
    taker_nick: str,
    cert_expiry_blocks: int = CERT_EXPIRY_BLOCKS,
) -> str | None:
    """
    Create a fidelity bond proof for broadcasting.

    The proof structure (252 bytes total):
    - 72 bytes: UTXO ownership signature (signs H(taker_nick))
    - 72 bytes: Certificate signature (signs H(cert_pub || expiry || maker_nick))
    - 33 bytes: Certificate public key (same as utxo_pub for self-signed)
    - 2 bytes: Certificate expiry (blocks / 2016)
    - 33 bytes: UTXO public key
    - 32 bytes: TXID (little-endian)
    - 4 bytes: Vout (little-endian)
    - 4 bytes: Locktime (little-endian)

    Args:
        bond: FidelityBondInfo with UTXO details and private key
        maker_nick: Maker's JoinMarket nick
        taker_nick: Target taker's nick (for ownership proof)
        cert_expiry_blocks: Certificate expiry in blocks

    Returns:
        Base64-encoded proof string, or None if signing fails
    """
    if not bond.private_key or not bond.pubkey:
        logger.error("Bond missing private key or pubkey")
        return None

    try:
        # For self-signed certificates, cert_pub == utxo_pub
        cert_pub = bond.pubkey
        utxo_pub = bond.pubkey

        # Expiry encoded as blocks / 2016 (difficulty period)
        cert_expiry_encoded = cert_expiry_blocks // 2016

        # 1. UTXO ownership signature: proves ownership to taker
        # Signs SHA256(taker_nick)
        ownership_message = hashlib.sha256(taker_nick.encode("utf-8")).digest()
        ownership_sig = _sign_message(bond.private_key, ownership_message)
        ownership_sig_padded = _pad_signature(ownership_sig, 72)

        # 2. Certificate signature: self-signed certificate
        # Signs SHA256(cert_pub || expiry || maker_nick)
        cert_message_preimage = (
            cert_pub + cert_expiry_encoded.to_bytes(2, "little") + maker_nick.encode("utf-8")
        )
        cert_message = hashlib.sha256(cert_message_preimage).digest()
        cert_sig = _sign_message(bond.private_key, cert_message)
        cert_sig_padded = _pad_signature(cert_sig, 72)

        # 3. Pack the proof
        # TXID needs to be in little-endian (as stored in transactions)
        txid_bytes = bytes.fromhex(bond.txid)
        if len(txid_bytes) != 32:
            raise ValueError(f"Invalid txid length: {len(txid_bytes)}")

        proof_data = struct.pack(
            "<72s72s33sH33s32sII",
            ownership_sig_padded,
            cert_sig_padded,
            cert_pub,
            cert_expiry_encoded,
            utxo_pub,
            txid_bytes,
            bond.vout,
            bond.locktime,
        )

        if len(proof_data) != 252:
            raise ValueError(f"Invalid proof length: {len(proof_data)}, expected 252")

        return base64.b64encode(proof_data).decode("ascii")

    except Exception as e:
        logger.error(f"Failed to create bond proof: {e}")
        return None


def get_best_fidelity_bond(
    wallet: WalletService, mixdepth: int = FIDELITY_BOND_MIXDEPTH
) -> FidelityBondInfo | None:
    """
    Get the best (highest value) fidelity bond from the wallet.

    Args:
        wallet: WalletService instance
        mixdepth: Mixdepth to search

    Returns:
        Best FidelityBondInfo or None if no bonds found
    """
    bonds = find_fidelity_bonds(wallet, mixdepth)
    if not bonds:
        return None

    return max(bonds, key=lambda b: b.bond_value)
