"""Fidelity bond utilities for maker bot."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmwallet.wallet.service import WalletService
from loguru import logger

FIDELITY_BOND_MIXDEPTH = 4
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
    private_key: ec.EllipticCurvePrivateKey | None = None


def find_fidelity_bonds(
    wallet: WalletService, mixdepth: int = FIDELITY_BOND_MIXDEPTH
) -> list[FidelityBondInfo]:
    """
    Find fidelity bonds in the wallet.

    Fidelity bonds are timelocked UTXOs in a specific mixdepth (default 4).
    They use a CLTV script: <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG

    Args:
        wallet: WalletService instance
        mixdepth: Mixdepth to search for bonds (default 4)

    Returns:
        List of FidelityBondInfo for each bond found
    """
    bonds: list[FidelityBondInfo] = []

    utxos_by_mixdepth = wallet.utxo_cache
    utxos = utxos_by_mixdepth.get(mixdepth)
    if not utxos:
        return bonds

    for (txid, vout), info in utxos.items():
        path = info.path
        # Fidelity bonds typically use internal (change) addresses
        if not path.endswith("/1"):
            continue

        # Get the key for this address
        key = wallet.get_key_for_address(info.address)
        pubkey = key.get_public_key_bytes(compressed=True) if key else None
        private_key = key.private_key if key else None

        # Note: In production, we'd need to detect actual locktime from the UTXO script
        # For now, we assume UTXOs in mixdepth 4 with /1 path suffix are timelocked
        # The locktime would be extracted from the redeem script
        locktime = 0  # TODO: Extract from script when on-chain validation is added

        confirmation_time = info.confirmations

        bond_value = calculate_timelocked_fidelity_bond_value(
            utxo_value=info.value,
            confirmation_time=confirmation_time,
            locktime=locktime,
        )

        bonds.append(
            FidelityBondInfo(
                txid=txid,
                vout=vout,
                value=info.value,
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


def _sign_message(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign a message with ECDSA and return DER-encoded signature."""
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    # Ensure low-S (BIP 62)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > n // 2:
        s = n - s
    return utils.encode_dss_signature(r, s)


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
