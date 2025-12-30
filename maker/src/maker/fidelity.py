"""Fidelity bond utilities for maker bot."""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass

from coincurve import PrivateKey
from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmcore.crypto import bitcoin_message_hash
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
    # Certificate fields (for cold wallet support)
    cert_pubkey: bytes | None = None
    cert_privkey: PrivateKey | None = None  # Hot wallet private key for signing nicks
    cert_signature: bytes | None = None
    cert_expiry: int | None = None


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

    This function also loads certificate information from the bond registry if available,
    allowing for cold wallet support.

    Args:
        wallet: WalletService instance
        mixdepth: Mixdepth to search for bonds (default 0)

    Returns:
        List of FidelityBondInfo for each bond found
    """
    bonds: list[FidelityBondInfo] = []

    # Try to load bond registry for certificate information
    registry = None
    try:
        from pathlib import Path

        from jmcore.paths import get_default_data_dir
        from jmwallet.wallet.bond_registry import load_registry

        data_dir = get_default_data_dir()
        registry = load_registry(Path(data_dir))
        logger.debug(f"Loaded bond registry with {len(registry.bonds)} bonds")
    except Exception as e:
        logger.debug(f"Could not load bond registry: {e}")

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

        # Check registry for certificate information
        cert_pubkey = None
        cert_privkey = None
        cert_signature = None
        cert_expiry = None

        if registry is not None:
            registry_bond = registry.get_bond_by_address(utxo_info.address)
            if registry_bond and registry_bond.has_certificate:
                try:
                    cert_pubkey = bytes.fromhex(registry_bond.cert_pubkey)  # type: ignore
                    cert_privkey = PrivateKey(
                        bytes.fromhex(registry_bond.cert_privkey)  # type: ignore
                    )
                    cert_signature = bytes.fromhex(registry_bond.cert_signature)  # type: ignore
                    cert_expiry = registry_bond.cert_expiry
                    logger.debug(
                        f"Found certificate for bond {utxo_info.address[:20]}... "
                        f"(expiry: {cert_expiry} periods)"
                    )
                except Exception as e:
                    logger.warning(f"Failed to parse certificate for {utxo_info.address}: {e}")

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
                cert_pubkey=cert_pubkey,
                cert_privkey=cert_privkey,
                cert_signature=cert_signature,
                cert_expiry=cert_expiry,
            )
        )

    return bonds

    return bonds


def _pad_signature(sig_der: bytes, target_len: int = 72) -> bytes:
    """
    Pad DER signature to fixed length for wire format.

    Uses leading 0xff padding (rjust) to match the reference implementation.
    The verifier strips padding by finding the DER header (0x30).
    """
    if len(sig_der) > target_len:
        raise ValueError(f"Signature too long: {len(sig_der)} > {target_len}")
    return sig_der.rjust(target_len, b"\xff")


def _sign_message_bitcoin(private_key: PrivateKey, message: bytes) -> bytes:
    """
    Sign a message using Bitcoin message signing format.

    Args:
        private_key: coincurve PrivateKey
        message: Raw message bytes (NOT pre-hashed)

    Returns:
        DER-encoded signature
    """
    msg_hash = bitcoin_message_hash(message)
    return private_key.sign(msg_hash, hasher=None)


def create_fidelity_bond_proof(
    bond: FidelityBondInfo,
    maker_nick: str,
    taker_nick: str,
    cert_expiry_blocks: int = CERT_EXPIRY_BLOCKS,
) -> str | None:
    """
    Create a fidelity bond proof for broadcasting.

    The proof structure (252 bytes total):
    - 72 bytes: Nick signature (signs "taker_nick|maker_nick" with Bitcoin message format)
    - 72 bytes: Certificate signature (signs cert message with Bitcoin message format)
    - 33 bytes: Certificate public key (hot wallet key or same as utxo_pub for self-signed)
    - 2 bytes: Certificate expiry (blocks / 2016)
    - 33 bytes: UTXO public key (cold wallet key)
    - 32 bytes: TXID (little-endian)
    - 4 bytes: Vout (little-endian)
    - 4 bytes: Locktime (little-endian)

    Nick signature message format:
        (taker_nick + '|' + maker_nick).encode('ascii')

    Certificate signature message format (binary):
        b'fidelity-bond-cert|' + cert_pub + b'|' + str(cert_expiry_encoded).encode('ascii')

    Both signatures use Bitcoin message signing format (double SHA256 with prefix).

    This function supports two modes:
    1. **Self-signed mode** (hot wallet): bond.private_key is available, signs everything
    2. **Certificate mode** (cold wallet): bond.cert_* fields are set, uses pre-signed cert

    Args:
        bond: FidelityBondInfo with UTXO details and either private key or certificate
        maker_nick: Maker's JoinMarket nick
        taker_nick: Target taker's nick (for ownership proof)
        cert_expiry_blocks: Certificate expiry in blocks (only used in self-signed mode)

    Returns:
        Base64-encoded proof string, or None if signing fails
    """
    if not bond.pubkey:
        logger.error("Bond missing pubkey")
        return None

    try:
        # Determine if we're using a certificate (cold wallet) or self-signing (hot wallet)
        use_certificate = (
            bond.cert_pubkey is not None
            and bond.cert_privkey is not None
            and bond.cert_signature is not None
            and bond.cert_expiry is not None
        )

        if use_certificate:
            # COLD WALLET MODE: Use pre-signed certificate
            cert_pub = bond.cert_pubkey  # type: ignore
            cert_sig = bond.cert_signature  # type: ignore
            cert_expiry_encoded = bond.cert_expiry  # type: ignore
            utxo_pub = bond.pubkey

            logger.debug(
                f"Using certificate mode for bond proof (cert_expiry={cert_expiry_encoded})"
            )

            # Sign nick message with hot wallet cert_privkey
            nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
            nick_sig = _sign_message_bitcoin(bond.cert_privkey, nick_msg)  # type: ignore
            nick_sig_padded = _pad_signature(nick_sig, 72)

            # Use pre-signed certificate signature (already padded if needed)
            cert_sig_padded = _pad_signature(cert_sig, 72)

        else:
            # HOT WALLET MODE (SELF-SIGNED): traditional single-key mode
            if not bond.private_key:
                logger.error("Bond missing private key (required for self-signed mode)")
                return None

            cert_pub = bond.pubkey
            utxo_pub = bond.pubkey
            cert_expiry_encoded = cert_expiry_blocks // 2016

            logger.debug(
                f"Using self-signed mode for bond proof (cert_expiry={cert_expiry_encoded})"
            )

            # 1. Nick signature: proves the maker controls the certificate key
            # Signs "(taker_nick|maker_nick)" using Bitcoin message format
            nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
            nick_sig = _sign_message_bitcoin(bond.private_key, nick_msg)
            nick_sig_padded = _pad_signature(nick_sig, 72)

            # 2. Certificate signature: self-signed certificate
            # Signs "fidelity-bond-cert|<cert_pub>|<cert_expiry_encoded>" using Bitcoin message format
            cert_msg = (
                b"fidelity-bond-cert|"
                + cert_pub
                + b"|"
                + str(cert_expiry_encoded).encode("ascii")
            )
            cert_sig = _sign_message_bitcoin(bond.private_key, cert_msg)
            cert_sig_padded = _pad_signature(cert_sig, 72)

        # 3. Pack the proof
        # TXID needs to be in little-endian (as stored in transactions)
        txid_bytes = bytes.fromhex(bond.txid)
        if len(txid_bytes) != 32:
            raise ValueError(f"Invalid txid length: {len(txid_bytes)}")

        proof_data = struct.pack(
            "<72s72s33sH33s32sII",
            nick_sig_padded,
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
