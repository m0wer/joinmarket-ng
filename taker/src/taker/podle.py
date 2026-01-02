"""
Proof of Discrete Log Equivalence (PoDLE) generation for takers.

This module re-exports PoDLE generation functions from jmcore and provides
taker-specific utilities for UTXO selection and commitment generation.

PoDLE is used to prevent sybil attacks in JoinMarket by requiring takers
to prove ownership of a UTXO without revealing which UTXO until after
the maker commits to participate.

Protocol flow:
1. Taker generates commitment C = H(P2) where P2 = k*J (k = private key, J = NUMS point)
2. Taker sends commitment C to maker
3. Maker accepts and sends pubkey
4. Taker reveals P, P2, sig, e as the "revelation"
5. Maker verifies: P = k*G and P2 = k*J (same k)

Reference: https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from jmcore.podle import (
    PoDLECommitment,
    PoDLEError,
    generate_podle,
    serialize_revelation,
)
from loguru import logger
from pydantic.dataclasses import dataclass

if TYPE_CHECKING:
    from jmwallet.wallet.models import UTXOInfo

__all__ = [
    "ExtendedPoDLECommitment",
    "PoDLECommitment",
    "PoDLEError",
    "generate_podle",
    "get_eligible_podle_utxos",
    "select_podle_utxo",
    "serialize_revelation",
]


@dataclass
class ExtendedPoDLECommitment:
    """
    PoDLE commitment with extended UTXO metadata for neutrino_compat feature.

    This extends the base PoDLECommitment with scriptpubkey and blockheight
    for Neutrino-compatible UTXO verification.
    """

    commitment: PoDLECommitment
    scriptpubkey: str | None = None  # Hex-encoded scriptPubKey
    blockheight: int | None = None  # Block height where UTXO was confirmed

    # Expose underlying commitment properties for compatibility
    @property
    def p(self) -> bytes:
        """Public key P = k*G"""
        return self.commitment.p

    @property
    def p2(self) -> bytes:
        """Commitment point P2 = k*J"""
        return self.commitment.p2

    @property
    def sig(self) -> bytes:
        """Schnorr signature s"""
        return self.commitment.sig

    @property
    def e(self) -> bytes:
        """Challenge e"""
        return self.commitment.e

    @property
    def utxo(self) -> str:
        """UTXO reference txid:vout"""
        return self.commitment.utxo

    @property
    def index(self) -> int:
        """NUMS point index used"""
        return self.commitment.index

    def to_revelation(self, extended: bool = False) -> dict[str, str]:
        """
        Convert to revelation format for sending to maker.

        Args:
            extended: If True, include scriptpubkey:blockheight in utxo string
        """
        rev = self.commitment.to_revelation()
        if extended and self.scriptpubkey and self.blockheight is not None:
            # Replace utxo with extended format: txid:vout:scriptpubkey:blockheight
            txid, vout = self.commitment.utxo.split(":")
            rev["utxo"] = f"{txid}:{vout}:{self.scriptpubkey}:{self.blockheight}"
        return rev

    def to_commitment_str(self) -> str:
        """Get commitment as hex string."""
        return self.commitment.to_commitment_str()

    def has_neutrino_metadata(self) -> bool:
        """Check if we have metadata for Neutrino-compatible verification."""
        return self.scriptpubkey is not None and self.blockheight is not None


def get_eligible_podle_utxos(
    utxos: list[UTXOInfo],
    cj_amount: int,
    min_confirmations: int = 5,
    min_percent: int = 20,
) -> list[UTXOInfo]:
    """
    Get all eligible UTXOs for PoDLE commitment, sorted by preference.

    Criteria:
    - Must have at least min_confirmations
    - Must be at least min_percent of cj_amount

    Returns:
        List of eligible UTXOs sorted by (confirmations, value) descending
    """
    min_value = int(cj_amount * min_percent / 100)

    eligible = [u for u in utxos if u.confirmations >= min_confirmations and u.value >= min_value]

    # Prefer older UTXOs with more value
    eligible.sort(key=lambda u: (u.confirmations, u.value), reverse=True)
    return eligible


def select_podle_utxo(
    utxos: list[UTXOInfo],
    cj_amount: int,
    min_confirmations: int = 5,
    min_percent: int = 20,
) -> UTXOInfo | None:
    """
    Select the best UTXO for PoDLE commitment.

    Args:
        utxos: Available UTXOs
        cj_amount: CoinJoin amount
        min_confirmations: Minimum confirmations required
        min_percent: Minimum value as percentage of cj_amount

    Returns:
        Best UTXO for PoDLE or None if no suitable UTXO
    """
    eligible = get_eligible_podle_utxos(utxos, cj_amount, min_confirmations, min_percent)

    if not eligible:
        min_value = int(cj_amount * min_percent / 100)
        logger.warning(
            f"No suitable UTXOs for PoDLE: need {min_confirmations}+ confirmations "
            f"and value >= {min_value} sats ({min_percent}% of {cj_amount})"
        )
        return None

    selected = eligible[0]
    logger.info(
        f"Selected UTXO for PoDLE: {selected.txid}:{selected.vout} "
        f"(value={selected.value}, confs={selected.confirmations})"
    )

    return selected
