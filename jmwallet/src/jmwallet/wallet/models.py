"""
Wallet data models.
"""

from __future__ import annotations

from typing import Literal

from pydantic.dataclasses import dataclass

# Address status types for wallet info display
AddressStatus = Literal[
    "deposit",  # External address with funds (received deposit)
    "cj-out",  # Internal address - CoinJoin output (from previous CJ)
    "non-cj-change",  # Internal address - regular change (not from CJ)
    "new",  # Unused address (no funds, never used)
    "reused",  # Address that was used and reused (privacy warning)
    "used-empty",  # Address that had funds but is now empty
    "bond",  # Fidelity bond address
    "flagged",  # Address flagged/shared but tx failed (should not reuse)
]


@dataclass
class AddressInfo:
    """Information about a wallet address for display."""

    address: str
    index: int
    balance: int  # satoshis
    status: AddressStatus
    path: str
    is_external: bool  # True for receive (external), False for change (internal)
    is_bond: bool = False
    locktime: int | None = None  # For fidelity bond addresses

    @property
    def short_path(self) -> str:
        """Get shortened path for display (e.g., m/84'/0'/0'/0/5 -> 0/5)."""
        parts = self.path.split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1]}"
        return self.path


@dataclass
class UTXOInfo:
    """Extended UTXO information with wallet context"""

    txid: str
    vout: int
    value: int
    address: str
    confirmations: int
    scriptpubkey: str
    path: str
    mixdepth: int
    height: int | None = None  # Block height where UTXO was confirmed (for Neutrino)
    locktime: int | None = None  # Locktime for fidelity bond UTXOs (None for regular UTXOs)

    @property
    def is_timelocked(self) -> bool:
        """Check if this is a timelocked (fidelity bond) UTXO."""
        return self.locktime is not None

    @property
    def is_p2wsh(self) -> bool:
        """Check if this UTXO is P2WSH based on scriptpubkey."""
        # P2WSH scriptpubkey: OP_0 (0x00) + PUSH32 (0x20) + 32-byte hash = 34 bytes (68 hex chars)
        if len(self.scriptpubkey) != 68:
            return False
        return self.scriptpubkey.startswith("0020")

    @property
    def is_p2wpkh(self) -> bool:
        """Check if this UTXO is P2WPKH based on scriptpubkey."""
        # P2WPKH scriptpubkey: OP_0 (0x00) + PUSH20 (0x14) + 20-byte hash = 22 bytes (44 hex chars)
        if len(self.scriptpubkey) != 44:
            return False
        return self.scriptpubkey.startswith("0014")


@dataclass
class CoinSelection:
    """Result of coin selection"""

    utxos: list[UTXOInfo]
    total_value: int
    change_value: int
    fee: int
