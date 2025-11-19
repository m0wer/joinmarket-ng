"""
Wallet data models.
"""

from __future__ import annotations

from dataclasses import dataclass


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


@dataclass
class CoinSelection:
    """Result of coin selection"""

    utxos: list[UTXOInfo]
    total_value: int
    change_value: int
    fee: int
