"""Fidelity bond utilities for maker bot."""

from __future__ import annotations

from dataclasses import dataclass

from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmwallet.wallet.service import WalletService

FIDELITY_BOND_MIXDEPTH = 4


@dataclass
class FidelityBondInfo:
    txid: str
    vout: int
    value: int
    locktime: int
    confirmation_time: int
    bond_value: int


def find_fidelity_bonds(
    wallet: WalletService, mixdepth: int = FIDELITY_BOND_MIXDEPTH
) -> list[FidelityBondInfo]:
    bonds: list[FidelityBondInfo] = []

    utxos_by_mixdepth = wallet.utxo_cache
    utxos = utxos_by_mixdepth.get(mixdepth)
    if not utxos:
        return bonds

    for (txid, vout), info in utxos.items():
        path = info.path
        if not path.endswith("/1"):
            continue

        confirmation_time = info.confirmations

        bond_value = calculate_timelocked_fidelity_bond_value(
            utxo_value=info.value,
            confirmation_time=confirmation_time,
            locktime=0,
        )

        bonds.append(
            FidelityBondInfo(
                txid=txid,
                vout=vout,
                value=info.value,
                locktime=0,
                confirmation_time=confirmation_time,
                bond_value=bond_value,
            )
        )

    return bonds
