"""
Fidelity bond value calculations.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

DEFAULT_INTEREST_RATE = 0.015
DEFAULT_BOND_VALUE_EXPONENT = 2.0


def calculate_timelocked_fidelity_bond_value(
    utxo_value: int,
    confirmation_time: int,
    locktime: int,
    current_time: int | None = None,
    interest_rate: float = DEFAULT_INTEREST_RATE,
    exponent: float = DEFAULT_BOND_VALUE_EXPONENT,
) -> int:
    """
    Calculate fidelity bond value using the timelocked bond formula.

    Args:
        utxo_value: UTXO value in satoshis
        confirmation_time: UTXO confirmation timestamp (Unix seconds)
        locktime: Bond locktime (Unix seconds)
        current_time: Current time (Unix seconds), defaults to now
        interest_rate: Annual interest rate (default 0.015 = 1.5%)
        exponent: Bond value exponent (default 1.3)

    Returns:
        Bond value as integer
    """
    if current_time is None:
        current_time = int(datetime.now(UTC).timestamp())

    year = 60 * 60 * 24 * 365.2425

    r = interest_rate
    time_to_maturity = (locktime - confirmation_time) / year
    locktime_years = locktime / year
    current_years = current_time / year

    a = max(
        0,
        min(1, math.exp(r * time_to_maturity) - 1)
        - min(1, math.exp(r * max(0, current_years - locktime_years)) - 1),
    )

    return int(pow(utxo_value * a, exponent))
