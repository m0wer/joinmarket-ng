"""
Tests for jmcore.bond_calc
"""

import math
from datetime import UTC, datetime

from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value


def test_calculate_bond_value_basic():
    # 1 BTC = 100_000_000 sats
    utxo_value = 100_000_000

    # Dates
    # Confirmation: 2023-01-01
    confirm_time = int(datetime(2023, 1, 1, tzinfo=UTC).timestamp())
    # Locktime: 2024-01-01 (1 year bond)
    locktime = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())
    # Current time: 2023-01-01 (At start)
    current_time = confirm_time

    value = calculate_timelocked_fidelity_bond_value(
        utxo_value=utxo_value,
        confirmation_time=confirm_time,
        locktime=locktime,
        current_time=current_time,
    )

    # Value should be positive
    assert value > 0

    # Calculate expected manually
    # r = 0.015 (default)
    # time_to_maturity = 1 year (approx)

    year = 60 * 60 * 24 * 365.2425
    time_to_maturity = (locktime - confirm_time) / year

    # a = exp(r * time_to_maturity) - 1 - (exp(r * max(0, current - locktime)) - 1)
    # Since current < locktime, the second term is 0

    a_expected = math.exp(0.015 * time_to_maturity) - 1
    val_expected = int(pow(utxo_value * a_expected, 1.3))

    assert value == val_expected


def test_bond_value_expired():
    # Bond expired
    utxo_value = 100_000_000
    confirm_time = int(datetime(2023, 1, 1, tzinfo=UTC).timestamp())
    locktime = int(datetime(2024, 1, 1, tzinfo=UTC).timestamp())
    current_time = int(datetime(2025, 1, 1, tzinfo=UTC).timestamp())  # 1 year after expiry

    value = calculate_timelocked_fidelity_bond_value(
        utxo_value=utxo_value,
        confirmation_time=confirm_time,
        locktime=locktime,
        current_time=current_time,
    )

    # Value should be 0 because it's expired for as long as it was valid (roughly)
    # Formula: exp(r * T) - 1 - (exp(r * (current - locktime)) - 1)
    # If (current - locktime) >= T, then it subtracts same or more amount, result <= 0 -> 0

    assert value == 0


def test_bond_value_decay():
    # Bond partially decayed
    utxo_value = 100_000_000
    confirm_time = int(datetime(2023, 1, 1, tzinfo=UTC).timestamp())
    locktime = int(datetime(2025, 1, 1, tzinfo=UTC).timestamp())  # 2 years

    # Check at start
    val_start = calculate_timelocked_fidelity_bond_value(
        utxo_value=utxo_value,
        confirmation_time=confirm_time,
        locktime=locktime,
        current_time=confirm_time,
    )

    # Check after 1 year passed (still locked)
    val_mid = calculate_timelocked_fidelity_bond_value(
        utxo_value=utxo_value,
        confirmation_time=confirm_time,
        locktime=locktime,
        current_time=int(datetime(2024, 1, 1, tzinfo=UTC).timestamp()),
    )

    # Should be same because max(0, current - locktime) is 0 for both
    assert val_start == val_mid

    # Check after expiry + small time
    val_expired_bit = calculate_timelocked_fidelity_bond_value(
        utxo_value=utxo_value,
        confirmation_time=confirm_time,
        locktime=locktime,
        current_time=int(datetime(2025, 2, 1, tzinfo=UTC).timestamp()),
    )

    assert val_expired_bit < val_start
    assert val_expired_bit > 0
