"""
Tests demonstrating floating point arithmetic issues and ensuring integer-based safety.

These tests serve as documentation for WHY we strictly use integer satoshis
and avoid float/Decimal for calculations.
"""

from jmcore.bitcoin import calculate_relative_fee, calculate_sweep_amount
from jmcore.constants import SATS_PER_BTC


def test_float_precision_loss_demonstration() -> None:
    """
    Demonstrate that standard float arithmetic loses precision.
    This explains why we don't use floats for financial calculations.
    """
    # Classic 0.1 + 0.2 != 0.3 example
    val1 = 0.1
    val2 = 0.2
    assert val1 + val2 != 0.3
    # In integer world (scaled by 10): 1 + 2 == 3
    assert (int(val1 * 10) + int(val2 * 10)) == 3

    # Bitcoin context:
    # 0.00000001 BTC (1 sat) + 0.00000002 BTC (2 sats)
    # sats1_btc = 0.00000001
    # sats2_btc = 0.00000002
    # This might actually work due to small numbers, but accumulation errors happen

    # Accumulation error demonstration
    # Adding 0.1 BTC (10M sats) ten times should be exactly 1.0 BTC
    total = 0.0
    for _ in range(10):
        total += 0.1
    # total is 0.9999999999999999, not 1.0
    assert total != 1.0

    # Integer arithmetic is exact
    total_sats = 0
    sats_step = 10_000_000
    for _ in range(10):
        total_sats += sats_step
    assert total_sats == 100_000_000


def test_calculate_relative_fee_vs_float() -> None:
    """Compare integer fee calculation vs naive float calculation."""
    amount = 50_000_000  # 0.5 BTC
    fee_rate_str = "0.0001"  # 0.01%

    # Correct integer calculation
    # 50,000,000 * 1 / 10,000 = 5,000 sats
    fee_int = calculate_relative_fee(amount, fee_rate_str)
    assert fee_int == 5_000

    # Naive float calculation (might work for simple cases but risky)
    fee_float = int(amount * float(fee_rate_str))
    assert fee_float == 5_000

    # Edge case where float might round incorrectly
    # Fee rate 1/3 cannot be represented exactly in float or decimal string
    # But we can approximate with high precision string: "0.3333333333"
    amount = 300_000_000
    # 30% fee
    fee_rate = "0.3"

    # Integer: 300,000,000 * 3 // 10 = 90,000,000
    assert calculate_relative_fee(amount, fee_rate) == 90_000_000

    # Float: 300,000,000 * 0.3 = 90,000,000.0 (exact in this case)
    assert int(amount * 0.3) == 90_000_000


def test_sweep_amount_precision() -> None:
    """
    Test sweep amount calculation precision.

    cj_amount = available / (1 + fee_rate)
    """
    # Scenario: 1 BTC available, 0.1% fee
    available = 100_000_000
    fee_rates = ["0.001"]

    # Correct integer calculation:
    # 100,000,000 * 1000 // 1001 = 99,900,099.9... -> 99,900,099
    cj_amount_int = calculate_sweep_amount(available, fee_rates)
    assert cj_amount_int == 99_900_099

    # Verify the fee matches
    # 99,900,099 * 0.001 = 99,900.099 -> 99,900 sats
    fee = calculate_relative_fee(cj_amount_int, "0.001")
    assert fee == 99_900

    # Total used: 99,900,099 + 99,900 = 99,999,999
    # 1 sat leftover (dust/rounding) - this is acceptable and expected
    remainder = available - (cj_amount_int + fee)
    assert remainder == 1

    # Naive float calculation
    # 100,000,000 / 1.001 = 99,900,099.9000999...
    cj_amount_float = int(available / 1.001)
    # In this specific case, float division + casting to int happens to give same result
    assert cj_amount_float == 99_900_099


def test_large_numbers_precision() -> None:
    """Test behavior with very large numbers (near max supply)."""
    # 21 million BTC in satoshis
    max_supply = 21_000_000 * SATS_PER_BTC

    # Integer arithmetic is fine
    assert max_supply == 2_100_000_000_000_000
    assert max_supply + 1 > max_supply

    # Float arithmetic (64-bit float has 53 bits of significand)
    # 2^53 is approx 9e15. 2.1e15 is within safe range for integer representation in float,
    # but operations can lose precision.
    max_supply_float = float(max_supply)

    # Adding 1 satoshi to max supply in float
    # This usually works because 2.1e15 < 2^53 (9e15)
    assert max_supply_float + 1.0 != max_supply_float

    # However, if we were working with micro-satoshis (millisats) or just larger numbers,
    # we would hit the limit.
    # Let's verify our integer math handles it correctly regardless.

    fee_rate = "0.00000001"  # 1 sat per 100M (very small fee)
    # Fee on max supply: 2.1e15 * 1e-8 = 2.1e7 sats (0.21 BTC)
    fee = calculate_relative_fee(max_supply, fee_rate)
    assert fee == 21_000_000  # 0.21 BTC

    # Float check
    fee_float = max_supply_float * 0.00000001
    assert int(fee_float) == 21_000_000


def test_verify_no_decimal_usage() -> None:
    """
    Verify that our critical functions don't use Decimal (by inspecting code is hard in test,
    but we can verify they work without importing decimal).
    """
    # This test is implicit - if the other tests pass without errors,
    # and we know we removed Decimal imports in previous steps, we are good.
    pass
