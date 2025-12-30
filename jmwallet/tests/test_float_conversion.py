"""
Tests specifically for Bitcoin amount conversion (BTC -> Sats).
Replicates the floating point precision bug found in issue #1.
"""

from jmcore.constants import SATS_PER_BTC


def btc_to_sats_int(amount_btc: float) -> int:
    """
    Naive implementation using int() - REPLICATES THE BUG.
    """
    return int(amount_btc * SATS_PER_BTC)


def btc_to_sats_round(amount_btc: float) -> int:
    """
    Correct implementation using round() - THE FIX.
    """
    return round(amount_btc * SATS_PER_BTC)


def test_replicate_precision_bug():
    """
    Replicate the exact bug where 0.0003 BTC became 29999 sats instead of 30000.
    """
    # The problematic value from the bug report
    amount_btc = 0.0003

    # Expected result
    expected_sats = 30000

    # Verify the bug exists in naive implementation
    buggy_sats = btc_to_sats_int(amount_btc)
    assert buggy_sats == 29999, (
        "Failed to replicate bug! int() conversion might behave differently on this platform"
    )
    assert buggy_sats != expected_sats

    # Verify the fix works
    fixed_sats = btc_to_sats_round(amount_btc)
    assert fixed_sats == expected_sats


def test_other_problematic_values():
    """
    Test other values that might cause precision issues.
    """
    # Values that often cause floating point representation issues
    test_cases = [
        (0.0003, 30000),
        (0.0006, 60000),
        (0.0007, 70000),
        (0.0012, 120000),
        (0.0029, 290000),
        (1.0003, 100030000),
        (0.00000001, 1),  # 1 sat
        (0.00000010, 10),
        (20999999.99999999, 2099999999999999),  # Max supply
    ]

    for btc_val, expected_sats in test_cases:
        # Check if naive approach fails (it doesn't fail for all values, but fails for many)
        # We don't assert failure here because we just want to ensure the FIX works for all

        # Verify fix
        result = btc_to_sats_round(btc_val)
        assert result == expected_sats, (
            f"Failed for {btc_val}: expected {expected_sats}, got {result}"
        )


def test_negative_values():
    """Test negative values work correctly (though usually not expected for amounts)."""
    assert btc_to_sats_round(-0.0003) == -30000


def test_zero():
    """Test zero conversion."""
    assert btc_to_sats_round(0.0) == 0
    assert btc_to_sats_round(0) == 0
