"""
Tests for offer randomization.
"""

from __future__ import annotations

from maker.offers import randomize_value


class TestRandomizeValue:
    """Tests for randomize_value helper function."""

    def test_randomize_value_no_variation(self):
        """Test that 0% variation returns original value."""
        result = randomize_value(100, 0.0)
        assert result == 100

    def test_randomize_value_int(self):
        """Test integer randomization."""
        base_value = 100_000
        percent = 0.2  # ±20%

        # Run multiple times to ensure variation
        results = [randomize_value(base_value, percent) for _ in range(100)]

        # Should have some variation
        assert len(set(results)) > 1

        # All results should be within range
        min_expected = int(base_value * (1 - percent))
        max_expected = int(base_value * (1 + percent))
        for result in results:
            assert min_expected <= result <= max_expected

    def test_randomize_value_float(self):
        """Test float randomization."""
        base_value = 0.001
        percent = 0.1  # ±10%

        # Run multiple times to ensure variation
        results = [randomize_value(base_value, percent, is_float=True) for _ in range(100)]

        # Should have some variation
        assert len(set(results)) > 1

        # All results should be within range
        min_expected = base_value * (1 - percent)
        max_expected = base_value * (1 + percent)
        for result in results:
            assert min_expected <= result <= max_expected
