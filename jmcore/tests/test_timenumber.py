"""Tests for timenumber utilities."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from jmcore.timenumber import (
    TIMELOCK_EPOCH_TIMESTAMP,
    TIMELOCK_EPOCH_YEAR,
    TIMELOCK_ERA_YEARS,
    TIMENUMBER_COUNT,
    format_locktime_date,
    get_all_locktimes,
    get_all_timenumbers,
    get_future_locktimes,
    get_nearest_valid_locktime,
    is_valid_locktime,
    parse_locktime_date,
    timenumber_to_timestamp,
    timestamp_to_timenumber,
    validate_locktime,
)


class TestTimenumberToTimestamp:
    """Tests for timenumber_to_timestamp."""

    def test_timenumber_zero_is_epoch(self):
        """Timenumber 0 should be January 2020."""
        ts = timenumber_to_timestamp(0)
        assert ts == TIMELOCK_EPOCH_TIMESTAMP
        dt = datetime.fromtimestamp(ts, tz=UTC)
        assert dt.year == 2020
        assert dt.month == 1
        assert dt.day == 1

    def test_timenumber_twelve_is_jan_2021(self):
        """Timenumber 12 should be January 2021."""
        ts = timenumber_to_timestamp(12)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        assert dt.year == 2021
        assert dt.month == 1
        assert dt.day == 1

    def test_timenumber_max_is_dec_2099(self):
        """Timenumber 959 should be December 2099."""
        ts = timenumber_to_timestamp(959)
        dt = datetime.fromtimestamp(ts, tz=UTC)
        assert dt.year == 2099
        assert dt.month == 12
        assert dt.day == 1

    def test_negative_timenumber_raises(self):
        """Negative timenumbers should raise ValueError."""
        with pytest.raises(ValueError, match="Timenumber must be"):
            timenumber_to_timestamp(-1)

    def test_timenumber_out_of_range_raises(self):
        """Timenumber >= 960 should raise ValueError."""
        with pytest.raises(ValueError, match="Timenumber must be"):
            timenumber_to_timestamp(960)

    def test_all_locktimes_are_first_of_month(self):
        """All generated locktimes should be 1st of month at midnight UTC."""
        # Test a sample of timenumbers
        for tn in [0, 1, 11, 12, 50, 100, 500, 959]:
            ts = timenumber_to_timestamp(tn)
            dt = datetime.fromtimestamp(ts, tz=UTC)
            assert dt.day == 1
            assert dt.hour == 0
            assert dt.minute == 0
            assert dt.second == 0


class TestTimestampToTimenumber:
    """Tests for timestamp_to_timenumber."""

    def test_epoch_timestamp_is_zero(self):
        """Epoch timestamp should return timenumber 0."""
        assert timestamp_to_timenumber(TIMELOCK_EPOCH_TIMESTAMP) == 0

    def test_roundtrip_all_timenumbers(self):
        """Converting timenumber -> timestamp -> timenumber should be identity."""
        for tn in range(TIMENUMBER_COUNT):
            ts = timenumber_to_timestamp(tn)
            result = timestamp_to_timenumber(ts)
            assert result == tn, f"Failed for timenumber {tn}"

    def test_non_first_of_month_raises(self):
        """Timestamps not on 1st of month should raise ValueError."""
        # Jan 2, 2020
        jan_2_2020 = datetime(2020, 1, 2, 0, 0, 0, tzinfo=UTC).timestamp()
        with pytest.raises(ValueError, match="must be 1st of month"):
            timestamp_to_timenumber(int(jan_2_2020))

    def test_non_midnight_raises(self):
        """Timestamps not at midnight should raise ValueError."""
        # Jan 1, 2020 at 12:00 UTC
        noon = datetime(2020, 1, 1, 12, 0, 0, tzinfo=UTC).timestamp()
        with pytest.raises(ValueError, match="must be midnight UTC"):
            timestamp_to_timenumber(int(noon))

    def test_before_epoch_raises(self):
        """Timestamps before epoch should raise ValueError."""
        # Dec 2019
        dec_2019 = datetime(2019, 12, 1, 0, 0, 0, tzinfo=UTC).timestamp()
        with pytest.raises(ValueError, match="before epoch"):
            timestamp_to_timenumber(int(dec_2019))

    def test_after_era_raises(self):
        """Timestamps after era should raise ValueError."""
        # Jan 2100
        jan_2100 = datetime(2100, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()
        with pytest.raises(ValueError, match="after maximum"):
            timestamp_to_timenumber(int(jan_2100))


class TestValidateLocktime:
    """Tests for validate_locktime."""

    def test_valid_locktime_passes(self):
        """Valid locktimes should not raise."""
        # Jan 1, 2025
        jan_2025 = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        validate_locktime(jan_2025)  # Should not raise

    def test_invalid_day_raises(self):
        """Non-first day should raise ValueError."""
        jan_15_2025 = int(datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC).timestamp())
        with pytest.raises(ValueError, match="must be 1st of month"):
            validate_locktime(jan_15_2025)

    def test_invalid_time_raises(self):
        """Non-midnight times should raise ValueError."""
        jan_1_noon = int(datetime(2025, 1, 1, 12, 30, 45, tzinfo=UTC).timestamp())
        with pytest.raises(ValueError, match="must be midnight UTC"):
            validate_locktime(jan_1_noon)


class TestIsValidLocktime:
    """Tests for is_valid_locktime."""

    def test_valid_locktime_returns_true(self):
        """Valid locktimes should return True."""
        jan_2025 = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert is_valid_locktime(jan_2025) is True

    def test_invalid_locktime_returns_false(self):
        """Invalid locktimes should return False."""
        # Wrong day
        jan_15_2025 = int(datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC).timestamp())
        assert is_valid_locktime(jan_15_2025) is False

        # Before epoch
        dec_2019 = int(datetime(2019, 12, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert is_valid_locktime(dec_2019) is False

        # After era
        jan_2100 = int(datetime(2100, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert is_valid_locktime(jan_2100) is False


class TestGetNearestValidLocktime:
    """Tests for get_nearest_valid_locktime."""

    def test_already_valid_unchanged(self):
        """Valid locktimes should remain unchanged."""
        jan_1_2025 = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert get_nearest_valid_locktime(jan_1_2025) == jan_1_2025
        assert get_nearest_valid_locktime(jan_1_2025, round_up=False) == jan_1_2025

    def test_round_up_to_next_month(self):
        """Non-1st should round up to next month."""
        jan_15_2025 = int(datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC).timestamp())
        feb_1_2025 = int(datetime(2025, 2, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert get_nearest_valid_locktime(jan_15_2025, round_up=True) == feb_1_2025

    def test_round_down_to_current_month(self):
        """Non-1st should round down to 1st of same month."""
        jan_15_2025 = int(datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC).timestamp())
        jan_1_2025 = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert get_nearest_valid_locktime(jan_15_2025, round_up=False) == jan_1_2025

    def test_round_up_december_goes_to_next_year(self):
        """December should round up to January of next year."""
        dec_15_2025 = int(datetime(2025, 12, 15, 0, 0, 0, tzinfo=UTC).timestamp())
        jan_1_2026 = int(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        assert get_nearest_valid_locktime(dec_15_2025, round_up=True) == jan_1_2026


class TestParseLocktime:
    """Tests for parse_locktime_date."""

    def test_parse_yyyy_mm(self):
        """YYYY-MM format should work."""
        ts = parse_locktime_date("2025-06")
        dt = datetime.fromtimestamp(ts, tz=UTC)
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 1

    def test_parse_yyyy_mm_dd(self):
        """YYYY-MM-DD format should work if day is 01."""
        ts = parse_locktime_date("2025-06-01")
        dt = datetime.fromtimestamp(ts, tz=UTC)
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 1

    def test_parse_non_first_day_raises(self):
        """YYYY-MM-DD with day != 01 should raise."""
        with pytest.raises(ValueError, match="must be 1st of month"):
            parse_locktime_date("2025-06-15")

    def test_parse_before_epoch_raises(self):
        """Dates before epoch should raise."""
        with pytest.raises(ValueError):
            parse_locktime_date("2019-12")

    def test_parse_invalid_format_raises(self):
        """Invalid formats should raise."""
        with pytest.raises(ValueError):
            parse_locktime_date("2025")
        with pytest.raises(ValueError):
            parse_locktime_date("invalid")


class TestFormatLocktimeDate:
    """Tests for format_locktime_date."""

    def test_format_epoch(self):
        """Epoch should format as 2020-01-01."""
        assert format_locktime_date(TIMELOCK_EPOCH_TIMESTAMP) == "2020-01-01"

    def test_format_roundtrip(self):
        """Parsing and formatting should roundtrip."""
        original = "2025-06-01"
        ts = parse_locktime_date(original)
        assert format_locktime_date(ts) == original


class TestGetAllFunctions:
    """Tests for get_all_* functions."""

    def test_get_all_timenumbers_count(self):
        """Should return exactly 960 timenumbers."""
        tns = get_all_timenumbers()
        assert len(tns) == TIMENUMBER_COUNT
        assert tns[0] == 0
        assert tns[-1] == 959

    def test_get_all_locktimes_count(self):
        """Should return exactly 960 locktimes."""
        lts = get_all_locktimes()
        assert len(lts) == TIMENUMBER_COUNT
        # First should be epoch
        assert lts[0] == TIMELOCK_EPOCH_TIMESTAMP

    def test_get_future_locktimes_subset(self):
        """Future locktimes should be a subset of all locktimes."""
        all_lts = set(get_all_locktimes())
        future_lts = set(get_future_locktimes())
        assert future_lts.issubset(all_lts)

    def test_get_future_locktimes_from_custom_time(self):
        """Should respect custom from_time."""
        # Use Jan 2025 as reference
        jan_2025 = int(datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp())
        future_lts = get_future_locktimes(from_time=jan_2025)
        # All should be after Jan 2025
        assert all(lt > jan_2025 for lt in future_lts)


class TestConstants:
    """Tests for module constants."""

    def test_timenumber_count(self):
        """TIMENUMBER_COUNT should be 960 (80 years * 12 months)."""
        assert TIMENUMBER_COUNT == 960

    def test_epoch_year(self):
        """Epoch year should be 2020."""
        assert TIMELOCK_EPOCH_YEAR == 2020

    def test_era_years(self):
        """Era should be 80 years."""
        assert TIMELOCK_ERA_YEARS == 80

    def test_epoch_timestamp(self):
        """Epoch timestamp should be Jan 1, 2020 00:00:00 UTC."""
        dt = datetime.fromtimestamp(TIMELOCK_EPOCH_TIMESTAMP, tz=UTC)
        assert dt.year == 2020
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 0
        assert dt.minute == 0
        assert dt.second == 0
