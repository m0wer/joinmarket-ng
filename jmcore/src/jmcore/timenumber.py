"""
Timenumber utilities for fidelity bond locktimes.

The timenumber system maps monthly locktimes to integers for efficient storage
and derivation path encoding. This matches the reference JoinMarket implementation.

Key constraints:
- Epoch: January 2020 (timenumber 0)
- Era: 80 years (960 possible locktimes)
- All locktimes are 1st of month at midnight UTC
- Timenumber unit: 1 month

Reference: joinmarket-clientserver/src/jmclient/wallet.py (FidelityBondMixin)
"""

from __future__ import annotations

from datetime import UTC, datetime

# Fidelity bond constants (matching reference implementation)
TIMENUMBER_UNIT = 1  # 1 month increments
TIMELOCK_EPOCH_YEAR = 2020
TIMELOCK_EPOCH_MONTH = 1  # January
TIMELOCK_ERA_YEARS = 80
MONTHS_IN_YEAR = 12
TIMENUMBER_COUNT = (TIMELOCK_ERA_YEARS * MONTHS_IN_YEAR) // TIMENUMBER_UNIT  # 960

# Epoch timestamp: 2020-01-01 00:00:00 UTC
TIMELOCK_EPOCH = datetime(TIMELOCK_EPOCH_YEAR, TIMELOCK_EPOCH_MONTH, 1, 0, 0, 0, tzinfo=UTC)
TIMELOCK_EPOCH_TIMESTAMP = int(TIMELOCK_EPOCH.timestamp())


def timenumber_to_timestamp(timenumber: int) -> int:
    """
    Convert a timenumber to a Unix timestamp.

    Timenumber 0 = January 2020 (epoch)
    Each timenumber increment = 1 month
    Maximum timenumber = 959 (December 2099)

    Args:
        timenumber: Integer from 0 to TIMENUMBER_COUNT-1

    Returns:
        Unix timestamp for 1st of month at midnight UTC

    Raises:
        ValueError: If timenumber is out of range

    Example:
        >>> timenumber_to_timestamp(0)  # Jan 2020
        1577836800
        >>> timenumber_to_timestamp(12)  # Jan 2021
        1609459200
    """
    if timenumber < 0 or timenumber >= TIMENUMBER_COUNT:
        raise ValueError(f"Timenumber must be 0-{TIMENUMBER_COUNT - 1}, got {timenumber}")

    year = TIMELOCK_EPOCH_YEAR + timenumber // MONTHS_IN_YEAR
    month = TIMELOCK_EPOCH_MONTH + timenumber % MONTHS_IN_YEAR

    # Handle month overflow (not needed with epoch starting at January)
    if month > MONTHS_IN_YEAR:
        year += 1
        month -= MONTHS_IN_YEAR

    dt = datetime(year, month, 1, 0, 0, 0, tzinfo=UTC)
    return int(dt.timestamp())


def timestamp_to_timenumber(locktime: int) -> int:
    """
    Convert a Unix timestamp to a timenumber.

    The timestamp MUST be midnight UTC on the 1st of a month, otherwise
    this function will raise an error.

    Args:
        locktime: Unix timestamp

    Returns:
        Timenumber (0 to 959)

    Raises:
        ValueError: If locktime is not midnight UTC on 1st of month,
                   or if it's outside the valid range

    Example:
        >>> timestamp_to_timenumber(1577836800)  # Jan 2020
        0
        >>> timestamp_to_timenumber(1609459200)  # Jan 2021
        12
    """
    # Validate the locktime is a valid first-of-month timestamp
    validate_locktime(locktime)

    dt = datetime.fromtimestamp(locktime, tz=UTC)

    # Calculate months since epoch
    year_diff = dt.year - TIMELOCK_EPOCH_YEAR
    month_diff = dt.month - TIMELOCK_EPOCH_MONTH
    timenumber = year_diff * MONTHS_IN_YEAR + month_diff

    if timenumber < 0:
        raise ValueError(
            f"Locktime {locktime} ({dt.strftime('%Y-%m-%d')}) is before epoch "
            f"({TIMELOCK_EPOCH_YEAR}-{TIMELOCK_EPOCH_MONTH:02d})"
        )

    if timenumber >= TIMENUMBER_COUNT:
        max_year = TIMELOCK_EPOCH_YEAR + TIMELOCK_ERA_YEARS - 1
        raise ValueError(
            f"Locktime {locktime} ({dt.strftime('%Y-%m-%d')}) is after maximum ({max_year}-12)"
        )

    return timenumber


def validate_locktime(locktime: int) -> None:
    """
    Validate that a locktime is midnight UTC on the 1st of a month.

    Fidelity bonds MUST use locktimes that fall on the 1st of a month
    at exactly midnight UTC. This constraint ensures:
    1. Consistent derivation paths across implementations
    2. Efficient scanning (only 960 possible values)
    3. Compatibility with the reference implementation

    Args:
        locktime: Unix timestamp to validate

    Raises:
        ValueError: If locktime doesn't meet constraints
    """
    try:
        dt = datetime.fromtimestamp(locktime, tz=UTC)
    except (ValueError, OSError) as e:
        raise ValueError(f"Invalid timestamp {locktime}: {e}") from e

    if dt.day != 1:
        raise ValueError(
            f"Locktime must be 1st of month, got day {dt.day} ({dt.strftime('%Y-%m-%d %H:%M:%S')})"
        )

    if dt.hour != 0 or dt.minute != 0 or dt.second != 0 or dt.microsecond != 0:
        raise ValueError(
            f"Locktime must be midnight UTC, got {dt.strftime('%H:%M:%S.%f')} "
            f"({dt.strftime('%Y-%m-%d %H:%M:%S')})"
        )


def is_valid_locktime(locktime: int) -> bool:
    """
    Check if a locktime is valid for fidelity bonds.

    A valid locktime is:
    1. Midnight UTC on the 1st of a month
    2. Within the epoch range (Jan 2020 to Dec 2099)

    Args:
        locktime: Unix timestamp to check

    Returns:
        True if valid, False otherwise
    """
    try:
        validate_locktime(locktime)
        timestamp_to_timenumber(locktime)
        return True
    except ValueError:
        return False


def get_nearest_valid_locktime(locktime: int, round_up: bool = True) -> int:
    """
    Get the nearest valid locktime (1st of month, midnight UTC).

    Args:
        locktime: Any Unix timestamp
        round_up: If True, round to next month; if False, round to previous month

    Returns:
        Valid locktime (1st of month, midnight UTC)

    Example:
        >>> get_nearest_valid_locktime(1577900000)  # Jan 2, 2020
        1580515200  # Feb 1, 2020 (round_up=True)
        >>> get_nearest_valid_locktime(1577900000, round_up=False)
        1577836800  # Jan 1, 2020
    """
    dt = datetime.fromtimestamp(locktime, tz=UTC)

    if round_up:
        # Round to next month if not already 1st at midnight
        if dt.day != 1 or dt.hour != 0 or dt.minute != 0 or dt.second != 0:
            # Move to next month
            if dt.month == 12:
                year = dt.year + 1
                month = 1
            else:
                year = dt.year
                month = dt.month + 1
        else:
            year = dt.year
            month = dt.month
    else:
        # Round to current or previous 1st of month
        year = dt.year
        month = dt.month

    result_dt = datetime(year, month, 1, 0, 0, 0, tzinfo=UTC)
    return int(result_dt.timestamp())


def parse_locktime_date(date_str: str) -> int:
    """
    Parse a date string to a locktime timestamp.

    Accepts formats:
    - YYYY-MM-DD (must be 1st of month)
    - YYYY-MM (assumes 1st of month)

    Args:
        date_str: Date string in supported format

    Returns:
        Unix timestamp for midnight UTC on the 1st of the month

    Raises:
        ValueError: If format is invalid or date is not 1st of month
    """
    # Try YYYY-MM format first
    if len(date_str) == 7 and date_str[4] == "-":
        try:
            year = int(date_str[:4])
            month = int(date_str[5:7])
            dt = datetime(year, month, 1, 0, 0, 0, tzinfo=UTC)
            locktime = int(dt.timestamp())
            # Validate it's in range
            timestamp_to_timenumber(locktime)
            return locktime
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid date format '{date_str}': {e}") from e

    # Try YYYY-MM-DD format
    if len(date_str) == 10 and date_str[4] == "-" and date_str[7] == "-":
        try:
            year = int(date_str[:4])
            month = int(date_str[5:7])
            day = int(date_str[8:10])

            if day != 1:
                raise ValueError(f"Fidelity bond locktime must be 1st of month, got day {day}")

            dt = datetime(year, month, 1, 0, 0, 0, tzinfo=UTC)
            locktime = int(dt.timestamp())
            # Validate it's in range
            timestamp_to_timenumber(locktime)
            return locktime
        except (ValueError, IndexError) as e:
            raise ValueError(f"Invalid date format '{date_str}': {e}") from e

    raise ValueError(f"Invalid date format '{date_str}'. Use YYYY-MM or YYYY-MM-DD (1st of month)")


def format_locktime_date(locktime: int) -> str:
    """
    Format a locktime timestamp as a human-readable date.

    Args:
        locktime: Unix timestamp

    Returns:
        Date string in YYYY-MM-DD format
    """
    dt = datetime.fromtimestamp(locktime, tz=UTC)
    return dt.strftime("%Y-%m-%d")


def get_all_timenumbers() -> list[int]:
    """
    Get all valid timenumbers (0 to 959).

    Returns:
        List of integers from 0 to TIMENUMBER_COUNT-1
    """
    return list(range(TIMENUMBER_COUNT))


def get_all_locktimes() -> list[int]:
    """
    Get all valid locktime timestamps for fidelity bonds.

    This generates all 960 possible locktimes from January 2020
    through December 2099.

    Returns:
        List of Unix timestamps (1st of each month, midnight UTC)
    """
    return [timenumber_to_timestamp(i) for i in range(TIMENUMBER_COUNT)]


def get_future_locktimes(from_time: int | None = None) -> list[int]:
    """
    Get all valid locktime timestamps that are in the future.

    Args:
        from_time: Reference timestamp (default: current time)

    Returns:
        List of future locktime timestamps
    """
    if from_time is None:
        from_time = int(datetime.now(UTC).timestamp())

    return [lt for lt in get_all_locktimes() if lt > from_time]
