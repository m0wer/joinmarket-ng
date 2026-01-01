"""
Tests for the rate limiter module.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from jmcore.rate_limiter import RateLimiter, TokenBucket


class TestTokenBucket:
    """Tests for TokenBucket class."""

    def test_initial_capacity(self) -> None:
        """Bucket starts at full capacity."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.tokens == 10.0

    def test_consume_success(self) -> None:
        """Consuming tokens when available returns True."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.consume(1) is True
        assert bucket.tokens == 9.0

    def test_consume_multiple(self) -> None:
        """Can consume multiple tokens at once."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.consume(5) is True
        assert bucket.tokens == 5.0

    def test_consume_failure_empty(self) -> None:
        """Consuming when empty returns False."""
        bucket = TokenBucket(capacity=1, refill_rate=1.0)
        assert bucket.consume(1) is True
        assert bucket.consume(1) is False

    def test_refill_over_time(self) -> None:
        """Tokens refill based on elapsed time."""
        bucket = TokenBucket(capacity=10, refill_rate=10.0)  # 10 tokens/sec

        # Consume all tokens
        for _ in range(10):
            bucket.consume(1)
        assert bucket.tokens < 1.0

        # Mock time passing
        with patch.object(time, "monotonic", return_value=bucket.last_refill + 0.5):
            # After 0.5 seconds at 10/sec, should have ~5 tokens
            assert bucket.consume(1) is True
            # tokens = min(10, old_tokens + 0.5 * 10) - 1 = min(10, ~5) - 1 = ~4
            assert 3.0 < bucket.tokens < 5.0

    def test_capacity_limit(self) -> None:
        """Tokens don't exceed capacity after refill."""
        bucket = TokenBucket(capacity=10, refill_rate=100.0)

        # Mock lots of time passing
        with patch.object(time, "monotonic", return_value=bucket.last_refill + 1000):
            bucket.consume(1)
            assert bucket.tokens == 9.0  # capped at capacity

    def test_reset(self) -> None:
        """Reset restores full capacity."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        bucket.consume(5)
        bucket.reset()
        assert bucket.tokens == 10.0


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_allows_initial_messages(self) -> None:
        """New peers can send messages immediately."""
        limiter = RateLimiter(rate_limit=10, burst_limit=20)
        for _ in range(20):
            assert limiter.check("peer1") is True

    def test_blocks_after_burst(self) -> None:
        """Blocks messages after burst is exhausted."""
        limiter = RateLimiter(rate_limit=10, burst_limit=5)
        for _ in range(5):
            assert limiter.check("peer1") is True
        assert limiter.check("peer1") is False

    def test_independent_peers(self) -> None:
        """Different peers have independent rate limits."""
        limiter = RateLimiter(rate_limit=10, burst_limit=5)

        # Exhaust peer1's burst
        for _ in range(5):
            limiter.check("peer1")
        assert limiter.check("peer1") is False

        # peer2 should still be allowed
        assert limiter.check("peer2") is True

    def test_violation_counting(self) -> None:
        """Violations are counted per peer."""
        limiter = RateLimiter(rate_limit=10, burst_limit=2)

        # Exhaust burst
        limiter.check("peer1")
        limiter.check("peer1")

        assert limiter.get_violation_count("peer1") == 0

        # These should be violations
        limiter.check("peer1")
        limiter.check("peer1")
        limiter.check("peer1")

        assert limiter.get_violation_count("peer1") == 3

    def test_remove_peer(self) -> None:
        """Removing peer clears their state."""
        limiter = RateLimiter(rate_limit=10, burst_limit=2)

        # Create state for peer
        limiter.check("peer1")
        limiter.check("peer1")
        limiter.check("peer1")  # violation

        assert limiter.get_violation_count("peer1") == 1

        limiter.remove_peer("peer1")

        assert limiter.get_violation_count("peer1") == 0
        # New bucket created on next check
        assert limiter.check("peer1") is True

    def test_stats(self) -> None:
        """Stats returns summary information."""
        limiter = RateLimiter(rate_limit=10, burst_limit=2)

        # Create some activity
        for _ in range(5):
            limiter.check("peer1")  # 2 allowed, 3 violations
        for _ in range(3):
            limiter.check("peer2")  # 2 allowed, 1 violation

        stats = limiter.get_stats()
        assert stats["tracked_peers"] == 2
        assert stats["total_violations"] == 4
        assert len(stats["top_violators"]) == 2

    def test_default_burst_limit(self) -> None:
        """Default burst limit is 10x rate limit."""
        limiter = RateLimiter(rate_limit=50)
        # Should allow 500 messages (10x rate)
        for i in range(500):
            assert limiter.check("peer1") is True, f"Failed at message {i}"
        assert limiter.check("peer1") is False

    def test_clear(self) -> None:
        """Clear removes all state."""
        limiter = RateLimiter(rate_limit=10, burst_limit=2)

        limiter.check("peer1")
        limiter.check("peer2")

        limiter.clear()

        assert limiter.get_stats()["tracked_peers"] == 0
        assert limiter.get_stats()["total_violations"] == 0
