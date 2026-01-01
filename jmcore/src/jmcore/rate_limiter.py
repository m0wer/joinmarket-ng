"""
Per-peer rate limiting using token bucket algorithm.

Prevents DoS attacks by limiting the message rate from each connected peer.
This module provides a generic rate limiter that can be used across all
JoinMarket components (directory server, makers, takers).

Design:
- Token bucket algorithm allows generous burst capacity with low sustained rate
- Default: 10 msg/sec sustained, 100 msg burst (allows ~10s of max-rate traffic)
- Per-peer tracking prevents one bad actor from affecting others
- Automatic cleanup prevents memory leaks
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    Tokens are added at a fixed rate up to a maximum capacity.
    Each message consumes one token. If no tokens are available,
    the message is rejected.
    """

    capacity: int  # Maximum tokens (burst allowance)
    refill_rate: float  # Tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens. Returns True if successful, False if rate limited.
        """
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now

        # Refill tokens based on elapsed time
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def reset(self) -> None:
        """Reset bucket to full capacity."""
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()


class RateLimiter:
    """
    Per-peer rate limiter using token bucket algorithm.

    Configuration:
    - rate_limit: messages per second (sustained rate)
    - burst_limit: maximum burst size (default: 10x rate_limit)

    Default settings (10 msg/sec sustained, 100 msg burst):
    - Allows ~10 seconds of continuous max-rate traffic before throttling
    - Prevents DoS from rapid spam while allowing legitimate burst patterns
    - Example: taker requesting orderbook from multiple makers simultaneously
    """

    def __init__(self, rate_limit: int = 10, burst_limit: int | None = None):
        """
        Initialize rate limiter.

        Args:
            rate_limit: Maximum messages per second (sustained, default: 10)
            burst_limit: Maximum burst size (default: 10x rate_limit = 100)
        """
        self.rate_limit = rate_limit
        self.burst_limit = burst_limit or (rate_limit * 10)
        self._buckets: dict[str, TokenBucket] = {}
        self._violation_counts: dict[str, int] = {}

    def check(self, peer_key: str) -> bool:
        """
        Check if a message from peer_key should be allowed.

        Returns True if allowed, False if rate limited.
        """
        if peer_key not in self._buckets:
            self._buckets[peer_key] = TokenBucket(
                capacity=self.burst_limit,
                refill_rate=float(self.rate_limit),
            )

        allowed = self._buckets[peer_key].consume()

        if not allowed:
            self._violation_counts[peer_key] = self._violation_counts.get(peer_key, 0) + 1

        return allowed

    def remove_peer(self, peer_key: str) -> None:
        """Remove rate limit state for a disconnected peer."""
        self._buckets.pop(peer_key, None)
        self._violation_counts.pop(peer_key, None)

    def get_violation_count(self, peer_key: str) -> int:
        """Get the number of rate limit violations for a peer."""
        return self._violation_counts.get(peer_key, 0)

    def cleanup_old_peers(self, max_idle_seconds: float = 3600.0) -> int:
        """
        Remove peers that haven't sent messages in max_idle_seconds.

        Returns the number of peers removed.
        """
        now = time.monotonic()
        stale_peers = [
            peer_key
            for peer_key, bucket in self._buckets.items()
            if now - bucket.last_refill > max_idle_seconds
        ]

        for peer_key in stale_peers:
            self.remove_peer(peer_key)

        return len(stale_peers)

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "tracked_peers": len(self._buckets),
            "total_violations": sum(self._violation_counts.values()),
            "top_violators": sorted(
                self._violation_counts.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }

    def clear(self) -> None:
        """Clear all rate limit state."""
        self._buckets.clear()
        self._violation_counts.clear()
