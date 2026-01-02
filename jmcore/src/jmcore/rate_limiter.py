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

Security considerations:
- Rate limiting should be keyed by connection ID, not self-declared nick
- Nick-based tracking is vulnerable to impersonation attacks
- A malicious peer could claim another's nick and trigger rate limits
"""

from __future__ import annotations

import time
from enum import Enum

from pydantic import Field, validate_call
from pydantic.dataclasses import dataclass


class RateLimitAction(Enum):
    """Action to take when rate limit is exceeded."""

    ALLOW = "allow"  # Message is allowed
    DELAY = "delay"  # Message should be delayed/dropped but connection stays
    DISCONNECT = "disconnect"  # Disconnect the peer (severe abuse)


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
    tokens: float = Field(init=False)
    last_refill: float = Field(init=False)

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

    def get_delay_seconds(self) -> float:
        """
        Get recommended delay in seconds before next message would be allowed.
        Returns 0 if tokens are available.
        """
        if self.tokens >= 1:
            return 0.0
        # Calculate time needed to refill 1 token
        tokens_needed = 1 - self.tokens
        return tokens_needed / self.refill_rate

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
    - disconnect_threshold: violations before disconnect (default: None = never)

    Default settings (10 msg/sec sustained, 100 msg burst):
    - Allows ~10 seconds of continuous max-rate traffic before throttling
    - Prevents DoS from rapid spam while allowing legitimate burst patterns
    - Example: taker requesting orderbook from multiple makers simultaneously

    Security:
    - Rate limit by connection ID, not self-declared nick, to prevent impersonation
    - Nick spoofing attack: attacker claims victim's nick to get them rate limited
    - Use connection-based keys until identity is cryptographically verified
    """

    @validate_call
    def __init__(
        self,
        rate_limit: int = 10,
        burst_limit: int | None = None,
        disconnect_threshold: int | None = None,
    ):
        """
        Initialize rate limiter.

        Args:
            rate_limit: Maximum messages per second (sustained, default: 10)
            burst_limit: Maximum burst size (default: 10x rate_limit = 100)
            disconnect_threshold: Violations before disconnect (None = never disconnect)
        """
        self.rate_limit = rate_limit
        self.burst_limit = burst_limit or (rate_limit * 10)
        self.disconnect_threshold = disconnect_threshold
        self._buckets: dict[str, TokenBucket] = {}
        self._violation_counts: dict[str, int] = {}

    def check(self, peer_key: str) -> tuple[RateLimitAction, float]:
        """
        Check rate limit and return recommended action.

        Returns:
            Tuple of (action, delay_seconds):
            - ALLOW: Message allowed, delay=0
            - DELAY: Message should be delayed/dropped, delay=recommended wait time
            - DISCONNECT: Peer should be disconnected (severe abuse), delay=0
        """
        if peer_key not in self._buckets:
            self._buckets[peer_key] = TokenBucket(
                capacity=self.burst_limit,
                refill_rate=float(self.rate_limit),
            )

        bucket = self._buckets[peer_key]
        allowed = bucket.consume()

        if allowed:
            return (RateLimitAction.ALLOW, 0.0)

        # Rate limited - increment violation count
        self._violation_counts[peer_key] = self._violation_counts.get(peer_key, 0) + 1
        violations = self._violation_counts[peer_key]

        # Check if we should disconnect (only if threshold is set)
        if self.disconnect_threshold is not None and violations >= self.disconnect_threshold:
            return (RateLimitAction.DISCONNECT, 0.0)

        # Otherwise, recommend delay
        delay = bucket.get_delay_seconds()
        return (RateLimitAction.DELAY, delay)

    def remove_peer(self, peer_key: str) -> None:
        """Remove rate limit state for a disconnected peer."""
        self._buckets.pop(peer_key, None)
        self._violation_counts.pop(peer_key, None)

    def get_violation_count(self, peer_key: str) -> int:
        """Get the number of rate limit violations for a peer."""
        return self._violation_counts.get(peer_key, 0)

    def get_delay_for_peer(self, peer_key: str) -> float:
        """Get recommended delay in seconds for a rate-limited peer."""
        bucket = self._buckets.get(peer_key)
        if bucket is None:
            return 0.0
        return bucket.get_delay_seconds()

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
