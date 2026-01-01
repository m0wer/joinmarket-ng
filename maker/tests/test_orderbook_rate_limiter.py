"""
Tests for the OrderbookRateLimiter class.

The rate limiter protects makers from spam attacks that flood orderbook requests.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from jmcore.models import NetworkType

from maker.bot import MakerBot, OrderbookRateLimiter
from maker.config import MakerConfig


class TestOrderbookRateLimiter:
    """Tests for OrderbookRateLimiter class."""

    def test_first_request_allowed(self):
        """Test that the first request from a peer is always allowed."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        assert limiter.check("J5peer1") is True

    def test_second_request_within_interval_blocked(self):
        """Test that rapid subsequent requests are blocked."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # First request - allowed
        assert limiter.check("J5peer1") is True

        # Immediate second request - blocked
        assert limiter.check("J5peer1") is False

    def test_request_after_interval_allowed(self):
        """Test that requests are allowed after the interval expires."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=0.1)  # 100ms interval

        # First request - allowed
        assert limiter.check("J5peer1") is True

        # Wait for interval to expire
        time.sleep(0.15)

        # Second request after interval - allowed
        assert limiter.check("J5peer1") is True

    def test_different_peers_independent(self):
        """Test that rate limiting is per-peer, not global."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # First request from peer1 - allowed
        assert limiter.check("J5peer1") is True

        # First request from peer2 - also allowed (different peer)
        assert limiter.check("J5peer2") is True

        # Second request from peer1 - blocked
        assert limiter.check("J5peer1") is False

        # Second request from peer2 - also blocked
        assert limiter.check("J5peer2") is False

    def test_violation_count_tracked(self):
        """Test that violation counts are tracked per peer."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # First request - allowed, no violations
        assert limiter.check("J5peer1") is True
        assert limiter.get_violation_count("J5peer1") == 0

        # Blocked requests increment violation count
        assert limiter.check("J5peer1") is False
        assert limiter.get_violation_count("J5peer1") == 1

        assert limiter.check("J5peer1") is False
        assert limiter.get_violation_count("J5peer1") == 2

        # Different peer has independent count
        assert limiter.get_violation_count("J5peer2") == 0

    def test_cleanup_old_entries(self):
        """Test that cleanup removes stale entries."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # Add some entries
        limiter.check("J5peer1")
        limiter.check("J5peer1")  # Creates a violation
        limiter.check("J5peer2")

        # Entries should exist
        assert "J5peer1" in limiter._last_response
        assert "J5peer2" in limiter._last_response
        assert limiter.get_violation_count("J5peer1") == 1

        # Cleanup with max_age=0 removes everything
        limiter.cleanup_old_entries(max_age=0)

        assert "J5peer1" not in limiter._last_response
        assert "J5peer2" not in limiter._last_response
        assert limiter.get_violation_count("J5peer1") == 0

    def test_cleanup_preserves_recent_entries(self):
        """Test that cleanup preserves recent entries."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # Add an entry
        limiter.check("J5peer1")

        # Cleanup with large max_age keeps the entry
        limiter.cleanup_old_entries(max_age=3600)

        assert "J5peer1" in limiter._last_response

    def test_default_values(self):
        """Test that default values are applied correctly."""
        limiter = OrderbookRateLimiter()

        # Should use defaults from bot.py (1 req per 10s)
        assert limiter.interval == 10.0


class TestMakerBotRateLimiting:
    """Tests for rate limiting integration in MakerBot."""

    @pytest.fixture
    def mock_wallet(self):
        """Create a mock wallet service."""
        wallet = MagicMock()
        wallet.mixdepth_count = 5
        wallet.utxo_cache = {}
        return wallet

    @pytest.fixture
    def mock_backend(self):
        """Create a mock blockchain backend."""
        return MagicMock()

    @pytest.fixture
    def config(self):
        """Create a test maker config with custom rate limit settings."""
        return MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            orderbook_rate_limit=1,
            orderbook_rate_interval=5.0,
        )

    @pytest.fixture
    def maker_bot(self, mock_wallet, mock_backend, config):
        """Create a MakerBot instance for testing."""
        return MakerBot(
            wallet=mock_wallet,
            backend=mock_backend,
            config=config,
        )

    def test_bot_has_rate_limiter(self, maker_bot):
        """Test that MakerBot initializes with a rate limiter."""
        assert hasattr(maker_bot, "_orderbook_rate_limiter")
        assert isinstance(maker_bot._orderbook_rate_limiter, OrderbookRateLimiter)

    def test_bot_rate_limiter_uses_config(self, maker_bot):
        """Test that rate limiter uses config values."""
        assert maker_bot._orderbook_rate_limiter.interval == 5.0

    def test_config_default_rate_limit_values(self, mock_wallet, mock_backend):
        """Test default rate limit values in MakerConfig."""
        default_config = MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
        )

        assert default_config.orderbook_rate_limit == 1
        assert default_config.orderbook_rate_interval == 10.0

    def test_config_custom_rate_limit_values(self):
        """Test custom rate limit values in MakerConfig."""
        config = MakerConfig(
            mnemonic="test " * 12,
            directory_servers=["localhost:5222"],
            network=NetworkType.REGTEST,
            orderbook_rate_limit=5,
            orderbook_rate_interval=30.0,
        )

        assert config.orderbook_rate_limit == 5
        assert config.orderbook_rate_interval == 30.0

    def test_config_rate_limit_validation(self):
        """Test that invalid rate limit values are rejected."""
        # rate_limit must be >= 1
        with pytest.raises(ValueError):
            MakerConfig(
                mnemonic="test " * 12,
                directory_servers=["localhost:5222"],
                network=NetworkType.REGTEST,
                orderbook_rate_limit=0,
            )

        # interval must be >= 1.0
        with pytest.raises(ValueError):
            MakerConfig(
                mnemonic="test " * 12,
                directory_servers=["localhost:5222"],
                network=NetworkType.REGTEST,
                orderbook_rate_interval=0.5,
            )


class TestRateLimiterLogThrottling:
    """Tests for log throttling in rate limiter violations."""

    def test_violation_count_for_log_throttling(self):
        """Test that violation counts can be used for log throttling."""
        limiter = OrderbookRateLimiter(rate_limit=1, interval=10.0)

        # Initial request
        limiter.check("J5spammer")

        # Simulate 25 spam requests
        for _ in range(25):
            limiter.check("J5spammer")

        # Should have 25 violations
        count = limiter.get_violation_count("J5spammer")
        assert count == 25

        # Logic: only log every 10th violation (violations 10, 20, 30...)
        # This prevents log flooding from the rate limiter itself
        should_log_1 = count % 10 == 0  # 25 % 10 != 0, so False
        should_log_2 = (count + 5) % 10 == 0  # 30 % 10 == 0, so True

        assert should_log_1 is False
        assert should_log_2 is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
