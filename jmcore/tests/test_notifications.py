"""
Tests for the notification module.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from jmcore.notifications import (
    NotificationConfig,
    NotificationPriority,
    Notifier,
    get_notifier,
    load_notification_config,
    reset_notifier,
)


class TestNotificationConfig:
    """Tests for NotificationConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = NotificationConfig()

        assert config.enabled is False
        assert config.urls == []
        assert config.title_prefix == "JoinMarket NG"
        assert config.include_amounts is True
        assert config.include_txids is False
        assert config.include_nick is True
        assert config.notify_fill is True
        assert config.notify_rejection is True
        assert config.notify_peer_events is False  # Disabled by default

    def test_config_from_dict(self) -> None:
        """Test creating config from dict."""
        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
            title_prefix="Test",
            include_amounts=False,
        )

        assert config.enabled is True
        assert [url.get_secret_value() for url in config.urls] == ["gotify://host/token"]
        assert config.title_prefix == "Test"
        assert config.include_amounts is False

    def test_tor_config_defaults(self) -> None:
        """Test Tor configuration defaults."""
        config = NotificationConfig()

        assert config.use_tor is True

    def test_tor_config_custom(self) -> None:
        """Test custom Tor configuration."""
        config = NotificationConfig(
            use_tor=False,
        )

        assert config.use_tor is False


class TestLoadNotificationConfig:
    """Tests for load_notification_config."""

    def test_load_empty_env(self) -> None:
        """Test loading config with no environment variables."""
        with patch.dict(os.environ, {}, clear=True):
            config = load_notification_config()

        assert config.enabled is False
        assert config.urls == []

    def test_load_with_urls(self) -> None:
        """Test loading config with NOTIFY_URLS set."""
        env = {"NOTIFY_URLS": "gotify://host/token,tgram://bot/chat"}

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.enabled is True
        assert [url.get_secret_value() for url in config.urls] == [
            "gotify://host/token",
            "tgram://bot/chat",
        ]

    def test_load_with_quoted_urls(self) -> None:
        """Test loading config with quoted NOTIFY_URLS (common from shell escaping)."""
        # Test both single and double quotes
        test_cases = [
            ('"gotify://host/token"', "gotify://host/token"),
            ("'gotify://host/token'", "gotify://host/token"),
            (
                '"gotify://host/token","tgram://bot/chat"',
                ["gotify://host/token", "tgram://bot/chat"],
            ),
        ]

        for env_value, expected in test_cases:
            env = {"NOTIFY_URLS": env_value}
            with patch.dict(os.environ, env, clear=True):
                config = load_notification_config()

            assert config.enabled is True
            if isinstance(expected, list):
                assert [url.get_secret_value() for url in config.urls] == expected
            else:
                assert [url.get_secret_value() for url in config.urls] == [expected]

    def test_load_disabled_with_urls(self) -> None:
        """Test loading config with URLs but explicitly disabled."""
        env = {
            "NOTIFY_URLS": "gotify://host/token",
            "NOTIFY_ENABLED": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.enabled is False
        assert [url.get_secret_value() for url in config.urls] == ["gotify://host/token"]

    def test_load_privacy_settings(self) -> None:
        """Test loading privacy-related settings."""
        env = {
            "NOTIFY_URLS": "gotify://host/token",
            "NOTIFY_INCLUDE_AMOUNTS": "false",
            "NOTIFY_INCLUDE_TXIDS": "true",
            "NOTIFY_INCLUDE_NICK": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.include_amounts is False
        assert config.include_txids is True
        assert config.include_nick is False

    def test_load_event_toggles(self) -> None:
        """Test loading per-event toggles."""
        env = {
            "NOTIFY_URLS": "gotify://host/token",
            "NOTIFY_FILL": "false",
            "NOTIFY_SIGNING": "false",
            "NOTIFY_PEER_EVENTS": "true",
            "NOTIFY_STARTUP": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.notify_fill is False
        assert config.notify_signing is False
        assert config.notify_peer_events is True
        assert config.notify_startup is False
        # Defaults should remain
        assert config.notify_rejection is True
        assert config.notify_mempool is True

    def test_load_tor_settings(self) -> None:
        """Test loading Tor configuration from environment."""
        env = {
            "NOTIFY_URLS": "gotify://host/token",
            "NOTIFY_USE_TOR": "false",
        }

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.use_tor is False

    def test_load_tor_defaults(self) -> None:
        """Test that Tor is enabled by default."""
        env = {"NOTIFY_URLS": "gotify://host/token"}

        with patch.dict(os.environ, env, clear=True):
            config = load_notification_config()

        assert config.use_tor is True


class TestNotifier:
    """Tests for Notifier class."""

    def test_notifier_disabled_by_default(self) -> None:
        """Test that notifier is disabled with empty config."""
        config = NotificationConfig()
        notifier = Notifier(config)

        assert notifier.config.enabled is False

    @pytest.mark.asyncio
    async def test_send_when_disabled(self) -> None:
        """Test that _send returns False when disabled."""
        config = NotificationConfig(enabled=False)
        notifier = Notifier(config)

        result = await notifier._send("Test", "Body")

        assert result is False

    @pytest.mark.asyncio
    async def test_send_when_no_urls(self) -> None:
        """Test that _send returns False when no URLs configured."""
        config = NotificationConfig(enabled=True, urls=[])
        notifier = Notifier(config)

        result = await notifier._send("Test", "Body")

        assert result is False

    def test_format_amount(self) -> None:
        """Test amount formatting."""
        config = NotificationConfig(include_amounts=True)
        notifier = Notifier(config)

        assert "sats" in notifier._format_amount(50000)
        assert "BTC" in notifier._format_amount(100_000_000)

    def test_format_amount_hidden(self) -> None:
        """Test amount formatting when privacy enabled."""
        config = NotificationConfig(include_amounts=False)
        notifier = Notifier(config)

        assert notifier._format_amount(50000) == "[hidden]"

    def test_format_nick(self) -> None:
        """Test nick formatting."""
        config = NotificationConfig(include_nick=True)
        notifier = Notifier(config)

        # Short nick
        assert notifier._format_nick("alice") == "alice"
        # Long nick (not truncated anymore)
        assert notifier._format_nick("verylongnickname") == "verylongnickname"

    def test_format_nick_hidden(self) -> None:
        """Test nick formatting when privacy enabled."""
        config = NotificationConfig(include_nick=False)
        notifier = Notifier(config)

        assert notifier._format_nick("alice") == "[hidden]"

    def test_format_txid(self) -> None:
        """Test txid formatting."""
        config = NotificationConfig(include_txids=True)
        notifier = Notifier(config)

        txid = "a" * 64
        formatted = notifier._format_txid(txid)
        assert "..." in formatted
        assert len(formatted) < len(txid)

    def test_format_txid_hidden(self) -> None:
        """Test txid formatting when privacy enabled."""
        config = NotificationConfig(include_txids=False)
        notifier = Notifier(config)

        assert notifier._format_txid("a" * 64) == "[hidden]"

    @pytest.mark.asyncio
    async def test_notify_fill_request_disabled(self) -> None:
        """Test that fill notification respects toggle."""
        config = NotificationConfig(enabled=True, urls=["test://"], notify_fill=False)
        notifier = Notifier(config)

        result = await notifier.notify_fill_request("taker", 100000, 0)

        assert result is False

    @pytest.mark.asyncio
    async def test_notify_rejection_disabled(self) -> None:
        """Test that rejection notification respects toggle."""
        config = NotificationConfig(enabled=True, urls=["test://"], notify_rejection=False)
        notifier = Notifier(config)

        result = await notifier.notify_rejection("taker", "reason")

        assert result is False

    @pytest.mark.asyncio
    async def test_notify_peer_events_disabled(self) -> None:
        """Test that peer event notifications respect toggle."""
        config = NotificationConfig(enabled=True, urls=["test://"], notify_peer_events=False)
        notifier = Notifier(config)

        result = await notifier.notify_peer_connected("alice", "onion", 10)

        assert result is False

    @pytest.mark.asyncio
    async def test_notify_startup_disabled(self) -> None:
        """Test that startup notification respects toggle."""
        config = NotificationConfig(enabled=True, urls=["test://"], notify_startup=False)
        notifier = Notifier(config)

        result = await notifier.notify_startup("maker", "1.0.0", "mainnet")

        assert result is False

    @pytest.mark.asyncio
    async def test_notify_with_mock_apprise(self) -> None:
        """Test notification with mocked apprise."""
        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
        )
        notifier = Notifier(config)

        # Mock the apprise module
        mock_apprise_instance = MagicMock()
        mock_apprise_instance.add.return_value = True
        mock_apprise_instance.__len__ = lambda self: 1
        mock_apprise_instance.async_notify = AsyncMock(return_value=True)

        mock_apprise_module = MagicMock()
        mock_apprise_module.Apprise.return_value = mock_apprise_instance
        mock_apprise_module.NotifyType.INFO = "info"

        with patch.dict("sys.modules", {"apprise": mock_apprise_module}):
            # Force re-initialization
            notifier._initialized = False
            notifier._apprise = None

            result = await notifier.notify_fill_request("taker123", 500000, 0)

        # Should succeed with mock
        assert result is True
        mock_apprise_instance.async_notify.assert_called_once()

    @pytest.mark.asyncio
    async def test_tor_proxy_configuration(self) -> None:
        """Test that Tor proxy environment variables are set correctly."""
        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
            use_tor=True,
        )
        notifier = Notifier(config)

        # Mock the apprise module
        mock_apprise_instance = MagicMock()
        mock_apprise_instance.add.return_value = True
        mock_apprise_instance.__len__ = lambda self: 1

        mock_apprise_module = MagicMock()
        mock_apprise_module.Apprise.return_value = mock_apprise_instance

        # Set custom TOR_SOCKS_HOST and TOR_SOCKS_PORT
        env = {
            "TOR_SOCKS_HOST": "192.168.1.100",
            "TOR_SOCKS_PORT": "9150",
        }

        with (
            patch.dict("sys.modules", {"apprise": mock_apprise_module}),
            patch.dict(os.environ, env),
        ):
            # Force re-initialization
            notifier._initialized = False
            notifier._apprise = None

            await notifier._ensure_initialized()

            # Verify proxy environment variables were set with socks5h:// (DNS through proxy)
            assert os.environ.get("HTTP_PROXY") == "socks5h://192.168.1.100:9150"
            assert os.environ.get("HTTPS_PROXY") == "socks5h://192.168.1.100:9150"

    @pytest.mark.asyncio
    async def test_tor_proxy_disabled(self) -> None:
        """Test that proxy is not set when Tor is disabled."""
        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
            use_tor=False,
        )
        notifier = Notifier(config)

        # Mock the apprise module
        mock_apprise_instance = MagicMock()
        mock_apprise_instance.add.return_value = True
        mock_apprise_instance.__len__ = lambda self: 1

        mock_apprise_module = MagicMock()
        mock_apprise_module.Apprise.return_value = mock_apprise_instance

        # Clear any existing proxy env vars
        env_clear = {k: v for k, v in os.environ.items() if k not in ["HTTP_PROXY", "HTTPS_PROXY"]}

        with (
            patch.dict("sys.modules", {"apprise": mock_apprise_module}),
            patch.dict(os.environ, env_clear, clear=True),
        ):
            # Force re-initialization
            notifier._initialized = False
            notifier._apprise = None

            await notifier._ensure_initialized()

            # Verify proxy environment variables were NOT set
            assert "HTTP_PROXY" not in os.environ
            assert "HTTPS_PROXY" not in os.environ


class TestGlobalNotifier:
    """Tests for global notifier functions."""

    def test_get_notifier_singleton(self) -> None:
        """Test that get_notifier returns same instance."""
        reset_notifier()

        n1 = get_notifier()
        n2 = get_notifier()

        assert n1 is n2

    def test_reset_notifier(self) -> None:
        """Test that reset_notifier clears the singleton."""
        reset_notifier()
        n1 = get_notifier()
        reset_notifier()
        n2 = get_notifier()

        assert n1 is not n2


class TestNotificationPriority:
    """Tests for NotificationPriority enum."""

    def test_priority_values(self) -> None:
        """Test priority enum values."""
        assert NotificationPriority.INFO.value == "info"
        assert NotificationPriority.SUCCESS.value == "success"
        assert NotificationPriority.WARNING.value == "warning"
        assert NotificationPriority.FAILURE.value == "failure"


class TestNotificationLogging:
    """Tests for notification logging."""

    def test_load_config_logs_enabled(self) -> None:
        """Test that loading config logs INFO when notifications enabled."""
        from io import StringIO

        from loguru import logger

        env = {"NOTIFY_URLS": "gotify://host/token,tgram://bot/chat"}
        output = StringIO()
        handler_id = logger.add(output, format="{message}", level="INFO")

        try:
            with patch.dict(os.environ, env, clear=True):
                load_notification_config()
        finally:
            logger.remove(handler_id)

        log_output = output.getvalue()
        assert "Notifications enabled with 2 URL(s)" in log_output
        assert "use_tor=True" in log_output

    def test_load_config_logs_disabled_no_urls(self) -> None:
        """Test that loading config logs INFO when no URLs set."""
        from io import StringIO

        from loguru import logger

        output = StringIO()
        handler_id = logger.add(output, format="{message}", level="INFO")

        try:
            with patch.dict(os.environ, {}, clear=True):
                load_notification_config()
        finally:
            logger.remove(handler_id)

        log_output = output.getvalue()
        assert "Notifications disabled (NOTIFY_URLS not set)" in log_output

    def test_load_config_logs_disabled_explicit(self) -> None:
        """Test that loading config logs INFO when explicitly disabled."""
        from io import StringIO

        from loguru import logger

        env = {
            "NOTIFY_URLS": "gotify://host/token",
            "NOTIFY_ENABLED": "false",
        }
        output = StringIO()
        handler_id = logger.add(output, format="{message}", level="INFO")

        try:
            with patch.dict(os.environ, env, clear=True):
                load_notification_config()
        finally:
            logger.remove(handler_id)

        log_output = output.getvalue()
        assert "Notifications disabled (NOTIFY_ENABLED=false)" in log_output

    @pytest.mark.asyncio
    async def test_send_logs_success_at_debug(self) -> None:
        """Test that successful notification sends log at DEBUG level."""
        from io import StringIO

        from loguru import logger

        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
        )
        notifier = Notifier(config)

        # Mock the apprise module
        mock_apprise_instance = MagicMock()
        mock_apprise_instance.add.return_value = True
        mock_apprise_instance.__len__ = lambda self: 1
        mock_apprise_instance.async_notify = AsyncMock(return_value=True)

        mock_apprise_module = MagicMock()
        mock_apprise_module.Apprise.return_value = mock_apprise_instance
        mock_apprise_module.NotifyType.INFO = "info"

        output = StringIO()
        handler_id = logger.add(output, format="{message}", level="DEBUG")

        try:
            with patch.dict("sys.modules", {"apprise": mock_apprise_module}):
                # Force re-initialization
                notifier._initialized = False
                notifier._apprise = None

                await notifier._send("Test Title", "Test body")
        finally:
            logger.remove(handler_id)

        log_output = output.getvalue()
        assert "Notification sent: Test Title" in log_output

    @pytest.mark.asyncio
    async def test_send_logs_failure_at_debug(self) -> None:
        """Test that failed notification sends log at DEBUG level."""
        from io import StringIO

        from loguru import logger

        config = NotificationConfig(
            enabled=True,
            urls=["gotify://host/token"],
        )
        notifier = Notifier(config)

        # Mock the apprise module
        mock_apprise_instance = MagicMock()
        mock_apprise_instance.add.return_value = True
        mock_apprise_instance.__len__ = lambda self: 1
        mock_apprise_instance.async_notify = AsyncMock(return_value=False)

        mock_apprise_module = MagicMock()
        mock_apprise_module.Apprise.return_value = mock_apprise_instance
        mock_apprise_module.NotifyType.INFO = "info"

        output = StringIO()
        handler_id = logger.add(output, format="{message}", level="DEBUG")

        try:
            with patch.dict("sys.modules", {"apprise": mock_apprise_module}):
                # Force re-initialization
                notifier._initialized = False
                notifier._apprise = None

                await notifier._send("Test Title", "Test body")
        finally:
            logger.remove(handler_id)

        log_output = output.getvalue()
        assert "Notification failed: Test Title" in log_output
