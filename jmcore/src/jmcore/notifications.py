"""
Notification system for JoinMarket components.

Provides operator notifications through Apprise, supporting multiple notification
channels (Gotify, Telegram, Pushover, Discord, email, etc.).

Configuration is via environment variables:
- NOTIFY_URLS: Comma-separated list of Apprise URLs (required to enable notifications)
- NOTIFY_ENABLED: Set to "false" to disable all notifications (default: true if NOTIFY_URLS set)
- NOTIFY_TITLE_PREFIX: Prefix for notification titles (default: "JoinMarket")

Example NOTIFY_URLS:
- Gotify: gotify://hostname/token
- Telegram: tgram://bot_token/chat_id
- Pushover: pover://user_key@token
- Discord: discord://webhook_id/webhook_token
- Slack: slack://hook_id
- Email: mailto://user:pass@smtp.example.com
- Multiple: gotify://host/token,tgram://bot/chat

For full list of supported services: https://github.com/caronc/apprise#supported-notifications

Usage:
    from jmcore.notifications import get_notifier

    notifier = get_notifier()
    await notifier.notify_fill_request(taker_nick, cj_amount, offer_id)

The module is designed to be:
1. Fire-and-forget: Notification failures don't affect protocol operations
2. Async-first: All notifications are sent asynchronously
3. Privacy-aware: Sensitive data (txids, amounts) can be optionally excluded
4. Configurable: Per-event type enable/disable through environment variables
"""

from __future__ import annotations

import asyncio
import os
from enum import Enum
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import BaseModel, Field, SecretStr

if TYPE_CHECKING:
    from jmcore.settings import JoinMarketSettings


class NotificationPriority(str, Enum):
    """Notification priority levels (maps to Apprise NotifyType)."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    FAILURE = "failure"


class NotificationConfig(BaseModel):
    """
    Configuration for the notification system.

    All configuration is loaded from environment variables.
    """

    # Core settings
    enabled: bool = Field(
        default=False,
        description="Master switch for notifications",
    )
    urls: list[SecretStr] = Field(
        default_factory=list,
        description="List of Apprise notification URLs",
    )
    title_prefix: str = Field(
        default="JoinMarket NG",
        description="Prefix for all notification titles",
    )

    # Privacy settings - exclude sensitive data from notifications
    include_amounts: bool = Field(
        default=True,
        description="Include amounts in notifications",
    )
    include_txids: bool = Field(
        default=False,
        description="Include transaction IDs in notifications (privacy risk)",
    )
    include_nick: bool = Field(
        default=True,
        description="Include peer nicks in notifications",
    )

    # Tor/Proxy settings
    use_tor: bool = Field(
        default=True,
        description="Route notifications through Tor SOCKS proxy",
    )

    # Event type toggles (all enabled by default if notifications are enabled)
    notify_fill: bool = Field(default=True, description="Notify on !fill requests")
    notify_rejection: bool = Field(default=True, description="Notify on rejections")
    notify_signing: bool = Field(default=True, description="Notify on tx signing")
    notify_mempool: bool = Field(default=True, description="Notify on mempool detection")
    notify_confirmed: bool = Field(default=True, description="Notify on confirmation")
    notify_nick_change: bool = Field(default=True, description="Notify on nick change")
    notify_disconnect: bool = Field(default=True, description="Notify on directory disconnect")
    notify_coinjoin_start: bool = Field(default=True, description="Notify on CoinJoin start")
    notify_coinjoin_complete: bool = Field(default=True, description="Notify on CoinJoin complete")
    notify_coinjoin_failed: bool = Field(default=True, description="Notify on CoinJoin failure")
    notify_peer_events: bool = Field(default=False, description="Notify on peer connect/disconnect")
    notify_rate_limit: bool = Field(default=True, description="Notify on rate limit bans")
    notify_startup: bool = Field(default=True, description="Notify on component startup")

    model_config = {"frozen": False}


def load_notification_config() -> NotificationConfig:
    """
    Load notification configuration from environment variables.

    Environment variables:
    - NOTIFY_URLS: Comma-separated Apprise URLs
    - NOTIFY_ENABLED: "true"/"false" (default: true if NOTIFY_URLS is set)
    - NOTIFY_TITLE_PREFIX: Title prefix (default: "JoinMarket")
    - NOTIFY_INCLUDE_AMOUNTS: Include amounts (default: true)
    - NOTIFY_INCLUDE_TXIDS: Include txids (default: false)
    - NOTIFY_INCLUDE_NICK: Include peer nicks (default: true)
    - NOTIFY_STARTUP: Notify on startup (default: true)
    - NOTIFY_USE_TOR: Route through Tor SOCKS proxy (default: true)
      - Uses TOR_SOCKS_HOST and TOR_SOCKS_PORT environment variables for proxy address
    - NOTIFY_<EVENT>: Per-event toggles (e.g., NOTIFY_FILL, NOTIFY_SIGNING)
    """
    urls_str = os.environ.get("NOTIFY_URLS", "")
    # Strip whitespace and quotes from URLs (quotes may be present from shell escaping)
    urls_raw = [url.strip().strip('"').strip("'") for url in urls_str.split(",") if url.strip()]
    # Wrap in SecretStr
    urls = [SecretStr(url) for url in urls_raw]

    # Notifications are enabled if URLs are provided and not explicitly disabled
    enabled_str = os.environ.get("NOTIFY_ENABLED", "").lower()
    if enabled_str == "false":
        enabled = False
    elif enabled_str == "true":
        enabled = True
    else:
        enabled = bool(urls)

    def get_bool_env(key: str, default: bool) -> bool:
        val = os.environ.get(key, "").lower()
        if val == "true":
            return True
        elif val == "false":
            return False
        return default

    config = NotificationConfig(
        enabled=enabled,
        urls=urls,
        title_prefix=os.environ.get("NOTIFY_TITLE_PREFIX", "JoinMarket NG"),
        include_amounts=get_bool_env("NOTIFY_INCLUDE_AMOUNTS", True),
        include_txids=get_bool_env("NOTIFY_INCLUDE_TXIDS", False),
        include_nick=get_bool_env("NOTIFY_INCLUDE_NICK", True),
        use_tor=get_bool_env("NOTIFY_USE_TOR", True),
        notify_fill=get_bool_env("NOTIFY_FILL", True),
        notify_rejection=get_bool_env("NOTIFY_REJECTION", True),
        notify_signing=get_bool_env("NOTIFY_SIGNING", True),
        notify_mempool=get_bool_env("NOTIFY_MEMPOOL", True),
        notify_confirmed=get_bool_env("NOTIFY_CONFIRMED", True),
        notify_nick_change=get_bool_env("NOTIFY_NICK_CHANGE", True),
        notify_disconnect=get_bool_env("NOTIFY_DISCONNECT", True),
        notify_coinjoin_start=get_bool_env("NOTIFY_COINJOIN_START", True),
        notify_coinjoin_complete=get_bool_env("NOTIFY_COINJOIN_COMPLETE", True),
        notify_coinjoin_failed=get_bool_env("NOTIFY_COINJOIN_FAILED", True),
        notify_peer_events=get_bool_env("NOTIFY_PEER_EVENTS", False),
        notify_rate_limit=get_bool_env("NOTIFY_RATE_LIMIT", True),
        notify_startup=get_bool_env("NOTIFY_STARTUP", True),
    )

    # Log configuration status at INFO level
    if config.enabled:
        logger.info(
            f"Notifications enabled with {len(config.urls)} URL(s), use_tor={config.use_tor}"
        )
    else:
        if urls:
            logger.info("Notifications disabled (NOTIFY_ENABLED=false)")
        else:
            logger.info("Notifications disabled (NOTIFY_URLS not set)")

    return config


def convert_settings_to_notification_config(settings: JoinMarketSettings) -> NotificationConfig:
    """
    Convert NotificationSettings from JoinMarketSettings to NotificationConfig.

    This allows the notification system to use the unified settings system
    (config file + env vars + CLI args) instead of only environment variables.

    Args:
        settings: JoinMarketSettings instance with notification configuration

    Returns:
        NotificationConfig suitable for use with Notifier
    """
    ns = settings.notifications

    # Convert URL strings to SecretStr
    urls = [SecretStr(url) for url in ns.urls]

    # Notifications are enabled if explicitly enabled or if URLs are provided
    enabled = ns.enabled or bool(ns.urls)

    return NotificationConfig(
        enabled=enabled,
        urls=urls,
        title_prefix=ns.title_prefix,
        include_amounts=ns.include_amounts,
        include_txids=ns.include_txids,
        include_nick=ns.include_nick,
        use_tor=ns.use_tor,
        notify_fill=ns.notify_fill,
        notify_rejection=ns.notify_rejection,
        notify_signing=ns.notify_signing,
        notify_mempool=ns.notify_mempool,
        notify_confirmed=ns.notify_confirmed,
        notify_nick_change=ns.notify_nick_change,
        notify_disconnect=ns.notify_disconnect,
        notify_coinjoin_start=ns.notify_coinjoin_start,
        notify_coinjoin_complete=ns.notify_coinjoin_complete,
        notify_coinjoin_failed=ns.notify_coinjoin_failed,
        notify_peer_events=ns.notify_peer_events,
        notify_rate_limit=ns.notify_rate_limit,
        notify_startup=ns.notify_startup,
    )


class Notifier:
    """
    Notification sender using Apprise.

    Thread-safe and async-friendly. Notification failures are logged but
    don't raise exceptions - notifications should never block protocol operations.
    """

    def __init__(self, config: NotificationConfig | None = None):
        """
        Initialize the notifier.

        Args:
            config: Notification configuration. If None, loads from environment.
        """
        self.config = config or load_notification_config()
        self._apprise: Any | None = None
        self._initialized = False
        self._lock = asyncio.Lock()

    async def _ensure_initialized(self) -> bool:
        """Lazily initialize Apprise. Returns True if ready to send."""
        if not self.config.enabled or not self.config.urls:
            return False

        if self._initialized:
            return self._apprise is not None

        async with self._lock:
            if self._initialized:
                return self._apprise is not None

            try:
                import apprise

                # Configure proxy environment variables if Tor is enabled
                if self.config.use_tor:
                    # Use the standard JoinMarket Tor configuration
                    tor_host = os.environ.get("TOR_SOCKS_HOST", "127.0.0.1")
                    tor_port = os.environ.get("TOR_SOCKS_PORT", "9050")
                    # Use socks5h:// to resolve DNS through the proxy (important for .onion)
                    proxy_url = f"socks5h://{tor_host}:{tor_port}"
                    # Set environment variables that Apprise/requests will use
                    os.environ["HTTP_PROXY"] = proxy_url
                    os.environ["HTTPS_PROXY"] = proxy_url
                    logger.info(f"Configuring notifications to route through Tor: {proxy_url}")

                self._apprise = apprise.Apprise()

                # Use longer timeout for Tor connections (default is 4s, too short for Tor)
                # Tor circuit establishment can take 10-30 seconds
                # Use Apprise's cto (connection timeout) and rto (read timeout) URL parameters
                for secret_url in self.config.urls:
                    # Get the actual URL string from SecretStr
                    url = secret_url.get_secret_value()

                    if self.config.use_tor:
                        # Append timeout parameters to URL for Tor connections
                        # cto = connection timeout, rto = read timeout (both in seconds)
                        timeout_params = "cto=30&rto=30"
                        if "?" in url:
                            url_with_timeout = f"{url}&{timeout_params}"
                        else:
                            url_with_timeout = f"{url}?{timeout_params}"
                    else:
                        url_with_timeout = url

                    if not self._apprise.add(url_with_timeout):
                        logger.warning(f"Failed to add notification URL: {url[:30]}...")

                if len(self._apprise) == 0:
                    logger.warning("No valid notification URLs configured")
                    self._apprise = None
                else:
                    logger.info(f"Notifications enabled with {len(self._apprise)} service(s)")

            except ImportError:
                logger.warning(
                    "Apprise not installed. Install with: pip install apprise\n"
                    "Notifications will be disabled."
                )
                self._apprise = None
            except Exception as e:
                logger.warning(f"Failed to initialize notifications: {e}")
                self._apprise = None

            self._initialized = True
            return self._apprise is not None

    async def _send(
        self,
        title: str,
        body: str,
        priority: NotificationPriority = NotificationPriority.INFO,
    ) -> bool:
        """
        Send a notification via Apprise.

        Args:
            title: Notification title (will be prefixed)
            body: Notification body
            priority: Notification priority

        Returns:
            True if sent successfully to at least one service
        """
        if not await self._ensure_initialized():
            return False

        # At this point, _apprise is guaranteed to be initialized
        assert self._apprise is not None
        apprise_instance = self._apprise  # Bind to local for type narrowing

        try:
            import apprise

            # Map our priority to Apprise NotifyType
            notify_type = {
                NotificationPriority.INFO: apprise.NotifyType.INFO,
                NotificationPriority.SUCCESS: apprise.NotifyType.SUCCESS,
                NotificationPriority.WARNING: apprise.NotifyType.WARNING,
                NotificationPriority.FAILURE: apprise.NotifyType.FAILURE,
            }.get(priority, apprise.NotifyType.INFO)

            full_title = f"{self.config.title_prefix}: {title}"

            # Send asynchronously if apprise supports it, otherwise in executor
            if hasattr(apprise_instance, "async_notify"):
                result = await apprise_instance.async_notify(
                    title=full_title,
                    body=body,
                    notify_type=notify_type,
                )
            else:
                # Run synchronous notify in thread pool
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: apprise_instance.notify(
                        title=full_title,
                        body=body,
                        notify_type=notify_type,
                    ),
                )

            if not result:
                logger.warning(
                    f"Notification failed: {title}. "
                    "Check Tor connectivity and notification service URL. "
                    "Ensure PySocks is installed for SOCKS proxy support."
                )
            else:
                logger.debug(f"Notification sent: {title}")
            return result

        except Exception as e:
            logger.warning(f"Failed to send notification '{title}': {e}")
            return False

    def _format_amount(self, sats: int) -> str:
        """Format satoshi amount for display."""
        if not self.config.include_amounts:
            return "[hidden]"
        if sats >= 100_000_000:
            return f"{sats / 100_000_000:.4f} BTC"
        return f"{sats:,} sats"

    def _format_nick(self, nick: str) -> str:
        """Format nick for display."""
        if not self.config.include_nick:
            return "[hidden]"
        return nick

    def _format_txid(self, txid: str) -> str:
        """Format txid for display."""
        if not self.config.include_txids:
            return "[hidden]"
        return f"{txid[:16]}..."

    # =========================================================================
    # Maker notifications
    # =========================================================================

    async def notify_fill_request(
        self,
        taker_nick: str,
        cj_amount: int,
        offer_id: int,
    ) -> bool:
        """Notify when a !fill request is received (maker)."""
        if not self.config.notify_fill:
            return False

        return await self._send(
            title="Fill Request Received",
            body=(
                f"Taker: {self._format_nick(taker_nick)}\n"
                f"Amount: {self._format_amount(cj_amount)}\n"
                f"Offer ID: {offer_id}"
            ),
            priority=NotificationPriority.INFO,
        )

    async def notify_rejection(
        self,
        taker_nick: str,
        reason: str,
        details: str = "",
    ) -> bool:
        """Notify when rejecting a taker request (maker)."""
        if not self.config.notify_rejection:
            return False

        body = f"Taker: {self._format_nick(taker_nick)}\nReason: {reason}"
        if details:
            body += f"\nDetails: {details}"

        return await self._send(
            title="Request Rejected",
            body=body,
            priority=NotificationPriority.WARNING,
        )

    async def notify_tx_signed(
        self,
        taker_nick: str,
        cj_amount: int,
        num_inputs: int,
        fee_earned: int,
    ) -> bool:
        """Notify when transaction is signed (maker)."""
        if not self.config.notify_signing:
            return False

        return await self._send(
            title="Transaction Signed",
            body=(
                f"Taker: {self._format_nick(taker_nick)}\n"
                f"CJ Amount: {self._format_amount(cj_amount)}\n"
                f"Inputs signed: {num_inputs}\n"
                f"Fee earned: {self._format_amount(fee_earned)}"
            ),
            priority=NotificationPriority.SUCCESS,
        )

    async def notify_mempool(
        self,
        txid: str,
        cj_amount: int,
        role: str = "maker",
    ) -> bool:
        """Notify when CoinJoin is seen in mempool."""
        if not self.config.notify_mempool:
            return False

        return await self._send(
            title="CoinJoin in Mempool",
            body=(
                f"Role: {role.capitalize()}\n"
                f"TxID: {self._format_txid(txid)}\n"
                f"Amount: {self._format_amount(cj_amount)}"
            ),
            priority=NotificationPriority.INFO,
        )

    async def notify_confirmed(
        self,
        txid: str,
        cj_amount: int,
        confirmations: int,
        role: str = "maker",
    ) -> bool:
        """Notify when CoinJoin is confirmed."""
        if not self.config.notify_confirmed:
            return False

        return await self._send(
            title="CoinJoin Confirmed",
            body=(
                f"Role: {role.capitalize()}\n"
                f"TxID: {self._format_txid(txid)}\n"
                f"Amount: {self._format_amount(cj_amount)}\n"
                f"Confirmations: {confirmations}"
            ),
            priority=NotificationPriority.SUCCESS,
        )

    async def notify_nick_change(
        self,
        old_nick: str,
        new_nick: str,
    ) -> bool:
        """Notify when maker nick changes (privacy feature)."""
        if not self.config.notify_nick_change:
            return False

        return await self._send(
            title="Nick Changed",
            body=(f"Old: {self._format_nick(old_nick)}\nNew: {self._format_nick(new_nick)}"),
            priority=NotificationPriority.INFO,
        )

    async def notify_directory_disconnect(
        self,
        server: str,
        connected_count: int,
        total_count: int,
        reconnecting: bool = True,
    ) -> bool:
        """Notify when disconnected from a directory server."""
        if not self.config.notify_disconnect:
            return False

        status = "reconnecting" if reconnecting else "disconnected"
        priority = NotificationPriority.WARNING
        if connected_count == 0:
            priority = NotificationPriority.FAILURE

        return await self._send(
            title="Directory Server Disconnected",
            body=(
                f"Server: {server[:30]}...\n"
                f"Status: {status}\n"
                f"Connected: {connected_count}/{total_count}"
            ),
            priority=priority,
        )

    async def notify_all_directories_disconnected(self) -> bool:
        """Notify when disconnected from ALL directory servers (critical)."""
        return await self._send(
            title="CRITICAL: All Directories Disconnected",
            body=(
                "Lost connection to ALL directory servers.\n"
                "No CoinJoins possible until reconnected.\n"
                "Check network connectivity and Tor status."
            ),
            priority=NotificationPriority.FAILURE,
        )

    # =========================================================================
    # Taker notifications
    # =========================================================================

    async def notify_coinjoin_start(
        self,
        cj_amount: int,
        num_makers: int,
        destination: str,
    ) -> bool:
        """Notify when CoinJoin is initiated (taker)."""
        if not self.config.notify_coinjoin_start:
            return False

        dest_display = "internal" if destination == "INTERNAL" else f"{destination[:12]}..."

        return await self._send(
            title="CoinJoin Started",
            body=(
                f"Amount: {self._format_amount(cj_amount)}\n"
                f"Makers: {num_makers}\n"
                f"Destination: {dest_display}"
            ),
            priority=NotificationPriority.INFO,
        )

    async def notify_coinjoin_complete(
        self,
        txid: str,
        cj_amount: int,
        num_makers: int,
        total_fees: int,
    ) -> bool:
        """Notify when CoinJoin completes successfully (taker)."""
        if not self.config.notify_coinjoin_complete:
            return False

        return await self._send(
            title="CoinJoin Complete",
            body=(
                f"TxID: {self._format_txid(txid)}\n"
                f"Amount: {self._format_amount(cj_amount)}\n"
                f"Makers: {num_makers}\n"
                f"Total fees: {self._format_amount(total_fees)}"
            ),
            priority=NotificationPriority.SUCCESS,
        )

    async def notify_coinjoin_failed(
        self,
        reason: str,
        phase: str = "",
        cj_amount: int = 0,
    ) -> bool:
        """Notify when CoinJoin fails (taker)."""
        if not self.config.notify_coinjoin_failed:
            return False

        body = f"Reason: {reason}"
        if phase:
            body = f"Phase: {phase}\n" + body
        if cj_amount > 0:
            body += f"\nAmount: {self._format_amount(cj_amount)}"

        return await self._send(
            title="CoinJoin Failed",
            body=body,
            priority=NotificationPriority.FAILURE,
        )

    # =========================================================================
    # Directory server notifications
    # =========================================================================

    async def notify_peer_connected(
        self,
        nick: str,
        location: str,
        total_peers: int,
    ) -> bool:
        """Notify when a new peer connects (directory server)."""
        if not self.config.notify_peer_events:
            return False

        return await self._send(
            title="Peer Connected",
            body=(
                f"Nick: {self._format_nick(nick)}\n"
                f"Location: {location[:30]}...\n"
                f"Total peers: {total_peers}"
            ),
            priority=NotificationPriority.INFO,
        )

    async def notify_peer_disconnected(
        self,
        nick: str,
        total_peers: int,
    ) -> bool:
        """Notify when a peer disconnects (directory server)."""
        if not self.config.notify_peer_events:
            return False

        return await self._send(
            title="Peer Disconnected",
            body=(f"Nick: {self._format_nick(nick)}\nRemaining peers: {total_peers}"),
            priority=NotificationPriority.INFO,
        )

    async def notify_peer_banned(
        self,
        nick: str,
        reason: str,
        duration: int,
    ) -> bool:
        """Notify when a peer is banned for rate limit violations."""
        if not self.config.notify_rate_limit:
            return False

        return await self._send(
            title="Peer Banned",
            body=(f"Nick: {self._format_nick(nick)}\nReason: {reason}\nDuration: {duration}s"),
            priority=NotificationPriority.WARNING,
        )

    # =========================================================================
    # Orderbook watcher notifications
    # =========================================================================

    async def notify_orderbook_status(
        self,
        connected_directories: int,
        total_directories: int,
        total_offers: int,
        total_makers: int,
    ) -> bool:
        """Notify orderbook status summary."""
        return await self._send(
            title="Orderbook Status",
            body=(
                f"Directories: {connected_directories}/{total_directories}\n"
                f"Offers: {total_offers}\n"
                f"Makers: {total_makers}"
            ),
            priority=NotificationPriority.INFO,
        )

    async def notify_maker_offline(
        self,
        nick: str,
        last_seen: str,
    ) -> bool:
        """Notify when a maker goes offline."""
        return await self._send(
            title="Maker Offline",
            body=(f"Nick: {self._format_nick(nick)}\nLast seen: {last_seen}"),
            priority=NotificationPriority.INFO,
        )

    # =========================================================================
    # Generic notification
    # =========================================================================

    async def notify_startup(
        self,
        component: str,
        version: str = "",
        network: str = "",
    ) -> bool:
        """Notify when a component starts up."""
        if not self.config.notify_startup:
            return False

        body = f"Component: {component}"
        if version:
            body += f"\nVersion: {version}"
        if network:
            body += f"\nNetwork: {network}"

        return await self._send(
            title="Component Started",
            body=body,
            priority=NotificationPriority.INFO,
        )

    async def notify(
        self,
        title: str,
        body: str,
        priority: NotificationPriority = NotificationPriority.INFO,
    ) -> bool:
        """Send a generic notification."""
        return await self._send(title, body, priority)


# Global notifier instance (lazy-loaded)
_notifier: Notifier | None = None


def get_notifier(settings: JoinMarketSettings | None = None) -> Notifier:
    """
    Get the global Notifier instance.

    The notifier is lazily initialized on first use. Configuration is loaded
    from JoinMarketSettings if provided, otherwise from environment variables.

    Args:
        settings: Optional JoinMarketSettings instance. If provided, notification
                  configuration will be taken from settings.notifications
                  (which supports config file + env vars + CLI args).
                  If None, falls back to environment variables only (legacy).

    Returns:
        Notifier instance
    """
    global _notifier
    if _notifier is None:
        if settings is not None:
            config = convert_settings_to_notification_config(settings)
        else:
            config = load_notification_config()
        _notifier = Notifier(config)
    return _notifier


def reset_notifier() -> None:
    """Reset the global notifier (useful for testing)."""
    global _notifier
    _notifier = None


__all__ = [
    "NotificationConfig",
    "NotificationPriority",
    "Notifier",
    "get_notifier",
    "reset_notifier",
    "load_notification_config",
    "convert_settings_to_notification_config",
]
