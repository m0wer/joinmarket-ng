#!/usr/bin/env python3
"""
CoinJoin History Monitor - Sends Gotify notifications for new CoinJoin transactions.

This script watches the coinjoin_history.csv file for new entries and sends
notifications via Gotify when CoinJoins are completed or confirmed.

Uses inotify to efficiently monitor file changes without polling.

Configuration via environment variables:
- HISTORY_FILE: Path to coinjoin_history.csv (default: ~/.joinmarket/coinjoin_history.csv)
- GOTIFY_URL: Gotify server URL (default: https://gotify.example.com)
- GOTIFY_TOKEN: Gotify app token (required)
- NOTIFY_ON_PENDING: Send notifications for pending transactions (default: true)
- NOTIFY_ON_CONFIRMED: Send notifications for confirmed transactions (default: true)

Usage:
    # Install dependencies (choose one):
    pip install inotify  # Recommended
    pip install pyinotify  # Alternative

    export GOTIFY_TOKEN="your-token-here"
    python3 coinjoin_notifier.py

    # Custom settings
    export HISTORY_FILE="/data/joinmarket-ng/coinjoin_history.csv"
    export GOTIFY_URL="https://gotify.example.com"
    python3 coinjoin_notifier.py
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import subprocess
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Configuration with sane defaults
HISTORY_FILE = Path(
    os.getenv("HISTORY_FILE", Path.home() / ".joinmarket" / "coinjoin_history.csv")
)
GOTIFY_URL = os.getenv("GOTIFY_URL", "https://gotify.example.com")
GOTIFY_TOKEN = os.getenv("GOTIFY_TOKEN", "")
NOTIFY_ON_PENDING = os.getenv("NOTIFY_ON_PENDING", "true").lower() == "true"
NOTIFY_ON_CONFIRMED = os.getenv("NOTIFY_ON_CONFIRMED", "true").lower() == "true"


def send_gotify_notification(title: str, message: str, priority: int = 5) -> bool:
    """
    Send a notification to Gotify using curl.

    Args:
        title: Notification title
        message: Notification message
        priority: Priority level (0-10, default 5)

    Returns:
        True if successful, False otherwise
    """
    if not GOTIFY_TOKEN:
        logger.error("GOTIFY_TOKEN not set. Skipping notification.")
        return False

    url = f"{GOTIFY_URL}/message?token={GOTIFY_TOKEN}"

    try:
        result = subprocess.run(
            [
                "curl",
                "-X",
                "POST",
                url,
                "-F",
                f"title={title}",
                "-F",
                f"message={message}",
                "-F",
                f"priority={priority}",
                "-s",  # Silent mode
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0:
            logger.debug(f"Notification sent: {title}")
            return True
        else:
            logger.error(f"Failed to send notification: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error("Notification timed out")
        return False
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        return False


SATS_PER_BTC = 100_000_000


def format_satoshis(sats: int) -> str:
    """Format satoshis as BTC with appropriate precision."""
    btc = sats / SATS_PER_BTC
    return f"{btc:.8f} BTC ({sats:,} sats)"


def format_fee(fee: int, is_cost: bool = False) -> str:
    """Format fee with sign."""
    sign = "-" if is_cost else "+"
    return f"{sign}{abs(fee):,} sats"


def create_notification_message(entry: dict[str, str]) -> tuple[str, str, int]:
    """
    Create notification title and message from history entry.

    Args:
        entry: CSV row as dict

    Returns:
        Tuple of (title, message, priority)
    """
    role = entry.get("role", "unknown")
    success = entry.get("success", "True").lower() == "true"
    confirmations = int(entry.get("confirmations", 0) or 0)
    cj_amount = int(entry.get("cj_amount", 0) or 0)
    peer_count_str = entry.get("peer_count", "")
    peer_count = (
        int(peer_count_str)
        if peer_count_str and peer_count_str not in ("", "None")
        else None
    )
    net_fee = int(entry.get("net_fee", 0) or 0)

    # Determine title and priority based on status
    if not success and confirmations == 0:
        status = "Pending"
        priority = 4
        emoji = "⏳"
    elif confirmations == 0:
        status = "Broadcast"
        priority = 5
        emoji = "📡"
    elif confirmations == 1:
        status = "Confirmed"
        priority = 7
        emoji = "✅"
    elif confirmations >= 6:
        status = "Fully Confirmed"
        priority = 8
        emoji = "🎉"
    else:
        status = f"{confirmations} Confirmations"
        priority = 6
        emoji = "⏱️"

    # Role emoji
    role_emoji = "🎲" if role == "maker" else "🎯"

    title = f"{emoji} CoinJoin {status} ({role.capitalize()})"

    # Build message - exclude sensitive information (txid, network, peer nicks)
    message_parts = [
        f"{role_emoji} Role: {role.capitalize()}",
        f"💰 Amount: {format_satoshis(cj_amount)}",
    ]

    # Only show peer count if known (takers know, makers don't)
    if peer_count is not None:
        message_parts.append(f"👥 Peers: {peer_count}")

    message_parts.append(f"💸 Net Fee: {format_fee(net_fee, is_cost=net_fee < 0)}")

    # Add role-specific details
    if role == "maker":
        fee_received = int(entry.get("fee_received", 0) or 0)
        if fee_received > 0:
            message_parts.append(f"💵 Fee Earned: +{fee_received:,} sats")
    else:  # taker
        total_fees = int(entry.get("total_maker_fees_paid", 0) or 0)
        mining_fee = int(entry.get("mining_fee_paid", 0) or 0)
        if total_fees > 0:
            message_parts.append(f"💳 Maker Fees: -{total_fees:,} sats")
        if mining_fee > 0:
            message_parts.append(f"⛏️ Mining Fee: -{mining_fee:,} sats")

    message = "\n".join(message_parts)

    return title, message, priority


def should_notify(entry: dict[str, str], seen_entries: set[str]) -> bool:
    """
    Determine if we should send a notification for this entry.

    Args:
        entry: CSV row as dict
        seen_entries: Set of already seen entry identifiers

    Returns:
        True if notification should be sent
    """
    txid = entry.get("txid", "")
    timestamp = entry.get("timestamp", "")
    success = entry.get("success", "True").lower() == "true"
    confirmations = int(entry.get("confirmations", 0) or 0)

    # Create unique identifier for this entry state
    entry_id = f"{txid}:{timestamp}:{confirmations}"

    # Skip if already seen
    if entry_id in seen_entries:
        return False

    seen_entries.add(entry_id)

    # Check notification settings
    is_pending = not success and confirmations == 0
    is_confirmed = confirmations > 0

    if is_pending and not NOTIFY_ON_PENDING:
        return False

    if is_confirmed and not NOTIFY_ON_CONFIRMED:
        return False

    return True


def process_history_file(seen_entries: set[str]) -> None:
    """
    Process the history file and send notifications for new entries.

    Args:
        seen_entries: Set of already seen entry identifiers
    """
    if not HISTORY_FILE.exists():
        logger.debug(f"History file not found: {HISTORY_FILE}")
        return

    try:
        with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if should_notify(row, seen_entries):
                    title, message, priority = create_notification_message(row)
                    logger.info(f"Sending notification: {title}")
                    send_gotify_notification(title, message, priority)
    except Exception as e:
        logger.error(f"Error processing history file: {e}")


def watch_with_inotify_adapters(seen_entries: set[str]) -> None:
    """Watch using inotify.adapters library."""
    import inotify.adapters  # type: ignore

    logger.info("Watching for file changes (using inotify.adapters)...")
    i = inotify.adapters.Inotify()

    # Watch the parent directory for file creation/modification
    watch_path = str(HISTORY_FILE.parent)
    i.add_watch(watch_path)

    try:
        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            # Only process events for our specific file
            if filename != HISTORY_FILE.name:
                continue

            # Process on MODIFY, CLOSE_WRITE, or MOVED_TO events
            if any(
                t in type_names
                for t in ["IN_MODIFY", "IN_CLOSE_WRITE", "IN_MOVED_TO", "IN_CREATE"]
            ):
                logger.debug(f"File change detected: {type_names}")
                process_history_file(seen_entries)

    finally:
        i.remove_watch(watch_path)


def watch_with_pyinotify(seen_entries: set[str]) -> None:
    """Watch using pyinotify library."""
    import pyinotify  # type: ignore

    logger.info("Watching for file changes (using pyinotify)...")

    class EventHandler(pyinotify.ProcessEvent):  # type: ignore
        def process_IN_MODIFY(self, event: object) -> None:
            logger.debug("File modified")
            process_history_file(seen_entries)

        def process_IN_CLOSE_WRITE(self, event: object) -> None:
            logger.debug("File closed after write")
            process_history_file(seen_entries)

        def process_IN_MOVED_TO(self, event: object) -> None:
            logger.debug("File moved to watched location")
            process_history_file(seen_entries)

        def process_IN_CREATE(self, event: object) -> None:
            logger.debug("File created")
            process_history_file(seen_entries)

    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)

    # Watch the parent directory
    mask = (
        pyinotify.IN_MODIFY
        | pyinotify.IN_CLOSE_WRITE
        | pyinotify.IN_MOVED_TO
        | pyinotify.IN_CREATE
    )
    wm.add_watch(str(HISTORY_FILE.parent), mask)

    notifier.loop()


def watch_history_file() -> None:
    """
    Main daemon loop that watches the history file for changes using inotify.
    """
    logger.info("Starting CoinJoin notifier daemon")
    logger.info(f"Watching: {HISTORY_FILE}")
    logger.info(f"Gotify: {GOTIFY_URL}")
    logger.info(f"Notify on pending: {NOTIFY_ON_PENDING}")
    logger.info(f"Notify on confirmed: {NOTIFY_ON_CONFIRMED}")

    if not GOTIFY_TOKEN:
        logger.warning("GOTIFY_TOKEN not set - notifications will be skipped!")
        logger.warning("Set it with: export GOTIFY_TOKEN='your-token-here'")

    seen_entries: set[str] = set()

    # Ensure parent directory exists
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Initial scan - populate seen_entries without notifying
    if HISTORY_FILE.exists():
        logger.info("Initial scan of history file...")
        try:
            with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    txid = row.get("txid", "")
                    timestamp = row.get("timestamp", "")
                    confirmations = int(row.get("confirmations", 0) or 0)
                    entry_id = f"{txid}:{timestamp}:{confirmations}"
                    seen_entries.add(entry_id)
            logger.info(f"Found {len(seen_entries)} existing entries")
        except Exception as e:
            logger.error(f"Error during initial scan: {e}")
    else:
        logger.info("History file does not exist yet, waiting for creation...")

    # Watch for file changes using appropriate inotify implementation
    try:
        # Try to import inotify at runtime
        try:
            import inotify.adapters  # type: ignore  # noqa: F401

            watch_with_inotify_adapters(seen_entries)
        except ImportError:
            try:
                import pyinotify  # type: ignore  # noqa: F401

                watch_with_pyinotify(seen_entries)
            except ImportError:
                logger.error("ERROR: inotify support required. Install with one of:")
                logger.error("  pip install inotify")
                logger.error("  pip install pyinotify")
                sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Error in watch loop: {e}")


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor CoinJoin history and send Gotify notifications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  HISTORY_FILE          Path to coinjoin_history.csv (default: ~/.joinmarket/coinjoin_history.csv)
  GOTIFY_URL            Gotify server URL (default: https://gotify.example.com)
  GOTIFY_TOKEN          Gotify app token (required)
  NOTIFY_ON_PENDING     Notify on pending transactions (default: true)
  NOTIFY_ON_CONFIRMED   Notify on confirmed transactions (default: true)

Example:
  export GOTIFY_TOKEN="A-72bLc7ONO6mG6"
  export HISTORY_FILE="/data/joinmarket-ng/coinjoin_history.csv"
  python3 coinjoin_notifier.py
        """,
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check if GOTIFY_TOKEN is set
    if not GOTIFY_TOKEN:
        logger.error("GOTIFY_TOKEN environment variable is not set!")
        logger.error("Set it with: export GOTIFY_TOKEN='your-token-here'")
        logger.error("The daemon will start but notifications will be skipped.")
        logger.error("")

    watch_history_file()


if __name__ == "__main__":
    main()
