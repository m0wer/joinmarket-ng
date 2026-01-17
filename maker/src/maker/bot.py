"""
Main maker bot implementation.

Coordinates all maker components:
- Wallet synchronization
- Directory server connections
- Offer creation and announcement
- CoinJoin protocol handling
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from jmcore.commitment_blacklist import add_commitment, check_commitment, set_blacklist_path
from jmcore.crypto import NickIdentity
from jmcore.deduplication import MessageDeduplicator
from jmcore.directory_client import DirectoryClient, DirectoryClientError
from jmcore.models import Offer
from jmcore.network import HiddenServiceListener, TCPConnection
from jmcore.notifications import get_notifier
from jmcore.protocol import (
    COMMAND_PREFIX,
    FEATURE_NEUTRINO_COMPAT,
    FEATURE_PEERLIST_FEATURES,
    JM_VERSION,
    FeatureSet,
    MessageType,
    create_handshake_response,
)
from jmcore.rate_limiter import RateLimiter
from jmcore.tor_control import (
    EphemeralHiddenService,
    TorControlClient,
    TorControlError,
)
from jmwallet.backends.base import BlockchainBackend
from jmwallet.history import (
    append_history_entry,
    create_maker_history_entry,
)
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.coinjoin import CoinJoinSession
from maker.config import MakerConfig
from maker.fidelity import (
    FidelityBondInfo,
    create_fidelity_bond_proof,
    find_fidelity_bonds,
    get_best_fidelity_bond,
)
from maker.offers import OfferManager

# Default hostid for onion network (matches reference implementation)
DEFAULT_HOSTID = "onion-network"

# Rate limiting defaults for orderbook requests
# These protect against spam attacks that can flood logs and exhaust resources
DEFAULT_ORDERBOOK_RATE_LIMIT = 1  # Max orderbook responses per peer per interval
DEFAULT_ORDERBOOK_RATE_INTERVAL = 10.0  # Interval in seconds (10s = 6 req/min)

# Violation thresholds for exponential backoff and banning
DEFAULT_VIOLATION_BAN_THRESHOLD = 100  # Ban peer after this many violations
DEFAULT_VIOLATION_WARNING_THRESHOLD = 10  # Start exponential backoff after this
DEFAULT_VIOLATION_SEVERE_THRESHOLD = 50  # Severe backoff threshold
DEFAULT_BAN_DURATION = 3600.0  # Ban duration in seconds (1 hour)


class OrderbookRateLimiter:
    """
    Per-peer rate limiter for orderbook requests with exponential backoff and banning.

    Prevents DoS attacks by limiting how often each peer can request the orderbook.
    Uses a timestamp-based approach with escalating penalties:

    1. Normal operation: 1 response per interval (default 10s)
    2. After 10 violations: Exponential backoff starts (60s interval)
    3. After 50 violations: Severe backoff (300s = 5min interval)
    4. After 100 violations: Permanent ban until cleanup/restart

    This is crucial because:
    1. !orderbook responses include fidelity bond proofs which are expensive to compute
    2. Unlimited responses can flood log files
    3. A bad actor can exhaust maker resources by spamming requests
    """

    def __init__(
        self,
        rate_limit: int = DEFAULT_ORDERBOOK_RATE_LIMIT,
        interval: float = DEFAULT_ORDERBOOK_RATE_INTERVAL,
        violation_ban_threshold: int = DEFAULT_VIOLATION_BAN_THRESHOLD,
        violation_warning_threshold: int = DEFAULT_VIOLATION_WARNING_THRESHOLD,
        violation_severe_threshold: int = DEFAULT_VIOLATION_SEVERE_THRESHOLD,
        ban_duration: float = DEFAULT_BAN_DURATION,
    ):
        """
        Initialize the rate limiter.

        Args:
            rate_limit: Maximum number of responses per interval (currently unused,
                       always 1 response per interval for simplicity)
            interval: Base time window in seconds
            violation_ban_threshold: Ban peer after this many violations
            violation_warning_threshold: Start exponential backoff after this
            violation_severe_threshold: Severe backoff threshold
            ban_duration: How long to ban peers (seconds)
        """
        self.interval = interval
        self.violation_ban_threshold = violation_ban_threshold
        self.violation_warning_threshold = violation_warning_threshold
        self.violation_severe_threshold = violation_severe_threshold
        self.ban_duration = ban_duration

        self._last_response: dict[str, float] = {}
        self._violation_counts: dict[str, int] = {}
        self._banned_peers: dict[str, float] = {}  # peer_nick -> ban_timestamp

    def check(self, peer_nick: str) -> bool:
        """
        Check if we should respond to an orderbook request from this peer.

        Returns True if allowed, False if rate limited or banned.
        """
        now = time.monotonic()

        # Check if peer is banned
        if peer_nick in self._banned_peers:
            ban_time = self._banned_peers[peer_nick]
            if now - ban_time < self.ban_duration:
                # Still banned, increment violation count
                self._violation_counts[peer_nick] = self._violation_counts.get(peer_nick, 0) + 1
                return False
            else:
                # Ban expired, reset state completely
                del self._banned_peers[peer_nick]
                self._violation_counts[peer_nick] = 0
                # Reset last response time so they can immediately get a response
                self._last_response[peer_nick] = 0.0

        violations = self._violation_counts.get(peer_nick, 0)

        # Check if peer should be banned based on violations
        if violations >= self.violation_ban_threshold:
            self._banned_peers[peer_nick] = now
            logger.warning(
                f"BANNED peer {peer_nick} for {self.ban_duration}s "
                f"after {violations} rate limit violations"
            )
            return False

        # Calculate effective interval with exponential backoff
        effective_interval = self._get_effective_interval(violations)

        last = self._last_response.get(peer_nick, 0.0)

        if now - last >= effective_interval:
            self._last_response[peer_nick] = now
            return True

        # Rate limited
        self._violation_counts[peer_nick] = violations + 1
        return False

    def _get_effective_interval(self, violations: int) -> float:
        """
        Calculate effective rate limit interval based on violation count.

        Implements exponential backoff:
        - 0-10 violations: base interval (10s)
        - 11-50 violations: 6x base interval (60s)
        - 51-99 violations: 30x base interval (300s = 5min)
        - 100+ violations: banned (handled separately)

        Args:
            violations: Number of violations for this peer

        Returns:
            Effective interval in seconds
        """
        if violations < self.violation_warning_threshold:
            return self.interval
        elif violations < self.violation_severe_threshold:
            # Moderate backoff: 6x base interval
            return self.interval * 6
        else:
            # Severe backoff: 30x base interval
            return self.interval * 30

    def get_violation_count(self, peer_nick: str) -> int:
        """Get the number of rate limit violations for a peer."""
        return self._violation_counts.get(peer_nick, 0)

    def is_banned(self, peer_nick: str) -> bool:
        """Check if a peer is currently banned."""
        if peer_nick not in self._banned_peers:
            return False

        now = time.monotonic()
        ban_time = self._banned_peers[peer_nick]
        if now - ban_time < self.ban_duration:
            return True

        # Ban expired, clean up and reset violations
        del self._banned_peers[peer_nick]
        self._violation_counts[peer_nick] = 0
        self._last_response[peer_nick] = 0.0
        return False

    def cleanup_old_entries(self, max_age: float = 3600.0) -> None:
        """Remove entries older than max_age to prevent memory growth."""
        now = time.monotonic()

        # Clean up old responses
        stale_peers = [peer for peer, last in self._last_response.items() if now - last > max_age]
        for peer in stale_peers:
            del self._last_response[peer]
            # Don't reset violation counts for stale peers - preserve ban history
            # Only reset if they're not banned
            if peer not in self._banned_peers:
                self._violation_counts.pop(peer, None)

        # Clean up expired bans
        expired_bans = [
            peer
            for peer, ban_time in self._banned_peers.items()
            if now - ban_time > self.ban_duration
        ]
        for peer in expired_bans:
            del self._banned_peers[peer]
            self._violation_counts[peer] = 0  # Reset violations after ban expires

    def get_statistics(self) -> dict[str, Any]:
        """
        Get rate limiter statistics for monitoring.

        Returns:
            Dict with keys:
                - total_violations: Total violation count across all peers
                - tracked_peers: Number of peers being tracked
                - banned_peers: List of currently banned peer nicks
                - top_violators: List of (nick, violations) tuples, top 10
        """
        now = time.monotonic()

        # Get currently banned peers (check for expired bans)
        banned = [
            nick
            for nick, ban_time in self._banned_peers.items()
            if now - ban_time < self.ban_duration
        ]

        # Get top violators (sorted by violation count)
        top_violators = sorted(
            [(nick, count) for nick, count in self._violation_counts.items() if count > 0],
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "total_violations": sum(self._violation_counts.values()),
            "tracked_peers": len(self._last_response),
            "banned_peers": banned,
            "top_violators": top_violators,
        }


class MakerBot:
    """
    Main maker bot coordinating all components.
    """

    def __init__(
        self,
        wallet: WalletService,
        backend: BlockchainBackend,
        config: MakerConfig,
    ):
        self.wallet = wallet
        self.backend = backend
        self.config = config

        # Create nick identity for signing messages
        self.nick_identity = NickIdentity(JM_VERSION)
        self.nick = self.nick_identity.nick

        self.offer_manager = OfferManager(self.wallet, config, self.nick)

        self.directory_clients: dict[str, DirectoryClient] = {}
        self.active_sessions: dict[str, CoinJoinSession] = {}
        self.current_offers: list[Offer] = []
        self.fidelity_bond: FidelityBondInfo | None = None
        self.current_block_height: int = 0  # Cached block height for bond proof generation

        self.running = False
        self.listen_tasks: list[asyncio.Task[None]] = []

        # Lock to prevent concurrent processing of the same session
        # Key: taker_nick, Value: asyncio.Lock
        # This prevents race conditions when duplicate messages arrive via multiple
        # directory servers or direct connections
        self._session_locks: dict[str, asyncio.Lock] = {}

        # Hidden service listener for direct peer connections
        self.hidden_service_listener: HiddenServiceListener | None = None
        self.direct_connections: dict[str, TCPConnection] = {}

        # Tor control for dynamic hidden service creation
        self._tor_control: TorControlClient | None = None
        self._ephemeral_hidden_service: EphemeralHiddenService | None = None

        # Generic per-peer rate limiter (token bucket algorithm)
        # Generous burst (100 msgs) but low sustained rate (10 msg/s)
        self._message_rate_limiter = RateLimiter(
            rate_limit=config.message_rate_limit,
            burst_limit=config.message_burst_limit,
        )

        # Rate limiter for orderbook requests to prevent spam attacks
        self._orderbook_rate_limiter = OrderbookRateLimiter(
            rate_limit=config.orderbook_rate_limit,
            interval=config.orderbook_rate_interval,
            violation_ban_threshold=config.orderbook_violation_ban_threshold,
            violation_warning_threshold=config.orderbook_violation_warning_threshold,
            violation_severe_threshold=config.orderbook_violation_severe_threshold,
            ban_duration=config.orderbook_ban_duration,
        )

        # Message deduplicator to handle receiving same message from multiple directories
        # This prevents processing duplicates and avoids false rate limit violations
        self._message_deduplicator = MessageDeduplicator(window_seconds=30.0)

        # Track failed directory reconnection attempts
        # Key: node_id (host:port), Value: number of reconnection attempts
        self._directory_reconnect_attempts: dict[str, int] = {}

    async def _setup_tor_hidden_service(self) -> str | None:
        """
        Create an ephemeral hidden service via Tor control port.

        Returns:
            The .onion address if successful, None otherwise
        """
        if not self.config.tor_control.enabled:
            logger.debug("Tor control port integration disabled")
            return None

        try:
            logger.info(
                f"Connecting to Tor control port at "
                f"{self.config.tor_control.host}:{self.config.tor_control.port}..."
            )

            self._tor_control = TorControlClient(
                control_host=self.config.tor_control.host,
                control_port=self.config.tor_control.port,
                cookie_path=self.config.tor_control.cookie_path,
                password=self.config.tor_control.password.get_secret_value()
                if self.config.tor_control.password
                else None,
            )

            await self._tor_control.connect()
            await self._tor_control.authenticate()

            # Get Tor version for logging
            try:
                tor_version = await self._tor_control.get_version()
                logger.info(f"Connected to Tor {tor_version}")
            except TorControlError:
                logger.debug("Could not get Tor version (non-critical)")

            # Create ephemeral hidden service
            # Maps external port (advertised) to our local serving port
            logger.info(
                f"Creating ephemeral hidden service on port {self.config.onion_serving_port} -> "
                f"{self.config.tor_target_host}:{self.config.onion_serving_port}..."
            )

            self._ephemeral_hidden_service = (
                await self._tor_control.create_ephemeral_hidden_service(
                    ports=[
                        (
                            self.config.onion_serving_port,
                            f"{self.config.tor_target_host}:{self.config.onion_serving_port}",
                        )
                    ],
                    # Don't discard private key in case we want to log it for debugging
                    discard_pk=True,
                    # Don't detach - we want the service to be removed when we disconnect
                    detach=False,
                )
            )

            logger.info(
                f"✓ Created ephemeral hidden service: "
                f"{self._ephemeral_hidden_service.onion_address}"
            )
            return self._ephemeral_hidden_service.onion_address

        except TorControlError as e:
            logger.warning(
                f"Could not create ephemeral hidden service via Tor control port: {e}\n"
                f"  Tor control configured: "
                f"{self.config.tor_control.host}:{self.config.tor_control.port}\n"
                f"  Cookie path: {self.config.tor_control.cookie_path}\n"
                f"  → Maker will advertise 'NOT-SERVING-ONION' and rely on directory routing.\n"
                f"  → For better privacy, ensure Tor is running with control port enabled:\n"
                f"     ControlPort {self.config.tor_control.port}\n"
                f"     CookieAuthentication 1"
            )
            # Clean up partial connection
            if self._tor_control:
                await self._tor_control.close()
                self._tor_control = None
            return None

    async def _cleanup_tor_hidden_service(self) -> None:
        """Clean up Tor control connection (hidden service is auto-removed)."""
        if self._tor_control:
            try:
                await self._tor_control.close()
                logger.debug("Closed Tor control connection")
            except Exception as e:
                logger.warning(f"Error closing Tor control connection: {e}")
            self._tor_control = None
            self._ephemeral_hidden_service = None

    async def _regenerate_nick(self) -> None:
        """
        Regenerate nick identity for privacy (currently disabled).

        Nick regeneration is disabled because:
        1. Reference implementation doesn't regenerate nicks after CoinJoin
        2. Fidelity bond makers need stable identity for reputation
        3. Causes timing issues with !push (taker waits ~60s to collect signatures)
        4. Privacy is maintained through Tor hidden services

        Future consideration: Could be re-enabled as opt-in feature with grace period.
        """
        pass

    async def start(self) -> None:
        """
        Start the maker bot.

        Flow:
        1. Initialize commitment blacklist
        2. Sync wallet with blockchain
        3. Create ephemeral hidden service if tor_control enabled
        4. Connect to directory servers
        5. Create and announce offers
        6. Listen for taker requests
        """
        try:
            logger.info(f"Starting maker bot (nick: {self.nick})")

            # Initialize commitment blacklist with configured data directory
            set_blacklist_path(data_dir=self.config.data_dir)

            # Load fidelity bond addresses for optimized scanning
            # We scan wallet + fidelity bonds in a single pass to avoid two separate
            # scantxoutset calls (which take ~90s each on mainnet)
            from jmcore.paths import get_default_data_dir
            from jmwallet.wallet.bond_registry import load_registry

            resolved_data_dir = (
                self.config.data_dir if self.config.data_dir else get_default_data_dir()
            )
            fidelity_bond_addresses: list[tuple[str, int, int]] = []

            # Option 1: Manual specification via fidelity_bond_index + locktimes (bypasses registry)
            # This is useful when running in Docker or when you don't have a registry yet
            if self.config.fidelity_bond_index is not None and self.config.fidelity_bond_locktimes:
                logger.info(
                    f"Using manual fidelity bond specification: "
                    f"index={self.config.fidelity_bond_index}, "
                    f"locktimes={self.config.fidelity_bond_locktimes}"
                )
                for locktime in self.config.fidelity_bond_locktimes:
                    address = self.wallet.get_fidelity_bond_address(
                        self.config.fidelity_bond_index, locktime
                    )
                    fidelity_bond_addresses.append(
                        (address, locktime, self.config.fidelity_bond_index)
                    )
                    logger.info(
                        f"Generated fidelity bond address for locktime {locktime}: {address}"
                    )
            # Option 2: Load from registry (default)
            else:
                bond_registry = load_registry(resolved_data_dir)
                if bond_registry.bonds:
                    # Extract (address, locktime, index) tuples from registry
                    fidelity_bond_addresses = [
                        (bond.address, bond.locktime, bond.index) for bond in bond_registry.bonds
                    ]
                    logger.info(
                        f"Loaded {len(fidelity_bond_addresses)} "
                        f"fidelity bond address(es) from registry"
                    )

            logger.info("Syncing wallet and fidelity bonds...")

            # Setup descriptor wallet if needed (one-time operation)
            from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

            if isinstance(self.backend, DescriptorWalletBackend):
                # Check if base wallet is set up (without counting bonds)
                base_wallet_ready = await self.wallet.is_descriptor_wallet_ready(
                    fidelity_bond_count=0
                )
                # Check if wallet with bonds is set up
                full_wallet_ready = await self.wallet.is_descriptor_wallet_ready(
                    fidelity_bond_count=len(fidelity_bond_addresses)
                )

                if not base_wallet_ready:
                    # First time setup - import everything including bonds
                    logger.info("Descriptor wallet not set up. Importing descriptors...")
                    await self.wallet.setup_descriptor_wallet(
                        rescan=True,
                        fidelity_bond_addresses=fidelity_bond_addresses,
                    )
                    logger.info("Descriptor wallet setup complete")
                elif not full_wallet_ready and fidelity_bond_addresses:
                    # Base wallet exists but bonds are missing - import just the bonds
                    logger.info(
                        "Descriptor wallet exists but fidelity bond addresses not imported. "
                        "Importing bond addresses..."
                    )
                    await self.wallet.import_fidelity_bond_addresses(
                        fidelity_bond_addresses, rescan=True
                    )

                # Use fast descriptor wallet sync
                await self.wallet.sync_with_descriptor_wallet(fidelity_bond_addresses)
            else:
                # Use standard sync (scantxoutset for scantxoutset, BIP157/158 for neutrino)
                await self.wallet.sync_all(fidelity_bond_addresses)

            # Update bond registry with UTXO info from the scan (only if using registry)
            if self.config.fidelity_bond_index is None and fidelity_bond_addresses:
                from jmwallet.wallet.bond_registry import save_registry

                bond_registry = load_registry(resolved_data_dir)
                for bond in bond_registry.bonds:
                    # Find the UTXO for this bond address in mixdepth 0
                    bond_utxo = next(
                        (
                            utxo
                            for utxo in self.wallet.utxo_cache.get(0, [])
                            if utxo.address == bond.address
                        ),
                        None,
                    )
                    if bond_utxo:
                        # Update the bond registry with UTXO info
                        bond.txid = bond_utxo.txid
                        bond.vout = bond_utxo.vout
                        bond.value = bond_utxo.value
                        bond.confirmations = bond_utxo.confirmations
                        logger.debug(
                            f"Updated bond {bond.address[:20]}... with UTXO "
                            f"{bond_utxo.txid[:16]}...:{bond_utxo.vout}, value={bond_utxo.value}"
                        )

                # Save updated registry
                save_registry(bond_registry, resolved_data_dir)

            # Get current block height for bond proof generation
            self.current_block_height = await self.backend.get_block_height()
            logger.debug(f"Current block height: {self.current_block_height}")

            total_balance = await self.wallet.get_total_balance()
            logger.info(f"Wallet synced. Total balance: {total_balance:,} sats")

            # Find fidelity bond for proof generation
            # If a specific bond is selected in config, use it; otherwise use the best one
            if self.config.selected_fidelity_bond:
                # User specified a specific bond
                sel_txid, sel_vout = self.config.selected_fidelity_bond
                bonds = await find_fidelity_bonds(self.wallet)
                self.fidelity_bond = next(
                    (b for b in bonds if b.txid == sel_txid and b.vout == sel_vout), None
                )
                if self.fidelity_bond:
                    logger.info(
                        f"Using selected fidelity bond: {sel_txid[:16]}...:{sel_vout}, "
                        f"value={self.fidelity_bond.value:,} sats, "
                        f"bond_value={self.fidelity_bond.bond_value:,}"
                    )
                else:
                    logger.warning(
                        f"Selected fidelity bond {sel_txid[:16]}...:{sel_vout} not found, "
                        "falling back to best available"
                    )
                    self.fidelity_bond = await get_best_fidelity_bond(self.wallet)
            else:
                # Auto-select the best (largest bond value) fidelity bond
                self.fidelity_bond = await get_best_fidelity_bond(self.wallet)
            if self.fidelity_bond:
                logger.info(
                    f"Fidelity bond found: {self.fidelity_bond.txid[:16]}..., "
                    f"value={self.fidelity_bond.value:,} sats, "
                    f"bond_value={self.fidelity_bond.bond_value:,}"
                )
            else:
                logger.info("No fidelity bond found (offers will have no bond proof)")

            logger.info("Creating offers...")
            self.current_offers = await self.offer_manager.create_offers()

            # If no offers due to insufficient balance, wait and retry
            retry_count = 0
            max_retries = 30  # 5 minutes max wait (30 * 10s)
            while not self.current_offers and retry_count < max_retries:
                retry_count += 1
                logger.warning(
                    f"No offers created (insufficient balance?). "
                    f"Waiting 10s and retrying... (attempt {retry_count}/{max_retries})"
                )
                await asyncio.sleep(10)

                # Re-sync wallet to check for new funds
                from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

                if isinstance(self.backend, DescriptorWalletBackend):
                    await self.wallet.sync_with_descriptor_wallet()
                else:
                    await self.wallet.sync_all()
                total_balance = await self.wallet.get_total_balance()
                logger.info(f"Wallet re-synced. Total balance: {total_balance:,} sats")

                self.current_offers = await self.offer_manager.create_offers()

            if not self.current_offers:
                logger.error(
                    f"No offers created after {max_retries} retries. "
                    "Please fund the wallet and restart."
                )
                return

            # Set up ephemeral hidden service via Tor control port if enabled
            # This must happen before connecting to directory servers so we can
            # advertise the onion address
            ephemeral_onion = await self._setup_tor_hidden_service()
            if ephemeral_onion:
                # Override onion_host with the dynamically created one
                object.__setattr__(self.config, "onion_host", ephemeral_onion)
                logger.info(f"Using ephemeral onion address: {ephemeral_onion}")

            # Determine the onion address to advertise
            onion_host = self.config.onion_host

            logger.info("Connecting to directory servers...")
            for dir_server in self.config.directory_servers:
                try:
                    parts = dir_server.split(":")
                    host = parts[0]
                    port = int(parts[1]) if len(parts) > 1 else 5222

                    # Determine location for handshake:
                    # If we have an onion_host configured (static or ephemeral),
                    # advertise it with port
                    # Otherwise, use NOT-SERVING-ONION
                    if onion_host:
                        location = f"{onion_host}:{self.config.onion_serving_port}"
                    else:
                        location = "NOT-SERVING-ONION"

                    # Advertise neutrino_compat if our backend can provide extended UTXO metadata.
                    # This tells Neutrino takers that we can provide scriptpubkey and blockheight.
                    # Full nodes (Bitcoin Core) can provide this; light clients (Neutrino) cannot.
                    neutrino_compat = self.backend.can_provide_neutrino_metadata()

                    # Create DirectoryClient with SOCKS config for Tor connections
                    client = DirectoryClient(
                        host=host,
                        port=port,
                        network=self.config.network.value,
                        nick_identity=self.nick_identity,
                        location=location,
                        socks_host=self.config.socks_host,
                        socks_port=self.config.socks_port,
                        neutrino_compat=neutrino_compat,
                    )

                    await client.connect()
                    node_id = f"{host}:{port}"
                    self.directory_clients[node_id] = client

                    logger.info(f"Connected to directory: {dir_server}")

                except Exception as e:
                    logger.error(f"Failed to connect to {dir_server}: {e}")

            if not self.directory_clients:
                logger.error("Failed to connect to any directory server")
                return

            # Start hidden service listener if we have an onion address (static or ephemeral)
            if onion_host:
                logger.info(
                    f"Starting hidden service listener on "
                    f"{self.config.onion_serving_host}:{self.config.onion_serving_port}..."
                )
                self.hidden_service_listener = HiddenServiceListener(
                    host=self.config.onion_serving_host,
                    port=self.config.onion_serving_port,
                    on_connection=self._on_direct_connection,
                )
                await self.hidden_service_listener.start()
                logger.info(f"Hidden service listener started (onion: {onion_host})")

            logger.info("Announcing offers...")
            await self._announce_offers()

            logger.info("Maker bot started. Listening for takers...")
            self.running = True

            # Start listening on all directory clients
            for node_id, client in self.directory_clients.items():
                task = asyncio.create_task(self._listen_client(node_id, client))
                self.listen_tasks.append(task)

            # If hidden service listener is running, start serve_forever task
            if self.hidden_service_listener:
                task = asyncio.create_task(self.hidden_service_listener.serve_forever())
                self.listen_tasks.append(task)

            # Start background task to monitor pending transactions
            monitor_task = asyncio.create_task(self._monitor_pending_transactions())
            self.listen_tasks.append(monitor_task)

            # Start periodic wallet rescan task
            rescan_task = asyncio.create_task(self._periodic_rescan())
            self.listen_tasks.append(rescan_task)

            # Start periodic rate limit status logging task
            status_task = asyncio.create_task(self._periodic_rate_limit_status())
            self.listen_tasks.append(status_task)

            # Start periodic directory connection status logging task
            conn_status_task = asyncio.create_task(self._periodic_directory_connection_status())
            self.listen_tasks.append(conn_status_task)

            # Start periodic directory reconnection task
            reconnect_task = asyncio.create_task(self._periodic_directory_reconnect())
            self.listen_tasks.append(reconnect_task)

            # Wait for all listening tasks to complete
            await asyncio.gather(*self.listen_tasks, return_exceptions=True)

        except Exception as e:
            logger.error(f"Failed to start maker bot: {e}")
            raise

    async def stop(self) -> None:
        """Stop the maker bot"""
        logger.info("Stopping maker bot...")
        self.running = False

        # Cancel all listening tasks
        for task in self.listen_tasks:
            task.cancel()

        if self.listen_tasks:
            await asyncio.gather(*self.listen_tasks, return_exceptions=True)

        # Stop hidden service listener
        if self.hidden_service_listener:
            await self.hidden_service_listener.stop()

        # Clean up Tor control connection (ephemeral hidden service auto-removed)
        await self._cleanup_tor_hidden_service()

        # Close all direct connections
        for conn in self.direct_connections.values():
            try:
                await conn.close()
            except Exception:
                pass
        self.direct_connections.clear()

        # Close all directory clients
        for client in self.directory_clients.values():
            try:
                await client.close()
            except Exception:
                pass

        await self.wallet.close()
        logger.info("Maker bot stopped")

    def _get_session_lock(self, taker_nick: str) -> asyncio.Lock:
        """Get or create a lock for a session to prevent concurrent processing."""
        if taker_nick not in self._session_locks:
            self._session_locks[taker_nick] = asyncio.Lock()
        return self._session_locks[taker_nick]

    def _cleanup_session_lock(self, taker_nick: str) -> None:
        """Clean up session lock when session is removed."""
        self._session_locks.pop(taker_nick, None)

    def _cleanup_timed_out_sessions(self) -> None:
        """Remove timed-out sessions from active_sessions and clean up rate limiter."""
        timed_out = [
            nick for nick, session in self.active_sessions.items() if session.is_timed_out()
        ]

        for nick in timed_out:
            session = self.active_sessions[nick]
            age = int(asyncio.get_event_loop().time() - session.created_at)
            logger.warning(
                f"Cleaning up timed-out session with {nick} (state: {session.state}, age: {age}s)"
            )
            del self.active_sessions[nick]
            self._cleanup_session_lock(nick)

        # Periodically cleanup old rate limiter entries to prevent memory growth
        self._orderbook_rate_limiter.cleanup_old_entries()

    async def _resync_wallet_and_update_offers(self) -> None:
        """Re-sync wallet and update offers if balance changed.

        This is the core rescan logic used by both post-CoinJoin resync
        and periodic rescan. It:
        1. Saves the current max balance
        2. Re-syncs the wallet
        3. If max balance changed, recreates and re-announces offers
        """
        # Get current max balance before resync
        old_max_balance = 0
        for mixdepth in range(self.wallet.mixdepth_count):
            balance = await self.wallet.get_balance(mixdepth)
            old_max_balance = max(old_max_balance, balance)

        # Sync wallet (use descriptor wallet if available for fast sync)
        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

        if isinstance(self.backend, DescriptorWalletBackend):
            await self.wallet.sync_with_descriptor_wallet()
        else:
            await self.wallet.sync_all()

        # Update current block height
        self.current_block_height = await self.backend.get_block_height()
        logger.debug(f"Updated block height: {self.current_block_height}")

        # Update pending history immediately after sync (in case of restart)
        await self._update_pending_history()

        # Get new max balance after resync
        new_max_balance = 0
        for mixdepth in range(self.wallet.mixdepth_count):
            balance = await self.wallet.get_balance(mixdepth)
            new_max_balance = max(new_max_balance, balance)

        total_balance = await self.wallet.get_total_balance()
        logger.info(f"Wallet re-synced. Total balance: {total_balance:,} sats")

        # If max balance changed, update offers
        if old_max_balance != new_max_balance:
            logger.info(
                f"Max balance changed: {old_max_balance:,} -> {new_max_balance:,} sats. "
                "Updating offers..."
            )
            await self._update_offers()
        else:
            logger.debug(f"Max balance unchanged at {new_max_balance:,} sats")

    async def _update_offers(self) -> None:
        """Recreate and re-announce offers based on current wallet state.

        Called when wallet balance changes (after CoinJoin, external transaction,
        or deposit). This allows the maker to adapt to changing balances without
        requiring a restart.
        """
        try:
            new_offers = await self.offer_manager.create_offers()

            if not new_offers:
                logger.warning(
                    "No offers could be created (insufficient balance?). "
                    "Keeping existing offers active."
                )
                return

            # Check if offers actually changed (compare maxsize for each offer by ID)
            offers_changed = False
            if self.current_offers and new_offers:
                # Build lookup by offer ID for comparison
                old_offers_by_id = {o.oid: o for o in self.current_offers}
                new_offers_by_id = {o.oid: o for o in new_offers}

                # Check if offer count changed
                if set(old_offers_by_id.keys()) != set(new_offers_by_id.keys()):
                    offers_changed = True
                else:
                    # Check if any offer's maxsize changed
                    for oid, new_offer in new_offers_by_id.items():
                        old_offer = old_offers_by_id.get(oid)
                        if old_offer is None or old_offer.maxsize != new_offer.maxsize:
                            offers_changed = True
                            break

                if not offers_changed:
                    logger.debug("Offer maxsizes unchanged, skipping re-announcement")
                    return
            else:
                offers_changed = True  # First time or recovering from no offers

            # Regenerate nick when offers change for additional privacy
            # This makes it harder for observers to track maker activity over time
            await self._regenerate_nick()

            # Update offers with new nick (OfferManager.maker_nick was updated by _regenerate_nick)
            for offer in new_offers:
                offer.counterparty = self.nick

            self.current_offers = new_offers
            await self._announce_offers()
            offer_summary = ", ".join(f"oid={o.oid}:{o.maxsize:,}" for o in new_offers)
            logger.info(f"Updated and re-announced {len(new_offers)} offer(s): {offer_summary}")
        except Exception as e:
            logger.error(f"Failed to update offers: {e}")

    async def _periodic_rescan(self) -> None:
        """Background task to periodically rescan wallet and update offers.

        This runs every `rescan_interval_sec` (default: 10 minutes) to:
        1. Detect external transactions (deposits, Sparrow spends, etc.)
        2. Update pending transaction confirmations
        3. Update offers if balance changed

        This allows the maker to run in the background and adapt to balance
        changes without manual intervention.
        """
        logger.info(
            f"Starting periodic rescan task (interval: {self.config.rescan_interval_sec}s)..."
        )

        while self.running:
            try:
                await asyncio.sleep(self.config.rescan_interval_sec)

                if not self.running:
                    break

                logger.info("Periodic wallet rescan starting...")
                await self._resync_wallet_and_update_offers()

            except asyncio.CancelledError:
                logger.info("Periodic rescan task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic rescan: {e}")

        logger.info("Periodic rescan task stopped")

    async def _periodic_rate_limit_status(self) -> None:
        """Background task to periodically log rate limiting statistics.

        This runs every hour to provide visibility into spam/abuse without
        flooding logs. Shows:
        - Total violations across all peers
        - Currently banned peers
        - Top violators (by violation count)
        """
        # First log after 10 minutes (give time for initial activity)
        await asyncio.sleep(600)

        while self.running:
            try:
                stats = self._orderbook_rate_limiter.get_statistics()

                # Only log if there's activity worth reporting
                if stats["total_violations"] > 0 or stats["banned_peers"]:
                    banned_count = len(stats["banned_peers"])
                    banned_list = ", ".join(stats["banned_peers"][:5])
                    if banned_count > 5:
                        banned_list += f", ... and {banned_count - 5} more"

                    top_violators_str = ", ".join(
                        f"{nick}({count})" for nick, count in stats["top_violators"][:5]
                    )

                    logger.info(
                        f"Rate limit status: {stats['total_violations']} total violations, "
                        f"{banned_count} banned peer(s)"
                        + (f" [{banned_list}]" if banned_count > 0 else "")
                        + (
                            f", top violators: {top_violators_str}"
                            if stats["top_violators"]
                            else ""
                        )
                    )

                # Log again in 1 hour
                await asyncio.sleep(3600)

            except asyncio.CancelledError:
                logger.info("Rate limit status task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in rate limit status task: {e}")
                await asyncio.sleep(3600)

        logger.info("Rate limit status task stopped")

    async def _periodic_directory_connection_status(self) -> None:
        """Background task to periodically log directory connection status.

        This runs every 10 minutes to provide visibility into orderbook
        connectivity. Shows:
        - Total directory servers configured
        - Currently connected servers
        - Disconnected servers (if any)
        """
        # First log after 5 minutes (give time for initial connection)
        await asyncio.sleep(300)

        while self.running:
            try:
                total_servers = len(self.config.directory_servers)
                connected_servers = list(self.directory_clients.keys())
                connected_count = len(connected_servers)
                disconnected_servers = [
                    server
                    for server in self.config.directory_servers
                    if f"{server.split(':')[0]}:{server.split(':')[1] if ':' in server else '5222'}"
                    not in connected_servers
                ]

                if disconnected_servers:
                    disconnected_str = ", ".join(disconnected_servers[:5])
                    if len(disconnected_servers) > 5:
                        disconnected_str += f", ... and {len(disconnected_servers) - 5} more"
                    logger.warning(
                        f"Directory connection status: {connected_count}/{total_servers} "
                        f"connected. Disconnected: [{disconnected_str}]"
                    )
                else:
                    logger.info(
                        f"Directory connection status: {connected_count}/{total_servers} connected "
                        f"[{', '.join(connected_servers)}]"
                    )

                # Log again in 10 minutes
                await asyncio.sleep(600)

            except asyncio.CancelledError:
                logger.info("Directory connection status task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in directory connection status task: {e}")
                await asyncio.sleep(600)

        logger.info("Directory connection status task stopped")

    async def _connect_to_directory(self, dir_server: str) -> tuple[str, DirectoryClient] | None:
        """
        Connect to a single directory server.

        Args:
            dir_server: Server address in format "host:port" or "host"

        Returns:
            Tuple of (node_id, client) if successful, None on failure
        """
        try:
            parts = dir_server.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 5222
            node_id = f"{host}:{port}"

            # Determine location for handshake
            onion_host = self.config.onion_host
            if onion_host:
                location = f"{onion_host}:{self.config.onion_serving_port}"
            else:
                location = "NOT-SERVING-ONION"

            # Check neutrino compatibility
            neutrino_compat = self.backend.can_provide_neutrino_metadata()

            # Create DirectoryClient with SOCKS config for Tor connections
            client = DirectoryClient(
                host=host,
                port=port,
                network=self.config.network.value,
                nick_identity=self.nick_identity,
                location=location,
                socks_host=self.config.socks_host,
                socks_port=self.config.socks_port,
                neutrino_compat=neutrino_compat,
            )

            await client.connect()
            return (node_id, client)

        except Exception as e:
            logger.debug(f"Failed to connect to {dir_server}: {e}")
            return None

    async def _periodic_directory_reconnect(self) -> None:
        """
        Background task to periodically reconnect to failed directory servers.

        Attempts to reconnect to disconnected directories at configured intervals.
        On successful reconnection:
        - Starts a listener task for the directory
        - Announces current offers to the newly connected directory
        """
        # Wait for initial connections to settle
        await asyncio.sleep(60)

        logger.info(
            f"Directory reconnection task started "
            f"(interval: {self.config.directory_reconnect_interval}s)"
        )

        while self.running:
            try:
                await asyncio.sleep(self.config.directory_reconnect_interval)

                # Find disconnected directories
                connected_servers = set(self.directory_clients.keys())
                disconnected_servers = []
                for server in self.config.directory_servers:
                    parts = server.split(":")
                    host = parts[0]
                    port = int(parts[1]) if len(parts) > 1 else 5222
                    node_id = f"{host}:{port}"
                    if node_id not in connected_servers:
                        disconnected_servers.append((server, node_id))

                if not disconnected_servers:
                    continue

                logger.info(
                    f"Attempting to reconnect to {len(disconnected_servers)} "
                    f"disconnected director{'y' if len(disconnected_servers) == 1 else 'ies'}..."
                )

                for dir_server, node_id in disconnected_servers:
                    # Check retry limit
                    max_retries = self.config.directory_reconnect_max_retries
                    attempts = self._directory_reconnect_attempts.get(node_id, 0)

                    if max_retries > 0 and attempts >= max_retries:
                        logger.debug(f"Skipping {node_id}: max retries ({max_retries}) reached")
                        continue

                    # Attempt reconnection
                    result = await self._connect_to_directory(dir_server)

                    if result:
                        new_node_id, client = result
                        self.directory_clients[new_node_id] = client

                        # Reset retry counter on success
                        self._directory_reconnect_attempts.pop(node_id, None)

                        logger.info(f"Reconnected to directory: {dir_server}")

                        # Announce offers to newly connected directory
                        for offer in self.current_offers:
                            try:
                                offer_msg = self._format_offer_announcement(
                                    offer, include_bond=False
                                )
                                await client.send_public_message(offer_msg)
                            except Exception as e:
                                logger.warning(f"Failed to announce offer to {new_node_id}: {e}")

                        # Start listener task
                        task = asyncio.create_task(self._listen_client(new_node_id, client))
                        self.listen_tasks.append(task)

                        # Notify reconnection
                        connected_count = len(self.directory_clients)
                        total_count = len(self.config.directory_servers)
                        asyncio.create_task(
                            get_notifier().notify_directory_reconnect(
                                new_node_id, connected_count, total_count
                            )
                        )
                    else:
                        # Increment retry counter
                        self._directory_reconnect_attempts[node_id] = attempts + 1
                        logger.debug(
                            f"Reconnection to {dir_server} failed "
                            f"(attempt {attempts + 1}"
                            f"{f'/{max_retries}' if max_retries > 0 else ''})"
                        )

            except asyncio.CancelledError:
                logger.info("Directory reconnection task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in directory reconnection task: {e}")

        logger.info("Directory reconnection task stopped")

    async def _monitor_pending_transactions(self) -> None:
        """
        Background task to monitor pending transactions and update their status.

        Checks pending transactions every 60 seconds and updates their confirmation
        status in the history file. Transactions are marked as successful once they
        receive their first confirmation.
        """
        logger.info("Starting pending transaction monitor...")
        check_interval = 60.0  # Check every 60 seconds

        while self.running:
            try:
                await asyncio.sleep(check_interval)
                await self._update_pending_history()

            except asyncio.CancelledError:
                logger.info("Pending transaction monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Error in pending transaction monitor: {e}")

        logger.info("Pending transaction monitor stopped")

    async def _update_pending_history(self) -> None:
        """Check and update pending transaction confirmations in history.

        For entries without txid, attempts to discover the txid by checking
        if the destination address has received funds.
        """
        from jmwallet.history import (
            get_pending_transactions,
            update_pending_transaction_txid,
            update_transaction_confirmation_with_detection,
        )

        pending = get_pending_transactions(data_dir=self.config.data_dir)
        if not pending:
            return

        logger.debug(f"Checking {len(pending)} pending transaction(s)...")

        for entry in pending:
            try:
                # If entry has no txid, try to discover it from the blockchain
                if not entry.txid:
                    if entry.destination_address:
                        logger.debug(
                            f"Attempting to discover txid for pending entry "
                            f"(dest: {entry.destination_address[:20]}...)"
                        )
                        # Look for the txid that paid to our CoinJoin address
                        txid = await self._discover_txid_for_address(entry.destination_address)
                        if txid:
                            update_pending_transaction_txid(
                                destination_address=entry.destination_address,
                                txid=txid,
                                data_dir=self.config.data_dir,
                            )
                            logger.info(
                                f"Discovered txid {txid[:16]}... for address "
                                f"{entry.destination_address[:20]}..."
                            )
                            # Update entry for confirmation check below
                            entry.txid = txid
                        else:
                            logger.debug(
                                f"No UTXO found for {entry.destination_address[:20]}... "
                                f"(tx may not be confirmed yet)"
                            )
                            continue
                    else:
                        logger.debug("Pending entry has no txid and no destination address")
                        continue

                # Check if transaction exists and get confirmations
                tx_info = await self.backend.get_transaction(entry.txid)

                if tx_info is None:
                    # Transaction not found - might have been rejected/replaced
                    from datetime import datetime

                    timestamp = datetime.fromisoformat(entry.timestamp)
                    age_hours = (datetime.now() - timestamp).total_seconds() / 3600

                    if age_hours > 24:
                        logger.warning(
                            f"Transaction {entry.txid[:16]}... not found after "
                            f"{age_hours:.1f} hours, may have been rejected"
                        )
                    continue

                confirmations = tx_info.confirmations

                # Mark as successful once it gets first confirmation
                if confirmations > 0 and entry.confirmations == 0:
                    logger.info(
                        f"Transaction {entry.txid[:16]}... confirmed "
                        f"({confirmations} confirmation(s))"
                    )
                    await update_transaction_confirmation_with_detection(
                        txid=entry.txid,
                        confirmations=confirmations,
                        backend=self.backend,
                        data_dir=self.config.data_dir,
                    )

            except Exception as e:
                txid_str = entry.txid[:16] if entry.txid else "unknown"
                logger.debug(f"Error checking transaction {txid_str}...: {e}")

    async def _discover_txid_for_address(self, address: str) -> str | None:
        """Try to discover the txid for a transaction that paid to an address.

        This is used when a maker history entry doesn't have a txid recorded
        (e.g., from older versions or if the txid wasn't captured).

        Args:
            address: The destination address to check

        Returns:
            Transaction ID if found, None otherwise
        """
        try:
            # Get UTXOs for this address - if there are any, the first one's txid
            # is likely our CoinJoin (assuming fresh addresses are used)
            utxos = await self.backend.get_utxos([address])
            if utxos:
                # Return the txid of the first (and likely only) UTXO
                return utxos[0].txid
            return None
        except Exception as e:
            logger.debug(f"Error discovering txid for {address[:20]}...: {e}")
            return None

    async def _deferred_wallet_resync(self) -> None:
        """Resync wallet in background after a CoinJoin completes."""
        try:
            # Small delay to allow transaction to propagate
            await asyncio.sleep(2)
            logger.info("Performing deferred wallet resync after CoinJoin...")
            await self._resync_wallet_and_update_offers()
        except Exception as e:
            logger.error(f"Error in deferred wallet resync: {e}")

    async def _announce_offers(self) -> None:
        """Announce offers to all connected directory servers (public broadcast, NO bonds)"""
        for offer in self.current_offers:
            offer_msg = self._format_offer_announcement(offer, include_bond=False)

            for client in self.directory_clients.values():
                try:
                    await client.send_public_message(offer_msg)
                    logger.debug("Announced offer to directory")
                except Exception as e:
                    logger.error(f"Failed to announce offer: {e}")

    def _format_offer_announcement(self, offer: Offer, include_bond: bool = False) -> str:
        """Format offer for announcement.

        Format: <ordertype> <oid> <minsize> <maxsize> <txfee> <cjfee>[!tbond <proof>]

        Args:
            offer: The offer to format
            include_bond: If True, append fidelity bond proof (for PRIVMSG only)

        Note:
            According to the JoinMarket protocol:
            - Public broadcasts: NO fidelity bond proof
            - Private responses to !orderbook: Include !tbond <proof>
        """

        order_type_str = offer.ordertype.value

        # NOTE: Don't include nick!PUBLIC! prefix here - send_public_message() adds it
        msg = (
            f"{order_type_str} "
            f"{offer.oid} {offer.minsize} {offer.maxsize} "
            f"{offer.txfee} {offer.cjfee}"
        )

        # Append fidelity bond proof ONLY for private responses
        if include_bond and self.fidelity_bond is not None:
            # For private response, we use the requesting taker's nick
            # The ownership signature proves we control the UTXO
            bond_proof = create_fidelity_bond_proof(
                bond=self.fidelity_bond,
                maker_nick=self.nick,
                taker_nick=self.nick,  # Will be updated when sending to specific taker
                current_block_height=self.current_block_height,
            )
            if bond_proof:
                msg += f"!tbond {bond_proof}"
                logger.debug(
                    f"Added fidelity bond proof to offer (proof length: {len(bond_proof)})"
                )

        return msg

    async def _listen_client(self, node_id: str, client: DirectoryClient) -> None:
        """Listen for messages from a specific directory client"""
        logger.info(f"Started listening on {node_id}")

        # Track last cleanup time
        last_cleanup = asyncio.get_event_loop().time()
        cleanup_interval = 60.0  # Clean up timed-out sessions every 60 seconds

        while self.running:
            try:
                # Use listen_for_messages with short duration to check running flag frequently
                messages = await client.listen_for_messages(duration=1.0)

                for message in messages:
                    await self._handle_message(message, source=f"dir:{node_id}")

                # Periodic cleanup of timed-out sessions
                now = asyncio.get_event_loop().time()
                if now - last_cleanup > cleanup_interval:
                    self._cleanup_timed_out_sessions()
                    last_cleanup = now

            except asyncio.CancelledError:
                logger.info(f"Listener for {node_id} cancelled")
                break
            except DirectoryClientError as e:
                # Connection lost - remove from directory_clients so reconnection task can handle it
                logger.warning(f"Connection lost on {node_id}: {e}")

                # Remove from connected clients
                self.directory_clients.pop(node_id, None)

                # Close the client gracefully
                try:
                    await client.close()
                except Exception:
                    pass

                # Fire-and-forget notification for directory disconnect
                connected_count = len(self.directory_clients)
                total_count = len(self.config.directory_servers)
                asyncio.create_task(
                    get_notifier().notify_directory_disconnect(
                        node_id, connected_count, total_count, reconnecting=True
                    )
                )
                if connected_count == 0:
                    asyncio.create_task(get_notifier().notify_all_directories_disconnected())
                break
            except Exception as e:
                logger.error(f"Error listening on {node_id}: {e}")
                await asyncio.sleep(1.0)

        logger.info(f"Stopped listening on {node_id}")

    async def _handle_message(self, message: dict[str, Any], source: str = "unknown") -> None:
        """
        Handle incoming message from directory or direct connection.

        Args:
            message: Message dict with 'type' and 'line' keys
            source: Message source for logging (e.g., "dir:node1", "direct:alice")
        """
        try:
            from jmcore.protocol import MessageType

            msg_type = message.get("type")
            line = message.get("line", "")

            # Extract from_nick for rate limiting (format: from_nick!to_nick!msg)
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 1:
                return

            from_nick = parts[0]

            # Create message fingerprint for deduplication
            # For private messages: use command (fill, auth, tx, etc.)
            # For public messages: use the whole message
            fingerprint: str | None = ""
            command = ""

            if msg_type == MessageType.PRIVMSG.value and len(parts) >= 3:
                # Format: from!to!command args...
                cmd_and_args = COMMAND_PREFIX.join(parts[2:])
                cmd_parts = cmd_and_args.strip().split(maxsplit=1)
                command = cmd_parts[0].lstrip("!")
                first_arg = cmd_parts[1].split()[0] if len(cmd_parts) > 1 else ""
                fingerprint = MessageDeduplicator.make_fingerprint(from_nick, command, first_arg)
            elif msg_type == MessageType.PUBMSG.value:
                # Parse the public message to check if it's !orderbook
                # Format: nick!PUBLIC!command or nick!PUBLIC!!command
                parts = line.split(COMMAND_PREFIX)
                # Check both parts[2] and parts[3] since format can be either:
                # nick!PUBLIC!orderbook or nick!PUBLIC!!orderbook
                is_orderbook_request = (
                    len(parts) >= 3
                    and parts[1] == "PUBLIC"
                    and (
                        parts[2].strip().lstrip("!") == "orderbook"
                        or (len(parts) >= 4 and parts[3].strip().lstrip("!") == "orderbook")
                    )
                )

                logger.debug(f"PUBMSG parts={parts}, is_orderbook={is_orderbook_request}")

                # Don't deduplicate !orderbook requests - they have their own rate limiting
                # and takers may legitimately request the orderbook multiple times
                if not is_orderbook_request:
                    # For other public messages, use the whole message as fingerprint
                    fingerprint = MessageDeduplicator.make_fingerprint(
                        from_nick, "pubmsg", line[len(from_nick) :]
                    )
                else:
                    fingerprint = None
                    logger.debug(f"Skipping deduplication for !orderbook from {from_nick}")

            # Check for duplicates (skip for !orderbook which has its own rate limiting)
            if fingerprint:
                is_dup, first_source, count = self._message_deduplicator.is_duplicate(
                    fingerprint, source
                )
                if is_dup:
                    # This is a duplicate - log and skip processing
                    # Only log first few duplicates to avoid spam
                    if count <= 3:
                        logger.debug(
                            f"Duplicate message #{count} from {from_nick} "
                            f"via {source} (first via {first_source}): {command or 'pubmsg'}"
                        )
                    return

            # Apply generic per-peer rate limiting (only for non-duplicates)
            action, _delay = self._message_rate_limiter.check(from_nick)
            from jmcore.rate_limiter import RateLimitAction

            if action != RateLimitAction.ALLOW:
                violations = self._message_rate_limiter.get_violation_count(from_nick)
                # Only log every 50th violation to prevent log flooding
                if violations % 50 == 0:
                    logger.warning(
                        f"Rate limit exceeded for {from_nick} ({violations} violations total)"
                    )
                return  # Drop the message

            # Process the message
            if msg_type == MessageType.PRIVMSG.value:
                await self._handle_privmsg(line, source=source)
            elif msg_type == MessageType.PUBMSG.value:
                await self._handle_pubmsg(line, source=source)
            elif msg_type == MessageType.PEERLIST.value:
                logger.debug(f"Received peerlist: {line[:50]}...")
            else:
                logger.debug(f"Ignoring message type {msg_type}")

        except Exception as e:
            logger.error(f"Failed to handle message: {e}")

    async def _handle_pubmsg(self, line: str, source: str = "unknown") -> None:
        """
        Handle public message (e.g., !orderbook request).

        Args:
            line: Message line in format "from_nick!to_nick!msg"
            source: Message source for logging (e.g., "dir:node1")
        """
        try:
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                return

            from_nick = parts[0]
            to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            # Ignore our own messages
            if from_nick == self.nick:
                return

            # Strip leading "!" and get command
            command = rest.strip().lstrip("!")

            # Respond to orderbook requests with PRIVMSG (including bond if available)
            if to_nick == "PUBLIC" and command == "orderbook":
                # Apply rate limiting to prevent spam attacks
                if not self._orderbook_rate_limiter.check(from_nick):
                    violations = self._orderbook_rate_limiter.get_violation_count(from_nick)
                    is_banned = self._orderbook_rate_limiter.is_banned(from_nick)

                    # Only log rate limiting (not bans) at specific violation milestones
                    # to prevent log flooding:
                    # - First violation (violations == 1)
                    # - Every 10th violation when not banned (10, 20, 30, etc.)
                    # Note: Ban events are already logged by check() method, so we skip
                    # logging here to avoid duplicate log messages
                    if not is_banned:
                        should_log = violations <= 1 or violations % 10 == 0

                        if should_log:
                            # Show backoff level for context
                            if violations >= self.config.orderbook_violation_severe_threshold:
                                backoff_level = "SEVERE"
                            elif violations >= self.config.orderbook_violation_warning_threshold:
                                backoff_level = "MODERATE"
                            else:
                                backoff_level = "NORMAL"

                            logger.debug(
                                f"Rate limiting orderbook request from {from_nick} "
                                f"(violations: {violations}, backoff: {backoff_level})"
                            )
                    return

                logger.info(
                    f"Received !orderbook request from {from_nick}, sending offers via PRIVMSG"
                )
                await self._send_offers_to_taker(from_nick)
            elif to_nick == "PUBLIC" and command.startswith("hp2"):
                # hp2 via pubmsg = commitment broadcast for blacklisting
                await self._handle_hp2_pubmsg(from_nick, command)

        except Exception as e:
            logger.error(f"Failed to handle pubmsg: {e}")

    async def _send_offers_to_taker(self, taker_nick: str) -> None:
        """Send offers to a specific taker via PRIVMSG, including fidelity bond if available.

        This is called when we receive a !orderbook request from a taker.
        According to the JoinMarket protocol, fidelity bonds must ONLY be sent
        via PRIVMSG, never in public broadcasts.

        For each offer:
        1. Format the offer parameters
        2. If we have a fidelity bond, create a proof signed for this specific taker
        3. Append !tbond <proof> to the offer data
        4. Send via PRIVMSG to the taker

        Message format:
            send_private_message(
                taker_nick,
                command="sw0reloffer",
                data="0 2500000 ... !tbond <proof>"
            )
            Results in: from_nick!taker_nick!sw0reloffer 0 2500000 ... !tbond <proof> <sig>

        Args:
            taker_nick: The nick of the taker requesting the orderbook
        """
        try:
            for offer in self.current_offers:
                # Format offer data (parameters without the command)
                order_type_str = offer.ordertype.value
                data = f"{offer.oid} {offer.minsize} {offer.maxsize} {offer.txfee} {offer.cjfee}"

                # Append fidelity bond proof if we have one
                # CRITICAL: The bond proof must be signed with the taker's nick
                if self.fidelity_bond is not None:
                    bond_proof = create_fidelity_bond_proof(
                        bond=self.fidelity_bond,
                        maker_nick=self.nick,
                        taker_nick=taker_nick,  # Sign for THIS specific taker
                        current_block_height=self.current_block_height,
                    )
                    if bond_proof:
                        data += f"!tbond {bond_proof}"
                        logger.debug(
                            f"Including fidelity bond proof in offer to {taker_nick} "
                            f"(proof length: {len(bond_proof)})"
                        )

                # Send via all connected directory clients
                for client in self.directory_clients.values():
                    try:
                        # Send as PRIVMSG
                        # Format: taker_nick!maker_nick!<order_type> <data> <signature>
                        await client.send_private_message(taker_nick, order_type_str, data)
                        logger.debug(f"Sent {order_type_str} offer to {taker_nick}")
                    except Exception as e:
                        logger.error(f"Failed to send offer to {taker_nick} via directory: {e}")

        except Exception as e:
            logger.error(f"Failed to send offers to taker {taker_nick}: {e}")

    async def _handle_privmsg(self, line: str, source: str = "unknown") -> None:
        """
        Handle private message (CoinJoin protocol).

        Args:
            line: Message line in format "from_nick!to_nick!msg"
            source: Message source for logging (e.g., "dir:node1", "direct:alice")
        """
        try:
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                return

            from_nick = parts[0]
            to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            if to_nick != self.nick:
                return

            # Strip leading "!" if present (due to !!command message format)
            command = rest.strip().lstrip("!")

            # Note: command prefix already stripped
            if command.startswith("fill"):
                await self._handle_fill(from_nick, command, source=source)
            elif command.startswith("auth"):
                await self._handle_auth(from_nick, command, source=source)
            elif command.startswith("tx"):
                await self._handle_tx(from_nick, command, source=source)
            elif command.startswith("push"):
                await self._handle_push(from_nick, command, source=source)
            elif command.startswith("hp2"):
                # hp2 via privmsg = commitment transfer request
                # We should re-broadcast it publicly to obfuscate the source
                await self._handle_hp2_privmsg(from_nick, command)
            else:
                logger.debug(f"Unknown command: {command[:20]}...")

        except Exception as e:
            logger.error(f"Failed to handle privmsg: {e}")

    async def _handle_fill(self, taker_nick: str, msg: str, source: str = "unknown") -> None:
        """Handle !fill request from taker.

        Fill message format: fill <oid> <amount> <taker_nacl_pk> <commitment> [<signing_pk> <sig>]

        The offer_id (oid) is used to identify which offer the taker wants to fill.
        This allows makers to have multiple offers (e.g., relative and absolute fee)
        simultaneously, each with a unique ID.
        """
        try:
            parts = msg.split()
            if len(parts) < 5:
                logger.warning(f"Invalid !fill format (need at least 5 parts): {msg}")
                return

            offer_id = int(parts[1])
            amount = int(parts[2])
            taker_pk = parts[3]  # Taker's NaCl pubkey for E2E encryption
            commitment = parts[4]  # PoDLE commitment (with prefix like "P")

            # Strip commitment prefix if present (e.g., "P" for standard PoDLE)
            if commitment.startswith("P"):
                commitment = commitment[1:]

            # Check if commitment is already blacklisted
            if not check_commitment(commitment):
                logger.warning(
                    f"Rejecting !fill from {taker_nick}: commitment already used "
                    f"({commitment[:16]}...)"
                )
                return

            # Find the offer by ID (supports multiple offers with different IDs)
            offer = self.offer_manager.get_offer_by_id(self.current_offers, offer_id)
            if offer is None:
                logger.warning(
                    f"Invalid offer ID: {offer_id} (available: "
                    f"{[o.oid for o in self.current_offers]})"
                )
                return

            is_valid, error = self.offer_manager.validate_offer_fill(offer, amount)
            if not is_valid:
                logger.warning(f"Invalid fill request for offer {offer_id}: {error}")
                return

            session = CoinJoinSession(
                taker_nick=taker_nick,
                offer=offer,
                wallet=self.wallet,
                backend=self.backend,
                session_timeout_sec=self.config.session_timeout_sec,
                merge_algorithm=self.config.merge_algorithm.value,
            )

            # Validate channel consistency (first message records the channel)
            if not session.validate_channel(source):
                logger.error(f"Channel consistency violation for !fill from {taker_nick}")
                return

            # Pass the taker's NaCl pubkey for setting up encryption
            success, response = await session.handle_fill(amount, commitment, taker_pk)

            if success:
                self.active_sessions[taker_nick] = session
                logger.info(
                    f"Created CoinJoin session with {taker_nick} "
                    f"(offer_id={offer_id}, type={offer.ordertype.value})"
                )

                # Fire-and-forget notification
                asyncio.create_task(
                    get_notifier().notify_fill_request(taker_nick, amount, offer_id)
                )

                await self._send_response(taker_nick, "pubkey", response)
            else:
                logger.warning(f"Failed to handle fill: {response.get('error')}")

        except Exception as e:
            logger.error(f"Failed to handle !fill: {e}")

    async def _handle_auth(self, taker_nick: str, msg: str, source: str = "unknown") -> None:
        """Handle !auth request from taker.

        The auth message is ENCRYPTED using NaCl.
        Format: auth <encrypted_base64> [<signing_pk> <sig>]

        After decryption, the plaintext is pipe-separated:
        txid:vout|P|P2|sig|e

        Note: The taker sends !auth via all directory servers, so we may receive
        duplicates. We use a lock per session to ensure only one message is
        processed at a time, and check state early to reject duplicates.
        """
        # Acquire lock for this session to prevent concurrent processing
        lock = self._get_session_lock(taker_nick)
        async with lock:
            try:
                if taker_nick not in self.active_sessions:
                    logger.warning(f"No active session for {taker_nick}")
                    return

                session = self.active_sessions[taker_nick]

                # Validate channel consistency before processing
                if not session.validate_channel(source):
                    logger.error(f"Channel consistency violation for !auth from {taker_nick}")
                    del self.active_sessions[taker_nick]
                    self._cleanup_session_lock(taker_nick)
                    return

                # Early state check to reject duplicate !auth messages
                # This happens when taker sends via multiple directory servers
                from maker.coinjoin import CoinJoinState

                if session.state != CoinJoinState.PUBKEY_SENT:
                    logger.debug(
                        f"Ignoring duplicate !auth from {taker_nick} "
                        f"(state={session.state}, expected=PUBKEY_SENT)"
                    )
                    return

                logger.info(f"Received !auth from {taker_nick}, decrypting and verifying PoDLE...")

                # Parse: auth <encrypted_base64> [<signing_pk> <sig>]
                parts = msg.split()
                if len(parts) < 2:
                    logger.error("Invalid !auth format: missing encrypted data")
                    return

                encrypted_data = parts[1]

                # Decrypt the auth message
                if not session.crypto.is_encrypted:
                    logger.error("Encryption not set up for this session")
                    return

                try:
                    decrypted = session.crypto.decrypt(encrypted_data)
                    logger.debug(f"Decrypted auth message length: {len(decrypted)}")
                except Exception as e:
                    logger.error(f"Failed to decrypt auth message: {e}")
                    return

                # Parse the decrypted revelation - pipe-separated format:
                # txid:vout|P|P2|sig|e
                try:
                    revelation_parts = decrypted.split("|")
                    if len(revelation_parts) != 5:
                        logger.error(
                            f"Invalid revelation format: expected 5 parts, "
                            f"got {len(revelation_parts)}"
                        )
                        return

                    utxo_str, p_hex, p2_hex, sig_hex, e_hex = revelation_parts

                    # Parse utxo
                    if ":" not in utxo_str:
                        logger.error(f"Invalid utxo format: {utxo_str}")
                        return

                    # Validate utxo format (txid:vout)
                    if not utxo_str.rsplit(":", 1)[1].isdigit():
                        logger.error(f"Invalid vout in utxo: {utxo_str}")
                        return

                    # parse_podle_revelation expects hex strings, not bytes
                    revelation = {
                        "utxo": utxo_str,
                        "P": p_hex,
                        "P2": p2_hex,
                        "sig": sig_hex,
                        "e": e_hex,
                    }
                    logger.debug(f"Parsed revelation: utxo={utxo_str}, P={p_hex[:16]}...")
                except Exception as e:
                    logger.error(f"Failed to parse revelation: {e}")
                    return

                # The commitment was already stored from the !fill message
                commitment = self.active_sessions[taker_nick].commitment.hex()

                # kphex is empty for now - we don't use it yet
                kphex = ""

                success, response = await session.handle_auth(commitment, revelation, kphex)

                if success:
                    await self._send_response(taker_nick, "ioauth", response)

                    # Broadcast the commitment via hp2 so other makers can blacklist it
                    # This prevents reuse of commitments in future CoinJoin attempts
                    await self._broadcast_commitment(commitment)
                else:
                    logger.error(f"Auth failed: {response.get('error')}")
                    # Fire-and-forget notification for rejection
                    asyncio.create_task(
                        get_notifier().notify_rejection(
                            taker_nick, "PoDLE verification failed", response.get("error", "")
                        )
                    )
                    del self.active_sessions[taker_nick]
                    self._cleanup_session_lock(taker_nick)

            except Exception as e:
                logger.error(f"Failed to handle !auth: {e}")

    async def _handle_tx(self, taker_nick: str, msg: str, source: str = "unknown") -> None:
        """Handle !tx request from taker.

        The tx message is ENCRYPTED using NaCl.
        Format: tx <encrypted_base64> [<signing_pk> <sig>]

        After decryption, the plaintext is base64-encoded transaction bytes.

        Note: The taker sends !tx via all directory servers, so we may receive
        duplicates. We use a lock per session to ensure only one message is
        processed at a time, and check state early to reject duplicates.
        """
        # Acquire lock for this session to prevent concurrent processing
        lock = self._get_session_lock(taker_nick)
        async with lock:
            try:
                if taker_nick not in self.active_sessions:
                    logger.warning(f"No active session for {taker_nick}")
                    return

                session = self.active_sessions[taker_nick]

                # Validate channel consistency before processing
                if not session.validate_channel(source):
                    logger.error(f"Channel consistency violation for !tx from {taker_nick}")
                    del self.active_sessions[taker_nick]
                    self._cleanup_session_lock(taker_nick)
                    return

                # Early state check to reject duplicate !tx messages
                # This happens when taker sends via multiple directory servers
                from maker.coinjoin import CoinJoinState

                if session.state != CoinJoinState.IOAUTH_SENT:
                    logger.debug(
                        f"Ignoring duplicate !tx from {taker_nick} "
                        f"(state={session.state}, expected=IOAUTH_SENT)"
                    )
                    return

                logger.info(
                    f"Received !tx from {taker_nick}, decrypting and verifying transaction..."
                )

                # Parse: tx <encrypted_base64> [<signing_pk> <sig>]
                parts = msg.split()
                if len(parts) < 2:
                    logger.warning("Invalid !tx format")
                    return

                encrypted_data = parts[1]

                # Decrypt the tx message
                if not session.crypto.is_encrypted:
                    logger.error("Encryption not set up for this session")
                    return

                try:
                    decrypted = session.crypto.decrypt(encrypted_data)
                    logger.debug(f"Decrypted tx message length: {len(decrypted)}")
                except Exception as e:
                    logger.error(f"Failed to decrypt tx message: {e}")
                    return

                # The decrypted content is base64-encoded transaction
                import base64

                try:
                    tx_bytes = base64.b64decode(decrypted)
                    tx_hex = tx_bytes.hex()
                except Exception as e:
                    logger.error(f"Failed to decode transaction: {e}")
                    return

                success, response = await session.handle_tx(tx_hex)

                if success:
                    # Send each signature as a separate message
                    signatures = response.get("signatures", [])
                    for sig in signatures:
                        await self._send_response(taker_nick, "sig", {"signature": sig})
                    logger.info(
                        f"CoinJoin with {taker_nick} COMPLETE (sent {len(signatures)} sigs)"
                    )

                    # Calculate fee for history and notification
                    fee_received = session.offer.calculate_fee(session.amount)
                    txfee_contribution = session.offer.txfee

                    # Record transaction in history
                    try:
                        our_utxos = list(session.our_utxos.keys())

                        history_entry = create_maker_history_entry(
                            taker_nick=taker_nick,
                            cj_amount=session.amount,
                            fee_received=fee_received,
                            txfee_contribution=txfee_contribution,
                            cj_address=session.cj_address,
                            change_address=session.change_address,
                            our_utxos=our_utxos,
                            txid=response.get("txid"),
                            network=self.config.network.value,
                        )
                        append_history_entry(history_entry, data_dir=self.config.data_dir)
                        net = fee_received - txfee_contribution
                        logger.debug(f"Recorded CoinJoin in history: net fee {net} sats")
                    except Exception as e:
                        logger.warning(f"Failed to record CoinJoin history: {e}")

                    # Fire-and-forget notification for successful signing
                    asyncio.create_task(
                        get_notifier().notify_tx_signed(
                            taker_nick,
                            session.amount,
                            len(signatures),
                            fee_received,
                        )
                    )

                    del self.active_sessions[taker_nick]
                    self._cleanup_session_lock(taker_nick)

                    # Nick regeneration disabled - see _regenerate_nick() docstring for rationale

                    # Schedule wallet re-sync in background to avoid blocking !push handling
                    asyncio.create_task(self._deferred_wallet_resync())
                else:
                    logger.error(f"TX verification failed: {response.get('error')}")
                    # Fire-and-forget notification for TX rejection
                    asyncio.create_task(
                        get_notifier().notify_rejection(
                            taker_nick, "TX verification failed", response.get("error", "")
                        )
                    )
                    del self.active_sessions[taker_nick]
                    self._cleanup_session_lock(taker_nick)

            except Exception as e:
                logger.error(f"Failed to handle !tx: {e}")

    async def _handle_push(self, taker_nick: str, msg: str, source: str = "unknown") -> None:
        """Handle !push request from taker.

        The push message contains a base64-encoded signed transaction that the taker
        wants us to broadcast. This provides privacy benefits as the taker's IP is
        not linked to the transaction broadcast.

        Per JoinMarket protocol, makers broadcast "unquestioningly" - we already
        signed this transaction so it must be valid from our perspective. We don't
        verify or check the result, just broadcast and move on.

        Security considerations:
        - DoS risk: A malicious taker could spam !push messages with invalid data
        - Mitigation: Generic per-peer rate limiting (in directory server) prevents
          this from being a significant attack vector
        - We intentionally do NOT validate session state here to maintain protocol
          compatibility and simplicity. The rate limiter is the primary defense.

        Format: push <base64_transaction>

        Note: !push doesn't require channel consistency validation since it's
        fire-and-forget and not part of the critical CoinJoin handshake.
        """
        try:
            import base64

            parts = msg.split()
            if len(parts) < 2:
                logger.warning(f"Invalid !push format from {taker_nick}")
                return

            tx_b64 = parts[1]

            try:
                tx_bytes = base64.b64decode(tx_b64)
                tx_hex = tx_bytes.hex()
            except Exception as e:
                logger.error(f"Failed to decode !push transaction: {e}")
                return

            logger.info(f"Received !push from {taker_nick}, broadcasting transaction...")

            # Broadcast "unquestioningly" - we already signed it, so it's valid
            # from our perspective. Don't check the result.
            try:
                txid = await self.backend.broadcast_transaction(tx_hex)
                logger.info(f"Broadcast transaction for {taker_nick}: {txid}")
            except Exception as e:
                # Log but don't fail - the taker may have a fallback
                logger.warning(f"Failed to broadcast !push transaction: {e}")

        except Exception as e:
            logger.error(f"Failed to handle !push: {e}")

    async def _handle_hp2_pubmsg(self, from_nick: str, msg: str) -> None:
        """Handle !hp2 commitment broadcast seen in public channel.

        When a maker sees a PoDLE commitment broadcast in public (via !hp2),
        they should blacklist it. This prevents reuse of commitments that
        may have been used in failed or malicious CoinJoin attempts.

        Format: hp2 <commitment_hex>
        """
        try:
            parts = msg.split()
            if len(parts) < 2:
                logger.debug(f"Invalid !hp2 format from {from_nick}: missing commitment")
                return

            commitment = parts[1]

            # Add to blacklist (persists to disk)
            if add_commitment(commitment):
                logger.info(
                    f"Received commitment broadcast from {from_nick}, "
                    f"added to blacklist: {commitment[:16]}..."
                )
            else:
                logger.debug(
                    f"Received commitment broadcast from {from_nick}, "
                    f"already blacklisted: {commitment[:16]}..."
                )

        except Exception as e:
            logger.error(f"Failed to handle !hp2 pubmsg: {e}")

    async def _handle_hp2_privmsg(self, from_nick: str, msg: str) -> None:
        """Handle !hp2 commitment transfer via private message.

        When a maker receives !hp2 via privmsg, another maker is asking us to
        broadcast the commitment publicly. This provides obfuscation of the
        original source of the commitment broadcast.

        We simply re-broadcast it via pubmsg without verifying the commitment.

        Format: hp2 <commitment_hex>
        """
        try:
            parts = msg.split()
            if len(parts) < 2:
                logger.debug(f"Invalid !hp2 format from {from_nick}: missing commitment")
                return

            commitment = parts[1]
            logger.info(f"Received commitment transfer from {from_nick}, re-broadcasting...")

            # Broadcast the commitment publicly
            hp2_msg = f"hp2 {commitment}"
            for client in self.directory_clients.values():
                try:
                    await client.send_public_message(hp2_msg)
                except Exception as e:
                    logger.warning(f"Failed to broadcast hp2: {e}")

            logger.debug(f"Re-broadcast commitment: {commitment[:16]}...")

        except Exception as e:
            logger.error(f"Failed to handle !hp2 privmsg: {e}")

    async def _broadcast_commitment(self, commitment: str) -> None:
        """Broadcast a PoDLE commitment via !hp2 to help other makers blacklist it.

        After successfully processing a taker's !auth message, we broadcast the
        commitment so other makers can add it to their blacklist. This prevents
        the same commitment from being reused in future CoinJoin attempts.

        The reference implementation does this to maintain network-wide commitment
        blacklisting, which is a key anti-Sybil mechanism.
        """
        try:
            # Add to our own blacklist first (persists to disk)
            add_commitment(commitment)

            hp2_msg = f"hp2 {commitment}"
            for client in self.directory_clients.values():
                try:
                    await client.send_public_message(hp2_msg)
                except Exception as e:
                    logger.warning(f"Failed to broadcast commitment: {e}")

            logger.debug(f"Broadcast commitment: {commitment[:16]}...")

        except Exception as e:
            logger.error(f"Failed to broadcast commitment: {e}")

    async def _send_response(self, taker_nick: str, command: str, data: dict[str, Any]) -> None:
        """Send signed response to taker.

        Different commands have different formats:
        - !pubkey <nacl_pubkey_hex> - NOT encrypted
        - !ioauth <encrypted_base64> - ENCRYPTED
        - !sig <encrypted_base64> - ENCRYPTED

        The signature is appended: <message_content> <signing_pubkey> <sig_b64>
        The signature is over: <message_content> + hostid (NOT including the command!)

        For encrypted commands, the plaintext is space-separated values that get
        encrypted and base64-encoded before signing.
        """
        try:
            # Format message content based on command type
            if command == "pubkey":
                # !pubkey <nacl_pubkey_hex> [features=<comma-separated>] - NOT encrypted
                # Features are optional and backwards compatible with legacy takers
                msg_content = data["nacl_pubkey"]
                features = data.get("features", [])
                if features:
                    msg_content += f" features={','.join(features)}"
            elif command == "ioauth":
                # Plaintext format: <utxo_list> <auth_pub> <cj_addr> <change_addr> <btc_sig>
                plaintext = " ".join(
                    [
                        data["utxo_list"],
                        data["auth_pub"],
                        data["cj_addr"],
                        data["change_addr"],
                        data["btc_sig"],
                    ]
                )

                # Get the session to encrypt the message
                if taker_nick not in self.active_sessions:
                    logger.error(f"No active session for {taker_nick} to encrypt ioauth")
                    return
                session = self.active_sessions[taker_nick]
                msg_content = session.crypto.encrypt(plaintext)
                logger.debug(f"Encrypted ioauth message, plaintext_len={len(plaintext)}")
            elif command == "sig":
                # Plaintext format: <signature_base64>
                # For multiple signatures, we send them one by one
                plaintext = data["signature"]

                # Get the session to encrypt the message
                if taker_nick not in self.active_sessions:
                    logger.error(f"No active session for {taker_nick} to encrypt sig")
                    return
                session = self.active_sessions[taker_nick]
                msg_content = session.crypto.encrypt(plaintext)
                logger.debug(f"Encrypted sig: plaintext_len={len(plaintext)}")
            else:
                # Fallback to JSON for unknown commands
                msg_content = json.dumps(data)

            # Send via directory clients - they will sign the message for us
            for client in self.directory_clients.values():
                await client.send_private_message(taker_nick, command, msg_content)

            logger.debug(f"Sent signed {command} to {taker_nick}")

        except Exception as e:
            logger.error(f"Failed to send response: {e}")

    def _parse_direct_message(self, data: bytes) -> tuple[str, str, str] | None:
        """Parse a direct connection message supporting both formats.

        The reference implementation uses OnionCustomMessage format:
            {"type": 685, "line": "from_nick!to_nick!command data"}
        Where type 685 = PRIVMSG.

        Our internal format (for future use):
            {"nick": "sender", "cmd": "command", "data": "..."}

        Returns:
            (sender_nick, command, message_data) tuple or None if parsing fails.
        """
        try:
            message = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return None

        # Check for reference implementation format: {"type": int, "line": str}
        if "type" in message and "line" in message:
            from jmcore.protocol import MessageType

            msg_type = message.get("type")
            line = message.get("line", "")

            # Only handle PRIVMSG for CoinJoin protocol
            if msg_type != MessageType.PRIVMSG.value:
                logger.debug(f"Ignoring non-PRIVMSG type {msg_type} on direct connection")
                return None

            # Parse line format: from_nick!to_nick!command data
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                logger.warning(f"Invalid line format: {line[:50]}...")
                return None

            sender_nick = parts[0]
            to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            # Check if message is for us
            if to_nick != self.nick:
                logger.debug(f"Ignoring message not for us: to={to_nick}, us={self.nick}")
                return None

            # Strip leading "!" and parse command
            rest = rest.strip().lstrip("!")

            # Extract command and data
            cmd_parts = rest.split(" ", 1)
            cmd = cmd_parts[0]
            msg_data = cmd_parts[1] if len(cmd_parts) > 1 else ""

            return (sender_nick, cmd, msg_data)

        # Check for our internal format: {"nick": str, "cmd": str, "data": str}
        elif "nick" in message or "cmd" in message:
            sender_nick = message.get("nick", "unknown")
            cmd = message.get("cmd", "")
            msg_data = message.get("data", "")
            return (sender_nick, cmd, msg_data)

        return None

    async def _try_handle_handshake(
        self, connection: TCPConnection, data: bytes, peer_str: str
    ) -> bool:
        """Try to handle a handshake request on a direct connection.

        Health checkers and feature discovery tools connect directly to makers
        and send a handshake request to discover features like neutrino_compat.

        The protocol mirrors the reference implementation:
        - Client sends HANDSHAKE (793) with client_handshake_json format
        - Server responds with DN_HANDSHAKE (795) with server_handshake_json format

        Args:
            connection: The TCP connection
            data: Raw message data
            peer_str: Peer identifier string for logging

        Returns:
            True if this was a handshake message (handled), False otherwise.
        """
        try:
            message = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

        # Check for handshake message type (793 = HANDSHAKE)
        if message.get("type") != MessageType.HANDSHAKE.value:
            return False

        # Parse the handshake request
        try:
            line = message.get("line", "")
            handshake_data = json.loads(line) if isinstance(line, str) else line
        except json.JSONDecodeError:
            logger.warning(f"Invalid handshake JSON from {peer_str}")
            return True  # Was a handshake message, just malformed

        peer_nick = handshake_data.get("nick", "unknown")
        peer_network = handshake_data.get("network", "")

        logger.info(f"Received handshake from {peer_nick} at {peer_str}")

        # Build our feature set
        features = FeatureSet()
        if self.backend.can_provide_neutrino_metadata():
            features.features.add(FEATURE_NEUTRINO_COMPAT)
        # We support peerlist_features protocol
        features.features.add(FEATURE_PEERLIST_FEATURES)

        # Validate network
        if peer_network and peer_network != self.config.network.value:
            logger.warning(
                f"Network mismatch from {peer_nick}: {peer_network} != {self.config.network.value}"
            )
            # Still respond but mark as rejected
            response_data = create_handshake_response(
                nick=self.nick,
                network=self.config.network.value,
                accepted=False,
                motd="Network mismatch",
                features=features,
            )
        else:
            response_data = create_handshake_response(
                nick=self.nick,
                network=self.config.network.value,
                accepted=True,
                motd="JoinMarket NG Maker",
                features=features,
            )

        # Send handshake response using DN_HANDSHAKE (795) type
        # This matches the reference implementation protocol where the server
        # (directory or maker accepting connections) responds with dn-handshake
        response_msg = {
            "type": MessageType.DN_HANDSHAKE.value,
            "line": json.dumps(response_data),
        }
        try:
            await connection.send(json.dumps(response_msg).encode("utf-8"))
            logger.info(
                f"Sent handshake response to {peer_nick} "
                f"(features: {features.to_comma_string() or 'none'})"
            )
        except Exception as e:
            logger.warning(f"Failed to send handshake response to {peer_str}: {e}")

        return True

    async def _on_direct_connection(self, connection: TCPConnection, peer_str: str) -> None:
        """Handle incoming direct connection from a taker via hidden service.

        Direct connections support three message formats:

        1. Handshake request (health check / feature discovery):
           {"type": 793, "line": "<json handshake data>"}
           Maker responds with handshake response including features.

        2. Reference implementation format (OnionCustomMessage):
           {"type": 685, "line": "from_nick!to_nick!command data"}
           Where type 685 = PRIVMSG.

        3. Our simplified format:
           {"nick": "sender", "cmd": "command", "data": "..."}

        This bypasses the directory server for lower latency once the taker
        knows the maker's onion address (from the peerlist).
        """
        logger.info(f"Handling direct connection from {peer_str}")

        try:
            # Keep connection open and process messages
            while self.running and connection.is_connected():
                try:
                    # Receive message with timeout
                    data = await asyncio.wait_for(connection.receive(), timeout=60.0)
                    if not data:
                        logger.info(f"Direct connection from {peer_str} closed")
                        break

                    # Check for handshake request first (health check / feature discovery)
                    handshake_handled = await self._try_handle_handshake(connection, data, peer_str)
                    if handshake_handled:
                        # Handshake was handled, connection may close after response
                        # Continue to allow follow-up messages or clean disconnect
                        continue

                    # Parse the message (supports both formats)
                    parsed = self._parse_direct_message(data)
                    if parsed is None:
                        logger.warning(f"Failed to parse direct message from {peer_str}")
                        continue

                    sender_nick, cmd, msg_data = parsed

                    logger.debug(f"Direct message from {sender_nick}: cmd={cmd}")

                    # Track this connection by nick for sending responses
                    if sender_nick and sender_nick != "unknown":
                        self.direct_connections[sender_nick] = connection

                    # Process the command - reuse existing handlers
                    # Commands: fill, auth, tx (same as via directory)
                    full_msg = f"{cmd} {msg_data}" if msg_data else cmd

                    if cmd == "fill":
                        await self._handle_fill(sender_nick, full_msg, source="direct")
                    elif cmd == "auth":
                        await self._handle_auth(sender_nick, full_msg, source="direct")
                    elif cmd == "tx":
                        await self._handle_tx(sender_nick, full_msg, source="direct")
                    elif cmd == "push":
                        await self._handle_push(sender_nick, full_msg, source="direct")
                    else:
                        logger.debug(f"Unknown direct command from {sender_nick}: {cmd}")

                except TimeoutError:
                    # No message received, continue waiting
                    continue
                except Exception as e:
                    logger.error(f"Error processing direct message from {peer_str}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error in direct connection handler for {peer_str}: {e}")
        finally:
            await connection.close()
            # Clean up nick -> connection mapping
            for nick, conn in list(self.direct_connections.items()):
                if conn == connection:
                    del self.direct_connections[nick]
            logger.info(f"Direct connection from {peer_str} closed")
