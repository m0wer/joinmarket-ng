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
from typing import Any

from jmcore.commitment_blacklist import add_commitment, check_commitment, set_blacklist_path
from jmcore.crypto import NickIdentity
from jmcore.directory_client import DirectoryClient, DirectoryClientError
from jmcore.models import Offer
from jmcore.network import HiddenServiceListener, TCPConnection
from jmcore.protocol import COMMAND_PREFIX, JM_VERSION
from jmcore.tor_control import (
    EphemeralHiddenService,
    TorControlClient,
    TorControlError,
)
from jmwallet.backends.base import BlockchainBackend
from jmwallet.history import (
    append_history_entry,
    create_maker_history_entry,
    get_pending_transactions,
    update_pending_transaction_txid,
    update_transaction_confirmation,
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

        self.running = False
        self.listen_tasks: list[asyncio.Task[None]] = []

        # Hidden service listener for direct peer connections
        self.hidden_service_listener: HiddenServiceListener | None = None
        self.direct_connections: dict[str, TCPConnection] = {}

        # Tor control for dynamic hidden service creation
        self._tor_control: TorControlClient | None = None
        self._ephemeral_hidden_service: EphemeralHiddenService | None = None

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
                password=self.config.tor_control.password,
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
            # Maps external port 27183 to our local serving port
            logger.info(
                f"Creating ephemeral hidden service on port 27183 -> "
                f"{self.config.onion_serving_host}:{self.config.onion_serving_port}..."
            )

            self._ephemeral_hidden_service = (
                await self._tor_control.create_ephemeral_hidden_service(
                    ports=[
                        (
                            27183,
                            f"{self.config.onion_serving_host}:{self.config.onion_serving_port}",
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

            logger.info("Syncing wallet...")
            await self.wallet.sync_all()

            # Sync fidelity bonds - auto-discover locktimes from registry if not specified
            fidelity_locktimes = list(self.config.fidelity_bond_locktimes)  # Copy to avoid mutating

            # Auto-discover locktimes from bond registry if none specified
            if not fidelity_locktimes:
                from jmcore.paths import get_default_data_dir
                from jmwallet.wallet.bond_registry import get_all_locktimes

                resolved_data_dir = (
                    self.config.data_dir if self.config.data_dir else get_default_data_dir()
                )
                registry_locktimes = get_all_locktimes(resolved_data_dir)
                if registry_locktimes:
                    fidelity_locktimes = registry_locktimes
                    logger.info(
                        f"Auto-discovered {len(registry_locktimes)} fidelity bond locktime(s) "
                        "from registry"
                    )

            if fidelity_locktimes:
                logger.info(f"Syncing fidelity bonds for locktimes: {fidelity_locktimes}")
                await self.wallet.sync_fidelity_bonds(fidelity_locktimes)

            total_balance = await self.wallet.get_total_balance()
            logger.info(f"Wallet synced. Total balance: {total_balance:,} sats")

            # Find fidelity bond for proof generation
            # If a specific bond is selected in config, use it; otherwise use the best one
            if self.config.selected_fidelity_bond:
                # User specified a specific bond
                sel_txid, sel_vout = self.config.selected_fidelity_bond
                bonds = find_fidelity_bonds(self.wallet)
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
                    self.fidelity_bond = get_best_fidelity_bond(self.wallet)
            else:
                # Auto-select the best (largest bond value) fidelity bond
                self.fidelity_bond = get_best_fidelity_bond(self.wallet)
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
                    # If we have an onion_host configured (static or ephemeral), advertise it
                    # Otherwise, use NOT-SERVING-ONION
                    location = onion_host or "NOT-SERVING-ONION"

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

    def _cleanup_timed_out_sessions(self) -> None:
        """Remove timed-out sessions from active_sessions."""
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

        await self.wallet.sync_all()

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

            # Check if offers actually changed
            if self.current_offers and new_offers:
                old_maxsize = self.current_offers[0].maxsize
                new_maxsize = new_offers[0].maxsize
                if old_maxsize == new_maxsize:
                    logger.debug("Offer maxsize unchanged, skipping re-announcement")
                    return

            self.current_offers = new_offers
            await self._announce_offers()
            logger.info(f"Updated and re-announced offers: maxsize={new_offers[0].maxsize:,} sats")
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

    async def _deferred_wallet_resync(self) -> None:
        """Re-sync wallet after CoinJoin completion in background.

        This is deferred to a background task to avoid blocking message processing.
        The transaction might not be broadcast yet (!push comes after !tx), so we
        add a configurable delay to give the transaction time to propagate.
        """
        try:
            # Wait before rescanning to:
            # 1. Allow !push message to be processed
            # 2. Give transaction time to propagate in mempool
            await asyncio.sleep(self.config.post_coinjoin_rescan_delay)

            logger.info("Re-syncing wallet after CoinJoin completion...")
            await self._resync_wallet_and_update_offers()
        except Exception as e:
            logger.error(f"Failed to re-sync wallet after CoinJoin: {e}")

    async def _update_pending_history(self) -> None:
        """Check and update status of pending transactions in history."""
        try:
            pending = get_pending_transactions(data_dir=self.config.data_dir)
            if not pending:
                return

            logger.debug(f"Checking {len(pending)} pending transaction(s)...")

            for entry in pending:
                # First, try to discover missing txids by looking up destination addresses
                if not entry.txid and entry.destination_address:
                    logger.debug(
                        f"Looking for txid by destination address "
                        f"{entry.destination_address[:20]}..."
                    )
                    utxo = self.wallet.find_utxo_by_address(entry.destination_address)
                    if utxo:
                        # Found the UTXO - update history with the txid
                        logger.info(
                            f"Discovered txid {utxo.txid[:16]}... for pending CoinJoin "
                            f"at {entry.destination_address[:20]}..."
                        )
                        update_pending_transaction_txid(
                            destination_address=entry.destination_address,
                            txid=utxo.txid,
                            data_dir=self.config.data_dir,
                        )
                        # Update the entry object so we can check confirmations below
                        entry.txid = utxo.txid

                # Now check confirmations for entries with txids
                if not entry.txid:
                    continue

                try:
                    # Check if transaction exists and get confirmations
                    tx_info = await self.backend.get_transaction(entry.txid)

                    if tx_info is None:
                        # Transaction not found - might have been rejected/replaced
                        # Check how long it's been pending
                        from datetime import datetime

                        timestamp = datetime.fromisoformat(entry.timestamp)
                        age_hours = (datetime.now() - timestamp).total_seconds() / 3600

                        if age_hours > 24:
                            # Mark as failed if pending for more than 24 hours
                            logger.warning(
                                f"Transaction {entry.txid[:16]}... not found after "
                                f"{age_hours:.1f} hours, may have been rejected"
                            )
                            # Could optionally mark as failed here
                        continue

                    confirmations = tx_info.confirmations

                    if confirmations > 0:
                        # Update history with confirmation
                        update_transaction_confirmation(
                            txid=entry.txid,
                            confirmations=confirmations,
                            data_dir=self.config.data_dir,
                        )

                        logger.info(
                            f"CoinJoin {entry.txid[:16]}... confirmed! "
                            f"({confirmations} confirmation{'s' if confirmations != 1 else ''})"
                        )

                except Exception as e:
                    logger.debug(f"Error checking transaction {entry.txid[:16]}...: {e}")

        except Exception as e:
            logger.error(f"Error updating pending history: {e}")

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
                    await self._handle_message(message)

                # Periodic cleanup of timed-out sessions
                now = asyncio.get_event_loop().time()
                if now - last_cleanup > cleanup_interval:
                    self._cleanup_timed_out_sessions()
                    last_cleanup = now

            except asyncio.CancelledError:
                logger.info(f"Listener for {node_id} cancelled")
                break
            except DirectoryClientError as e:
                # Connection lost - exit listener, let reconnection logic handle it
                logger.warning(f"Connection lost on {node_id}: {e}")
                break
            except Exception as e:
                logger.error(f"Error listening on {node_id}: {e}")
                await asyncio.sleep(1.0)

        logger.info(f"Stopped listening on {node_id}")

    async def _handle_message(self, message: dict[str, Any]) -> None:
        """Handle incoming message from directory"""
        try:
            from jmcore.protocol import MessageType

            msg_type = message.get("type")
            line = message.get("line", "")

            if msg_type == MessageType.PRIVMSG.value:
                await self._handle_privmsg(line)
            elif msg_type == MessageType.PUBMSG.value:
                await self._handle_pubmsg(line)
            elif msg_type == MessageType.PEERLIST.value:
                logger.debug(f"Received peerlist: {line[:50]}...")
            else:
                logger.debug(f"Ignoring message type {msg_type}")

        except Exception as e:
            logger.error(f"Failed to handle message: {e}")

    async def _handle_pubmsg(self, line: str) -> None:
        """Handle public message (e.g., !orderbook request)"""
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

    async def _handle_privmsg(self, line: str) -> None:
        """Handle private message (CoinJoin protocol)"""
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
                await self._handle_fill(from_nick, command)
            elif command.startswith("auth"):
                await self._handle_auth(from_nick, command)
            elif command.startswith("tx"):
                await self._handle_tx(from_nick, command)
            elif command.startswith("push"):
                await self._handle_push(from_nick, command)
            elif command.startswith("hp2"):
                # hp2 via privmsg = commitment transfer request
                # We should re-broadcast it publicly to obfuscate the source
                await self._handle_hp2_privmsg(from_nick, command)
            else:
                logger.debug(f"Unknown command: {command[:20]}...")

        except Exception as e:
            logger.error(f"Failed to handle privmsg: {e}")

    async def _handle_fill(self, taker_nick: str, msg: str) -> None:
        """Handle !fill request from taker.

        Fill message format: fill <oid> <amount> <taker_nacl_pk> <commitment> [<signing_pk> <sig>]
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

            if offer_id >= len(self.current_offers):
                logger.warning(f"Invalid offer ID: {offer_id}")
                return

            offer = self.current_offers[offer_id]

            is_valid, error = self.offer_manager.validate_offer_fill(offer, amount)
            if not is_valid:
                logger.warning(f"Invalid fill request: {error}")
                return

            session = CoinJoinSession(
                taker_nick=taker_nick,
                offer=offer,
                wallet=self.wallet,
                backend=self.backend,
                session_timeout_sec=self.config.session_timeout_sec,
                merge_algorithm=self.config.merge_algorithm.value,
            )

            # Pass the taker's NaCl pubkey for setting up encryption
            success, response = await session.handle_fill(amount, commitment, taker_pk)

            if success:
                self.active_sessions[taker_nick] = session
                logger.info(f"Created CoinJoin session with {taker_nick}")

                await self._send_response(taker_nick, "pubkey", response)
            else:
                logger.warning(f"Failed to handle fill: {response.get('error')}")

        except Exception as e:
            logger.error(f"Failed to handle !fill: {e}")

    async def _handle_auth(self, taker_nick: str, msg: str) -> None:
        """Handle !auth request from taker.

        The auth message is ENCRYPTED using NaCl.
        Format: auth <encrypted_base64> [<signing_pk> <sig>]

        After decryption, the plaintext is pipe-separated:
        txid:vout|P|P2|sig|e
        """
        try:
            if taker_nick not in self.active_sessions:
                logger.warning(f"No active session for {taker_nick}")
                return

            session = self.active_sessions[taker_nick]

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
                        f"Invalid revelation format: expected 5 parts, got {len(revelation_parts)}"
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
                del self.active_sessions[taker_nick]

        except Exception as e:
            logger.error(f"Failed to handle !auth: {e}")

    async def _handle_tx(self, taker_nick: str, msg: str) -> None:
        """Handle !tx request from taker.

        The tx message is ENCRYPTED using NaCl.
        Format: tx <encrypted_base64> [<signing_pk> <sig>]

        After decryption, the plaintext is base64-encoded transaction bytes.
        """
        try:
            if taker_nick not in self.active_sessions:
                logger.warning(f"No active session for {taker_nick}")
                return

            session = self.active_sessions[taker_nick]

            logger.info(f"Received !tx from {taker_nick}, decrypting and verifying transaction...")

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
                logger.info(f"CoinJoin with {taker_nick} COMPLETE ✓ (sent {len(signatures)} sigs)")

                # Record transaction in history
                try:
                    fee_received = session.offer.calculate_fee(session.amount)
                    txfee_contribution = session.offer.txfee
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

                del self.active_sessions[taker_nick]

                # Schedule wallet re-sync in background to avoid blocking !push handling
                # The transaction hasn't been broadcast yet, so we should not block here
                asyncio.create_task(self._deferred_wallet_resync())
            else:
                logger.error(f"TX verification failed: {response.get('error')}")
                del self.active_sessions[taker_nick]

        except Exception as e:
            logger.error(f"Failed to handle !tx: {e}")

    async def _handle_push(self, taker_nick: str, msg: str) -> None:
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

    async def _on_direct_connection(self, connection: TCPConnection, peer_str: str) -> None:
        """Handle incoming direct connection from a taker via hidden service.

        Direct connections use a simplified protocol compared to directory messages:
        - Messages are sent as newline-delimited JSON over TCP
        - Format: {"nick": "sender", "cmd": "command", "data": "..."}

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

                    # Parse the message
                    try:
                        message = json.loads(data.decode("utf-8"))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON from {peer_str}: {e}")
                        continue

                    sender_nick = message.get("nick", "unknown")
                    cmd = message.get("cmd", "")
                    msg_data = message.get("data", "")

                    logger.debug(f"Direct message from {sender_nick}: cmd={cmd}")

                    # Track this connection by nick for sending responses
                    if sender_nick != "unknown":
                        self.direct_connections[sender_nick] = connection

                    # Process the command - reuse existing handlers
                    # Commands: fill, auth, tx (same as via directory)
                    full_msg = f"{cmd} {msg_data}" if msg_data else cmd

                    if cmd == "fill":
                        await self._handle_fill(sender_nick, full_msg)
                    elif cmd == "auth":
                        await self._handle_auth(sender_nick, full_msg)
                    elif cmd == "tx":
                        await self._handle_tx(sender_nick, full_msg)
                    elif cmd == "push":
                        await self._handle_push(sender_nick, full_msg)
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
