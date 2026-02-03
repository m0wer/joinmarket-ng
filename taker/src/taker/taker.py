"""
Main Taker class for CoinJoin execution.

Orchestrates the complete CoinJoin protocol:
1. Fetch orderbook from directory nodes
2. Select makers and generate PoDLE commitment
3. Send !fill requests and receive !pubkey responses
4. Send !auth with PoDLE proof and receive !ioauth (maker UTXOs)
5. Build unsigned transaction and send !tx
6. Collect !sig responses and broadcast

Reference: Original joinmarket-clientserver/src/jmclient/taker.py
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Any

from jmcore.bitcoin import calculate_tx_vsize, get_txid
from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmcore.commitment_blacklist import set_blacklist_path
from jmcore.crypto import NickIdentity
from jmcore.deduplication import ResponseDeduplicator
from jmcore.directory_client import DirectoryClient
from jmcore.encryption import CryptoSession
from jmcore.models import Offer
from jmcore.network import OnionPeer
from jmcore.notifications import get_notifier
from jmcore.paths import read_nick_state
from jmcore.protocol import JM_VERSION, NOT_SERVING_ONION_HOSTNAME, parse_utxo_list
from jmwallet.backends.base import BlockchainBackend
from jmwallet.history import (
    TransactionHistoryEntry,
    append_history_entry,
    create_taker_history_entry,
    get_pending_transactions,
    update_taker_awaiting_transaction_broadcast,
    update_transaction_confirmation,
)
from jmwallet.wallet.models import UTXOInfo
from jmwallet.wallet.service import WalletService
from jmwallet.wallet.signing import (
    TransactionSigningError,
    create_p2wpkh_script_code,
    create_witness_stack,
    deserialize_transaction,
    sign_p2wpkh_input,
    verify_p2wpkh_signature,
)
from loguru import logger
from pydantic import ConfigDict, Field
from pydantic.dataclasses import dataclass

from taker.config import BroadcastPolicy, Schedule, TakerConfig
from taker.orderbook import OrderbookManager, calculate_cj_fee
from taker.podle import ExtendedPoDLECommitment
from taker.podle_manager import PoDLEManager
from taker.tx_builder import CoinJoinTxBuilder, build_coinjoin_tx


class MultiDirectoryClient:
    """
    Wrapper for managing multiple DirectoryClient connections.

    Provides a unified interface for connecting to multiple directory servers
    and aggregating orderbook data. Implements multi-directory aware nick
    tracking - a nick is only considered "gone" when ALL directories report
    it as disconnected.

    Direct Peer Connections:
    When enabled (prefer_direct_connections=True), the client will establish
    direct Tor connections to makers when possible, bypassing directory servers
    for private messages. This improves privacy by preventing directories from
    observing who is communicating with whom.

    Connection flow:
    1. First message to a maker goes via directory relay
    2. Opportunistically starts direct connection in background
    3. Subsequent messages prefer direct connection if available
    4. Falls back to directory relay if direct connection fails

    This prevents premature maker removal when:
    - A maker temporarily disconnects from one directory but remains on others
    - Directory connections are flaky or experiencing network issues
    - There's a race condition between directory updates

    Reference: JoinMarket onionmc.py lines 1078-1103
    """

    def __init__(
        self,
        directory_servers: list[str],
        network: str,
        nick_identity: NickIdentity,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        neutrino_compat: bool = False,
        on_nick_leave: Any | None = None,
        prefer_direct_connections: bool = True,
        our_location: str = "NOT-SERVING-ONION",
    ):
        self.directory_servers = directory_servers
        self.network = network
        self.nick_identity = nick_identity
        self.nick = nick_identity.nick
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.neutrino_compat = neutrino_compat
        self.clients: dict[str, DirectoryClient] = {}
        self.on_nick_leave = on_nick_leave

        # Direct peer connection settings
        self.prefer_direct_connections = prefer_direct_connections
        self.our_location = our_location
        # Peer connections indexed by nick
        self._peer_connections: dict[str, OnionPeer] = {}
        # Background tasks for pending connections
        self._pending_connect_tasks: dict[str, asyncio.Task[bool]] = {}

        # Unified message queue for direct peer messages
        # Messages from direct peers are queued here and consumed by wait_for_responses
        self._direct_message_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        # Multi-directory nick tracking
        # Format: active_nicks[nick] = {server1: True, server2: True, ...}
        # True = nick is present on this server, False = gone from this server
        # A nick is only considered completely gone when ALL servers report False
        self._active_nicks: dict[str, dict[str, bool]] = {}

    def _update_nick_status(self, nick: str, server: str, is_present: bool) -> None:
        """
        Update a nick's presence status on a specific directory server.

        If this causes the nick to become completely gone (absent from ALL servers),
        triggers the on_nick_leave callback.
        """
        if nick not in self._active_nicks:
            self._active_nicks[nick] = {}

        old_status = self._active_nicks[nick].get(server)
        self._active_nicks[nick][server] = is_present

        # Check if this update causes the nick to be completely gone
        if not is_present and old_status is True:
            # Nick just disappeared from this directory
            # Check if it's still present on any other directory
            if not any(status for status in self._active_nicks[nick].values()):
                logger.info(
                    f"Nick {nick} has left all directories "
                    f"(servers: {list(self._active_nicks[nick].keys())})"
                )
                if self.on_nick_leave:
                    self.on_nick_leave(nick)
                # Clean up the entry
                del self._active_nicks[nick]
        elif is_present and old_status is False:
            logger.debug(f"Nick {nick} returned to server {server}")

    def is_nick_active(self, nick: str) -> bool:
        """
        Check if a nick is active on at least one directory server.

        Returns:
            True if nick is present on at least one server
        """
        if nick not in self._active_nicks:
            return False
        return any(status for status in self._active_nicks[nick].values())

    def sync_nicks_with_peerlist(self, server: str, active_nicks: set[str]) -> None:
        """
        Synchronize nick tracking with a directory's peerlist.

        This is called after fetching a peerlist from a directory to update
        the nick tracking state. Nicks not in the peerlist are marked as gone
        from that directory.

        Args:
            server: The server identifier reporting the peerlist
            active_nicks: Set of nicks currently active on this server
        """
        # Mark all nicks in the peerlist as present
        for nick in active_nicks:
            self._update_nick_status(nick, server, True)

        # Mark nicks we're tracking but not in this peerlist as gone from this server
        for nick in list(self._active_nicks.keys()):
            if server in self._active_nicks[nick] and nick not in active_nicks:
                self._update_nick_status(nick, server, False)

    # =========================================================================
    # Direct Peer Connection Methods
    # =========================================================================

    def _get_peer_location(self, nick: str) -> str | None:
        """
        Get a maker's onion location from the peerlist.

        Args:
            nick: Maker's JoinMarket nick

        Returns:
            Onion address (host:port) or None if not found/not serving
        """
        for client in self.clients.values():
            location = client._active_peers.get(nick)
            if location and location != NOT_SERVING_ONION_HOSTNAME:
                return location
        return None

    def _should_try_direct_connect(self, nick: str) -> bool:
        """
        Check if we should attempt a direct connection to this peer.

        Returns False if:
        - Direct connections are disabled
        - We already have a connected peer
        - Peer doesn't serve an onion address
        - Connection attempt is already in progress
        """
        if not self.prefer_direct_connections:
            return False

        # Already connected?
        if nick in self._peer_connections:
            peer = self._peer_connections[nick]
            if peer.is_connected() or peer.is_connecting():
                return False

        # Connection attempt in progress?
        if nick in self._pending_connect_tasks:
            task = self._pending_connect_tasks[nick]
            if not task.done():
                return False

        # Has a valid onion address?
        location = self._get_peer_location(nick)
        return location is not None

    def _get_connected_peer(self, nick: str) -> OnionPeer | None:
        """
        Get a connected peer by nick.

        Returns:
            OnionPeer if connected and handshaked, None otherwise
        """
        peer = self._peer_connections.get(nick)
        if peer and peer.is_connected():
            return peer
        return None

    async def _on_peer_message(self, nick: str, data: bytes) -> None:
        """
        Handle message received from a direct peer connection.

        Messages are forwarded to the unified direct message queue for processing
        by wait_for_responses(). The message is enriched with the sender's nick
        to match the format expected by the response processing logic.
        """
        try:
            import json

            msg = json.loads(data.decode("utf-8"))
            logger.debug(f"Received direct message from {nick}: type={msg.get('type')}")

            # Enrich message with sender nick for wait_for_responses to identify
            msg["from_nick"] = nick
            msg["from_direct"] = True

            # Queue for processing by wait_for_responses
            await self._direct_message_queue.put(msg)
        except Exception as e:
            logger.warning(f"Error processing peer message from {nick}: {e}")

    async def _on_peer_disconnect(self, nick: str) -> None:
        """Handle peer disconnection."""
        logger.debug(f"Peer {nick} disconnected")
        # Clean up but don't remove from _peer_connections immediately
        # in case we want to reconnect

    async def _on_peer_handshake_complete(self, nick: str) -> None:
        """Handle successful peer handshake."""
        logger.info(f"Direct connection established with {nick}")

    def _try_direct_connect(self, nick: str) -> None:
        """
        Opportunistically try to establish a direct connection to a maker.

        This is called asynchronously when sending a message via directory relay.
        The connection attempt runs in the background and future messages will
        use the direct connection if it succeeds.
        """
        if not self._should_try_direct_connect(nick):
            return

        location = self._get_peer_location(nick)
        if not location:
            return

        # Create peer if needed
        if nick not in self._peer_connections:
            peer = OnionPeer(
                nick=nick,
                location=location,
                socks_host=self.socks_host,
                socks_port=self.socks_port,
                on_message=self._on_peer_message,
                on_disconnect=self._on_peer_disconnect,
                on_handshake_complete=self._on_peer_handshake_complete,
                nick_identity=self.nick_identity,
            )
            self._peer_connections[nick] = peer
        else:
            peer = self._peer_connections[nick]

        # Start connection in background
        task = peer.try_to_connect(
            our_nick=self.nick,
            our_location=self.our_location,
            network=self.network,
        )
        if task:
            self._pending_connect_tasks[nick] = task
            logger.debug(f"Started background connection to {nick} at {location}")

    async def _cleanup_peer_connections(self) -> None:
        """Clean up all peer connections (called on close)."""
        # Cancel pending connection tasks
        for nick, task in self._pending_connect_tasks.items():
            if not task.done():
                task.cancel()
        self._pending_connect_tasks.clear()

        # Disconnect all peers
        for nick, peer in self._peer_connections.items():
            try:
                await peer.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting from peer {nick}: {e}")
        self._peer_connections.clear()

    async def connect_all(self) -> int:
        """Connect to all directory servers in parallel, return count of successful connections."""

        async def connect_single(server: str) -> tuple[str, DirectoryClient | None]:
            """Connect to a single directory server."""
            try:
                parts = server.split(":")
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 5222

                client = DirectoryClient(
                    host=host,
                    port=port,
                    network=self.network,
                    nick_identity=self.nick_identity,
                    socks_host=self.socks_host,
                    socks_port=self.socks_port,
                    neutrino_compat=self.neutrino_compat,
                )
                await client.connect()
                logger.info(f"Connected to directory server: {server}")
                return (server, client)
            except Exception as e:
                logger.warning(f"Failed to connect to {server}: {e}")
                return (server, None)

        # Connect to all directories in parallel
        tasks = [connect_single(server) for server in self.directory_servers]
        results = await asyncio.gather(*tasks)

        # Collect successful connections
        connected = 0
        for server, client in results:
            if client is not None:
                self.clients[server] = client
                connected += 1

        return connected

    async def close_all(self) -> None:
        """Close all directory and peer connections."""
        # Clean up peer connections first
        await self._cleanup_peer_connections()

        # Close directory connections
        for server, client in self.clients.items():
            try:
                await client.close()
            except Exception as e:
                logger.warning(f"Error closing connection to {server}: {e}")
        self.clients.clear()

    async def fetch_orderbook(self, timeout: float = 120.0) -> list[Offer]:
        """
        Fetch orderbook from all connected directory servers in parallel.

        Trusts the directory's orderbook as authoritative - if a maker has an offer
        in the directory, they are considered online. This avoids incorrectly filtering
        offers as "stale" based on slow peerlist responses.

        Args:
            timeout: Timeout in seconds (default: 120s). Note: The actual timeout is
                    controlled by DirectoryClient.fetch_orderbooks() which uses 120s
                    to capture ~95% of offers based on empirical testing over Tor.
                    The 95th percentile response time is ~101s, so 120s provides a
                    20% safety buffer.
        """
        all_offers: list[Offer] = []
        seen_offers: set[tuple[str, int]] = set()

        async def fetch_from_server(
            server: str, client: DirectoryClient
        ) -> tuple[str, list[Offer]]:
            """Fetch offers from a single directory server."""
            try:
                offers, _bonds = await client.fetch_orderbooks()
                return (server, offers)
            except Exception as e:
                logger.warning(f"Failed to fetch orderbook from {server}: {e}")
                return (server, [])

        # Fetch from all directories in parallel
        tasks = [fetch_from_server(server, client) for server, client in self.clients.items()]
        results = await asyncio.gather(*tasks)

        # Aggregate and deduplicate offers
        for server, offers in results:
            for offer in offers:
                key = (offer.counterparty, offer.oid)
                if key not in seen_offers:
                    seen_offers.add(key)
                    all_offers.append(offer)

        return all_offers

    async def send_privmsg(
        self,
        recipient: str,
        command: str,
        data: str,
        log_routing: bool = False,
        force_channel: str | None = None,
    ) -> str:
        """Send a private message, respecting channel consistency for CoinJoin sessions.

        CRITICAL: Within a single CoinJoin session, all messages to a maker MUST use the
        same communication channel (either direct or a specific directory). Mixing channels
        causes the maker to reject messages as they appear to be from different sessions.

        Message routing priority (when force_channel is None):
        1. Direct peer connection (if connected and prefer_direct_connections=True)
        2. Directory relay (fallback)

        Args:
            recipient: Target maker nick
            command: Command name (without ! prefix)
            data: Command arguments
            log_routing: If True, log detailed routing information
            force_channel: If set, only use this channel:
                - "direct" = peer-to-peer onion connection
                - "directory:<host>:<port>" = relay through specific directory

        Returns:
            Channel used: "direct" or "directory:<host>:<port>"
        """
        # Get maker's direct onion location if available
        maker_location = self._get_peer_location(recipient)

        # If force_channel is set, use only that channel
        if force_channel:
            if force_channel == "direct":
                peer = self._get_connected_peer(recipient)
                if not peer:
                    raise RuntimeError(
                        f"Forced to use direct channel but no connection to {recipient}"
                    )
                success = await peer.send_privmsg(self.nick, command, data)
                if not success:
                    raise RuntimeError(f"Failed to send to {recipient} via direct connection")
                if log_routing:
                    logger.debug(
                        f"Sent !{command} to {recipient} via DIRECT connection "
                        f"(onion: {maker_location})"
                    )
                return "direct"
            elif force_channel.startswith("directory:"):
                # Extract host:port from "directory:host:port"
                server = force_channel[10:]  # Skip "directory:"
                client = self.clients.get(server)
                if not client:
                    raise RuntimeError(f"Forced to use directory {server} but not connected")
                await client.send_private_message(recipient, command, data)
                if log_routing:
                    logger.debug(
                        f"Sent !{command} to {recipient} via directory {server} "
                        f"(maker onion: {maker_location}, using relay)"
                    )
                return force_channel
            else:
                raise ValueError(f"Invalid force_channel: {force_channel}")

        # No forced channel - choose best available
        # Try direct connection first if available
        if self.prefer_direct_connections:
            peer = self._get_connected_peer(recipient)
            if peer:
                try:
                    success = await peer.send_privmsg(self.nick, command, data)
                    if success:
                        if log_routing:
                            logger.debug(
                                f"Sent !{command} to {recipient} via DIRECT connection "
                                f"(onion: {maker_location})"
                            )
                        return "direct"
                except Exception as e:
                    logger.debug(f"Direct send to {recipient} failed: {e}")

        # Fall back to directory relay
        # Opportunistically start direct connection for future messages
        if self.prefer_direct_connections and maker_location:
            self._try_direct_connect(recipient)

        # Identify valid directories for this recipient
        target_directories = []

        # Check active nicks tracking first
        if recipient in self._active_nicks:
            for server, is_active in self._active_nicks[recipient].items():
                if is_active and server in self.clients:
                    target_directories.append(server)

        # If not found in tracking (e.g. startup race), try all clients that list the peer
        if not target_directories:
            for server, client in self.clients.items():
                if recipient in client._active_peers:
                    target_directories.append(server)

        # If still not found, fall back to all connected clients (broadcast)
        if not target_directories:
            target_directories = list(self.clients.keys())

        # Shuffle to load balance
        import random

        random.shuffle(target_directories)

        # Send via the first working directory
        # We strictly send to ONE directory to avoid message duplication
        for server in target_directories:
            client = self.clients.get(server)
            if not client:
                continue

            try:
                await client.send_private_message(recipient, command, data)
                if log_routing:
                    directory = f"{client.host}:{client.port}"
                    if maker_location:
                        logger.debug(
                            f"Sent !{command} to {recipient} via directory {directory} "
                            f"(maker onion: {maker_location}, using relay)"
                        )
                    else:
                        logger.debug(f"Sent !{command} to {recipient} via directory {directory}")
                # Success - return the channel used
                return f"directory:{server}"
            except Exception as e:
                logger.warning(f"Failed to send privmsg via {server}: {e}")

        raise RuntimeError(f"Failed to send !{command} to {recipient} via any directory")

    async def wait_for_responses(
        self,
        expected_nicks: list[str],
        expected_command: str,
        timeout: float = 60.0,
        expected_counts: dict[str, int] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Wait for responses from multiple makers at once.

        Listens for responses from BOTH:
        - Directory server message streams (via client.listen_for_messages())
        - Direct peer connections (via self._direct_message_queue)

        Returns a dict of nick -> response data for all makers that responded.
        Responses can include:
        - Normal responses matching expected_command
        - Error responses marked with "error": True

        Error handling:
        - Makers may send !error messages instead of the expected response
        - These indicate protocol failures (e.g., blacklisted PoDLE commitment)
        - Errors are returned in the response dict with {"error": True, "data": "reason"}

        Deduplication:
        - When connected to multiple directory servers, the same response may arrive
          multiple times. ResponseDeduplicator tracks which responses we've seen
          and logs duplicates for debugging.

        Special handling for !sig:
        - Makers send multiple !sig messages (one per UTXO)
        - We accumulate all messages in a list instead of keeping just the last one
        - Use expected_counts to specify how many signatures to expect per maker
        - Returns as soon as all expected signatures are received

        Args:
            expected_nicks: List of maker nicks to expect responses from
            expected_command: Command to wait for (e.g., "!pubkey", "!sig")
            timeout: Maximum time to wait in seconds
            expected_counts: For !sig, dict of nick -> expected signature count
        """
        # Track if this command expects multiple messages per maker
        accumulate_responses = expected_command == "!sig"

        responses: dict[str, dict[str, Any]] = {}
        remaining_nicks = set(expected_nicks)
        deduplicator = ResponseDeduplicator()
        start_time = asyncio.get_event_loop().time()

        def is_complete() -> bool:
            """Check if we have all expected responses."""
            if remaining_nicks:
                return False
            if accumulate_responses and expected_counts:
                # For !sig, check if we have all expected signatures
                for nick, expected in expected_counts.items():
                    if nick not in responses:
                        return False
                    received = len(responses[nick].get("data", []))
                    if received < expected:
                        return False
            return True

        def process_message(msg: dict[str, Any], source: str) -> None:
            """Process a single message from any source (directory or direct)."""
            nonlocal responses, remaining_nicks

            line = msg.get("line", "")
            if not line:
                return

            # Check for !error messages from any of our expected nicks
            if "!error" in line:
                for nick in list(remaining_nicks):
                    if nick in line:
                        # Deduplicate error responses too
                        if not deduplicator.add_response(nick, "error", line, source):
                            logger.debug(f"Duplicate !error from {nick} via {source}")
                            break
                        # Extract error message after !error
                        parts = line.split("!error", 1)
                        error_msg = parts[1].strip() if len(parts) > 1 else "Unknown error"
                        responses[nick] = {"error": True, "data": error_msg}
                        remaining_nicks.discard(nick)
                        logger.warning(f"Received !error from {nick}: {error_msg}")
                        break
                return

            # Parse the message to find sender and command
            if expected_command not in line:
                return

            # Match against expected nicks (not just remaining)
            for nick in expected_nicks:
                if nick in line:
                    # For accumulating responses (like !sig), skip deduplication
                    # since we expect multiple messages from the same maker
                    if not accumulate_responses:
                        # Check for duplicate response from another directory
                        if not deduplicator.add_response(nick, expected_command, line, source):
                            logger.debug(f"Duplicate {expected_command} from {nick} via {source}")
                            break

                    # Extract data after the command
                    parts = line.split(expected_command, 1)
                    if len(parts) > 1:
                        data = parts[1].strip()
                        if accumulate_responses:
                            # Accumulate multiple !sig messages
                            if nick not in responses:
                                responses[nick] = {"data": []}
                                remaining_nicks.discard(nick)
                            responses[nick]["data"].append(data)
                            logger.debug(
                                f"Received {expected_command} "
                                f"#{len(responses[nick]['data'])} "
                                f"from {nick} via {source}"
                            )
                        else:
                            # Single response (original behavior)
                            responses[nick] = {"data": data}
                            remaining_nicks.discard(nick)
                            logger.debug(f"Received {expected_command} from {nick} via {source}")
                    break

        while not is_complete():
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= timeout:
                if not accumulate_responses:
                    logger.warning(
                        f"Timeout waiting for {expected_command} from: {remaining_nicks}"
                    )
                elif expected_counts:
                    # Log which makers haven't sent all signatures
                    for nick, expected in expected_counts.items():
                        received = len(responses.get(nick, {}).get("data", []))
                        if received < expected:
                            logger.warning(f"Timeout: {nick} sent {received}/{expected} signatures")
                break

            remaining_time = min(5.0, timeout - elapsed)  # Listen in 5s chunks

            # First, drain any pending direct peer messages (non-blocking)
            while True:
                try:
                    msg = self._direct_message_queue.get_nowait()
                    process_message(msg, "direct")
                except asyncio.QueueEmpty:
                    break

            # Check if we have everything after processing direct messages
            if is_complete():
                break

            # Listen to all directory clients concurrently for shorter duration
            # Use 1s chunks to allow more frequent checking of direct message queue
            listen_duration = min(1.0, remaining_time)

            async def listen_to_client(
                server: str, client: DirectoryClient
            ) -> list[tuple[str, dict[str, Any]]]:
                try:
                    messages = await client.listen_for_messages(duration=listen_duration)
                    return [(server, msg) for msg in messages]
                except Exception as e:
                    logger.debug(f"Error listening to {server}: {e}")
                    return []

            # Gather messages from all directories concurrently
            results = await asyncio.gather(
                *[listen_to_client(s, c) for s, c in self.clients.items()]
            )
            for result_list in results:
                for server, msg in result_list:
                    process_message(msg, f"directory:{server}")

        # Log deduplication stats if there were duplicates
        stats = deduplicator.stats
        if stats.duplicates_dropped > 0:
            logger.debug(
                f"Response deduplication: {stats.unique_messages} unique, "
                f"{stats.duplicates_dropped} duplicates dropped "
                f"({stats.duplicate_rate:.1f}% duplicate rate)"
            )

        return responses

    async def wait_for_response(
        self,
        from_nick: str,
        expected_command: str,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """Wait for a specific response from a maker (legacy method)."""
        responses = await self.wait_for_responses([from_nick], expected_command, timeout)
        return responses.get(from_nick)


class TakerState(str, Enum):
    """Taker protocol states."""

    IDLE = "idle"
    FETCHING_ORDERBOOK = "fetching_orderbook"
    SELECTING_MAKERS = "selecting_makers"
    FILLING = "filling"
    AUTHENTICATING = "authenticating"
    BUILDING_TX = "building_tx"
    COLLECTING_SIGNATURES = "collecting_signatures"
    BROADCASTING = "broadcasting"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"  # User cancelled the operation


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class MakerSession:
    """Session data for a single maker."""

    nick: str
    offer: Offer
    utxos: list[dict[str, Any]] = Field(default_factory=list)
    cj_address: str = ""
    change_address: str = ""
    pubkey: str = ""  # Maker's NaCl public key (hex)
    auth_pubkey: str = ""  # Maker's EC auth public key from !ioauth (hex)
    crypto: CryptoSession | None = None  # Encryption session with this maker
    signature: dict[str, Any] | None = None
    responded_fill: bool = False
    responded_auth: bool = False
    responded_sig: bool = False
    supports_neutrino_compat: bool = False  # Supports extended UTXO metadata for Neutrino
    # Communication channel used for this session (must be consistent throughout)
    # "direct" = peer-to-peer onion connection
    # "directory:<host>:<port>" = relayed through specific directory
    comm_channel: str = ""


@dataclass
class PhaseResult:
    """Result from a CoinJoin phase with failed maker tracking.

    Used to communicate phase outcomes and enable maker replacement logic.
    """

    success: bool
    failed_makers: list[str] = Field(default_factory=list)
    blacklist_error: bool = False  # True if any maker rejected due to blacklisted commitment

    @property
    def needs_replacement(self) -> bool:
        """True if phase failed due to non-responsive makers (not other errors)."""
        return not self.success and len(self.failed_makers) > 0


class Taker:
    """
    Main Taker class for executing CoinJoin transactions.
    """

    def __init__(
        self,
        wallet: WalletService,
        backend: BlockchainBackend,
        config: TakerConfig,
        confirmation_callback: Any | None = None,
    ):
        """
        Initialize the Taker.

        Args:
            wallet: Wallet service for UTXO management and signing
            backend: Blockchain backend for broadcasting
            config: Taker configuration
            confirmation_callback: Optional callback for user confirmation before proceeding
        """
        self.wallet = wallet
        self.backend = backend
        self.config = config
        self.confirmation_callback = confirmation_callback

        self.nick_identity = NickIdentity(JM_VERSION)
        self.nick = self.nick_identity.nick
        self.state = TakerState.IDLE

        # Advertise neutrino_compat if our backend can provide extended UTXO metadata.
        # This tells other peers that we can provide scriptpubkey and blockheight.
        # Full nodes (Bitcoin Core) can provide this; light clients (Neutrino) cannot.
        neutrino_compat = backend.can_provide_neutrino_metadata()

        # Directory client
        self.directory_client = MultiDirectoryClient(
            directory_servers=config.directory_servers,
            network=config.network.value,
            nick_identity=self.nick_identity,
            socks_host=config.socks_host,
            socks_port=config.socks_port,
            neutrino_compat=neutrino_compat,
        )

        # Orderbook manager
        # Read maker nick from state file to exclude from peer selection (self-CoinJoin protection)
        own_wallet_nicks: set[str] = set()
        maker_nick = read_nick_state(config.data_dir, "maker")
        if maker_nick:
            own_wallet_nicks.add(maker_nick)
            logger.info(f"Self-CoinJoin protection: excluding maker nick {maker_nick}")

        self.orderbook_manager = OrderbookManager(
            config.max_cj_fee,
            bondless_makers_allowance=config.bondless_makers_allowance,
            bondless_require_zero_fee=config.bondless_makers_allowance_require_zero_fee,
            data_dir=config.data_dir,
            own_wallet_nicks=own_wallet_nicks,
        )

        # PoDLE manager for commitment tracking
        self.podle_manager = PoDLEManager(config.data_dir)

        # Current CoinJoin session data
        self.cj_amount = 0
        self.is_sweep = False  # True when amount=0 (sweep mode, no change output)
        self.maker_sessions: dict[str, MakerSession] = {}
        self.podle_commitment: ExtendedPoDLECommitment | None = None
        self.unsigned_tx: bytes = b""
        self.tx_metadata: dict[str, Any] = {}
        self.final_tx: bytes = b""
        self.txid: str = ""
        self.preselected_utxos: list[UTXOInfo] = []  # UTXOs pre-selected for CoinJoin
        self.selected_utxos: list[UTXOInfo] = []  # Taker's final selected UTXOs for signing
        self.cj_destination: str = ""  # Taker's CJ destination address for broadcast verification
        self.taker_change_address: str = ""  # Taker's change address for broadcast verification
        # For sweeps: store the tx_fee budget calculated at order selection time
        # This is the amount reserved for tx fees when calculating cj_amount.
        # At build time, we use this budget (not a new estimate) to ensure the
        # actual tx fee matches what was budgeted, preventing residual fee issues.
        self._sweep_tx_fee_budget: int = 0

        # E2E encryption session for communication with makers
        self.crypto_session: CryptoSession | None = None

        # Schedule for tumbler-style operations
        self.schedule: Schedule | None = None

        # Cached fee rate for the current CoinJoin (set in _resolve_fee_rate)
        # This is the base rate from backend estimation or manual config
        self._fee_rate: float | None = None
        # Randomized fee rate for this CoinJoin session (set once in _resolve_fee_rate)
        # This applies tx_fee_factor randomization and is used for all fee calculations
        self._randomized_fee_rate: float | None = None

        # Background task tracking
        self.running = False
        self._background_tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Start the taker and connect to directory servers."""
        logger.info(f"Starting taker (nick: {self.nick})")

        # Log wallet name if using descriptor wallet backend
        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

        if isinstance(self.backend, DescriptorWalletBackend):
            logger.info(f"Using wallet: {self.backend.wallet_name}")

        # Initialize commitment blacklist with configured data directory
        set_blacklist_path(data_dir=self.config.data_dir)

        # Sync wallet
        logger.info("Syncing wallet...")

        # Setup descriptor wallet if needed (one-time operation)
        if isinstance(self.backend, DescriptorWalletBackend):
            if not await self.wallet.is_descriptor_wallet_ready():
                logger.info("Descriptor wallet not set up. Importing descriptors...")
                await self.wallet.setup_descriptor_wallet(rescan=True)
                logger.info("Descriptor wallet setup complete")

            # Use fast descriptor wallet sync
            await self.wallet.sync_with_descriptor_wallet()
        else:
            # Use standard sync (scantxoutset for scantxoutset, BIP157/158 for neutrino)
            await self.wallet.sync_all()

        total_balance = await self.wallet.get_total_balance()
        logger.info(f"Wallet synced. Total balance: {total_balance:,} sats")

        # Connect to directory servers
        logger.info("Connecting to directory servers...")
        connected = await self.directory_client.connect_all()

        if connected == 0:
            raise RuntimeError("Failed to connect to any directory server")

        logger.info(f"Connected to {connected} directory servers")

        # Mark as running and start background tasks
        self.running = True

        # Start pending transaction monitor
        monitor_task = asyncio.create_task(self._monitor_pending_transactions())
        self._background_tasks.append(monitor_task)

        # Start periodic rescan task (useful for schedule mode)
        rescan_task = asyncio.create_task(self._periodic_rescan())
        self._background_tasks.append(rescan_task)

        # Start periodic directory connection status logging task
        conn_status_task = asyncio.create_task(self._periodic_directory_connection_status())
        self._background_tasks.append(conn_status_task)

    async def stop(self) -> None:
        """Stop the taker and close connections."""
        logger.info("Stopping taker...")
        self.running = False

        # Cancel all background tasks
        for task in self._background_tasks:
            task.cancel()

        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()

        await self.directory_client.close_all()
        await self.wallet.close()
        logger.info("Taker stopped")

    async def _monitor_pending_transactions(self) -> None:
        """
        Background task to monitor pending transactions and update their status.

        Checks pending transactions every 60 seconds and updates their confirmation
        status in the history file. Transactions are marked as successful once they
        receive their first confirmation.

        Neutrino-specific behavior:
        - Neutrino cannot fetch arbitrary transactions by txid (get_transaction returns None)
        - Instead, we use verify_tx_output() with the destination address hint
        - This uses compact block filters to check if the output exists in confirmed blocks
        - For Neutrino, we must wait for confirmation before we can verify the transaction
        """
        logger.info("Starting pending transaction monitor...")
        check_interval = 60.0  # Check every 60 seconds
        has_mempool = self.backend.has_mempool_access()

        if not has_mempool:
            logger.info(
                "Backend has no mempool access (Neutrino). "
                "Pending transactions will be verified via block confirmation only."
            )

        while self.running:
            try:
                await asyncio.sleep(check_interval)

                if not self.running:
                    break

                pending = get_pending_transactions(data_dir=self.config.data_dir)
                if not pending:
                    continue

                logger.debug(f"Checking {len(pending)} pending transaction(s)...")

                for entry in pending:
                    if not entry.txid:
                        continue

                    try:
                        if has_mempool:
                            # Full node / Mempool API: can get transaction directly
                            await self._check_pending_with_mempool(entry)
                        else:
                            # Neutrino: must use address-based verification
                            await self._check_pending_without_mempool(entry)

                    except Exception as e:
                        logger.debug(f"Error checking transaction {entry.txid[:16]}...: {e}")

            except asyncio.CancelledError:
                logger.info("Pending transaction monitor cancelled")
                break
            except Exception as e:
                logger.error(f"Error in pending transaction monitor: {e}")

        logger.info("Pending transaction monitor stopped")

    async def _check_pending_with_mempool(self, entry: TransactionHistoryEntry) -> None:
        """Check pending transaction status using get_transaction (requires mempool access)."""
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
            return

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

    async def _check_pending_without_mempool(self, entry: TransactionHistoryEntry) -> None:
        """Check pending transaction status without mempool access (Neutrino).

        Uses verify_tx_output() with the destination address to check if the
        CoinJoin output has been confirmed in a block. This works because
        Neutrino compact block filters can match on addresses.

        Note: This cannot detect unconfirmed transactions, so we must wait
        for block confirmation. The transaction may be in mempool but we
        won't know until it's mined.
        """
        from datetime import datetime

        # Need destination address for Neutrino verification
        if not entry.destination_address:
            logger.debug(
                f"Transaction {entry.txid[:16]}... has no destination_address, "
                "cannot verify with Neutrino"
            )
            return

        # Get current block height for efficient scanning
        try:
            current_height = await self.backend.get_block_height()
        except Exception:
            current_height = None

        # Try to verify the CJ output exists in a confirmed block
        # We use vout=0 as a guess for the CJ output position, but this may not be accurate
        # A more robust solution would store the vout in history
        # For now, we rely on the fact that if the address has a UTXO with this txid,
        # the transaction is confirmed
        verified = await self.backend.verify_tx_output(
            txid=entry.txid,
            vout=0,  # CJ outputs are typically first, but this is a guess
            address=entry.destination_address,
            start_height=current_height,
        )

        if verified:
            # Transaction output found in a confirmed block
            # We don't know exact confirmation count with Neutrino, assume 1
            update_transaction_confirmation(
                txid=entry.txid,
                confirmations=1,  # We know it's confirmed but not exact count
                data_dir=self.config.data_dir,
            )

            logger.info(
                f"CoinJoin {entry.txid[:16]}... confirmed! (verified via Neutrino block filters)"
            )
        else:
            # Not found yet - could be in mempool or not broadcast
            timestamp = datetime.fromisoformat(entry.timestamp)
            age_hours = (datetime.now() - timestamp).total_seconds() / 3600

            # For Neutrino, be more patient before warning since we can't see mempool
            # Only log at WARNING level if it's been a long time, otherwise DEBUG to reduce noise
            if age_hours > 10:  # 10 hour timeout for Neutrino
                logger.warning(
                    f"Transaction {entry.txid[:16]}... not confirmed after "
                    f"{age_hours:.1f} hours. May still be in mempool (not visible to Neutrino) "
                    "or may have been rejected/never broadcast."
                )
            elif age_hours > 1:  # Log at debug for txs older than 1 hour
                logger.debug(
                    f"Transaction {entry.txid[:16]}... not confirmed after "
                    f"{age_hours:.1f} hours (may be in mempool, waiting for confirmation)"
                )

    async def _update_pending_transaction_now(
        self, txid: str, destination_address: str | None = None
    ) -> None:
        """
        Immediately check and update a pending transaction's status.

        This is called right after recording a new transaction in history to check
        if it's already visible in mempool (for full nodes) or confirmed (for Neutrino).
        This is important for one-shot coinjoin CLI calls that exit immediately after
        broadcast without waiting for the background monitor.

        Args:
            txid: Transaction ID to check
            destination_address: Optional destination address (needed for Neutrino)
        """
        try:
            has_mempool = self.backend.has_mempool_access()

            if has_mempool:
                # Full node: can check mempool directly
                tx_info = await self.backend.get_transaction(txid)
                if tx_info is not None:
                    confirmations = tx_info.confirmations
                    if confirmations >= 0:
                        # Transaction is in mempool (0 confs) or confirmed (>0 confs)
                        # Mark as success even with 0 confs (mempool visible)
                        update_transaction_confirmation(
                            txid=txid,
                            confirmations=max(confirmations, 1),
                            data_dir=self.config.data_dir,
                        )
                        if confirmations > 0:
                            logger.info(
                                f"CoinJoin {txid[:16]}... already confirmed "
                                f"({confirmations} confirmation{'s' if confirmations != 1 else ''})"
                            )
                        else:
                            logger.info(f"CoinJoin {txid[:16]}... visible in mempool")
            else:
                # Neutrino: can only check confirmed blocks, not mempool
                # For Neutrino, we need to wait for block confirmation
                # This will be handled by the background monitor on next startup
                if destination_address:
                    try:
                        current_height = await self.backend.get_block_height()
                    except Exception:
                        current_height = None

                    verified = await self.backend.verify_tx_output(
                        txid=txid,
                        vout=0,  # CJ outputs are typically first
                        address=destination_address,
                        start_height=current_height,
                    )

                    if verified:
                        update_transaction_confirmation(
                            txid=txid,
                            confirmations=1,
                            data_dir=self.config.data_dir,
                        )
                        logger.info(f"CoinJoin {txid[:16]}... confirmed via Neutrino block filters")
                    else:
                        logger.debug(
                            f"CoinJoin {txid[:16]}... not yet confirmed "
                            "(may be in mempool, Neutrino will verify on next block)"
                        )
        except Exception as e:
            logger.debug(f"Could not update transaction status immediately: {e}")

    async def _periodic_rescan(self) -> None:
        """Background task to periodically rescan wallet.

        This runs every `rescan_interval_sec` (default: 10 minutes) to:
        1. Detect confirmed transactions
        2. Update wallet balance after external transactions
        3. Update pending transaction status

        This is useful when running schedule/tumbler mode to ensure wallet
        state is fresh between CoinJoins.
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

                # Use fast descriptor wallet sync if available
                from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

                if isinstance(self.backend, DescriptorWalletBackend):
                    await self.wallet.sync_with_descriptor_wallet()
                else:
                    await self.wallet.sync_all()

                total_balance = await self.wallet.get_total_balance()
                logger.info(f"Wallet re-synced. Total balance: {total_balance:,} sats")

            except asyncio.CancelledError:
                logger.info("Periodic rescan task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic rescan: {e}")

        logger.info("Periodic rescan task stopped")

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
                total_servers = len(self.directory_client.directory_servers)
                connected_servers = list(self.directory_client.clients.keys())
                connected_count = len(connected_servers)
                disconnected_servers = [
                    server
                    for server in self.directory_client.directory_servers
                    if server not in connected_servers
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

    async def _update_offers_with_bond_values(self, offers: list[Offer]) -> None:
        """
        Verify fidelity bonds and calculate their values.

        Fetches bond UTXO data from the backend and updates offer.fidelity_bond_value.
        """
        # Identify unique bond UTXOs
        bond_utxos = set()
        for offer in offers:
            if offer.fidelity_bond_data and offer.fidelity_bond_value == 0:
                txid = offer.fidelity_bond_data["utxo_txid"]
                vout = offer.fidelity_bond_data["utxo_vout"]
                bond_utxos.add((txid, vout))

        if not bond_utxos:
            return

        logger.info(f"Verifying {len(bond_utxos)} fidelity bonds...")

        # Get current block height and time once
        try:
            current_height = await self.backend.get_block_height()
            current_time = int(time.time())
        except Exception as e:
            logger.warning(f"Failed to get blockchain info for bond verification: {e}")
            return

        # Fetch UTXOs in parallel
        semaphore = asyncio.Semaphore(10)

        async def process_bond(txid: str, vout: int) -> tuple[str, int, tuple[int, int] | None]:
            async with semaphore:
                try:
                    utxo = await self.backend.get_utxo(txid, vout)
                    if not utxo or utxo.confirmations <= 0:
                        return (txid, vout, None)

                    # Calculate confirmation time
                    # Use block height to estimate time if exact block time unavailable
                    conf_height = current_height - utxo.confirmations + 1
                    try:
                        conf_time = await self.backend.get_block_time(conf_height)
                    except Exception:
                        # Fallback if block time fetch fails
                        # Estimate: current_time - (confirmations * 10 mins)
                        conf_time = current_time - (utxo.confirmations * 600)

                    return (txid, vout, (utxo.value, conf_time))
                except Exception as e:
                    logger.debug(f"Failed to verify bond {txid}:{vout}: {e}")
                    return (txid, vout, None)

        tasks = [process_bond(txid, vout) for txid, vout in bond_utxos]
        results = await asyncio.gather(*tasks)

        # Build map of (txid, vout) -> (value, conf_time)
        bond_info = {}
        for txid, vout, info in results:
            if info:
                bond_info[(txid, vout)] = info

        # Update offers
        updated_count = 0

        for offer in offers:
            if offer.fidelity_bond_data and offer.fidelity_bond_value == 0:
                txid = offer.fidelity_bond_data["utxo_txid"]
                vout = offer.fidelity_bond_data["utxo_vout"]
                locktime = offer.fidelity_bond_data["locktime"]

                if (txid, vout) in bond_info:
                    utxo_value, conf_time = bond_info[(txid, vout)]

                    bond_value = calculate_timelocked_fidelity_bond_value(
                        utxo_value=utxo_value,
                        confirmation_time=conf_time,
                        locktime=locktime,
                        current_time=current_time,
                    )

                    if bond_value > 0:
                        offer.fidelity_bond_value = bond_value
                        updated_count += 1

        logger.info(f"Updated {updated_count} offers with verified fidelity bond values")

    async def do_coinjoin(
        self,
        amount: int,
        destination: str,
        mixdepth: int = 0,
        counterparty_count: int | None = None,
    ) -> str | None:
        """
        Execute a single CoinJoin transaction.

        Args:
            amount: Amount in satoshis (0 for sweep)
            destination: Destination address ("INTERNAL" for next mixdepth)
            mixdepth: Source mixdepth
            counterparty_count: Number of makers (default from config)

        Returns:
            Transaction ID if successful, None otherwise
        """
        try:
            n_makers = counterparty_count or self.config.counterparty_count

            # Determine destination address
            if destination == "INTERNAL":
                dest_mixdepth = (mixdepth + 1) % self.wallet.mixdepth_count
                # Use internal chain (/1) for CoinJoin outputs, not external (/0)
                # This matches the reference implementation behavior where all JM-generated
                # addresses (CJ outputs and change) use the internal branch
                dest_index = self.wallet.get_next_address_index(dest_mixdepth, 1)
                destination = self.wallet.get_change_address(dest_mixdepth, dest_index)
                logger.info(f"Using internal address: {destination}")

            # Resolve fee rate early (before any fee estimation calls)
            try:
                await self._resolve_fee_rate()
            except ValueError as e:
                logger.error(str(e))
                self.state = TakerState.FAILED
                return None

            # Track if this is a sweep (no change) transaction
            self.is_sweep = amount == 0

            # Select UTXOs from wallet BEFORE fetching orderbook to avoid wasting user's time
            logger.info(f"Selecting UTXOs from mixdepth {mixdepth}...")

            # Interactive UTXO selection if requested
            manually_selected_utxos: list[UTXOInfo] | None = None
            if self.config.select_utxos:
                from jmwallet.history import get_utxo_label
                from jmwallet.utxo_selector import select_utxos_interactive

                try:
                    # Get all eligible UTXOs for selection
                    available_utxos = self.wallet.get_all_utxos(
                        mixdepth, self.config.taker_utxo_age
                    )
                    if not available_utxos:
                        logger.error(f"No eligible UTXOs in mixdepth {mixdepth}")
                        self.state = TakerState.FAILED
                        return None

                    # Populate labels for each UTXO based on history
                    for utxo in available_utxos:
                        utxo.label = get_utxo_label(utxo.address, self.config.data_dir)

                    logger.info(
                        f"Launching interactive UTXO selector ({len(available_utxos)} available, "
                        f"target amount: {amount} sats, sweep: {amount == 0})..."
                    )
                    manually_selected_utxos = select_utxos_interactive(available_utxos, amount)

                    if not manually_selected_utxos:
                        logger.info("UTXO selection cancelled by user")
                        self.state = TakerState.CANCELLED
                        return None

                    total_selected = sum(u.value for u in manually_selected_utxos)
                    logger.info(
                        f"Manually selected {len(manually_selected_utxos)} UTXOs "
                        f"(total: {total_selected:,} sats)"
                    )

                    # Validate selected UTXOs have sufficient funds (for non-sweep)
                    if amount > 0 and total_selected < amount:
                        logger.error(
                            f"Insufficient funds in selected UTXOs: "
                            f"have {total_selected:,} sats, need at least {amount:,} sats"
                        )
                        self.state = TakerState.FAILED
                        return None
                except RuntimeError as e:
                    logger.error(f"Interactive UTXO selection failed: {e}")
                    self.state = TakerState.FAILED
                    return None
            else:
                logger.debug("Interactive UTXO selection not requested (--select-utxos not set)")

            # Now fetch orderbook after UTXO selection is done
            self.state = TakerState.FETCHING_ORDERBOOK
            logger.info("Fetching orderbook...")
            offers = await self.directory_client.fetch_orderbook(self.config.order_wait_time)

            # Verify and calculate fidelity bond values
            await self._update_offers_with_bond_values(offers)

            self.orderbook_manager.update_offers(offers)

            if len(offers) < n_makers:
                logger.error(f"Not enough offers: need {n_makers}, found {len(offers)}")
                self.state = TakerState.FAILED
                return None

            # NOTE: Neutrino takers require makers that support extended UTXO metadata
            # (scriptPubKey + blockheight). This is negotiated during the CoinJoin handshake
            # via the neutrino_compat feature in the !pubkey response. All peers use v5
            # protocol; feature support is advertised separately for smooth rollout.
            # Incompatible makers (no neutrino_compat) are filtered during _phase_auth().
            if self.backend.requires_neutrino_metadata():
                logger.info("Neutrino backend: will negotiate neutrino_compat during handshake")

            self.state = TakerState.SELECTING_MAKERS

            if self.is_sweep:
                # SWEEP MODE: Select ALL UTXOs and calculate exact cj_amount for zero change
                logger.info("Sweep mode: selecting UTXOs from mixdepth")

                # Use manually selected UTXOs if available, otherwise get all UTXOs
                if manually_selected_utxos:
                    self.preselected_utxos = manually_selected_utxos
                    logger.info(
                        f"Sweep using {len(manually_selected_utxos)} manually selected UTXOs "
                        f"(--select-utxos was used)"
                    )
                else:
                    # Get ALL UTXOs from the mixdepth (default sweep behavior)
                    self.preselected_utxos = self.wallet.get_all_utxos(
                        mixdepth, self.config.taker_utxo_age
                    )
                    logger.info(
                        f"Sweep using all {len(self.preselected_utxos)} UTXOs from mixdepth "
                        f"(no --select-utxos)"
                    )

                if not self.preselected_utxos:
                    logger.error(f"No eligible UTXOs in mixdepth {mixdepth}")
                    self.state = TakerState.FAILED
                    return None

                total_input_value = sum(u.value for u in self.preselected_utxos)
                logger.info(
                    f"Sweep: {len(self.preselected_utxos)} UTXOs, "
                    f"total value: {total_input_value:,} sats"
                )

                # Estimate tx fee for sweep order calculation
                # Conservative estimate: 2 inputs per maker + buffer for edge cases
                # Most makers have 1-2 inputs, but occasionally one might have 6+.
                # The buffer (5 inputs) covers the edge case without being excessive.
                # If actual < estimated: extra goes to miner (acceptable)
                # If actual > estimated: CoinJoin fails with negative residual error
                maker_inputs_per_maker = 2
                maker_inputs_buffer = 5  # Extra inputs to handle edge cases
                estimated_inputs = (
                    len(self.preselected_utxos)
                    + n_makers * maker_inputs_per_maker
                    + maker_inputs_buffer
                )
                # CJ outputs + maker changes (no taker change in sweep!)
                estimated_outputs = 1 + n_makers + n_makers
                # For sweeps, use base rate for deterministic budget calculation.
                # The cj_amount is calculated based on this budget, so it must match
                # exactly at build time. Using randomized rate would cause residual fees.
                estimated_tx_fee = self._estimate_tx_fee(
                    estimated_inputs, estimated_outputs, use_base_rate=True
                )

                # Store the tx fee budget for use at build time.
                # This is critical: the cj_amount is calculated based on this budget,
                # so we MUST use this same value at build time to avoid residual fees.
                self._sweep_tx_fee_budget = estimated_tx_fee

                # Use sweep order selection - this calculates exact cj_amount for zero change
                selected_offers, self.cj_amount, total_fee = (
                    self.orderbook_manager.select_makers_for_sweep(
                        total_input_value=total_input_value,
                        my_txfee=estimated_tx_fee,
                        n=n_makers,
                    )
                )

                if len(selected_offers) < self.config.minimum_makers:
                    logger.error(f"Not enough makers for sweep: {len(selected_offers)}")
                    self.state = TakerState.FAILED
                    return None

                logger.info(f"Sweep: cj_amount={self.cj_amount:,} sats calculated for zero change")

            else:
                # NORMAL MODE: Select minimum UTXOs needed
                self.cj_amount = amount
                logger.info(f"Selecting {n_makers} makers for {self.cj_amount:,} sats...")

                selected_offers, total_fee = self.orderbook_manager.select_makers(
                    cj_amount=self.cj_amount,
                    n=n_makers,
                )

                if len(selected_offers) < self.config.minimum_makers:
                    logger.error(f"Not enough makers selected: {len(selected_offers)}")
                    self.state = TakerState.FAILED
                    return None

                # Pre-select UTXOs for CoinJoin, then generate PoDLE from one of them
                # This ensures the PoDLE UTXO is one we'll actually use in the transaction
                logger.info("Selecting UTXOs and generating PoDLE commitment...")

                # Use manually selected UTXOs if available
                if manually_selected_utxos:
                    self.preselected_utxos = manually_selected_utxos
                    logger.info(
                        f"Using {len(manually_selected_utxos)} manually selected UTXOs "
                        f"(total: {sum(u.value for u in manually_selected_utxos):,} sats)"
                    )
                else:
                    # Estimate required amount (conservative estimate for UTXO pre-selection)
                    # We'll refine this in _phase_build_tx once we have exact maker UTXOs
                    estimated_inputs = 2 + len(selected_offers) * 2  # Rough estimate
                    estimated_outputs = 2 + len(selected_offers) * 2
                    estimated_tx_fee = self._estimate_tx_fee(estimated_inputs, estimated_outputs)
                    estimated_required = self.cj_amount + total_fee + estimated_tx_fee

                    # Pre-select UTXOs for the CoinJoin
                    try:
                        self.preselected_utxos = self.wallet.select_utxos(
                            mixdepth, estimated_required, self.config.taker_utxo_age
                        )
                        logger.info(
                            f"Pre-selected {len(self.preselected_utxos)} UTXOs for CoinJoin "
                            f"(total: {sum(u.value for u in self.preselected_utxos):,} sats)"
                        )
                    except ValueError as e:
                        logger.error(f"Insufficient funds for CoinJoin: {e}")
                        self.state = TakerState.FAILED
                        return None

            # Initialize maker sessions - neutrino_compat will be detected during handshake
            # when we receive the !pubkey response with features field
            self.maker_sessions = {
                nick: MakerSession(nick=nick, offer=offer, supports_neutrino_compat=False)
                for nick, offer in selected_offers.items()
            }

            logger.info(
                f"Selected {len(self.maker_sessions)} makers, total fee: {total_fee:,} sats"
            )

            # Log estimated transaction fee before prompting for confirmation
            # Conservative estimate: assume 1 input per maker + 20% buffer, rounded up
            import math

            estimated_maker_inputs = math.ceil(n_makers * 1.2)
            estimated_inputs = len(self.preselected_utxos) + estimated_maker_inputs
            # Outputs: 1 CJ output per participant + change outputs (assume all have change)
            estimated_outputs = (1 + n_makers) + (1 + n_makers)
            estimated_tx_fee = self._estimate_tx_fee(estimated_inputs, estimated_outputs)
            logger.info(
                f"Estimated transaction (mining) fee: {estimated_tx_fee:,} sats "
                f"(~{self._fee_rate:.2f} sat/vB for ~{estimated_inputs} inputs, "
                f"{estimated_outputs} outputs)"
            )

            # Prompt for confirmation after maker selection
            if hasattr(self, "confirmation_callback") and self.confirmation_callback:
                try:
                    # Build maker details for confirmation
                    maker_details = []
                    for nick, session in self.maker_sessions.items():
                        fee = session.offer.calculate_fee(self.cj_amount)
                        bond_value = session.offer.fidelity_bond_value
                        # Get maker's location from any connected directory
                        location = None
                        for client in self.directory_client.clients.values():
                            location = client._active_peers.get(nick)
                            if location and location != "NOT-SERVING-ONION":
                                break
                        maker_details.append(
                            {
                                "nick": nick,
                                "fee": fee,
                                "bond_value": bond_value,
                                "location": location,
                            }
                        )

                    confirmed = self.confirmation_callback(
                        maker_details=maker_details,
                        cj_amount=self.cj_amount,
                        total_fee=total_fee + estimated_tx_fee,
                        destination=destination,
                        mining_fee=estimated_tx_fee,
                        fee_rate=self._fee_rate,
                    )
                    if not confirmed:
                        logger.info("CoinJoin cancelled by user")
                        self.state = TakerState.CANCELLED
                        return None
                except Exception as e:
                    logger.error(f"Confirmation failed: {e}")
                    self.state = TakerState.FAILED
                    return None

            def get_private_key(addr: str) -> bytes | None:
                key = self.wallet.get_key_for_address(addr)
                if key is None:
                    return None
                return key.get_private_key_bytes()

            # Generate PoDLE from pre-selected UTXOs only
            # This ensures the commitment is from a UTXO that will be in the transaction
            self.podle_commitment = self.podle_manager.generate_fresh_commitment(
                wallet_utxos=self.preselected_utxos,  # Only from pre-selected UTXOs!
                cj_amount=self.cj_amount,
                private_key_getter=get_private_key,
                min_confirmations=self.config.taker_utxo_age,
                min_percent=self.config.taker_utxo_amtpercent,
                max_retries=self.config.taker_utxo_retries,
            )

            if not self.podle_commitment:
                logger.error("Failed to generate PoDLE commitment")
                self.state = TakerState.FAILED
                return None

            # Phase 1: Fill orders (with retry logic for blacklisted commitments)
            self.state = TakerState.FILLING
            logger.info("Phase 1: Sending !fill to makers...")
            # Log directory routing info
            directory_count = len(self.directory_client.clients)
            directories = [
                f"{client.host}:{client.port}" for client in self.directory_client.clients.values()
            ]
            logger.info(
                f"Routing via {directory_count} director{'y' if directory_count == 1 else 'ies'}: "
                f"{', '.join(directories)}"
            )
            if self.directory_client.prefer_direct_connections:
                logger.debug(
                    "Direct connections preferred - will attempt to connect directly to makers"
                )
            else:
                logger.debug(
                    "Direct connections disabled - all messages relayed through directories"
                )

            # Fire-and-forget notification for CoinJoin start
            asyncio.create_task(
                get_notifier().notify_coinjoin_start(
                    self.cj_amount, len(self.maker_sessions), destination
                )
            )

            # Retry loop for blacklisted commitments and maker replacement
            max_podle_retries = self.config.taker_utxo_retries
            max_replacement_attempts = self.config.max_maker_replacement_attempts
            replacement_attempt = 0

            for podle_retry in range(max_podle_retries):
                fill_result = await self._phase_fill()

                if fill_result.success:
                    break  # Success, proceed to next phase

                if fill_result.blacklist_error:
                    # Don't add makers to ignored list when commitment is blacklisted
                    # The maker may accept a different commitment, so we should retry
                    # with a new NUMS index or different UTXO
                    logger.debug(
                        f"Commitment blacklisted by makers: {fill_result.failed_makers}. "
                        "Will retry with new commitment."
                    )
                elif fill_result.failed_makers:
                    # Add failed makers to ignore list for non-blacklist failures
                    for failed_nick in fill_result.failed_makers:
                        self.orderbook_manager.add_ignored_maker(failed_nick)
                        logger.debug(f"Added {failed_nick} to ignored makers (failed fill)")

                if fill_result.blacklist_error:
                    # Commitment was blacklisted - try with a new commitment
                    if podle_retry < max_podle_retries - 1:
                        logger.warning(
                            f"Commitment blacklisted, retrying with new NUMS index "
                            f"(attempt {podle_retry + 2}/{max_podle_retries})..."
                        )

                        # The current commitment is already marked as used
                        # Generate a new one (will use next index automatically)
                        self.podle_commitment = self.podle_manager.generate_fresh_commitment(
                            wallet_utxos=self.preselected_utxos,
                            cj_amount=self.cj_amount,
                            private_key_getter=get_private_key,
                            min_confirmations=self.config.taker_utxo_age,
                            min_percent=self.config.taker_utxo_amtpercent,
                            max_retries=self.config.taker_utxo_retries,
                        )

                        if not self.podle_commitment:
                            logger.error(
                                "No more PoDLE commitments available - all indices exhausted"
                            )
                            self.state = TakerState.FAILED
                            return None

                        # Reset maker sessions for retry (excluding ignored makers)
                        self.maker_sessions = {
                            nick: MakerSession(
                                nick=nick, offer=offer, supports_neutrino_compat=False
                            )
                            for nick, offer in selected_offers.items()
                            if nick not in self.orderbook_manager.ignored_makers
                        }
                        continue
                    else:
                        logger.error(
                            f"Fill phase failed after {max_podle_retries} PoDLE commitment attempts"
                        )
                        self.state = TakerState.FAILED
                        return None

                # Not a blacklist error - try maker replacement if enabled
                if fill_result.needs_replacement and replacement_attempt < max_replacement_attempts:
                    replacement_attempt += 1
                    needed = self.config.minimum_makers - len(self.maker_sessions)
                    logger.info(
                        f"Attempting maker replacement (attempt {replacement_attempt}/"
                        f"{max_replacement_attempts}): need {needed} more makers"
                    )

                    # Select replacement makers from orderbook
                    # Exclude makers already in current session to avoid reusing them
                    current_session_nicks = set(self.maker_sessions.keys())
                    replacement_offers, _ = self.orderbook_manager.select_makers(
                        cj_amount=self.cj_amount,
                        n=needed,
                        exclude_nicks=current_session_nicks,
                    )

                    if len(replacement_offers) < needed:
                        logger.error(
                            f"Not enough replacement makers available: "
                            f"found {len(replacement_offers)}, need {needed}"
                        )
                        self.state = TakerState.FAILED
                        return None

                    # Add replacement makers to session
                    for nick, offer in replacement_offers.items():
                        self.maker_sessions[nick] = MakerSession(
                            nick=nick, offer=offer, supports_neutrino_compat=False
                        )
                        logger.info(f"Added replacement maker: {nick}")

                    # Update selected_offers for potential future retries
                    selected_offers.update(replacement_offers)
                    continue

                # Failed and no replacement possible
                logger.error("Fill phase failed")
                self.state = TakerState.FAILED
                return None

            # Phase 2: Auth and get maker UTXOs (with maker replacement)
            self.state = TakerState.AUTHENTICATING
            logger.info("Phase 2: Sending !auth and receiving !ioauth...")

            auth_replacement_attempt = 0
            while True:
                auth_result = await self._phase_auth()

                if auth_result.success:
                    break  # Success, proceed to next phase

                # Add failed makers to ignore list
                for failed_nick in auth_result.failed_makers:
                    self.orderbook_manager.add_ignored_maker(failed_nick)
                    logger.debug(f"Added {failed_nick} to ignored makers (failed auth)")

                # Try maker replacement if enabled
                if (
                    auth_result.needs_replacement
                    and auth_replacement_attempt < max_replacement_attempts
                ):
                    auth_replacement_attempt += 1
                    needed = self.config.minimum_makers - len(self.maker_sessions)
                    logger.info(
                        f"Attempting maker replacement in auth phase "
                        f"(attempt {auth_replacement_attempt}/{max_replacement_attempts}): "
                        f"need {needed} more makers"
                    )

                    # Select replacement makers
                    # Exclude makers already in current session to avoid reusing them
                    current_session_nicks = set(self.maker_sessions.keys())
                    replacement_offers, _ = self.orderbook_manager.select_makers(
                        cj_amount=self.cj_amount,
                        n=needed,
                        exclude_nicks=current_session_nicks,
                    )

                    if len(replacement_offers) < needed:
                        logger.error(
                            f"Not enough replacement makers for auth phase: "
                            f"found {len(replacement_offers)}, need {needed}"
                        )
                        self.state = TakerState.FAILED
                        return None

                    # Add replacement makers - they need to go through fill first
                    for nick, offer in replacement_offers.items():
                        self.maker_sessions[nick] = MakerSession(
                            nick=nick, offer=offer, supports_neutrino_compat=False
                        )
                        logger.info(f"Added replacement maker for auth: {nick}")

                    # Run fill phase for new makers only
                    logger.info("Running fill phase for replacement makers...")
                    new_maker_nicks = list(replacement_offers.keys())

                    # Send !fill to new makers
                    if not self.podle_commitment or not self.crypto_session:
                        logger.error("Missing commitment or crypto session for replacement")
                        self.state = TakerState.FAILED
                        return None

                    commitment_hex = self.podle_commitment.to_commitment_str()
                    taker_pubkey = self.crypto_session.get_pubkey_hex()

                    # Establish communication channels for replacement makers
                    # (Same logic as in _phase_fill)
                    for nick in new_maker_nicks:
                        peer = self.directory_client._get_connected_peer(nick)
                        session = self.maker_sessions[nick]
                        if peer and self.directory_client.prefer_direct_connections:
                            session.comm_channel = "direct"
                            logger.debug(f"Will use DIRECT connection for replacement maker {nick}")
                        else:
                            # Use directory relay
                            target_directories = []

                            if nick in self.directory_client._active_nicks:
                                active_nicks_dict = self.directory_client._active_nicks[nick]
                                for server, is_active in active_nicks_dict.items():
                                    if is_active and server in self.directory_client.clients:
                                        target_directories.append(server)

                            if not target_directories:
                                for server, client in self.directory_client.clients.items():
                                    if nick in client._active_peers:
                                        target_directories.append(server)

                            if not target_directories:
                                target_directories = list(self.directory_client.clients.keys())

                            if target_directories:
                                chosen_dir = target_directories[0]
                                session.comm_channel = f"directory:{chosen_dir}"
                                logger.debug(
                                    f"Will use DIRECTORY relay {chosen_dir} "
                                    f"for replacement maker {nick}"
                                )

                    # Send !fill to replacement makers using their designated channels
                    for nick in new_maker_nicks:
                        session = self.maker_sessions[nick]
                        fill_data = (
                            f"{session.offer.oid} {self.cj_amount} {taker_pubkey} {commitment_hex}"
                        )
                        await self.directory_client.send_privmsg(
                            nick,
                            "fill",
                            fill_data,
                            log_routing=True,
                            force_channel=session.comm_channel,
                        )

                    # Wait for !pubkey responses from new makers
                    responses = await self.directory_client.wait_for_responses(
                        expected_nicks=new_maker_nicks,
                        expected_command="!pubkey",
                        timeout=self.config.maker_timeout_sec,
                    )

                    # Process responses for new makers
                    new_makers_ready = 0
                    for nick in new_maker_nicks:
                        if nick in responses and not responses[nick].get("error"):
                            try:
                                response_data = responses[nick]["data"].strip()
                                parts = response_data.split()
                                if parts:
                                    nacl_pubkey = parts[0]
                                    self.maker_sessions[nick].pubkey = nacl_pubkey
                                    self.maker_sessions[nick].responded_fill = True

                                    # Set up encryption (reuse taker keypair)
                                    crypto = CryptoSession.__new__(CryptoSession)
                                    crypto.keypair = self.crypto_session.keypair
                                    crypto.box = None
                                    crypto.counterparty_pubkey = ""
                                    crypto.setup_encryption(nacl_pubkey)
                                    self.maker_sessions[nick].crypto = crypto
                                    new_makers_ready += 1
                                    logger.debug(f"Replacement maker {nick} ready")
                            except Exception as e:
                                logger.warning(f"Failed to process {nick}: {e}")
                                del self.maker_sessions[nick]
                        else:
                            logger.warning(f"Replacement maker {nick} didn't respond")
                            if nick in self.maker_sessions:
                                del self.maker_sessions[nick]

                    if new_makers_ready == 0:
                        logger.error("No replacement makers responded to fill")
                        self.state = TakerState.FAILED
                        return None

                    # Continue to retry auth with all makers
                    continue

                # Failed and no replacement possible
                logger.error("Auth phase failed")
                self.state = TakerState.FAILED
                return None

            # Phase 3: Build transaction
            self.state = TakerState.BUILDING_TX
            logger.info("Phase 3: Building transaction...")

            tx_success = await self._phase_build_tx(
                destination=destination,
                mixdepth=mixdepth,
            )
            if not tx_success:
                logger.error("Transaction build failed")
                self.state = TakerState.FAILED
                return None

            # Phase 4: Collect signatures
            self.state = TakerState.COLLECTING_SIGNATURES
            logger.info("Phase 4: Collecting signatures...")

            sig_success = await self._phase_collect_signatures()
            if not sig_success:
                logger.error("Signature collection failed")
                self.state = TakerState.FAILED
                return None

            # Final confirmation before broadcast
            # Calculate exact transaction details
            num_taker_inputs = len(self.selected_utxos)
            num_maker_inputs = sum(len(s.utxos) for s in self.maker_sessions.values())
            total_inputs = num_taker_inputs + num_maker_inputs

            # Parse transaction to count outputs and sum output values
            tx = deserialize_transaction(self.final_tx)
            total_outputs = len(tx.outputs)
            total_output_value = sum(out.value for out in tx.outputs)

            # Calculate total input value (taker + maker UTXOs)
            taker_input_value = sum(utxo.value for utxo in self.selected_utxos)
            maker_input_value = sum(
                utxo["value"] for session in self.maker_sessions.values() for utxo in session.utxos
            )
            total_input_value = taker_input_value + maker_input_value

            # Calculate actual mining fee from the transaction (includes any residual/dust)
            actual_mining_fee = total_input_value - total_output_value

            # Calculate maker fees
            total_maker_fees = sum(
                calculate_cj_fee(session.offer, self.cj_amount)
                for session in self.maker_sessions.values()
            )
            total_cost = total_maker_fees + actual_mining_fee

            # Calculate actual fee rate from the final signed transaction
            actual_vsize = calculate_tx_vsize(self.final_tx)
            actual_fee_rate = actual_mining_fee / actual_vsize if actual_vsize > 0 else 0.0

            # Log final transaction details
            logger.info("=" * 70)
            logger.info("FINAL TRANSACTION SUMMARY - Ready to broadcast")
            logger.info("=" * 70)
            logger.info(f"CoinJoin amount:      {self.cj_amount:,} sats")
            logger.info(f"Makers participating: {len(self.maker_sessions)}")
            logger.info(
                f"  Makers: {', '.join(nick[:10] + '...' for nick in self.maker_sessions.keys())}"
            )
            logger.info(
                f"Transaction inputs:   {total_inputs} ({num_taker_inputs} yours, "
                f"{num_maker_inputs} makers)"
            )
            logger.info(f"Transaction outputs:  {total_outputs}")
            logger.info(f"Maker fees:           {total_maker_fees:,} sats")
            logger.info(
                f"Mining fee:           {actual_mining_fee:,} sats ({actual_fee_rate:.2f} sat/vB)"
            )
            logger.info(f"Total cost:           {total_cost:,} sats")
            logger.info(f"Transaction size:     {actual_vsize} vbytes ({len(self.final_tx)} bytes)")
            logger.info("-" * 70)
            logger.info("Transaction hex (for manual verification/broadcast):")
            logger.info(self.final_tx.hex())
            logger.info("=" * 70)

            # Prompt for final confirmation if callback is set
            if hasattr(self, "confirmation_callback") and self.confirmation_callback:
                try:
                    # Build maker details for final confirmation
                    maker_details = []
                    for nick, session in self.maker_sessions.items():
                        fee = calculate_cj_fee(session.offer, self.cj_amount)
                        bond_value = session.offer.fidelity_bond_value
                        # Get maker's location from any connected directory
                        location = None
                        for client in self.directory_client.clients.values():
                            location = client._active_peers.get(nick)
                            if location and location != "NOT-SERVING-ONION":
                                break
                        maker_details.append(
                            {
                                "nick": nick,
                                "fee": fee,
                                "bond_value": bond_value,
                                "location": location,
                            }
                        )

                    confirmed = self.confirmation_callback(
                        maker_details=maker_details,
                        cj_amount=self.cj_amount,
                        total_fee=total_cost,
                        destination=destination,
                        mining_fee=actual_mining_fee,
                        fee_rate=actual_fee_rate,
                    )
                    if not confirmed:
                        logger.warning("User declined final broadcast confirmation")
                        # Log CSV entry for manual tracking/broadcast
                        self._log_manual_csv_entry(total_maker_fees, actual_mining_fee, destination)
                        self.state = TakerState.FAILED
                        return None
                except Exception as e:
                    logger.error(f"Final confirmation callback failed: {e}")
                    self.state = TakerState.FAILED
                    return None

            # Phase 5: Broadcast
            self.state = TakerState.BROADCASTING
            logger.info("Phase 5: Broadcasting transaction...")

            self.txid = await self._phase_broadcast()
            if not self.txid:
                logger.error("Broadcast failed")
                self.state = TakerState.FAILED
                return None

            self.state = TakerState.COMPLETE
            logger.info(f"CoinJoin COMPLETE! txid: {self.txid}")

            # Update the "Awaiting transaction" history entry with txid and mining fee
            # The entry was created before sending !tx to preserve address privacy
            try:
                mining_fee = self.tx_metadata.get("fee", 0)

                updated = update_taker_awaiting_transaction_broadcast(
                    destination_address=self.cj_destination,
                    change_address=self.taker_change_address,
                    txid=self.txid,
                    mining_fee=mining_fee,
                    data_dir=self.config.data_dir,
                )
                if updated:
                    logger.debug(
                        f"Updated history entry for CJ txid {self.txid[:16]}..., "
                        f"mining_fee={mining_fee} sats"
                    )
                else:
                    logger.warning(
                        f"No matching 'Awaiting transaction' entry found for "
                        f"{self.cj_destination[:20]}... - history may be inconsistent"
                    )

                # Immediately check if tx is confirmed/in mempool and update history
                # This is important for one-shot coinjoin CLI calls that exit immediately
                await self._update_pending_transaction_now(self.txid, self.cj_destination)
            except Exception as e:
                logger.warning(f"Failed to update CoinJoin history: {e}")

            # Fire-and-forget notification for successful CoinJoin
            total_fees = total_maker_fees + actual_mining_fee
            asyncio.create_task(
                get_notifier().notify_coinjoin_complete(
                    self.txid, self.cj_amount, len(self.maker_sessions), total_fees
                )
            )

            return self.txid

        except Exception as e:
            logger.error(f"CoinJoin failed: {e}")
            # Fire-and-forget notification for failed CoinJoin
            phase = self.state.value if hasattr(self, "state") else ""
            amount = self.cj_amount if hasattr(self, "cj_amount") else 0
            asyncio.create_task(get_notifier().notify_coinjoin_failed(str(e), phase, amount))
            self.state = TakerState.FAILED
            return None

    async def _phase_fill(self) -> PhaseResult:
        """Send !fill to all selected makers and wait for !pubkey responses.

        Returns:
            PhaseResult with success status, failed makers list, and blacklist flag.
        """
        if not self.podle_commitment:
            return PhaseResult(success=False)

        # Create a new crypto session for this CoinJoin
        self.crypto_session = CryptoSession()
        taker_pubkey = self.crypto_session.get_pubkey_hex()
        commitment_hex = self.podle_commitment.to_commitment_str()

        # CRITICAL: Establish communication channels BEFORE sending !fill
        # We must use the SAME channel for ALL messages to each maker in this session
        # Mixing channels (e.g., !fill via directory, !auth via direct) causes makers to reject
        #
        # Strategy:
        # 1. Try to establish direct connections (with reasonable timeout)
        # 2. Choose ONE channel per maker (direct OR specific directory)
        # 3. Record the channel in maker_session.comm_channel
        # 4. Use only that channel for all subsequent messages

        # Start direct connection attempts for all makers
        if self.directory_client.prefer_direct_connections:
            for nick in self.maker_sessions.keys():
                maker_location = self.directory_client._get_peer_location(nick)
                if maker_location:
                    self.directory_client._try_direct_connect(nick)

        # Wait up to 5 seconds for direct connections to establish
        # This timeout balances privacy (prefer direct) vs latency (don't wait too long)
        if self.directory_client.prefer_direct_connections:
            pending_tasks = []
            for nick in self.maker_sessions.keys():
                if nick in self.directory_client._pending_connect_tasks:
                    task = self.directory_client._pending_connect_tasks[nick]
                    if not task.done():
                        pending_tasks.append(task)

            if pending_tasks:
                logger.info(
                    f"Waiting up to 5s for direct connections to {len(pending_tasks)} makers..."
                )
                done, pending = await asyncio.wait(
                    pending_tasks, timeout=5.0, return_when=asyncio.ALL_COMPLETED
                )
                connected_count = len([t for t in done if not t.exception()])
                if connected_count > 0:
                    logger.info(
                        f"Established {connected_count}/{len(pending_tasks)} direct connections"
                    )

        # Determine and record communication channel for each maker
        for nick, session in self.maker_sessions.items():
            # Check if direct connection is available
            peer = self.directory_client._get_connected_peer(nick)
            if peer and self.directory_client.prefer_direct_connections:
                session.comm_channel = "direct"
                logger.debug(f"Will use DIRECT connection for {nick}")
            else:
                # Use directory relay - pick one directory for this maker
                maker_location = self.directory_client._get_peer_location(nick)
                target_directories = []

                # Check active nicks tracking first
                if nick in self.directory_client._active_nicks:
                    for server, is_active in self.directory_client._active_nicks[nick].items():
                        if is_active and server in self.directory_client.clients:
                            target_directories.append(server)

                # If not found, try all clients that list the peer
                if not target_directories:
                    for server, client in self.directory_client.clients.items():
                        if nick in client._active_peers:
                            target_directories.append(server)

                # If still not found, use all connected clients
                if not target_directories:
                    target_directories = list(self.directory_client.clients.keys())

                # Pick first directory (already shuffled during orderbook fetch)
                if target_directories:
                    chosen_dir = target_directories[0]
                    session.comm_channel = f"directory:{chosen_dir}"
                    logger.debug(
                        f"Will use DIRECTORY relay {chosen_dir} for {nick} "
                        f"(onion: {maker_location or 'unknown'})"
                    )
                else:
                    # This should never happen if we're connected to directories
                    raise RuntimeError(f"No communication channel available for {nick}")

        # Send !fill to all makers using their designated channels
        # Format: fill <oid> <amount> <taker_pubkey> <commitment>
        for nick, session in self.maker_sessions.items():
            fill_data = f"{session.offer.oid} {self.cj_amount} {taker_pubkey} {commitment_hex}"
            channel = await self.directory_client.send_privmsg(
                nick, "fill", fill_data, log_routing=True, force_channel=session.comm_channel
            )
            # Verify the channel used matches what we recorded
            assert channel == session.comm_channel, f"Channel mismatch for {nick}"

        # Wait for all !pubkey responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!pubkey",
            timeout=timeout,
        )

        # Track failed makers and blacklist errors
        failed_makers: list[str] = []
        blacklist_error = False

        # Process responses
        # Maker sends: "<nacl_pubkey> [features=...] <signing_pubkey> <signature>"
        # Directory client strips command, we get the data part
        # Note: responses may include error responses with {"error": True, "data": "reason"}
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                # Check if this is an error response
                if responses[nick].get("error"):
                    error_msg = responses[nick].get("data", "Unknown error")
                    logger.error(f"Maker {nick} rejected !fill: {error_msg}")
                    # Check if this is a blacklist error
                    if "blacklist" in error_msg.lower():
                        blacklist_error = True
                        logger.warning(
                            f"Commitment was blacklisted by {nick} - may need retry with new index"
                        )
                    failed_makers.append(nick)
                    del self.maker_sessions[nick]
                    continue

                try:
                    response_data = responses[nick]["data"].strip()
                    # Format: "<nacl_pubkey_hex> [features=...] <signing_pk> <sig>"
                    # We need the first part (nacl_pubkey_hex) and optionally features
                    parts = response_data.split()
                    if parts:
                        nacl_pubkey = parts[0]
                        self.maker_sessions[nick].pubkey = nacl_pubkey
                        self.maker_sessions[nick].responded_fill = True

                        # Parse optional features (e.g., "features=neutrino_compat")
                        for part in parts[1:]:
                            if part.startswith("features="):
                                features_str = part[9:]  # Skip "features="
                                features = set(features_str.split(",")) if features_str else set()
                                if "neutrino_compat" in features:
                                    self.maker_sessions[nick].supports_neutrino_compat = True
                                    logger.debug(f"Maker {nick} supports neutrino_compat")
                                break

                        # Set up encryption session with this maker using their NaCl pubkey
                        # IMPORTANT: Reuse the same keypair from self.crypto_session
                        # that was sent in !fill, just set up new box with maker's pubkey
                        crypto = CryptoSession.__new__(CryptoSession)
                        crypto.keypair = self.crypto_session.keypair  # Reuse taker keypair!
                        crypto.box = None
                        crypto.counterparty_pubkey = ""
                        crypto.setup_encryption(nacl_pubkey)
                        self.maker_sessions[nick].crypto = crypto
                        logger.debug(
                            f"Processed !pubkey from {nick}: {nacl_pubkey[:16]}..., "
                            f"encryption set up"
                        )
                    else:
                        logger.warning(f"Empty !pubkey response from {nick}")
                        failed_makers.append(nick)
                        del self.maker_sessions[nick]
                except Exception as e:
                    logger.warning(f"Invalid !pubkey response from {nick}: {e}")
                    failed_makers.append(nick)
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !pubkey response from {nick}")
                failed_makers.append(nick)
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough makers responded: {len(self.maker_sessions)}")
            return PhaseResult(
                success=False, failed_makers=failed_makers, blacklist_error=blacklist_error
            )

        return PhaseResult(
            success=True, failed_makers=failed_makers, blacklist_error=blacklist_error
        )

    async def _phase_auth(self) -> PhaseResult:
        """Send !auth with PoDLE proof and wait for !ioauth responses.

        Returns:
            PhaseResult with success status and failed makers list.
        """
        if not self.podle_commitment:
            return PhaseResult(success=False)

        # Send !auth to each maker with format based on their feature support.
        # - Makers with neutrino_compat: MUST receive extended format
        #   (txid:vout:scriptpubkey:blockheight)
        # - Legacy makers: Receive legacy format (txid:vout)
        #
        # Feature detection happens via handshake - makers advertise neutrino_compat
        # in their !pubkey response's features field. This is backwards compatible:
        # legacy JoinMarket makers don't send features, so they default to legacy format.
        #
        # Compatibility matrix:
        # | Taker Backend | Maker neutrino_compat | Action |
        # |---------------|----------------------|--------|
        # | Full node     | False                | Send legacy format |
        # | Full node     | True                 | Send extended format (maker requires it) |
        # | Neutrino      | False                | FAIL - incompatible, maker filtered out |
        # | Neutrino      | True                 | Send extended format (both support it) |
        has_metadata = self.podle_commitment.has_neutrino_metadata()
        taker_requires_extended = self.backend.requires_neutrino_metadata()

        for nick, session in list(self.maker_sessions.items()):
            if session.crypto is None:
                logger.error(f"No encryption session for {nick}")
                continue

            maker_requires_extended = session.supports_neutrino_compat

            # Fail early if taker needs extended format but maker doesn't support it
            # This happens when taker uses Neutrino backend but maker uses full node
            # The maker won't be able to verify our UTXO without extended metadata
            if taker_requires_extended and not maker_requires_extended:
                logger.error(
                    f"Incompatible maker {nick}: taker uses Neutrino backend but maker "
                    f"doesn't support neutrino_compat. Maker cannot verify our UTXOs."
                )
                del self.maker_sessions[nick]
                continue

            # Send extended format if:
            # 1. We have the metadata AND
            # 2. Either maker requires it OR we (taker) need it for our verification
            use_extended = has_metadata and (maker_requires_extended or taker_requires_extended)
            revelation = self.podle_commitment.to_revelation(extended=use_extended)

            # Create pipe-separated revelation format:
            # Legacy: txid:vout|P|P2|sig|e
            # Extended: txid:vout:scriptpubkey:blockheight|P|P2|sig|e
            revelation_str = "|".join(
                [
                    revelation["utxo"],
                    revelation["P"],
                    revelation["P2"],
                    revelation["sig"],
                    revelation["e"],
                ]
            )

            if use_extended:
                logger.debug(f"Sending extended UTXO format to maker {nick}")
            else:
                logger.debug(f"Sending legacy UTXO format to maker {nick}")

            # Encrypt and send (using same channel as !fill)
            encrypted_revelation = session.crypto.encrypt(revelation_str)
            await self.directory_client.send_privmsg(
                nick,
                "auth",
                encrypted_revelation,
                log_routing=True,
                force_channel=session.comm_channel,
            )

        # Track makers filtered due to incompatibility (not the same as failed)
        incompatible_makers: list[str] = []

        # Check if we still have enough makers after filtering incompatible ones
        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(
                f"Not enough compatible makers: {len(self.maker_sessions)} "
                f"< {self.config.minimum_makers}. Neutrino takers require neutrino_compat."
            )
            return PhaseResult(success=False, failed_makers=incompatible_makers)

        # Wait for all !ioauth responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!ioauth",
            timeout=timeout,
        )

        # Track failed makers for potential replacement
        failed_makers: list[str] = []

        # Process responses
        # Maker sends !ioauth as ENCRYPTED space-separated:
        # <utxo_list> <auth_pub> <cj_addr> <change_addr> <btc_sig>
        # where utxo_list can be:
        # - Legacy format: txid:vout,txid:vout,...
        # - Extended format (neutrino_compat): txid:vout:scriptpubkey:blockheight,...
        # Response format from directory: "<encrypted_data> <signing_pubkey> <signature>"
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                try:
                    session = self.maker_sessions[nick]
                    if session.crypto is None:
                        logger.warning(f"No encryption session for {nick}")
                        failed_makers.append(nick)
                        del self.maker_sessions[nick]
                        continue

                    # Extract encrypted data (first part of response)
                    response_data = responses[nick]["data"].strip()
                    parts = response_data.split()
                    if not parts:
                        logger.warning(f"Empty !ioauth response from {nick}")
                        failed_makers.append(nick)
                        del self.maker_sessions[nick]
                        continue

                    encrypted_data = parts[0]

                    # Decrypt the ioauth message
                    decrypted = session.crypto.decrypt(encrypted_data)
                    logger.debug(f"Decrypted !ioauth from {nick}: {decrypted[:50]}...")

                    # Parse: <utxo_list> <auth_pub> <cj_addr> <change_addr> <btc_sig>
                    ioauth_parts = decrypted.split()
                    if len(ioauth_parts) < 4:
                        logger.warning(
                            f"Invalid !ioauth format from {nick}: expected 5 parts, "
                            f"got {len(ioauth_parts)}"
                        )
                        failed_makers.append(nick)
                        del self.maker_sessions[nick]
                        continue

                    utxo_list_str = ioauth_parts[0]
                    auth_pub = ioauth_parts[1]
                    cj_addr = ioauth_parts[2]
                    change_addr = ioauth_parts[3]

                    # Verify btc_sig if present - proves maker owns the UTXO
                    # NOTE: BTC sig verification is OPTIONAL per JoinMarket protocol
                    # It provides additional security by proving maker controls the UTXO
                    # but not all makers may provide it
                    if len(ioauth_parts) >= 5:
                        btc_sig = ioauth_parts[4]
                        # The signature is over the maker's NaCl pubkey
                        from jmcore.crypto import ecdsa_verify

                        maker_nacl_pk = session.pubkey  # Maker's NaCl pubkey from !pubkey
                        auth_pub_bytes = bytes.fromhex(auth_pub)
                        logger.debug(
                            f"Verifying BTC sig from {nick}: "
                            f"message={maker_nacl_pk[:32]}..., "
                            f"sig={btc_sig[:32]}..., "
                            f"pubkey={auth_pub[:16]}..."
                        )
                        if not ecdsa_verify(maker_nacl_pk, btc_sig, auth_pub_bytes):
                            logger.warning(
                                f"BTC signature verification failed from {nick} - "
                                f"continuing anyway (optional security feature)"
                            )
                            # NOTE: We don't delete the session here - BTC sig is optional
                            # The transaction verification will still protect against fraud
                        else:
                            logger.info(f"BTC signature verified for {nick} ✓")

                    # Parse utxo_list using protocol helper
                    # (handles both legacy and extended format)
                    # Then verify each UTXO using the appropriate backend method
                    session.utxos = []
                    utxo_metadata_list = parse_utxo_list(utxo_list_str)

                    # Track if maker sent extended format
                    has_extended = any(u.has_neutrino_metadata() for u in utxo_metadata_list)
                    if has_extended:
                        session.supports_neutrino_compat = True
                        logger.debug(f"Maker {nick} sent extended UTXO format (neutrino_compat)")

                    for utxo_meta in utxo_metadata_list:
                        txid = utxo_meta.txid
                        vout = utxo_meta.vout

                        # Verify UTXO and get value/address
                        try:
                            if (
                                self.backend.requires_neutrino_metadata()
                                and utxo_meta.has_neutrino_metadata()
                            ):
                                # Use Neutrino-compatible verification with metadata
                                result = await self.backend.verify_utxo_with_metadata(
                                    txid=txid,
                                    vout=vout,
                                    scriptpubkey=utxo_meta.scriptpubkey,  # type: ignore
                                    blockheight=utxo_meta.blockheight,  # type: ignore
                                )
                                if result.valid:
                                    value = result.value
                                    address = ""  # Not available from verification
                                    logger.debug(
                                        f"Neutrino-verified UTXO {txid}:{vout} = {value} sats"
                                    )
                                else:
                                    logger.warning(
                                        f"Neutrino UTXO verification failed for "
                                        f"{txid}:{vout}: {result.error}"
                                    )
                                    continue
                            else:
                                # Full node: direct UTXO lookup
                                utxo_info = await self.backend.get_utxo(txid, vout)
                                if utxo_info:
                                    value = utxo_info.value
                                    address = utxo_info.address
                                else:
                                    # Fallback: get raw transaction and parse it
                                    tx_info = await self.backend.get_transaction(txid)
                                    if tx_info and tx_info.raw:
                                        from maker.tx_verification import parse_transaction

                                        parsed_tx = parse_transaction(
                                            tx_info.raw, network=self.config.network
                                        )
                                        if parsed_tx and len(parsed_tx["outputs"]) > vout:
                                            value = parsed_tx["outputs"][vout]["value"]
                                            address = parsed_tx["outputs"][vout].get("address", "")
                                        else:
                                            logger.warning(
                                                f"Could not parse output {vout} from tx {txid}"
                                            )
                                            value = 0
                                            address = ""
                                    else:
                                        logger.warning(f"Could not fetch transaction {txid}")
                                        value = 0
                                        address = ""
                        except Exception as e:
                            logger.warning(f"Error verifying UTXO {txid}:{vout}: {e}")
                            value = 0
                            address = ""

                        session.utxos.append(
                            {
                                "txid": txid,
                                "vout": vout,
                                "value": value,
                                "address": address,
                            }
                        )
                        logger.debug(f"Added UTXO from {nick}: {txid}:{vout} = {value} sats")

                    session.cj_address = cj_addr
                    session.change_address = change_addr
                    session.auth_pubkey = auth_pub  # Store for later verification
                    session.responded_auth = True
                    logger.debug(
                        f"Processed !ioauth from {nick}: {len(session.utxos)} UTXOs, "
                        f"cj_addr={cj_addr[:16]}..."
                    )
                except Exception as e:
                    logger.warning(f"Invalid !ioauth response from {nick}: {e}")
                    failed_makers.append(nick)
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !ioauth response from {nick}")
                failed_makers.append(nick)
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough makers sent UTXOs: {len(self.maker_sessions)}")
            return PhaseResult(success=False, failed_makers=failed_makers)

        return PhaseResult(success=True, failed_makers=failed_makers)

    def _parse_utxos(self, utxos_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse UTXO data from !ioauth response."""
        result = []
        for utxo_str, info in utxos_dict.items():
            try:
                txid, vout_str = utxo_str.split(":")
                result.append(
                    {
                        "txid": txid,
                        "vout": int(vout_str),
                        "value": info.get("value", 0),
                        "address": info.get("address", ""),
                    }
                )
            except (ValueError, KeyError):
                continue
        return result

    async def _phase_build_tx(self, destination: str, mixdepth: int) -> bool:
        """Build the unsigned CoinJoin transaction."""
        try:
            # Store destination for broadcast verification
            self.cj_destination = destination

            # Calculate total input needed (now with exact maker UTXOs)
            total_maker_fee = sum(
                calculate_cj_fee(s.offer, self.cj_amount) for s in self.maker_sessions.values()
            )

            # Estimate tx fee with actual input counts
            num_taker_inputs = len(self.preselected_utxos)
            num_maker_inputs = sum(len(s.utxos) for s in self.maker_sessions.values())
            num_inputs = num_taker_inputs + num_maker_inputs

            # Output count depends on sweep mode:
            # - Normal: CJ outputs (1 + n_makers) + change outputs (1 + n_makers)
            # - Sweep: CJ outputs (1 + n_makers) + maker changes only (n_makers)
            if self.is_sweep:
                # No taker change output in sweep mode
                num_outputs = 1 + len(self.maker_sessions) + len(self.maker_sessions)
            else:
                # Normal mode: include taker change
                num_outputs = 1 + len(self.maker_sessions) + 1 + len(self.maker_sessions)

            # Calculate actual tx fee based on real transaction size
            actual_tx_fee = self._estimate_tx_fee(num_inputs, num_outputs)

            preselected_total = sum(u.value for u in self.preselected_utxos)

            if self.is_sweep:
                # SWEEP MODE: Use ALL preselected UTXOs, preserve cj_amount from !fill
                selected_utxos = self.preselected_utxos
                logger.info(
                    f"Sweep mode: using all {len(selected_utxos)} UTXOs, "
                    f"total {preselected_total:,} sats"
                )

                # For sweeps, we MUST use the tx_fee_budget that was calculated at order
                # selection time. The equation that determined cj_amount was:
                #   total_input = cj_amount + maker_fees + tx_fee_budget
                #
                # Using any other value for tx_fee would create a residual:
                #   residual = total_input - cj_amount - maker_fees - tx_fee
                #            = tx_fee_budget - tx_fee
                #
                # If tx_fee < budget: positive residual goes to miners (overpaying!)
                # If tx_fee > budget: negative residual fails the CJ (underfunded)
                #
                # By using the budget as tx_fee, we ensure:
                #   - The taker pays exactly what was stated at the start
                #   - The fee rate may differ based on actual tx size
                #   - No funds are lost to unexpected miner fees
                #
                # Calculate actual vsize for fee rate logging
                actual_tx_vsize = num_inputs * 68 + num_outputs * 31 + 11

                # Use the budget as the tx_fee
                tx_fee = self._sweep_tx_fee_budget

                # Calculate residual (should be minimal - just from integer division)
                residual = preselected_total - self.cj_amount - total_maker_fee - tx_fee
                actual_fee_rate = tx_fee / actual_tx_vsize if actual_tx_vsize > 0 else 0

                logger.info(
                    f"Sweep: cj_amount={self.cj_amount:,} (from !fill), "
                    f"maker_fees={total_maker_fee:,}, "
                    f"tx_fee={tx_fee:,} (budget), "
                    f"residual={residual} sats, "
                    f"actual_vsize={actual_tx_vsize}, "
                    f"effective_rate={actual_fee_rate:.2f} sat/vB"
                )

                if residual < 0:
                    # Negative residual means the budget was insufficient
                    # This should only happen if there's a bug in the calculation
                    logger.error(
                        f"Sweep failed: negative residual of {residual} sats. "
                        f"This indicates a bug in cj_amount calculation. "
                        f"total_input={preselected_total}, cj_amount={self.cj_amount}, "
                        f"maker_fees={total_maker_fee}, tx_fee_budget={tx_fee}"
                    )
                    return False

                # Small positive residual (typically < 100 sats) is expected from integer
                # division in calculate_sweep_amount. This goes to miners.
                if residual > 100:
                    # Larger residual indicates a calculation issue
                    logger.warning(
                        f"Sweep: unexpected residual of {residual} sats. "
                        f"Expected < 100 sats from integer rounding. "
                        "This may indicate a fee calculation mismatch."
                    )

                # The residual becomes additional miner fee (no taker change in sweep)

            else:
                # NORMAL MODE: Use pre-selected UTXOs, add more if needed
                # For normal mode, we use the actual tx_fee estimate
                tx_fee = actual_tx_fee
                required = self.cj_amount + total_maker_fee + tx_fee

                # Use pre-selected UTXOs (which include the PoDLE UTXO)
                # These were selected during PoDLE generation to ensure the commitment
                # UTXO is one we'll actually use in the transaction
                if preselected_total >= required:
                    # Pre-selected UTXOs are sufficient
                    selected_utxos = self.preselected_utxos
                    logger.info(
                        f"Using pre-selected UTXOs: {len(selected_utxos)} UTXOs, "
                        f"total {preselected_total:,} sats (need {required:,})"
                    )
                else:
                    # Need additional UTXOs beyond pre-selection
                    # This can happen if actual fees were higher than estimated
                    logger.warning(
                        f"Pre-selected UTXOs insufficient: have {preselected_total:,}, "
                        f"need {required:,}. Selecting additional UTXOs..."
                    )
                    selected_utxos = self.wallet.select_utxos(
                        mixdepth,
                        required,
                        self.config.taker_utxo_age,
                        include_utxos=self.preselected_utxos,  # Include pre-selected (PoDLE UTXO)
                    )

            if not selected_utxos:
                logger.error("Failed to select enough UTXOs")
                return False

            # Store selected UTXOs for signing later
            self.selected_utxos = selected_utxos

            taker_total = sum(u.value for u in selected_utxos)

            # Taker change address - store for broadcast verification
            # (Even for sweep, we generate one in case of dust handling)
            change_index = self.wallet.get_next_address_index(mixdepth, 1)
            taker_change_address = self.wallet.get_change_address(mixdepth, change_index)
            self.taker_change_address = taker_change_address

            # Build maker data
            maker_data = {}
            for nick, session in self.maker_sessions.items():
                cjfee = calculate_cj_fee(session.offer, self.cj_amount)
                # JoinMarket protocol: txfee in offer is the total transaction fee
                # the maker contributes (in satoshis), not a per-input/output fee
                maker_txfee = session.offer.txfee

                maker_data[nick] = {
                    "utxos": session.utxos,
                    "cj_addr": session.cj_address,
                    "change_addr": session.change_address,
                    "cjfee": cjfee,
                    "txfee": maker_txfee,
                }

            # Build transaction
            network = self.config.network.value
            self.unsigned_tx, self.tx_metadata = build_coinjoin_tx(
                taker_utxos=[
                    {
                        "txid": u.txid,
                        "vout": u.vout,
                        "value": u.value,
                        "scriptpubkey": u.scriptpubkey,
                    }
                    for u in selected_utxos
                ],
                taker_cj_address=destination,
                taker_change_address=taker_change_address,
                taker_total_input=taker_total,
                maker_data=maker_data,
                cj_amount=self.cj_amount,
                tx_fee=tx_fee,
                network=network,
                dust_threshold=self.config.dust_threshold,
            )

            logger.info(f"Built unsigned tx: {len(self.unsigned_tx)} bytes")

            # Log final transaction details
            logger.info(
                f"Final CoinJoin transaction details: "
                f"{num_inputs} inputs ({num_taker_inputs} taker, {num_maker_inputs} maker), "
                f"{num_outputs} outputs"
            )
            logger.info(
                f"Transaction amounts: cj_amount={self.cj_amount:,} sats, "
                f"total_maker_fees={total_maker_fee:,} sats, "
                f"mining_fee={tx_fee:,} sats "
                f"({self._fee_rate:.2f} sat/vB)"
            )
            logger.info(f"Participating makers: {', '.join(self.maker_sessions.keys())}")

            return True

        except Exception as e:
            logger.error(f"Failed to build transaction: {e}")
            return False

    def _estimate_tx_fee(
        self, num_inputs: int, num_outputs: int, *, use_base_rate: bool = False
    ) -> int:
        """Estimate transaction fee.

        Uses the fee rate from _resolve_fee_rate() which must be called before
        this method. By default, uses the session's randomized fee rate for
        privacy. For sweep budget calculations, use_base_rate=True to get
        a deterministic estimate.

        Args:
            num_inputs: Number of transaction inputs
            num_outputs: Number of transaction outputs
            use_base_rate: If True, use the base fee rate instead of the
                          session's randomized rate. Used for sweep cj_amount
                          calculations where determinism is required.

        Returns:
            Estimated fee in satoshis
        """
        import math

        # P2WPKH: ~68 vbytes per input, 31 vbytes per output, ~11 overhead
        vsize = num_inputs * 68 + num_outputs * 31 + 11

        # Use base rate for deterministic calculations (sweeps),
        # otherwise use the session's randomized rate for privacy
        if use_base_rate:
            rate = self._fee_rate if self._fee_rate is not None else 1.0
        else:
            rate = self._randomized_fee_rate if self._randomized_fee_rate is not None else 1.0

        return math.ceil(vsize * rate)

    async def _resolve_fee_rate(self) -> float:
        """
        Resolve the fee rate to use for the current CoinJoin.

        Priority:
        1. Manual fee_rate from config
        2. Backend fee estimation with fee_block_target
        3. Default 3-block estimation if backend supports it
        4. Fallback to 1 sat/vB

        The resolved fee rate is also checked against mempool minimum fee
        (if available) to ensure transactions are accepted.

        Returns:
            Fee rate in sat/vB (cached in self._fee_rate)

        Raises:
            ValueError: If fee_block_target specified with neutrino backend
        """
        # If already resolved, return cached value
        if self._fee_rate is not None:
            return self._fee_rate

        # Get mempool minimum fee (if available) as a floor
        mempool_min_fee: float | None = None
        try:
            mempool_min_fee = await self.backend.get_mempool_min_fee()
            if mempool_min_fee is not None:
                logger.debug(f"Mempool min fee: {mempool_min_fee:.2f} sat/vB")
        except Exception:
            # Backend may not support this method
            pass

        # 1. Manual fee rate takes priority
        if self.config.fee_rate is not None:
            self._fee_rate = self.config.fee_rate
            # Check against mempool min fee
            if mempool_min_fee is not None and self._fee_rate < mempool_min_fee:
                logger.warning(
                    f"Manual fee rate {self._fee_rate:.2f} sat/vB is below mempool min "
                    f"{mempool_min_fee:.2f} sat/vB, using mempool min"
                )
                self._fee_rate = mempool_min_fee
            logger.info(f"Using manual fee rate: {self._fee_rate:.2f} sat/vB")
            self._apply_fee_randomization()
            return self._fee_rate

        # 2. Block target specified - check backend capability
        if self.config.fee_block_target is not None:
            if not self.backend.can_estimate_fee():
                raise ValueError(
                    "Cannot use --block-target with neutrino backend. "
                    "Fee estimation requires a full node. "
                    "Use --fee-rate to specify a manual rate instead."
                )
            self._fee_rate = await self.backend.estimate_fee(self.config.fee_block_target)
            # Check against mempool min fee
            if mempool_min_fee is not None and self._fee_rate < mempool_min_fee:
                logger.info(
                    f"Estimated fee {self._fee_rate:.2f} sat/vB is below mempool min "
                    f"{mempool_min_fee:.2f} sat/vB, using mempool min"
                )
                self._fee_rate = mempool_min_fee
            logger.info(
                f"Fee estimation for {self.config.fee_block_target} blocks: "
                f"{self._fee_rate:.2f} sat/vB"
            )
            self._apply_fee_randomization()
            return self._fee_rate

        # 3. Default: 3-block estimation if backend supports it
        if self.backend.can_estimate_fee():
            default_target = 3
            self._fee_rate = await self.backend.estimate_fee(default_target)
            # Check against mempool min fee
            if mempool_min_fee is not None and self._fee_rate < mempool_min_fee:
                logger.info(
                    f"Estimated fee {self._fee_rate:.2f} sat/vB is below mempool min "
                    f"{mempool_min_fee:.2f} sat/vB, using mempool min"
                )
                self._fee_rate = mempool_min_fee
            logger.info(
                f"Fee estimation for {default_target} blocks (default): {self._fee_rate:.2f} sat/vB"
            )
            self._apply_fee_randomization()
            return self._fee_rate

        # 4. Fallback for neutrino without manual fee
        self._fee_rate = 1.0
        logger.warning(
            "No fee estimation available (neutrino backend). "
            "Using fallback rate: 1.0 sat/vB. "
            "Consider using --fee-rate for production."
        )
        self._apply_fee_randomization()
        return self._fee_rate

    def _apply_fee_randomization(self) -> None:
        """Apply tx_fee_factor randomization to get the session's fee rate.

        This is called once per CoinJoin session to determine the randomized
        fee rate used for all fee calculations. The randomization provides
        privacy by varying the fee rate within the configured range.

        The randomized rate is stored in self._randomized_fee_rate and used
        by _estimate_tx_fee() for all calculations.
        """
        import random

        if self._fee_rate is None:
            return

        base_rate = self._fee_rate

        if self.config.tx_fee_factor > 0:
            # Randomize between base and base * (1 + factor)
            self._randomized_fee_rate = random.uniform(
                base_rate, base_rate * (1 + self.config.tx_fee_factor)
            )
            logger.debug(
                f"Fee rate randomized: base={base_rate:.2f}, "
                f"randomized={self._randomized_fee_rate:.2f} sat/vB "
                f"(factor={self.config.tx_fee_factor})"
            )
        else:
            self._randomized_fee_rate = base_rate

    def _get_taker_cj_output_index(self) -> int | None:
        """
        Find the index of the taker's CoinJoin output in the transaction.

        Uses tx_metadata["output_owners"] which tracks (owner, type) for each output.
        The taker's CJ output is marked as ("taker", "cj").

        Returns:
            Output index (vout) or None if not found
        """
        output_owners = self.tx_metadata.get("output_owners", [])
        for idx, (owner, out_type) in enumerate(output_owners):
            if owner == "taker" and out_type == "cj":
                return idx
        return None

    def _get_taker_change_output_index(self) -> int | None:
        """
        Find the index of the taker's change output in the transaction.

        Uses tx_metadata["output_owners"] which tracks (owner, type) for each output.
        The taker's change output is marked as ("taker", "change").

        Returns:
            Output index (vout) or None if not found
        """
        output_owners = self.tx_metadata.get("output_owners", [])
        for idx, (owner, out_type) in enumerate(output_owners):
            if owner == "taker" and out_type == "change":
                return idx
        return None

    async def _phase_collect_signatures(self) -> bool:
        """Send !tx and collect !sig responses from makers.

        The reference maker sends signatures in TRANSACTION INPUT ORDER, not in the
        order UTXOs were originally provided. We must match signatures to transaction
        inputs by verifying which UTXO each signature is valid for, not by index.
        """
        # Encode transaction as base64 (expected by maker after decryption)
        import base64

        tx_b64 = base64.b64encode(self.unsigned_tx).decode("ascii")

        # Record history BEFORE sending !tx to makers.
        # This ensures addresses are persisted before they're revealed in the transaction.
        # If we crash after sending !tx but before broadcast, the addresses won't be reused.
        try:
            total_maker_fees = sum(
                calculate_cj_fee(session.offer, self.cj_amount)
                for session in self.maker_sessions.values()
            )
            maker_nicks = list(self.maker_sessions.keys())

            history_entry = create_taker_history_entry(
                maker_nicks=maker_nicks,
                cj_amount=self.cj_amount,
                total_maker_fees=total_maker_fees,
                mining_fee=0,  # Will be updated after signing
                destination=self.cj_destination,
                change_address=self.taker_change_address,
                source_mixdepth=self.tx_metadata.get("source_mixdepth", 0),
                selected_utxos=[(utxo.txid, utxo.vout) for utxo in self.selected_utxos],
                txid="",  # Will be updated after broadcast
                broadcast_method=self.config.tx_broadcast.value,
                network=self.config.network.value,
                failure_reason="Awaiting transaction",
            )
            append_history_entry(history_entry, data_dir=self.config.data_dir)
            logger.debug(
                f"Recorded pre-broadcast history entry for CJ to {self.cj_destination[:20]}..."
            )
        except Exception as e:
            logger.warning(f"Failed to record pre-broadcast history: {e}")
            # Continue anyway - the CoinJoin can still proceed

        # Send ENCRYPTED !tx to each maker
        for nick, session in self.maker_sessions.items():
            if session.crypto is None:
                logger.error(f"No encryption session for {nick}")
                continue

            encrypted_tx = session.crypto.encrypt(tx_b64)
            await self.directory_client.send_privmsg(
                nick, "tx", encrypted_tx, log_routing=True, force_channel=session.comm_channel
            )

        # Build expected signature counts for early termination
        expected_counts = {
            nick: len(session.utxos) for nick, session in self.maker_sessions.items()
        }

        # Wait for all !sig responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())
        signatures: dict[str, list[dict[str, Any]]] = {}

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!sig",
            timeout=timeout,
            expected_counts=expected_counts,
        )

        # Deserialize transaction for signature verification
        # We use verification-based matching: verify each signature against inputs
        # to find the correct match, rather than relying on ordering.
        try:
            tx = deserialize_transaction(self.unsigned_tx)
        except Exception as e:
            logger.error(f"Failed to deserialize transaction: {e}")
            return False

        # Build a map of input_index -> (txid_hex, vout)
        input_map: dict[int, tuple[str, int]] = {}
        for idx, tx_input in enumerate(tx.inputs):
            txid_hex = tx_input.txid_le[::-1].hex()
            input_map[idx] = (txid_hex, tx_input.vout)

        # Process responses
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                try:
                    session = self.maker_sessions[nick]
                    if session.crypto is None:
                        logger.warning(f"No encryption session for {nick}")
                        del self.maker_sessions[nick]
                        continue

                    # Get all signature messages for this maker
                    response_data_list = responses[nick]["data"]
                    if not isinstance(response_data_list, list):
                        response_data_list = [response_data_list]

                    if not response_data_list:
                        logger.warning(f"Empty !sig response from {nick}")
                        del self.maker_sessions[nick]
                        continue

                    # Identify this maker's input indices in the transaction
                    maker_utxo_map = {(u["txid"], u["vout"]): u for u in session.utxos}
                    maker_input_indices: list[int] = []

                    for idx, (txid, vout) in input_map.items():
                        if (txid, vout) in maker_utxo_map:
                            maker_input_indices.append(idx)

                    if len(maker_input_indices) != len(session.utxos):
                        logger.warning(
                            f"UTXO count mismatch for {nick}: found {len(maker_input_indices)} "
                            f"inputs in tx, expected {len(session.utxos)}"
                        )
                        # Continue anyway, maybe some UTXOs were excluded (though shouldn't happen)

                    # Process signatures with verification
                    sig_infos: list[dict[str, Any]] = []
                    matched_indices: set[int] = set()

                    for sig_idx, response_data in enumerate(response_data_list):
                        parts = response_data.strip().split()
                        if not parts:
                            continue

                        encrypted_data = parts[0]
                        decrypted_sig = session.crypto.decrypt(encrypted_data)

                        # Parse signature (same as before)
                        padding_needed = (4 - len(decrypted_sig) % 4) % 4
                        padded_sig = decrypted_sig + "=" * padding_needed
                        sig_bytes = base64.b64decode(padded_sig)
                        sig_len = sig_bytes[0]
                        signature = sig_bytes[1 : 1 + sig_len]
                        pub_len = sig_bytes[1 + sig_len]
                        pubkey = sig_bytes[2 + sig_len : 2 + sig_len + pub_len]

                        # Try to verify against each of maker's inputs
                        matched_input_idx = None

                        for idx in maker_input_indices:
                            if idx in matched_indices:
                                continue

                            txid, vout = input_map[idx]
                            utxo = maker_utxo_map[(txid, vout)]
                            value = utxo["value"]

                            # Create scriptCode for verification
                            script_code = create_p2wpkh_script_code(pubkey)

                            if verify_p2wpkh_signature(
                                tx, idx, script_code, value, signature, pubkey
                            ):
                                matched_input_idx = idx
                                break

                        if matched_input_idx is not None:
                            matched_indices.add(matched_input_idx)
                            txid, vout = input_map[matched_input_idx]
                            witness = [signature.hex(), pubkey.hex()]

                            sig_infos.append({"txid": txid, "vout": vout, "witness": witness})
                            logger.debug(
                                f"Verified signature from {nick} matches input {matched_input_idx} "
                                f"({txid[:16]}...:{vout})"
                            )
                        else:
                            logger.warning(
                                f"Signature #{sig_idx + 1} from {nick} "
                                "did not verify against any input"
                            )

                    if len(sig_infos) != len(session.utxos):
                        logger.warning(
                            f"Signature count mismatch for {nick}: "
                            f"verified {len(sig_infos)}, expected {len(session.utxos)}"
                        )
                        del self.maker_sessions[nick]
                        continue

                    signatures[nick] = sig_infos
                    session.signature = {"signatures": sig_infos}
                    session.responded_sig = True
                    logger.debug(f"Processed {len(sig_infos)} verified signatures from {nick}")

                except Exception as e:
                    logger.warning(f"Invalid !sig response from {nick}: {e}")
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !sig response from {nick}")
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough signatures: {len(self.maker_sessions)}")
            return False

        # Add signatures to transaction
        builder = CoinJoinTxBuilder(self.config.network.value)

        # Add taker's signatures
        taker_sigs = await self._sign_our_inputs()
        signatures["taker"] = taker_sigs

        self.final_tx = builder.add_signatures(
            self.unsigned_tx,
            signatures,
            self.tx_metadata,
        )

        logger.info(f"Signed tx: {len(self.final_tx)} bytes")
        return True

    async def _sign_our_inputs(self) -> list[dict[str, Any]]:
        """
        Sign taker's inputs in the transaction.

        Finds the correct input indices in the shuffled transaction by matching
        txid:vout from selected UTXOs, then signs each input.

        Returns:
            List of signature info dicts with txid, vout, signature, pubkey, witness
        """
        try:
            if not self.unsigned_tx:
                logger.error("No unsigned transaction to sign")
                return []

            if not self.selected_utxos:
                logger.error("No selected UTXOs to sign")
                return []

            tx = deserialize_transaction(self.unsigned_tx)
            signatures_info: list[dict[str, Any]] = []

            # Build a map of (txid, vout) -> input index for the transaction
            # Note: txid in tx.inputs is little-endian bytes, need to convert
            input_index_map: dict[tuple[str, int], int] = {}
            for idx, tx_input in enumerate(tx.inputs):
                # Convert little-endian txid bytes to big-endian hex string (RPC format)
                txid_hex = tx_input.txid_le[::-1].hex()
                input_index_map[(txid_hex, tx_input.vout)] = idx

            # Sign each of our UTXOs
            for utxo in self.selected_utxos:
                # Find the input index in the transaction
                utxo_key = (utxo.txid, utxo.vout)
                if utxo_key not in input_index_map:
                    logger.error(f"UTXO {utxo.txid}:{utxo.vout} not found in transaction inputs")
                    continue

                input_index = input_index_map[utxo_key]

                # Safety check: Fidelity bond (P2WSH) UTXOs should never be in CoinJoins
                if utxo.is_p2wsh:
                    raise TransactionSigningError(
                        f"Cannot sign P2WSH UTXO {utxo.txid}:{utxo.vout} in CoinJoin - "
                        f"fidelity bond UTXOs cannot be used in CoinJoins"
                    )

                # Get the key for this address
                key = self.wallet.get_key_for_address(utxo.address)
                if not key:
                    raise TransactionSigningError(f"Missing key for address {utxo.address}")

                priv_key = key.private_key
                pubkey_bytes = key.get_public_key_bytes(compressed=True)

                # Create script code and sign
                script_code = create_p2wpkh_script_code(pubkey_bytes)
                signature = sign_p2wpkh_input(
                    tx=tx,
                    input_index=input_index,
                    script_code=script_code,
                    value=utxo.value,
                    private_key=priv_key,
                )

                # Create witness stack
                witness = create_witness_stack(signature, pubkey_bytes)

                signatures_info.append(
                    {
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "signature": signature.hex(),
                        "pubkey": pubkey_bytes.hex(),
                        "witness": [item.hex() for item in witness],
                    }
                )

                logger.debug(f"Signed input {input_index} for UTXO {utxo.txid}:{utxo.vout}")

            logger.info(f"Signed {len(signatures_info)} taker inputs")
            return signatures_info

        except TransactionSigningError as e:
            logger.error(f"Signing error: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to sign transaction: {e}")
            return []

    def _log_manual_csv_entry(
        self, total_maker_fees: int, mining_fee: int, destination: str
    ) -> None:
        """
        Log a CSV entry that can be manually added for tracking unbroadcast transactions.

        When users decline to broadcast or want to broadcast manually, this logs
        the CSV entry they can add to coinjoin_history.csv for tracking.
        """
        try:
            txid = get_txid(self.final_tx.hex())
            maker_nicks = list(self.maker_sessions.keys())
            broadcast_method = self.config.tx_broadcast.value

            history_entry = create_taker_history_entry(
                maker_nicks=maker_nicks,
                cj_amount=self.cj_amount,
                total_maker_fees=total_maker_fees,
                mining_fee=mining_fee,
                destination=destination,
                source_mixdepth=self.tx_metadata.get("source_mixdepth", 0),
                selected_utxos=[(utxo.txid, utxo.vout) for utxo in self.selected_utxos],
                txid=txid,
                broadcast_method=broadcast_method,
                network=self.config.network.value,
                failure_reason="User declined broadcast (manual broadcast pending)",
            )

            # Format as CSV line for manual addition
            from dataclasses import fields

            fieldnames = [f.name for f in fields(history_entry)]
            values = [str(getattr(history_entry, f)) for f in fieldnames]

            logger.info("-" * 70)
            logger.info("MANUAL CSV ENTRY - Add to coinjoin_history.csv if broadcasting manually:")
            logger.info(f"txid: {txid}")
            logger.info(f"CSV line: {','.join(values)}")
            logger.info("-" * 70)
        except Exception as e:
            logger.warning(f"Failed to generate manual CSV entry: {e}")

    async def _phase_broadcast(self) -> str:
        """
        Broadcast the signed transaction based on the configured policy.

        Privacy implications:
        - SELF: Taker broadcasts via own node. Links taker's IP to the transaction.
        - RANDOM_PEER: Random maker selected. Falls back to next maker on failure,
                       then self as last resort. Good balance of privacy and reliability.
        - MULTIPLE_PEERS: Broadcast to N random makers simultaneously (default 3).
                          Falls back to self if all fail. Recommended for Neutrino.
        - NOT_SELF: Try makers sequentially, never self. Maximum privacy.
                    WARNING: No fallback if all makers fail!

        Neutrino notes:
        - Cannot verify mempool transactions (only confirmed blocks)
        - Self-fallback allowed but verification skipped (trusts broadcast succeeded)

        Returns:
            Transaction ID if successful, empty string otherwise
        """
        import base64
        import random

        policy = self.config.tx_broadcast
        has_mempool = self.backend.has_mempool_access()
        logger.info(f"Broadcasting with policy: {policy.value}, mempool_access: {has_mempool}")

        # Encode transaction as base64 for !push message
        tx_b64 = base64.b64encode(self.final_tx).decode("ascii")

        # Calculate expected txid upfront (needed for Neutrino)
        from taker.tx_builder import CoinJoinTxBuilder

        builder = CoinJoinTxBuilder(self.config.bitcoin_network or self.config.network)
        expected_txid = builder.get_txid(self.final_tx)

        # Build list of broadcast candidates based on policy
        maker_nicks = list(self.maker_sessions.keys())

        if policy == BroadcastPolicy.SELF:
            # Always broadcast via own node
            return await self._broadcast_self()

        elif policy == BroadcastPolicy.RANDOM_PEER:
            # Try makers in random order, fall back to self as last resort
            if not maker_nicks:
                logger.warning("RANDOM_PEER policy but no makers available, using self")
                return await self._broadcast_self()

            random.shuffle(maker_nicks)

            for candidate in maker_nicks:
                txid = await self._broadcast_via_maker(candidate, tx_b64)
                if txid:
                    return txid

            # Last resort: self-broadcast
            logger.warning("All makers failed, falling back to self-broadcast")
            return await self._broadcast_self()

        elif policy == BroadcastPolicy.MULTIPLE_PEERS:
            # Broadcast to N random makers simultaneously, fall back to self
            if not maker_nicks:
                logger.warning("MULTIPLE_PEERS policy but no makers available, using self")
                return await self._broadcast_self()

            # Select N random makers (or all if less than N)
            peer_count = min(self.config.broadcast_peer_count, len(maker_nicks))
            selected_peers = random.sample(maker_nicks, peer_count)

            success_count = await self._broadcast_to_all_makers(selected_peers, tx_b64)

            if success_count > 0:
                if has_mempool:
                    logger.info(
                        f"Broadcast sent to {success_count}/{peer_count} makers "
                        "(MULTIPLE_PEERS policy)."
                    )
                else:
                    logger.info(
                        f"Broadcast sent to {success_count}/{peer_count} makers "
                        f"(MULTIPLE_PEERS policy). Transaction {expected_txid} will be "
                        "confirmed via block monitoring (Neutrino cannot verify mempool)"
                    )
                return expected_txid

            # All peers failed, fall back to self
            logger.warning(f"All {peer_count} peer broadcast attempts failed, falling back to self")
            return await self._broadcast_self()

        elif policy == BroadcastPolicy.NOT_SELF:
            # Only makers can broadcast - no self fallback
            if not maker_nicks:
                logger.error("NOT_SELF policy but no makers available")
                return ""

            # Try makers in random order with verification
            random.shuffle(maker_nicks)

            for maker_nick in maker_nicks:
                txid = await self._broadcast_via_maker(maker_nick, tx_b64)
                if txid:
                    return txid

            # No fallback for NOT_SELF - log the transaction for manual broadcast
            logger.error(
                "All maker broadcast attempts failed. "
                "Transaction hex (for manual broadcast): "
                f"{self.final_tx.hex()}"
            )
            return ""

        else:
            # Unknown policy, fallback to self
            logger.warning(f"Unknown broadcast policy {policy}, falling back to self")
            return await self._broadcast_self()

    async def _broadcast_to_all_makers(self, maker_nicks: list[str], tx_b64: str) -> int:
        """
        Send !push to all makers simultaneously for redundant broadcast.

        This is used by Neutrino takers who cannot verify mempool transactions.
        By broadcasting to all makers, we maximize the chance that at least one
        will successfully broadcast the transaction to the Bitcoin network.

        Privacy note: All makers already participated in the CoinJoin, so they
        all know the transaction. Sending !push to all of them doesn't reveal
        any new information.

        Args:
            maker_nicks: List of maker nicks to send !push to
            tx_b64: Base64-encoded signed transaction

        Returns:
            Number of makers that successfully received the !push message
        """
        import asyncio

        async def send_push(nick: str) -> bool:
            """Send !push to a single maker, return True if no exception."""
            try:
                # Get the comm_channel from maker_sessions if available
                session = self.maker_sessions.get(nick)
                force_channel = session.comm_channel if session else None
                await self.directory_client.send_privmsg(
                    nick, "push", tx_b64, log_routing=True, force_channel=force_channel
                )
                return True
            except Exception as e:
                logger.warning(f"Failed to send !push to {nick}: {e}")
                return False

        # Send to all makers concurrently
        results = await asyncio.gather(*[send_push(nick) for nick in maker_nicks])

        success_count = sum(1 for r in results if r)
        logger.info(f"!push sent to {success_count}/{len(maker_nicks)} makers")

        return success_count

    async def _broadcast_self(self) -> str:
        """
        Broadcast transaction via our own backend.

        Handles the case where a maker may have already broadcast the transaction,
        which would cause our broadcast to fail with "inputs already spent" or
        "already in mempool". In these cases, we verify the transaction exists
        and treat it as success.
        """
        from taker.tx_builder import CoinJoinTxBuilder

        try:
            txid = await self.backend.broadcast_transaction(self.final_tx.hex())
            logger.info(f"Broadcast via self successful: {txid}")
            return txid
        except Exception as e:
            error_str = str(e).lower()

            # Check if error indicates the transaction was already broadcast
            # This can happen in multi-node setups where a maker broadcast to a
            # different node that hasn't synced with ours yet, but then syncs
            # before we try to self-broadcast.
            already_broadcast_indicators = [
                "bad-txns-inputs-missingorspent",  # Inputs already spent
                "txn-already-in-mempool",  # Already in our mempool
                "txn-mempool-conflict",  # Conflicts with mempool tx
                "missing-inputs",  # Alternative wording for spent inputs
            ]

            if any(ind in error_str for ind in already_broadcast_indicators):
                logger.info(
                    f"Self-broadcast rejected ({e}), checking if transaction "
                    "was already broadcast by a maker..."
                )

                # Calculate expected txid and verify the CoinJoin output exists
                builder = CoinJoinTxBuilder(self.config.bitcoin_network or self.config.network)
                expected_txid = builder.get_txid(self.final_tx)

                # Get taker's CJ output index for verification
                taker_cj_vout = self._get_taker_cj_output_index()
                if taker_cj_vout is None:
                    logger.warning("Could not find taker CJ output index for verification")
                    return ""

                # Get block height for verification hint
                try:
                    current_height = await self.backend.get_block_height()
                except Exception:
                    current_height = None

                # Verify the CoinJoin output exists (transaction was broadcast)
                cj_verified = await self.backend.verify_tx_output(
                    txid=expected_txid,
                    vout=taker_cj_vout,
                    address=self.cj_destination,
                    start_height=current_height,
                )

                if cj_verified:
                    logger.info(f"Transaction was already broadcast by maker: {expected_txid}")
                    return expected_txid

                # Not verified - could be a race condition or actual failure
                # Wait a bit and try once more (transaction might be propagating)
                await asyncio.sleep(3)
                cj_verified = await self.backend.verify_tx_output(
                    txid=expected_txid,
                    vout=taker_cj_vout,
                    address=self.cj_destination,
                    start_height=current_height,
                )

                if cj_verified:
                    logger.info(f"Transaction confirmed after propagation delay: {expected_txid}")
                    return expected_txid

                logger.warning(f"Self-broadcast failed and transaction not found: {e}")
                return ""

            logger.warning(f"Self-broadcast failed: {e}")
            return ""

    async def _broadcast_via_maker(self, maker_nick: str, tx_b64: str) -> str:
        """
        Request a maker to broadcast the transaction.

        Sends !push command and waits briefly for the transaction to appear.
        We don't expect a response from the maker - they broadcast unquestioningly.

        Verification is done using verify_tx_output() which works with all backends
        including Neutrino (which can't fetch arbitrary transactions by txid).
        We verify both CJ and change outputs for extra confidence.

        Args:
            maker_nick: The maker's nick to send the push request to
            tx_b64: Base64-encoded signed transaction

        Returns:
            Transaction ID if broadcast detected, empty string otherwise
        """
        try:
            start_time = time.time()
            logger.info(f"Requesting broadcast via maker: {maker_nick}")

            # Send !push to the maker (unencrypted, like reference implementation)
            # Use the same comm_channel as the rest of the session
            session = self.maker_sessions.get(maker_nick)
            force_channel = session.comm_channel if session else None
            await self.directory_client.send_privmsg(
                maker_nick, "push", tx_b64, log_routing=True, force_channel=force_channel
            )

            # Wait and check if the transaction was broadcast
            await asyncio.sleep(2)  # Give maker time to broadcast

            # Calculate the expected txid
            from taker.tx_builder import CoinJoinTxBuilder

            builder = CoinJoinTxBuilder(self.config.bitcoin_network or self.config.network)
            expected_txid = builder.get_txid(self.final_tx)

            # Get current block height for Neutrino optimization
            try:
                current_height = await self.backend.get_block_height()
            except Exception as e:
                logger.debug(f"Could not get block height: {e}, proceeding without hint")
                current_height = None

            # Get taker's CJ output index for verification
            taker_cj_vout = self._get_taker_cj_output_index()
            if taker_cj_vout is None:
                logger.warning("Could not find taker CJ output index for verification")
                # Can't verify without output index - treat as unverified failure
                return ""

            # Also get change output for additional verification
            taker_change_vout = self._get_taker_change_output_index()

            # Verify the transaction was broadcast by checking our CJ output exists
            # This works with all backends including Neutrino (uses address-based lookup)
            verify_start = time.time()
            cj_verified = await self.backend.verify_tx_output(
                txid=expected_txid,
                vout=taker_cj_vout,
                address=self.cj_destination,
                start_height=current_height,
            )
            verify_time = time.time() - verify_start

            # Also verify change output if it exists (extra confidence)
            change_verified = True  # Default to True if no change output
            if taker_change_vout is not None and self.taker_change_address:
                change_verify_start = time.time()
                change_verified = await self.backend.verify_tx_output(
                    txid=expected_txid,
                    vout=taker_change_vout,
                    address=self.taker_change_address,
                    start_height=current_height,
                )
                change_verify_time = time.time() - change_verify_start
                logger.debug(
                    f"Change output verification: {change_verified} "
                    f"(took {change_verify_time:.2f}s)"
                )

            if cj_verified and change_verified:
                total_time = time.time() - start_time
                logger.info(
                    f"Transaction broadcast via {maker_nick} confirmed: {expected_txid} "
                    f"(CJ verify: {verify_time:.2f}s, total: {total_time:.2f}s)"
                )
                return expected_txid

            # Wait longer and try once more
            await asyncio.sleep(self.config.broadcast_timeout_sec - 2)

            verify_start = time.time()
            cj_verified = await self.backend.verify_tx_output(
                txid=expected_txid,
                vout=taker_cj_vout,
                address=self.cj_destination,
                start_height=current_height,
            )
            verify_time = time.time() - verify_start

            # Verify change output again if it exists
            if taker_change_vout is not None and self.taker_change_address:
                change_verified = await self.backend.verify_tx_output(
                    txid=expected_txid,
                    vout=taker_change_vout,
                    address=self.taker_change_address,
                    start_height=current_height,
                )

            if cj_verified and change_verified:
                total_time = time.time() - start_time
                logger.info(
                    f"Transaction broadcast via {maker_nick} confirmed: {expected_txid} "
                    f"(CJ verify: {verify_time:.2f}s, total: {total_time:.2f}s)"
                )
                return expected_txid

            # Could not verify broadcast
            total_time = time.time() - start_time
            logger.debug(
                f"Could not confirm broadcast via {maker_nick} - "
                f"CJ output {expected_txid}:{taker_cj_vout} verified={cj_verified}, "
                f"change output verified={change_verified} (took {total_time:.2f}s)"
            )
            return ""

        except Exception as e:
            logger.warning(f"Broadcast via maker {maker_nick} failed: {e}")
            return ""

    async def run_schedule(self, schedule: Schedule) -> bool:
        """
        Run a tumbler-style schedule of CoinJoins.

        Args:
            schedule: Schedule with multiple CoinJoin entries

        Returns:
            True if all entries completed successfully
        """
        self.schedule = schedule

        while not schedule.is_complete():
            entry = schedule.current_entry()
            if not entry:
                break

            logger.info(
                f"Running schedule entry {schedule.current_index + 1}/{len(schedule.entries)}"
            )

            # Calculate actual amount
            if entry.amount_fraction is not None:
                # Fraction of balance
                balance = await self.wallet.get_balance(entry.mixdepth)
                amount = int(balance * entry.amount_fraction)
            else:
                assert entry.amount is not None
                amount = entry.amount

            # Execute CoinJoin
            txid = await self.do_coinjoin(
                amount=amount,
                destination=entry.destination,
                mixdepth=entry.mixdepth,
                counterparty_count=entry.counterparty_count,
            )

            if not txid:
                logger.error(f"Schedule entry {schedule.current_index + 1} failed")
                return False

            # Advance schedule
            schedule.advance()

            # Wait between CoinJoins
            if entry.wait_time > 0 and not schedule.is_complete():
                logger.info(f"Waiting {entry.wait_time}s before next CoinJoin...")
                await asyncio.sleep(entry.wait_time)

        logger.info("Schedule complete!")
        return True
