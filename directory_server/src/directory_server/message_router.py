"""
Message routing logic for forwarding messages between peers.

Implements Single Responsibility Principle: only handles message routing.
"""

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Iterator

from jmcore.models import MessageEnvelope, NetworkType, PeerInfo
from jmcore.protocol import MessageType, create_peerlist_entry, parse_jm_message
from loguru import logger

from directory_server.peer_registry import PeerRegistry

SendCallback = Callable[[str, bytes], Awaitable[None]]
FailedSendCallback = Callable[[str], Awaitable[None]]

# Default batch size for concurrent broadcasts to limit memory usage
# This can be overridden via Settings.broadcast_batch_size
DEFAULT_BROADCAST_BATCH_SIZE = 50


class MessageRouter:
    def __init__(
        self,
        peer_registry: PeerRegistry,
        send_callback: SendCallback,
        broadcast_batch_size: int = DEFAULT_BROADCAST_BATCH_SIZE,
        on_send_failed: FailedSendCallback | None = None,
    ):
        self.peer_registry = peer_registry
        self.send_callback = send_callback
        self.broadcast_batch_size = broadcast_batch_size
        self.on_send_failed = on_send_failed
        # Track peers that failed during current operation to avoid repeated attempts
        self._failed_peers: set[str] = set()

    async def route_message(self, envelope: MessageEnvelope, from_key: str) -> None:
        if envelope.message_type == MessageType.PUBMSG:
            await self._handle_public_message(envelope, from_key)
        elif envelope.message_type == MessageType.PRIVMSG:
            await self._handle_private_message(envelope, from_key)
        elif envelope.message_type == MessageType.GETPEERLIST:
            await self._handle_peerlist_request(from_key)
        elif envelope.message_type == MessageType.PING:
            await self._handle_ping(from_key)
        else:
            logger.debug(f"Unhandled message type: {envelope.message_type}")

    async def _handle_public_message(self, envelope: MessageEnvelope, from_key: str) -> None:
        parsed = parse_jm_message(envelope.payload)
        if not parsed:
            logger.warning("Invalid public message format")
            return

        from_nick, to_nick, _ = parsed
        if to_nick != "PUBLIC":
            logger.warning(f"Public message not addressed to PUBLIC: {to_nick}")
            return

        from_peer = self.peer_registry.get_by_key(from_key)
        if not from_peer:
            logger.warning(f"Unknown peer sending public message: {from_key}")
            return

        # Pre-serialize envelope once instead of per-peer
        envelope_bytes = envelope.to_bytes()

        # Use generator to avoid building full target list in memory
        def target_generator() -> Iterator[tuple[str, str | None]]:
            for peer in self.peer_registry.iter_connected(from_peer.network):
                peer_key = (
                    peer.nick
                    if peer.location_string == "NOT-SERVING-ONION"
                    else peer.location_string
                )
                if peer_key != from_key:
                    yield (peer_key, peer.nick)

        # Execute sends in batches to limit memory usage
        sent_count = await self._batched_broadcast_iter(target_generator(), envelope_bytes)

        logger.trace(f"Broadcasted public message from {from_nick} to {sent_count} peers")

    async def _safe_send(self, peer_key: str, data: bytes, nick: str | None = None) -> None:
        """Send with exception handling to prevent one failed send from affecting others."""
        # Skip if this peer already failed in current operation
        if peer_key in self._failed_peers:
            return

        try:
            await self.send_callback(peer_key, data)
        except Exception as e:
            logger.warning(f"Failed to send to {nick or peer_key}: {e}")
            # Mark peer as failed to prevent repeated attempts
            self._failed_peers.add(peer_key)
            # Notify server to clean up this peer
            if self.on_send_failed:
                try:
                    await self.on_send_failed(peer_key)
                except Exception as cleanup_err:
                    logger.trace(f"Error in on_send_failed callback: {cleanup_err}")

    async def _batched_broadcast(self, targets: list[tuple[str, str | None]], data: bytes) -> int:
        """
        Broadcast data to targets in batches to limit memory usage.

        Instead of creating all coroutines at once (which caused 2GB+ memory usage),
        we process in batches of broadcast_batch_size to keep memory bounded.

        Returns the number of targets processed.
        """
        return await self._batched_broadcast_iter(iter(targets), data)

    async def _batched_broadcast_iter(
        self, targets: Iterator[tuple[str, str | None]], data: bytes
    ) -> int:
        """
        Broadcast data to targets from an iterator in batches.

        This is the memory-efficient version that consumes targets lazily,
        only materializing batch_size items at a time.

        Returns the number of targets processed.
        """
        # Clear failed peers set at start of broadcast to allow fresh attempts
        # while still preventing repeated attempts within this broadcast
        self._failed_peers.clear()

        total_sent = 0
        batch: list[tuple[str, str | None]] = []

        for target in targets:
            peer_key, nick = target
            # Skip peers that have already failed in this broadcast
            if peer_key in self._failed_peers:
                continue
            batch.append(target)

            if len(batch) >= self.broadcast_batch_size:
                tasks = [self._safe_send(pk, data, n) for pk, n in batch]
                await asyncio.gather(*tasks)
                total_sent += len(batch)
                batch = []

        # Process remaining items
        if batch:
            tasks = [self._safe_send(pk, data, n) for pk, n in batch]
            await asyncio.gather(*tasks)
            total_sent += len(batch)

        return total_sent

    async def _handle_private_message(self, envelope: MessageEnvelope, from_key: str) -> None:
        parsed = parse_jm_message(envelope.payload)
        if not parsed:
            logger.warning("Invalid private message format")
            return

        from_nick, to_nick, rest = parsed
        logger.info(f"PRIVMSG routing: {from_nick} -> {to_nick} (rest: {rest[:50]}...)")

        to_peer = self.peer_registry.get_by_nick(to_nick)
        if not to_peer:
            logger.warning(f"Target peer not found: {to_nick}")
            # Log all registered peers for debugging
            all_peers = list(self.peer_registry._peers.keys())
            logger.info(f"Registered peer keys: {all_peers}")
            nick_map = dict(self.peer_registry._nick_to_key)
            logger.info(f"Nick to key map: {nick_map}")
            return

        from_peer = self.peer_registry.get_by_key(from_key)
        if not from_peer or from_peer.network != to_peer.network:
            logger.warning("Network mismatch or unknown sender")
            return

        try:
            to_peer_key = (
                to_peer.nick
                if to_peer.location_string == "NOT-SERVING-ONION"
                else to_peer.location_string
            )
            logger.info(f"Sending to peer_key: {to_peer_key}")
            await self.send_callback(to_peer_key, envelope.to_bytes())
            logger.info(f"Successfully routed private message: {from_nick} -> {to_nick}")

            await self._send_peer_location(to_peer_key, from_peer)
        except Exception as e:
            logger.warning(f"Failed to route private message to {to_nick}: {e}")
            # Notify server to clean up this peer's mapping
            if self.on_send_failed:
                to_peer_key = (
                    to_peer.nick
                    if to_peer.location_string == "NOT-SERVING-ONION"
                    else to_peer.location_string
                )
                with contextlib.suppress(Exception):
                    await self.on_send_failed(to_peer_key)

    async def _handle_peerlist_request(self, from_key: str) -> None:
        peer = self.peer_registry.get_by_key(from_key)
        if not peer:
            return

        await self.send_peerlist(from_key, peer.network)

    async def _handle_ping(self, from_key: str) -> None:
        pong_envelope = MessageEnvelope(message_type=MessageType.PONG, payload="")
        try:
            await self.send_callback(from_key, pong_envelope.to_bytes())
            logger.trace(f"Sent PONG to {from_key}")
        except Exception as e:
            logger.trace(f"Failed to send PONG: {e}")

    async def send_peerlist(self, to_key: str, network: NetworkType) -> None:
        logger.trace(f"send_peerlist called for {to_key}, network={network}")
        peers = self.peer_registry.get_peerlist_for_network(network)

        # Always send a response, even if empty - clients wait for PEERLIST response
        if not peers:
            peerlist_msg = ""
        else:
            entries = [create_peerlist_entry(nick, loc) for nick, loc in peers]
            peerlist_msg = ",".join(entries)

        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=peerlist_msg)

        try:
            await self.send_callback(to_key, envelope.to_bytes())
            logger.trace(f"Sent peerlist with {len(peers)} peers to {to_key}")
        except Exception as e:
            logger.warning(f"Failed to send peerlist to {to_key}: {e}")

    async def _send_peer_location(self, to_location: str, peer_info: PeerInfo) -> None:
        if peer_info.onion_address == "NOT-SERVING-ONION":
            return

        entry = create_peerlist_entry(peer_info.nick, peer_info.location_string)
        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=entry)

        try:
            await self.send_callback(to_location, envelope.to_bytes())
        except Exception as e:
            logger.trace(f"Failed to send peer location: {e}")

    async def broadcast_peer_disconnect(self, peer_location: str, network: NetworkType) -> None:
        peer = self.peer_registry.get_by_location(peer_location)
        if not peer or not peer.nick:
            return

        entry = create_peerlist_entry(peer.nick, peer.location_string, disconnected=True)
        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=entry)

        # Pre-serialize envelope once instead of per-peer
        envelope_bytes = envelope.to_bytes()

        # Use generator to avoid building full target list in memory
        def target_generator() -> Iterator[tuple[str, str | None]]:
            for p in self.peer_registry.iter_connected(network):
                if p.location_string == peer_location:
                    continue
                peer_key = p.nick if p.location_string == "NOT-SERVING-ONION" else p.location_string
                yield (peer_key, p.nick)

        # Execute sends in batches to limit memory usage
        sent_count = await self._batched_broadcast_iter(target_generator(), envelope_bytes)

        logger.info(f"Broadcasted disconnect for {peer.nick} to {sent_count} peers")
