"""
Message routing logic for forwarding messages between peers.

Implements Single Responsibility Principle: only handles message routing.
"""

from collections.abc import Awaitable, Callable

from jmcore.models import MessageEnvelope, NetworkType, PeerInfo
from jmcore.protocol import MessageType, create_peerlist_entry, parse_jm_message
from loguru import logger

from directory_server.peer_registry import PeerRegistry

SendCallback = Callable[[str, bytes], Awaitable[None]]


class MessageRouter:
    def __init__(self, peer_registry: PeerRegistry, send_callback: SendCallback):
        self.peer_registry = peer_registry
        self.send_callback = send_callback

    async def route_message(self, envelope: MessageEnvelope, from_key: str) -> None:
        if envelope.message_type == MessageType.PUBMSG:
            await self._handle_public_message(envelope, from_key)
        elif envelope.message_type == MessageType.PRIVMSG:
            await self._handle_private_message(envelope, from_key)
        elif envelope.message_type == MessageType.GETPEERLIST:
            await self._handle_peerlist_request(from_key)
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

        connected_peers = self.peer_registry.get_all_connected(from_peer.network)

        for peer in connected_peers:
            peer_key = (
                peer.nick
                if peer.location_string() == "NOT-SERVING-ONION"
                else peer.location_string()
            )
            if peer_key == from_key:
                continue

            try:
                await self.send_callback(peer_key, envelope.to_bytes())
            except Exception as e:
                logger.error(f"Failed to forward public message to {peer.nick}: {e}")

        logger.debug(f"Broadcasted public message from {from_nick} to {len(connected_peers)} peers")

    async def _handle_private_message(self, envelope: MessageEnvelope, from_key: str) -> None:
        parsed = parse_jm_message(envelope.payload)
        if not parsed:
            logger.warning("Invalid private message format")
            return

        from_nick, to_nick, rest = parsed

        to_peer = self.peer_registry.get_by_nick(to_nick)
        if not to_peer:
            logger.debug(f"Target peer not found: {to_nick}")
            return

        from_peer = self.peer_registry.get_by_key(from_key)
        if not from_peer or from_peer.network != to_peer.network:
            logger.warning("Network mismatch or unknown sender")
            return

        try:
            to_peer_key = (
                to_peer.nick
                if to_peer.location_string() == "NOT-SERVING-ONION"
                else to_peer.location_string()
            )
            await self.send_callback(to_peer_key, envelope.to_bytes())
            logger.debug(f"Routed private message: {from_nick} -> {to_nick}")

            await self._send_peer_location(to_peer_key, from_peer)
        except Exception as e:
            logger.error(f"Failed to route private message: {e}")

    async def _handle_peerlist_request(self, from_key: str) -> None:
        peer = self.peer_registry.get_by_key(from_key)
        if not peer:
            return

        await self.send_peerlist(from_key, peer.network)

    async def send_peerlist(self, to_key: str, network: NetworkType) -> None:
        logger.debug(f"send_peerlist called for {to_key}, network={network}")
        peers = self.peer_registry.get_peerlist_for_network(network)
        logger.debug(f"send_peerlist: got {len(peers) if peers else 0} peers")
        if not peers:
            logger.debug("send_peerlist: no peers to send, returning")
            return

        entries = [create_peerlist_entry(nick, loc) for nick, loc in peers]
        peerlist_msg = ",".join(entries)
        logger.debug(f"send_peerlist: peerlist message: {peerlist_msg}")

        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=peerlist_msg)

        try:
            logger.debug(f"send_peerlist: calling send_callback for {to_key}")
            await self.send_callback(to_key, envelope.to_bytes())
            logger.debug(f"Sent peerlist with {len(peers)} peers to {to_key}")
        except Exception as e:
            logger.error(f"Failed to send peerlist: {e}", exc_info=True)

    async def _send_peer_location(self, to_location: str, peer_info: PeerInfo) -> None:
        if peer_info.onion_address == "NOT-SERVING-ONION":
            return

        entry = create_peerlist_entry(peer_info.nick, peer_info.location_string())
        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=entry)

        try:
            await self.send_callback(to_location, envelope.to_bytes())
        except Exception as e:
            logger.debug(f"Failed to send peer location: {e}")

    async def broadcast_peer_disconnect(self, peer_location: str, network: NetworkType) -> None:
        peer = self.peer_registry.get_by_location(peer_location)
        if not peer or not peer.nick:
            return

        entry = create_peerlist_entry(peer.nick, peer.location_string(), disconnected=True)
        envelope = MessageEnvelope(message_type=MessageType.PEERLIST, payload=entry)

        connected_peers = self.peer_registry.get_all_connected(network)
        for p in connected_peers:
            if p.location_string() == peer_location:
                continue

            try:
                peer_key = (
                    p.nick if p.location_string() == "NOT-SERVING-ONION" else p.location_string()
                )
                await self.send_callback(peer_key, envelope.to_bytes())
            except Exception as e:
                logger.error(f"Failed to broadcast disconnect: {e}")

        logger.info(f"Broadcasted disconnect for {peer.nick}")
