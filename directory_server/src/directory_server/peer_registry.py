"""
Peer registry for tracking active peers and their metadata.

Implements Single Responsibility Principle: only manages peer state.
"""

from datetime import datetime

from jmcore.models import NetworkType, PeerInfo, PeerStatus
from loguru import logger


class PeerNotFoundError(Exception):
    pass


class PeerRegistry:
    def __init__(self, max_peers: int = 1000):
        self.max_peers = max_peers
        self._peers: dict[str, PeerInfo] = {}
        self._nick_to_key: dict[str, str] = {}

    def register(self, peer: PeerInfo) -> None:
        if len(self._peers) >= self.max_peers:
            raise ValueError(f"Maximum peers reached: {self.max_peers}")

        location = peer.location_string()
        key = peer.nick if location == "NOT-SERVING-ONION" else location

        self._peers[key] = peer
        if peer.nick:
            self._nick_to_key[peer.nick] = key

        peer.last_seen = datetime.utcnow()
        logger.info(f"Registered peer: {peer.nick} at {location}")

    def unregister(self, key: str) -> None:
        if key not in self._peers:
            return

        peer = self._peers[key]
        if peer.nick in self._nick_to_key:
            del self._nick_to_key[peer.nick]

        del self._peers[key]
        logger.info(f"Unregistered peer: {peer.nick} at {peer.location_string()}")

    def get_by_key(self, key: str) -> PeerInfo | None:
        return self._peers.get(key)

    def get_by_location(self, location: str) -> PeerInfo | None:
        return self._peers.get(location)

    def get_by_nick(self, nick: str) -> PeerInfo | None:
        key = self._nick_to_key.get(nick)
        if key:
            return self._peers.get(key)
        return None

    def update_status(self, key: str, status: PeerStatus) -> None:
        peer = self.get_by_key(key)
        if peer:
            peer.status = status
            if status in (PeerStatus.CONNECTED, PeerStatus.HANDSHAKED):
                peer.last_seen = datetime.utcnow()

    def get_all_connected(self, network: NetworkType | None = None) -> list[PeerInfo]:
        peers = [
            p
            for p in self._peers.values()
            if p.status == PeerStatus.HANDSHAKED and not p.is_directory
        ]
        if network:
            peers = [p for p in peers if p.network == network]
        return peers

    def get_peerlist_for_network(self, network: NetworkType) -> list[tuple[str, str]]:
        peers = self.get_all_connected(network)
        result = []
        for peer in peers:
            if peer.onion_address != "NOT-SERVING-ONION":
                result.append((peer.nick, peer.location_string()))
        return result

    def count(self) -> int:
        return len(self._peers)

    def clear(self) -> None:
        self._peers.clear()
        self._nick_to_key.clear()
