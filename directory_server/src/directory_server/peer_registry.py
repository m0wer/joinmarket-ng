"""
Peer registry for tracking active peers and their metadata.

Implements Single Responsibility Principle: only manages peer state.
"""

from collections.abc import Iterator
from datetime import UTC, datetime

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

        location = peer.location_string
        key = peer.nick if location == "NOT-SERVING-ONION" else location

        self._peers[key] = peer
        if peer.nick:
            self._nick_to_key[peer.nick] = key

        peer.last_seen = datetime.now(UTC)
        logger.info(f"Registered peer: {peer.nick} at {location}")

    def unregister(self, key: str) -> None:
        if key not in self._peers:
            return

        peer = self._peers[key]
        if peer.nick in self._nick_to_key:
            del self._nick_to_key[peer.nick]

        del self._peers[key]
        logger.info(f"Unregistered peer: {peer.nick} at {peer.location_string}")

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
                peer.last_seen = datetime.now(UTC)

    def _iter_connected(self, network: NetworkType | None = None) -> Iterator[PeerInfo]:
        """Iterator over connected peers.

        Creates a snapshot of peers to avoid RuntimeError if dict is modified during iteration.
        """
        for p in list(self._peers.values()):
            if (
                p.status == PeerStatus.HANDSHAKED
                and not p.is_directory
                and (network is None or p.network == network)
            ):
                yield p

    def iter_connected(self, network: NetworkType | None = None) -> Iterator[PeerInfo]:
        """Public memory-efficient iterator over connected peers."""
        return self._iter_connected(network)

    def get_all_connected(self, network: NetworkType | None = None) -> list[PeerInfo]:
        return list(self._iter_connected(network))

    def get_peerlist_for_network(self, network: NetworkType) -> list[tuple[str, str]]:
        # Use generator to avoid intermediate list
        return [
            (peer.nick, peer.location_string)
            for peer in self._iter_connected(network)
            if peer.onion_address != "NOT-SERVING-ONION"
        ]

    def count(self) -> int:
        return len(self._peers)

    def clear(self) -> None:
        self._peers.clear()
        self._nick_to_key.clear()

    def get_passive_peers(self, network: NetworkType | None = None) -> list[PeerInfo]:
        """
        Get passive peers (NOT-SERVING-ONION).

        These are typically orderbook watchers/takers that don't host their own
        onion service but connect to the directory to watch offers.
        """
        return [p for p in self._iter_connected(network) if p.onion_address == "NOT-SERVING-ONION"]

    def get_active_peers(self, network: NetworkType | None = None) -> list[PeerInfo]:
        """
        Get active peers (serving onion address).

        These are typically makers that host their own onion service and
        publish offers to the orderbook.
        """
        return [p for p in self._iter_connected(network) if p.onion_address != "NOT-SERVING-ONION"]

    def get_stats(self) -> dict[str, int]:
        connected = 0
        passive = 0
        active = 0
        neutrino_compat = 0

        for p in list(self._peers.values()):
            if p.status == PeerStatus.HANDSHAKED and not p.is_directory:
                connected += 1
                if p.onion_address == "NOT-SERVING-ONION":
                    passive += 1
                else:
                    active += 1
                if p.neutrino_compat:
                    neutrino_compat += 1

        return {
            "total_peers": len(self._peers),
            "connected_peers": connected,
            "passive_peers": passive,
            "active_peers": active,
            "neutrino_compat_peers": neutrino_compat,
        }

    def get_neutrino_compat_peers(self, network: NetworkType | None = None) -> list[PeerInfo]:
        """
        Get peers that support neutrino_compat feature.

        These peers advertise extended UTXO metadata (scriptpubkey, blockheight)
        which is required for Neutrino backend verification.
        """
        return [p for p in self._iter_connected(network) if p.neutrino_compat]
