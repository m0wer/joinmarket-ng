"""
Tests for peer registry.
"""

import pytest
from jmcore.models import NetworkType, PeerInfo, PeerStatus

from directory_server.peer_registry import PeerRegistry


@pytest.fixture
def registry():
    return PeerRegistry(max_peers=10)


@pytest.fixture
def sample_peer():
    return PeerInfo(
        nick="test_peer",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        port=5222,
        network=NetworkType.MAINNET,
    )


def test_register_peer(registry, sample_peer):
    registry.register(sample_peer)

    assert registry.count() == 1
    retrieved = registry.get_by_nick("test_peer")
    assert retrieved is not None
    assert retrieved.nick == "test_peer"


def test_register_duplicate_nick(registry, sample_peer):
    registry.register(sample_peer)

    peer2 = PeerInfo(
        nick="test_peer",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw2.onion",
        port=5222,
    )
    registry.register(peer2)

    assert registry.count() == 2


def test_max_peers_limit(registry):
    for i in range(10):
        peer = PeerInfo(nick=f"peer{i}", onion_address=f"{'a' * 56}.onion", port=5222 + i)
        registry.register(peer)

    assert registry.count() == 10

    with pytest.raises(ValueError, match="Maximum peers reached"):
        extra_peer = PeerInfo(nick="extra", onion_address=f"{'b' * 56}.onion", port=6000)
        registry.register(extra_peer)


def test_unregister_peer(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    registry.unregister(location)

    assert registry.count() == 0
    assert registry.get_by_nick("test_peer") is None


def test_get_by_location(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    retrieved = registry.get_by_location(location)
    assert retrieved is not None
    assert retrieved.nick == "test_peer"


def test_update_status(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    registry.update_status(location, PeerStatus.HANDSHAKED)

    peer = registry.get_by_location(location)
    assert peer.status == PeerStatus.HANDSHAKED


def test_get_all_connected(registry):
    for i in range(3):
        peer = PeerInfo(
            nick=f"peer{i}",
            onion_address=f"{'a' * 56}.onion",
            port=5220 + i,
            network=NetworkType.MAINNET,
        )
        registry.register(peer)
        registry.update_status(peer.location_string(), PeerStatus.HANDSHAKED)

    connected = registry.get_all_connected(NetworkType.MAINNET)
    assert len(connected) == 3


def test_get_all_connected_filters_network(registry):
    mainnet_peer = PeerInfo(
        nick="mainnet", onion_address=f"{'a' * 56}.onion", port=5222, network=NetworkType.MAINNET
    )
    testnet_peer = PeerInfo(
        nick="testnet", onion_address=f"{'b' * 56}.onion", port=5222, network=NetworkType.TESTNET
    )

    registry.register(mainnet_peer)
    registry.register(testnet_peer)
    registry.update_status(mainnet_peer.location_string(), PeerStatus.HANDSHAKED)
    registry.update_status(testnet_peer.location_string(), PeerStatus.HANDSHAKED)

    mainnet_peers = registry.get_all_connected(NetworkType.MAINNET)
    assert len(mainnet_peers) == 1
    assert mainnet_peers[0].nick == "mainnet"


def test_get_peerlist_for_network(registry):
    peer = PeerInfo(
        nick="peer1", onion_address=f"{'a' * 56}.onion", port=5222, network=NetworkType.MAINNET
    )
    registry.register(peer)
    registry.update_status(peer.location_string(), PeerStatus.HANDSHAKED)

    peerlist = registry.get_peerlist_for_network(NetworkType.MAINNET)
    assert len(peerlist) == 1
    assert peerlist[0] == ("peer1", peer.location_string())


def test_clear(registry, sample_peer):
    registry.register(sample_peer)
    registry.clear()

    assert registry.count() == 0
    assert registry.get_by_nick("test_peer") is None
