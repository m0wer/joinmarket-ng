"""
Tests for server send failure cleanup to prevent zombie peers.

These tests verify that when sending to a peer fails, the peer is properly
cleaned up from both the connection mapping and the peer registry.
"""

import pytest
from jmcore.models import NetworkType, PeerInfo, PeerStatus
from jmcore.settings import DirectoryServerSettings

from directory_server.server import DirectoryServer


@pytest.fixture
def settings():
    return DirectoryServerSettings(
        host="127.0.0.1",
        port=0,  # Let OS assign port
        max_peers=100,
    )


@pytest.fixture
def server(settings):
    return DirectoryServer(settings, NetworkType.MAINNET)


@pytest.fixture
def sample_peer():
    """Create a sample peer with a valid onion address."""
    return PeerInfo(
        nick="test_peer",
        onion_address="a" * 56 + ".onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )


class TestHandleSendFailed:
    """Tests for _handle_send_failed cleanup behavior."""

    @pytest.mark.anyio
    async def test_handle_send_failed_removes_connection_mapping(self, server, sample_peer):
        """When send fails, the peer_key_to_conn_id mapping should be removed."""
        # Register the peer
        server.peer_registry.register(sample_peer)
        peer_key = sample_peer.location_string

        # Simulate connection mapping
        server.peer_key_to_conn_id[peer_key] = "conn_123"

        # Trigger send failure cleanup
        await server._handle_send_failed(peer_key)

        # Verify mapping is removed
        assert peer_key not in server.peer_key_to_conn_id

    @pytest.mark.anyio
    async def test_handle_send_failed_unregisters_peer_from_registry(self, server, sample_peer):
        """When send fails, the peer should be unregistered from the registry."""
        # Register the peer
        server.peer_registry.register(sample_peer)
        peer_key = sample_peer.location_string

        # Verify peer is registered
        assert server.peer_registry.get_by_key(peer_key) is not None
        assert server.peer_registry.get_by_nick(sample_peer.nick) is not None

        # Trigger send failure cleanup
        await server._handle_send_failed(peer_key)

        # Verify peer is unregistered
        assert server.peer_registry.get_by_key(peer_key) is None
        assert server.peer_registry.get_by_nick(sample_peer.nick) is None

    @pytest.mark.anyio
    async def test_handle_send_failed_handles_missing_peer(self, server):
        """_handle_send_failed should handle non-existent peer gracefully."""
        # Should not raise for non-existent peer
        await server._handle_send_failed("nonexistent_peer")

    @pytest.mark.anyio
    async def test_handle_send_failed_handles_missing_mapping(self, server, sample_peer):
        """_handle_send_failed should handle missing connection mapping gracefully."""
        # Register the peer but don't create a connection mapping
        server.peer_registry.register(sample_peer)
        peer_key = sample_peer.location_string

        # Should not raise despite missing mapping
        await server._handle_send_failed(peer_key)

        # Peer should still be unregistered
        assert server.peer_registry.get_by_key(peer_key) is None

    @pytest.mark.anyio
    async def test_handle_send_failed_removes_both_mapping_and_registry(self, server, sample_peer):
        """_handle_send_failed should clean up both mapping and registry."""
        # Register the peer
        server.peer_registry.register(sample_peer)
        peer_key = sample_peer.location_string

        # Create connection mapping
        server.peer_key_to_conn_id[peer_key] = "conn_456"

        # Trigger send failure cleanup
        await server._handle_send_failed(peer_key)

        # Verify complete cleanup
        assert peer_key not in server.peer_key_to_conn_id
        assert server.peer_registry.get_by_key(peer_key) is None
        assert server.peer_registry.get_by_nick(sample_peer.nick) is None

    @pytest.mark.anyio
    async def test_peer_not_in_iter_connected_after_send_failure(self, server, sample_peer):
        """After send failure, peer should not appear in iter_connected."""
        # Register the peer
        server.peer_registry.register(sample_peer)
        peer_key = sample_peer.location_string

        # Verify peer appears in connected list
        connected_before = list(server.peer_registry.iter_connected(NetworkType.MAINNET))
        assert any(p.nick == sample_peer.nick for p in connected_before)

        # Trigger send failure cleanup
        await server._handle_send_failed(peer_key)

        # Verify peer no longer appears in connected list
        connected_after = list(server.peer_registry.iter_connected(NetworkType.MAINNET))
        assert not any(p.nick == sample_peer.nick for p in connected_after)


class TestPassivePeerSendFailure:
    """Tests for send failure cleanup with passive peers (NOT-SERVING-ONION)."""

    @pytest.fixture
    def passive_peer(self):
        """Create a passive peer (taker/watcher)."""
        return PeerInfo(
            nick="passive_taker",
            onion_address="NOT-SERVING-ONION",
            port=5222,  # Port is validated even for passive peers
            network=NetworkType.MAINNET,
            status=PeerStatus.HANDSHAKED,
        )

    @pytest.mark.anyio
    async def test_handle_send_failed_for_passive_peer(self, server, passive_peer):
        """Passive peers (keyed by nick) should be cleaned up correctly."""
        # Register the peer
        server.peer_registry.register(passive_peer)
        # Passive peers use nick as key
        peer_key = passive_peer.nick

        # Create connection mapping
        server.peer_key_to_conn_id[peer_key] = "conn_789"

        # Verify peer is registered
        assert server.peer_registry.get_by_key(peer_key) is not None

        # Trigger send failure cleanup
        await server._handle_send_failed(peer_key)

        # Verify cleanup
        assert peer_key not in server.peer_key_to_conn_id
        assert server.peer_registry.get_by_key(peer_key) is None
        assert server.peer_registry.get_by_nick(passive_peer.nick) is None
