"""
Test parallel directory server connections for Taker.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from jmcore.crypto import NickIdentity
from jmcore.protocol import JM_VERSION
from taker.taker import MultiDirectoryClient


@pytest.mark.asyncio
async def test_connect_all_parallel():
    """Test that MultiDirectoryClient.connect_all() connects to all servers in parallel."""
    # Setup
    directory_servers = [
        "server1.onion:5222",
        "server2.onion:5222",
        "server3.onion:5222",
    ]
    nick_identity = NickIdentity(JM_VERSION)

    client = MultiDirectoryClient(
        directory_servers=directory_servers,
        network="regtest",
        nick_identity=nick_identity,
        neutrino_compat=False,
    )

    # Track connection order and timing
    connection_order = []
    connection_times = []

    async def mock_connect_side_effect(*args, **kwargs):
        """Simulate connection with delay."""
        server = args[0] if args else None
        start_time = asyncio.get_event_loop().time()
        connection_times.append(start_time)
        connection_order.append(server)
        # Simulate varying connection times
        await asyncio.sleep(0.1)  # Small delay to verify parallel execution
        return AsyncMock()

    # Patch DirectoryClient to track parallel execution
    with patch("taker.taker.DirectoryClient") as MockDirectoryClient:
        mock_instance = AsyncMock()
        mock_instance.connect = AsyncMock(side_effect=mock_connect_side_effect)
        MockDirectoryClient.return_value = mock_instance

        # Execute
        start = asyncio.get_event_loop().time()
        connected_count = await client.connect_all()
        end = asyncio.get_event_loop().time()

        # Verify parallel execution
        # If connections were sequential, total time would be >= 0.3 seconds (3 * 0.1)
        # If parallel, total time should be ~0.1 seconds
        total_time = end - start
        assert total_time < 0.25, f"Connections appear sequential (took {total_time:.2f}s)"
        assert connected_count == 3, f"Expected 3 connections, got {connected_count}"

        # Verify all servers were connected to
        assert len(client.clients) == 3
        assert "server1.onion:5222" in client.clients
        assert "server2.onion:5222" in client.clients
        assert "server3.onion:5222" in client.clients

        # Verify connections started nearly simultaneously (within 0.05s of each other)
        if len(connection_times) > 1:
            time_spread = max(connection_times) - min(connection_times)
            assert time_spread < 0.05, (
                f"Connection times too spread out ({time_spread:.3f}s), "
                "indicating sequential execution"
            )


@pytest.mark.asyncio
async def test_connect_all_handles_failures():
    """Test that MultiDirectoryClient.connect_all() handles partial failures gracefully."""
    directory_servers = [
        "working.onion:5222",
        "failing.onion:5222",
        "also-working.onion:5222",
    ]
    nick_identity = NickIdentity(JM_VERSION)

    client = MultiDirectoryClient(
        directory_servers=directory_servers,
        network="regtest",
        nick_identity=nick_identity,
        neutrino_compat=False,
    )

    # Mock DirectoryClient to fail on second server
    with patch("taker.taker.DirectoryClient") as MockDirectoryClient:

        def create_mock_client(host, port, *args, **kwargs):
            mock_instance = AsyncMock()
            if host == "failing.onion":
                # Simulate connection failure
                mock_instance.connect = AsyncMock(side_effect=Exception("Connection failed"))
            else:
                # Successful connection
                mock_instance.connect = AsyncMock()
            return mock_instance

        MockDirectoryClient.side_effect = create_mock_client

        # Execute
        connected_count = await client.connect_all()

        # Verify partial success
        assert connected_count == 2, f"Expected 2 successful connections, got {connected_count}"
        assert len(client.clients) == 2
        assert "working.onion:5222" in client.clients
        assert "also-working.onion:5222" in client.clients
        assert "failing.onion:5222" not in client.clients


@pytest.mark.asyncio
async def test_connect_all_with_exceptions():
    """Test that MultiDirectoryClient.connect_all() handles exceptions gracefully."""
    directory_servers = [
        "server1.onion:5222",
        "server2.onion:5222",
    ]
    nick_identity = NickIdentity(JM_VERSION)

    client = MultiDirectoryClient(
        directory_servers=directory_servers,
        network="regtest",
        nick_identity=nick_identity,
        neutrino_compat=False,
    )

    with patch("taker.taker.DirectoryClient") as MockDirectoryClient:

        def create_mock_client(host, port, *args, **kwargs):
            mock_instance = AsyncMock()
            if host == "server2.onion":
                # Simulate connection exception for second server
                mock_instance.connect = AsyncMock(side_effect=Exception("Network error"))
            else:
                # Successful connection for first server
                mock_instance.connect = AsyncMock()
            return mock_instance

        MockDirectoryClient.side_effect = create_mock_client

        # Execute - should not crash and should connect to at least one
        connected_count = await client.connect_all()

        # First server should succeed
        assert connected_count == 1
        assert "server1.onion:5222" in client.clients
        assert "server2.onion:5222" not in client.clients
