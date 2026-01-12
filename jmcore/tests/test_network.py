"""
Tests for jmcore.network
"""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from jmcore.network import (
    ConnectionError,
    ConnectionPool,
    OnionPeer,
    PeerStatus,
    TCPConnection,
)


@pytest.mark.asyncio
async def test_tcp_connection_send():
    reader = AsyncMock()
    writer = Mock()
    writer.drain = AsyncMock()

    conn = TCPConnection(reader, writer)
    await conn.send(b"hello")

    writer.write.assert_called_with(b"hello\r\n")
    writer.drain.assert_called()

    # Test message too large
    conn.max_message_size = 5
    with pytest.raises(ValueError):
        await conn.send(b"123456")


@pytest.mark.asyncio
async def test_tcp_connection_receive():
    reader = AsyncMock()
    reader.readuntil.return_value = b"response\r\n"
    writer = Mock()

    conn = TCPConnection(reader, writer)
    data = await conn.receive()

    assert data == b"response"

    # Test connection closed
    conn._connected = False
    with pytest.raises(ConnectionError):
        await conn.receive()


def test_connection_pool():
    pool = ConnectionPool(max_connections=2)
    c1 = Mock()
    c2 = Mock()
    c3 = Mock()

    pool.add("p1", c1)
    pool.add("p2", c2)

    assert pool.get("p1") == c1
    assert len(pool) == 2

    with pytest.raises(ConnectionError):
        pool.add("p3", c3)

    pool.remove("p1")
    assert len(pool) == 1
    pool.add("p3", c3)
    assert len(pool) == 2


@pytest.mark.asyncio
async def test_connection_pool_close_all():
    pool = ConnectionPool()
    c1 = Mock()
    c1.close = AsyncMock()
    pool.add("p1", c1)

    await pool.close_all()
    c1.close.assert_called()
    assert len(pool) == 0


@pytest.mark.asyncio
async def test_tcp_connection_concurrent_receive():
    """Test that concurrent receive calls are serialized by the receive lock.

    This test reproduces the bug:
    "readuntil() called while another coroutine is already waiting for incoming data"

    The issue occurs when:
    1. listen_continuously() is waiting on receive() in an infinite loop
    2. get_peerlist_with_features() tries to receive() concurrently

    Without the receive lock, asyncio.StreamReader.readuntil() raises RuntimeError
    when called by multiple coroutines simultaneously.
    """
    import asyncio

    # Create a real StreamReader/StreamWriter pair using pipes
    # This allows us to test actual concurrent read behavior
    reader = asyncio.StreamReader()
    writer = Mock()

    conn = TCPConnection(reader, writer)

    # Track the order of operations
    events: list[str] = []
    results: list[bytes] = []

    async def slow_reader(name: str) -> None:
        """Simulate a slow reader that waits for data."""
        events.append(f"{name}_start")
        try:
            data = await conn.receive()
            results.append(data)
            events.append(f"{name}_got_{data.decode()}")
        except Exception as e:
            events.append(f"{name}_error_{type(e).__name__}")

    async def feed_data_delayed() -> None:
        """Feed data to the reader after a short delay."""
        await asyncio.sleep(0.05)
        reader.feed_data(b"msg1\r\n")
        await asyncio.sleep(0.05)
        reader.feed_data(b"msg2\r\n")

    # Start two concurrent readers and the data feeder
    task1 = asyncio.create_task(slow_reader("reader1"))
    task2 = asyncio.create_task(slow_reader("reader2"))
    feeder = asyncio.create_task(feed_data_delayed())

    # Wait for all tasks
    await asyncio.gather(task1, task2, feeder, return_exceptions=True)

    # Both readers should complete successfully (serialized by lock)
    assert "reader1_start" in events
    assert "reader2_start" in events

    # Both messages should be received (one by each reader)
    assert len(results) == 2
    assert set(results) == {b"msg1", b"msg2"}

    # No RuntimeError should have occurred
    error_events = [e for e in events if "error" in e]
    assert not error_events, f"Unexpected errors: {error_events}"


# =============================================================================
# OnionPeer Tests
# =============================================================================


class TestOnionPeerBasic:
    """Basic OnionPeer tests without network calls."""

    def test_peer_initialization(self):
        """Test OnionPeer initialization with valid location."""
        peer = OnionPeer(
            nick="J5maker123",
            location="abc123def.onion:5222",
        )

        assert peer.nick == "J5maker123"
        assert peer.location == "abc123def.onion:5222"
        assert peer.hostname == "abc123def.onion"
        assert peer.port == 5222
        assert peer.status() == PeerStatus.UNCONNECTED
        assert not peer.is_connected()
        assert peer.can_connect()

    def test_peer_not_serving_onion(self):
        """Test OnionPeer with NOT-SERVING-ONION location."""
        peer = OnionPeer(
            nick="J5taker456",
            location="NOT-SERVING-ONION",
        )

        assert peer.nick == "J5taker456"
        assert peer.hostname is None
        assert peer.port is None
        assert not peer.can_connect()  # Cannot connect to non-serving peer

    def test_peer_invalid_location(self):
        """Test OnionPeer with invalid location format."""
        peer = OnionPeer(
            nick="J5bad",
            location="invalid-no-port",
        )

        assert peer.hostname is None
        assert peer.port is None
        assert not peer.can_connect()

    def test_peer_status_transitions(self):
        """Test that peer status is tracked correctly."""
        peer = OnionPeer(
            nick="J5test",
            location="test.onion:5222",
        )

        assert peer.status() == PeerStatus.UNCONNECTED
        assert peer.can_connect()
        assert not peer.is_connected()
        assert not peer.is_connecting()


class TestOnionPeerConnection:
    """OnionPeer connection tests with mocked network."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful peer connection and handshake."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        # Mock the connection
        mock_connection = AsyncMock()
        mock_connection.is_connected.return_value = True

        # Mock handshake response (peer-to-peer format)
        handshake_response = {
            "type": 793,  # HANDSHAKE
            "data": {
                "app-name": "joinmarket",
                "proto-ver": 5,
                "directory": False,
                "features": {},
                "location-string": "test.onion:5222",
                "nick": "J5maker",
                "network": "regtest",
            },
        }
        import json

        mock_connection.receive.return_value = json.dumps(handshake_response).encode()

        with patch("jmcore.network.connect_via_tor", return_value=mock_connection):
            success = await peer.connect(
                our_nick="J5taker",
                our_location="NOT-SERVING-ONION",
                network="regtest",
            )

            # Disconnect immediately to stop the receive loop task
            await peer.disconnect()

        assert success
        # Status will be DISCONNECTED after disconnect()
        # But success indicates the connect+handshake worked

    @pytest.mark.asyncio
    async def test_connect_handshake_rejected(self):
        """Test connection when handshake has wrong app name."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        mock_connection = AsyncMock()
        mock_connection.is_connected.return_value = True

        # Wrong app name
        handshake_response = {
            "type": 793,
            "data": {
                "app-name": "wrongapp",
                "proto-ver": 5,
                "directory": False,
                "features": {},
                "location-string": "test.onion:5222",
                "nick": "J5maker",
                "network": "regtest",
            },
        }
        import json

        mock_connection.receive.return_value = json.dumps(handshake_response).encode()

        with patch("jmcore.network.connect_via_tor", return_value=mock_connection):
            success = await peer.connect(
                our_nick="J5taker",
                our_location="NOT-SERVING-ONION",
                network="regtest",
            )

        assert not success
        assert peer.status() == PeerStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connect_network_mismatch(self):
        """Test connection when network doesn't match."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        mock_connection = AsyncMock()
        mock_connection.is_connected.return_value = True

        # Different network
        handshake_response = {
            "type": 793,
            "data": {
                "app-name": "joinmarket",
                "proto-ver": 5,
                "directory": False,
                "features": {},
                "location-string": "test.onion:5222",
                "nick": "J5maker",
                "network": "mainnet",  # We expect regtest
            },
        }
        import json

        mock_connection.receive.return_value = json.dumps(handshake_response).encode()

        with patch("jmcore.network.connect_via_tor", return_value=mock_connection):
            success = await peer.connect(
                our_nick="J5taker",
                our_location="NOT-SERVING-ONION",
                network="regtest",
            )

        assert not success
        assert peer.status() == PeerStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_connect_connection_failure(self):
        """Test connection when network connection fails."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        with patch(
            "jmcore.network.connect_via_tor", side_effect=ConnectionError("Connection refused")
        ):
            success = await peer.connect(
                our_nick="J5taker",
                our_location="NOT-SERVING-ONION",
                network="regtest",
            )

        assert not success
        assert peer.status() == PeerStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_send_privmsg(self):
        """Test sending a private message via direct connection."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        # Set up as connected (without starting receive loop)
        mock_connection = AsyncMock()
        mock_connection.is_connected.return_value = True
        peer._connection = mock_connection
        peer._status = PeerStatus.HANDSHAKED

        success = await peer.send_privmsg(
            our_nick="J5taker",
            command="fill",
            message="123 456 abc",
        )

        assert success
        mock_connection.send.assert_called_once()

        # Verify message format
        import json

        sent_data = mock_connection.send.call_args[0][0]
        msg = json.loads(sent_data.decode())
        assert msg["type"] == 685  # PRIVMSG
        assert "J5taker!J5maker!fill 123 456 abc" in msg["line"]

    @pytest.mark.asyncio
    async def test_send_when_not_connected(self):
        """Test that send fails when not connected."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        success = await peer.send(b"test message")
        assert not success

        success = await peer.send_privmsg(
            our_nick="J5taker",
            command="fill",
            message="test",
        )
        assert not success


class TestOnionPeerBackoff:
    """Test connection backoff and retry behavior."""

    @pytest.mark.asyncio
    async def test_try_to_connect_backoff(self):
        """Test that failed connections trigger backoff."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        # First attempt should be allowed
        assert peer.can_connect()

        # Simulate a failed connection attempt
        peer._connect_attempts = 1
        peer._last_connect_attempt = asyncio.get_event_loop().time()
        peer._status = PeerStatus.DISCONNECTED

        # Immediate retry should be blocked by backoff
        task = peer.try_to_connect(
            our_nick="J5taker",
            our_location="NOT-SERVING-ONION",
            network="regtest",
        )
        assert task is None  # Blocked by backoff

    @pytest.mark.asyncio
    async def test_max_attempts_exceeded(self):
        """Test that connection gives up after max attempts."""
        peer = OnionPeer(
            nick="J5maker",
            location="test.onion:5222",
        )

        peer._connect_attempts = 3  # Max default
        peer._status = PeerStatus.DISCONNECTED
        peer._last_connect_attempt = 0  # Long ago, no backoff

        task = peer.try_to_connect(
            our_nick="J5taker",
            our_location="NOT-SERVING-ONION",
            network="regtest",
        )
        assert task is None  # Gave up
