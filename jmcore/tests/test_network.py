"""
Tests for jmcore.network
"""

from unittest.mock import AsyncMock, Mock

import pytest

from jmcore.network import ConnectionError, ConnectionPool, TCPConnection


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
