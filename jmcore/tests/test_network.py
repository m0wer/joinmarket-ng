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
