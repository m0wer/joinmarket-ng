"""
Network primitives and connection management.
"""

import asyncio
from abc import ABC, abstractmethod

from loguru import logger


class ConnectionError(Exception):
    pass


class Connection(ABC):
    @abstractmethod
    async def send(self, data: bytes) -> None:
        pass

    @abstractmethod
    async def receive(self) -> bytes:
        pass

    @abstractmethod
    async def close(self) -> None:
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        pass


class TCPConnection(Connection):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        max_message_size: int = 40000,
    ):
        self.reader = reader
        self.writer = writer
        self.max_message_size = max_message_size
        self._connected = True

    async def send(self, data: bytes) -> None:
        if not self._connected:
            raise ConnectionError("Connection closed")
        if len(data) > self.max_message_size:
            raise ValueError(f"Message too large: {len(data)} > {self.max_message_size}")

        message_to_send = data + b"\r\n"
        logger.debug(
            f"TCPConnection.send: sending {len(message_to_send)} bytes (with \\r\\n): {message_to_send[:200]!r}"
        )
        logger.debug(f"TCPConnection.send: full message: {message_to_send!r}")
        self.writer.write(message_to_send)
        logger.debug("TCPConnection.send: write() completed, calling drain()")
        await self.writer.drain()
        logger.debug(
            f"TCPConnection.send: drain completed, checking if writer is closing: {self.writer.is_closing()}"
        )

        # Force a small delay to ensure data is flushed
        try:
            await asyncio.sleep(0.01)
            logger.debug("TCPConnection.send: post-drain sleep completed")
        except Exception as e:
            logger.error(f"TCPConnection.send: error during sleep: {e}")

    async def receive(self) -> bytes:
        if not self._connected:
            raise ConnectionError("Connection closed")

        try:
            logger.debug("TCPConnection.receive: waiting for message...")
            data = await self.reader.readuntil(b"\n")
            stripped = data.rstrip(b"\r\n")
            logger.debug(
                f"TCPConnection.receive: received {len(data)} bytes, stripped to {len(stripped)}"
            )
            logger.debug(f"TCPConnection.receive: full message: {stripped!r}")
            return stripped
        except asyncio.LimitOverrunError as e:
            logger.error(f"Message too large (>{self.max_message_size} bytes)")
            raise ConnectionError("Message too large") from e
        except asyncio.IncompleteReadError as e:
            self._connected = False
            logger.debug("TCPConnection.receive: connection closed by peer")
            raise ConnectionError("Connection closed by peer") from e

    async def close(self) -> None:
        if not self._connected:
            return
        self._connected = False
        self.writer.close()
        await self.writer.wait_closed()

    def is_connected(self) -> bool:
        return self._connected


class ConnectionPool:
    def __init__(self, max_connections: int = 1000):
        self.max_connections = max_connections
        self.connections: dict[str, Connection] = {}

    def add(self, peer_id: str, connection: Connection) -> None:
        if len(self.connections) >= self.max_connections:
            raise ConnectionError(f"Connection pool full ({self.max_connections})")
        self.connections[peer_id] = connection

    def get(self, peer_id: str) -> Connection | None:
        return self.connections.get(peer_id)

    def remove(self, peer_id: str) -> None:
        if peer_id in self.connections:
            del self.connections[peer_id]

    async def close_all(self) -> None:
        for conn in self.connections.values():
            await conn.close()
        self.connections.clear()

    def __len__(self) -> int:
        return len(self.connections)
