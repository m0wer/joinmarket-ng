"""
Network primitives and connection management.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from typing import Any

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
        max_message_size: int = 2097152,  # 2MB
    ):
        self.reader = reader
        self.writer = writer
        self.max_message_size = max_message_size
        self._connected = True
        self._send_lock = asyncio.Lock()
        self._receive_lock = asyncio.Lock()

    async def send(self, data: bytes) -> None:
        if not self._connected:
            raise ConnectionError("Connection closed")
        if len(data) > self.max_message_size:
            raise ValueError(f"Message too large: {len(data)} > {self.max_message_size}")

        async with self._send_lock:
            if not self._connected:
                raise ConnectionError("Connection closed")

            message_to_send = data + b"\r\n"
            logger.trace(f"TCPConnection.send: sending {len(message_to_send)} bytes")
            try:
                self.writer.write(message_to_send)
                await self.writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self._connected = False
                raise ConnectionError(f"Send failed: {e}") from e

    async def receive(self) -> bytes:
        if not self._connected:
            raise ConnectionError("Connection closed")

        async with self._receive_lock:
            if not self._connected:
                raise ConnectionError("Connection closed")

            try:
                data = await self.reader.readuntil(b"\n")
                stripped = data.rstrip(b"\r\n")
                logger.trace(f"TCPConnection.receive: received {len(stripped)} bytes")
                return stripped
            except asyncio.LimitOverrunError as e:
                logger.error(f"Message too large (>{self.max_message_size} bytes)")
                raise ConnectionError("Message too large") from e
            except asyncio.IncompleteReadError as e:
                self._connected = False
                logger.trace("TCPConnection.receive: connection closed by peer")
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
        connections_snapshot = list(self.connections.values())
        for conn in connections_snapshot:
            await conn.close()
        self.connections.clear()

    def __len__(self) -> int:
        return len(self.connections)


async def connect_direct(
    host: str,
    port: int,
    max_message_size: int = 2097152,  # 2MB
    timeout: float = 30.0,
) -> TCPConnection:
    """Connect directly via TCP without Tor (for local development/testing)."""
    try:
        logger.info(f"Connecting directly to {host}:{port}")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, limit=max_message_size),
            timeout=timeout,
        )
        logger.info(f"Connected to {host}:{port}")
        return TCPConnection(reader, writer, max_message_size)
    except Exception as e:
        logger.error(f"Failed to connect to {host}:{port}: {e}")
        raise ConnectionError(f"Direct connection failed: {e}") from e


async def connect_via_tor(
    onion_address: str,
    port: int,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
    max_message_size: int = 2097152,  # 2MB
    timeout: float = 30.0,
) -> TCPConnection:
    try:
        import socket

        import socks

        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(socks.SOCKS5, socks_host, socks_port)
        sock.settimeout(timeout)

        logger.info(f"Connecting to {onion_address}:{port} via Tor ({socks_host}:{socks_port})")
        await asyncio.get_event_loop().run_in_executor(None, sock.connect, (onion_address, port))

        sock.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=sock, limit=max_message_size)

        logger.info(f"Connected to {onion_address}:{port}")
        return TCPConnection(reader, writer, max_message_size)

    except Exception as e:
        logger.error(f"Failed to connect to {onion_address}:{port} via Tor: {e}")
        raise ConnectionError(f"Tor connection failed: {e}") from e


class HiddenServiceListener:
    """
    TCP listener for accepting direct peer connections via Tor hidden service.

    This is used by makers to accept direct connections from takers,
    bypassing the directory server for lower latency.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        max_message_size: int = 2097152,
        on_connection: Callable[[TCPConnection, str], Coroutine[Any, Any, None]] | None = None,
    ):
        """
        Initialize hidden service listener.

        Args:
            host: Local address to bind to (typically 127.0.0.1 for Tor)
            port: Local port to bind to (0 for auto-assign)
            max_message_size: Maximum message size in bytes
            on_connection: Callback when new connection is accepted
        """
        self.host = host
        self.port = port
        self.max_message_size = max_message_size
        self.on_connection = on_connection
        self.server: asyncio.Server | None = None  # type: ignore[no-any-unimported]
        self.running = False
        self._bound_port: int = 0

    @property
    def bound_port(self) -> int:
        """Get the actual port the server is bound to."""
        return self._bound_port

    async def start(self) -> int:
        """
        Start listening for connections.

        Returns:
            The port number the server is bound to
        """
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
            limit=self.max_message_size,
        )
        self.running = True

        # Get the actual bound port
        addrs = self.server.sockets[0].getsockname() if self.server.sockets else None
        if addrs:
            self._bound_port = addrs[1]
        else:
            self._bound_port = self.port

        logger.info(f"Hidden service listener started on {self.host}:{self._bound_port}")
        return self._bound_port

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection."""
        peer_addr = writer.get_extra_info("peername")
        peer_str = f"{peer_addr[0]}:{peer_addr[1]}" if peer_addr else "unknown"
        logger.info(f"Accepted connection from {peer_str}")

        connection = TCPConnection(reader, writer, self.max_message_size)

        if self.on_connection:
            try:
                await self.on_connection(connection, peer_str)
            except Exception as e:
                logger.error(f"Error handling connection from {peer_str}: {e}")
                await connection.close()

    async def stop(self) -> None:
        """Stop the listener."""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        logger.info("Hidden service listener stopped")

    async def serve_forever(self) -> None:
        """Run the server until stopped."""
        if self.server:
            await self.server.serve_forever()
