"""
Main directory server implementation using asyncio.

Implements Open/Closed Principle: extensible without modification.
"""

import asyncio
import json

from jmcore.models import MessageEnvelope, NetworkType, PeerStatus
from jmcore.network import ConnectionPool, TCPConnection
from jmcore.protocol import MessageType
from loguru import logger

from directory_server.config import Settings
from directory_server.handshake_handler import HandshakeError, HandshakeHandler
from directory_server.message_router import MessageRouter
from directory_server.peer_registry import PeerRegistry


class DirectoryServer:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.network = NetworkType(settings.network)

        self.peer_registry = PeerRegistry(max_peers=settings.max_peers)
        self.connections = ConnectionPool(max_connections=settings.max_peers)
        self.peer_key_to_conn_id: dict[str, str] = {}
        self.message_router = MessageRouter(
            peer_registry=self.peer_registry, send_callback=self._send_to_peer
        )
        self.handshake_handler = HandshakeHandler(
            network=self.network, server_nick=f"directory-{settings.network}", motd=settings.motd
        )

        self.server: asyncio.Server | None = None
        self._shutdown = False

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client, self.settings.host, self.settings.port
        )

        addr = self.server.sockets[0].getsockname()
        logger.info(
            f"Directory server started on {addr[0]}:{addr[1]} (network: {self.network.value})"
        )

        async with self.server:
            await self.server.serve_forever()

    async def stop(self) -> None:
        logger.info("Shutting down directory server...")
        self._shutdown = True

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        await self.connections.close_all()
        logger.info("Directory server stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_addr = writer.get_extra_info("peername")
        conn_id = f"{peer_addr[0]}:{peer_addr[1]}"
        logger.debug(f"New connection from {conn_id}")

        transport = writer.transport
        transport.set_write_buffer_limits(high=0)
        sock = transport.get_extra_info("socket")
        if sock:
            import socket

            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        connection = TCPConnection(reader, writer, self.settings.max_message_size)
        peer_key: str | None = None

        try:
            self.connections.add(conn_id, connection)
            peer_key = await self._perform_handshake(connection, conn_id)
            if not peer_key:
                return

            await self._handle_peer_messages(connection, conn_id, peer_key)

        except Exception as e:
            logger.error(f"Error handling client {conn_id}: {e}")
        finally:
            await self._cleanup_peer(connection, conn_id, peer_key)

    async def _perform_handshake(self, connection: TCPConnection, conn_id: str) -> str | None:
        try:
            logger.debug(f"_perform_handshake: waiting for handshake from {conn_id}")
            data = await asyncio.wait_for(connection.receive(), timeout=30.0)
            logger.debug(f"_perform_handshake: received {len(data)} bytes from {conn_id}")
            envelope = MessageEnvelope.from_bytes(data)
            logger.debug(f"_perform_handshake: parsed envelope type={envelope.message_type}")

            if envelope.message_type != MessageType.HANDSHAKE:
                logger.warning(f"Expected handshake, got {envelope.message_type}")
                return None

            peer_info, response = self.handshake_handler.process_handshake(
                envelope.payload, conn_id
            )

            response_envelope = MessageEnvelope(
                message_type=MessageType.DN_HANDSHAKE, payload=json.dumps(response)
            )
            response_bytes = response_envelope.to_bytes()
            logger.debug(
                f"Sending handshake response: type={response_envelope.message_type}, "
                f"payload={response}, bytes_len={len(response_bytes)}, "
                f"actual_bytes={response_bytes.decode('utf-8')}"
            )
            try:
                await connection.send(response_bytes)
                logger.debug("Handshake response sent successfully, waiting a moment...")
                # Give the client time to receive and process the response
                await asyncio.sleep(0.1)
                logger.debug("Post-handshake delay completed")
            except Exception as e:
                logger.error(f"Failed to send handshake response: {e}")
                raise

            peer_location = peer_info.location_string()
            self.peer_registry.register(peer_info)

            peer_key = peer_info.nick if peer_location == "NOT-SERVING-ONION" else peer_location
            self.peer_registry.update_status(peer_key, PeerStatus.HANDSHAKED)
            self.peer_key_to_conn_id[peer_key] = conn_id

            logger.debug(
                f"Mapped peer_key={peer_key} (nick={peer_info.nick}, location={peer_location}) "
                f"to conn_id={conn_id}, connection exists: {self.connections.get(conn_id) is not None}"
            )

            # NOTE: Original JoinMarket directory does NOT send peerlist automatically after handshake
            # Peerlist is only sent when forwarding private messages or on disconnect events
            # logger.debug(f"_perform_handshake: sending peerlist to {peer_key}")
            # await self.message_router.send_peerlist(peer_key, peer_info.network)
            logger.debug(f"_perform_handshake: handshake complete for {peer_key}")

            return peer_key

        except HandshakeError as e:
            logger.warning(f"Handshake failed for {conn_id}: {e}")
            return None
        except TimeoutError:
            logger.warning(f"Handshake timeout for {conn_id}")
            return None
        except Exception as e:
            logger.error(f"Handshake error for {conn_id}: {e}")
            return None

    async def _handle_peer_messages(
        self, connection: TCPConnection, conn_id: str, peer_key: str
    ) -> None:
        peer_info = self.peer_registry.get_by_key(peer_key)
        if not peer_info:
            return

        logger.info(f"Peer {peer_info.nick} connected from {peer_info.location_string()}")

        while connection.is_connected() and not self._shutdown:
            try:
                data = await connection.receive()
                envelope = MessageEnvelope.from_bytes(data)

                await self.message_router.route_message(envelope, peer_key)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing message from {peer_info.nick}: {e}")
                break

    async def _cleanup_peer(
        self, connection: TCPConnection, conn_id: str, peer_key: str | None
    ) -> None:
        if peer_key:
            peer_info = self.peer_registry.get_by_key(peer_key)

            if peer_info:
                logger.info(f"Peer {peer_info.nick} disconnected")
                await self.message_router.broadcast_peer_disconnect(
                    peer_info.location_string(), peer_info.network
                )
                self.peer_registry.unregister(peer_key)

            if peer_key in self.peer_key_to_conn_id:
                del self.peer_key_to_conn_id[peer_key]

        self.connections.remove(conn_id)

        try:
            await connection.close()
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")

    async def _send_to_peer(self, peer_location: str, data: bytes) -> None:
        peer_key = peer_location

        conn_id = self.peer_key_to_conn_id.get(peer_key)
        logger.debug(
            f"_send_to_peer: peer_location={peer_location}, conn_id={conn_id}, "
            f"peer_key_to_conn_id keys: {list(self.peer_key_to_conn_id.keys())}, "
            f"connection pool keys: {list(self.connections.connections.keys())}"
        )
        if not conn_id:
            raise ValueError(f"No connection for peer: {peer_location}")

        connection = self.connections.get(conn_id)
        if not connection:
            raise ValueError(f"No connection for conn_id: {conn_id}")

        await connection.send(data)

    def get_stats(self) -> dict:
        return {
            "network": self.network.value,
            "connected_peers": self.peer_registry.count(),
            "max_peers": self.settings.max_peers,
            "active_connections": len(self.connections),
        }
