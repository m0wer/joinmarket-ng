"""
Direct connection handling for the maker bot.

Contains methods for handling incoming direct (onion) peer connections,
including message parsing, handshake handling, and connection lifecycle.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from jmcore.directory_client import DirectoryClient
from jmcore.models import Offer
from jmcore.network import TCPConnection
from jmcore.protocol import (
    COMMAND_PREFIX,
    FEATURE_NEUTRINO_COMPAT,
    FEATURE_PEERLIST_FEATURES,
    FeatureSet,
    MessageType,
    create_handshake_response,
)
from jmwallet.backends.base import BlockchainBackend
from loguru import logger

from maker.config import MakerConfig
from maker.rate_limiting import DirectConnectionRateLimiter


class DirectConnectionMixin:
    """Mixin class providing direct connection handling methods for MakerBot.

    These methods handle incoming connections from takers via the hidden service,
    including message parsing, handshake protocol, and message routing.
    """

    # -- Attributes provided by MakerBot --
    running: bool
    config: MakerConfig
    backend: BlockchainBackend
    nick: str
    current_offers: list[Offer]
    directory_clients: dict[str, DirectoryClient]
    direct_connections: dict[str, TCPConnection]
    _direct_connection_rate_limiter: DirectConnectionRateLimiter

    # -- Methods provided by MakerBot --
    def _log_rate_limited(self, key: str, message: str, interval_sec: float = 10.0) -> None: ...

    # -- Methods provided by ProtocolHandlersMixin --
    async def _handle_message(self, message: dict[str, Any], source: str = "unknown") -> None: ...
    async def _handle_fill(self, taker_nick: str, msg: str, source: str = "unknown") -> None: ...
    async def _handle_auth(self, taker_nick: str, msg: str, source: str = "unknown") -> None: ...
    async def _handle_tx(self, taker_nick: str, msg: str, source: str = "unknown") -> None: ...
    async def _handle_push(self, taker_nick: str, msg: str, source: str = "unknown") -> None: ...
    async def _send_offers_via_direct_connection(
        self, taker_nick: str, connection: TCPConnection
    ) -> None: ...

    def _parse_direct_message(self, data: bytes) -> tuple[str, str, str] | None:
        """Parse a direct connection message supporting both formats.

        The reference implementation uses OnionCustomMessage format:
            {"type": 685, "line": "from_nick!to_nick!command data"}
        Where type 685 = PRIVMSG, type 687 = PUBMSG.

        Our internal format (for future use):
            {"nick": "sender", "cmd": "command", "data": "..."}

        Returns:
            (sender_nick, command, message_data) tuple or None if parsing fails.
            For PUBMSG (orderbook), returns (sender_nick, "PUBLIC:orderbook", "").
        """
        try:
            message = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return None

        # Check for reference implementation format: {"type": int, "line": str}
        if "type" in message and "line" in message:
            msg_type = message.get("type")
            line = message.get("line", "")

            # Handle PUBMSG (687) - typically orderbook requests
            if msg_type == MessageType.PUBMSG.value:
                # Parse line format: from_nick!PUBLIC!command
                parts = line.split(COMMAND_PREFIX)
                if len(parts) < 3:
                    logger.debug(f"Invalid PUBMSG line format: {line[:50]}...")
                    return None

                sender_nick = parts[0]
                to_nick = parts[1]
                rest = COMMAND_PREFIX.join(parts[2:]).strip().lstrip("!")

                if to_nick == "PUBLIC":
                    # Return special marker for public messages
                    logger.trace(
                        f"Received PUBMSG from {sender_nick} via direct connection: {rest}"
                    )
                    return (sender_nick, f"PUBLIC:{rest}", "")
                else:
                    logger.debug(f"Ignoring PUBMSG with non-PUBLIC target: {to_nick}")
                    return None

            # Handle PRIVMSG (685) for CoinJoin protocol
            if msg_type != MessageType.PRIVMSG.value:
                logger.debug(f"Ignoring message type {msg_type} on direct connection")
                return None

            # Parse line format: from_nick!to_nick!command data
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                logger.warning(f"Invalid line format: {line[:50]}...")
                return None

            sender_nick = parts[0]
            to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            # Check if message is for us
            if to_nick != self.nick:
                logger.debug(f"Ignoring message not for us: to={to_nick}, us={self.nick}")
                return None

            # Strip leading "!" and parse command
            rest = rest.strip().lstrip("!")

            # Extract command and data
            cmd_parts = rest.split(" ", 1)
            cmd = cmd_parts[0]
            msg_data = cmd_parts[1] if len(cmd_parts) > 1 else ""

            return (sender_nick, cmd, msg_data)

        # Check for our internal format: {"nick": str, "cmd": str, "data": str}
        elif "nick" in message or "cmd" in message:
            sender_nick = message.get("nick", "unknown")
            cmd = message.get("cmd", "")
            msg_data = message.get("data", "")
            return (sender_nick, cmd, msg_data)

        return None

    async def _try_handle_handshake(
        self, connection: TCPConnection, data: bytes, peer_str: str
    ) -> bool:
        """Try to handle a handshake request on a direct connection.

        Health checkers and feature discovery tools connect directly to makers
        and send a handshake request to discover features like neutrino_compat.

        The protocol mirrors the reference implementation:
        - Client sends HANDSHAKE (793) with client_handshake_json format
        - Server responds with DN_HANDSHAKE (795) with server_handshake_json format

        Args:
            connection: The TCP connection
            data: Raw message data
            peer_str: Peer identifier string for logging

        Returns:
            True if this was a handshake message (handled), False otherwise.
        """
        try:
            message = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

        # Check for handshake message type (793 = HANDSHAKE)
        if message.get("type") != MessageType.HANDSHAKE.value:
            return False

        # Parse the handshake request
        try:
            line = message.get("line", "")
            handshake_data = json.loads(line) if isinstance(line, str) else line
        except json.JSONDecodeError:
            logger.warning(f"Invalid handshake JSON from {peer_str}")
            return True  # Was a handshake message, just malformed

        peer_nick = handshake_data.get("nick", "unknown")
        peer_network = handshake_data.get("network", "")

        # Parse peer's advertised features (supports both dict and comma-string formats)
        peer_features_raw = handshake_data.get("features", "")
        peer_features = FeatureSet()
        if isinstance(peer_features_raw, dict):
            # Reference implementation format: {"peerlist_features": True, ...}
            for feature_name, enabled in peer_features_raw.items():
                if enabled:
                    peer_features.features.add(feature_name)
        elif isinstance(peer_features_raw, str) and peer_features_raw:
            # Comma-separated string format: "neutrino_compat,peerlist_features"
            peer_features = FeatureSet.from_comma_string(peer_features_raw)
        peer_version = handshake_data.get("version", handshake_data.get("proto-ver", "unknown"))

        logger.info(f"Received handshake from {peer_nick} at {peer_str}")
        logger.debug(
            f"Peer {peer_nick} handshake details: version={peer_version}, "
            f"network={peer_network or 'unspecified'}, "
            f"features={peer_features.to_comma_string() or 'none'}"
        )

        # Build our feature set
        features = FeatureSet()
        if self.backend.can_provide_neutrino_metadata():
            features.features.add(FEATURE_NEUTRINO_COMPAT)
        # We support peerlist_features protocol
        features.features.add(FEATURE_PEERLIST_FEATURES)

        # Validate network
        if peer_network and peer_network != self.config.network.value:
            logger.warning(
                f"Network mismatch from {peer_nick}: {peer_network} != {self.config.network.value}"
            )
            # Still respond but mark as rejected
            response_data = create_handshake_response(
                nick=self.nick,
                network=self.config.network.value,
                accepted=False,
                motd="Network mismatch",
                features=features,
            )
        else:
            response_data = create_handshake_response(
                nick=self.nick,
                network=self.config.network.value,
                accepted=True,
                motd="JoinMarket NG Maker",
                features=features,
            )

        # Send handshake response using DN_HANDSHAKE (795) type
        # This matches the reference implementation protocol where the server
        # (directory or maker accepting connections) responds with dn-handshake
        response_msg = {
            "type": MessageType.DN_HANDSHAKE.value,
            "line": json.dumps(response_data),
        }
        try:
            await connection.send(json.dumps(response_msg).encode("utf-8"))
            logger.info(
                f"Sent handshake response to {peer_nick} "
                f"(features: {features.to_comma_string() or 'none'})"
            )
        except Exception as e:
            logger.warning(f"Failed to send handshake response to {peer_str}: {e}")

        return True

    async def _on_direct_connection(self, connection: TCPConnection, peer_str: str) -> None:
        """Handle incoming direct connection from a taker via hidden service.

        Direct connections support three message formats:

        1. Handshake request (health check / feature discovery):
           {"type": 793, "line": "<json handshake data>"}
           Maker responds with handshake response including features.

        2. Reference implementation format (OnionCustomMessage):
           {"type": 685, "line": "from_nick!to_nick!command data"}
           Where type 685 = PRIVMSG.

        3. Our simplified format:
           {"nick": "sender", "cmd": "command", "data": "..."}

        This bypasses the directory server for lower latency once the taker
        knows the maker's onion address (from the peerlist).

        Rate Limiting Strategy:
        - Direct connections are rate limited by connection address (peer_str), not by nick
        - This prevents nick rotation attacks where attackers use different nicks per request
        - Attackers connecting directly to the onion bypass directory-level protections
        - Connection-based limiting is stricter: faster bans, longer intervals
        """
        logger.info(f"Handling direct connection from {peer_str}")

        # Check if this connection is already banned
        if self._direct_connection_rate_limiter.is_banned(peer_str):
            logger.debug(f"Rejecting direct connection from banned address {peer_str}")
            await connection.close()
            return

        try:
            # Keep connection open and process messages
            while self.running and connection.is_connected():
                try:
                    # Receive message with timeout
                    data = await asyncio.wait_for(connection.receive(), timeout=60.0)
                    if not data:
                        logger.info(f"Direct connection from {peer_str} closed")
                        break

                    # Apply connection-based message rate limiting FIRST
                    # This catches general floods before any processing
                    if not self._direct_connection_rate_limiter.check_message(peer_str):
                        logger.debug(f"Rate limiting message from {peer_str} (message flood)")
                        continue

                    # Check for handshake request first (health check / feature discovery)
                    handshake_handled = await self._try_handle_handshake(connection, data, peer_str)
                    if handshake_handled:
                        # Handshake was handled, connection may close after response
                        # Continue to allow follow-up messages or clean disconnect
                        continue

                    # Parse the message (supports both formats)
                    parsed = self._parse_direct_message(data)
                    if parsed is None:
                        # Log message content for debugging
                        # data is bytes, decode for display (replace errors to handle binary)
                        data_str = (
                            data.decode("utf-8", errors="replace")
                            if isinstance(data, bytes)
                            else str(data)
                        )
                        # Full message at DEBUG level for troubleshooting
                        logger.debug(f"Unparseable direct message from {peer_str}: {data_str!r}")
                        # Rate-limited WARNING with truncated preview
                        msg_preview = data_str[:100] + "..." if len(data_str) > 100 else data_str
                        self._log_rate_limited(
                            f"direct_parse_fail:{peer_str}",
                            f"Failed to parse direct message from {peer_str}: {msg_preview!r}",
                            interval_sec=10,
                        )
                        continue

                    sender_nick, cmd, msg_data = parsed

                    logger.debug(f"Direct message from {sender_nick}: cmd={cmd}")

                    # Track this connection by nick for sending responses
                    if sender_nick and sender_nick != "unknown":
                        self.direct_connections[sender_nick] = connection

                    # Handle PUBLIC messages (orderbook requests via direct connection)
                    if cmd.startswith("PUBLIC:"):
                        public_cmd = cmd[7:]  # Strip "PUBLIC:" prefix
                        if public_cmd == "orderbook":
                            # Apply CONNECTION-BASED rate limiting (not nick-based!)
                            # This prevents nick rotation attacks
                            if not self._direct_connection_rate_limiter.check_orderbook(peer_str):
                                violations = (
                                    self._direct_connection_rate_limiter.get_violation_count(
                                        peer_str
                                    )
                                )
                                is_banned = self._direct_connection_rate_limiter.is_banned(peer_str)
                                if is_banned:
                                    logger.debug(
                                        f"Ignoring orderbook request from banned connection "
                                        f"{peer_str} (nick: {sender_nick})"
                                    )
                                    # Close connection to banned peer
                                    await connection.close()
                                    return
                                else:
                                    logger.debug(
                                        f"Rate limiting orderbook request from {peer_str} "
                                        f"(nick: {sender_nick}, violations: {violations})"
                                    )
                                continue

                            logger.info(
                                f"Received !orderbook request from {sender_nick} via direct "
                                f"connection, sending offers"
                            )
                            await self._send_offers_via_direct_connection(sender_nick, connection)
                        else:
                            logger.debug(
                                f"Unknown PUBLIC command from {sender_nick} via direct: "
                                f"{public_cmd}"
                            )
                        continue

                    # Process the command - reuse existing handlers
                    # Commands: fill, auth, tx (same as via directory)
                    full_msg = f"{cmd} {msg_data}" if msg_data else cmd

                    if cmd == "fill":
                        await self._handle_fill(sender_nick, full_msg, source="direct")
                    elif cmd == "auth":
                        await self._handle_auth(sender_nick, full_msg, source="direct")
                    elif cmd == "tx":
                        await self._handle_tx(sender_nick, full_msg, source="direct")
                    elif cmd == "push":
                        await self._handle_push(sender_nick, full_msg, source="direct")
                    else:
                        logger.debug(f"Unknown direct command from {sender_nick}: {cmd}")

                except TimeoutError:
                    # No message received, continue waiting
                    continue
                except Exception as e:
                    logger.error(f"Error processing direct message from {peer_str}: {e}")
                    break

        except Exception as e:
            logger.error(f"Error in direct connection handler for {peer_str}: {e}")
        finally:
            await connection.close()
            # Clean up nick -> connection mapping
            for nick, conn in list(self.direct_connections.items()):
                if conn == connection:
                    del self.direct_connections[nick]
            logger.info(f"Direct connection from {peer_str} closed")
