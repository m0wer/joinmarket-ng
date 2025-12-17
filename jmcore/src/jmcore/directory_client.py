"""
Shared DirectoryClient for connecting to JoinMarket directory nodes.

This module provides a unified client for:
- Orderbook watcher (passive monitoring)
- Maker (announcing offers)
- Taker (fetching orderbooks and coordinating CoinJoins)
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import struct
from collections.abc import Callable
from decimal import Decimal
from typing import Any

from loguru import logger

from jmcore.btc_script import mk_freeze_script, redeem_script_to_p2wsh_script
from jmcore.crypto import generate_jm_nick
from jmcore.models import FidelityBond, Offer, OfferType
from jmcore.network import TCPConnection, connect_direct, connect_via_tor
from jmcore.protocol import (
    COMMAND_PREFIX,
    JM_VERSION,
    MessageType,
    create_handshake_request,
    parse_peerlist_entry,
)


class DirectoryClientError(Exception):
    """Error raised by DirectoryClient operations."""


def parse_fidelity_bond_proof(
    proof_base64: str, maker_nick: str, taker_nick: str
) -> dict[str, Any] | None:
    """
    Parse a fidelity bond proof from base64-encoded binary data.

    Args:
        proof_base64: Base64-encoded bond proof
        maker_nick: Maker's nick
        taker_nick: Taker's nick (requesting party)

    Returns:
        Dict with bond details or None if parsing fails
    """
    try:
        decoded_data = base64.b64decode(proof_base64)
    except (binascii.Error, ValueError) as e:
        logger.warning(f"Failed to decode bond proof: {e}")
        return None

    if len(decoded_data) != 252:
        logger.warning(f"Invalid bond proof length: {len(decoded_data)}, expected 252")
        return None

    try:
        unpacked_data = struct.unpack("<72s72s33sH33s32sII", decoded_data)

        txid = unpacked_data[5]
        vout = unpacked_data[6]
        locktime = unpacked_data[7]
        utxo_pub = unpacked_data[4]
        cert_pub = unpacked_data[2]
        cert_expiry_raw = unpacked_data[3]
        cert_expiry = cert_expiry_raw * 2016

        utxo_pub_hex = binascii.hexlify(utxo_pub).decode("ascii")
        redeem_script = mk_freeze_script(utxo_pub_hex, locktime)
        redeem_script_hex = binascii.hexlify(redeem_script).decode("ascii")
        p2wsh_script = redeem_script_to_p2wsh_script(redeem_script)
        p2wsh_script_hex = binascii.hexlify(p2wsh_script).decode("ascii")

        return {
            "maker_nick": maker_nick,
            "taker_nick": taker_nick,
            "utxo_txid": binascii.hexlify(txid).decode("ascii"),
            "utxo_vout": vout,
            "locktime": locktime,
            "utxo_pub": utxo_pub_hex,
            "cert_pub": binascii.hexlify(cert_pub).decode("ascii"),
            "cert_expiry": cert_expiry,
            "proof": proof_base64,
            "redeem_script": redeem_script_hex,
            "p2wsh_script": p2wsh_script_hex,
        }
    except Exception as e:
        logger.warning(f"Failed to unpack bond proof: {e}")
        return None


class DirectoryClient:
    """
    Client for connecting to JoinMarket directory servers.

    Supports:
    - Direct TCP connections (for local/dev)
    - Tor connections (for .onion addresses)
    - Handshake protocol
    - Peerlist fetching
    - Orderbook fetching
    - Continuous listening for updates
    """

    def __init__(
        self,
        host: str,
        port: int,
        network: str,
        nick: str | None = None,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        timeout: float = 30.0,
        max_message_size: int = 2097152,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        """
        Initialize DirectoryClient.

        Args:
            host: Directory server hostname or .onion address
            port: Directory server port
            network: Bitcoin network (mainnet, testnet, signet, regtest)
            nick: JoinMarket nick (generated if None)
            socks_host: SOCKS proxy host for Tor
            socks_port: SOCKS proxy port for Tor
            timeout: Connection timeout in seconds
            max_message_size: Maximum message size in bytes
            on_disconnect: Callback when connection drops
        """
        self.host = host
        self.port = port
        self.network = network
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.timeout = timeout
        self.max_message_size = max_message_size
        self.connection: TCPConnection | None = None
        self.nick = nick or generate_jm_nick(JM_VERSION)
        self.offers: dict[tuple[str, int], Offer] = {}
        self.bonds: dict[str, FidelityBond] = {}
        self.running = False
        self.on_disconnect = on_disconnect
        self.initial_orderbook_received = False
        self.last_orderbook_request_time: float = 0.0
        self.last_offer_received_time: float | None = None

        # Timing intervals
        self.peerlist_check_interval = 1800.0
        self.orderbook_refresh_interval = 1800.0
        self.orderbook_retry_interval = 300.0
        self.zero_offer_retry_interval = 600.0

    async def connect(self) -> None:
        """Connect to the directory server and perform handshake."""
        try:
            if not self.host.endswith(".onion"):
                self.connection = await connect_direct(
                    self.host,
                    self.port,
                    self.max_message_size,
                    self.timeout,
                )
            else:
                self.connection = await connect_via_tor(
                    self.host,
                    self.port,
                    self.socks_host,
                    self.socks_port,
                    self.max_message_size,
                    self.timeout,
                )
            await self._handshake()
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            raise DirectoryClientError(f"Connection failed: {e}") from e

    async def _handshake(self) -> None:
        """Perform directory server handshake."""
        if not self.connection:
            raise DirectoryClientError("Not connected")

        handshake_data = create_handshake_request(
            nick=self.nick,
            location="NOT-SERVING-ONION",
            network=self.network,
            directory=False,
        )
        handshake_msg = {
            "type": MessageType.HANDSHAKE.value,
            "line": json.dumps(handshake_data),
        }
        await self.connection.send(json.dumps(handshake_msg).encode("utf-8"))

        response_data = await asyncio.wait_for(self.connection.receive(), timeout=self.timeout)
        response = json.loads(response_data.decode("utf-8"))

        if response["type"] not in (MessageType.HANDSHAKE.value, MessageType.DN_HANDSHAKE.value):
            raise DirectoryClientError(f"Unexpected response type: {response['type']}")

        handshake_response = json.loads(response["line"])
        if not handshake_response.get("accepted", False):
            raise DirectoryClientError("Handshake rejected")

        logger.info(f"Handshake successful with {self.host}:{self.port} (nick: {self.nick})")

    async def get_peerlist(self) -> list[str]:
        """
        Fetch the current list of connected peers.

        Returns:
            List of active peer nicks
        """
        if not self.connection:
            raise DirectoryClientError("Not connected")

        getpeerlist_msg = {"type": MessageType.GETPEERLIST.value, "line": ""}
        logger.debug("Sending GETPEERLIST request")
        await self.connection.send(json.dumps(getpeerlist_msg).encode("utf-8"))

        start_time = asyncio.get_event_loop().time()
        response = None

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > self.timeout:
                raise DirectoryClientError("Timed out waiting for PEERLIST response")

            try:
                response_data = await asyncio.wait_for(
                    self.connection.receive(), timeout=self.timeout - elapsed
                )
                response = json.loads(response_data.decode("utf-8"))
                msg_type = response.get("type")
                logger.debug(f"Received response type: {msg_type}")

                if msg_type == MessageType.PEERLIST.value:
                    break

                logger.debug(
                    f"Skipping unexpected message type {msg_type} while waiting for PEERLIST"
                )
            except TimeoutError as e:
                raise DirectoryClientError("Timed out waiting for PEERLIST response") from e
            except Exception as e:
                logger.warning(f"Error receiving/parsing message while waiting for PEERLIST: {e}")
                if asyncio.get_event_loop().time() - start_time > self.timeout:
                    raise DirectoryClientError(f"Failed to get PEERLIST: {e}") from e

        peerlist_str = response["line"]
        logger.debug(f"Peerlist string: {peerlist_str}")

        if not peerlist_str:
            return []

        peers = []
        for entry in peerlist_str.split(","):
            try:
                nick, location, disconnected = parse_peerlist_entry(entry)
                logger.debug(f"Parsed peer: {nick} at {location}, disconnected={disconnected}")
                if not disconnected:
                    peers.append(nick)
            except ValueError as e:
                logger.warning(f"Failed to parse peerlist entry '{entry}': {e}")
                continue

        logger.info(f"Received {len(peers)} active peers from {self.host}:{self.port}")
        return peers

    async def listen_for_messages(self, duration: float = 5.0) -> list[dict[str, Any]]:
        """
        Listen for messages for a specified duration.

        Args:
            duration: How long to listen in seconds

        Returns:
            List of received messages
        """
        if not self.connection:
            raise DirectoryClientError("Not connected")

        messages: list[dict[str, Any]] = []
        start_time = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start_time < duration:
            try:
                remaining_time = duration - (asyncio.get_event_loop().time() - start_time)
                if remaining_time <= 0:
                    break

                response_data = await asyncio.wait_for(
                    self.connection.receive(), timeout=remaining_time
                )
                response = json.loads(response_data.decode("utf-8"))
                logger.debug(
                    f"Received message type {response.get('type')}: "
                    f"{response.get('line', '')[:80]}..."
                )
                messages.append(response)

            except TimeoutError:
                logger.debug("Timeout waiting for more messages")
                break
            except Exception as e:
                logger.debug(f"Error receiving message: {e}")
                break

        logger.debug(f"Collected {len(messages)} messages in {duration}s")
        return messages

    async def fetch_orderbooks(self) -> tuple[list[Offer], list[FidelityBond]]:
        """
        Fetch orderbooks from all connected peers.

        Returns:
            Tuple of (offers, fidelity_bonds)
        """
        peers = await self.get_peerlist()
        offers: list[Offer] = []
        bonds: list[FidelityBond] = []
        bond_utxo_set: set[str] = set()

        # NOTE: Peerlist may be empty if all makers use NOT-SERVING-ONION (regtest/local).
        # We still broadcast !orderbook because makers will respond via the directory.
        if not peers:
            logger.info(
                f"Peerlist empty on {self.host}:{self.port} (makers may be NOT-SERVING-ONION)"
            )
        else:
            logger.info(f"Found {len(peers)} peers on {self.host}:{self.port}")

        if not self.connection:
            raise DirectoryClientError("Not connected")

        pubmsg = {
            "type": MessageType.PUBMSG.value,
            "line": f"{self.nick}!PUBLIC!!orderbook",
        }
        await self.connection.send(json.dumps(pubmsg).encode("utf-8"))
        logger.debug("Sent !orderbook broadcast to PUBLIC")

        logger.info("Listening for offer announcements for 10 seconds...")
        messages = await self.listen_for_messages(duration=10.0)

        logger.info(f"Received {len(messages)} messages, parsing offers...")

        for response in messages:
            try:
                msg_type = response.get("type")
                if msg_type not in (MessageType.PUBMSG.value, MessageType.PRIVMSG.value):
                    logger.debug(f"Skipping message type {msg_type}")
                    continue

                line = response["line"]
                logger.debug(f"Processing message type {msg_type}: {line[:100]}...")

                parts = line.split(COMMAND_PREFIX)
                if len(parts) < 3:
                    logger.debug(f"Message has insufficient parts: {len(parts)}")
                    continue

                from_nick = parts[0]
                _to_nick = parts[1]
                rest = COMMAND_PREFIX.join(parts[2:])

                if not rest.strip():
                    logger.debug("Empty message content")
                    continue

                offer_types = ["sw0absoffer", "sw0reloffer", "swabsoffer", "swreloffer"]
                parsed = False
                for offer_type in offer_types:
                    if rest.startswith(offer_type):
                        try:
                            rest_parts = rest.split(COMMAND_PREFIX, 1)
                            offer_line = rest_parts[0]
                            bond_data = None

                            if len(rest_parts) > 1 and rest_parts[1].startswith("tbond "):
                                bond_parts = rest_parts[1][6:].split()
                                if bond_parts:
                                    bond_proof_b64 = bond_parts[0]
                                    bond_data = parse_fidelity_bond_proof(
                                        bond_proof_b64, from_nick, self.nick
                                    )
                                    if bond_data:
                                        logger.debug(
                                            f"Parsed fidelity bond from {from_nick}: "
                                            f"txid={bond_data['utxo_txid'][:16]}..., "
                                            f"locktime={bond_data['locktime']}"
                                        )

                                        utxo_str = (
                                            f"{bond_data['utxo_txid']}:{bond_data['utxo_vout']}"
                                        )
                                        if utxo_str not in bond_utxo_set:
                                            bond_utxo_set.add(utxo_str)
                                            bond = FidelityBond(
                                                counterparty=from_nick,
                                                utxo_txid=bond_data["utxo_txid"],
                                                utxo_vout=bond_data["utxo_vout"],
                                                locktime=bond_data["locktime"],
                                                script=bond_data["utxo_pub"],
                                                utxo_confirmations=0,
                                                cert_expiry=bond_data["cert_expiry"],
                                                fidelity_bond_data=bond_data,
                                            )
                                            bonds.append(bond)

                            offer_parts = offer_line.split()
                            if len(offer_parts) < 6:
                                logger.warning(
                                    f"Offer from {from_nick} has {len(offer_parts)} parts, need 6"
                                )
                                continue

                            oid = int(offer_parts[1])
                            minsize = int(offer_parts[2])
                            maxsize = int(offer_parts[3])
                            txfee = int(offer_parts[4])
                            cjfee_str = offer_parts[5]

                            if offer_type in ["sw0absoffer", "swabsoffer"]:
                                cjfee = str(int(cjfee_str))
                            else:
                                cjfee = str(Decimal(cjfee_str))

                            offer = Offer(
                                counterparty=from_nick,
                                oid=oid,
                                ordertype=OfferType(offer_type),
                                minsize=minsize,
                                maxsize=maxsize,
                                txfee=txfee,
                                cjfee=cjfee,
                                fidelity_bond_value=0,
                            )
                            offers.append(offer)

                            if bond_data:
                                offer.fidelity_bond_data = bond_data

                            logger.info(
                                f"Parsed {offer_type} from {from_nick}: "
                                f"oid={oid}, size={minsize}-{maxsize}, fee={cjfee}, "
                                f"has_bond={bond_data is not None}"
                            )
                            parsed = True
                        except Exception as e:
                            logger.warning(f"Failed to parse {offer_type} from {from_nick}: {e}")
                        break

                if not parsed:
                    logger.debug(f"Message not an offer: {rest[:50]}...")

            except Exception as e:
                logger.warning(f"Failed to process message: {e}")
                continue

        logger.info(
            f"Fetched {len(offers)} offers and {len(bonds)} fidelity bonds from "
            f"{self.host}:{self.port}"
        )
        return offers, bonds

    async def send_public_message(self, message: str) -> None:
        """
        Send a public message to all peers.

        Args:
            message: Message to broadcast
        """
        if not self.connection:
            raise DirectoryClientError("Not connected")

        pubmsg = {
            "type": MessageType.PUBMSG.value,
            "line": f"{self.nick}!PUBLIC!{message}",
        }
        await self.connection.send(json.dumps(pubmsg).encode("utf-8"))

    async def send_private_message(self, recipient: str, message: str) -> None:
        """
        Send a private message to a specific peer.

        Args:
            recipient: Target peer nick
            message: Message to send
        """
        if not self.connection:
            raise DirectoryClientError("Not connected")

        privmsg = {
            "type": MessageType.PRIVMSG.value,
            "line": f"{self.nick}!{recipient}!{message}",
        }
        await self.connection.send(json.dumps(privmsg).encode("utf-8"))

    async def close(self) -> None:
        """Close the connection to the directory server."""
        if self.connection:
            try:
                # NOTE: We skip sending DISCONNECT (801) because the reference implementation
                # crashes on unhandled control messages.
                pass
            except Exception:
                pass
            finally:
                await self.connection.close()
                self.connection = None

    def stop(self) -> None:
        """Stop continuous listening."""
        self.running = False

    async def listen_continuously(self) -> None:
        """
        Continuously listen for messages and update internal offer/bond caches.

        This method runs indefinitely until stop() is called or connection is lost.
        Used by orderbook_watcher and maker to maintain live orderbook state.
        """
        if not self.connection:
            raise DirectoryClientError("Not connected")

        logger.info(f"Starting continuous listening on {self.host}:{self.port}")
        self.running = True

        while self.running:
            try:
                # Read next message with timeout
                data = await asyncio.wait_for(self.connection.receive(), timeout=5.0)

                if not data:
                    logger.warning(f"Connection to {self.host}:{self.port} closed")
                    break

                message = json.loads(data.decode("utf-8"))
                msg_type = message.get("type")
                line = message.get("line", "")

                # Process PUBMSG to update offers/bonds cache
                if msg_type == MessageType.PUBMSG.value:
                    try:
                        parts = line.split(COMMAND_PREFIX)
                        if len(parts) >= 3:
                            from_nick = parts[0]
                            to_nick = parts[1]
                            rest = COMMAND_PREFIX.join(parts[2:])

                            if to_nick == "PUBLIC":
                                # Parse offer announcements
                                for offer_type_prefix in [
                                    "sw0reloffer",
                                    "sw0absoffer",
                                    "swreloffer",
                                    "swabsoffer",
                                ]:
                                    if rest.startswith(offer_type_prefix):
                                        offer_parts = rest[len(offer_type_prefix) :].strip().split()
                                        if len(offer_parts) >= 5:
                                            try:
                                                oid = int(offer_parts[0])
                                                minsize = int(offer_parts[1])
                                                maxsize = int(offer_parts[2])
                                                txfee = int(offer_parts[3])
                                                cjfee_str = offer_parts[4]

                                                if offer_type_prefix in [
                                                    "sw0absoffer",
                                                    "swabsoffer",
                                                ]:
                                                    cjfee = str(int(cjfee_str))
                                                else:
                                                    cjfee = str(Decimal(cjfee_str))

                                                offer = Offer(
                                                    counterparty=from_nick,
                                                    oid=oid,
                                                    ordertype=OfferType(offer_type_prefix),
                                                    minsize=minsize,
                                                    maxsize=maxsize,
                                                    txfee=txfee,
                                                    cjfee=cjfee,
                                                    fidelity_bond_value=0,
                                                )

                                                # Update cache using tuple key
                                                offer_key = (from_nick, oid)
                                                self.offers[offer_key] = offer

                                                logger.debug(
                                                    f"Updated offer cache: {from_nick} {offer_type_prefix} "
                                                    f"oid={oid}"
                                                )
                                            except Exception as e:
                                                logger.debug(f"Failed to parse offer update: {e}")
                                        break
                    except Exception as e:
                        logger.debug(f"Failed to process PUBMSG: {e}")

            except TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info(f"Continuous listening on {self.host}:{self.port} cancelled")
                break
            except Exception as e:
                logger.error(f"Error in continuous listening: {e}")
                if self.on_disconnect:
                    self.on_disconnect()
                break

        self.running = False
        logger.info(f"Stopped continuous listening on {self.host}:{self.port}")

    def get_current_offers(self) -> list[Offer]:
        """Get the current list of cached offers."""
        return list(self.offers.values())

    def get_current_bonds(self) -> list[FidelityBond]:
        """Get the current list of cached fidelity bonds."""
        return list(self.bonds.values())
