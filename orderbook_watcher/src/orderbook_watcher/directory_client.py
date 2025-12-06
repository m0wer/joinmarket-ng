"""
Client for connecting to JoinMarket directory nodes and fetching orderbooks.
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

from jmcore.btc_script import mk_freeze_script, redeem_script_to_p2wsh_script
from jmcore.crypto import generate_jm_nick
from jmcore.models import FidelityBond, Offer, OfferType
from jmcore.network import TCPConnection, connect_via_tor
from jmcore.protocol import (
    COMMAND_PREFIX,
    JM_VERSION,
    MessageType,
    create_handshake_request,
    parse_peerlist_entry,
)
from loguru import logger


class DirectoryClientError(Exception):
    pass


def parse_fidelity_bond_proof(
    proof_base64: str, maker_nick: str, taker_nick: str
) -> dict[str, Any] | None:
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
    def __init__(
        self,
        onion_address: str,
        port: int,
        network: str,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        timeout: float = 30.0,
        max_message_size: int = 2097152,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self.onion_address = onion_address
        self.port = port
        self.network = network
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.timeout = timeout
        self.max_message_size = max_message_size
        self.connection: TCPConnection | None = None
        self.nick = generate_jm_nick(JM_VERSION)
        self.offers: dict[tuple[str, int], Offer] = {}
        self.bonds: dict[str, FidelityBond] = {}
        self.running = False
        self.on_disconnect = on_disconnect
        self.initial_orderbook_received = False
        self.last_orderbook_request_time: float = 0.0
        self.last_offer_received_time: float | None = None
        self.peerlist_check_interval = 1800.0
        self.orderbook_refresh_interval = 1800.0
        self.orderbook_retry_interval = 300.0
        self.zero_offer_retry_interval = 600.0

    async def connect(self) -> None:
        try:
            self.connection = await connect_via_tor(
                self.onion_address,
                self.port,
                self.socks_host,
                self.socks_port,
                self.max_message_size,
                self.timeout,
            )
            await self._handshake()
        except Exception as e:
            logger.error(f"Failed to connect to {self.onion_address}:{self.port}: {e}")
            raise DirectoryClientError(f"Connection failed: {e}") from e

    async def _handshake(self) -> None:
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

        logger.info(
            f"Handshake successful with {self.onion_address}:{self.port} (nick: {self.nick})"
        )

    async def get_peerlist(self) -> list[str]:
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
                # Use remaining time for timeout
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
                # If we fail to parse a message, we should probably keep trying unless it's critical
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

        logger.info(f"Received {len(peers)} active peers from {self.onion_address}:{self.port}")
        return peers

    async def listen_for_messages(self, duration: float = 5.0) -> list[dict[str, Any]]:
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
                    f"Received message type {response.get('type')}: {response.get('line', '')[:80]}..."
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
        peers = await self.get_peerlist()
        offers: list[Offer] = []
        bonds: list[FidelityBond] = []
        bond_utxo_set: set[str] = set()

        if not peers:
            logger.info(f"No peers found on {self.onion_address}:{self.port}")
            return offers, bonds

        logger.info(f"Found {len(peers)} peers, broadcasting !orderbook request to PUBLIC...")

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
            f"Fetched {len(offers)} offers and {len(bonds)} fidelity bonds from {self.onion_address}:{self.port}"
        )
        return offers, bonds

    async def close(self) -> None:
        if self.connection:
            try:
                # NOTE: We skip sending DISCONNECT (801) because the reference implementation
                # crashes on unhandled control messages.
                # disconnect_msg = {"type": MessageType.DISCONNECT.value, "line": ""}
                # await self.connection.send(json.dumps(disconnect_msg).encode("utf-8"))
                pass
            except Exception:
                pass
            finally:
                await self.connection.close()
                self.connection = None

    def _parse_offer_message(self, line: str) -> Offer | None:
        try:
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                return None

            from_nick = parts[0]
            _to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            if not rest.strip():
                return None

            offer_types = ["sw0absoffer", "sw0reloffer", "swabsoffer", "swreloffer"]
            for offer_type in offer_types:
                if rest.startswith(offer_type):
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
                                    f"txid={bond_data['utxo_txid'][:16]}..."
                                )

                                utxo_str = f"{bond_data['utxo_txid']}:{bond_data['utxo_vout']}"
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
                                self.bonds[utxo_str] = bond

                    offer_parts = offer_line.split()
                    if len(offer_parts) < 6:
                        return None

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

                    if bond_data:
                        offer.fidelity_bond_data = bond_data
                    else:
                        offer_key = (from_nick, oid)
                        if offer_key in self.offers and self.offers[offer_key].fidelity_bond_data:
                            offer.fidelity_bond_data = self.offers[offer_key].fidelity_bond_data
                            logger.debug(f"Preserved bond data for {from_nick} oid={oid}")

                    logger.info(
                        f"Parsed {offer_type} from {from_nick}: "
                        f"oid={oid}, size={minsize}-{maxsize}, fee={cjfee}, "
                        f"has_bond={offer.fidelity_bond_data is not None}"
                    )
                    return offer
        except Exception as e:
            logger.warning(f"Failed to parse offer: {e}")
        return None

    async def request_bond_for_maker(self, maker_nick: str) -> None:
        if not self.connection:
            return

        try:
            privmsg = {
                "type": MessageType.PRIVMSG.value,
                "line": f"{self.nick}!{maker_nick}!!hp2",
            }
            await self.connection.send(json.dumps(privmsg).encode("utf-8"))
            logger.debug(f"Requested bond info from {maker_nick}")
        except Exception as e:
            logger.warning(f"Failed to request bond from {maker_nick}: {e}")

    async def _send_orderbook_request(self, reason: str) -> bool:
        """Send a !orderbook request and update the retry timestamp."""
        if not self.connection:
            logger.warning(f"Cannot send {reason} !orderbook request without a connection")
            return False

        try:
            peer_count = len(await self.get_peerlist())
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning(f"Failed to fetch peerlist for {reason} request: {exc}")
            return False

        if peer_count == 0:
            logger.warning(f"No peers available, skipping {reason} !orderbook request")
            return False

        pubmsg = {
            "type": MessageType.PUBMSG.value,
            "line": f"{self.nick}!PUBLIC!!orderbook",
        }
        await self.connection.send(json.dumps(pubmsg).encode("utf-8"))
        self.last_orderbook_request_time = asyncio.get_event_loop().time()
        logger.info(f"Sent {reason} !orderbook request ({peer_count} peers)")
        return True

    async def listen_continuously(self) -> None:
        self.running = True
        logger.info(f"Starting continuous listener for {self.onion_address}:{self.port}")
        peers_with_bonds: set[str] = set()
        peers_without_bonds: set[str] = set()
        loop = asyncio.get_event_loop()
        last_peerlist_check_time = loop.time()
        last_orderbook_refresh_time = loop.time()
        last_zero_offer_retry_time = loop.time()

        if self.connection:
            await self._send_orderbook_request("initial")
            last_orderbook_refresh_time = loop.time()

        while self.running:
            try:
                if not self.connection:
                    logger.warning("Connection lost, stopping listener")
                    break

                response_data = await asyncio.wait_for(self.connection.receive(), timeout=60.0)
                response = json.loads(response_data.decode("utf-8"))
                msg_type = response.get("type")

                if msg_type in (MessageType.PUBMSG.value, MessageType.PRIVMSG.value):
                    line = response["line"]
                    offer = self._parse_offer_message(line)
                    if offer:
                        offer_key = (offer.counterparty, offer.oid)
                        is_new_offer = offer_key not in self.offers
                        self.offers[offer_key] = offer
                        logger.debug(f"Updated offer: {offer_key}")
                        self.last_offer_received_time = loop.time()

                        if not self.initial_orderbook_received and len(self.offers) > 0:
                            self.initial_orderbook_received = True
                            logger.info(
                                f"Received first offers from {self.onion_address}:{self.port}"
                            )

                        if offer.fidelity_bond_data:
                            peers_with_bonds.add(offer.counterparty)
                            peers_without_bonds.discard(offer.counterparty)
                        elif is_new_offer and offer.counterparty not in peers_without_bonds:
                            logger.debug(
                                f"New offer from {offer.counterparty} without bond, requesting..."
                            )
                            await self.request_bond_for_maker(offer.counterparty)
                elif msg_type == MessageType.PEERLIST.value:
                    logger.debug("Received PEERLIST update")
                else:
                    logger.debug(f"Received message type {msg_type}")

                current_time = asyncio.get_event_loop().time()

                if (
                    not self.initial_orderbook_received
                    and len(self.offers) == 0
                    and current_time - self.last_orderbook_request_time
                    >= self.orderbook_retry_interval
                ):
                    logger.warning(
                        f"No offers received yet from {self.onion_address}:{self.port}, "
                        f"retrying !orderbook request"
                    )
                    await self._send_orderbook_request("retry")

                if (
                    len(self.offers) == 0
                    and current_time - last_zero_offer_retry_time >= self.zero_offer_retry_interval
                ):
                    logger.info("No offers currently available, sending zero-offer retry request")
                    if await self._send_orderbook_request("zero-offer retry"):
                        last_zero_offer_retry_time = current_time

                if (
                    self.last_offer_received_time
                    and (current_time - self.last_offer_received_time)
                    >= self.orderbook_refresh_interval
                ):
                    logger.warning(
                        "No offers received since the last refresh interval, re-requesting"
                    )
                    await self._send_orderbook_request("stale-offer refresh")
                    self.last_offer_received_time = current_time

                if current_time - last_peerlist_check_time >= self.peerlist_check_interval:
                    removed_count = await self._cleanup_disconnected_peers()
                    if removed_count > 0:
                        logger.info(f"Removed {removed_count} offers from disconnected peers")
                    last_peerlist_check_time = current_time

                if current_time - last_orderbook_refresh_time >= self.orderbook_refresh_interval:
                    logger.info("Sending periodic !orderbook refresh")
                    if await self._send_orderbook_request("periodic refresh"):
                        last_orderbook_refresh_time = current_time

            except TimeoutError:
                # NOTE: We do NOT send keepalive PINGs because the reference implementation
                # of the directory server (joinmarket-clientserver) crashes on receiving PING (797)
                # due to an ID collision with its internal 'connect-in' message.
                # We simply log the timeout and continue listening.
                logger.debug("No messages received in 60s (keepalive skipped)")
            except Exception as e:
                logger.error(f"Error in continuous listener: {e}")
                self.connection = None
                if self.on_disconnect:
                    self.on_disconnect()
                await asyncio.sleep(5)

    async def _cleanup_disconnected_peers(self) -> int:
        try:
            active_peers = await self.get_peerlist()
            active_peers_set = set(active_peers)

            all_counterparties = {key[0] for key in self.offers}
            disconnected_counterparties = all_counterparties - active_peers_set

            removed_count = 0
            for counterparty in disconnected_counterparties:
                offers_to_remove = [key for key in self.offers if key[0] == counterparty]
                for key in offers_to_remove:
                    del self.offers[key]
                    removed_count += 1
                    logger.debug(f"Removed offer from disconnected peer: {key}")

                if counterparty in self.bonds:
                    del self.bonds[counterparty]

            return removed_count
        except Exception as e:
            logger.warning(f"Failed to fetch peerlist for cleanup: {e}")
            return 0

    def stop(self) -> None:
        self.running = False

    def get_current_offers(self) -> list[Offer]:
        return list(self.offers.values())

    def get_current_bonds(self) -> list[FidelityBond]:
        return list(self.bonds.values())
