"""
Main maker bot implementation.

Coordinates all maker components:
- Wallet synchronization
- Directory server connections
- Offer creation and announcement
- CoinJoin protocol handling
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from jmcore.crypto import generate_jm_nick
from jmcore.directory_client import DirectoryClient
from jmcore.models import Offer
from jmcore.protocol import COMMAND_PREFIX, JM_VERSION
from jmwallet.backends.base import BlockchainBackend
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.coinjoin import CoinJoinSession
from maker.config import MakerConfig
from maker.offers import OfferManager


class MakerBot:
    """
    Main maker bot coordinating all components.
    """

    def __init__(
        self,
        wallet: WalletService,
        backend: BlockchainBackend,
        config: MakerConfig,
    ):
        self.wallet = wallet
        self.backend = backend
        self.config = config
        self.nick = generate_jm_nick(JM_VERSION)

        self.offer_manager = OfferManager(self.wallet, config, self.nick)

        self.directory_clients: dict[str, DirectoryClient] = {}
        self.active_sessions: dict[str, CoinJoinSession] = {}
        self.current_offers: list[Offer] = []

        self.running = False
        self.listen_tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        """
        Start the maker bot.

        Flow:
        1. Sync wallet with blockchain
        2. Connect to directory servers
        3. Create and announce offers
        4. Listen for taker requests
        """
        try:
            logger.info(f"Starting maker bot (nick: {self.nick})")

            logger.info("Syncing wallet...")
            await self.wallet.sync_all()

            total_balance = await self.wallet.get_total_balance()
            logger.info(f"Wallet synced. Total balance: {total_balance:,} sats")

            logger.info("Creating offers...")
            self.current_offers = await self.offer_manager.create_offers()

            if not self.current_offers:
                logger.error("No offers created. Insufficient balance?")
                return

            logger.info("Connecting to directory servers...")
            for dir_server in self.config.directory_servers:
                try:
                    parts = dir_server.split(":")
                    host = parts[0]
                    port = int(parts[1]) if len(parts) > 1 else 5222

                    # Create DirectoryClient
                    client = DirectoryClient(
                        host=host,
                        port=port,
                        network=self.config.network.value,
                        nick=self.nick,
                    )

                    await client.connect()
                    node_id = f"{host}:{port}"
                    self.directory_clients[node_id] = client

                    logger.info(f"Connected to directory: {dir_server}")

                except Exception as e:
                    logger.error(f"Failed to connect to {dir_server}: {e}")

            if not self.directory_clients:
                logger.error("Failed to connect to any directory server")
                return

            logger.info("Announcing offers...")
            await self._announce_offers()

            logger.info("Maker bot started. Listening for takers...")
            self.running = True

            # Start listening on all clients
            for node_id, client in self.directory_clients.items():
                task = asyncio.create_task(self._listen_client(node_id, client))
                self.listen_tasks.append(task)

            # Wait for all listening tasks to complete
            await asyncio.gather(*self.listen_tasks, return_exceptions=True)

        except Exception as e:
            logger.error(f"Failed to start maker bot: {e}")
            raise

    async def stop(self) -> None:
        """Stop the maker bot"""
        logger.info("Stopping maker bot...")
        self.running = False

        # Cancel all listening tasks
        for task in self.listen_tasks:
            task.cancel()

        if self.listen_tasks:
            await asyncio.gather(*self.listen_tasks, return_exceptions=True)

        # Close all directory clients
        for client in self.directory_clients.values():
            try:
                await client.close()
            except Exception:
                pass

        await self.wallet.close()
        logger.info("Maker bot stopped")

    async def _announce_offers(self) -> None:
        """Announce offers to all connected directory servers"""
        for offer in self.current_offers:
            offer_msg = self._format_offer_announcement(offer)

            for client in self.directory_clients.values():
                try:
                    await client.send_public_message(offer_msg)
                    logger.debug("Announced offer to directory")
                except Exception as e:
                    logger.error(f"Failed to announce offer: {e}")

    def _format_offer_announcement(self, offer) -> str:
        """Format offer for announcement"""

        order_type_str = offer.ordertype.value

        msg = (
            f"{self.nick}!PUBLIC!{order_type_str} "
            f"{offer.oid} {offer.minsize} {offer.maxsize} "
            f"{offer.txfee} {offer.cjfee}"
        )

        return msg

    async def _listen_client(self, node_id: str, client: DirectoryClient) -> None:
        """Listen for messages from a specific directory client"""
        logger.info(f"Started listening on {node_id}")

        while self.running:
            try:
                # Use listen_for_messages with short duration to check running flag frequently
                messages = await client.listen_for_messages(duration=1.0)

                for message in messages:
                    await self._handle_message(message)

            except asyncio.CancelledError:
                logger.info(f"Listener for {node_id} cancelled")
                break
            except Exception as e:
                logger.error(f"Error listening on {node_id}: {e}")
                await asyncio.sleep(1.0)

        logger.info(f"Stopped listening on {node_id}")

    async def _handle_message(self, message: dict[str, Any]) -> None:
        """Handle incoming message from directory"""
        try:
            from jmcore.protocol import MessageType

            msg_type = message.get("type")
            line = message.get("line", "")

            if msg_type == MessageType.PRIVMSG.value:
                await self._handle_privmsg(line)
            elif msg_type == MessageType.PUBMSG.value:
                pass
            elif msg_type == MessageType.PEERLIST.value:
                logger.debug(f"Received peerlist: {line[:50]}...")
            else:
                logger.debug(f"Ignoring message type {msg_type}")

        except Exception as e:
            logger.error(f"Failed to handle message: {e}")

    async def _handle_privmsg(self, line: str) -> None:
        """Handle private message (CoinJoin protocol)"""
        try:
            parts = line.split(COMMAND_PREFIX)
            if len(parts) < 3:
                return

            from_nick = parts[0]
            to_nick = parts[1]
            rest = COMMAND_PREFIX.join(parts[2:])

            if to_nick != self.nick:
                return

            if rest.startswith("!fill"):
                await self._handle_fill(from_nick, rest)
            elif rest.startswith("!auth"):
                await self._handle_auth(from_nick, rest)
            elif rest.startswith("!tx"):
                await self._handle_tx(from_nick, rest)
            else:
                logger.debug(f"Unknown command: {rest[:20]}...")

        except Exception as e:
            logger.error(f"Failed to handle privmsg: {e}")

    async def _handle_fill(self, taker_nick: str, msg: str) -> None:
        """Handle !fill request from taker"""
        try:
            parts = msg.split()
            if len(parts) < 4:
                logger.warning(f"Invalid !fill format: {msg}")
                return

            offer_id = int(parts[1])
            amount = int(parts[2])
            commitment = parts[3]

            if offer_id >= len(self.current_offers):
                logger.warning(f"Invalid offer ID: {offer_id}")
                return

            offer = self.current_offers[offer_id]

            is_valid, error = self.offer_manager.validate_offer_fill(offer, amount)
            if not is_valid:
                logger.warning(f"Invalid fill request: {error}")
                return

            session = CoinJoinSession(
                taker_nick=taker_nick,
                offer=offer,
                wallet=self.wallet,
                backend=self.backend,
            )

            success, response = await session.handle_fill(amount, commitment)

            if success:
                self.active_sessions[taker_nick] = session
                logger.info(f"Created CoinJoin session with {taker_nick}")

                await self._send_response(taker_nick, "!pubkey", response)
            else:
                logger.warning(f"Failed to handle fill: {response.get('error')}")

        except Exception as e:
            logger.error(f"Failed to handle !fill: {e}")

    async def _handle_auth(self, taker_nick: str, msg: str) -> None:
        """Handle !auth request from taker"""
        try:
            if taker_nick not in self.active_sessions:
                logger.warning(f"No active session for {taker_nick}")
                return

            session = self.active_sessions[taker_nick]

            logger.info(f"Received !auth from {taker_nick}, verifying PoDLE...")

            parts = msg.split()
            commitment = parts[1]
            revelation_json = parts[2]
            kphex = parts[3] if len(parts) > 3 else ""

            revelation = json.loads(revelation_json)

            success, response = await session.handle_auth(commitment, revelation, kphex)

            if success:
                await self._send_response(taker_nick, "!ioauth", response)
            else:
                logger.error(f"Auth failed: {response.get('error')}")
                del self.active_sessions[taker_nick]

        except Exception as e:
            logger.error(f"Failed to handle !auth: {e}")

    async def _handle_tx(self, taker_nick: str, msg: str) -> None:
        """Handle !tx request from taker"""
        try:
            if taker_nick not in self.active_sessions:
                logger.warning(f"No active session for {taker_nick}")
                return

            session = self.active_sessions[taker_nick]

            logger.info(f"Received !tx from {taker_nick}, verifying transaction...")

            parts = msg.split(maxsplit=1)
            if len(parts) < 2:
                logger.warning("Invalid !tx format")
                return

            tx_hex = parts[1]

            success, response = await session.handle_tx(tx_hex)

            if success:
                await self._send_response(taker_nick, "!sig", response)
                logger.info(f"CoinJoin with {taker_nick} COMPLETE ✓")
                del self.active_sessions[taker_nick]
            else:
                logger.error(f"TX verification failed: {response.get('error')}")
                del self.active_sessions[taker_nick]

        except Exception as e:
            logger.error(f"Failed to handle !tx: {e}")

    async def _send_response(self, taker_nick: str, command: str, data: dict[str, Any]) -> None:
        """Send response to taker"""
        try:
            data_json = json.dumps(data)
            msg = f"{command} {data_json}"

            for client in self.directory_clients.values():
                await client.send_private_message(taker_nick, msg)

            logger.debug(f"Sent {command} to {taker_nick}")

        except Exception as e:
            logger.error(f"Failed to send response: {e}")
