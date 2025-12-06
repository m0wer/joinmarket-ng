"""
Orderbook aggregation logic across multiple directory nodes.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
from typing import Any

from jmcore.bond_calc import calculate_timelocked_fidelity_bond_value
from jmcore.mempool_api import MempoolAPI
from jmcore.models import FidelityBond, Offer, OrderBook
from loguru import logger

from orderbook_watcher.directory_client import DirectoryClient
from orderbook_watcher.nostr_adapter import NostrWatcherClient


class DirectoryNodeStatus:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self.connected = False
        self.last_connected: datetime | None = None
        self.last_disconnected: datetime | None = None
        self.connection_attempts = 0
        self.successful_connections = 0
        self.total_uptime_seconds = 0.0
        self.current_session_start: datetime | None = None
        self.tracking_started: datetime | None = None

    def mark_connected(self, current_time: datetime | None = None) -> None:
        now = current_time or datetime.utcnow()
        if not self.tracking_started:
            self.tracking_started = now
        self.connected = True
        self.last_connected = now
        self.current_session_start = now
        self.successful_connections += 1

    def mark_disconnected(self, current_time: datetime | None = None) -> None:
        now = current_time or datetime.utcnow()
        if self.connected and self.current_session_start:
            session_duration = (now - self.current_session_start).total_seconds()
            self.total_uptime_seconds += session_duration
        self.connected = False
        self.last_disconnected = now
        self.current_session_start = None

    def get_uptime_percentage(self, current_time: datetime | None = None) -> float:
        if self.successful_connections == 0:
            return 0.0
        if not self.tracking_started:
            return 0.0
        now = current_time or datetime.utcnow()
        total_time = (now - self.tracking_started).total_seconds()
        if total_time == 0:
            return 0.0
        current_uptime = self.total_uptime_seconds
        if self.connected and self.current_session_start:
            current_uptime += (now - self.current_session_start).total_seconds()
        return (current_uptime / total_time) * 100.0

    def to_dict(self, current_time: datetime | None = None) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "connected": self.connected,
            "last_connected": self.last_connected.isoformat() if self.last_connected else None,
            "last_disconnected": self.last_disconnected.isoformat()
            if self.last_disconnected
            else None,
            "connection_attempts": self.connection_attempts,
            "successful_connections": self.successful_connections,
            "uptime_percentage": round(self.get_uptime_percentage(current_time), 2),
        }


class OrderbookAggregator:
    def __init__(
        self,
        directory_nodes: list[tuple[str, int]],
        network: str,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        timeout: float = 30.0,
        mempool_api_url: str = "https://mempool.space/api",
        max_retry_attempts: int = 3,
        retry_delay: float = 5.0,
        max_message_size: int = 2097152,
        nostr_relays: list[str] | None = None,
    ) -> None:
        self.directory_nodes = directory_nodes
        self.network = network
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.timeout = timeout
        self.mempool_api_url = mempool_api_url
        self.max_retry_attempts = max_retry_attempts
        self.retry_delay = retry_delay
        self.max_message_size = max_message_size
        self.nostr_relays = nostr_relays or []
        self.nostr_client: NostrWatcherClient | None = None
        if self.nostr_relays:
            self.nostr_client = NostrWatcherClient(self.nostr_relays)

        socks_proxy = f"socks5://{socks_host}:{socks_port}"
        logger.info(f"Configuring MempoolAPI with SOCKS proxy: {socks_proxy}")
        mempool_timeout = 60.0
        self.mempool_api = MempoolAPI(
            base_url=mempool_api_url, socks_proxy=socks_proxy, timeout=mempool_timeout
        )

        self._socks_test_task = asyncio.create_task(self._test_socks_connection())
        self.current_orderbook: OrderBook = OrderBook()
        self._lock = asyncio.Lock()
        self.clients: dict[str, DirectoryClient] = {}
        self.listener_tasks: list[asyncio.Task] = []
        self._bond_calculation_task: asyncio.Task[Any] | None = None
        self._bond_queue: asyncio.Queue[OrderBook] = asyncio.Queue()
        self._bond_cache: dict[str, FidelityBond] = {}
        self._last_offers_hash: int = 0
        self._mempool_semaphore = asyncio.Semaphore(5)
        self.node_statuses: dict[str, DirectoryNodeStatus] = {}
        self._retry_tasks: list[asyncio.Task] = []

        for onion_address, port in directory_nodes:
            node_id = f"{onion_address}:{port}"
            self.node_statuses[node_id] = DirectoryNodeStatus(node_id)

    def _handle_client_disconnect(self, onion_address: str, port: int) -> None:
        node_id = f"{onion_address}:{port}"
        client = self.clients.pop(node_id, None)
        if client:
            client.stop()
        self._schedule_reconnect(onion_address, port)

    def _schedule_reconnect(self, onion_address: str, port: int) -> None:
        node_id = f"{onion_address}:{port}"
        self._retry_tasks = [task for task in self._retry_tasks if not task.done()]
        if any(task.get_name() == f"retry:{node_id}" for task in self._retry_tasks):
            logger.debug(f"Retry already scheduled for {node_id}")
            return
        retry_task = asyncio.create_task(self._retry_failed_connection(onion_address, port))
        retry_task.set_name(f"retry:{node_id}")
        self._retry_tasks.append(retry_task)
        logger.info(f"Scheduled retry task for {node_id}")

    async def fetch_from_directory(
        self, onion_address: str, port: int
    ) -> tuple[list[Offer], list[FidelityBond], str]:
        node_id = f"{onion_address}:{port}"
        logger.info(f"Fetching orderbook from directory: {node_id}")
        client = DirectoryClient(
            onion_address,
            port,
            self.network,
            self.socks_host,
            self.socks_port,
            self.timeout,
            max_message_size=self.max_message_size,
        )
        try:
            await client.connect()
            offers, bonds = await client.fetch_orderbooks()

            for offer in offers:
                offer.directory_node = node_id
            for bond in bonds:
                bond.directory_node = node_id

            return offers, bonds, node_id
        except Exception as e:
            logger.error(f"Failed to fetch from directory {node_id}: {e}")
            return [], [], node_id
        finally:
            await client.close()

    async def fetch_from_nostr(self) -> tuple[list[Offer], list[FidelityBond], str]:
        if not self.nostr_relays:
            return [], [], "nostr"

        logger.info(f"Fetching orderbook from Nostr relays: {self.nostr_relays}")
        try:
            client = NostrWatcherClient(self.nostr_relays)
            offers, bonds = await client.fetch_offers()

            for offer in offers:
                offer.directory_node = "nostr"
            # Bonds handling if any

            return offers, bonds, "nostr"
        except Exception as e:
            logger.error(f"Failed to fetch from Nostr: {e}")
            return [], [], "nostr"

    async def update_orderbook(self) -> OrderBook:
        tasks = [
            self.fetch_from_directory(onion_address, port)
            for onion_address, port in self.directory_nodes
        ]

        # Add Nostr task
        if self.nostr_relays:
            tasks.append(self.fetch_from_nostr())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        new_orderbook = OrderBook(timestamp=datetime.utcnow())

        for result in results:
            if isinstance(result, BaseException):
                logger.error(f"Directory fetch failed: {result}")
                continue

            offers, bonds, node_id = result
            if offers or bonds:
                new_orderbook.add_offers(offers, node_id)
                new_orderbook.add_fidelity_bonds(bonds, node_id)

        await self._calculate_bond_values(new_orderbook)

        async with self._lock:
            self.current_orderbook = new_orderbook

        logger.info(
            f"Updated orderbook: {len(new_orderbook.offers)} offers, "
            f"{len(new_orderbook.fidelity_bonds)} bonds from "
            f"{len(new_orderbook.directory_nodes)} directory nodes"
        )

        return new_orderbook

    async def get_orderbook(self) -> OrderBook:
        async with self._lock:
            return self.current_orderbook

    async def _background_bond_calculator(self) -> None:
        while True:
            try:
                orderbook = await self._bond_queue.get()
                await self._calculate_bond_values(orderbook)
                for offer in orderbook.offers:
                    if offer.fidelity_bond_data:
                        matching_bonds = [
                            b
                            for b in orderbook.fidelity_bonds
                            if b.counterparty == offer.counterparty
                            and b.utxo_txid == offer.fidelity_bond_data.get("utxo_txid")
                        ]
                        if matching_bonds and matching_bonds[0].bond_value is not None:
                            offer.fidelity_bond_value = matching_bonds[0].bond_value
                logger.debug("Background bond calculation completed")
            except Exception as e:
                logger.error(f"Error in background bond calculator: {e}")

    async def _connect_to_node(self, onion_address: str, port: int) -> DirectoryClient | None:
        node_id = f"{onion_address}:{port}"
        status = self.node_statuses[node_id]
        status.connection_attempts += 1

        logger.info(f"Connecting to directory: {node_id}")

        def on_disconnect() -> None:
            logger.info(f"Directory node {node_id} disconnected")
            status.mark_disconnected()
            self._handle_client_disconnect(onion_address, port)

        client = DirectoryClient(
            onion_address,
            port,
            self.network,
            self.socks_host,
            self.socks_port,
            self.timeout,
            max_message_size=self.max_message_size,
            on_disconnect=on_disconnect,
        )

        try:
            await client.connect()
            status.mark_connected()
            logger.info(f"Successfully connected to directory: {node_id}")
            return client

        except Exception as e:
            logger.warning(f"Connection to directory {node_id} failed: {e}")
            await client.close()
            status.mark_disconnected()
            self._schedule_reconnect(onion_address, port)
            return None

    async def _retry_failed_connection(self, onion_address: str, port: int) -> None:
        node_id = f"{onion_address}:{port}"

        while True:
            await asyncio.sleep(60)

            if node_id in self.clients:
                logger.debug(f"Node {node_id} already connected, stopping retry")
                return

            logger.info(f"Retrying connection to directory {node_id}...")
            client = await self._connect_to_node(onion_address, port)

            if client:
                self.clients[node_id] = client
                task = asyncio.create_task(client.listen_continuously())
                self.listener_tasks.append(task)
                logger.info(f"Successfully reconnected to directory: {node_id}")
                return

    async def start_continuous_listening(self) -> None:
        logger.info("Starting continuous listening on all directory nodes")

        self._bond_calculation_task = asyncio.create_task(self._background_bond_calculator())

        if self.nostr_client:
            logger.info("Starting continuous Nostr listener")
            task = asyncio.create_task(self.nostr_client.listen_continuously())
            self.listener_tasks.append(task)

        connection_tasks = [
            self._connect_to_node(onion_address, port)
            for onion_address, port in self.directory_nodes
        ]

        clients = await asyncio.gather(*connection_tasks, return_exceptions=True)

        for (onion_address, port), result in zip(self.directory_nodes, clients, strict=True):
            node_id = f"{onion_address}:{port}"

            if isinstance(result, BaseException):
                logger.error(f"Connection to {node_id} raised exception: {result}")
                retry_task = asyncio.create_task(self._retry_failed_connection(onion_address, port))
                self._retry_tasks.append(retry_task)
                logger.info(f"Scheduled retry task for {node_id}")
            elif result is not None:
                self.clients[node_id] = result
                task = asyncio.create_task(result.listen_continuously())
                self.listener_tasks.append(task)
                logger.info(f"Started listener task for {node_id}")
            else:
                retry_task = asyncio.create_task(self._retry_failed_connection(onion_address, port))
                self._retry_tasks.append(retry_task)
                logger.info(f"Scheduled retry task for {node_id}")

    async def stop_listening(self) -> None:
        logger.info("Stopping all directory listeners")

        if self._bond_calculation_task:
            self._bond_calculation_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._bond_calculation_task

        for task in self._retry_tasks:
            task.cancel()

        if self._retry_tasks:
            await asyncio.gather(*self._retry_tasks, return_exceptions=True)

        for client in self.clients.values():
            client.stop()

        for task in self.listener_tasks:
            task.cancel()

        if self.listener_tasks:
            await asyncio.gather(*self.listener_tasks, return_exceptions=True)

        for node_id, client in self.clients.items():
            self.node_statuses[node_id].mark_disconnected()
            await client.close()

        self.clients.clear()
        self.listener_tasks.clear()
        self._retry_tasks.clear()

    async def get_live_orderbook(self, calculate_bonds: bool = True) -> OrderBook:
        orderbook = OrderBook(timestamp=datetime.utcnow())

        if self.nostr_client:
            offers = self.nostr_client.get_current_offers()
            bonds = self.nostr_client.get_current_bonds()
            if offers:
                logger.debug(f"Nostr: {len(offers)} offers, {len(bonds)} bonds")
                for offer in offers:
                    offer.directory_node = "nostr"
                orderbook.add_offers(offers, "nostr")
                orderbook.add_fidelity_bonds(bonds, "nostr")

        for node_id, client in self.clients.items():
            offers = client.get_current_offers()
            bonds = client.get_current_bonds()
            logger.debug(f"Node {node_id}: {len(offers)} offers, {len(bonds)} bonds")
            for offer in offers:
                offer.directory_node = node_id
            for bond in bonds:
                bond.directory_node = node_id
            orderbook.add_offers(offers, node_id)
            orderbook.add_fidelity_bonds(bonds, node_id)

        unique_bonds: dict[str, FidelityBond] = {}
        for bond in orderbook.fidelity_bonds:
            cache_key = f"{bond.utxo_txid}:{bond.utxo_vout}"
            if cache_key not in unique_bonds:
                unique_bonds[cache_key] = bond
        orderbook.fidelity_bonds = list(unique_bonds.values())

        if calculate_bonds:
            cached_count = 0
            for bond in orderbook.fidelity_bonds:
                cache_key = f"{bond.utxo_txid}:{bond.utxo_vout}"
                if cache_key in self._bond_cache:
                    cached_bond = self._bond_cache[cache_key]
                    bond.bond_value = cached_bond.bond_value
                    bond.amount = cached_bond.amount
                    bond.utxo_confirmation_timestamp = cached_bond.utxo_confirmation_timestamp
                    cached_count += 1

            if cached_count > 0:
                logger.debug(
                    f"Loaded {cached_count}/{len(orderbook.fidelity_bonds)} bonds from cache"
                )

            await self._calculate_bond_values(orderbook)

            for bond in orderbook.fidelity_bonds:
                if bond.bond_value is not None:
                    cache_key = f"{bond.utxo_txid}:{bond.utxo_vout}"
                    self._bond_cache[cache_key] = bond

            for offer in orderbook.offers:
                if offer.fidelity_bond_data:
                    matching_bonds = [
                        b
                        for b in orderbook.fidelity_bonds
                        if b.counterparty == offer.counterparty
                        and b.utxo_txid == offer.fidelity_bond_data.get("utxo_txid")
                    ]
                    if matching_bonds and matching_bonds[0].bond_value is not None:
                        offer.fidelity_bond_value = matching_bonds[0].bond_value

        return orderbook

    async def _calculate_bond_value_single(
        self, bond: FidelityBond, current_time: int
    ) -> FidelityBond:
        if bond.bond_value is not None:
            return bond

        async with self._mempool_semaphore:
            try:
                tx_data = await self.mempool_api.get_transaction(bond.utxo_txid)
                if not tx_data or not tx_data.status.confirmed:
                    logger.debug(f"Bond {bond.utxo_txid}:{bond.utxo_vout} not confirmed")
                    return bond

                if bond.utxo_vout >= len(tx_data.vout):
                    logger.warning(
                        f"Invalid vout {bond.utxo_vout} for tx {bond.utxo_txid} "
                        f"(only {len(tx_data.vout)} outputs)"
                    )
                    return bond

                utxo = tx_data.vout[bond.utxo_vout]
                amount = utxo.value
                confirmation_time = tx_data.status.block_time or current_time

                bond_value = calculate_timelocked_fidelity_bond_value(
                    amount, confirmation_time, bond.locktime, current_time
                )

                bond.bond_value = bond_value
                bond.amount = amount
                bond.utxo_confirmation_timestamp = confirmation_time

                logger.debug(
                    f"Bond {bond.counterparty}: value={bond_value}, "
                    f"amount={amount}, locktime={datetime.utcfromtimestamp(bond.locktime)}, "
                    f"confirmed={datetime.utcfromtimestamp(confirmation_time)}"
                )

            except Exception as e:
                logger.error(f"Failed to calculate bond value for {bond.utxo_txid}: {e}")
                logger.debug(
                    f"Bond data: txid={bond.utxo_txid}, vout={bond.utxo_vout}, amount={bond.amount}"
                )

        return bond

    async def _calculate_bond_values(self, orderbook: OrderBook) -> None:
        current_time = int(datetime.utcnow().timestamp())

        tasks = [
            self._calculate_bond_value_single(bond, current_time)
            for bond in orderbook.fidelity_bonds
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_socks_connection(self) -> None:
        """Test SOCKS proxy connection on startup."""
        try:
            success = await self.mempool_api.test_connection()
            if success:
                logger.info("SOCKS proxy connection test successful")
            else:
                logger.warning(
                    "SOCKS proxy connection test failed - bond value calculation may not work"
                )
        except Exception as e:
            logger.error(f"SOCKS proxy connection test error: {e}")
            logger.warning("Bond value calculation may not work without SOCKS proxy")
