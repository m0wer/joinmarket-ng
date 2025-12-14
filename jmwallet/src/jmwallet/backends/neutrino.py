"""
Neutrino (BIP157/BIP158) light client blockchain backend.

Lightweight alternative to running a full Bitcoin node.
Uses compact block filters for privacy-preserving SPV operation.

The Neutrino client runs as a separate Go process and communicates via gRPC.
This backend wraps the neutrino gRPC API for the JoinMarket wallet.

Reference: https://github.com/lightninglabs/neutrino
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from loguru import logger

from jmwallet.backends.base import UTXO, BlockchainBackend, Transaction


class NeutrinoBackend(BlockchainBackend):
    """
    Blockchain backend using Neutrino light client.

    Neutrino is a privacy-preserving Bitcoin light client that uses
    BIP157/BIP158 compact block filters instead of traditional SPV.

    Communication with the neutrino daemon is via REST API.
    The neutrino daemon should be running alongside this client.
    """

    def __init__(
        self,
        neutrino_url: str = "http://127.0.0.1:8334",
        network: str = "mainnet",
        connect_peers: list[str] | None = None,
        data_dir: str = "/data/neutrino",
    ):
        """
        Initialize Neutrino backend.

        Args:
            neutrino_url: URL of the neutrino REST API (default port 8334)
            network: Bitcoin network (mainnet, testnet, regtest, signet)
            connect_peers: List of peer addresses to connect to (optional)
            data_dir: Directory for neutrino data (headers, filters)
        """
        self.neutrino_url = neutrino_url.rstrip("/")
        self.network = network
        self.connect_peers = connect_peers or []
        self.data_dir = data_dir
        self.client = httpx.AsyncClient(timeout=60.0)

        # Cache for watched addresses (neutrino needs to know what to scan for)
        self._watched_addresses: set[str] = set()
        self._watched_outpoints: set[tuple[str, int]] = set()

        # Block filter cache
        self._filter_header_tip: int = 0
        self._synced: bool = False

    async def _api_call(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        """Make an API call to the neutrino daemon."""
        url = f"{self.neutrino_url}/{endpoint}"

        try:
            if method == "GET":
                response = await self.client.get(url, params=params)
            elif method == "POST":
                response = await self.client.post(url, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()

        except httpx.HTTPError as e:
            logger.error(f"Neutrino API call failed: {endpoint} - {e}")
            raise

    async def wait_for_sync(self, timeout: float = 300.0) -> bool:
        """
        Wait for neutrino to sync block headers and filters.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if synced, False if timeout
        """
        start_time = asyncio.get_event_loop().time()

        while True:
            try:
                status = await self._api_call("GET", "v1/status")
                synced = status.get("synced", False)
                block_height = status.get("block_height", 0)
                filter_height = status.get("filter_height", 0)

                if synced and block_height == filter_height:
                    self._synced = True
                    self._filter_header_tip = block_height
                    logger.info(f"Neutrino synced at height {block_height}")
                    return True

                logger.debug(f"Syncing... blocks: {block_height}, filters: {filter_height}")

            except Exception as e:
                logger.warning(f"Waiting for neutrino daemon: {e}")

            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                logger.error("Neutrino sync timeout")
                return False

            await asyncio.sleep(2.0)

    async def add_watch_address(self, address: str) -> None:
        """
        Add an address to watch for relevant transactions.

        Neutrino uses compact block filters to check if blocks might
        contain transactions for watched addresses.

        Args:
            address: Bitcoin address to watch
        """
        if address in self._watched_addresses:
            return

        try:
            await self._api_call(
                "POST",
                "v1/watch/address",
                data={"address": address},
            )
            self._watched_addresses.add(address)
            logger.debug(f"Watching address: {address}")

        except Exception as e:
            logger.warning(f"Failed to watch address {address}: {e}")

    async def add_watch_outpoint(self, txid: str, vout: int) -> None:
        """
        Add an outpoint to watch for spending.

        Args:
            txid: Transaction ID
            vout: Output index
        """
        outpoint = (txid, vout)
        if outpoint in self._watched_outpoints:
            return

        try:
            await self._api_call(
                "POST",
                "v1/watch/outpoint",
                data={"txid": txid, "vout": vout},
            )
            self._watched_outpoints.add(outpoint)
            logger.debug(f"Watching outpoint: {txid}:{vout}")

        except Exception as e:
            logger.warning(f"Failed to watch outpoint {txid}:{vout}: {e}")

    async def get_utxos(self, addresses: list[str]) -> list[UTXO]:
        """
        Get UTXOs for given addresses using neutrino's rescan capability.

        Neutrino will scan the blockchain using compact block filters
        to find transactions relevant to the watched addresses.
        """
        utxos: list[UTXO] = []

        # Add addresses to watch list
        for address in addresses:
            await self.add_watch_address(address)

        # Wait a moment for filter matching to complete
        await asyncio.sleep(0.5)

        try:
            # Request UTXO scan for addresses
            result = await self._api_call(
                "POST",
                "v1/utxos",
                data={"addresses": addresses},
            )

            tip_height = await self.get_block_height()

            for utxo_data in result.get("utxos", []):
                height = utxo_data.get("height", 0)
                confirmations = 0
                if height > 0:
                    confirmations = tip_height - height + 1

                utxo = UTXO(
                    txid=utxo_data["txid"],
                    vout=utxo_data["vout"],
                    value=utxo_data["value"],
                    address=utxo_data.get("address", ""),
                    confirmations=confirmations,
                    scriptpubkey=utxo_data.get("scriptpubkey", ""),
                    height=height if height > 0 else None,
                )
                utxos.append(utxo)

            logger.debug(f"Found {len(utxos)} UTXOs for {len(addresses)} addresses")

        except Exception as e:
            logger.error(f"Failed to fetch UTXOs: {e}")

        return utxos

    async def get_address_balance(self, address: str) -> int:
        """Get balance for an address in satoshis."""
        utxos = await self.get_utxos([address])
        balance = sum(utxo.value for utxo in utxos)
        logger.debug(f"Balance for {address}: {balance} sats")
        return balance

    async def broadcast_transaction(self, tx_hex: str) -> str:
        """
        Broadcast transaction via neutrino to the P2P network.

        Neutrino maintains P2P connections and can broadcast transactions
        directly to connected peers.
        """
        try:
            result = await self._api_call(
                "POST",
                "v1/tx/broadcast",
                data={"tx_hex": tx_hex},
            )
            txid = result.get("txid", "")
            logger.info(f"Broadcast transaction: {txid}")
            return txid

        except Exception as e:
            logger.error(f"Failed to broadcast transaction: {e}")
            raise ValueError(f"Broadcast failed: {e}") from e

    async def get_transaction(self, txid: str) -> Transaction | None:
        """
        Get transaction by txid.

        Neutrino fetches full blocks when needed (for relevant transactions).
        """
        try:
            result = await self._api_call(
                "GET",
                f"v1/tx/{txid}",
            )

            if not result or "txid" not in result:
                return None

            tip_height = await self.get_block_height()
            block_height = result.get("block_height")
            confirmations = 0

            if block_height and block_height > 0:
                confirmations = tip_height - block_height + 1

            return Transaction(
                txid=result["txid"],
                raw=result.get("hex", ""),
                confirmations=confirmations,
                block_height=block_height,
                block_time=result.get("block_time"),
            )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.warning(f"Failed to fetch transaction {txid}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to fetch transaction {txid}: {e}")
            return None

    async def estimate_fee(self, target_blocks: int) -> int:
        """
        Estimate fee in sat/vbyte for target confirmation blocks.

        Neutrino can estimate fees based on observed mempool/block data.
        Falls back to reasonable defaults if estimation unavailable.
        """
        try:
            result = await self._api_call(
                "GET",
                "v1/fees/estimate",
                params={"target_blocks": target_blocks},
            )

            fee_rate = result.get("fee_rate", 0)
            if fee_rate > 0:
                logger.debug(f"Estimated fee for {target_blocks} blocks: {fee_rate} sat/vB")
                return int(fee_rate)

        except Exception as e:
            logger.warning(f"Fee estimation failed: {e}")

        # Fallback fee rates based on target
        if target_blocks <= 1:
            return 20
        elif target_blocks <= 3:
            return 10
        elif target_blocks <= 6:
            return 5
        else:
            return 2

    async def get_block_height(self) -> int:
        """Get current blockchain height from neutrino."""
        try:
            result = await self._api_call("GET", "v1/status")
            height = result.get("block_height", 0)
            logger.debug(f"Current block height: {height}")
            return height

        except Exception as e:
            logger.error(f"Failed to fetch block height: {e}")
            raise

    async def get_block_time(self, block_height: int) -> int:
        """Get block time (unix timestamp) for given height."""
        try:
            result = await self._api_call(
                "GET",
                f"v1/block/{block_height}/header",
            )
            timestamp = result.get("timestamp", 0)
            logger.debug(f"Block {block_height} timestamp: {timestamp}")
            return timestamp

        except Exception as e:
            logger.error(f"Failed to fetch block time for height {block_height}: {e}")
            raise

    async def get_block_hash(self, block_height: int) -> str:
        """Get block hash for given height."""
        try:
            result = await self._api_call(
                "GET",
                f"v1/block/{block_height}/header",
            )
            block_hash = result.get("hash", "")
            logger.debug(f"Block hash for height {block_height}: {block_hash}")
            return block_hash

        except Exception as e:
            logger.error(f"Failed to fetch block hash for height {block_height}: {e}")
            raise

    async def get_filter_header(self, block_height: int) -> str:
        """
        Get compact block filter header for given height.

        BIP157 filter headers form a chain for validation.
        """
        try:
            result = await self._api_call(
                "GET",
                f"v1/block/{block_height}/filter_header",
            )
            return result.get("filter_header", "")

        except Exception as e:
            logger.error(f"Failed to fetch filter header for height {block_height}: {e}")
            raise

    async def get_connected_peers(self) -> list[dict[str, Any]]:
        """Get list of connected P2P peers."""
        try:
            result = await self._api_call("GET", "v1/peers")
            return result.get("peers", [])

        except Exception as e:
            logger.warning(f"Failed to fetch peers: {e}")
            return []

    async def rescan_from_height(
        self,
        start_height: int,
        addresses: list[str] | None = None,
        outpoints: list[tuple[str, int]] | None = None,
    ) -> None:
        """
        Rescan blockchain from a specific height for addresses/outpoints.

        This triggers neutrino to re-check compact block filters from
        the specified height for relevant transactions.

        Args:
            start_height: Block height to start rescan from
            addresses: List of addresses to scan for (optional)
            outpoints: List of (txid, vout) outpoints to scan for (optional)
        """
        # Add items to watch first
        if addresses:
            for addr in addresses:
                await self.add_watch_address(addr)

        if outpoints:
            for txid, vout in outpoints:
                await self.add_watch_outpoint(txid, vout)

        try:
            await self._api_call(
                "POST",
                "v1/rescan",
                data={
                    "start_height": start_height,
                    "addresses": addresses or [],
                    "outpoints": [{"txid": txid, "vout": vout} for txid, vout in (outpoints or [])],
                },
            )
            logger.info(f"Started rescan from height {start_height}")

        except Exception as e:
            logger.error(f"Failed to start rescan: {e}")
            raise

    async def close(self) -> None:
        """Close the HTTP client connection."""
        await self.client.aclose()


class NeutrinoConfig:
    """
    Configuration for running a neutrino daemon.

    This configuration can be used to start a neutrino process
    programmatically or generate a config file.
    """

    def __init__(
        self,
        network: str = "mainnet",
        data_dir: str = "/data/neutrino",
        listen_port: int = 8334,
        peers: list[str] | None = None,
        tor_socks: str | None = None,
    ):
        """
        Initialize neutrino configuration.

        Args:
            network: Bitcoin network (mainnet, testnet, regtest, signet)
            data_dir: Directory for neutrino data
            listen_port: Port for REST API
            peers: List of peer addresses to connect to
            tor_socks: Tor SOCKS5 proxy address (e.g., "127.0.0.1:9050")
        """
        self.network = network
        self.data_dir = data_dir
        self.listen_port = listen_port
        self.peers = peers or []
        self.tor_socks = tor_socks

    def get_chain_params(self) -> dict[str, Any]:
        """Get chain-specific parameters."""
        params = {
            "mainnet": {
                "default_port": 8333,
                "dns_seeds": [
                    "seed.bitcoin.sipa.be",
                    "dnsseed.bluematt.me",
                    "dnsseed.bitcoin.dashjr.org",
                    "seed.bitcoinstats.com",
                    "seed.bitcoin.jonasschnelli.ch",
                    "seed.btc.petertodd.net",
                ],
            },
            "testnet": {
                "default_port": 18333,
                "dns_seeds": [
                    "testnet-seed.bitcoin.jonasschnelli.ch",
                    "seed.tbtc.petertodd.net",
                    "testnet-seed.bluematt.me",
                ],
            },
            "signet": {
                "default_port": 38333,
                "dns_seeds": [
                    "seed.signet.bitcoin.sprovoost.nl",
                ],
            },
            "regtest": {
                "default_port": 18444,
                "dns_seeds": [],
            },
        }
        return params.get(self.network, params["mainnet"])

    def to_args(self) -> list[str]:
        """Generate command-line arguments for neutrino daemon."""
        args = [
            f"--datadir={self.data_dir}",
            f"--{self.network}",
            f"--restlisten=0.0.0.0:{self.listen_port}",
        ]

        if self.tor_socks:
            args.append(f"--proxy={self.tor_socks}")

        for peer in self.peers:
            args.append(f"--connect={peer}")

        return args
