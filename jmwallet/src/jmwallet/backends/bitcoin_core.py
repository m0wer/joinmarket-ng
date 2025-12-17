"""
Bitcoin Core RPC blockchain backend.
Uses RPC calls but NOT wallet functionality (no BDB dependency).
"""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from jmwallet.backends.base import UTXO, BlockchainBackend, Transaction


class BitcoinCoreBackend(BlockchainBackend):
    """
    Blockchain backend using Bitcoin Core RPC.
    Does NOT use Bitcoin Core wallet (avoids BDB issues).
    Uses scantxoutset and other non-wallet RPC methods.
    """

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:18443",
        rpc_user: str = "rpcuser",
        rpc_password: str = "rpcpassword",
    ):
        self.rpc_url = rpc_url.rstrip("/")
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.client = httpx.AsyncClient(timeout=30.0, auth=(rpc_user, rpc_password))
        self._request_id = 0

    async def _rpc_call(self, method: str, params: list | None = None) -> Any:
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or [],
        }

        try:
            response = await self.client.post(self.rpc_url, json=payload)
            response.raise_for_status()
            data = response.json()

            if "error" in data and data["error"]:
                raise ValueError(f"RPC error: {data['error']}")

            return data.get("result")

        except httpx.HTTPError as e:
            logger.error(f"RPC call failed: {method} - {e}")
            raise

    async def get_utxos(self, addresses: list[str]) -> list[UTXO]:
        utxos: list[UTXO] = []
        if not addresses:
            return utxos

        # Get tip height once for confirmation calculation
        try:
            tip_height = await self.get_block_height()
        except Exception as e:
            logger.error(f"Failed to get block height for UTXO scan: {e}")
            return utxos

        # Process in batches to avoid huge RPC requests
        batch_size = 100
        for i in range(0, len(addresses), batch_size):
            chunk = addresses[i : i + batch_size]
            descriptors = [f"addr({addr})" for addr in chunk]

            try:
                # Scan for all addresses in this chunk at once
                result = await self._rpc_call("scantxoutset", ["start", descriptors])

                if not result or "unspents" not in result:
                    continue

                for utxo_data in result["unspents"]:
                    confirmations = 0
                    if utxo_data.get("height", 0) > 0:
                        confirmations = tip_height - utxo_data["height"] + 1

                    # Extract address from descriptor "addr(ADDRESS)#checksum" or "addr(ADDRESS)"
                    desc = utxo_data.get("desc", "")
                    # Remove checksum if present
                    if "#" in desc:
                        desc = desc.split("#")[0]

                    address = ""
                    if desc.startswith("addr(") and desc.endswith(")"):
                        address = desc[5:-1]
                    else:
                        # Only log warning if we really can't parse it (and it's not empty)
                        if desc:
                            logger.warning(f"Failed to parse address from descriptor: '{desc}'")

                    utxo = UTXO(
                        txid=utxo_data["txid"],
                        vout=utxo_data["vout"],
                        value=int(utxo_data["amount"] * 100_000_000),
                        address=address,
                        confirmations=confirmations,
                        scriptpubkey=utxo_data.get("scriptPubKey", ""),
                        height=utxo_data.get("height"),
                    )
                    utxos.append(utxo)

                logger.debug(
                    f"Scanned {len(chunk)} addresses, found {len(result['unspents'])} UTXOs"
                )

            except Exception as e:
                logger.warning(f"Failed to scan UTXOs for batch starting {chunk[0]}: {e}")
                continue

        return utxos

    async def get_address_balance(self, address: str) -> int:
        utxos = await self.get_utxos([address])
        balance = sum(utxo.value for utxo in utxos)
        logger.debug(f"Balance for {address}: {balance} sats")
        return balance

    async def broadcast_transaction(self, tx_hex: str) -> str:
        try:
            txid = await self._rpc_call("sendrawtransaction", [tx_hex])
            logger.info(f"Broadcast transaction: {txid}")
            return txid

        except Exception as e:
            logger.error(f"Failed to broadcast transaction: {e}")
            raise ValueError(f"Broadcast failed: {e}") from e

    async def get_transaction(self, txid: str) -> Transaction | None:
        try:
            tx_data = await self._rpc_call("getrawtransaction", [txid, True])

            if not tx_data:
                return None

            confirmations = tx_data.get("confirmations", 0)
            block_height = None
            block_time = None

            if "blockhash" in tx_data:
                block_info = await self._rpc_call("getblockheader", [tx_data["blockhash"]])
                block_height = block_info.get("height")
                block_time = block_info.get("time")

            raw_hex = tx_data.get("hex", "")

            return Transaction(
                txid=txid,
                raw=raw_hex,
                confirmations=confirmations,
                block_height=block_height,
                block_time=block_time,
            )

        except Exception as e:
            logger.warning(f"Failed to fetch transaction {txid}: {e}")
            return None

    async def estimate_fee(self, target_blocks: int) -> int:
        try:
            result = await self._rpc_call("estimatesmartfee", [target_blocks])

            if "feerate" in result:
                btc_per_kb = result["feerate"]
                sat_per_vbyte = int((btc_per_kb * 100_000_000) / 1000)
                logger.debug(f"Estimated fee for {target_blocks} blocks: {sat_per_vbyte} sat/vB")
                return sat_per_vbyte
            else:
                logger.warning("Fee estimation unavailable, using fallback")
                return 10

        except Exception as e:
            logger.warning(f"Failed to estimate fee: {e}, using fallback")
            return 10

    async def get_block_height(self) -> int:
        try:
            info = await self._rpc_call("getblockchaininfo", [])
            height = info.get("blocks", 0)
            logger.debug(f"Current block height: {height}")
            return height

        except Exception as e:
            logger.error(f"Failed to fetch block height: {e}")
            raise

    async def get_block_time(self, block_height: int) -> int:
        try:
            block_hash = await self.get_block_hash(block_height)
            block_header = await self._rpc_call("getblockheader", [block_hash])
            timestamp = block_header.get("time", 0)
            logger.debug(f"Block {block_height} timestamp: {timestamp}")
            return timestamp

        except Exception as e:
            logger.error(f"Failed to fetch block time for height {block_height}: {e}")
            raise

    async def get_block_hash(self, block_height: int) -> str:
        try:
            block_hash = await self._rpc_call("getblockhash", [block_height])
            logger.debug(f"Block hash for height {block_height}: {block_hash}")
            return block_hash

        except Exception as e:
            logger.error(f"Failed to fetch block hash for height {block_height}: {e}")
            raise

    async def get_utxo(self, txid: str, vout: int) -> UTXO | None:
        """Get a specific UTXO from the blockchain UTXO set using gettxout.
        Returns None if the UTXO does not exist or has been spent."""
        try:
            # gettxout returns None if UTXO doesn't exist or is spent
            result = await self._rpc_call("gettxout", [txid, vout, True])

            if result is None:
                logger.debug(f"UTXO {txid}:{vout} not found in UTXO set")
                return None

            # Get tip height for confirmation calculation
            tip_height = await self.get_block_height()

            confirmations = result.get("confirmations", 0)
            value = int(result.get("value", 0) * 100_000_000)  # BTC to sats

            # Extract address from scriptPubKey
            script_pub_key = result.get("scriptPubKey", {})
            address = script_pub_key.get("address", "")
            scriptpubkey = script_pub_key.get("hex", "")

            # Calculate height from confirmations
            height = None
            if confirmations > 0:
                height = tip_height - confirmations + 1

            return UTXO(
                txid=txid,
                vout=vout,
                value=value,
                address=address,
                confirmations=confirmations,
                scriptpubkey=scriptpubkey,
                height=height,
            )

        except Exception as e:
            logger.error(f"Failed to get UTXO {txid}:{vout}: {e}")
            return None

    async def close(self) -> None:
        await self.client.aclose()
