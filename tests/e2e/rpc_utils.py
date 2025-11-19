"""
Helpers for interacting with local Bitcoin Core regtest node.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from loguru import logger

BITCOIN_RPC_URL = os.getenv("BITCOIN_RPC_URL", "http://127.0.0.1:18443")
BITCOIN_RPC_USER = os.getenv("BITCOIN_RPC_USER", "test")
BITCOIN_RPC_PASSWORD = os.getenv("BITCOIN_RPC_PASSWORD", "test")
BITCOIN_RPC_WALLET = os.getenv("BITCOIN_RPC_WALLET", "jm-e2e-test")


class BitcoinRPCError(Exception):
    pass


async def rpc_call(
    method: str, params: list[Any] | None = None, wallet: str | None = None
) -> Any:
    url = BITCOIN_RPC_URL.rstrip("/")
    if wallet:
        url = f"{url}/wallet/{wallet}"

    payload = {
        "jsonrpc": "1.0",
        "id": "jm-tests",
        "method": method,
        "params": params or [],
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            url, auth=(BITCOIN_RPC_USER, BITCOIN_RPC_PASSWORD), json=payload
        )

    data = response.json()
    if data.get("error"):
        raise BitcoinRPCError(data["error"])
    return data.get("result")


async def ensure_test_wallet() -> str:
    try:
        wallets = await rpc_call("listwallets")
        if BITCOIN_RPC_WALLET in wallets:
            return BITCOIN_RPC_WALLET
    except BitcoinRPCError:
        pass

    try:
        await rpc_call("loadwallet", [BITCOIN_RPC_WALLET])
    except BitcoinRPCError as exc:
        error_message = str(exc)
        if "not found" in error_message.lower():
            await rpc_call("createwallet", [BITCOIN_RPC_WALLET])
        elif "already loaded" not in error_message.lower():
            raise

    return BITCOIN_RPC_WALLET


async def get_new_address(wallet: str | None = None) -> str:
    wallet_name = wallet or await ensure_test_wallet()
    return await rpc_call("getnewaddress", [], wallet=wallet_name)


async def send_to_address(
    address: str, amount_btc: float, wallet: str | None = None
) -> str:
    wallet_name = wallet or await ensure_test_wallet()
    txid = await rpc_call("sendtoaddress", [address, amount_btc], wallet=wallet_name)
    logger.info(f"Sent {amount_btc} BTC to {address}, txid={txid}")
    return txid


async def mine_blocks(blocks: int, address: str | None = None) -> None:
    mining_address = address or await get_new_address()
    await rpc_call("generatetoaddress", [blocks, mining_address])


async def ensure_wallet_funded(
    target_address: str, amount_btc: float = 1.0, confirmations: int = 1
) -> bool:
    try:
        await ensure_test_wallet()
        await send_to_address(target_address, amount_btc)
        await mine_blocks(max(1, confirmations))
        return True
    except BitcoinRPCError as exc:
        logger.warning(f"Failed to auto-fund wallet: {exc}")
        return False
