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


async def mine_blocks(blocks: int, address: str) -> None:
    """
    Mine blocks to a specific address.

    We avoid using wallet RPC completely - the wallet is external to Bitcoin Core.
    """
    await rpc_call("generatetoaddress", [blocks, address])
    logger.info(f"Mined {blocks} blocks to {address}")


async def ensure_wallet_funded(
    target_address: str, amount_btc: float = 1.0, confirmations: int = 1
) -> bool:
    """
    Fund a wallet address by mining blocks directly to it.

    We avoid wallet RPC completely - Bitcoin Core is just a source of truth,
    not for managing funds. The wallet is completely external.

    On regtest, each mined block gives 50 BTC reward.
    We mine 110 blocks for coinbase maturity + confirmations.

    Args:
        target_address: Address to fund
        amount_btc: Amount needed (ignored, we just mine blocks)
        confirmations: Additional confirmations needed

    Returns:
        True if successful, False otherwise
    """
    try:
        # Mine directly to target address
        # 110 blocks for coinbase maturity + confirmations
        blocks_to_mine = 110 + confirmations
        logger.info(f"Mining {blocks_to_mine} blocks directly to {target_address}")
        await rpc_call("generatetoaddress", [blocks_to_mine, target_address])
        logger.info(
            f"Mined {blocks_to_mine} blocks (110 for maturity + {confirmations} confirmations)"
        )
        logger.info(
            f"Funded address with {blocks_to_mine * 50} BTC from coinbase rewards"
        )
        return True
    except BitcoinRPCError as exc:
        logger.error(f"Failed to auto-fund wallet: {exc}")
        return False
    except Exception as exc:
        logger.error(f"Unexpected error during auto-funding: {exc}")
        return False
