"""
Base blockchain backend interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class UTXO:
    txid: str
    vout: int
    value: int
    address: str
    confirmations: int
    scriptpubkey: str
    height: int | None = None


@dataclass
class Transaction:
    txid: str
    raw: str
    confirmations: int
    block_height: int | None = None
    block_time: int | None = None


class BlockchainBackend(ABC):
    """
    Abstract blockchain backend interface.
    Implementations provide access to blockchain data without requiring
    Bitcoin Core wallet functionality (avoiding BerkeleyDB issues).
    """

    @abstractmethod
    async def get_utxos(self, addresses: list[str]) -> list[UTXO]:
        """Get UTXOs for given addresses"""

    @abstractmethod
    async def get_address_balance(self, address: str) -> int:
        """Get balance for an address in satoshis"""

    @abstractmethod
    async def broadcast_transaction(self, tx_hex: str) -> str:
        """Broadcast transaction, returns txid"""

    @abstractmethod
    async def get_transaction(self, txid: str) -> Transaction | None:
        """Get transaction by txid"""

    @abstractmethod
    async def estimate_fee(self, target_blocks: int) -> int:
        """Estimate fee in sat/vbyte for target confirmation blocks"""

    @abstractmethod
    async def get_block_height(self) -> int:
        """Get current blockchain height"""

    @abstractmethod
    async def get_block_time(self, block_height: int) -> int:
        """Get block time (unix timestamp) for given height"""

    @abstractmethod
    async def get_block_hash(self, block_height: int) -> str:
        """Get block hash for given height"""
