"""
JoinMarket wallet service with mixdepth support.
"""

from __future__ import annotations

from loguru import logger

from jmwallet.backends.base import BlockchainBackend
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.models import UTXOInfo


class WalletService:
    """
    JoinMarket wallet service.
    Manages BIP84 hierarchical deterministic wallet with mixdepths.

    Derivation path: m/84'/0'/{mixdepth}'/{change}/{index}
    - mixdepth: 0-4 (JoinMarket isolation levels)
    - change: 0 (external/receive), 1 (internal/change)
    - index: address index
    """

    def __init__(
        self,
        mnemonic: str,
        backend: BlockchainBackend,
        network: str = "mainnet",
        mixdepth_count: int = 5,
        gap_limit: int = 20,
    ):
        self.mnemonic = mnemonic
        self.backend = backend
        self.network = network
        self.mixdepth_count = mixdepth_count
        self.gap_limit = gap_limit

        seed = mnemonic_to_seed(mnemonic)
        self.master_key = HDKey.from_seed(seed)

        coin_type = 0 if network == "mainnet" else 1
        self.root_path = f"m/84'/{coin_type}'"

        self.address_cache: dict[str, tuple[int, int, int]] = {}
        self.utxo_cache: dict[int, list[UTXOInfo]] = {}

        logger.info(f"Initialized wallet with {mixdepth_count} mixdepths")

    def get_address(self, mixdepth: int, change: int, index: int) -> str:
        """Get address for given path"""
        if mixdepth >= self.mixdepth_count:
            raise ValueError(f"Mixdepth {mixdepth} exceeds maximum {self.mixdepth_count}")

        path = f"{self.root_path}/{mixdepth}'/{change}/{index}"
        key = self.master_key.derive(path)
        address = key.get_address(self.network)

        self.address_cache[address] = (mixdepth, change, index)

        return address

    def get_receive_address(self, mixdepth: int, index: int) -> str:
        """Get external (receive) address"""
        return self.get_address(mixdepth, 0, index)

    def get_change_address(self, mixdepth: int, index: int) -> str:
        """Get internal (change) address"""
        return self.get_address(mixdepth, 1, index)

    def get_private_key(self, mixdepth: int, change: int, index: int) -> bytes:
        """Get private key for given path"""
        path = f"{self.root_path}/{mixdepth}'/{change}/{index}"
        key = self.master_key.derive(path)
        return key.get_private_key_bytes()

    def get_key_for_address(self, address: str) -> HDKey | None:
        """Get HD key for a known address"""
        if address not in self.address_cache:
            return None

        mixdepth, change, index = self.address_cache[address]
        path = f"{self.root_path}/{mixdepth}'/{change}/{index}"
        return self.master_key.derive(path)

    async def sync_mixdepth(self, mixdepth: int) -> list[UTXOInfo]:
        """
        Sync a mixdepth with the blockchain.
        Scans addresses up to gap limit.
        """
        utxos: list[UTXOInfo] = []

        for change in [0, 1]:
            consecutive_empty = 0
            index = 0

            while consecutive_empty < self.gap_limit:
                address = self.get_address(mixdepth, change, index)

                backend_utxos = await self.backend.get_utxos([address])

                if backend_utxos:
                    for utxo in backend_utxos:
                        path = f"{self.root_path}/{mixdepth}'/{change}/{index}"
                        utxo_info = UTXOInfo(
                            txid=utxo.txid,
                            vout=utxo.vout,
                            value=utxo.value,
                            address=address,
                            confirmations=utxo.confirmations,
                            scriptpubkey=utxo.scriptpubkey,
                            path=path,
                            mixdepth=mixdepth,
                        )
                        utxos.append(utxo_info)

                    consecutive_empty = 0
                else:
                    consecutive_empty += 1

                index += 1

            logger.debug(
                f"Synced mixdepth {mixdepth} change {change}: "
                f"scanned {index} addresses, found {len(utxos)} UTXOs"
            )

        self.utxo_cache[mixdepth] = utxos
        return utxos

    async def sync_all(self) -> dict[int, list[UTXOInfo]]:
        """Sync all mixdepths"""
        logger.info("Syncing all mixdepths...")
        result = {}
        for mixdepth in range(self.mixdepth_count):
            utxos = await self.sync_mixdepth(mixdepth)
            result[mixdepth] = utxos
        logger.info(f"Sync complete: {sum(len(u) for u in result.values())} total UTXOs")
        return result

    async def get_balance(self, mixdepth: int) -> int:
        """Get balance for a mixdepth"""
        if mixdepth not in self.utxo_cache:
            await self.sync_mixdepth(mixdepth)

        utxos = self.utxo_cache.get(mixdepth, [])
        return sum(utxo.value for utxo in utxos)

    async def get_total_balance(self) -> int:
        """Get total balance across all mixdepths"""
        total = 0
        for mixdepth in range(self.mixdepth_count):
            balance = await self.get_balance(mixdepth)
            total += balance
        return total

    def select_utxos(
        self, mixdepth: int, target_amount: int, min_confirmations: int = 1
    ) -> list[UTXOInfo]:
        """
        Select UTXOs for spending from a mixdepth.
        Uses simple greedy selection strategy.
        """
        utxos = self.utxo_cache.get(mixdepth, [])

        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]

        eligible.sort(key=lambda u: u.value, reverse=True)

        selected = []
        total = 0

        for utxo in eligible:
            selected.append(utxo)
            total += utxo.value
            if total >= target_amount:
                break

        if total < target_amount:
            raise ValueError(f"Insufficient funds: need {target_amount}, have {total}")

        return selected

    def get_next_address_index(self, mixdepth: int, change: int) -> int:
        """Get next unused address index for mixdepth/change"""
        max_index = -1

        for address, (md, ch, idx) in self.address_cache.items():
            if md == mixdepth and ch == change:
                if idx > max_index:
                    max_index = idx

        utxos = self.utxo_cache.get(mixdepth, [])
        for utxo in utxos:
            if utxo.address in self.address_cache:
                md, ch, idx = self.address_cache[utxo.address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        return max_index + 1

    async def close(self) -> None:
        """Close backend connection"""
        await self.backend.close()
