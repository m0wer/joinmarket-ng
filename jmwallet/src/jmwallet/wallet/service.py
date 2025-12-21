"""
JoinMarket wallet service with mixdepth support.
"""

from __future__ import annotations

from jmcore.btc_script import mk_freeze_script
from loguru import logger

from jmwallet.backends.base import BlockchainBackend
from jmwallet.wallet.address import script_to_p2wsh_address
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.models import UTXOInfo

# Fidelity bond constants
FIDELITY_BOND_BRANCH = 2  # Internal branch for fidelity bonds


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

    def get_fidelity_bond_key(self, index: int, locktime: int) -> HDKey:
        """
        Get the HD key for a fidelity bond.

        Fidelity bond path: m/84'/coin'/0'/2/index
        The locktime is NOT in the derivation path, but stored separately.

        Args:
            index: Address index within the fidelity bond branch
            locktime: Unix timestamp for the timelock (stored in path notation as :locktime)

        Returns:
            HDKey for the fidelity bond
        """
        # Fidelity bonds always use mixdepth 0, branch 2
        path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index}"
        return self.master_key.derive(path)

    def get_fidelity_bond_address(self, index: int, locktime: int) -> str:
        """
        Get a fidelity bond P2WSH address.

        Creates a timelocked script: <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG
        wrapped in P2WSH.

        Args:
            index: Address index within the fidelity bond branch
            locktime: Unix timestamp for the timelock

        Returns:
            P2WSH address for the fidelity bond
        """
        key = self.get_fidelity_bond_key(index, locktime)
        pubkey_hex = key.get_public_key_bytes(compressed=True).hex()

        # Create the timelock script
        script = mk_freeze_script(pubkey_hex, locktime)

        # Convert to P2WSH address
        address = script_to_p2wsh_address(script, self.network)

        # Cache with special path notation including locktime
        # Path format: m/84'/coin'/0'/2/index:locktime
        self.address_cache[address] = (0, FIDELITY_BOND_BRANCH, index)
        # Also store the locktime in a separate cache for fidelity bonds
        if not hasattr(self, "fidelity_bond_locktime_cache"):
            self.fidelity_bond_locktime_cache: dict[str, int] = {}
        self.fidelity_bond_locktime_cache[address] = locktime

        logger.debug(f"Created fidelity bond address {address} with locktime {locktime}")
        return address

    def get_fidelity_bond_script(self, index: int, locktime: int) -> bytes:
        """
        Get the redeem script for a fidelity bond.

        Args:
            index: Address index within the fidelity bond branch
            locktime: Unix timestamp for the timelock

        Returns:
            Timelock redeem script bytes
        """
        key = self.get_fidelity_bond_key(index, locktime)
        pubkey_hex = key.get_public_key_bytes(compressed=True).hex()
        return mk_freeze_script(pubkey_hex, locktime)

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
                # Scan in batches of gap_limit size for performance
                batch_size = self.gap_limit
                addresses = []

                for i in range(batch_size):
                    address = self.get_address(mixdepth, change, index + i)
                    addresses.append(address)

                # Fetch UTXOs for the whole batch
                backend_utxos = await self.backend.get_utxos(addresses)

                # Group results by address
                utxos_by_address: dict[str, list] = {addr: [] for addr in addresses}
                for utxo in backend_utxos:
                    if utxo.address in utxos_by_address:
                        utxos_by_address[utxo.address].append(utxo)

                # Process batch results in order
                for i, address in enumerate(addresses):
                    addr_utxos = utxos_by_address[address]

                    if addr_utxos:
                        consecutive_empty = 0
                        for utxo in addr_utxos:
                            path = f"{self.root_path}/{mixdepth}'/{change}/{index + i}"
                            utxo_info = UTXOInfo(
                                txid=utxo.txid,
                                vout=utxo.vout,
                                value=utxo.value,
                                address=address,
                                confirmations=utxo.confirmations,
                                scriptpubkey=utxo.scriptpubkey,
                                path=path,
                                mixdepth=mixdepth,
                                height=utxo.height,
                            )
                            utxos.append(utxo_info)
                    else:
                        consecutive_empty += 1

                    if consecutive_empty >= self.gap_limit:
                        break

                index += batch_size

            logger.debug(
                f"Synced mixdepth {mixdepth} change {change}: "
                f"scanned ~{index} addresses, found "
                f"{len([u for u in utxos if u.path.split('/')[-2] == str(change)])} UTXOs"
            )

        self.utxo_cache[mixdepth] = utxos
        return utxos

    async def sync_fidelity_bonds(self, locktimes: list[int]) -> list[UTXOInfo]:
        """
        Sync fidelity bond UTXOs with specific locktimes.

        Fidelity bonds use mixdepth 0, branch 2, with path format:
        m/84'/coin'/0'/2/index:locktime

        Args:
            locktimes: List of Unix timestamps to scan for

        Returns:
            List of fidelity bond UTXOs found
        """
        utxos: list[UTXOInfo] = []

        if not locktimes:
            logger.debug("No locktimes provided for fidelity bond sync")
            return utxos

        for locktime in locktimes:
            consecutive_empty = 0
            index = 0

            while consecutive_empty < self.gap_limit:
                # Generate addresses for this locktime
                addresses = []
                for i in range(self.gap_limit):
                    address = self.get_fidelity_bond_address(index + i, locktime)
                    addresses.append(address)

                # Fetch UTXOs
                backend_utxos = await self.backend.get_utxos(addresses)

                # Group by address
                utxos_by_address: dict[str, list] = {addr: [] for addr in addresses}
                for utxo in backend_utxos:
                    if utxo.address in utxos_by_address:
                        utxos_by_address[utxo.address].append(utxo)

                # Process results
                for i, address in enumerate(addresses):
                    addr_utxos = utxos_by_address[address]

                    if addr_utxos:
                        consecutive_empty = 0
                        for utxo in addr_utxos:
                            # Path includes locktime notation
                            path = (
                                f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index + i}:{locktime}"
                            )
                            utxo_info = UTXOInfo(
                                txid=utxo.txid,
                                vout=utxo.vout,
                                value=utxo.value,
                                address=address,
                                confirmations=utxo.confirmations,
                                scriptpubkey=utxo.scriptpubkey,
                                path=path,
                                mixdepth=0,  # Fidelity bonds always in mixdepth 0
                                height=utxo.height,
                            )
                            utxos.append(utxo_info)
                            logger.info(
                                f"Found fidelity bond UTXO: {utxo.txid}:{utxo.vout} "
                                f"value={utxo.value} locktime={locktime}"
                            )
                    else:
                        consecutive_empty += 1

                    if consecutive_empty >= self.gap_limit:
                        break

                index += self.gap_limit

        # Add fidelity bond UTXOs to mixdepth 0 cache
        if utxos:
            if 0 not in self.utxo_cache:
                self.utxo_cache[0] = []
            self.utxo_cache[0].extend(utxos)
            logger.info(f"Found {len(utxos)} fidelity bond UTXOs")

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

    async def get_utxos(self, mixdepth: int) -> list[UTXOInfo]:
        """Get UTXOs for a mixdepth, syncing if not cached."""
        if mixdepth not in self.utxo_cache:
            await self.sync_mixdepth(mixdepth)
        return self.utxo_cache.get(mixdepth, [])

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

    async def sync(self) -> dict[int, list[UTXOInfo]]:
        """Sync wallet (alias for sync_all for backward compatibility)."""
        return await self.sync_all()

    def get_new_address(self, mixdepth: int) -> str:
        """Get next unused receive address for a mixdepth."""
        next_index = self.get_next_address_index(mixdepth, 0)
        return self.get_receive_address(mixdepth, next_index)

    async def close(self) -> None:
        """Close backend connection"""
        await self.backend.close()
