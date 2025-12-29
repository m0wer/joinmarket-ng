"""
JoinMarket wallet service with mixdepth support.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jmcore.btc_script import mk_freeze_script
from loguru import logger

from jmwallet.backends.base import BlockchainBackend
from jmwallet.wallet.address import script_to_p2wsh_address
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.models import UTXOInfo

# Fidelity bond constants
FIDELITY_BOND_BRANCH = 2  # Internal branch for fidelity bonds

# Default range for descriptor scans (Bitcoin Core default is 1000)
DEFAULT_SCAN_RANGE = 1000


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
        data_dir: Path | None = None,
    ):
        self.mnemonic = mnemonic
        self.backend = backend
        self.network = network
        self.mixdepth_count = mixdepth_count
        self.gap_limit = gap_limit
        self.data_dir = data_dir

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

    def get_account_xpub(self, mixdepth: int) -> str:
        """
        Get the extended public key (xpub) for a mixdepth account.

        Derives the key at path m/84'/coin'/mixdepth' and returns its xpub.
        This xpub can be used in Bitcoin Core descriptors for efficient scanning.

        Args:
            mixdepth: The mixdepth (account) number (0-4)

        Returns:
            xpub/tpub string for the account
        """
        account_path = f"{self.root_path}/{mixdepth}'"
        account_key = self.master_key.derive(account_path)
        return account_key.get_xpub(self.network)

    def get_scan_descriptors(self, scan_range: int = DEFAULT_SCAN_RANGE) -> list[dict[str, Any]]:
        """
        Generate descriptors for efficient UTXO scanning with Bitcoin Core.

        Creates wpkh() descriptors with xpub and range for all mixdepths,
        both external (receive) and internal (change) addresses.

        Using descriptors with ranges is much more efficient than scanning
        individual addresses, as Bitcoin Core can scan the entire range in
        a single pass through the UTXO set.

        Args:
            scan_range: Maximum index to scan (default 1000, Bitcoin Core's default)

        Returns:
            List of descriptor dicts for use with scantxoutset:
            [{"desc": "wpkh(xpub.../0/*)", "range": [0, 999]}, ...]
        """
        descriptors = []

        for mixdepth in range(self.mixdepth_count):
            xpub = self.get_account_xpub(mixdepth)

            # External (receive) addresses: .../0/*
            descriptors.append({"desc": f"wpkh({xpub}/0/*)", "range": [0, scan_range - 1]})

            # Internal (change) addresses: .../1/*
            descriptors.append({"desc": f"wpkh({xpub}/1/*)", "range": [0, scan_range - 1]})

        logger.debug(
            f"Generated {len(descriptors)} descriptors for {self.mixdepth_count} mixdepths "
            f"with range [0, {scan_range - 1}]"
        )
        return descriptors

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

        # Try efficient descriptor-based sync if backend supports it
        if hasattr(self.backend, "scan_descriptors"):
            result = await self._sync_all_with_descriptors()
            if result is not None:
                return result
            # Fall back to address-by-address sync on failure
            logger.warning("Descriptor scan failed, falling back to address scan")

        # Legacy address-by-address scanning
        result = {}
        for mixdepth in range(self.mixdepth_count):
            utxos = await self.sync_mixdepth(mixdepth)
            result[mixdepth] = utxos
        logger.info(f"Sync complete: {sum(len(u) for u in result.values())} total UTXOs")
        return result

    async def _sync_all_with_descriptors(self) -> dict[int, list[UTXOInfo]] | None:
        """
        Sync all mixdepths using efficient descriptor scanning.

        This scans the entire wallet in a single UTXO set pass using xpub descriptors,
        which is much faster than scanning addresses individually (especially on mainnet
        where a full UTXO set scan takes ~90 seconds).

        Returns:
            Dictionary mapping mixdepth to list of UTXOInfo, or None on failure
        """
        # Generate descriptors for all mixdepths and build a lookup table
        scan_range = max(DEFAULT_SCAN_RANGE, self.gap_limit * 10)
        descriptors = []
        # Map descriptor string (without checksum) -> (mixdepth, change)
        desc_to_path: dict[str, tuple[int, int]] = {}

        for mixdepth in range(self.mixdepth_count):
            xpub = self.get_account_xpub(mixdepth)

            # External (receive) addresses: .../0/*
            desc_ext = f"wpkh({xpub}/0/*)"
            descriptors.append({"desc": desc_ext, "range": [0, scan_range - 1]})
            desc_to_path[desc_ext] = (mixdepth, 0)

            # Internal (change) addresses: .../1/*
            desc_int = f"wpkh({xpub}/1/*)"
            descriptors.append({"desc": desc_int, "range": [0, scan_range - 1]})
            desc_to_path[desc_int] = (mixdepth, 1)

        # Get current block height for confirmation calculation
        try:
            tip_height = await self.backend.get_block_height()
        except Exception as e:
            logger.error(f"Failed to get block height for descriptor scan: {e}")
            return None

        # Perform the scan
        scan_result = await self.backend.scan_descriptors(descriptors)
        if not scan_result or not scan_result.get("success", False):
            return None

        # Parse results and organize by mixdepth
        result: dict[int, list[UTXOInfo]] = {md: [] for md in range(self.mixdepth_count)}

        for utxo_data in scan_result.get("unspents", []):
            # Parse the descriptor to extract change and index
            # Descriptor format from Bitcoin Core when using xpub:
            # wpkh([fingerprint/change/index]pubkey)#checksum
            # The fingerprint is the parent xpub's fingerprint
            desc = utxo_data.get("desc", "")
            path_info = self._parse_descriptor_path(desc, desc_to_path)

            if path_info is None:
                logger.warning(f"Could not parse path from descriptor: {desc}")
                continue

            mixdepth, change, index = path_info

            # Calculate confirmations
            confirmations = 0
            utxo_height = utxo_data.get("height", 0)
            if utxo_height > 0:
                confirmations = tip_height - utxo_height + 1

            # Generate the address and cache it
            address = self.get_address(mixdepth, change, index)

            # Build path string
            path = f"{self.root_path}/{mixdepth}'/{change}/{index}"

            utxo_info = UTXOInfo(
                txid=utxo_data["txid"],
                vout=utxo_data["vout"],
                value=int(utxo_data["amount"] * 100_000_000),
                address=address,
                confirmations=confirmations,
                scriptpubkey=utxo_data.get("scriptPubKey", ""),
                path=path,
                mixdepth=mixdepth,
                height=utxo_height if utxo_height > 0 else None,
            )
            result[mixdepth].append(utxo_info)

        # Update cache
        self.utxo_cache = result

        total_utxos = sum(len(u) for u in result.values())
        total_value = sum(sum(u.value for u in utxos) for utxos in result.values())
        logger.info(
            f"Descriptor sync complete: {total_utxos} UTXOs, "
            f"{total_value / 100_000_000:.8f} BTC total"
        )

        return result

    def _parse_descriptor_path(
        self, desc: str, desc_to_path: dict[str, tuple[int, int]]
    ) -> tuple[int, int, int] | None:
        """
        Parse a descriptor to extract mixdepth, change, and index.

        When using xpub descriptors, Bitcoin Core returns a descriptor showing
        the path RELATIVE to the xpub we provided:
        wpkh([fingerprint/change/index]pubkey)#checksum

        We need to match this back to the original descriptor to determine mixdepth.

        Args:
            desc: Descriptor string from scantxoutset result
            desc_to_path: Mapping of descriptor (without checksum) to (mixdepth, change)

        Returns:
            Tuple of (mixdepth, change, index) or None if parsing fails
        """
        import re

        # Remove checksum
        if "#" in desc:
            desc_base = desc.split("#")[0]
        else:
            desc_base = desc

        # Extract the relative path [fingerprint/change/index] and pubkey
        # Pattern: wpkh([fingerprint/change/index]pubkey)
        match = re.search(r"wpkh\(\[[\da-f]+/(\d+)/(\d+)\]([\da-f]+)\)", desc_base, re.I)
        if not match:
            return None

        change_from_desc = int(match.group(1))
        index = int(match.group(2))
        pubkey = match.group(3)

        # Find which descriptor this matches by checking all our descriptors
        # We need to derive the key and check if it matches the pubkey
        for base_desc, (mixdepth, change) in desc_to_path.items():
            if change == change_from_desc:
                # Verify by deriving the key and comparing pubkeys
                try:
                    derived_key = self.master_key.derive(
                        f"{self.root_path}/{mixdepth}'/{change}/{index}"
                    )
                    derived_pubkey = derived_key.get_public_key_bytes(compressed=True).hex()
                    if derived_pubkey == pubkey:
                        return (mixdepth, change, index)
                except Exception:
                    continue

        return None

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

    def find_utxo_by_address(self, address: str) -> UTXOInfo | None:
        """
        Find a UTXO by its address across all mixdepths.

        This is useful for matching CoinJoin outputs to history entries.
        Returns the first matching UTXO found, or None if address not found.

        Args:
            address: Bitcoin address to search for

        Returns:
            UTXOInfo if found, None otherwise
        """
        for mixdepth in range(self.mixdepth_count):
            utxos = self.utxo_cache.get(mixdepth, [])
            for utxo in utxos:
                if utxo.address == address:
                    return utxo
        return None

    async def get_total_balance(self) -> int:
        """Get total balance across all mixdepths"""
        total = 0
        for mixdepth in range(self.mixdepth_count):
            balance = await self.get_balance(mixdepth)
            total += balance
        return total

    def select_utxos(
        self,
        mixdepth: int,
        target_amount: int,
        min_confirmations: int = 1,
        include_utxos: list[UTXOInfo] | None = None,
    ) -> list[UTXOInfo]:
        """
        Select UTXOs for spending from a mixdepth.
        Uses simple greedy selection strategy.

        Args:
            mixdepth: Mixdepth to select from
            target_amount: Target amount in satoshis
            min_confirmations: Minimum confirmations required
            include_utxos: List of UTXOs that MUST be included in selection
        """
        utxos = self.utxo_cache.get(mixdepth, [])

        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]

        # Filter out included UTXOs from eligible pool to avoid duplicates
        included_txid_vout = set()
        if include_utxos:
            included_txid_vout = {(u.txid, u.vout) for u in include_utxos}
            eligible = [u for u in eligible if (u.txid, u.vout) not in included_txid_vout]

        eligible.sort(key=lambda u: u.value, reverse=True)

        selected = []
        total = 0

        # Add mandatory UTXOs first
        if include_utxos:
            for utxo in include_utxos:
                selected.append(utxo)
                total += utxo.value

        if total >= target_amount:
            # Already enough with mandatory UTXOs
            return selected

        for utxo in eligible:
            selected.append(utxo)
            total += utxo.value
            if total >= target_amount:
                break

        if total < target_amount:
            raise ValueError(f"Insufficient funds: need {target_amount}, have {total}")

        return selected

    def get_all_utxos(
        self,
        mixdepth: int,
        min_confirmations: int = 1,
    ) -> list[UTXOInfo]:
        """
        Get all UTXOs from a mixdepth for sweep operations.

        Unlike select_utxos(), this returns ALL eligible UTXOs regardless of
        target amount. Used for sweep mode to ensure no change output.

        Args:
            mixdepth: Mixdepth to get UTXOs from
            min_confirmations: Minimum confirmations required

        Returns:
            List of all eligible UTXOs in the mixdepth
        """
        utxos = self.utxo_cache.get(mixdepth, [])
        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]
        return eligible

    def select_utxos_with_merge(
        self,
        mixdepth: int,
        target_amount: int,
        min_confirmations: int = 1,
        merge_algorithm: str = "default",
    ) -> list[UTXOInfo]:
        """
        Select UTXOs with merge algorithm for maker UTXO consolidation.

        Unlike regular select_utxos(), this method can select MORE UTXOs than
        strictly necessary based on the merge algorithm. Since takers pay tx fees,
        makers can add extra inputs "for free" to consolidate their UTXOs.

        Args:
            mixdepth: Mixdepth to select from
            target_amount: Minimum target amount in satoshis
            min_confirmations: Minimum confirmations required
            merge_algorithm: Selection strategy:
                - "default": Minimum UTXOs needed (same as select_utxos)
                - "gradual": +1 additional UTXO beyond minimum
                - "greedy": ALL eligible UTXOs from the mixdepth
                - "random": +0 to +2 additional UTXOs randomly

        Returns:
            List of selected UTXOs

        Raises:
            ValueError: If insufficient funds
        """
        import random as rand_module

        utxos = self.utxo_cache.get(mixdepth, [])
        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]

        # Sort by value descending for efficient selection
        eligible.sort(key=lambda u: u.value, reverse=True)

        # First, select minimum needed (greedy by value)
        selected = []
        total = 0

        for utxo in eligible:
            selected.append(utxo)
            total += utxo.value
            if total >= target_amount:
                break

        if total < target_amount:
            raise ValueError(f"Insufficient funds: need {target_amount}, have {total}")

        # Record where minimum selection ends
        min_count = len(selected)

        # Get remaining eligible UTXOs not yet selected
        remaining = eligible[min_count:]

        # Apply merge algorithm to add additional UTXOs
        if merge_algorithm == "greedy":
            # Add ALL remaining UTXOs
            selected.extend(remaining)
        elif merge_algorithm == "gradual" and remaining:
            # Add exactly 1 more UTXO (smallest to preserve larger ones)
            remaining_sorted = sorted(remaining, key=lambda u: u.value)
            selected.append(remaining_sorted[0])
        elif merge_algorithm == "random" and remaining:
            # Add 0-2 additional UTXOs randomly
            extra_count = rand_module.randint(0, min(2, len(remaining)))
            if extra_count > 0:
                # Prefer smaller UTXOs for consolidation
                remaining_sorted = sorted(remaining, key=lambda u: u.value)
                selected.extend(remaining_sorted[:extra_count])
        # "default" - no additional UTXOs

        return selected

    def get_next_address_index(self, mixdepth: int, change: int) -> int:
        """
        Get next unused address index for mixdepth/change.

        Checks both the address/UTXO cache and the CoinJoin history to ensure
        we never reuse addresses that were shared in previous CoinJoins, even
        if those transactions weren't confirmed or we don't know their txid.
        """
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

        # Check history for used addresses to prevent reuse
        used_addresses: set[str] = set()
        if self.data_dir:
            from jmwallet.history import get_used_addresses

            used_addresses = get_used_addresses(self.data_dir)

        # Find the first index that generates an unused address
        candidate_index = max_index + 1
        max_attempts = 100  # Safety limit to prevent infinite loop

        for attempt in range(max_attempts):
            test_address = self.get_address(mixdepth, change, candidate_index)
            if test_address not in used_addresses:
                return candidate_index
            # This address was used in history, try next
            logger.warning(
                f"Skipping index {candidate_index} for mixdepth {mixdepth}, "
                f"change {change} - address was used in previous CoinJoin"
            )
            candidate_index += 1

        # Shouldn't happen unless we have 100 consecutive used addresses
        raise RuntimeError(
            f"Could not find unused address after {max_attempts} attempts. "
            f"This likely indicates a bug in address history tracking."
        )

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
