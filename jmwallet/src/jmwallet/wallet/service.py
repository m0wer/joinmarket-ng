"""
JoinMarket wallet service with mixdepth support.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jmcore.bitcoin import btc_to_sats, format_amount
from jmcore.btc_script import mk_freeze_script
from loguru import logger

from jmwallet.backends.base import BlockchainBackend
from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
from jmwallet.wallet.address import script_to_p2wsh_address
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
from jmwallet.wallet.models import AddressInfo, AddressStatus, UTXOInfo
from jmwallet.wallet.utxo_metadata import UTXOMetadataStore, load_metadata_store

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
        passphrase: str = "",
    ):
        self.mnemonic = mnemonic
        self.backend = backend
        self.network = network
        self.mixdepth_count = mixdepth_count
        self.gap_limit = gap_limit
        self.data_dir = data_dir
        self.passphrase = passphrase

        seed = mnemonic_to_seed(mnemonic, passphrase)
        self.master_key = HDKey.from_seed(seed)

        coin_type = 0 if network == "mainnet" else 1
        self.root_path = f"m/84'/{coin_type}'"

        # Log fingerprint for debugging (helps identify passphrase issues)
        fingerprint = self.master_key.derive("m/0").fingerprint.hex()
        logger.info(
            f"Initialized wallet: fingerprint={fingerprint}, "
            f"mixdepths={mixdepth_count}, network={network}, "
            f"passphrase={'(set)' if passphrase else '(none)'}"
        )

        self.address_cache: dict[str, tuple[int, int, int]] = {}
        self.utxo_cache: dict[int, list[UTXOInfo]] = {}
        # Track addresses that have ever had UTXOs (including spent ones)
        # This is used to correctly label addresses as "used-empty" vs "new"
        self.addresses_with_history: set[str] = set()
        # Track addresses currently reserved for in-progress CoinJoin sessions
        # These addresses have been shared with a taker but the CoinJoin hasn't
        # completed yet. They must not be reused until the session ends.
        self.reserved_addresses: set[str] = set()
        # Cache for fidelity bond locktimes (address -> locktime)
        self.fidelity_bond_locktime_cache: dict[str, int] = {}

        # UTXO metadata store for frozen state and labels (BIP-329)
        self.metadata_store: UTXOMetadataStore | None = None
        if data_dir is not None:
            self.metadata_store = load_metadata_store(data_dir)

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

    def get_account_zpub(self, mixdepth: int) -> str:
        """
        Get the BIP84 extended public key (zpub) for a mixdepth account.

        Derives the key at path m/84'/coin'/mixdepth' and returns its zpub.
        zpub explicitly indicates this is a native segwit (P2WPKH) wallet.

        Args:
            mixdepth: The mixdepth (account) number (0-4)

        Returns:
            zpub/vpub string for the account
        """
        account_path = f"{self.root_path}/{mixdepth}'"
        account_key = self.master_key.derive(account_path)
        return account_key.get_zpub(self.network)

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
        self.fidelity_bond_locktime_cache[address] = locktime

        logger.trace(f"Created fidelity bond address {address} with locktime {locktime}")
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

    def get_locktime_for_address(self, address: str) -> int | None:
        """
        Get the locktime for a fidelity bond address.

        Args:
            address: The fidelity bond address

        Returns:
            Locktime as Unix timestamp, or None if not a fidelity bond address
        """
        if not hasattr(self, "fidelity_bond_locktime_cache"):
            return None
        return self.fidelity_bond_locktime_cache.get(address)

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
                        # Track that this address has had UTXOs
                        self.addresses_with_history.add(address)
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
                        # Track that this address has had UTXOs
                        self.addresses_with_history.add(address)
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
                                locktime=locktime,  # Store locktime for P2WSH signing
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

    async def discover_fidelity_bonds(
        self,
        max_index: int = 1,
        progress_callback: Any | None = None,
    ) -> list[UTXOInfo]:
        """
        Discover fidelity bonds by scanning all 960 possible locktimes.

        This is used during wallet recovery when the user doesn't know which
        locktimes they used. It generates addresses for all valid timenumbers
        (0-959, representing Jan 2020 through Dec 2099) and scans for UTXOs.

        For descriptor_wallet backend, this method will import addresses into
        the wallet as it scans in batches, then clean up addresses that had no UTXOs.

        The scan is optimized by:
        1. Using index=0 only (most users only use one address per locktime)
        2. Batching address generation and UTXO queries
        3. Optionally extending index range only for locktimes with funds

        Args:
            max_index: Maximum address index to scan per locktime (default 1).
                      Higher values increase scan time linearly.
            progress_callback: Optional callback(timenumber, total) for progress updates

        Returns:
            List of discovered fidelity bond UTXOs
        """
        from jmcore.timenumber import TIMENUMBER_COUNT, timenumber_to_timestamp

        from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

        logger.info(
            f"Starting fidelity bond discovery scan "
            f"({TIMENUMBER_COUNT} timelocks × {max_index} index(es))"
        )

        discovered_utxos: list[UTXOInfo] = []
        batch_size = 100  # Process timenumbers in batches
        is_descriptor_wallet = isinstance(self.backend, DescriptorWalletBackend)

        # Initialize locktime cache if needed
        if not hasattr(self, "fidelity_bond_locktime_cache"):
            self.fidelity_bond_locktime_cache = {}

        for batch_start in range(0, TIMENUMBER_COUNT, batch_size):
            batch_end = min(batch_start + batch_size, TIMENUMBER_COUNT)
            addresses: list[str] = []
            address_to_locktime: dict[str, tuple[int, int]] = {}  # address -> (locktime, index)

            # Generate addresses for this batch of timenumbers
            for timenumber in range(batch_start, batch_end):
                locktime = timenumber_to_timestamp(timenumber)
                for idx in range(max_index):
                    address = self.get_fidelity_bond_address(idx, locktime)
                    addresses.append(address)
                    address_to_locktime[address] = (locktime, idx)

            # For descriptor wallet, import addresses before scanning
            if is_descriptor_wallet:
                fidelity_bond_addresses = [
                    (addr, locktime, idx) for addr, (locktime, idx) in address_to_locktime.items()
                ]
                try:
                    await self.import_fidelity_bond_addresses(
                        fidelity_bond_addresses=fidelity_bond_addresses,
                        rescan=True,
                    )
                    # Wait for rescan to complete before querying UTXOs
                    # This ensures the wallet has indexed all transactions for these addresses
                    if hasattr(self.backend, "wait_for_rescan_complete"):
                        logger.info("Waiting for wallet rescan to complete...")
                        await self.backend.wait_for_rescan_complete(
                            poll_interval=5.0,
                            progress_callback=lambda p: logger.debug(f"Rescan progress: {p:.1%}"),
                        )
                except Exception as e:
                    logger.error(f"Failed to import batch {batch_start}-{batch_end}: {e}")
                    continue

            # Fetch UTXOs for all addresses in batch
            try:
                backend_utxos = await self.backend.get_utxos(addresses)
            except Exception as e:
                logger.error(f"Failed to scan batch {batch_start}-{batch_end}: {e}")
                continue

            # Process found UTXOs
            for utxo in backend_utxos:
                if utxo.address in address_to_locktime:
                    locktime, idx = address_to_locktime[utxo.address]
                    path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{idx}:{locktime}"

                    utxo_info = UTXOInfo(
                        txid=utxo.txid,
                        vout=utxo.vout,
                        value=utxo.value,
                        address=utxo.address,
                        confirmations=utxo.confirmations,
                        scriptpubkey=utxo.scriptpubkey,
                        path=path,
                        mixdepth=0,
                        height=utxo.height,
                        locktime=locktime,
                    )
                    discovered_utxos.append(utxo_info)

                    from jmcore.timenumber import format_locktime_date

                    logger.info(
                        f"Discovered fidelity bond: {utxo.txid}:{utxo.vout} "
                        f"value={utxo.value:,} sats, locktime={format_locktime_date(locktime)}"
                    )

            # Progress callback
            if progress_callback:
                progress_callback(batch_end, TIMENUMBER_COUNT)

        # Add discovered UTXOs to mixdepth 0 cache
        if discovered_utxos:
            if 0 not in self.utxo_cache:
                self.utxo_cache[0] = []
            # Avoid duplicates
            existing_outpoints = {(u.txid, u.vout) for u in self.utxo_cache[0]}
            for utxo_info in discovered_utxos:
                if (utxo_info.txid, utxo_info.vout) not in existing_outpoints:
                    self.utxo_cache[0].append(utxo_info)

            logger.info(f"Discovery complete: found {len(discovered_utxos)} fidelity bond(s)")
        else:
            logger.info("Discovery complete: no fidelity bonds found")

        return discovered_utxos

    async def sync_all(
        self, fidelity_bond_addresses: list[tuple[str, int, int]] | None = None
    ) -> dict[int, list[UTXOInfo]]:
        """
        Sync all mixdepths, optionally including fidelity bond addresses.

        Args:
            fidelity_bond_addresses: Optional list of (address, locktime, index) tuples
                                    for fidelity bonds to scan with wallet descriptors

        Returns:
            Dictionary mapping mixdepth to list of UTXOs
        """
        logger.info("Syncing all mixdepths...")

        # Try efficient descriptor-based sync if backend supports it
        if hasattr(self.backend, "scan_descriptors"):
            result = await self._sync_all_with_descriptors(fidelity_bond_addresses)
            if result is not None:
                self._apply_frozen_state()
                return result
            # Fall back to address-by-address sync on failure
            logger.warning("Descriptor scan failed, falling back to address scan")

        # Legacy address-by-address scanning
        result = {}
        for mixdepth in range(self.mixdepth_count):
            utxos = await self.sync_mixdepth(mixdepth)
            result[mixdepth] = utxos
        logger.info(f"Sync complete: {sum(len(u) for u in result.values())} total UTXOs")
        self._apply_frozen_state()
        return result

    async def _sync_all_with_descriptors(
        self, fidelity_bond_addresses: list[tuple[str, int, int]] | None = None
    ) -> dict[int, list[UTXOInfo]] | None:
        """
        Sync all mixdepths using efficient descriptor scanning.

        This scans the entire wallet in a single UTXO set pass using xpub descriptors,
        which is much faster than scanning addresses individually (especially on mainnet
        where a full UTXO set scan takes ~90 seconds).

        Args:
            fidelity_bond_addresses: Optional list of (address, locktime, index) tuples to scan
                                    in the same pass as wallet descriptors

        Returns:
            Dictionary mapping mixdepth to list of UTXOInfo, or None on failure
        """
        # Generate descriptors for all mixdepths and build a lookup table
        scan_range = max(DEFAULT_SCAN_RANGE, self.gap_limit * 10)
        descriptors: list[str | dict[str, Any]] = []
        # Map descriptor string (without checksum) -> (mixdepth, change)
        desc_to_path: dict[str, tuple[int, int]] = {}
        # Map fidelity bond address -> (locktime, index)
        bond_address_to_info: dict[str, tuple[int, int]] = {}

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

        # Add fidelity bond addresses to the scan
        if fidelity_bond_addresses:
            logger.info(
                f"Including {len(fidelity_bond_addresses)} fidelity bond address(es) in scan"
            )
            # Initialize locktime cache if needed
            if not hasattr(self, "fidelity_bond_locktime_cache"):
                self.fidelity_bond_locktime_cache = {}

            for address, locktime, index in fidelity_bond_addresses:
                descriptors.append(f"addr({address})")
                bond_address_to_info[address] = (locktime, index)
                # Cache the address with the correct index from registry
                self.address_cache[address] = (0, FIDELITY_BOND_BRANCH, index)
                self.fidelity_bond_locktime_cache[address] = locktime

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
        fidelity_bond_utxos: list[UTXOInfo] = []

        for utxo_data in scan_result.get("unspents", []):
            desc = utxo_data.get("desc", "")

            # Check if this is a fidelity bond address result
            # Fidelity bond descriptors are returned as: addr(bc1q...)#checksum
            if "#" in desc:
                desc_base = desc.split("#")[0]
            else:
                desc_base = desc

            if desc_base.startswith("addr(") and desc_base.endswith(")"):
                bond_address = desc_base[5:-1]
                if bond_address in bond_address_to_info:
                    # This is a fidelity bond UTXO
                    locktime, index = bond_address_to_info[bond_address]
                    confirmations = 0
                    utxo_height = utxo_data.get("height", 0)
                    if utxo_height > 0:
                        confirmations = tip_height - utxo_height + 1

                    # Path format for fidelity bonds: m/84'/0'/0'/2/index:locktime
                    path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index}:{locktime}"

                    utxo_info = UTXOInfo(
                        txid=utxo_data["txid"],
                        vout=utxo_data["vout"],
                        value=btc_to_sats(utxo_data["amount"]),
                        address=bond_address,
                        confirmations=confirmations,
                        scriptpubkey=utxo_data.get("scriptPubKey", ""),
                        path=path,
                        mixdepth=0,  # Fidelity bonds in mixdepth 0
                        height=utxo_height if utxo_height > 0 else None,
                        locktime=locktime,
                    )
                    fidelity_bond_utxos.append(utxo_info)
                    logger.info(
                        f"Found fidelity bond UTXO: {utxo_info.txid}:{utxo_info.vout} "
                        f"value={utxo_info.value} locktime={locktime} index={index}"
                    )
                    continue

            # Parse the descriptor to extract change and index for regular wallet UTXOs
            # Descriptor format from Bitcoin Core when using xpub:
            # wpkh([fingerprint/change/index]pubkey)#checksum
            # The fingerprint is the parent xpub's fingerprint
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

            # Track that this address has had UTXOs
            self.addresses_with_history.add(address)

            # Build path string
            path = f"{self.root_path}/{mixdepth}'/{change}/{index}"

            utxo_info = UTXOInfo(
                txid=utxo_data["txid"],
                vout=utxo_data["vout"],
                value=btc_to_sats(utxo_data["amount"]),
                address=address,
                confirmations=confirmations,
                scriptpubkey=utxo_data.get("scriptPubKey", ""),
                path=path,
                mixdepth=mixdepth,
                height=utxo_height if utxo_height > 0 else None,
            )
            result[mixdepth].append(utxo_info)

        # Add fidelity bond UTXOs to mixdepth 0
        if fidelity_bond_utxos:
            result[0].extend(fidelity_bond_utxos)

        # Update cache
        self.utxo_cache = result

        total_utxos = sum(len(u) for u in result.values())
        total_value = sum(sum(u.value for u in utxos) for utxos in result.values())
        bond_count = len(fidelity_bond_utxos)
        if bond_count > 0:
            logger.info(
                f"Descriptor sync complete: {total_utxos} UTXOs "
                f"({bond_count} fidelity bond(s)), {format_amount(total_value)} total"
            )
        else:
            logger.info(
                f"Descriptor sync complete: {total_utxos} UTXOs, {format_amount(total_value)} total"
            )

        return result

    async def setup_descriptor_wallet(
        self,
        scan_range: int = DEFAULT_SCAN_RANGE,
        fidelity_bond_addresses: list[tuple[str, int, int]] | None = None,
        rescan: bool = True,
        check_existing: bool = True,
        smart_scan: bool = True,
        background_full_rescan: bool = True,
    ) -> bool:
        """
        Setup descriptor wallet backend for efficient UTXO tracking.

        This imports wallet descriptors into Bitcoin Core's descriptor wallet,
        enabling fast UTXO queries via listunspent instead of slow scantxoutset.

        By default, uses smart scan for fast startup (~1 minute instead of 20+ minutes)
        with a background full rescan to catch any older transactions.

        Should be called once on first use or when restoring a wallet.
        Subsequent operations will be much faster.

        Args:
            scan_range: Address index range to import (default 1000)
            fidelity_bond_addresses: Optional list of (address, locktime, index) tuples
            rescan: Whether to rescan blockchain
            check_existing: If True, checks if wallet is already set up and skips import
            smart_scan: If True and rescan=True, scan from ~1 year ago for fast startup.
                       A full rescan runs in background to catch older transactions.
            background_full_rescan: If True and smart_scan=True, run full rescan in background

        Returns:
            True if setup completed successfully

        Raises:
            RuntimeError: If backend is not DescriptorWalletBackend

        Example:
            # Fast setup with smart scan (default) - starts quickly, full scan in background
            await wallet.setup_descriptor_wallet(rescan=True)

            # Full scan from genesis (slow but complete) - use for wallet recovery
            await wallet.setup_descriptor_wallet(rescan=True, smart_scan=False)

            # No rescan (for brand new wallets with no history)
            await wallet.setup_descriptor_wallet(rescan=False)
        """
        if not isinstance(self.backend, DescriptorWalletBackend):
            raise RuntimeError(
                "setup_descriptor_wallet() requires DescriptorWalletBackend. "
                "Current backend does not support descriptor wallets."
            )

        # Check if already set up (unless explicitly disabled)
        if check_existing:
            expected_count = self.mixdepth_count * 2  # external + internal per mixdepth
            if fidelity_bond_addresses:
                expected_count += len(fidelity_bond_addresses)

            if await self.backend.is_wallet_setup(expected_descriptor_count=expected_count):
                logger.info("Descriptor wallet already set up, skipping import")
                return True

        # Generate descriptors for all mixdepths
        descriptors = self._generate_import_descriptors(scan_range)

        # Add fidelity bond addresses
        if fidelity_bond_addresses:
            logger.info(f"Including {len(fidelity_bond_addresses)} fidelity bond addresses")
            for address, locktime, index in fidelity_bond_addresses:
                descriptors.append(
                    {
                        "desc": f"addr({address})",
                        "internal": False,
                    }
                )
                # Cache the address info
                if not hasattr(self, "fidelity_bond_locktime_cache"):
                    self.fidelity_bond_locktime_cache = {}
                self.address_cache[address] = (0, FIDELITY_BOND_BRANCH, index)
                self.fidelity_bond_locktime_cache[address] = locktime

        # Setup wallet and import descriptors
        logger.info("Setting up descriptor wallet...")
        await self.backend.setup_wallet(
            descriptors,
            rescan=rescan,
            smart_scan=smart_scan,
            background_full_rescan=background_full_rescan,
        )
        logger.info("Descriptor wallet setup complete")
        return True

    async def is_descriptor_wallet_ready(self, fidelity_bond_count: int = 0) -> bool:
        """
        Check if descriptor wallet is already set up and ready to use.

        Args:
            fidelity_bond_count: Expected number of fidelity bond addresses

        Returns:
            True if wallet is set up with all expected descriptors

        Example:
            if await wallet.is_descriptor_wallet_ready():
                # Just sync
                utxos = await wallet.sync_with_descriptor_wallet()
            else:
                # First time - import descriptors
                await wallet.setup_descriptor_wallet(rescan=True)
        """
        if not isinstance(self.backend, DescriptorWalletBackend):
            return False

        expected_count = self.mixdepth_count * 2  # external + internal per mixdepth
        if fidelity_bond_count > 0:
            expected_count += fidelity_bond_count

        return await self.backend.is_wallet_setup(expected_descriptor_count=expected_count)

    async def import_fidelity_bond_addresses(
        self,
        fidelity_bond_addresses: list[tuple[str, int, int]],
        rescan: bool = True,
    ) -> bool:
        """
        Import fidelity bond addresses into the descriptor wallet.

        This is used to add fidelity bond addresses that weren't included
        in the initial wallet setup. Fidelity bonds use P2WSH addresses
        (timelocked scripts) that are not part of the standard BIP84 derivation,
        so they must be explicitly imported.

        Args:
            fidelity_bond_addresses: List of (address, locktime, index) tuples
            rescan: Whether to rescan the blockchain for these addresses

        Returns:
            True if import succeeded

        Raises:
            RuntimeError: If backend is not DescriptorWalletBackend
        """
        if not isinstance(self.backend, DescriptorWalletBackend):
            raise RuntimeError("import_fidelity_bond_addresses() requires DescriptorWalletBackend")

        if not fidelity_bond_addresses:
            return True

        # Build descriptors for the bond addresses
        descriptors = []
        for address, locktime, index in fidelity_bond_addresses:
            descriptors.append(
                {
                    "desc": f"addr({address})",
                    "internal": False,
                }
            )
            # Cache the address info
            if not hasattr(self, "fidelity_bond_locktime_cache"):
                self.fidelity_bond_locktime_cache = {}
            self.address_cache[address] = (0, FIDELITY_BOND_BRANCH, index)
            self.fidelity_bond_locktime_cache[address] = locktime

        logger.info(f"Importing {len(descriptors)} fidelity bond address(es)...")
        await self.backend.import_descriptors(descriptors, rescan=rescan)
        logger.info("Fidelity bond addresses imported")
        return True

    def _generate_import_descriptors(
        self, scan_range: int = DEFAULT_SCAN_RANGE
    ) -> list[dict[str, Any]]:
        """
        Generate descriptors for importdescriptors RPC.

        Creates descriptors for all mixdepths (external and internal addresses)
        with proper formatting for Bitcoin Core's importdescriptors.

        Args:
            scan_range: Maximum index to import

        Returns:
            List of descriptor dicts for importdescriptors
        """
        descriptors = []

        for mixdepth in range(self.mixdepth_count):
            xpub = self.get_account_xpub(mixdepth)

            # External (receive) addresses: .../0/*
            descriptors.append(
                {
                    "desc": f"wpkh({xpub}/0/*)",
                    "range": [0, scan_range - 1],
                    "internal": False,
                }
            )

            # Internal (change) addresses: .../1/*
            descriptors.append(
                {
                    "desc": f"wpkh({xpub}/1/*)",
                    "range": [0, scan_range - 1],
                    "internal": True,
                }
            )

        logger.debug(
            f"Generated {len(descriptors)} import descriptors for "
            f"{self.mixdepth_count} mixdepths with range [0, {scan_range - 1}]"
        )
        return descriptors

    async def sync_with_descriptor_wallet(
        self,
        fidelity_bond_addresses: list[tuple[str, int, int]] | None = None,
    ) -> dict[int, list[UTXOInfo]]:
        """
        Sync wallet using descriptor wallet backend (fast listunspent).

        This is MUCH faster than scantxoutset because it only queries the
        wallet's tracked UTXOs, not the entire UTXO set.

        Args:
            fidelity_bond_addresses: Optional fidelity bond addresses to include

        Returns:
            Dictionary mapping mixdepth to list of UTXOs

        Raises:
            RuntimeError: If backend is not DescriptorWalletBackend
        """
        if not isinstance(self.backend, DescriptorWalletBackend):
            raise RuntimeError("sync_with_descriptor_wallet() requires DescriptorWalletBackend")

        logger.info("Syncing via descriptor wallet (listunspent)...")

        # Get the current descriptor range from Bitcoin Core and cache it
        # This is used by _find_address_path to know how far to scan
        current_range = await self.backend.get_max_descriptor_range()
        self._current_descriptor_range = current_range
        logger.debug(f"Current descriptor range: [0, {current_range}]")

        # Pre-populate address cache for the entire descriptor range
        # This is more efficient than deriving addresses one by one during lookup
        await self._populate_address_cache(current_range)

        # Get all wallet UTXOs at once
        all_utxos = await self.backend.get_all_utxos()

        # Organize UTXOs by mixdepth
        result: dict[int, list[UTXOInfo]] = {md: [] for md in range(self.mixdepth_count)}
        fidelity_bond_utxos: list[UTXOInfo] = []

        # Build fidelity bond address lookup
        # Note: Normalize addresses to lowercase for consistent comparison
        # (bech32 addresses are case-insensitive but Python string comparison is not)
        bond_address_to_info: dict[str, tuple[int, int]] = {}
        if fidelity_bond_addresses:
            if not hasattr(self, "fidelity_bond_locktime_cache"):
                self.fidelity_bond_locktime_cache = {}
            for address, locktime, index in fidelity_bond_addresses:
                addr_lower = address.lower()
                bond_address_to_info[addr_lower] = (locktime, index)
                self.address_cache[addr_lower] = (0, FIDELITY_BOND_BRANCH, index)
                self.fidelity_bond_locktime_cache[addr_lower] = locktime
            logger.debug(f"Registered {len(bond_address_to_info)} fidelity bond addresses for sync")

        for utxo in all_utxos:
            # Normalize address to lowercase for consistent comparison
            # (bech32 addresses are case-insensitive but Python string comparison is not)
            original_address = utxo.address
            address = original_address.lower()

            # Check if this is a fidelity bond
            if address in bond_address_to_info:
                locktime, index = bond_address_to_info[address]
                path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index}:{locktime}"
                # Track that this address has had UTXOs
                self.addresses_with_history.add(address)
                utxo_info = UTXOInfo(
                    txid=utxo.txid,
                    vout=utxo.vout,
                    value=utxo.value,
                    address=original_address,  # Preserve original case
                    confirmations=utxo.confirmations,
                    scriptpubkey=utxo.scriptpubkey,
                    path=path,
                    mixdepth=0,
                    height=utxo.height,
                    locktime=locktime,
                )
                fidelity_bond_utxos.append(utxo_info)
                logger.debug(
                    f"Recognized fidelity bond UTXO: {address[:20]}... "
                    f"value={utxo.value} locktime={locktime}"
                )
                continue

            # Try to find address in cache (should be pre-populated now)
            path_info = self.address_cache.get(address)
            if path_info is None:
                # Fallback to derivation scan (shouldn't happen often now)
                path_info = self._find_address_path(address)
            if path_info is None:
                # Check if this is a P2WSH address (likely a fidelity bond we don't know about)
                # P2WSH: OP_0 (0x00) + PUSH32 (0x20) + 32-byte hash = 68 hex chars
                if len(utxo.scriptpubkey) == 68 and utxo.scriptpubkey.startswith("0020"):
                    # Check if this P2WSH address is a known fidelity bond from the registry
                    # This handles external bonds that may have been imported but not matched above
                    if hasattr(self, "fidelity_bond_locktime_cache"):
                        cached_locktime = self.fidelity_bond_locktime_cache.get(address)
                        if cached_locktime is not None:
                            # This is a known fidelity bond from the registry
                            # Get index from address_cache (should have been set during import)
                            cached = self.address_cache.get(address)
                            index = cached[2] if cached else -1
                            path = (
                                f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}"
                                f"/{index}:{cached_locktime}"
                            )
                            self.addresses_with_history.add(address)
                            utxo_info = UTXOInfo(
                                txid=utxo.txid,
                                vout=utxo.vout,
                                value=utxo.value,
                                address=original_address,  # Preserve original case
                                confirmations=utxo.confirmations,
                                scriptpubkey=utxo.scriptpubkey,
                                path=path,
                                mixdepth=0,
                                height=utxo.height,
                                locktime=cached_locktime,
                            )
                            fidelity_bond_utxos.append(utxo_info)
                            logger.debug(
                                f"Recognized P2WSH as fidelity bond from registry: "
                                f"{address[:20]}... locktime={cached_locktime}"
                            )
                            continue
                    # Unknown P2WSH - silently skip (fidelity bonds we don't know about)
                    logger.trace(f"Skipping unknown P2WSH address {address}")
                    continue
                logger.debug(f"Unknown address {address}, skipping")
                continue

            mixdepth, change, index = path_info

            # Check if this is a fidelity bond address (branch 2)
            # This handles cases where the address was added to address_cache but
            # the UTXO wasn't matched in bond_address_to_info (e.g., external bonds)
            if change == FIDELITY_BOND_BRANCH:
                # Get locktime from cache
                bond_locktime: int | None = None
                if hasattr(self, "fidelity_bond_locktime_cache"):
                    bond_locktime = self.fidelity_bond_locktime_cache.get(address)

                if bond_locktime is not None:
                    path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index}:{bond_locktime}"
                    self.addresses_with_history.add(address)
                    utxo_info = UTXOInfo(
                        txid=utxo.txid,
                        vout=utxo.vout,
                        value=utxo.value,
                        address=original_address,  # Preserve original case
                        confirmations=utxo.confirmations,
                        scriptpubkey=utxo.scriptpubkey,
                        path=path,
                        mixdepth=0,
                        height=utxo.height,
                        locktime=bond_locktime,
                    )
                    fidelity_bond_utxos.append(utxo_info)
                    logger.debug(
                        f"Recognized fidelity bond from cache: "
                        f"{address[:20]}... locktime={bond_locktime} index={index}"
                    )
                    continue
                else:
                    # Fidelity bond address without locktime - skip with warning
                    logger.warning(
                        f"Fidelity bond address {address[:20]}... found without locktime, skipping"
                    )
                    continue

            path = f"{self.root_path}/{mixdepth}'/{change}/{index}"

            # Track that this address has had UTXOs
            self.addresses_with_history.add(address)

            utxo_info = UTXOInfo(
                txid=utxo.txid,
                vout=utxo.vout,
                value=utxo.value,
                address=original_address,  # Preserve original case
                confirmations=utxo.confirmations,
                scriptpubkey=utxo.scriptpubkey,
                path=path,
                mixdepth=mixdepth,
                height=utxo.height,
            )
            result[mixdepth].append(utxo_info)

        # Add fidelity bonds to mixdepth 0
        if fidelity_bond_utxos:
            result[0].extend(fidelity_bond_utxos)

        # Update cache
        self.utxo_cache = result

        # Fetch all addresses with transaction history (including spent)
        # This is important to track addresses that have been used but are now empty
        addresses_beyond_range: list[str] = []
        try:
            if hasattr(self.backend, "get_addresses_with_history"):
                history_addresses = await self.backend.get_addresses_with_history()
                for address in history_addresses:
                    # Check if this address belongs to our wallet
                    # Use _find_address_path which checks cache first, then derives if needed
                    path_info = self._find_address_path(address)
                    if path_info is not None:
                        self.addresses_with_history.add(address)
                    else:
                        # Address not found in current range - may be beyond descriptor range
                        addresses_beyond_range.append(address)
                logger.debug(f"Tracked {len(self.addresses_with_history)} addresses with history")
                if addresses_beyond_range:
                    logger.info(
                        f"Found {len(addresses_beyond_range)} address(es) from history "
                        f"not in current range [0, {current_range}], searching extended range..."
                    )
        except Exception as e:
            logger.debug(f"Could not fetch addresses with history: {e}")

        # Search for addresses beyond the current range
        # This handles wallets previously used with different software (e.g., reference impl)
        # that may have used addresses at indices beyond our current descriptor range
        if addresses_beyond_range:
            extended_addresses_found = 0
            for address in addresses_beyond_range:
                path_info = self._find_address_path_extended(address)
                if path_info is not None:
                    self.addresses_with_history.add(address)
                    extended_addresses_found += 1
            if extended_addresses_found > 0:
                logger.info(
                    f"Found {extended_addresses_found} address(es) in extended range search"
                )

        # Check if descriptor range needs to be upgraded
        # This handles wallets that have grown beyond the initial range
        try:
            upgraded = await self.check_and_upgrade_descriptor_range(gap_limit=100)
            if upgraded:
                # Re-populate address cache with the new range
                new_range = await self.backend.get_max_descriptor_range()
                await self._populate_address_cache(new_range)
        except Exception as e:
            logger.warning(f"Could not check/upgrade descriptor range: {e}")

        total_utxos = sum(len(u) for u in result.values())
        total_value = sum(sum(u.value for u in utxos) for utxos in result.values())
        logger.info(
            f"Descriptor wallet sync complete: {total_utxos} UTXOs, "
            f"{format_amount(total_value)} total"
        )

        self._apply_frozen_state()
        return result

    async def check_and_upgrade_descriptor_range(
        self,
        gap_limit: int = 100,
    ) -> bool:
        """
        Check if descriptor range needs upgrading and upgrade if necessary.

        This method detects if the wallet has used addresses beyond the current
        descriptor range and automatically upgrades the range if needed.

        The algorithm:
        1. Get the current descriptor range from Bitcoin Core
        2. Check addresses with history to find the highest used index
        3. If highest used index + gap_limit > current range, upgrade

        Args:
            gap_limit: Number of empty addresses to maintain beyond highest used

        Returns:
            True if upgrade was performed, False otherwise

        Raises:
            RuntimeError: If backend is not DescriptorWalletBackend
        """
        if not isinstance(self.backend, DescriptorWalletBackend):
            raise RuntimeError(
                "check_and_upgrade_descriptor_range() requires DescriptorWalletBackend"
            )

        # Get current range
        current_range = await self.backend.get_max_descriptor_range()
        logger.debug(f"Current descriptor range: [0, {current_range}]")

        # Find highest used index across all mixdepths/branches
        highest_used = await self._find_highest_used_index_from_history()

        # Calculate required range
        required_range = highest_used + gap_limit + 1

        if required_range <= current_range:
            logger.debug(
                f"Descriptor range sufficient: highest used={highest_used}, "
                f"current range={current_range}"
            )
            return False

        # Need to upgrade
        logger.info(
            f"Upgrading descriptor range: highest used={highest_used}, "
            f"current={current_range}, new={required_range}"
        )

        # Generate descriptors with new range
        descriptors = self._generate_import_descriptors(required_range)

        # Upgrade (no rescan needed - addresses already exist in blockchain)
        await self.backend.upgrade_descriptor_ranges(descriptors, required_range, rescan=False)

        # Update our cached range
        self._current_descriptor_range = required_range

        logger.info(f"Descriptor range upgraded to [0, {required_range}]")
        return True

    async def _find_highest_used_index_from_history(self) -> int:
        """
        Find the highest address index that has ever been used.

        Uses addresses_with_history which is populated from Bitcoin Core's
        transaction history.

        Returns:
            Highest used address index, or -1 if no addresses used
        """
        highest_index = -1

        # Check addresses from blockchain history
        for address in self.addresses_with_history:
            if address in self.address_cache:
                _, _, index = self.address_cache[address]
                if index > highest_index:
                    highest_index = index

        # Also check current UTXOs
        for mixdepth in range(self.mixdepth_count):
            utxos = self.utxo_cache.get(mixdepth, [])
            for utxo in utxos:
                if utxo.address in self.address_cache:
                    _, _, index = self.address_cache[utxo.address]
                    if index > highest_index:
                        highest_index = index

        return highest_index

    async def _populate_address_cache(self, max_index: int) -> None:
        """
        Pre-populate the address cache for efficient address lookups.

        This derives addresses for all mixdepths and branches up to max_index,
        storing them in the address_cache for O(1) lookups during sync.

        Args:
            max_index: Maximum address index to derive (typically the descriptor range)
        """
        import time

        # Only populate if we haven't already cached enough addresses
        current_cache_size = len(self.address_cache)
        expected_size = self.mixdepth_count * 2 * max_index  # mixdepths * branches * indices

        # If cache already has enough entries, skip
        if current_cache_size >= expected_size * 0.9:  # 90% threshold
            logger.debug(f"Address cache already populated ({current_cache_size} entries)")
            return

        total_addresses = expected_size
        logger.info(
            f"Populating address cache for range [0, {max_index}] "
            f"({total_addresses:,} addresses)..."
        )

        start_time = time.time()
        count = 0
        last_log_time = start_time

        for mixdepth in range(self.mixdepth_count):
            for change in [0, 1]:
                for index in range(max_index):
                    # get_address automatically caches
                    self.get_address(mixdepth, change, index)
                    count += 1

                    # Log progress every 5 seconds for large caches
                    current_time = time.time()
                    if current_time - last_log_time >= 5.0:
                        progress = count / total_addresses * 100
                        elapsed = current_time - start_time
                        rate = count / elapsed if elapsed > 0 else 0
                        remaining = (total_addresses - count) / rate if rate > 0 else 0
                        logger.info(
                            f"Address cache progress: {count:,}/{total_addresses:,} "
                            f"({progress:.1f}%) - ETA: {remaining:.0f}s"
                        )
                        last_log_time = current_time

        elapsed = time.time() - start_time
        logger.info(
            f"Address cache populated with {len(self.address_cache):,} entries in {elapsed:.1f}s"
        )

    def _find_address_path(
        self, address: str, max_scan: int | None = None
    ) -> tuple[int, int, int] | None:
        """
        Find the derivation path for an address.

        First checks the cache, then checks the fidelity bond registry,
        then tries to derive and match.

        Args:
            address: Bitcoin address
            max_scan: Maximum index to scan per branch. If None, uses the current
                     descriptor range from _current_descriptor_range or DEFAULT_SCAN_RANGE.

        Returns:
            Tuple of (mixdepth, change, index) or None if not found
        """
        # Check cache first
        if address in self.address_cache:
            return self.address_cache[address]

        # Check fidelity bond registry if data_dir is available
        # Fidelity bond addresses use branch 2 and aren't in the normal cache
        if self.data_dir:
            try:
                from jmwallet.wallet.bond_registry import load_registry

                registry = load_registry(self.data_dir)
                bond = registry.get_bond_by_address(address)
                if bond is not None:
                    # Found in fidelity bond registry - cache it and return
                    path_info = (0, FIDELITY_BOND_BRANCH, bond.index)
                    self.address_cache[address] = path_info
                    # Also cache the locktime
                    self.fidelity_bond_locktime_cache[address] = bond.locktime
                    logger.debug(
                        f"Found address {address[:20]}... in fidelity bond registry "
                        f"(index={bond.index}, locktime={bond.locktime})"
                    )
                    return path_info
            except Exception as e:
                logger.trace(f"Could not check bond registry: {e}")

        # Determine scan range - use the current descriptor range if available
        if max_scan is None:
            max_scan = int(getattr(self, "_current_descriptor_range", DEFAULT_SCAN_RANGE))

        # Try to find by deriving addresses (expensive but necessary)
        # We must scan up to the descriptor range to find all addresses
        for mixdepth in range(self.mixdepth_count):
            for change in [0, 1]:
                for index in range(max_scan):
                    derived_addr = self.get_address(mixdepth, change, index)
                    if derived_addr == address:
                        return (mixdepth, change, index)

        return None

    def _find_address_path_extended(
        self, address: str, extend_by: int = 5000
    ) -> tuple[int, int, int] | None:
        """
        Find the derivation path for an address, searching beyond the current range.

        This is used for addresses from transaction history that might be at
        indices beyond the current descriptor range (e.g., from previous use
        with a different wallet software).

        Args:
            address: Bitcoin address
            extend_by: How far beyond the current range to search

        Returns:
            Tuple of (mixdepth, change, index) or None if not found
        """
        # Check cache first
        if address in self.address_cache:
            return self.address_cache[address]

        current_range = int(getattr(self, "_current_descriptor_range", DEFAULT_SCAN_RANGE))
        extended_max = current_range + extend_by

        # Search from current_range to extended_max (the normal range was already searched)
        for mixdepth in range(self.mixdepth_count):
            for change in [0, 1]:
                for index in range(current_range, extended_max):
                    derived_addr = self.get_address(mixdepth, change, index)
                    if derived_addr == address:
                        logger.info(
                            f"Found address at extended index {index} "
                            f"(beyond current range {current_range})"
                        )
                        return (mixdepth, change, index)

        return None

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

    async def get_balance(self, mixdepth: int, include_fidelity_bonds: bool = True) -> int:
        """Get balance for a mixdepth.

        Args:
            mixdepth: Mixdepth to get balance for
            include_fidelity_bonds: If True (default), include fidelity bond UTXOs.
                                    If False, exclude fidelity bond UTXOs.

        Note:
            Frozen UTXOs are excluded from balance calculations.
        """
        if mixdepth not in self.utxo_cache:
            await self.sync_mixdepth(mixdepth)

        utxos = self.utxo_cache.get(mixdepth, [])
        utxos = [u for u in utxos if not u.frozen]
        if not include_fidelity_bonds:
            utxos = [u for u in utxos if not u.is_fidelity_bond]
        return sum(utxo.value for utxo in utxos)

    async def get_balance_for_offers(self, mixdepth: int) -> int:
        """Get balance available for maker offers (excludes fidelity bond UTXOs).

        Fidelity bonds should never be automatically spent in CoinJoins,
        so makers must exclude them when calculating available offer amounts.
        """
        return await self.get_balance(mixdepth, include_fidelity_bonds=False)

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

    async def get_total_balance(self, include_fidelity_bonds: bool = True) -> int:
        """Get total balance across all mixdepths.

        Args:
            include_fidelity_bonds: If True (default), include fidelity bond UTXOs.
                                    If False, exclude fidelity bond UTXOs.

        Note:
            Frozen UTXOs are excluded from balance calculations.
        """
        total = 0
        for mixdepth in range(self.mixdepth_count):
            balance = await self.get_balance(
                mixdepth, include_fidelity_bonds=include_fidelity_bonds
            )
            total += balance
        return total

    async def get_fidelity_bond_balance(self, mixdepth: int) -> int:
        """Get balance of fidelity bond UTXOs for a mixdepth."""
        if mixdepth not in self.utxo_cache:
            await self.sync_mixdepth(mixdepth)

        utxos = self.utxo_cache.get(mixdepth, [])
        return sum(utxo.value for utxo in utxos if utxo.is_fidelity_bond)

    def select_utxos(
        self,
        mixdepth: int,
        target_amount: int,
        min_confirmations: int = 1,
        include_utxos: list[UTXOInfo] | None = None,
        include_fidelity_bonds: bool = False,
    ) -> list[UTXOInfo]:
        """
        Select UTXOs for spending from a mixdepth.
        Uses simple greedy selection strategy.

        Args:
            mixdepth: Mixdepth to select from
            target_amount: Target amount in satoshis
            min_confirmations: Minimum confirmations required
            include_utxos: List of UTXOs that MUST be included in selection
            include_fidelity_bonds: If True, include fidelity bond UTXOs in automatic
                                    selection. Defaults to False to prevent accidentally
                                    spending bonds.
        """
        utxos = self.utxo_cache.get(mixdepth, [])

        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]

        # Filter out frozen UTXOs (never auto-selected)
        eligible = [utxo for utxo in eligible if not utxo.frozen]

        # Filter out fidelity bond UTXOs by default
        if not include_fidelity_bonds:
            eligible = [utxo for utxo in eligible if not utxo.is_fidelity_bond]

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
        include_fidelity_bonds: bool = False,
    ) -> list[UTXOInfo]:
        """
        Get all UTXOs from a mixdepth for sweep operations.

        Unlike select_utxos(), this returns ALL eligible UTXOs regardless of
        target amount. Used for sweep mode to ensure no change output.

        Args:
            mixdepth: Mixdepth to get UTXOs from
            min_confirmations: Minimum confirmations required
            include_fidelity_bonds: If True, include fidelity bond UTXOs.
                                    Defaults to False to prevent accidentally
                                    spending bonds in sweeps.

        Returns:
            List of all eligible UTXOs in the mixdepth
        """
        utxos = self.utxo_cache.get(mixdepth, [])
        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]
        # Filter out frozen UTXOs (never auto-selected)
        eligible = [utxo for utxo in eligible if not utxo.frozen]
        if not include_fidelity_bonds:
            eligible = [utxo for utxo in eligible if not utxo.is_fidelity_bond]
        return eligible

    def select_utxos_with_merge(
        self,
        mixdepth: int,
        target_amount: int,
        min_confirmations: int = 1,
        merge_algorithm: str = "default",
        include_fidelity_bonds: bool = False,
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
            include_fidelity_bonds: If True, include fidelity bond UTXOs.
                                    Defaults to False since they should never be
                                    automatically spent in CoinJoins.

        Returns:
            List of selected UTXOs

        Raises:
            ValueError: If insufficient funds
        """
        import random as rand_module

        utxos = self.utxo_cache.get(mixdepth, [])
        eligible = [utxo for utxo in utxos if utxo.confirmations >= min_confirmations]

        # Filter out frozen UTXOs (never auto-selected)
        eligible = [utxo for utxo in eligible if not utxo.frozen]

        # Filter out fidelity bond UTXOs by default
        if not include_fidelity_bonds:
            eligible = [utxo for utxo in eligible if not utxo.is_fidelity_bond]

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

        Returns the highest index + 1 among all addresses that have ever been used,
        ensuring we never reuse addresses. An address is considered "used" if it:
        - Has current UTXOs
        - Had UTXOs in the past (tracked in addresses_with_history)
        - Appears in CoinJoin history (even if never funded)

        We always return one past the highest used index, even if lower indices
        appear unused. Those may have been skipped for a reason (e.g., shared in
        a failed CoinJoin, or spent in an internal transfer).
        """
        max_index = -1

        # Check addresses with current UTXOs
        utxos = self.utxo_cache.get(mixdepth, [])
        for utxo in utxos:
            if utxo.address in self.address_cache:
                md, ch, idx = self.address_cache[utxo.address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        # Check addresses that ever had blockchain activity (including spent)
        for address in self.addresses_with_history:
            if address in self.address_cache:
                md, ch, idx = self.address_cache[address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        # Check CoinJoin history for addresses that may have been shared
        # but never received funds (e.g., failed CoinJoins)
        if self.data_dir:
            from jmwallet.history import get_used_addresses

            cj_addresses = get_used_addresses(self.data_dir)
            for address in cj_addresses:
                if address in self.address_cache:
                    md, ch, idx = self.address_cache[address]
                    if md == mixdepth and ch == change and idx > max_index:
                        max_index = idx

        # Check addresses reserved for in-progress CoinJoin sessions
        # These have been shared with takers but the session hasn't completed yet
        for address in self.reserved_addresses:
            if address in self.address_cache:
                md, ch, idx = self.address_cache[address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        return max_index + 1

    def reserve_addresses(self, addresses: set[str]) -> None:
        """
        Reserve addresses for an in-progress CoinJoin session.

        Once addresses are shared with a taker (in !ioauth message), they must not
        be reused even if the CoinJoin fails. This method marks addresses as reserved
        so get_next_address_index() will skip past them.

        Note: Addresses stay reserved until the wallet is restarted, since they may
        have been logged by counterparties. The CoinJoin history file provides
        persistent tracking across restarts.

        Args:
            addresses: Set of addresses to reserve (typically cj_address + change_address)
        """
        self.reserved_addresses.update(addresses)
        logger.debug(f"Reserved {len(addresses)} addresses: {addresses}")

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

    def _apply_frozen_state(self) -> None:
        """Apply frozen state from metadata store to all cached UTXOs.

        Called after sync operations to mark UTXOs that are frozen according
        to the persisted metadata. Also applies labels from metadata.

        Re-reads the metadata file from disk on each call to pick up changes
        made by other processes (e.g., ``jm-wallet freeze`` while maker is running).
        """
        if self.metadata_store is None:
            return

        # Re-read from disk to pick up changes from other processes
        self.metadata_store.load()

        frozen_outpoints = self.metadata_store.get_frozen_outpoints()

        frozen_count = 0
        for utxos in self.utxo_cache.values():
            for utxo in utxos:
                outpoint = utxo.outpoint
                utxo.frozen = outpoint in frozen_outpoints
                if utxo.frozen:
                    frozen_count += 1
                # Apply label from metadata if not already set
                stored_label = self.metadata_store.get_label(outpoint)
                if stored_label is not None and utxo.label is None:
                    utxo.label = stored_label

        if frozen_count > 0:
            logger.debug(f"Applied frozen state to {frozen_count} UTXO(s)")

    def freeze_utxo(self, outpoint: str) -> None:
        """Freeze a UTXO by outpoint (persisted to disk).

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Raises:
            RuntimeError: If no metadata store is available (no data_dir).
        """
        if self.metadata_store is None:
            raise RuntimeError("Cannot freeze UTXOs without a data directory")
        self.metadata_store.freeze(outpoint)
        # Update the in-memory UTXO cache
        for utxos in self.utxo_cache.values():
            for utxo in utxos:
                if utxo.outpoint == outpoint:
                    utxo.frozen = True
                    return

    def unfreeze_utxo(self, outpoint: str) -> None:
        """Unfreeze a UTXO by outpoint (persisted to disk).

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Raises:
            RuntimeError: If no metadata store is available (no data_dir).
        """
        if self.metadata_store is None:
            raise RuntimeError("Cannot unfreeze UTXOs without a data directory")
        self.metadata_store.unfreeze(outpoint)
        # Update the in-memory UTXO cache
        for utxos in self.utxo_cache.values():
            for utxo in utxos:
                if utxo.outpoint == outpoint:
                    utxo.frozen = False
                    return

    def toggle_freeze_utxo(self, outpoint: str) -> bool:
        """Toggle frozen state of a UTXO by outpoint (persisted to disk).

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Returns:
            True if now frozen, False if now unfrozen.

        Raises:
            RuntimeError: If no metadata store is available (no data_dir).
        """
        if self.metadata_store is None:
            raise RuntimeError("Cannot toggle freeze without a data directory")
        now_frozen = self.metadata_store.toggle_freeze(outpoint)
        # Update the in-memory UTXO cache
        for utxos in self.utxo_cache.values():
            for utxo in utxos:
                if utxo.outpoint == outpoint:
                    utxo.frozen = now_frozen
                    break
        return now_frozen

    def is_utxo_frozen(self, outpoint: str) -> bool:
        """Check if a UTXO is frozen.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Returns:
            True if frozen, False otherwise.
        """
        if self.metadata_store is None:
            return False
        return self.metadata_store.is_frozen(outpoint)

    def get_address_info_for_mixdepth(
        self,
        mixdepth: int,
        change: int,
        gap_limit: int = 6,
        used_addresses: set[str] | None = None,
        history_addresses: dict[str, str] | None = None,
    ) -> list[AddressInfo]:
        """
        Get detailed address information for a mixdepth branch.

        This generates a list of AddressInfo objects for addresses in the
        specified mixdepth and branch (external or internal), up to the
        specified gap limit beyond the last used address.

        Args:
            mixdepth: The mixdepth (account) number (0-4)
            change: Branch (0 for external/receive, 1 for internal/change)
            gap_limit: Number of empty addresses to show beyond last used
            used_addresses: Set of addresses that were used in CoinJoin history
            history_addresses: Dict mapping address -> status from history

        Returns:
            List of AddressInfo objects for display
        """
        if used_addresses is None:
            used_addresses = set()
        if history_addresses is None:
            history_addresses = {}

        is_external = change == 0
        addresses: list[AddressInfo] = []

        # Get UTXOs for this mixdepth
        utxos = self.utxo_cache.get(mixdepth, [])

        # Build maps of address -> balance and address -> has_unconfirmed
        address_balances: dict[str, int] = {}
        address_unconfirmed: dict[str, bool] = {}
        for utxo in utxos:
            if utxo.address not in address_balances:
                address_balances[utxo.address] = 0
                address_unconfirmed[utxo.address] = False
            address_balances[utxo.address] += utxo.value
            # Track if any UTXO at this address is unconfirmed (0 confirmations)
            if utxo.confirmations == 0:
                address_unconfirmed[utxo.address] = True

        # Find the highest index with funds or history
        max_used_index = -1
        for address, (md, ch, idx) in self.address_cache.items():
            if md == mixdepth and ch == change:
                has_balance = address in address_balances
                # Check both CoinJoin history AND general blockchain activity
                has_history = address in used_addresses or address in self.addresses_with_history
                if has_balance or has_history:
                    if idx > max_used_index:
                        max_used_index = idx

        # Also check UTXOs directly
        for utxo in utxos:
            if utxo.address in self.address_cache:
                md, ch, idx = self.address_cache[utxo.address]
                if md == mixdepth and ch == change and idx > max_used_index:
                    max_used_index = idx

        # Generate addresses from 0 to max_used_index + gap_limit
        end_index = max(0, max_used_index + 1 + gap_limit)

        for index in range(end_index):
            address = self.get_address(mixdepth, change, index)
            path = f"{self.root_path}/{mixdepth}'/{change}/{index}"
            balance = address_balances.get(address, 0)

            # Determine status
            status = self._determine_address_status(
                address=address,
                balance=balance,
                is_external=is_external,
                used_addresses=used_addresses,
                history_addresses=history_addresses,
            )

            addresses.append(
                AddressInfo(
                    address=address,
                    index=index,
                    balance=balance,
                    status=status,
                    path=path,
                    is_external=is_external,
                    has_unconfirmed=address_unconfirmed.get(address, False),
                )
            )

        return addresses

    def _determine_address_status(
        self,
        address: str,
        balance: int,
        is_external: bool,
        used_addresses: set[str],
        history_addresses: dict[str, str],
    ) -> AddressStatus:
        """
        Determine the status label for an address.

        Args:
            address: The address to check
            balance: Current balance in satoshis
            is_external: True if external (receive) address
            used_addresses: Set of addresses used in CoinJoin history
            history_addresses: Dict mapping address -> type (cj_out, change, etc.)

        Returns:
            Status string for display
        """
        # Check if it was used in CoinJoin history
        history_type = history_addresses.get(address)

        if balance > 0:
            # Has funds
            if history_type == "cj_out":
                return "cj-out"
            elif history_type == "change":
                return "non-cj-change"
            elif is_external:
                return "deposit"
            else:
                # Internal address with funds but not from CJ
                return "non-cj-change"
        else:
            # No funds
            # Check if address was used in CoinJoin history OR had blockchain activity
            was_used_in_cj = address in used_addresses
            had_blockchain_activity = address in self.addresses_with_history

            if was_used_in_cj or had_blockchain_activity:
                # Was used but now empty
                if history_type == "cj_out":
                    return "used-empty"  # CJ output that was spent
                elif history_type == "change":
                    return "used-empty"  # Change that was spent
                elif history_type == "flagged":
                    return "flagged"  # Shared but tx failed
                else:
                    return "used-empty"
            else:
                return "new"

    def get_next_after_last_used_address(
        self,
        mixdepth: int,
        used_addresses: set[str] | None = None,
    ) -> tuple[str, int]:
        """
        Get the next receive address after the last used one for a mixdepth.

        This returns the address at (highest used index + 1). The highest used index
        is determined by checking blockchain history, UTXOs, and CoinJoin history.
        If no address has been used yet, returns index 0.

        This is useful for wallet info display, showing the next address to use
        after the last one that was used in any way, ignoring any gaps in the sequence.

        Args:
            mixdepth: The mixdepth (account) number
            used_addresses: Set of addresses that were used/flagged in CoinJoins

        Returns:
            Tuple of (address, index)
        """
        if used_addresses is None:
            if self.data_dir:
                from jmwallet.history import get_used_addresses

                used_addresses = get_used_addresses(self.data_dir)
            else:
                used_addresses = set()

        max_index = -1
        change = 0  # external/receive chain

        # Check addresses with current UTXOs
        utxos = self.utxo_cache.get(mixdepth, [])
        for utxo in utxos:
            if utxo.address in self.address_cache:
                md, ch, idx = self.address_cache[utxo.address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        # Check addresses that ever had blockchain activity (including spent)
        for address in self.addresses_with_history:
            if address in self.address_cache:
                md, ch, idx = self.address_cache[address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        # Check CoinJoin history for addresses that may have been shared
        for address in used_addresses:
            if address in self.address_cache:
                md, ch, idx = self.address_cache[address]
                if md == mixdepth and ch == change and idx > max_index:
                    max_index = idx

        # Return next index after the last used (or 0 if none used)
        next_index = max_index + 1

        address = self.get_receive_address(mixdepth, next_index)
        return address, next_index

    def get_next_unused_unflagged_address(
        self,
        mixdepth: int,
        used_addresses: set[str] | None = None,
    ) -> tuple[str, int]:
        """
        Get the next unused and unflagged receive address for a mixdepth.

        An address is considered "used" if it has blockchain history (received/spent funds).
        An address is considered "flagged" if it was shared with peers in a
        CoinJoin attempt (even if the transaction failed). These should not
        be reused for privacy.

        This method starts from the next index after the highest used address
        (based on blockchain history, UTXOs, and CoinJoin history), ensuring
        we never reuse addresses that have been seen on-chain.

        Args:
            mixdepth: The mixdepth (account) number
            used_addresses: Set of addresses that were used/flagged in CoinJoins

        Returns:
            Tuple of (address, index)
        """
        if used_addresses is None:
            if self.data_dir:
                from jmwallet.history import get_used_addresses

                used_addresses = get_used_addresses(self.data_dir)
            else:
                used_addresses = set()

        # Start from the next address after the highest used one
        # This accounts for blockchain history, UTXOs, and CoinJoin history
        index = self.get_next_address_index(mixdepth, 0)  # 0 = external/receive chain
        max_attempts = 1000  # Safety limit

        for _ in range(max_attempts):
            address = self.get_receive_address(mixdepth, index)
            if address not in used_addresses:
                return address, index
            index += 1

        raise RuntimeError(f"Could not find unused address after {max_attempts} attempts")

    def get_fidelity_bond_addresses_info(
        self,
        max_gap: int = 6,
    ) -> list[AddressInfo]:
        """
        Get information about fidelity bond addresses.

        Args:
            max_gap: Maximum gap of empty addresses to show

        Returns:
            List of AddressInfo for fidelity bond addresses
        """
        addresses: list[AddressInfo] = []

        if not hasattr(self, "fidelity_bond_locktime_cache"):
            return addresses

        # Get UTXOs that are fidelity bonds (in mixdepth 0)
        utxos = self.utxo_cache.get(0, [])
        bond_utxos = [u for u in utxos if u.is_timelocked]

        # Build address -> balance map and address -> has_unconfirmed map for bonds
        address_balances: dict[str, int] = {}
        address_unconfirmed: dict[str, bool] = {}
        for utxo in bond_utxos:
            if utxo.address not in address_balances:
                address_balances[utxo.address] = 0
                address_unconfirmed[utxo.address] = False
            address_balances[utxo.address] += utxo.value
            if utxo.confirmations == 0:
                address_unconfirmed[utxo.address] = True

        for address, locktime in self.fidelity_bond_locktime_cache.items():
            if address in self.address_cache:
                _, _, index = self.address_cache[address]
                balance = address_balances.get(address, 0)
                path = f"{self.root_path}/0'/{FIDELITY_BOND_BRANCH}/{index}:{locktime}"

                addresses.append(
                    AddressInfo(
                        address=address,
                        index=index,
                        balance=balance,
                        status="bond",
                        path=path,
                        is_external=False,
                        is_bond=True,
                        locktime=locktime,
                        has_unconfirmed=address_unconfirmed.get(address, False),
                    )
                )

        # Sort by locktime
        addresses.sort(key=lambda a: (a.locktime or 0, a.index))
        return addresses
