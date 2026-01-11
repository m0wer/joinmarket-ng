"""
Bitcoin Core Descriptor Wallet backend.

Uses descriptor wallets with importdescriptors RPC for efficient UTXO tracking.
This is much faster than scantxoutset for ongoing wallet operations as Bitcoin Core
maintains the UTXO state automatically.

Key advantages over scantxoutset:
1. Persistent tracking: Once descriptors are imported, UTXOs are tracked automatically
2. Real-time updates: Balance updates as blocks arrive, no need for full UTXO set scan
3. Efficient queries: listunspent is O(wallet UTXOs) vs O(entire UTXO set) for scantxoutset
4. Mempool awareness: Can see unconfirmed transactions immediately

Trade-offs:
1. Requires wallet creation/management on Bitcoin Core side
2. Wallet files persist on disk (privacy consideration)
3. Initial import can take time for large descriptor ranges
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

import httpx
from jmcore.bitcoin import btc_to_sats
from loguru import logger

from jmwallet.backends.base import UTXO, BlockchainBackend, Transaction

# Timeout for regular RPC calls (seconds)
DEFAULT_RPC_TIMEOUT = 30.0

# Timeout for descriptor import - can take a while for large ranges
IMPORT_RPC_TIMEOUT = 120.0

# Default gap limit for descriptor ranges
DEFAULT_GAP_LIMIT = 1000

# Environment variable to enable sensitive logging (descriptors, addresses, etc.)
SENSITIVE_LOGGING = os.environ.get("SENSITIVE_LOGGING", "").lower() in ("1", "true", "yes")


class DescriptorWalletBackend(BlockchainBackend):
    """
    Blockchain backend using Bitcoin Core descriptor wallets.

    This backend creates and manages a descriptor wallet in Bitcoin Core,
    importing xpub descriptors for efficient UTXO tracking. Once imported,
    Bitcoin Core automatically tracks UTXOs and provides fast queries via listunspent.

    Usage:
        backend = DescriptorWalletBackend(
            rpc_url="http://127.0.0.1:8332",
            rpc_user="user",
            rpc_password="pass",
            wallet_name="jm_wallet",
        )

        # Setup wallet and import descriptors (one-time or on startup)
        await backend.setup_wallet(descriptors)

        # Fast UTXO queries - no more full UTXO set scans
        utxos = await backend.get_utxos(addresses)
    """

    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:18443",
        rpc_user: str = "rpcuser",
        rpc_password: str = "rpcpassword",
        wallet_name: str = "jm_descriptor_wallet",
        import_timeout: float = IMPORT_RPC_TIMEOUT,
    ):
        """
        Initialize descriptor wallet backend.

        Args:
            rpc_url: Bitcoin Core RPC URL
            rpc_user: RPC username
            rpc_password: RPC password
            wallet_name: Name for the descriptor wallet in Bitcoin Core
            import_timeout: Timeout for descriptor import operations
        """
        self.rpc_url = rpc_url.rstrip("/")
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.wallet_name = wallet_name
        self.import_timeout = import_timeout

        # Client for regular RPC calls
        self.client = httpx.AsyncClient(timeout=DEFAULT_RPC_TIMEOUT, auth=(rpc_user, rpc_password))
        # Client for long-running import operations
        self._import_client = httpx.AsyncClient(
            timeout=import_timeout, auth=(rpc_user, rpc_password)
        )
        self._request_id = 0

        # Track if wallet is setup
        self._wallet_loaded = False
        self._descriptors_imported = False

    def _get_wallet_url(self) -> str:
        """Get the RPC URL for wallet-specific calls."""
        return f"{self.rpc_url}/wallet/{self.wallet_name}"

    async def _rpc_call(
        self,
        method: str,
        params: list | None = None,
        client: httpx.AsyncClient | None = None,
        use_wallet: bool = True,
    ) -> Any:
        """
        Make an RPC call to Bitcoin Core.

        Args:
            method: RPC method name
            params: Method parameters
            client: Optional httpx client (uses default client if not provided)
            use_wallet: If True, use wallet-specific URL

        Returns:
            RPC result

        Raises:
            ValueError: On RPC errors
            httpx.HTTPError: On connection/timeout errors
        """
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or [],
        }

        use_client = client or self.client
        url = self._get_wallet_url() if use_wallet and self._wallet_loaded else self.rpc_url

        try:
            response = await use_client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            if "error" in data and data["error"]:
                error_info = data["error"]
                error_code = error_info.get("code", "unknown")
                error_msg = error_info.get("message", str(error_info))
                raise ValueError(f"RPC error {error_code}: {error_msg}")

            return data.get("result")

        except httpx.TimeoutException as e:
            logger.error(f"RPC call timed out: {method} - {e}")
            raise
        except httpx.HTTPError as e:
            logger.error(f"RPC call failed: {method} - {e}")
            raise

    async def create_wallet(self, disable_private_keys: bool = True) -> bool:
        """
        Create a descriptor wallet in Bitcoin Core.

        Args:
            disable_private_keys: If True, creates a watch-only wallet (recommended)

        Returns:
            True if wallet was created or already exists
        """
        try:
            # First check if wallet already exists
            wallets = await self._rpc_call("listwallets", use_wallet=False)
            if self.wallet_name in wallets:
                logger.info(f"Wallet '{self.wallet_name}' already loaded")
                self._wallet_loaded = True
                return True

            # Try to load existing wallet
            try:
                await self._rpc_call("loadwallet", [self.wallet_name], use_wallet=False)
                logger.info(f"Loaded existing wallet '{self.wallet_name}'")
                self._wallet_loaded = True
                return True
            except ValueError as e:
                error_str = str(e).lower()
                # RPC error -18 is "Wallet not found" or "Path does not exist"
                not_found_errs = ("not found", "does not exist", "-18")
                if not any(err in error_str for err in not_found_errs):
                    raise

            # Create new descriptor wallet
            # Params: wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
            result = await self._rpc_call(
                "createwallet",
                [
                    self.wallet_name,  # wallet_name
                    disable_private_keys,  # disable_private_keys
                    True,  # blank (no default keys)
                    "",  # passphrase
                    False,  # avoid_reuse
                    True,  # descriptors (MUST be True for descriptor wallet)
                ],
                use_wallet=False,
            )

            logger.info(f"Created descriptor wallet '{self.wallet_name}': {result}")
            self._wallet_loaded = True
            return True

        except Exception as e:
            logger.error(f"Failed to create/load wallet: {e}")
            raise

    async def import_descriptors(
        self,
        descriptors: Sequence[str | dict[str, Any]],
        rescan: bool = True,
        timestamp: str | int | None = None,
    ) -> dict[str, Any]:
        """
        Import descriptors into the wallet.

        This is the key operation that enables efficient UTXO tracking. Once imported,
        Bitcoin Core will automatically track all addresses derived from these descriptors.

        Args:
            descriptors: List of output descriptors. Can be:
                - Simple strings: "wpkh(xpub.../0/*)"
                - Dicts with range: {"desc": "wpkh(xpub.../0/*)", "range": [0, 999]}
            rescan: If True, rescan blockchain from genesis (timestamp=0).
                   If False, only track new transactions (timestamp="now").
            timestamp: Override timestamp. If None, uses 0 (rescan=True) or "now" (rescan=False).
                      Can be Unix timestamp for partial rescan from specific time.

        Returns:
            Import result from Bitcoin Core

        Example:
            # Import and rescan entire blockchain (slow on mainnet)
            await backend.import_descriptors([
                {"desc": "wpkh(xpub.../0/*)", "range": [0, 999], "internal": False},
            ], rescan=True)

            # Import without rescanning (for new wallets with no history)
            await backend.import_descriptors([...], rescan=False)
        """
        if not self._wallet_loaded:
            raise RuntimeError("Wallet not loaded. Call create_wallet() first.")

        # Determine timestamp based on rescan parameter if not explicitly provided
        if timestamp is None:
            timestamp = 0 if rescan else "now"

        # Format descriptors for importdescriptors RPC
        import_requests = []
        for desc in descriptors:
            if isinstance(desc, str):
                # Add checksum if not present
                desc_with_checksum = await self._add_descriptor_checksum(desc)
                import_requests.append(
                    {
                        "desc": desc_with_checksum,
                        "timestamp": timestamp,
                        "active": True,  # Track this descriptor actively
                        "internal": False,
                    }
                )
            elif isinstance(desc, dict):
                desc_str = desc.get("desc", "")
                desc_with_checksum = await self._add_descriptor_checksum(desc_str)
                request = {
                    "desc": desc_with_checksum,
                    "timestamp": timestamp,
                    "active": True,
                }
                if "range" in desc:
                    request["range"] = desc["range"]
                if "internal" in desc:
                    request["internal"] = desc["internal"]
                import_requests.append(request)

        if SENSITIVE_LOGGING:
            logger.debug(f"Importing {len(import_requests)} descriptor(s): {import_requests}")
        else:
            rescan_info = (
                "from genesis (timestamp=0)" if timestamp == 0 else f"timestamp={timestamp}"
            )
            logger.info(
                f"Importing {len(import_requests)} descriptor(s) into wallet "
                f"(rescan={rescan}, {rescan_info})..."
            )

        try:
            result = await self._rpc_call(
                "importdescriptors", [import_requests], client=self._import_client
            )

            # Check for errors in results
            success_count = sum(1 for r in result if r.get("success", False))
            error_count = len(result) - success_count

            if error_count > 0:
                errors = [
                    r.get("error", {}).get("message", "unknown")
                    for r in result
                    if not r.get("success", False)
                ]
                logger.warning(f"Import completed with {error_count} error(s): {errors}")
                # Log full results for debugging
                for i, r in enumerate(result):
                    if not r.get("success", False):
                        logger.debug(f"  Descriptor {i} failed: {r}")
            else:
                logger.info(f"Successfully imported {success_count} descriptor(s)")

            # Verify import by listing descriptors
            try:
                verify_result = await self._rpc_call("listdescriptors")
                actual_count = len(verify_result.get("descriptors", []))
                logger.debug(f"Verification: wallet now has {actual_count} descriptor(s)")
                if actual_count == 0 and success_count > 0:
                    logger.error(
                        f"CRITICAL: Import reported {success_count} successes but wallet has "
                        f"0 descriptors! This may indicate a Bitcoin Core bug or wallet issue."
                    )
            except Exception as e:
                logger.warning(f"Could not verify descriptor import: {e}")

            self._descriptors_imported = True
            return {"success_count": success_count, "error_count": error_count, "results": result}

        except Exception as e:
            logger.error(f"Failed to import descriptors: {e}")
            raise

    async def _add_descriptor_checksum(self, descriptor: str) -> str:
        """Add checksum to descriptor if not present."""
        if "#" in descriptor:
            return descriptor  # Already has checksum

        try:
            result = await self._rpc_call("getdescriptorinfo", [descriptor], use_wallet=False)
            return result.get("descriptor", descriptor)
        except Exception as e:
            logger.warning(f"Failed to get descriptor checksum: {e}")
            return descriptor

    async def setup_wallet(
        self,
        descriptors: Sequence[str | dict[str, Any]],
        rescan: bool = True,
    ) -> bool:
        """
        Complete wallet setup: create wallet and import descriptors.

        This is a convenience method for initial setup.

        Args:
            descriptors: Descriptors to import
            rescan: Whether to rescan blockchain (can be slow for mainnet)

        Returns:
            True if setup completed successfully
        """
        await self.create_wallet(disable_private_keys=True)
        await self.import_descriptors(descriptors, rescan=rescan)
        return True

    async def list_descriptors(self) -> list[dict[str, Any]]:
        """
        List all descriptors currently imported in the wallet.

        Returns:
            List of descriptor info dicts with fields like 'desc', 'timestamp', 'active', etc.

        Example:
            descriptors = await backend.list_descriptors()
            for d in descriptors:
                print(f"Descriptor: {d['desc']}, Active: {d.get('active', False)}")
        """
        if not self._wallet_loaded:
            raise RuntimeError("Wallet not loaded. Call create_wallet() first.")

        try:
            result = await self._rpc_call("listdescriptors")
            return result.get("descriptors", [])
        except Exception as e:
            logger.error(f"Failed to list descriptors: {e}")
            raise

    async def is_wallet_setup(self, expected_descriptor_count: int | None = None) -> bool:
        """
        Check if wallet is already set up with imported descriptors.

        Args:
            expected_descriptor_count: If provided, verifies this many descriptors are imported.
                                      For JoinMarket: 2 per mixdepth (external + internal)
                                      Example: 5 mixdepths = 10 descriptors minimum

        Returns:
            True if wallet exists and has descriptors imported

        Example:
            # Check if wallet is set up for 5 mixdepths
            if await backend.is_wallet_setup(expected_descriptor_count=10):
                # Already set up, just sync
                utxos = await wallet.sync_with_descriptor_wallet()
            else:
                # First time - import descriptors
                await wallet.setup_descriptor_wallet(rescan=True)
        """
        try:
            # Check if wallet exists and is loaded
            wallets = await self._rpc_call("listwallets", use_wallet=False)
            if self.wallet_name in wallets:
                self._wallet_loaded = True
            else:
                # Try to load it
                try:
                    await self._rpc_call("loadwallet", [self.wallet_name], use_wallet=False)
                    self._wallet_loaded = True
                except ValueError:
                    return False

            # Check if descriptors are imported
            descriptors = await self.list_descriptors()
            if not descriptors:
                return False

            # If expected count provided, verify
            if expected_descriptor_count is not None:
                return len(descriptors) >= expected_descriptor_count

            return True

        except Exception as e:
            logger.debug(f"Wallet setup check failed: {e}")
            return False

    async def get_utxos(self, addresses: list[str]) -> list[UTXO]:
        """
        Get UTXOs for given addresses using listunspent.

        This is MUCH faster than scantxoutset because:
        1. Only queries wallet's tracked UTXOs (not entire UTXO set)
        2. Includes unconfirmed transactions from mempool
        3. O(wallet size) instead of O(UTXO set size)

        Args:
            addresses: List of addresses to filter by (empty = all wallet UTXOs)

        Returns:
            List of UTXOs
        """
        if not self._wallet_loaded:
            logger.warning("Wallet not loaded, returning empty UTXO list")
            return []

        try:
            # listunspent params: minconf, maxconf, addresses, include_unsafe, query_options
            # minconf=0 includes unconfirmed, maxconf=9999999 includes all confirmed
            # NOTE: When addresses is empty, we must omit it entirely (not pass [])
            # because Bitcoin Core interprets [] as "filter to 0 addresses" = return nothing
            if addresses:
                # Filter to specific addresses
                result = await self._rpc_call(
                    "listunspent",
                    [
                        0,  # minconf - include unconfirmed
                        9999999,  # maxconf
                        addresses,  # filter addresses
                        True,  # include_unsafe (include unconfirmed from mempool)
                    ],
                )
            else:
                # Get all wallet UTXOs - omit addresses parameter
                result = await self._rpc_call(
                    "listunspent",
                    [
                        0,  # minconf - include unconfirmed
                        9999999,  # maxconf
                    ],
                )

            utxos = []
            for utxo_data in result:
                utxo = UTXO(
                    txid=utxo_data["txid"],
                    vout=utxo_data["vout"],
                    value=btc_to_sats(utxo_data["amount"]),
                    address=utxo_data.get("address", ""),
                    confirmations=utxo_data.get("confirmations", 0),
                    scriptpubkey=utxo_data.get("scriptPubKey", ""),
                    height=None,  # listunspent doesn't provide block height directly
                )
                utxos.append(utxo)

            logger.debug(f"Found {len(utxos)} UTXOs via listunspent")
            return utxos

        except Exception as e:
            logger.error(f"Failed to get UTXOs via listunspent: {e}")
            return []

    async def get_all_utxos(self) -> list[UTXO]:
        """
        Get all UTXOs tracked by the wallet.

        Returns:
            List of all wallet UTXOs
        """
        return await self.get_utxos([])

    async def get_address_balance(self, address: str) -> int:
        """Get balance for an address in satoshis."""
        utxos = await self.get_utxos([address])
        return sum(utxo.value for utxo in utxos)

    async def get_wallet_balance(self) -> dict[str, int]:
        """
        Get total wallet balance including unconfirmed.

        Returns:
            Dict with 'confirmed', 'unconfirmed', 'total' balances in satoshis
        """
        try:
            result = await self._rpc_call("getbalances")
            mine = result.get("mine", {})
            confirmed = btc_to_sats(mine.get("trusted", 0))
            unconfirmed = btc_to_sats(mine.get("untrusted_pending", 0))
            return {
                "confirmed": confirmed,
                "unconfirmed": unconfirmed,
                "total": confirmed + unconfirmed,
            }
        except Exception as e:
            logger.error(f"Failed to get wallet balance: {e}")
            return {"confirmed": 0, "unconfirmed": 0, "total": 0}

    async def broadcast_transaction(self, tx_hex: str) -> str:
        """Broadcast transaction, returns txid."""
        try:
            txid = await self._rpc_call("sendrawtransaction", [tx_hex], use_wallet=False)
            logger.info(f"Broadcast transaction: {txid}")
            return txid
        except Exception as e:
            logger.error(f"Failed to broadcast transaction: {e}")
            raise ValueError(f"Broadcast failed: {e}") from e

    async def get_transaction(self, txid: str) -> Transaction | None:
        """Get transaction by txid."""
        try:
            # First try wallet transaction for extra info
            try:
                tx_data = await self._rpc_call("gettransaction", [txid, True])
                confirmations = tx_data.get("confirmations", 0)
                block_height = tx_data.get("blockheight")
                block_time = tx_data.get("blocktime")
                raw_hex = tx_data.get("hex", "")
            except ValueError:
                # Fall back to getrawtransaction if not in wallet
                tx_data = await self._rpc_call("getrawtransaction", [txid, True], use_wallet=False)
                if not tx_data:
                    return None
                confirmations = tx_data.get("confirmations", 0)
                block_height = None
                block_time = None
                if "blockhash" in tx_data:
                    block_info = await self._rpc_call(
                        "getblockheader", [tx_data["blockhash"]], use_wallet=False
                    )
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
            logger.warning(f"Failed to get transaction {txid}: {e}")
            return None

    async def estimate_fee(self, target_blocks: int) -> float:
        """Estimate fee in sat/vbyte for target confirmation blocks."""
        try:
            result = await self._rpc_call("estimatesmartfee", [target_blocks], use_wallet=False)
            if "feerate" in result:
                btc_per_kb = result["feerate"]
                sat_per_vbyte = btc_to_sats(btc_per_kb) / 1000
                return sat_per_vbyte
            else:
                logger.warning("Fee estimation unavailable, using fallback")
                return 1.0
        except Exception as e:
            logger.warning(f"Failed to estimate fee: {e}, using fallback")
            return 1.0

    async def get_block_height(self) -> int:
        """Get current blockchain height."""
        info = await self._rpc_call("getblockchaininfo", use_wallet=False)
        return info.get("blocks", 0)

    async def get_block_time(self, block_height: int) -> int:
        """Get block time (unix timestamp) for given height."""
        block_hash = await self.get_block_hash(block_height)
        block_header = await self._rpc_call("getblockheader", [block_hash], use_wallet=False)
        return block_header.get("time", 0)

    async def get_block_hash(self, block_height: int) -> str:
        """Get block hash for given height."""
        return await self._rpc_call("getblockhash", [block_height], use_wallet=False)

    async def get_utxo(self, txid: str, vout: int) -> UTXO | None:
        """
        Get a specific UTXO.

        First checks wallet's UTXOs, then falls back to gettxout for non-wallet UTXOs.
        """
        # First check wallet UTXOs (fast)
        try:
            utxos = await self._rpc_call(
                "listunspent",
                [0, 9999999, [], True, {"minimumAmount": 0}],
            )
            for utxo_data in utxos:
                if utxo_data["txid"] == txid and utxo_data["vout"] == vout:
                    return UTXO(
                        txid=utxo_data["txid"],
                        vout=utxo_data["vout"],
                        value=btc_to_sats(utxo_data["amount"]),
                        address=utxo_data.get("address", ""),
                        confirmations=utxo_data.get("confirmations", 0),
                        scriptpubkey=utxo_data.get("scriptPubKey", ""),
                        height=None,
                    )
        except Exception as e:
            logger.debug(f"Wallet UTXO lookup failed: {e}")

        # Fall back to gettxout for non-wallet UTXOs
        try:
            result = await self._rpc_call("gettxout", [txid, vout, True], use_wallet=False)
            if result is None:
                return None

            tip_height = await self.get_block_height()
            confirmations = result.get("confirmations", 0)
            height = tip_height - confirmations + 1 if confirmations > 0 else None

            script_pub_key = result.get("scriptPubKey", {})
            return UTXO(
                txid=txid,
                vout=vout,
                value=btc_to_sats(result.get("value", 0)),
                address=script_pub_key.get("address", ""),
                confirmations=confirmations,
                scriptpubkey=script_pub_key.get("hex", ""),
                height=height,
            )
        except Exception as e:
            logger.error(f"Failed to get UTXO {txid}:{vout}: {e}")
            return None

    async def rescan_blockchain(self, start_height: int = 0) -> dict[str, Any]:
        """
        Rescan blockchain from given height.

        Useful after importing new descriptors or recovering wallet.

        Args:
            start_height: Block height to start rescan from

        Returns:
            Rescan result
        """
        try:
            logger.info(f"Starting blockchain rescan from height {start_height}...")
            result = await self._rpc_call(
                "rescanblockchain",
                [start_height],
                client=self._import_client,  # Use longer timeout
            )
            logger.info(f"Rescan complete: {result}")
            return result
        except Exception as e:
            logger.error(f"Rescan failed: {e}")
            raise

    async def get_new_address(self, address_type: str = "bech32") -> str:
        """
        Get a new address from the wallet.

        Note: This only works if private keys are enabled in the wallet.
        For watch-only wallets, derive addresses from the descriptors instead.
        """
        try:
            return await self._rpc_call("getnewaddress", ["", address_type])
        except ValueError as e:
            if "private keys disabled" in str(e).lower():
                raise RuntimeError(
                    "Cannot generate new addresses in watch-only wallet. "
                    "Derive addresses from your descriptors instead."
                ) from e
            raise

    async def unload_wallet(self) -> None:
        """Unload the wallet from Bitcoin Core."""
        if self._wallet_loaded:
            try:
                await self._rpc_call("unloadwallet", [self.wallet_name], use_wallet=False)
                logger.info(f"Unloaded wallet '{self.wallet_name}'")
                self._wallet_loaded = False
            except Exception as e:
                logger.warning(f"Failed to unload wallet: {e}")

    def can_provide_neutrino_metadata(self) -> bool:
        """Bitcoin Core can provide Neutrino-compatible metadata."""
        return True

    async def close(self) -> None:
        """Close backend connections."""
        await self.client.aclose()
        await self._import_client.aclose()


def generate_wallet_name(mnemonic_fingerprint: str, network: str = "mainnet") -> str:
    """
    Generate a deterministic wallet name from mnemonic fingerprint.

    This ensures the same mnemonic always uses the same wallet, avoiding
    duplicate wallet creation.

    Args:
        mnemonic_fingerprint: First 8 chars of SHA256(mnemonic)
        network: Network name (mainnet, testnet, regtest)

    Returns:
        Wallet name like "jm_abc12345_mainnet"
    """
    return f"jm_{mnemonic_fingerprint}_{network}"


def get_mnemonic_fingerprint(mnemonic: str, passphrase: str = "") -> str:
    """
    Get BIP32 master key fingerprint from mnemonic (like SeedSigner).

    This creates the master HD key from the seed and derives m/0 to get
    the fingerprint, following the same approach as SeedSigner and other
    Bitcoin wallet software.

    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional BIP39 passphrase (13th/25th word)

    Returns:
        8-character hex string (4 bytes) of the m/0 fingerprint
    """
    from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed

    # Convert mnemonic to seed bytes
    seed = mnemonic_to_seed(mnemonic, passphrase)

    # Create master HD key from seed
    root = HDKey.from_seed(seed)

    # Derive m/0 child key (following SeedSigner approach)
    child = root.derive("m/0")

    # Get fingerprint (4 bytes)
    fingerprint_bytes = child.fingerprint

    # Convert to 8-character hex string
    return fingerprint_bytes.hex()
