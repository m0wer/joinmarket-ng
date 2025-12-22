"""
Main Taker class for CoinJoin execution.

Orchestrates the complete CoinJoin protocol:
1. Fetch orderbook from directory nodes
2. Select makers and generate PoDLE commitment
3. Send !fill requests and receive !pubkey responses
4. Send !auth with PoDLE proof and receive !ioauth (maker UTXOs)
5. Build unsigned transaction and send !tx
6. Collect !sig responses and broadcast

Reference: Original joinmarket-clientserver/src/jmclient/taker.py
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from jmcore.crypto import generate_jm_nick
from jmcore.directory_client import DirectoryClient
from jmcore.encryption import CryptoSession
from jmcore.models import Offer
from jmcore.protocol import JM_VERSION, is_v6_nick, parse_utxo_list
from jmwallet.backends.base import BlockchainBackend
from jmwallet.history import append_history_entry, create_taker_history_entry
from jmwallet.wallet.models import UTXOInfo
from jmwallet.wallet.service import WalletService
from jmwallet.wallet.signing import (
    TransactionSigningError,
    create_p2wpkh_script_code,
    create_witness_stack,
    deserialize_transaction,
    sign_p2wpkh_input,
)
from loguru import logger

from taker.config import BroadcastPolicy, Schedule, TakerConfig
from taker.orderbook import OrderbookManager, calculate_cj_fee
from taker.podle import ExtendedPoDLECommitment, generate_podle_for_coinjoin
from taker.tx_builder import CoinJoinTxBuilder, build_coinjoin_tx


class MultiDirectoryClient:
    """
    Wrapper for managing multiple DirectoryClient connections.

    Provides a unified interface for connecting to multiple directory servers
    and aggregating orderbook data.
    """

    def __init__(
        self,
        directory_servers: list[str],
        network: str,
        nick: str,
    ):
        self.directory_servers = directory_servers
        self.network = network
        self.nick = nick
        self.clients: dict[str, DirectoryClient] = {}
        self._response_queues: dict[str, asyncio.Queue[dict[str, Any]]] = {}

    async def connect_all(self) -> int:
        """Connect to all directory servers, return count of successful connections."""
        connected = 0
        for server in self.directory_servers:
            try:
                parts = server.split(":")
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 5222

                client = DirectoryClient(
                    host=host,
                    port=port,
                    network=self.network,
                    nick=self.nick,
                )
                await client.connect()
                self.clients[server] = client
                connected += 1
                logger.info(f"Connected to directory server: {server}")
            except Exception as e:
                logger.warning(f"Failed to connect to {server}: {e}")
        return connected

    async def close_all(self) -> None:
        """Close all directory connections."""
        for server, client in self.clients.items():
            try:
                await client.close()
            except Exception as e:
                logger.warning(f"Error closing connection to {server}: {e}")
        self.clients.clear()

    async def fetch_orderbook(self, timeout: float = 10.0) -> list[Offer]:
        """Fetch orderbook from all connected directory servers."""
        all_offers: list[Offer] = []
        seen_offers: set[tuple[str, int]] = set()

        for server, client in self.clients.items():
            try:
                offers, _bonds = await client.fetch_orderbooks()
                for offer in offers:
                    key = (offer.counterparty, offer.oid)
                    if key not in seen_offers:
                        seen_offers.add(key)
                        all_offers.append(offer)
            except Exception as e:
                logger.warning(f"Failed to fetch orderbook from {server}: {e}")

        return all_offers

    async def send_privmsg(self, recipient: str, command: str, data: str) -> None:
        """Send a private message via all connected directory servers."""
        message = f"{command} {data}"
        for client in self.clients.values():
            try:
                await client.send_private_message(recipient, message)
            except Exception as e:
                logger.warning(f"Failed to send privmsg: {e}")

    async def wait_for_responses(
        self,
        expected_nicks: list[str],
        expected_command: str,
        timeout: float = 60.0,
    ) -> dict[str, dict[str, Any]]:
        """Wait for responses from multiple makers at once.

        Returns a dict of nick -> response data for all makers that responded.
        """
        responses: dict[str, dict[str, Any]] = {}
        remaining_nicks = set(expected_nicks)
        start_time = asyncio.get_event_loop().time()

        while remaining_nicks:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= timeout:
                logger.warning(f"Timeout waiting for {expected_command} from: {remaining_nicks}")
                break

            remaining_time = min(5.0, timeout - elapsed)  # Listen in 5s chunks

            for client in self.clients.values():
                try:
                    messages = await client.listen_for_messages(duration=remaining_time)
                    for msg in messages:
                        line = msg.get("line", "")
                        # Parse the message to find sender and command
                        if expected_command not in line:
                            continue

                        # Match against remaining nicks
                        for nick in list(remaining_nicks):
                            if nick in line:
                                # Extract data after the command
                                parts = line.split(expected_command, 1)
                                if len(parts) > 1:
                                    responses[nick] = {"data": parts[1].strip()}
                                    remaining_nicks.discard(nick)
                                    logger.debug(f"Received {expected_command} from {nick}")
                                break
                except Exception as e:
                    logger.debug(f"Error waiting for responses: {e}")

            # Check if we got all responses
            if not remaining_nicks:
                break

        return responses

    async def wait_for_response(
        self,
        from_nick: str,
        expected_command: str,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """Wait for a specific response from a maker (legacy method)."""
        responses = await self.wait_for_responses([from_nick], expected_command, timeout)
        return responses.get(from_nick)


class TakerState(str, Enum):
    """Taker protocol states."""

    IDLE = "idle"
    FETCHING_ORDERBOOK = "fetching_orderbook"
    SELECTING_MAKERS = "selecting_makers"
    FILLING = "filling"
    AUTHENTICATING = "authenticating"
    BUILDING_TX = "building_tx"
    COLLECTING_SIGNATURES = "collecting_signatures"
    BROADCASTING = "broadcasting"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class MakerSession:
    """Session data for a single maker."""

    nick: str
    offer: Offer
    utxos: list[dict[str, Any]] = field(default_factory=list)
    cj_address: str = ""
    change_address: str = ""
    pubkey: str = ""  # Maker's NaCl public key (hex)
    auth_pubkey: str = ""  # Maker's EC auth public key from !ioauth (hex)
    crypto: CryptoSession | None = None  # Encryption session with this maker
    signature: dict[str, Any] | None = None
    responded_fill: bool = False
    responded_auth: bool = False
    responded_sig: bool = False
    supports_v6: bool = False  # Protocol v6: supports extended UTXO metadata


class Taker:
    """
    Main Taker class for executing CoinJoin transactions.
    """

    def __init__(
        self,
        wallet: WalletService,
        backend: BlockchainBackend,
        config: TakerConfig,
    ):
        """
        Initialize the Taker.

        Args:
            wallet: Wallet service for UTXO management and signing
            backend: Blockchain backend for broadcasting
            config: Taker configuration
        """
        self.wallet = wallet
        self.backend = backend
        self.config = config

        self.nick = generate_jm_nick(JM_VERSION)
        self.state = TakerState.IDLE

        # Directory client
        self.directory_client = MultiDirectoryClient(
            directory_servers=config.directory_servers,
            network=config.network.value,
            nick=self.nick,
        )

        # Orderbook manager
        self.orderbook_manager = OrderbookManager(
            config.max_cj_fee, config.bondless_makers_allowance
        )

        # Current CoinJoin session data
        self.cj_amount = 0
        self.cj_destination: str = ""  # Destination address for history
        self.cj_mixdepth: int = 0  # Source mixdepth for history
        self.cj_total_maker_fee: int = 0  # Total maker fees for history
        self.cj_mining_fee: int = 0  # Mining fee for history
        self.maker_sessions: dict[str, MakerSession] = {}
        self.podle_commitment: ExtendedPoDLECommitment | None = None
        self.unsigned_tx: bytes = b""
        self.tx_metadata: dict[str, Any] = {}
        self.final_tx: bytes = b""
        self.txid: str = ""
        self.selected_utxos: list[UTXOInfo] = []  # Taker's selected UTXOs for signing

        # E2E encryption session for communication with makers
        self.crypto_session: CryptoSession | None = None

        # Schedule for tumbler-style operations
        self.schedule: Schedule | None = None

    async def start(self) -> None:
        """Start the taker and connect to directory servers."""
        logger.info(f"Starting taker (nick: {self.nick})")

        # Sync wallet
        logger.info("Syncing wallet...")
        await self.wallet.sync_all()

        total_balance = await self.wallet.get_total_balance()
        logger.info(f"Wallet synced. Total balance: {total_balance:,} sats")

        # Connect to directory servers
        logger.info("Connecting to directory servers...")
        connected = await self.directory_client.connect_all()

        if connected == 0:
            raise RuntimeError("Failed to connect to any directory server")

        logger.info(f"Connected to {connected} directory servers")

    async def stop(self) -> None:
        """Stop the taker and close connections."""
        logger.info("Stopping taker...")
        await self.directory_client.close_all()
        await self.wallet.close()
        logger.info("Taker stopped")

    async def do_coinjoin(
        self,
        amount: int,
        destination: str,
        mixdepth: int = 0,
        counterparty_count: int | None = None,
    ) -> str | None:
        """
        Execute a single CoinJoin transaction.

        Args:
            amount: Amount in satoshis (0 for sweep)
            destination: Destination address ("INTERNAL" for next mixdepth)
            mixdepth: Source mixdepth
            counterparty_count: Number of makers (default from config)

        Returns:
            Transaction ID if successful, None otherwise
        """
        try:
            self.state = TakerState.FETCHING_ORDERBOOK

            n_makers = counterparty_count or self.config.counterparty_count

            # Determine destination address
            if destination == "INTERNAL":
                dest_mixdepth = (mixdepth + 1) % self.wallet.mixdepth_count
                dest_index = self.wallet.get_next_address_index(dest_mixdepth, 0)
                destination = self.wallet.get_receive_address(dest_mixdepth, dest_index)
                logger.info(f"Using internal address: {destination}")

            # Fetch orderbook
            logger.info("Fetching orderbook...")
            offers = await self.directory_client.fetch_orderbook(self.config.order_wait_time)
            self.orderbook_manager.update_offers(offers)

            if len(offers) < n_makers:
                logger.error(f"Not enough offers: need {n_makers}, found {len(offers)}")
                self.state = TakerState.FAILED
                return None

            # Select UTXOs from wallet
            logger.info(f"Selecting UTXOs from mixdepth {mixdepth}...")
            balance = await self.wallet.get_balance(mixdepth)

            if amount == 0:
                # Sweep - use all available
                self.cj_amount = balance
            else:
                self.cj_amount = amount

            # Select makers
            self.state = TakerState.SELECTING_MAKERS
            logger.info(f"Selecting {n_makers} makers for {self.cj_amount:,} sats...")

            # If using neutrino backend, only select v6 makers (they can send extended UTXO format)
            min_nick_version = 6 if self.backend.requires_neutrino_metadata() else None
            if min_nick_version:
                logger.info("Neutrino backend: filtering for v6 makers only")

            selected_offers, total_fee = self.orderbook_manager.select_makers(
                cj_amount=self.cj_amount,
                n=n_makers,
                min_nick_version=min_nick_version,
            )

            if len(selected_offers) < self.config.minimum_makers:
                logger.error(f"Not enough makers selected: {len(selected_offers)}")
                self.state = TakerState.FAILED
                return None

            # Initialize maker sessions
            self.maker_sessions = {
                nick: MakerSession(nick=nick, offer=offer)
                for nick, offer in selected_offers.items()
            }

            logger.info(
                f"Selected {len(self.maker_sessions)} makers, total fee: {total_fee:,} sats"
            )

            # Generate PoDLE commitment
            logger.info("Generating PoDLE commitment...")
            wallet_utxos = await self.wallet.get_utxos(mixdepth)

            def get_private_key(addr: str) -> bytes | None:
                key = self.wallet.get_key_for_address(addr)
                if key is None:
                    return None
                return key.get_private_key_bytes()

            self.podle_commitment = generate_podle_for_coinjoin(
                wallet_utxos=wallet_utxos,
                cj_amount=self.cj_amount,
                private_key_getter=get_private_key,
                min_confirmations=self.config.taker_utxo_age,
                min_percent=self.config.taker_utxo_amtpercent,
            )

            if not self.podle_commitment:
                logger.error("Failed to generate PoDLE commitment")
                self.state = TakerState.FAILED
                return None

            # Phase 1: Fill orders
            self.state = TakerState.FILLING
            logger.info("Phase 1: Sending !fill to makers...")

            fill_success = await self._phase_fill()
            if not fill_success:
                logger.error("Fill phase failed")
                self.state = TakerState.FAILED
                return None

            # Phase 2: Auth and get maker UTXOs
            self.state = TakerState.AUTHENTICATING
            logger.info("Phase 2: Sending !auth and receiving !ioauth...")

            auth_success = await self._phase_auth()
            if not auth_success:
                logger.error("Auth phase failed")
                self.state = TakerState.FAILED
                return None

            # Phase 3: Build transaction
            self.state = TakerState.BUILDING_TX
            logger.info("Phase 3: Building transaction...")

            tx_success = await self._phase_build_tx(
                destination=destination,
                mixdepth=mixdepth,
            )
            if not tx_success:
                logger.error("Transaction build failed")
                self.state = TakerState.FAILED
                return None

            # Phase 4: Collect signatures
            self.state = TakerState.COLLECTING_SIGNATURES
            logger.info("Phase 4: Collecting signatures...")

            sig_success = await self._phase_collect_signatures()
            if not sig_success:
                logger.error("Signature collection failed")
                self.state = TakerState.FAILED
                return None

            # Phase 5: Broadcast
            self.state = TakerState.BROADCASTING
            logger.info("Phase 5: Broadcasting transaction...")

            self.txid = await self._phase_broadcast()
            if not self.txid:
                logger.error("Broadcast failed")
                self.state = TakerState.FAILED
                return None

            self.state = TakerState.COMPLETE
            logger.info(f"CoinJoin COMPLETE! txid: {self.txid}")

            # Record transaction in history
            try:
                maker_nicks = list(self.maker_sessions.keys())
                selected_utxo_tuples = [(u.txid, u.vout) for u in self.selected_utxos]

                history_entry = create_taker_history_entry(
                    maker_nicks=maker_nicks,
                    cj_amount=self.cj_amount,
                    total_maker_fees=self.cj_total_maker_fee,
                    mining_fee=self.cj_mining_fee,
                    destination=self.cj_destination,
                    source_mixdepth=self.cj_mixdepth,
                    selected_utxos=selected_utxo_tuples,
                    txid=self.txid,
                    broadcast_method="self",
                    network=self.config.network.value,
                )
                append_history_entry(history_entry)
                logger.debug(
                    f"Recorded CoinJoin in history: "
                    f"cost {self.cj_total_maker_fee + self.cj_mining_fee} sats"
                )
            except Exception as e:
                logger.warning(f"Failed to record CoinJoin history: {e}")

            return self.txid

        except Exception as e:
            logger.error(f"CoinJoin failed: {e}")
            self.state = TakerState.FAILED
            return None

    async def _phase_fill(self) -> bool:
        """Send !fill to all selected makers and wait for !pubkey responses."""
        if not self.podle_commitment:
            return False

        # Create a new crypto session for this CoinJoin
        self.crypto_session = CryptoSession()
        taker_pubkey = self.crypto_session.get_pubkey_hex()
        commitment_hex = self.podle_commitment.to_commitment_str()

        # Send !fill to all makers
        # Format: fill <oid> <amount> <taker_pubkey> <commitment>
        for nick, session in self.maker_sessions.items():
            fill_data = f"{session.offer.oid} {self.cj_amount} {taker_pubkey} {commitment_hex}"
            await self.directory_client.send_privmsg(nick, "!fill", fill_data)
            logger.debug(f"Sent !fill to {nick}")

        # Wait for all !pubkey responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!pubkey",
            timeout=timeout,
        )

        # Process responses
        # Maker sends !pubkey as plain hex: "<nacl_pubkey_hex> <signing_pubkey> <signature>"
        # Directory client strips the command: "<nacl_pubkey_hex> <signing_pubkey> <sig>"
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                try:
                    response_data = responses[nick]["data"].strip()
                    # The response format is: "<nacl_pubkey_hex> <signing_pubkey> <signature>"
                    # We just need the first part (nacl_pubkey_hex)
                    parts = response_data.split()
                    if parts:
                        nacl_pubkey = parts[0]
                        self.maker_sessions[nick].pubkey = nacl_pubkey
                        self.maker_sessions[nick].responded_fill = True

                        # Set up encryption session with this maker using their NaCl pubkey
                        # IMPORTANT: Reuse the same keypair from self.crypto_session
                        # that was sent in !fill, just set up new box with maker's pubkey
                        crypto = CryptoSession.__new__(CryptoSession)
                        crypto.keypair = self.crypto_session.keypair  # Reuse taker keypair!
                        crypto.box = None
                        crypto.counterparty_pubkey = ""
                        crypto.setup_encryption(nacl_pubkey)
                        self.maker_sessions[nick].crypto = crypto
                        logger.debug(
                            f"Processed !pubkey from {nick}: {nacl_pubkey[:16]}..., "
                            f"encryption set up"
                        )
                    else:
                        logger.warning(f"Empty !pubkey response from {nick}")
                        del self.maker_sessions[nick]
                except Exception as e:
                    logger.warning(f"Invalid !pubkey response from {nick}: {e}")
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !pubkey response from {nick}")
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough makers responded: {len(self.maker_sessions)}")
            return False

        return True

    async def _phase_auth(self) -> bool:
        """Send !auth with PoDLE proof and wait for !ioauth responses."""
        if not self.podle_commitment:
            return False

        # Send !auth to each maker with format based on their protocol version (nick).
        # - J6 makers: Send extended format (txid:vout:scriptpubkey:blockheight)
        # - J5 makers: Send legacy format (txid:vout)
        #
        # This ensures backward compatibility with JAM (v5) while enabling extended
        # format for our v6 implementation that supports Neutrino backends.
        has_metadata = self.podle_commitment.has_neutrino_metadata()

        for nick, session in self.maker_sessions.items():
            if session.crypto is None:
                logger.error(f"No encryption session for {nick}")
                continue

            # Determine format based on maker's nick version
            use_extended = has_metadata and is_v6_nick(nick)
            revelation = self.podle_commitment.to_revelation(extended=use_extended)

            # Create pipe-separated revelation format:
            # Legacy (v5): txid:vout|P|P2|sig|e
            # Extended (v6): txid:vout:scriptpubkey:blockheight|P|P2|sig|e
            revelation_str = "|".join(
                [
                    revelation["utxo"],
                    revelation["P"],
                    revelation["P2"],
                    revelation["sig"],
                    revelation["e"],
                ]
            )

            if use_extended:
                logger.debug(f"Sending extended UTXO format to v6 maker {nick}")
            else:
                logger.debug(f"Sending legacy UTXO format to v5 maker {nick}")

            # Encrypt and send
            encrypted_revelation = session.crypto.encrypt(revelation_str)
            await self.directory_client.send_privmsg(nick, "!auth", encrypted_revelation)

        # Wait for all !ioauth responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!ioauth",
            timeout=timeout,
        )

        # Process responses
        # Maker sends !ioauth as ENCRYPTED space-separated:
        # <utxo_list> <auth_pub> <cj_addr> <change_addr> <btc_sig>
        # where utxo_list can be:
        # - Legacy (v5): txid:vout,txid:vout,...
        # - Extended (v6): txid:vout:scriptpubkey:blockheight,...
        # Response format from directory: "<encrypted_data> <signing_pubkey> <signature>"
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                try:
                    session = self.maker_sessions[nick]
                    if session.crypto is None:
                        logger.warning(f"No encryption session for {nick}")
                        del self.maker_sessions[nick]
                        continue

                    # Extract encrypted data (first part of response)
                    response_data = responses[nick]["data"].strip()
                    parts = response_data.split()
                    if not parts:
                        logger.warning(f"Empty !ioauth response from {nick}")
                        del self.maker_sessions[nick]
                        continue

                    encrypted_data = parts[0]

                    # Decrypt the ioauth message
                    decrypted = session.crypto.decrypt(encrypted_data)
                    logger.debug(f"Decrypted !ioauth from {nick}: {decrypted[:50]}...")

                    # Parse: <utxo_list> <auth_pub> <cj_addr> <change_addr> <btc_sig>
                    ioauth_parts = decrypted.split()
                    if len(ioauth_parts) < 4:
                        logger.warning(
                            f"Invalid !ioauth format from {nick}: expected 5 parts, "
                            f"got {len(ioauth_parts)}"
                        )
                        del self.maker_sessions[nick]
                        continue

                    utxo_list_str = ioauth_parts[0]
                    auth_pub = ioauth_parts[1]
                    cj_addr = ioauth_parts[2]
                    change_addr = ioauth_parts[3]

                    # Verify btc_sig if present - proves maker owns the UTXO
                    # NOTE: BTC sig verification is OPTIONAL per JoinMarket protocol
                    # It provides additional security by proving maker controls the UTXO
                    # but not all makers may provide it
                    if len(ioauth_parts) >= 5:
                        btc_sig = ioauth_parts[4]
                        # The signature is over the maker's NaCl pubkey
                        from jmcore.crypto import ecdsa_verify

                        maker_nacl_pk = session.pubkey  # Maker's NaCl pubkey from !pubkey
                        auth_pub_bytes = bytes.fromhex(auth_pub)
                        logger.debug(
                            f"Verifying BTC sig from {nick}: "
                            f"message={maker_nacl_pk[:32]}..., "
                            f"sig={btc_sig[:32]}..., "
                            f"pubkey={auth_pub[:16]}..."
                        )
                        if not ecdsa_verify(maker_nacl_pk, btc_sig, auth_pub_bytes):
                            logger.warning(
                                f"BTC signature verification failed from {nick} - "
                                f"continuing anyway (optional security feature)"
                            )
                            # NOTE: We don't delete the session here - BTC sig is optional
                            # The transaction verification will still protect against fraud
                        else:
                            logger.info(f"BTC signature verified for {nick} ✓")

                    # Parse utxo_list using protocol helper (handles both v5 and v6 format)
                    # Then verify each UTXO using the appropriate backend method
                    session.utxos = []
                    utxo_metadata_list = parse_utxo_list(utxo_list_str)

                    # Track if maker sent extended format
                    has_extended = any(u.has_neutrino_metadata() for u in utxo_metadata_list)
                    if has_extended:
                        session.supports_v6 = True
                        logger.debug(f"Maker {nick} sent extended UTXO format (v6)")

                    for utxo_meta in utxo_metadata_list:
                        txid = utxo_meta.txid
                        vout = utxo_meta.vout

                        # Verify UTXO and get value/address
                        try:
                            if (
                                self.backend.requires_neutrino_metadata()
                                and utxo_meta.has_neutrino_metadata()
                            ):
                                # Use Neutrino-compatible verification with metadata
                                result = await self.backend.verify_utxo_with_metadata(
                                    txid=txid,
                                    vout=vout,
                                    scriptpubkey=utxo_meta.scriptpubkey,  # type: ignore
                                    blockheight=utxo_meta.blockheight,  # type: ignore
                                )
                                if result.valid:
                                    value = result.value
                                    address = ""  # Not available from verification
                                    logger.debug(
                                        f"Neutrino-verified UTXO {txid}:{vout} = {value} sats"
                                    )
                                else:
                                    logger.warning(
                                        f"Neutrino UTXO verification failed for "
                                        f"{txid}:{vout}: {result.error}"
                                    )
                                    continue
                            else:
                                # Full node: direct UTXO lookup
                                utxo_info = await self.backend.get_utxo(txid, vout)
                                if utxo_info:
                                    value = utxo_info.value
                                    address = utxo_info.address
                                else:
                                    # Fallback: get raw transaction and parse it
                                    tx_info = await self.backend.get_transaction(txid)
                                    if tx_info and tx_info.raw:
                                        from maker.tx_verification import parse_transaction

                                        parsed_tx = parse_transaction(
                                            tx_info.raw, network=self.config.network
                                        )
                                        if parsed_tx and len(parsed_tx["outputs"]) > vout:
                                            value = parsed_tx["outputs"][vout]["value"]
                                            address = parsed_tx["outputs"][vout].get("address", "")
                                        else:
                                            logger.warning(
                                                f"Could not parse output {vout} from tx {txid}"
                                            )
                                            value = 0
                                            address = ""
                                    else:
                                        logger.warning(f"Could not fetch transaction {txid}")
                                        value = 0
                                        address = ""
                        except Exception as e:
                            logger.warning(f"Error verifying UTXO {txid}:{vout}: {e}")
                            value = 0
                            address = ""

                        session.utxos.append(
                            {
                                "txid": txid,
                                "vout": vout,
                                "value": value,
                                "address": address,
                            }
                        )
                        logger.debug(f"Added UTXO from {nick}: {txid}:{vout} = {value} sats")

                    session.cj_address = cj_addr
                    session.change_address = change_addr
                    session.auth_pubkey = auth_pub  # Store for later verification
                    session.responded_auth = True
                    logger.debug(
                        f"Processed !ioauth from {nick}: {len(session.utxos)} UTXOs, "
                        f"cj_addr={cj_addr[:16]}..."
                    )
                except Exception as e:
                    logger.warning(f"Invalid !ioauth response from {nick}: {e}")
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !ioauth response from {nick}")
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough makers sent UTXOs: {len(self.maker_sessions)}")
            return False

        return True

    def _parse_utxos(self, utxos_dict: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse UTXO data from !ioauth response."""
        result = []
        for utxo_str, info in utxos_dict.items():
            try:
                txid, vout_str = utxo_str.split(":")
                result.append(
                    {
                        "txid": txid,
                        "vout": int(vout_str),
                        "value": info.get("value", 0),
                        "address": info.get("address", ""),
                    }
                )
            except (ValueError, KeyError):
                continue
        return result

    async def _phase_build_tx(self, destination: str, mixdepth: int) -> bool:
        """Build the unsigned CoinJoin transaction."""
        try:
            # Get taker's UTXOs
            taker_utxos = await self.wallet.get_utxos(mixdepth)

            # Calculate total input needed
            total_maker_fee = sum(
                calculate_cj_fee(s.offer, self.cj_amount) for s in self.maker_sessions.values()
            )

            # Estimate tx fee
            num_inputs = len(taker_utxos) + sum(len(s.utxos) for s in self.maker_sessions.values())
            num_outputs = 1 + len(self.maker_sessions) + 1 + len(self.maker_sessions)  # CJ + change
            tx_fee = self._estimate_tx_fee(num_inputs, num_outputs)

            # Select taker UTXOs
            required = self.cj_amount + total_maker_fee + tx_fee
            selected_utxos = self.wallet.select_utxos(
                mixdepth, required, self.config.taker_utxo_age
            )

            if not selected_utxos:
                logger.error("Failed to select enough UTXOs")
                return False

            # Store selected UTXOs for signing later
            self.selected_utxos = selected_utxos

            taker_total = sum(u.value for u in selected_utxos)

            # Taker change address
            change_index = self.wallet.get_next_address_index(mixdepth, 1)
            taker_change_address = self.wallet.get_change_address(mixdepth, change_index)

            # Build maker data
            maker_data = {}
            for nick, session in self.maker_sessions.items():
                cjfee = calculate_cj_fee(session.offer, self.cj_amount)
                maker_data[nick] = {
                    "utxos": session.utxos,
                    "cj_addr": session.cj_address,
                    "change_addr": session.change_address,
                    "cjfee": cjfee,
                    "txfee": session.offer.txfee,  # Maker's share of tx fee
                }

            # Build transaction
            network = self.config.network.value
            self.unsigned_tx, self.tx_metadata = build_coinjoin_tx(
                taker_utxos=[
                    {
                        "txid": u.txid,
                        "vout": u.vout,
                        "value": u.value,
                        "scriptpubkey": u.scriptpubkey,
                    }
                    for u in selected_utxos
                ],
                taker_cj_address=destination,
                taker_change_address=taker_change_address,
                taker_total_input=taker_total,
                maker_data=maker_data,
                cj_amount=self.cj_amount,
                tx_fee=tx_fee,
                network=network,
            )

            # Store info for history tracking
            self.cj_destination = destination
            self.cj_mixdepth = mixdepth
            self.cj_total_maker_fee = total_maker_fee
            self.cj_mining_fee = tx_fee

            logger.info(f"Built unsigned tx: {len(self.unsigned_tx)} bytes")
            return True

        except Exception as e:
            logger.error(f"Failed to build transaction: {e}")
            return False

    def _estimate_tx_fee(self, num_inputs: int, num_outputs: int) -> int:
        """Estimate transaction fee."""
        # P2WPKH: ~68 vbytes per input, 31 vbytes per output, ~11 overhead
        vsize = num_inputs * 68 + num_outputs * 31 + 11
        fee_rate = 10  # sat/vbyte, should come from backend
        return int(vsize * fee_rate * self.config.tx_fee_factor)

    async def _phase_collect_signatures(self) -> bool:
        """Send !tx and collect !sig responses from makers."""
        # Encode transaction as base64 (expected by maker after decryption)
        import base64

        tx_b64 = base64.b64encode(self.unsigned_tx).decode("ascii")

        # Send ENCRYPTED !tx to each maker
        for nick, session in self.maker_sessions.items():
            if session.crypto is None:
                logger.error(f"No encryption session for {nick}")
                continue

            encrypted_tx = session.crypto.encrypt(tx_b64)
            await self.directory_client.send_privmsg(nick, "!tx", encrypted_tx)
            logger.debug(f"Sent encrypted !tx to {nick}")

        # Wait for all !sig responses at once
        timeout = self.config.maker_timeout_sec
        expected_nicks = list(self.maker_sessions.keys())
        signatures: dict[str, list[dict[str, Any]]] = {}

        responses = await self.directory_client.wait_for_responses(
            expected_nicks=expected_nicks,
            expected_command="!sig",
            timeout=timeout,
        )

        # Process responses
        # Maker sends !sig as ENCRYPTED: just the signature base64
        # Response format: "<encrypted_sig> <signing_pubkey> <signature>"
        for nick in list(self.maker_sessions.keys()):
            if nick in responses:
                try:
                    session = self.maker_sessions[nick]
                    if session.crypto is None:
                        logger.warning(f"No encryption session for {nick}")
                        del self.maker_sessions[nick]
                        continue

                    # Extract encrypted data (first part of response)
                    response_data = responses[nick]["data"].strip()
                    parts = response_data.split()
                    if not parts:
                        logger.warning(f"Empty !sig response from {nick}")
                        del self.maker_sessions[nick]
                        continue

                    encrypted_data = parts[0]

                    # Decrypt the signature
                    # Maker sends base64: varint(sig_len) + sig + varint(pub_len) + pub
                    decrypted_sig = session.crypto.decrypt(encrypted_data)

                    # Parse the signature to extract the witness stack
                    # Format: varint(sig_len) + sig + varint(pub_len) + pub
                    import base64

                    sig_bytes = base64.b64decode(decrypted_sig)
                    sig_len = sig_bytes[0]
                    signature = sig_bytes[1 : 1 + sig_len]
                    pub_len = sig_bytes[1 + sig_len]
                    pubkey = sig_bytes[2 + sig_len : 2 + sig_len + pub_len]

                    # Build witness as [signature_hex, pubkey_hex]
                    witness = [signature.hex(), pubkey.hex()]

                    # Match signature to the maker's UTXO
                    # Makers send one signature per UTXO in the same order
                    # For now, assume single UTXO per maker (most common case)
                    if session.utxos:
                        utxo = session.utxos[0]  # First (and usually only) UTXO
                        sig_info = {
                            "txid": utxo["txid"],
                            "vout": utxo["vout"],
                            "witness": witness,
                        }
                        signatures[nick] = [sig_info]
                        session.signature = {"signatures": [sig_info]}
                        session.responded_sig = True
                        logger.debug(f"Processed !sig from {nick}: {decrypted_sig[:32]}...")
                except Exception as e:
                    logger.warning(f"Invalid !sig response from {nick}: {e}")
                    del self.maker_sessions[nick]
            else:
                logger.warning(f"No !sig response from {nick}")
                del self.maker_sessions[nick]

        if len(self.maker_sessions) < self.config.minimum_makers:
            logger.error(f"Not enough signatures: {len(self.maker_sessions)}")
            return False

        # Add signatures to transaction
        builder = CoinJoinTxBuilder(self.config.network.value)

        # Add taker's signatures
        taker_sigs = await self._sign_our_inputs()
        signatures["taker"] = taker_sigs

        self.final_tx = builder.add_signatures(
            self.unsigned_tx,
            signatures,
            self.tx_metadata,
        )

        logger.info(f"Signed tx: {len(self.final_tx)} bytes")
        return True

    async def _sign_our_inputs(self) -> list[dict[str, Any]]:
        """
        Sign taker's inputs in the transaction.

        Finds the correct input indices in the shuffled transaction by matching
        txid:vout from selected UTXOs, then signs each input.

        Returns:
            List of signature info dicts with txid, vout, signature, pubkey, witness
        """
        try:
            if not self.unsigned_tx:
                logger.error("No unsigned transaction to sign")
                return []

            if not self.selected_utxos:
                logger.error("No selected UTXOs to sign")
                return []

            tx = deserialize_transaction(self.unsigned_tx)
            signatures_info: list[dict[str, Any]] = []

            # Build a map of (txid, vout) -> input index for the transaction
            # Note: txid in tx.inputs is little-endian bytes, need to convert
            input_index_map: dict[tuple[str, int], int] = {}
            for idx, tx_input in enumerate(tx.inputs):
                # Convert little-endian txid bytes to big-endian hex string (RPC format)
                txid_hex = tx_input.txid_le[::-1].hex()
                input_index_map[(txid_hex, tx_input.vout)] = idx

            # Sign each of our UTXOs
            for utxo in self.selected_utxos:
                # Find the input index in the transaction
                utxo_key = (utxo.txid, utxo.vout)
                if utxo_key not in input_index_map:
                    logger.error(f"UTXO {utxo.txid}:{utxo.vout} not found in transaction inputs")
                    continue

                input_index = input_index_map[utxo_key]

                # Get the key for this address
                key = self.wallet.get_key_for_address(utxo.address)
                if not key:
                    raise TransactionSigningError(f"Missing key for address {utxo.address}")

                priv_key = key.private_key
                pubkey_bytes = key.get_public_key_bytes(compressed=True)

                # Create script code and sign
                script_code = create_p2wpkh_script_code(pubkey_bytes)
                signature = sign_p2wpkh_input(
                    tx=tx,
                    input_index=input_index,
                    script_code=script_code,
                    value=utxo.value,
                    private_key=priv_key,
                )

                # Create witness stack
                witness = create_witness_stack(signature, pubkey_bytes)

                signatures_info.append(
                    {
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "signature": signature.hex(),
                        "pubkey": pubkey_bytes.hex(),
                        "witness": [item.hex() for item in witness],
                    }
                )

                logger.debug(f"Signed input {input_index} for UTXO {utxo.txid}:{utxo.vout}")

            logger.info(f"Signed {len(signatures_info)} taker inputs")
            return signatures_info

        except TransactionSigningError as e:
            logger.error(f"Signing error: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to sign transaction: {e}")
            return []

    async def _phase_broadcast(self) -> str:
        """
        Broadcast the signed transaction based on the configured policy.

        Privacy implications:
        - SELF: Taker broadcasts via own node. Links taker's IP to the transaction.
        - RANDOM_PEER: Random selection from makers + self. Provides plausible deniability.
        - NOT_SELF: Only makers can broadcast. Maximum privacy - taker's node never touches tx.
                    WARNING: No fallback if makers fail to broadcast!

        Returns:
            Transaction ID if successful, empty string otherwise
        """
        import base64
        import random

        policy = self.config.tx_broadcast
        logger.info(f"Broadcasting with policy: {policy.value}")

        # Encode transaction as base64 for !push message
        tx_b64 = base64.b64encode(self.final_tx).decode("ascii")

        # Build list of broadcast candidates based on policy
        maker_nicks = list(self.maker_sessions.keys())

        if policy == BroadcastPolicy.SELF:
            # Always broadcast via own node
            return await self._broadcast_self()

        elif policy == BroadcastPolicy.RANDOM_PEER:
            # Random selection from makers + self
            candidates = maker_nicks + ["self"]
            random.shuffle(candidates)

            for candidate in candidates:
                if candidate == "self":
                    txid = await self._broadcast_self()
                    if txid:
                        return txid
                else:
                    txid = await self._broadcast_via_maker(candidate, tx_b64)
                    if txid:
                        return txid

            logger.error("All broadcast attempts failed")
            return ""

        elif policy == BroadcastPolicy.NOT_SELF:
            # Only makers can broadcast - no self fallback
            if not maker_nicks:
                logger.error("NOT_SELF policy but no makers available")
                return ""

            random.shuffle(maker_nicks)

            for maker_nick in maker_nicks:
                txid = await self._broadcast_via_maker(maker_nick, tx_b64)
                if txid:
                    return txid

            # No fallback for NOT_SELF - log the transaction for manual broadcast
            logger.error(
                "All maker broadcast attempts failed. "
                "Transaction hex (for manual broadcast): "
                f"{self.final_tx.hex()}"
            )
            return ""

        else:
            # Unknown policy, fallback to self
            logger.warning(f"Unknown broadcast policy {policy}, falling back to self")
            return await self._broadcast_self()

    async def _broadcast_self(self) -> str:
        """Broadcast transaction via our own backend."""
        try:
            txid = await self.backend.broadcast_transaction(self.final_tx.hex())
            logger.info(f"Broadcast via self successful: {txid}")
            return txid
        except Exception as e:
            logger.warning(f"Self-broadcast failed: {e}")
            return ""

    async def _broadcast_via_maker(self, maker_nick: str, tx_b64: str) -> str:
        """
        Request a maker to broadcast the transaction.

        Sends !push command and waits briefly for the transaction to appear.
        We don't expect a response from the maker - they broadcast unquestioningly.

        Args:
            maker_nick: The maker's nick to send the push request to
            tx_b64: Base64-encoded signed transaction

        Returns:
            Transaction ID if broadcast detected, empty string otherwise
        """
        try:
            logger.info(f"Requesting broadcast via maker: {maker_nick}")

            # Send !push to the maker (unencrypted, like reference implementation)
            await self.directory_client.send_privmsg(maker_nick, "!push", tx_b64)

            # Wait briefly and check if the transaction was broadcast
            # We poll mempool/blockchain for the transaction
            await asyncio.sleep(2)  # Give maker time to broadcast

            # Check if transaction is now visible
            # Calculate the expected txid from the raw transaction
            import hashlib

            tx_hash = hashlib.sha256(hashlib.sha256(self.final_tx).digest()).digest()
            expected_txid = tx_hash[::-1].hex()

            # Try to get the transaction from our backend
            try:
                tx_info = await self.backend.get_transaction(expected_txid)
                if tx_info:
                    logger.info(
                        f"Transaction broadcast via {maker_nick} confirmed: {expected_txid}"
                    )
                    return expected_txid
            except Exception:
                # Transaction not yet visible
                pass

            # Wait a bit more and try again
            await asyncio.sleep(self.config.broadcast_timeout_sec - 2)

            try:
                tx_info = await self.backend.get_transaction(expected_txid)
                if tx_info:
                    logger.info(
                        f"Transaction broadcast via {maker_nick} confirmed: {expected_txid}"
                    )
                    return expected_txid
            except Exception:
                pass

            logger.warning(f"Broadcast via {maker_nick} not confirmed within timeout")
            return ""

        except Exception as e:
            logger.warning(f"Broadcast via maker {maker_nick} failed: {e}")
            return ""

    async def run_schedule(self, schedule: Schedule) -> bool:
        """
        Run a tumbler-style schedule of CoinJoins.

        Args:
            schedule: Schedule with multiple CoinJoin entries

        Returns:
            True if all entries completed successfully
        """
        self.schedule = schedule

        while not schedule.is_complete():
            entry = schedule.current_entry()
            if not entry:
                break

            logger.info(
                f"Running schedule entry {schedule.current_index + 1}/{len(schedule.entries)}"
            )

            # Calculate actual amount
            if isinstance(entry.amount, float) and 0 < entry.amount < 1:
                # Fraction of balance
                balance = await self.wallet.get_balance(entry.mixdepth)
                amount = int(balance * entry.amount)
            else:
                amount = int(entry.amount)

            # Execute CoinJoin
            txid = await self.do_coinjoin(
                amount=amount,
                destination=entry.destination,
                mixdepth=entry.mixdepth,
                counterparty_count=entry.counterparty_count,
            )

            if not txid:
                logger.error(f"Schedule entry {schedule.current_index + 1} failed")
                return False

            # Advance schedule
            schedule.advance()

            # Wait between CoinJoins
            if entry.wait_time > 0 and not schedule.is_complete():
                logger.info(f"Waiting {entry.wait_time}s before next CoinJoin...")
                await asyncio.sleep(entry.wait_time)

        logger.info("Schedule complete!")
        return True
