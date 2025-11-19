"""
CoinJoin protocol handler for makers.

Manages the maker side of the CoinJoin protocol:
1. !fill - Taker requests to fill order
2. !pubkey - Maker sends commitment pubkey
3. !auth - Taker sends PoDLE proof (VERIFY!)
4. !ioauth - Maker sends selected UTXOs
5. !tx - Taker sends unsigned transaction (VERIFY!)
6. !sig - Maker sends signatures
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from jmcore.models import Offer
from jmwallet.backends.base import BlockchainBackend
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

from maker.podle import parse_podle_revelation, verify_podle
from maker.tx_verification import verify_unsigned_transaction


class CoinJoinState(str, Enum):
    """CoinJoin session states"""

    IDLE = "idle"
    FILL_RECEIVED = "fill_received"
    PUBKEY_SENT = "pubkey_sent"
    AUTH_RECEIVED = "auth_received"
    IOAUTH_SENT = "ioauth_sent"
    TX_RECEIVED = "tx_received"
    SIG_SENT = "sig_sent"
    COMPLETE = "complete"
    FAILED = "failed"


class CoinJoinSession:
    """
    Manages a single CoinJoin session with a taker.
    """

    def __init__(
        self,
        taker_nick: str,
        offer: Offer,
        wallet: WalletService,
        backend: BlockchainBackend,
        min_confirmations: int = 1,
        taker_utxo_retries: int = 10,
        taker_utxo_age: int = 5,
        taker_utxo_amtpercent: int = 20,
    ):
        self.taker_nick = taker_nick
        self.offer = offer
        self.wallet = wallet
        self.backend = backend
        self.min_confirmations = min_confirmations
        self.taker_utxo_retries = taker_utxo_retries
        self.taker_utxo_age = taker_utxo_age
        self.taker_utxo_amtpercent = taker_utxo_amtpercent

        self.state = CoinJoinState.IDLE
        self.amount = 0
        self.our_utxos: dict[tuple[str, int], UTXOInfo] = {}
        self.cj_address = ""
        self.change_address = ""
        self.mixdepth = 0
        self.commitment = b""
        self.auth_pubkey = b""
        self.created_at = time.time()

    async def handle_fill(self, amount: int, commitment: str) -> tuple[bool, dict[str, Any]]:
        """
        Handle !fill message from taker.

        Args:
            amount: CoinJoin amount requested
            commitment: PoDLE commitment (will be verified later in !auth)

        Returns:
            (success, response_data)
        """
        try:
            if self.state != CoinJoinState.IDLE:
                return False, {"error": "Session not in IDLE state"}

            if amount < self.offer.minsize:
                return False, {"error": f"Amount too small: {amount} < {self.offer.minsize}"}

            if amount > self.offer.maxsize:
                return False, {"error": f"Amount too large: {amount} > {self.offer.maxsize}"}

            self.amount = amount
            self.commitment = bytes.fromhex(commitment)
            self.state = CoinJoinState.FILL_RECEIVED

            logger.info(
                f"Received !fill from {self.taker_nick}: "
                f"amount={amount}, commitment={commitment[:16]}..."
            )

            response = {"nick": self.offer.counterparty, "pubkey": self.auth_pubkey.hex()}

            self.state = CoinJoinState.PUBKEY_SENT

            return True, response

        except Exception as e:
            logger.error(f"Failed to handle !fill: {e}")
            self.state = CoinJoinState.FAILED
            return False, {"error": str(e)}

    async def handle_auth(
        self, commitment: str, revelation: dict[str, Any], kphex: str
    ) -> tuple[bool, dict[str, Any]]:
        """
        Handle !auth message from taker.

        CRITICAL SECURITY: Verifies PoDLE proof and taker's UTXO.

        Args:
            commitment: PoDLE commitment (should match from !fill)
            revelation: PoDLE revelation data
            kphex: Encryption key (hex)

        Returns:
            (success, response_data with UTXOs or error)
        """
        try:
            if self.state != CoinJoinState.PUBKEY_SENT:
                return False, {"error": "Session not in correct state for !auth"}

            commitment_bytes = bytes.fromhex(commitment)
            if commitment_bytes != self.commitment:
                return False, {"error": "Commitment mismatch"}

            parsed_rev = parse_podle_revelation(revelation)
            if not parsed_rev:
                return False, {"error": "Invalid PoDLE revelation format"}

            is_valid, error = verify_podle(
                parsed_rev["P"],
                parsed_rev["P2"],
                parsed_rev["sig"],
                parsed_rev["e"],
                commitment_bytes,
                index_range=range(self.taker_utxo_retries),
            )

            if not is_valid:
                logger.warning(f"PoDLE verification failed: {error}")
                return False, {"error": f"PoDLE verification failed: {error}"}

            logger.info("PoDLE proof verified ✓")

            utxo_txid = parsed_rev["txid"]
            utxo_vout = parsed_rev["vout"]

            utxos = await self.backend.get_utxos([])
            taker_utxo = None
            for utxo in utxos:
                if utxo.txid == utxo_txid and utxo.vout == utxo_vout:
                    taker_utxo = utxo
                    break

            if not taker_utxo:
                return False, {"error": "Taker's UTXO not found on blockchain"}

            if taker_utxo.confirmations < self.taker_utxo_age:
                return False, {
                    "error": f"Taker's UTXO too young: "
                    f"{taker_utxo.confirmations} < {self.taker_utxo_age}"
                }

            required_amount = int(self.amount * self.taker_utxo_amtpercent / 100)
            if taker_utxo.value < required_amount:
                return False, {
                    "error": f"Taker's UTXO too small: {taker_utxo.value} < {required_amount}"
                }

            logger.info("Taker's UTXO validated ✓")

            utxos_dict, cj_addr, change_addr, mixdepth = await self._select_our_utxos()

            if not utxos_dict:
                return False, {"error": "Failed to select UTXOs"}

            self.our_utxos = utxos_dict
            self.cj_address = cj_addr
            self.change_address = change_addr
            self.mixdepth = mixdepth

            utxos_serialized = {
                f"{txid}:{vout}": {"address": info.address, "value": info.value}
                for (txid, vout), info in utxos_dict.items()
            }

            response = {
                "utxos": utxos_serialized,
                "auth_pub": parsed_rev["P"].hex(),
                "cj_addr": cj_addr,
                "change_addr": change_addr,
                "btc_sig": "",
            }

            self.state = CoinJoinState.IOAUTH_SENT
            logger.info(f"Sent !ioauth with {len(utxos_dict)} UTXOs")

            return True, response

        except Exception as e:
            logger.error(f"Failed to handle !auth: {e}")
            self.state = CoinJoinState.FAILED
            return False, {"error": str(e)}

    async def handle_tx(self, tx_hex: str) -> tuple[bool, dict[str, Any]]:
        """
        Handle !tx message from taker.

        CRITICAL SECURITY: Verifies unsigned transaction before signing!

        Args:
            tx_hex: Unsigned transaction hex

        Returns:
            (success, response_data with signatures or error)
        """
        try:
            if self.state != CoinJoinState.IOAUTH_SENT:
                return False, {"error": "Session not in correct state for !tx"}

            logger.info(f"Received !tx from {self.taker_nick}, verifying...")

            is_valid, error = verify_unsigned_transaction(
                tx_hex=tx_hex,
                our_utxos=self.our_utxos,
                cj_address=self.cj_address,
                change_address=self.change_address,
                amount=self.amount,
                cjfee=self.offer.cjfee,
                txfee=self.offer.txfee,
                offer_type=self.offer.ordertype,
            )

            if not is_valid:
                logger.error(f"Transaction verification FAILED: {error}")
                self.state = CoinJoinState.FAILED
                return False, {"error": f"Transaction verification failed: {error}"}

            logger.info("Transaction verification PASSED ✓")

            signatures = await self._sign_transaction(tx_hex)  # type: ignore[arg-type]

            if not signatures:
                return False, {"error": "Failed to sign transaction"}

            response = {"signatures": signatures}

            self.state = CoinJoinState.SIG_SENT
            logger.info(f"Sent !sig with {len(signatures)} signatures")

            return True, response

        except Exception as e:
            logger.error(f"Failed to handle !tx: {e}")
            self.state = CoinJoinState.FAILED
            return False, {"error": str(e)}

    async def _select_our_utxos(
        self,
    ) -> tuple[dict[tuple[str, int], UTXOInfo], str, str, int]:
        """
        Select our UTXOs for the CoinJoin.

        Returns:
            (utxos_dict, cj_address, change_address, mixdepth)
        """
        try:
            from jmcore.models import OfferType

            real_cjfee = 0
            if self.offer.ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
                real_cjfee = int(self.offer.cjfee)
            else:
                from decimal import Decimal

                real_cjfee = int(Decimal(str(self.offer.cjfee)) * Decimal(self.amount))

            total_amount = self.amount + self.offer.txfee
            required_amount = total_amount + 10000 - real_cjfee

            balances = {}
            for md in range(self.wallet.mixdepth_count):
                balance = await self.wallet.get_balance(md)
                balances[md] = balance

            eligible_mixdepths = {md: bal for md, bal in balances.items() if bal >= required_amount}

            if not eligible_mixdepths:
                logger.error(f"No mixdepth with sufficient balance: need {required_amount}")
                return {}, "", "", -1

            max_mixdepth = max(eligible_mixdepths, key=lambda md: eligible_mixdepths[md])

            selected = self.wallet.select_utxos(
                max_mixdepth, required_amount, self.min_confirmations
            )

            utxos_dict = {(utxo.txid, utxo.vout): utxo for utxo in selected}

            cj_output_mixdepth = (max_mixdepth + 1) % self.wallet.mixdepth_count
            cj_index = self.wallet.get_next_address_index(cj_output_mixdepth, 1)
            cj_address = self.wallet.get_change_address(cj_output_mixdepth, cj_index)

            change_index = self.wallet.get_next_address_index(max_mixdepth, 1)
            change_address = self.wallet.get_change_address(max_mixdepth, change_index)

            logger.info(
                f"Selected {len(selected)} UTXOs from mixdepth {max_mixdepth}, "
                f"total value: {sum(u.value for u in selected)} sats"
            )

            return utxos_dict, cj_address, change_address, max_mixdepth

        except Exception as e:
            logger.error(f"Failed to select UTXOs: {e}")
            return {}, "", "", -1

    async def _sign_transaction(self, tx_hex: str) -> list[str]:
        """Sign our inputs in the transaction."""
        try:
            tx_bytes = bytes.fromhex(tx_hex)
            tx = deserialize_transaction(tx_bytes)

            signatures: list[str] = []

            signatures_info = []

            for index, ((txid, vout), utxo_info) in enumerate(self.our_utxos.items()):
                key = self.wallet.get_key_for_address(utxo_info.address)
                if not key:
                    raise TransactionSigningError(f"Missing key for address {utxo_info.address}")

                priv_key = key.private_key
                pubkey_bytes = key.get_public_key_bytes(compressed=True)

                script_code = create_p2wpkh_script_code(pubkey_bytes)
                signature = sign_p2wpkh_input(
                    tx=tx,
                    input_index=index,
                    script_code=script_code,
                    value=utxo_info.value,
                    private_key=priv_key,
                )

                witness = create_witness_stack(signature, pubkey_bytes)

                signatures_info.append(
                    {
                        "txid": txid,
                        "vout": vout,
                        "signature": signature.hex(),
                        "pubkey": pubkey_bytes.hex(),
                        "witness": [item.hex() for item in witness],
                    }
                )

            return signatures_info

            return signatures

        except TransactionSigningError as e:
            logger.error(f"Signing error: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to sign transaction: {e}")
            return []
