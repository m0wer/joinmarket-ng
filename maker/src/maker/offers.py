"""
Offer management for makers.

Creates and manages liquidity offers based on wallet balance and configuration.
"""

from __future__ import annotations

from jmcore.models import Offer, OfferType
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.config import MakerConfig
from maker.fidelity import get_best_fidelity_bond


class OfferManager:
    """
    Creates and manages offers for the maker bot.
    """

    def __init__(self, wallet: WalletService, config: MakerConfig, maker_nick: str):
        self.wallet = wallet
        self.config = config
        self.maker_nick = maker_nick

    async def create_offers(self) -> list[Offer]:
        """
        Create offers based on wallet balance and configuration.

        Logic:
        1. Find mixdepth with maximum balance
        2. Calculate available amount (balance - dust - txfee)
        3. Create offer with configured fee structure
        4. Attach fidelity bond value if available

        Returns:
            List of offers (usually just one)
        """
        try:
            balances = {}
            for mixdepth in range(self.wallet.mixdepth_count):
                balance = await self.wallet.get_balance(mixdepth)
                balances[mixdepth] = balance

            available_mixdepths = {md: bal for md, bal in balances.items() if bal > 0}

            if not available_mixdepths:
                logger.warning("No mixdepth with positive balance")
                return []

            max_mixdepth = max(available_mixdepths, key=lambda md: available_mixdepths[md])
            max_balance = available_mixdepths[max_mixdepth]

            dust_threshold = 5000
            max_available = max_balance - max(dust_threshold, self.config.tx_fee_contribution)

            if max_available <= self.config.min_size:
                logger.warning(f"Insufficient balance: {max_available} <= {self.config.min_size}")
                return []

            if self.config.offer_type in (OfferType.SW0_RELATIVE, OfferType.SWA_RELATIVE):
                cjfee = self.config.cj_fee_relative

                min_size_for_profit = int(
                    1.5 * self.config.tx_fee_contribution / float(self.config.cj_fee_relative)
                )
                min_size = max(min_size_for_profit, self.config.min_size)
            else:
                cjfee = str(self.config.cj_fee_absolute)
                min_size = self.config.min_size

            # Get fidelity bond value if available
            fidelity_bond_value = 0
            bond = get_best_fidelity_bond(self.wallet)
            if bond:
                fidelity_bond_value = bond.bond_value
                logger.info(
                    f"Fidelity bond found: {bond.txid}:{bond.vout} "
                    f"value={bond.value} sats, bond_value={bond.bond_value}"
                )

            offer = Offer(
                counterparty=self.maker_nick,
                oid=0,
                ordertype=self.config.offer_type,
                minsize=min_size,
                maxsize=max_available,
                txfee=self.config.tx_fee_contribution,
                cjfee=cjfee,
                fidelity_bond_value=fidelity_bond_value,
            )

            logger.info(
                f"Created offer: type={offer.ordertype}, "
                f"size={min_size}-{max_available}, "
                f"cjfee={cjfee}, txfee={self.config.tx_fee_contribution}, "
                f"bond_value={fidelity_bond_value}"
            )

            return [offer]

        except Exception as e:
            logger.error(f"Failed to create offers: {e}")
            return []

    def validate_offer_fill(self, offer: Offer, amount: int) -> tuple[bool, str]:
        """
        Validate a fill request for an offer.

        Args:
            offer: The offer being filled
            amount: Requested amount

        Returns:
            (is_valid, error_message)
        """
        if amount < offer.minsize:
            return False, f"Amount {amount} below minimum {offer.minsize}"

        if amount > offer.maxsize:
            return False, f"Amount {amount} above maximum {offer.maxsize}"

        return True, ""
