"""
Offer management for makers.

Creates and manages liquidity offers based on wallet balance and configuration.
"""

from __future__ import annotations

import random

from jmcore.models import Offer, OfferType
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.config import MakerConfig
from maker.fidelity import get_best_fidelity_bond


def randomize_value(value: int | float, percent: float, is_float: bool = False) -> int | float:
    """
    Randomize a value by +/- a percentage.

    Args:
        value: Base value to randomize
        percent: Maximum percentage variation (e.g., 0.2 for ±20%)
        is_float: If True, return float; otherwise return int

    Returns:
        Randomized value
    """
    if percent <= 0:
        return value

    # Random factor between (1 - percent) and (1 + percent)
    factor = 1 + random.uniform(-percent, percent)
    result = value * factor

    if is_float:
        return result
    return int(result)


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

            # Reserve dust threshold + tx fee contribution
            max_available = max_balance - max(
                self.config.dust_threshold, self.config.tx_fee_contribution
            )

            if max_available <= self.config.min_size:
                logger.warning(f"Insufficient balance: {max_available} <= {self.config.min_size}")
                return []

            if self.config.offer_type in (OfferType.SW0_RELATIVE, OfferType.SWA_RELATIVE):
                cj_fee_base = float(self.config.cj_fee_relative)

                # Validate cj_fee_relative to prevent division by zero
                if cj_fee_base <= 0:
                    logger.error(
                        f"Invalid cj_fee_relative: {self.config.cj_fee_relative}. "
                        "Must be > 0 for relative offer types."
                    )
                    return []

                # Apply fee randomization if enabled
                if self.config.randomize_offer_fee:
                    cj_fee_randomized = randomize_value(
                        cj_fee_base, self.config.fee_randomization_percent, is_float=True
                    )
                    # Ensure it stays positive
                    cj_fee_randomized = max(cj_fee_randomized, cj_fee_base * 0.5)
                    cjfee = f"{cj_fee_randomized:.6f}"
                    logger.debug(
                        f"Randomized relative fee: {self.config.cj_fee_relative} -> {cjfee}"
                    )
                else:
                    cjfee = self.config.cj_fee_relative

                min_size_for_profit = int(1.5 * self.config.tx_fee_contribution / cj_fee_base)
                min_size = max(min_size_for_profit, self.config.min_size)
            else:
                # Absolute fee
                cj_fee_base = self.config.cj_fee_absolute

                # Apply fee randomization if enabled
                if self.config.randomize_offer_fee:
                    cj_fee_randomized = randomize_value(
                        cj_fee_base, self.config.fee_randomization_percent, is_float=False
                    )
                    # Ensure it stays positive and reasonable
                    cj_fee_randomized = max(int(cj_fee_randomized), cj_fee_base // 2)
                    cjfee = str(cj_fee_randomized)
                    logger.debug(f"Randomized absolute fee: {cj_fee_base} -> {cjfee}")
                else:
                    cjfee = str(cj_fee_base)

                min_size = self.config.min_size

            # Apply size randomization if enabled
            if self.config.randomize_offer_size:
                min_size = randomize_value(min_size, self.config.size_randomization_percent)
                max_available = randomize_value(
                    max_available, self.config.size_randomization_percent
                )
                # Ensure min_size < max_available
                if min_size >= max_available:
                    min_size = int(max_available * 0.5)
                logger.debug(
                    f"Randomized sizes: min={min_size:,} max={max_available:,} "
                    f"(±{self.config.size_randomization_percent * 100}%)"
                )

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
