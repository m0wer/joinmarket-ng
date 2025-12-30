"""
Orderbook management and order selection for taker.

Implements:
- Orderbook fetching from directory nodes
- Order filtering by fee limits and amount ranges
- Maker selection algorithms (fidelity bond weighted, random, cheapest)
- Fee calculation for CoinJoin transactions
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from jmcore.bitcoin import (
    calculate_relative_fee,
    calculate_sweep_amount,
)
from jmcore.models import Offer, OfferType
from jmcore.protocol import get_nick_version
from loguru import logger

from taker.config import MaxCjFee


def calculate_cj_fee(offer: Offer, cj_amount: int) -> int:
    """
    Calculate the CoinJoin fee for a specific offer and amount.

    Args:
        offer: The maker's offer
        cj_amount: The CoinJoin amount in satoshis

    Returns:
        Fee in satoshis
    """
    if offer.ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
        return int(offer.cjfee)
    else:
        return calculate_relative_fee(cj_amount, str(offer.cjfee))


def is_fee_within_limits(offer: Offer, cj_amount: int, max_cj_fee: MaxCjFee) -> bool:
    """
    Check if an offer's fee is within the configured limits.

    For absolute offers: check cjfee <= abs_fee
    For relative offers: check cjfee <= rel_fee

    It's a logical OR - an offer passes if it meets either limit for its type.

    Args:
        offer: The maker's offer
        cj_amount: The CoinJoin amount (not used in the new logic)
        max_cj_fee: Fee limits configuration

    Returns:
        True if fee is acceptable
    """
    if offer.ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
        # For absolute offers, check against absolute limit directly
        return int(offer.cjfee) <= max_cj_fee.abs_fee
    else:
        # For relative offers, check against relative limit directly
        # Compare by calculating fee on a large reference amount
        ref_amount = 100_000_000_000  # 1000 BTC
        fee_val = calculate_relative_fee(ref_amount, str(offer.cjfee))
        limit_val = calculate_relative_fee(ref_amount, max_cj_fee.rel_fee)
        return fee_val <= limit_val


def filter_offers(
    offers: list[Offer],
    cj_amount: int,
    max_cj_fee: MaxCjFee,
    ignored_makers: set[str] | None = None,
    allowed_types: set[OfferType] | None = None,
    min_nick_version: int | None = None,
) -> list[Offer]:
    """
    Filter offers based on amount range, fee limits, and other criteria.

    Args:
        offers: List of all offers
        cj_amount: Target CoinJoin amount
        max_cj_fee: Fee limits
        ignored_makers: Set of maker nicks to exclude
        allowed_types: Set of allowed offer types (default: all sw0* types)
        min_nick_version: Minimum nick version for reference compatibility (not used for
            neutrino detection - that uses handshake features instead)

    Returns:
        List of eligible offers
    """
    if ignored_makers is None:
        ignored_makers = set()

    if allowed_types is None:
        allowed_types = {OfferType.SW0_RELATIVE, OfferType.SW0_ABSOLUTE}

    eligible = []

    for offer in offers:
        # Filter by maker
        if offer.counterparty in ignored_makers:
            logger.debug(f"Ignoring offer from {offer.counterparty} (in ignored list)")
            continue

        # Filter by nick version (reserved for potential future reference compatibility)
        # NOTE: This is NOT used for neutrino detection - that uses handshake features
        if min_nick_version is not None:
            nick_version = get_nick_version(offer.counterparty)
            if nick_version < min_nick_version:
                logger.debug(
                    f"Ignoring offer from {offer.counterparty}: "
                    f"nick version {nick_version} < required {min_nick_version}"
                )
                continue

        # Filter by offer type
        if offer.ordertype not in allowed_types:
            logger.debug(
                f"Ignoring offer from {offer.counterparty}: "
                f"type {offer.ordertype} not in allowed types"
            )
            continue

        # Filter by amount range
        if cj_amount < offer.minsize:
            logger.debug(
                f"Ignoring offer from {offer.counterparty}: "
                f"amount {cj_amount} < minsize {offer.minsize}"
            )
            continue

        if cj_amount > offer.maxsize:
            logger.debug(
                f"Ignoring offer from {offer.counterparty}: "
                f"amount {cj_amount} > maxsize {offer.maxsize}"
            )
            continue

        # Filter by fee limits
        if not is_fee_within_limits(offer, cj_amount, max_cj_fee):
            fee = calculate_cj_fee(offer, cj_amount)
            logger.debug(f"Ignoring offer from {offer.counterparty}: fee {fee} exceeds limits")
            continue

        eligible.append(offer)

    logger.info(f"Filtered {len(offers)} offers to {len(eligible)} eligible offers")
    return eligible


def dedupe_offers_by_maker(offers: list[Offer]) -> list[Offer]:
    """
    Keep only the cheapest offer from each maker.

    Args:
        offers: List of offers (possibly multiple per maker)

    Returns:
        List with at most one offer per maker (the cheapest)
    """
    by_maker: dict[str, list[Offer]] = {}

    for offer in offers:
        if offer.counterparty not in by_maker:
            by_maker[offer.counterparty] = []
        by_maker[offer.counterparty].append(offer)

    result = []
    for maker, maker_offers in by_maker.items():
        # Sort by absolute fee equivalent at some reference amount (1 BTC)
        reference_amount = 100_000_000  # 1 BTC
        sorted_offers = sorted(maker_offers, key=lambda o: calculate_cj_fee(o, reference_amount))
        result.append(sorted_offers[0])
        if len(maker_offers) > 1:
            logger.debug(f"Kept cheapest of {len(maker_offers)} offers from {maker}")

    return result


# Order chooser functions (selection algorithms)


def random_order_choose(offers: list[Offer], n: int) -> list[Offer]:
    """
    Choose n offers randomly.

    Args:
        offers: Eligible offers
        n: Number of offers to choose

    Returns:
        Selected offers
    """
    if len(offers) <= n:
        return offers[:]

    return random.sample(offers, n)


def cheapest_order_choose(offers: list[Offer], n: int, cj_amount: int = 0) -> list[Offer]:
    """
    Choose n cheapest offers.

    Args:
        offers: Eligible offers
        n: Number of offers to choose
        cj_amount: CoinJoin amount for fee calculation (default uses 1 BTC)

    Returns:
        Selected offers (sorted by fee, cheapest first)
    """
    if cj_amount == 0:
        cj_amount = 100_000_000  # 1 BTC

    sorted_offers = sorted(offers, key=lambda o: calculate_cj_fee(o, cj_amount))
    return sorted_offers[:n]


def weighted_order_choose(
    offers: list[Offer], n: int, cj_amount: int = 0, exponent: float = 3.0
) -> list[Offer]:
    """
    Choose n offers with exponential weighting by inverse fee.

    Cheaper offers are more likely to be selected.

    Args:
        offers: Eligible offers
        n: Number of offers to choose
        cj_amount: CoinJoin amount for fee calculation
        exponent: Higher values favor cheaper offers more strongly

    Returns:
        Selected offers
    """
    if len(offers) <= n:
        return offers[:]

    if cj_amount == 0:
        cj_amount = 100_000_000  # 1 BTC

    # Calculate weights (inverse fee, exponentially weighted)
    fees = [calculate_cj_fee(o, cj_amount) for o in offers]
    max_fee = max(fees) if fees else 1
    weights = [(max_fee - fee + 1) ** exponent for fee in fees]

    total_weight = sum(weights)
    if total_weight == 0:
        return random.sample(offers, n)

    selected = []
    remaining_offers = list(enumerate(offers))
    remaining_weights = list(weights)

    for _ in range(n):
        if not remaining_offers:
            break

        # Weighted random selection
        total = sum(remaining_weights)
        r = random.uniform(0, total)
        cumulative = 0

        for i, (idx, offer) in enumerate(remaining_offers):
            cumulative += remaining_weights[i]
            if r <= cumulative:
                selected.append(offer)
                remaining_offers.pop(i)
                remaining_weights.pop(i)
                break

    return selected


def fidelity_bond_weighted_choose(
    offers: list[Offer],
    n: int,
    bondless_makers_allowance: float = 0.125,
) -> list[Offer]:
    """
    Choose n offers with fidelity bond weighting.

    With probability `bondless_makers_allowance`, falls back to random selection.
    Otherwise, weights by fidelity bond value.

    Args:
        offers: Eligible offers
        n: Number of offers to choose
        bondless_makers_allowance: Probability of using random selection

    Returns:
        Selected offers
    """
    if len(offers) <= n:
        return offers[:]

    # With some probability, use random selection (allows makers without bonds)
    if random.random() < bondless_makers_allowance:
        logger.debug("Using random selection (bondless makers allowance)")
        return random_order_choose(offers, n)

    # Weight by fidelity bond value
    bond_values = [o.fidelity_bond_value for o in offers]

    # If no bonds, fall back to random
    if sum(bond_values) == 0:
        logger.debug("No fidelity bonds found, using random selection")
        return random_order_choose(offers, n)

    # Weighted selection
    selected = []
    remaining_offers = list(enumerate(offers))
    remaining_weights = list(bond_values)

    for _ in range(n):
        if not remaining_offers:
            break

        total = sum(remaining_weights)
        if total == 0:
            # Pick randomly from remaining
            idx = random.randrange(len(remaining_offers))
            selected.append(remaining_offers[idx][1])
            remaining_offers.pop(idx)
            remaining_weights.pop(idx)
            continue

        r = random.uniform(0, total)
        cumulative = 0

        for i, (idx, offer) in enumerate(remaining_offers):
            cumulative += remaining_weights[i]
            if r <= cumulative:
                selected.append(offer)
                remaining_offers.pop(i)
                remaining_weights.pop(i)
                break

    return selected


def choose_orders(
    offers: list[Offer],
    cj_amount: int,
    n: int,
    max_cj_fee: MaxCjFee,
    choose_fn: Callable[[list[Offer], int], list[Offer]] | None = None,
    ignored_makers: set[str] | None = None,
    min_nick_version: int | None = None,
    bondless_makers_allowance: float = 0.125,
) -> tuple[dict[str, Offer], int]:
    """
    Choose n orders from the orderbook for a CoinJoin.

    Args:
        offers: All offers from orderbook
        cj_amount: Target CoinJoin amount
        n: Number of makers to select
        max_cj_fee: Fee limits
        choose_fn: Selection algorithm (default: fidelity_bond_weighted_choose)
        ignored_makers: Makers to exclude
        min_nick_version: Minimum required nick version (e.g., 6 for neutrino takers)
        bondless_makers_allowance: Probability of random selection vs fidelity bond weighting

    Returns:
        (dict of counterparty -> offer, total_cj_fee)
    """
    if choose_fn is None:
        # Use partial to bind bondless_makers_allowance
        from functools import partial

        choose_fn = partial(
            fidelity_bond_weighted_choose, bondless_makers_allowance=bondless_makers_allowance
        )

    # Filter offers
    eligible = filter_offers(
        offers=offers,
        cj_amount=cj_amount,
        max_cj_fee=max_cj_fee,
        ignored_makers=ignored_makers,
        min_nick_version=min_nick_version,
    )

    # Dedupe by maker
    deduped = dedupe_offers_by_maker(eligible)

    if len(deduped) < n:
        logger.warning(
            f"Not enough makers: need {n}, found {len(deduped)} (from {len(offers)} total offers)"
        )
        n = len(deduped)

    # Select makers
    selected = choose_fn(deduped, n)

    # Build result
    result = {offer.counterparty: offer for offer in selected}

    # Calculate total fee
    total_fee = sum(calculate_cj_fee(offer, cj_amount) for offer in selected)

    logger.info(
        f"Selected {len(result)} makers from {len(offers)} offers, total fee: {total_fee} sats"
    )

    return result, total_fee


def choose_sweep_orders(
    offers: list[Offer],
    total_input_value: int,
    my_txfee: int,
    n: int,
    max_cj_fee: MaxCjFee,
    choose_fn: Callable[[list[Offer], int], list[Offer]] | None = None,
    ignored_makers: set[str] | None = None,
    min_nick_version: int | None = None,
    bondless_makers_allowance: float = 0.125,
) -> tuple[dict[str, Offer], int, int]:
    """
    Choose n orders for a sweep transaction (no change).

    For sweeps, we need to solve for cj_amount such that:
    my_change = total_input - cj_amount - sum(cjfees) - my_txfee = 0

    Args:
        offers: All offers from orderbook
        total_input_value: Total value of taker's inputs
        my_txfee: Taker's portion of transaction fee
        n: Number of makers to select
        max_cj_fee: Fee limits
        choose_fn: Selection algorithm
        ignored_makers: Makers to exclude
        min_nick_version: Minimum required nick version (e.g., 6 for neutrino takers)
        bondless_makers_allowance: Probability of random selection vs fidelity bond weighting

    Returns:
        (dict of counterparty -> offer, cj_amount, total_cj_fee)
    """
    if choose_fn is None:
        from functools import partial

        choose_fn = partial(
            fidelity_bond_weighted_choose, bondless_makers_allowance=bondless_makers_allowance
        )

    if ignored_makers is None:
        ignored_makers = set()

    # For sweep, we need to find offers that work for the available amount
    # First estimate: cj_amount = total_input - my_txfee - estimated_fees
    # Assume ~0.1% per maker for estimation
    estimated_rel_fees = ["0.001"] * n
    estimated_cj_amount = calculate_sweep_amount(total_input_value - my_txfee, estimated_rel_fees)

    # Filter with estimated amount
    eligible = filter_offers(
        offers=offers,
        cj_amount=estimated_cj_amount,
        max_cj_fee=max_cj_fee,
        ignored_makers=ignored_makers,
        min_nick_version=min_nick_version,
    )

    # Dedupe
    deduped = dedupe_offers_by_maker(eligible)

    if len(deduped) < n:
        logger.warning(f"Not enough makers for sweep: need {n}, found {len(deduped)}")
        n = len(deduped)

    if n == 0:
        return {}, 0, 0

    # Select makers
    selected = choose_fn(deduped, n)

    # Now solve for exact cj_amount
    sum_abs_fees = 0
    rel_fees = []

    for offer in selected:
        if offer.ordertype in (OfferType.SW0_ABSOLUTE, OfferType.SWA_ABSOLUTE):
            sum_abs_fees += int(offer.cjfee)
        else:
            rel_fees.append(str(offer.cjfee))

    available = total_input_value - my_txfee - sum_abs_fees
    cj_amount = calculate_sweep_amount(available, rel_fees)

    # Verify this works for all selected offers
    for offer in selected:
        if cj_amount < offer.minsize or cj_amount > offer.maxsize:
            logger.error(
                f"Sweep amount {cj_amount} outside range for {offer.counterparty}: "
                f"{offer.minsize}-{offer.maxsize}"
            )
            # Could retry with fewer makers here

    result = {offer.counterparty: offer for offer in selected}
    total_fee = sum(calculate_cj_fee(offer, cj_amount) for offer in selected)

    logger.info(f"Sweep: selected {len(result)} makers, cj_amount={cj_amount}, fee={total_fee}")

    return result, cj_amount, total_fee


class OrderbookManager:
    """Manages orderbook state and maker selection."""

    def __init__(self, max_cj_fee: MaxCjFee, bondless_makers_allowance: float = 0.125):
        self.max_cj_fee = max_cj_fee
        self.bondless_makers_allowance = bondless_makers_allowance
        self.offers: list[Offer] = []
        self.bonds: dict[str, Any] = {}  # maker -> bond info
        self.ignored_makers: set[str] = set()
        self.honest_makers: set[str] = set()

    def update_offers(self, offers: list[Offer]) -> None:
        """Update orderbook with new offers."""
        self.offers = offers
        logger.info(f"Updated orderbook with {len(offers)} offers")

    def add_ignored_maker(self, maker: str) -> None:
        """Add a maker to the ignored list (permanently for this session)."""
        self.ignored_makers.add(maker)
        logger.info(f"Added {maker} to ignored makers list")

    def add_honest_maker(self, maker: str) -> None:
        """Mark a maker as honest (completed a CoinJoin successfully)."""
        self.honest_makers.add(maker)
        logger.debug(f"Added {maker} to honest makers list")

    def select_makers(
        self,
        cj_amount: int,
        n: int,
        honest_only: bool = False,
        min_nick_version: int | None = None,
    ) -> tuple[dict[str, Offer], int]:
        """
        Select makers for a CoinJoin.

        Args:
            cj_amount: Target amount
            n: Number of makers
            honest_only: Only select from honest makers
            min_nick_version: Minimum required nick version (e.g., 6 for neutrino takers)

        Returns:
            (selected offers dict, total fee)
        """
        available_offers = self.offers

        if honest_only:
            available_offers = [o for o in self.offers if o.counterparty in self.honest_makers]

        return choose_orders(
            offers=available_offers,
            cj_amount=cj_amount,
            n=n,
            max_cj_fee=self.max_cj_fee,
            ignored_makers=self.ignored_makers,
            min_nick_version=min_nick_version,
            bondless_makers_allowance=self.bondless_makers_allowance,
        )

    def select_makers_for_sweep(
        self,
        total_input_value: int,
        my_txfee: int,
        n: int,
        honest_only: bool = False,
        min_nick_version: int | None = None,
    ) -> tuple[dict[str, Offer], int, int]:
        """
        Select makers for a sweep CoinJoin.

        Args:
            total_input_value: Total input value
            my_txfee: Taker's tx fee portion
            n: Number of makers
            honest_only: Only select from honest makers
            min_nick_version: Minimum required nick version (e.g., 6 for neutrino takers)

        Returns:
            (selected offers dict, cj_amount, total fee)
        """
        available_offers = self.offers

        if honest_only:
            available_offers = [o for o in self.offers if o.counterparty in self.honest_makers]

        return choose_sweep_orders(
            offers=available_offers,
            total_input_value=total_input_value,
            my_txfee=my_txfee,
            n=n,
            max_cj_fee=self.max_cj_fee,
            ignored_makers=self.ignored_makers,
            min_nick_version=min_nick_version,
            bondless_makers_allowance=self.bondless_makers_allowance,
        )
