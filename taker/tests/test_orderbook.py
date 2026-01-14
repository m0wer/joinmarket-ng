"""
Unit tests for orderbook management and order selection.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jmcore.models import Offer, OfferType

from taker.config import MaxCjFee
from taker.orderbook import (
    OrderbookManager,
    calculate_cj_fee,
    cheapest_order_choose,
    choose_orders,
    dedupe_offers_by_maker,
    fidelity_bond_weighted_choose,
    filter_offers,
    is_fee_within_limits,
    random_order_choose,
    weighted_order_choose,
)


@pytest.fixture
def sample_offers() -> list[Offer]:
    """Sample offers for testing."""
    return [
        Offer(
            counterparty="maker1",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee="0.001",
            fidelity_bond_value=100_000,
        ),
        Offer(
            counterparty="maker2",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=500_000,
            txfee=500,
            cjfee="0.0005",
            fidelity_bond_value=50_000,
        ),
        Offer(
            counterparty="maker3",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=10_000,
            maxsize=2_000_000,
            txfee=1500,
            cjfee=5000,  # Absolute fee
            fidelity_bond_value=200_000,
        ),
        Offer(
            counterparty="maker4",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=100_000,
            maxsize=10_000_000,
            txfee=2000,
            cjfee="0.002",
            fidelity_bond_value=0,
        ),
    ]


@pytest.fixture
def max_cj_fee() -> MaxCjFee:
    """Default fee limits - generous enough to allow maker3's absolute fee at 50k."""
    return MaxCjFee(abs_fee=50_000, rel_fee="0.1")


class TestCalculateCjFee:
    """Tests for calculate_cj_fee."""

    def test_relative_fee(self) -> None:
        """Test relative fee calculation."""
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee="0.001",
        )
        # 0.1% of 100,000 = 100
        assert calculate_cj_fee(offer, 100_000) == 100

    def test_absolute_fee(self) -> None:
        """Test absolute fee calculation."""
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee=5000,
        )
        # Fixed 5000 sats regardless of amount
        assert calculate_cj_fee(offer, 100_000) == 5000
        assert calculate_cj_fee(offer, 1_000_000) == 5000


class TestIsFeeWithinLimits:
    """Tests for is_fee_within_limits."""

    def test_within_limits(self, max_cj_fee: MaxCjFee) -> None:
        """Test relative fee within limits."""
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee="0.001",  # 0.1% - checked against rel_fee limit
        )
        # 0.001 <= 0.1 (rel_fee), so it passes
        assert is_fee_within_limits(offer, 100_000, max_cj_fee) is True

    def test_exceeds_absolute_limit(self) -> None:
        """Test absolute fee exceeds absolute limit."""
        max_fee = MaxCjFee(abs_fee=1000, rel_fee="0.01")
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee=5000,  # 5000 > 1000 abs_fee limit
        )
        assert is_fee_within_limits(offer, 100_000, max_fee) is False

    def test_exceeds_relative_limit(self) -> None:
        """Test relative fee exceeds relative limit."""
        max_fee = MaxCjFee(abs_fee=50_000, rel_fee="0.0005")  # 0.05%
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee="0.001",  # 0.001 > 0.0005 rel_fee limit
        )
        assert is_fee_within_limits(offer, 100_000, max_fee) is False

    def test_absolute_within_abs_limit_even_if_high_for_amount(self) -> None:
        """Test that absolute offers are only checked against abs limit, not amount."""
        max_fee = MaxCjFee(abs_fee=10_000, rel_fee="0.001")  # 0.1%
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=10_000,
            maxsize=1_000_000,
            txfee=1000,
            cjfee=5000,  # 5000 <= 10000 abs_fee, so it passes
        )
        # Even though 5000/100000 = 5% which exceeds the 0.1% rel_fee limit,
        # absolute offers are only checked against abs_fee
        assert is_fee_within_limits(offer, 100_000, max_fee) is True

    def test_relative_within_rel_limit_even_if_high_absolute(self) -> None:
        """Test that relative offers are only checked against rel limit, not absolute."""
        max_fee = MaxCjFee(abs_fee=100, rel_fee="0.01")  # 1%
        offer = Offer(
            counterparty="maker",
            oid=0,
            ordertype=OfferType.SW0_RELATIVE,
            minsize=10_000,
            maxsize=10_000_000,
            txfee=1000,
            cjfee="0.005",  # 0.5% - within 1% rel_fee limit
        )
        # At 10M sats, this would be 50,000 sats which exceeds abs_fee=100
        # But relative offers are only checked against rel_fee
        assert is_fee_within_limits(offer, 10_000_000, max_fee) is True


class TestFilterOffers:
    """Tests for filter_offers."""

    def test_filters_by_amount_range(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """Test filtering by amount range."""
        # maker4 requires minsize=100_000
        filtered = filter_offers(sample_offers, 50_000, max_cj_fee)
        assert len(filtered) == 3
        assert all(o.counterparty != "maker4" for o in filtered)

    def test_filters_ignored_makers(self, sample_offers: list[Offer], max_cj_fee: MaxCjFee) -> None:
        """Test filtering ignored makers."""
        filtered = filter_offers(
            sample_offers, 100_000, max_cj_fee, ignored_makers={"maker1", "maker2"}
        )
        assert len(filtered) == 2
        assert all(o.counterparty not in ("maker1", "maker2") for o in filtered)

    def test_filters_by_offer_type(self, sample_offers: list[Offer], max_cj_fee: MaxCjFee) -> None:
        """Test filtering by offer type."""
        filtered = filter_offers(
            sample_offers, 100_000, max_cj_fee, allowed_types={OfferType.SW0_ABSOLUTE}
        )
        assert len(filtered) == 1
        assert filtered[0].counterparty == "maker3"


class TestDedupeOffersByMaker:
    """Tests for dedupe_offers_by_maker."""

    def test_keeps_cheapest(self) -> None:
        """Test keeping only cheapest offer per maker."""
        offers = [
            Offer(
                counterparty="maker1",
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=1_000_000,
                txfee=1000,
                cjfee="0.002",  # More expensive
            ),
            Offer(
                counterparty="maker1",
                oid=1,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=1_000_000,
                txfee=1000,
                cjfee="0.001",  # Cheaper
            ),
        ]
        deduped = dedupe_offers_by_maker(offers)
        assert len(deduped) == 1
        assert deduped[0].cjfee == "0.001"


class TestOrderChoosers:
    """Tests for order selection algorithms."""

    def test_random_order_choose(self, sample_offers: list[Offer]) -> None:
        """Test random selection."""
        selected = random_order_choose(sample_offers, 2)
        assert len(selected) == 2
        assert all(o in sample_offers for o in selected)

    def test_random_order_choose_more_than_available(self, sample_offers: list[Offer]) -> None:
        """Test random selection when requesting more than available."""
        selected = random_order_choose(sample_offers, 10)
        assert len(selected) == len(sample_offers)

    def test_cheapest_order_choose(self, sample_offers: list[Offer]) -> None:
        """Test cheapest selection."""
        selected = cheapest_order_choose(sample_offers, 2, cj_amount=100_000)
        assert len(selected) == 2
        # maker2 (0.0005) and maker3 (5000 absolute = 5% at 100k) should be cheapest
        # Actually maker2 = 50 sats, maker3 = 5000 sats, maker1 = 100 sats
        nicks = {o.counterparty for o in selected}
        assert "maker2" in nicks  # Cheapest at 50 sats

    def test_weighted_order_choose(self, sample_offers: list[Offer]) -> None:
        """Test weighted selection."""
        selected = weighted_order_choose(sample_offers, 2)
        assert len(selected) == 2
        assert all(o in sample_offers for o in selected)

    def test_fidelity_bond_weighted_choose(self, sample_offers: list[Offer]) -> None:
        """Test fidelity bond weighted selection."""
        selected = fidelity_bond_weighted_choose(sample_offers, 2)
        assert len(selected) == 2
        # maker3 has highest bond value (200,000), should be frequently selected


class TestChooseOrders:
    """Tests for choose_orders."""

    def test_choose_orders(self, sample_offers: list[Offer], max_cj_fee: MaxCjFee) -> None:
        """Test full order selection flow."""
        orders, total_fee = choose_orders(
            offers=sample_offers,
            cj_amount=100_000,
            n=2,
            max_cj_fee=max_cj_fee,
        )
        assert len(orders) == 2
        assert total_fee > 0

    def test_choose_orders_not_enough_makers(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """Test when not enough makers available."""
        orders, total_fee = choose_orders(
            offers=sample_offers[:1],  # Only 1 offer
            cj_amount=100_000,
            n=3,
            max_cj_fee=max_cj_fee,
        )
        assert len(orders) == 1


class TestChooseSweepOrders:
    """Tests for choose_sweep_orders."""

    def test_choose_sweep_orders(self, max_cj_fee: MaxCjFee) -> None:
        """Test sweep order selection and amount calculation."""
        from taker.orderbook import choose_sweep_orders

        # Create specific offers for this test
        offers = [
            Offer(
                counterparty="maker1",
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=200_000_000,  # Large enough
                txfee=1000,
                cjfee="0.001",  # 0.1%
                fidelity_bond_value=100_000,
            ),
            Offer(
                counterparty="maker2",
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=200_000_000,  # Large enough
                txfee=500,
                cjfee="0.0005",  # 0.05%
                fidelity_bond_value=50_000,
            ),
        ]

        # Total input 1 BTC, txfee 10k sats
        # Makers: maker1 (0.1%), maker2 (0.05%)
        # Approx fees: 0.15% of ~1 BTC ~ 150k sats
        # expected cj_amount around 100M - 10k - 150k = 99.84M
        orders, cj_amount, total_fee = choose_sweep_orders(
            offers=offers,
            total_input_value=100_000_000,
            my_txfee=10_000,
            n=2,
            max_cj_fee=max_cj_fee,
        )
        assert len(orders) == 2
        assert cj_amount > 0
        assert total_fee > 0
        # Should be exactly equal or off by very small amount due to integer rounding
        # With integer arithmetic, we might leave 1-2 sats behind (miner donation)
        diff = 100_000_000 - (cj_amount + total_fee + 10_000)
        assert diff >= 0
        assert diff < 5

        # Verify cj_amount is calculated correctly with integer arithmetic
        # sum_rel_fees = 0.001 + 0.0005 = 0.0015
        # available = 100_000_000 - 10_000 = 99_990_000
        # expected = 99_990_000 / 1.0015 = 99,840,239 (rounded down)
        # Using integer arithmetic:
        # num=99990000, den=10000, sum_num=15
        # (99990000 * 10000) // (10000 + 15) = 999900000000 // 10015 = 99840239
        assert cj_amount == 99_840_239


class TestOrderbookManager:
    """Tests for OrderbookManager."""

    def test_update_offers(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """Test updating orderbook."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(sample_offers)
        assert len(manager.offers) == len(sample_offers)

    def test_add_ignored_maker(self, max_cj_fee: MaxCjFee, tmp_path: Path) -> None:
        """Test adding ignored maker."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.add_ignored_maker("bad_maker")
        assert "bad_maker" in manager.ignored_makers

        # Verify persistence
        ignored_path = tmp_path / "ignored_makers.txt"
        assert ignored_path.exists()
        with open(ignored_path, encoding="utf-8") as f:
            makers = {line.strip() for line in f}
        assert "bad_maker" in makers

    def test_ignored_makers_persistence(self, max_cj_fee: MaxCjFee, tmp_path: Path) -> None:
        """Test that ignored makers persist across manager instances."""
        # First manager adds ignored makers
        manager1 = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager1.add_ignored_maker("maker1")
        manager1.add_ignored_maker("maker2")
        assert len(manager1.ignored_makers) == 2

        # Second manager should load the persisted ignored makers
        manager2 = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        assert len(manager2.ignored_makers) == 2
        assert "maker1" in manager2.ignored_makers
        assert "maker2" in manager2.ignored_makers

    def test_clear_ignored_makers(self, max_cj_fee: MaxCjFee, tmp_path: Path) -> None:
        """Test clearing ignored makers."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.add_ignored_maker("maker1")
        manager.add_ignored_maker("maker2")
        assert len(manager.ignored_makers) == 2

        ignored_path = tmp_path / "ignored_makers.txt"
        assert ignored_path.exists()

        manager.clear_ignored_makers()
        assert len(manager.ignored_makers) == 0
        assert not ignored_path.exists()

    def test_add_honest_maker(self, max_cj_fee: MaxCjFee, tmp_path: Path) -> None:
        """Test adding honest maker."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.add_honest_maker("good_maker")
        assert "good_maker" in manager.honest_makers

    def test_select_makers(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """Test maker selection."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(sample_offers)

        orders, fee = manager.select_makers(cj_amount=100_000, n=2)
        assert len(orders) == 2
        assert fee > 0

    def test_select_makers_honest_only(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """Test honest-only maker selection."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(sample_offers)
        manager.add_honest_maker("maker1")

        orders, fee = manager.select_makers(cj_amount=100_000, n=2, honest_only=True)
        # Only maker1 is honest
        assert len(orders) <= 1

    def test_select_makers_exclude_nicks(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """Test maker selection with explicit nick exclusion.

        This tests the exclude_nicks parameter used during maker replacement
        to avoid re-selecting makers that are already in the current session.
        """
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(sample_offers)

        # First, select some makers without exclusion
        orders1, _ = manager.select_makers(cj_amount=100_000, n=2)
        assert len(orders1) == 2

        # Get the nicks of selected makers
        selected_nicks = set(orders1.keys())

        # Now select again, excluding the previously selected makers
        orders2, _ = manager.select_makers(
            cj_amount=100_000,
            n=2,
            exclude_nicks=selected_nicks,
        )

        # The newly selected makers should not overlap with the first selection
        new_nicks = set(orders2.keys())
        assert len(new_nicks & selected_nicks) == 0, "Should not re-select excluded makers"

    def test_select_makers_exclude_nicks_combined_with_ignored(
        self, sample_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """Test that exclude_nicks works together with ignored_makers."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(sample_offers)

        # Ignore maker1
        manager.add_ignored_maker("maker1")

        # Exclude maker2 via parameter
        exclude = {"maker2"}

        # Try to select makers (should not get maker1 or maker2)
        orders, _ = manager.select_makers(
            cj_amount=100_000,
            n=2,
            exclude_nicks=exclude,
        )

        # Verify neither excluded maker is in the result
        assert "maker1" not in orders
        assert "maker2" not in orders


class TestMixedBondedBondlessSelection:
    """Tests for the mixed bonded/bondless selection strategy."""

    def test_deterministic_split(self) -> None:
        """Test that the split between bonded and bondless is deterministic."""
        offers = [
            Offer(
                counterparty=f"Maker{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=1000 if i < 5 else 0,  # First 5 bonded
            )
            for i in range(10)
        ]

        # With 3 makers and 0.125 allowance: bonded = floor(3 * 0.875) = 2
        selected = fidelity_bond_weighted_choose(
            offers=offers, n=3, bondless_makers_allowance=0.125, bondless_require_zero_fee=False
        )

        assert len(selected) == 3

    def test_fills_all_slots(self) -> None:
        """Ensure we always fill all n slots when enough offers exist."""
        offers = [
            Offer(
                counterparty=f"BondedMaker{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=100000,
            )
            for i in range(2)
        ] + [
            Offer(
                counterparty=f"BondlessMaker{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=0,
            )
            for i in range(8)
        ]

        # Should always get exactly 5 makers
        for _ in range(10):
            selected = fidelity_bond_weighted_choose(
                offers=offers,
                n=5,
                bondless_makers_allowance=0.2,
                bondless_require_zero_fee=False,
            )
            assert len(selected) == 5

    def test_bonded_makers_prioritized(self) -> None:
        """High-bond makers should be heavily favored in bonded slots."""
        high_bond = Offer(
            counterparty="HighBond",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=1000,
            maxsize=1000000,
            txfee=0,
            cjfee=0,
            fidelity_bond_value=1_000_000_000,  # 1B sats
        )

        low_bonds = [
            Offer(
                counterparty=f"LowBond{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=1000,  # 1k sats
            )
            for i in range(9)
        ]

        offers = [high_bond] + low_bonds

        # Run 100 times, high bond should be selected almost always
        # With allowance=0.2, bonded slots = floor(3 * 0.8) = 2
        # HighBond should win at least one of these slots nearly every time
        high_bond_count = 0
        for _ in range(100):
            selected = fidelity_bond_weighted_choose(
                offers=offers, n=3, bondless_makers_allowance=0.2, bondless_require_zero_fee=False
            )
            if high_bond in selected:
                high_bond_count += 1

        # Should be selected in >90% of runs
        assert high_bond_count > 90

    def test_bondless_fills_remaining_with_zero_fee(self) -> None:
        """Bondless slots should fill from zero-fee offers when required."""
        bonded = [
            Offer(
                counterparty=f"Bonded{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=100000,
            )
            for i in range(2)
        ]

        # Zero fee bondless
        zero_fee = [
            Offer(
                counterparty=f"ZeroFee{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,  # Zero fee
                fidelity_bond_value=0,
            )
            for i in range(3)
        ]

        # Non-zero fee bondless (should be excluded from bondless slots)
        nonzero_fee = [
            Offer(
                counterparty=f"NonZeroFee{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=100,  # Non-zero fee
                fidelity_bond_value=0,
            )
            for i in range(3)
        ]

        offers = bonded + zero_fee + nonzero_fee

        # With n=3, allowance=0.4: bonded=floor(3*0.6)=1, bondless=2
        # Should pick 1 bonded + 2 from zero_fee (not nonzero_fee)
        for _ in range(10):
            selected = fidelity_bond_weighted_choose(
                offers=offers, n=3, bondless_makers_allowance=0.4, bondless_require_zero_fee=True
            )
            assert len(selected) == 3

            # Check that nonzero_fee makers are not in bondless slots
            # (Note: they could be in bonded slots since they have bond=0,
            # but bonded prioritizes bond>0)
            selected_nicks = {o.counterparty for o in selected}
            nonzero_nicks = {o.counterparty for o in nonzero_fee}

            # Since bonded slots pick from bond>0 only, and bondless require zero fee,
            # nonzero_fee makers should not appear
            assert len(selected_nicks & nonzero_nicks) == 0

    def test_insufficient_bonded_fills_from_bondless(self) -> None:
        """If not enough bonded offers, fill remainder from bondless pool."""
        # Only 1 bonded maker
        bonded = Offer(
            counterparty="OnlyBonded",
            oid=0,
            ordertype=OfferType.SW0_ABSOLUTE,
            minsize=1000,
            maxsize=1000000,
            txfee=0,
            cjfee=0,
            fidelity_bond_value=100000,
        )

        # 5 bondless makers
        bondless = [
            Offer(
                counterparty=f"Bondless{i}",
                oid=0,
                ordertype=OfferType.SW0_ABSOLUTE,
                minsize=1000,
                maxsize=1000000,
                txfee=0,
                cjfee=0,
                fidelity_bond_value=0,
            )
            for i in range(5)
        ]

        offers = [bonded] + bondless

        # With n=4, allowance=0.25: bonded=floor(4*0.75)=3, bondless=1
        # But we only have 1 bonded offer, so remaining 3 slots filled from bondless
        selected = fidelity_bond_weighted_choose(
            offers=offers, n=4, bondless_makers_allowance=0.25, bondless_require_zero_fee=False
        )

        assert len(selected) == 4
        # OnlyBonded should always be selected (in bonded phase)
        assert bonded in selected


class TestFilterOffersByNickVersion:
    """Tests for filtering offers by nick version (reserved for future reference compat).

    NOTE: Nick version filtering is NOT used for neutrino detection - that uses
    handshake features instead. These tests ensure the filter logic works correctly
    for potential future reference implementation compatibility.
    """

    @pytest.fixture
    def mixed_version_offers(self) -> list[Offer]:
        """Offers from makers with different nicks (all J5 in our implementation)."""
        return [
            Offer(
                counterparty="J5oldmaker123OOO",  # maker 1
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=1_000_000,
                txfee=1000,
                cjfee="0.001",
            ),
            Offer(
                counterparty="J5newmaker456OOO",  # maker 2
                oid=0,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=1_000_000,
                txfee=1000,
                cjfee="0.001",
            ),
            Offer(
                counterparty="J5another789OOO",  # maker 3
                oid=1,
                ordertype=OfferType.SW0_RELATIVE,
                minsize=10_000,
                maxsize=500_000,
                txfee=500,
                cjfee="0.0005",
            ),
        ]

    def test_filter_no_version_requirement(
        self, mixed_version_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """Without version requirement, all offers pass."""
        eligible = filter_offers(
            offers=mixed_version_offers,
            cj_amount=100_000,
            max_cj_fee=max_cj_fee,
            min_nick_version=None,
        )
        assert len(eligible) == 3

    def test_filter_min_version(
        self, mixed_version_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """Test min_nick_version filtering (for potential future reference compat)."""
        # In our implementation all makers use v5, but filter logic remains for future compat
        eligible = filter_offers(
            offers=mixed_version_offers,
            cj_amount=100_000,
            max_cj_fee=max_cj_fee,
            min_nick_version=6,  # Would filter for hypothetical future nick versions
        )
        # All our test makers are J5, so none pass
        assert len(eligible) == 0

    def test_choose_orders_with_version_filter(
        self, mixed_version_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """choose_orders respects min_nick_version (for reference compat)."""
        orders, fee = choose_orders(
            offers=mixed_version_offers,
            cj_amount=100_000,
            n=2,
            max_cj_fee=max_cj_fee,
            min_nick_version=5,  # Our makers are J5
        )
        assert len(orders) == 2
        for nick in orders.keys():
            assert nick.startswith("J5")

    def test_orderbook_manager_with_version_filter(
        self, mixed_version_offers: list[Offer], max_cj_fee: MaxCjFee, tmp_path: Path
    ) -> None:
        """OrderbookManager.select_makers respects min_nick_version."""
        manager = OrderbookManager(max_cj_fee, data_dir=tmp_path)
        manager.update_offers(mixed_version_offers)

        orders, fee = manager.select_makers(cj_amount=100_000, n=2, min_nick_version=5)
        assert len(orders) == 2
        for nick in orders.keys():
            assert nick.startswith("J5")

    def test_not_enough_makers_with_min_version(
        self, mixed_version_offers: list[Offer], max_cj_fee: MaxCjFee
    ) -> None:
        """When not enough makers meet version requirement, return what's available."""
        orders, fee = choose_orders(
            offers=mixed_version_offers,
            cj_amount=100_000,
            n=5,  # Request more than total available
            max_cj_fee=max_cj_fee,
            min_nick_version=5,
        )
        # Only 3 J5 makers available
        assert len(orders) == 3
