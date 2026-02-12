"""
Coin selection algorithms for wallet spending.

Provides UTXO selection strategies for CoinJoin transactions and sweeps.
"""

from __future__ import annotations

from jmwallet.wallet.models import UTXOInfo


class CoinSelectionMixin:
    """Mixin providing coin selection capabilities.

    Expects the host class to provide ``utxo_cache`` (dict[int, list[UTXOInfo]]).
    """

    # Declared for mypy -- actually set by the host class __init__
    utxo_cache: dict[int, list[UTXOInfo]]

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
