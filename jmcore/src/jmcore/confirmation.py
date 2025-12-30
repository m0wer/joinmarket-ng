"""
User confirmation prompts for fund-moving operations.
"""

from __future__ import annotations

import os
import sys
from typing import Any


def is_interactive_mode() -> bool:
    """
    Check if we're running in interactive mode.

    Returns False if NO_INTERACTIVE env var is set or if not attached to a TTY.
    """
    if os.environ.get("NO_INTERACTIVE"):
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def confirm_transaction(
    operation: str,
    amount: int,
    destination: str | None = None,
    fee: int | None = None,
    additional_info: dict[str, Any] | None = None,
    skip_confirmation: bool = False,
) -> bool:
    """
    Prompt user to confirm a transaction that moves funds.

    Args:
        operation: Type of operation (e.g., "send", "coinjoin")
        amount: Amount in satoshis (0 for sweep)
        destination: Destination address (optional)
        fee: Total fee in satoshis (optional)
        additional_info: Additional details to show (e.g., maker fees, counterparties)
        skip_confirmation: If True, skip prompt (from --yes flag)

    Returns:
        True if user confirms, False otherwise

    Raises:
        RuntimeError: If in non-interactive mode without skip_confirmation
    """
    # Skip if confirmation disabled
    if skip_confirmation:
        return True

    # Error if non-interactive without --yes
    if not is_interactive_mode():
        raise RuntimeError(
            "Cannot prompt for confirmation in non-interactive mode. "
            "Use --yes flag or set NO_INTERACTIVE=1 to skip confirmation."
        )

    # Build transaction summary
    print("\n" + "=" * 80)
    print(f"TRANSACTION CONFIRMATION - {operation.upper()}")
    print("=" * 80)

    # Amount
    if amount == 0:
        print("Amount:       SWEEP (all available funds)")
    else:
        from jmcore.bitcoin import format_amount

        print(f"Amount:       {format_amount(amount)}")

    # Destination
    if destination:
        if destination == "INTERNAL":
            print("Destination:  INTERNAL (next mixdepth)")
        else:
            print(f"Destination:  {destination}")

    # Fee
    if fee is not None:
        from jmcore.bitcoin import format_amount

        print(f"Fee:          {format_amount(fee)}")

    # Additional info
    if additional_info:
        for key, value in additional_info.items():
            # Format based on type
            if isinstance(value, int) and key.lower().endswith(("fee", "amount", "value")):
                from jmcore.bitcoin import format_amount

                print(f"{key}:  {format_amount(value)}".ljust(80))
            elif isinstance(value, list):
                print(f"{key}:  {len(value)} item(s)")
                for i, item in enumerate(value, 1):
                    if isinstance(item, dict):
                        # Show dict items nicely
                        print(f"  {i}. {item}")
                    else:
                        print(f"  {i}. {item}")
            else:
                print(f"{key}:  {value}".ljust(80))

    print("=" * 80)

    # Prompt for confirmation
    try:
        response = input("\nProceed with this transaction? [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\n\nTransaction cancelled by user.")
        return False


def format_maker_summary(makers: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Format maker information for confirmation display.

    Args:
        makers: List of selected maker dicts with 'nick', 'fee', 'bond_value', etc.

    Returns:
        Dict with formatted maker info
    """
    total_maker_fee = sum(m.get("fee", 0) for m in makers)

    maker_details = []
    for m in makers:
        nick = m.get("nick", "unknown")
        fee = m.get("fee", 0)
        bond_value = m.get("bond_value", 0)
        bond_str = f" [bond: {bond_value:,}]" if bond_value > 0 else " [no bond]"
        maker_details.append(f"{nick}: {fee:,} sats{bond_str}")

    return {
        "Counterparties": len(makers),
        "Total Maker Fees": total_maker_fee,
        "Makers": maker_details,
    }
