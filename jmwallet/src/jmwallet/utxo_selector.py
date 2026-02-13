"""
Interactive UTXO selector TUI.

Provides an fzf-like interface for manually selecting UTXOs
with multi-select support using Tab and Enter to confirm.
"""

from __future__ import annotations

import curses
import sys
from typing import TYPE_CHECKING

from jmcore.bitcoin import format_amount

if TYPE_CHECKING:
    from jmwallet.wallet.models import UTXOInfo


def format_utxo_line(utxo: UTXOInfo, max_width: int = 80) -> str:
    """Format a single UTXO for display.

    Args:
        utxo: The UTXO to format
        max_width: Maximum line width

    Returns:
        Formatted string showing mixdepth, amount, confirmations, outpoint, and label
    """
    amount_str = format_amount(utxo.value)
    conf_str = f"{utxo.confirmations:>6} conf"
    md_str = f"m{utxo.mixdepth}"

    # Fidelity bond indicator (locked vs unlocked)
    fb_indicator = ""
    if utxo.is_fidelity_bond:
        if utxo.is_locked:
            fb_indicator = " [FB-LOCKED]"
        else:
            fb_indicator = " [FB]"

    # Truncate txid for display
    outpoint = f"{utxo.txid[:8]}...:{utxo.vout}"

    # Label/note for UTXO type
    label_str = f" ({utxo.label})" if utxo.label else ""

    # Frozen indicator (placed after label for consistency with --extended view)
    frozen_indicator = " [FROZEN]" if utxo.frozen else ""

    line = (
        f"{md_str:>3} | {amount_str:>18} | {conf_str} | "
        f"{outpoint}{fb_indicator}{label_str}{frozen_indicator}"
    )

    if len(line) > max_width:
        line = line[: max_width - 3] + "..."

    return line


def _run_selector(
    stdscr: curses.window,
    utxos: list[UTXOInfo],
    target_amount: int,
) -> list[UTXOInfo]:
    """Run the curses-based UTXO selector.

    Args:
        stdscr: The curses window
        utxos: List of available UTXOs
        target_amount: Target amount in sats (0 for sweep, shown for info)

    Returns:
        List of selected UTXOs
    """
    # Initialize curses
    curses.curs_set(0)  # Hide cursor
    curses.use_default_colors()

    # Initialize color pairs
    curses.init_pair(1, curses.COLOR_GREEN, -1)  # Selected items
    curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Current cursor
    curses.init_pair(3, curses.COLOR_CYAN, -1)  # Header
    curses.init_pair(4, curses.COLOR_RED, -1)  # Locked fidelity bonds / frozen UTXOs
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Unlocked fidelity bonds (can be spent)

    selected: set[int] = set()
    cursor_pos = 0
    scroll_offset = 0

    # Pre-compute which UTXOs are unselectable (frozen or locked fidelity bonds)
    unselectable: set[int] = {
        i for i, u in enumerate(utxos) if u.frozen or (u.is_fidelity_bond and u.is_locked)
    }

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        # Header
        header = " UTXO Selector - Tab: toggle, Enter: confirm, q: cancel "
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, 0, header.center(width)[:width])
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

        # Column headers
        col_header = "    MD |             Amount |   Confs   | Outpoint (Label)"
        stdscr.addstr(1, 0, col_header[:width])
        stdscr.addstr(2, 0, "-" * min(len(col_header), width))

        # Calculate visible area
        list_start = 3
        list_height = height - 6  # Reserve space for header and footer

        # Adjust scroll to keep cursor visible
        if cursor_pos < scroll_offset:
            scroll_offset = cursor_pos
        elif cursor_pos >= scroll_offset + list_height:
            scroll_offset = cursor_pos - list_height + 1

        # Display UTXOs
        for i, utxo in enumerate(utxos):
            if i < scroll_offset or i >= scroll_offset + list_height:
                continue

            display_row = list_start + (i - scroll_offset)
            if display_row >= height - 3:
                break

            # Format the line
            is_selected = i in selected
            is_cursor = i == cursor_pos
            is_unselectable = i in unselectable

            if is_unselectable:
                prefix = "[-] "
            elif is_selected:
                prefix = "[x] "
            else:
                prefix = "[ ] "
            line = prefix + format_utxo_line(utxo, width - 5)

            # Apply colors
            if is_cursor:
                attr = curses.color_pair(2) | curses.A_REVERSE
            elif is_selected:
                attr = curses.color_pair(1) | curses.A_BOLD
            elif utxo.frozen:
                # Frozen UTXOs - red, dimmed (excluded from automatic selection)
                attr = curses.color_pair(4) | curses.A_DIM
            elif utxo.is_fidelity_bond:
                if utxo.is_locked:
                    # Locked FB - red, dimmed (cannot be spent yet)
                    attr = curses.color_pair(4) | curses.A_DIM
                else:
                    # Unlocked FB - magenta (can be spent but should be careful)
                    attr = curses.color_pair(5)
            else:
                attr = curses.A_NORMAL

            try:
                stdscr.addstr(display_row, 0, line[: width - 1], attr)
            except curses.error:
                pass  # Ignore if we write past the edge

        # Footer with selection summary
        total_selected = sum(utxos[i].value for i in selected)
        total_str = format_amount(total_selected)
        selectable_count = len(utxos) - len(unselectable)
        footer_line1 = f" Selected: {len(selected)}/{selectable_count} UTXOs | Total: {total_str} "

        if target_amount > 0:
            remaining = target_amount - total_selected
            target_str = format_amount(target_amount)
            if remaining > 0:
                footer_line2 = f" Target: {target_str} | Need: {format_amount(remaining)} more "
            else:
                excess_str = format_amount(-remaining)
                footer_line2 = f" Target: {target_str} | Excess: {excess_str} (change) "
        else:
            footer_line2 = " Sweep mode: all selected UTXOs will be spent "

        stdscr.addstr(height - 3, 0, "-" * min(width, 80))

        stdscr.attron(curses.A_BOLD)
        try:
            stdscr.addstr(height - 2, 0, footer_line1[: width - 1])
            stdscr.addstr(height - 1, 0, footer_line2[: width - 1])
        except curses.error:
            pass
        stdscr.attroff(curses.A_BOLD)

        stdscr.refresh()

        # Handle input
        key = stdscr.getch()

        if key == ord("q") or key == 27:  # q or Escape
            return []

        if key == ord("\n") or key == curses.KEY_ENTER:  # Enter
            if selected:
                return [utxos[i] for i in sorted(selected)]
            # If nothing selected but there's only one selectable UTXO, select it
            if selectable_count == 1:
                selectable_idx = next(i for i in range(len(utxos)) if i not in unselectable)
                return [utxos[selectable_idx]]
            # Otherwise require explicit selection
            continue

        if key == ord("\t") or key == ord(" "):  # Tab or Space to toggle
            if cursor_pos not in unselectable:
                if cursor_pos in selected:
                    selected.discard(cursor_pos)
                else:
                    selected.add(cursor_pos)
            # Move cursor down after toggle attempt
            if cursor_pos < len(utxos) - 1:
                cursor_pos += 1

        elif key == curses.KEY_UP or key == ord("k"):
            cursor_pos = max(0, cursor_pos - 1)

        elif key == curses.KEY_DOWN or key == ord("j"):
            cursor_pos = min(len(utxos) - 1, cursor_pos + 1)

        elif key == curses.KEY_PPAGE:  # Page Up
            cursor_pos = max(0, cursor_pos - list_height)

        elif key == curses.KEY_NPAGE:  # Page Down
            cursor_pos = min(len(utxos) - 1, cursor_pos + list_height)

        elif key == ord("g"):  # Go to top
            cursor_pos = 0

        elif key == ord("G"):  # Go to bottom
            cursor_pos = len(utxos) - 1

        elif key == ord("a"):  # Select all (skip unselectable UTXOs)
            selected = {i for i in range(len(utxos)) if i not in unselectable}

        elif key == ord("n"):  # Deselect all
            selected = set()


def select_utxos_interactive(
    utxos: list[UTXOInfo],
    target_amount: int = 0,
) -> list[UTXOInfo]:
    """Display an interactive UTXO selector.

    Provides an fzf-like interface for selecting UTXOs:
    - Up/Down or j/k: Navigate
    - Tab/Space: Toggle selection
    - Enter: Confirm selection
    - q/Escape: Cancel
    - a: Select all
    - n: Deselect all
    - g/G: Go to top/bottom

    Args:
        utxos: List of available UTXOs to choose from
        target_amount: Target amount in sats (0 for sweep, used for display)

    Returns:
        List of selected UTXOs, empty if cancelled

    Raises:
        RuntimeError: If not running in a terminal
    """
    # Handle trivial cases without requiring a terminal
    if not utxos:
        return []

    # For multiple UTXOs, we need a terminal
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        # If only one UTXO and no terminal, auto-select it (only if selectable)
        if len(utxos) == 1:
            utxo = utxos[0]
            if utxo.frozen or (utxo.is_fidelity_bond and utxo.is_locked):
                return []
            return utxos
        raise RuntimeError("Interactive UTXO selection requires a terminal")

    # Sort UTXOs by mixdepth, then by value (descending)
    sorted_utxos = sorted(utxos, key=lambda u: (u.mixdepth, -u.value))

    return curses.wrapper(_run_selector, sorted_utxos, target_amount)
