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
        Formatted string showing mixdepth, amount, confirmations, and outpoint
    """
    amount_str = format_amount(utxo.value)
    conf_str = f"{utxo.confirmations:>6} conf"
    md_str = f"m{utxo.mixdepth}"

    # Timelocked indicator
    lock_indicator = " [LOCKED]" if utxo.is_timelocked else ""

    # Truncate txid for display
    outpoint = f"{utxo.txid[:8]}...:{utxo.vout}"

    line = f"{md_str:>3} | {amount_str:>18} | {conf_str} | {outpoint}{lock_indicator}"

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
    curses.init_pair(4, curses.COLOR_RED, -1)  # Locked UTXOs

    selected: set[int] = set()
    cursor_pos = 0
    scroll_offset = 0

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        # Header
        header = " UTXO Selector - Tab: toggle, Enter: confirm, q: cancel "
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, 0, header.center(width)[:width])
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

        # Column headers
        col_header = "    MD |             Amount |   Confs   | Outpoint"
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

            prefix = "[x] " if is_selected else "[ ] "
            line = prefix + format_utxo_line(utxo, width - 5)

            # Apply colors
            if is_cursor:
                attr = curses.color_pair(2) | curses.A_REVERSE
            elif is_selected:
                attr = curses.color_pair(1) | curses.A_BOLD
            elif utxo.is_timelocked:
                attr = curses.color_pair(4)
            else:
                attr = curses.A_NORMAL

            try:
                stdscr.addstr(display_row, 0, line[: width - 1], attr)
            except curses.error:
                pass  # Ignore if we write past the edge

        # Footer with selection summary
        total_selected = sum(utxos[i].value for i in selected)
        total_str = format_amount(total_selected)
        footer_line1 = f" Selected: {len(selected)}/{len(utxos)} UTXOs | Total: {total_str} "

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
            # If nothing selected but there's only one UTXO, select it
            if len(utxos) == 1:
                return [utxos[0]]
            # Otherwise require explicit selection
            continue

        if key == ord("\t") or key == ord(" "):  # Tab or Space to toggle
            if cursor_pos in selected:
                selected.discard(cursor_pos)
            else:
                selected.add(cursor_pos)
            # Move cursor down after selection
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

        elif key == ord("a"):  # Select all
            selected = set(range(len(utxos)))

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

    # If only one UTXO, return it directly
    if len(utxos) == 1:
        return utxos

    # For multiple UTXOs, we need a terminal
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("Interactive UTXO selection requires a terminal")

    # Sort UTXOs by mixdepth, then by value (descending)
    sorted_utxos = sorted(utxos, key=lambda u: (u.mixdepth, -u.value))

    return curses.wrapper(_run_selector, sorted_utxos, target_amount)
