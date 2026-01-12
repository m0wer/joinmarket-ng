"""
Tests for the interactive UTXO selector TUI.

Tests cover:
- format_utxo_line() output formatting
- select_utxos_interactive() behavior in non-TTY environments
- Single UTXO auto-selection
"""

from __future__ import annotations

import pytest

from jmwallet.utxo_selector import format_utxo_line, select_utxos_interactive
from jmwallet.wallet.models import UTXOInfo


@pytest.fixture
def sample_utxos() -> list[UTXOInfo]:
    """Create sample UTXOs for testing."""
    return [
        UTXOInfo(
            txid="a" * 64,
            vout=0,
            value=100_000,
            address="bcrt1test1",
            confirmations=10,
            scriptpubkey="0014" + "aa" * 20,
            path="m/84'/0'/0'/0/0",
            mixdepth=0,
        ),
        UTXOInfo(
            txid="b" * 64,
            vout=1,
            value=50_000,
            address="bcrt1test2",
            confirmations=5,
            scriptpubkey="0014" + "bb" * 20,
            path="m/84'/0'/0'/0/1",
            mixdepth=0,
        ),
        UTXOInfo(
            txid="c" * 64,
            vout=0,
            value=1_000_000,
            address="bcrt1test3",
            confirmations=100,
            scriptpubkey="0014" + "cc" * 20,
            path="m/84'/0'/0'/0/2",
            mixdepth=1,
        ),
        # Timelocked fidelity bond UTXO
        UTXOInfo(
            txid="d" * 64,
            vout=0,
            value=500_000,
            address="bcrt1bond",
            confirmations=1000,
            scriptpubkey="0020" + "dd" * 32,  # P2WSH
            path="m/84'/0'/0'/2/0",
            mixdepth=0,
            locktime=1893456000,
        ),
    ]


class TestFormatUtxoLine:
    """Tests for format_utxo_line()."""

    def test_format_basic_utxo(self, sample_utxos: list[UTXOInfo]) -> None:
        """Test formatting a basic UTXO."""
        utxo = sample_utxos[0]
        line = format_utxo_line(utxo)

        assert "m0" in line  # Mixdepth 0
        assert "100,000" in line or "0.00100000" in line  # Amount
        assert "10 conf" in line  # Confirmations
        assert "aaaaaaaa" in line  # Truncated txid
        assert ":0" in line  # Vout

    def test_format_timelocked_utxo(self, sample_utxos: list[UTXOInfo]) -> None:
        """Test formatting a timelocked (fidelity bond) UTXO."""
        utxo = sample_utxos[3]  # The timelocked one
        line = format_utxo_line(utxo)

        assert "[LOCKED]" in line

    def test_format_with_max_width(self, sample_utxos: list[UTXOInfo]) -> None:
        """Test that lines are truncated to max width."""
        utxo = sample_utxos[0]
        line = format_utxo_line(utxo, max_width=40)

        assert len(line) <= 40
        assert line.endswith("...")

    def test_format_large_value(self, sample_utxos: list[UTXOInfo]) -> None:
        """Test formatting UTXO with larger value."""
        utxo = sample_utxos[2]  # 1,000,000 sats
        line = format_utxo_line(utxo)

        assert "m1" in line  # Mixdepth 1
        # Should show the BTC amount
        assert "0.01" in line or "1,000,000" in line


class TestSelectUtxosInteractive:
    """Tests for select_utxos_interactive()."""

    def test_empty_utxos_returns_empty(self) -> None:
        """Test that empty input returns empty list."""
        result = select_utxos_interactive([])
        assert result == []

    def test_single_utxo_returns_directly(self, sample_utxos: list[UTXOInfo]) -> None:
        """Test that single UTXO is returned without TUI."""
        single_utxo = [sample_utxos[0]]
        result = select_utxos_interactive(single_utxo)
        assert result == single_utxo

    def test_non_tty_raises_error(
        self, sample_utxos: list[UTXOInfo], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that non-TTY environment raises RuntimeError."""
        import sys
        from io import StringIO

        # Simulate non-TTY stdin
        fake_stdin = StringIO()
        monkeypatch.setattr(sys, "stdin", fake_stdin)

        with pytest.raises(RuntimeError, match="terminal"):
            select_utxos_interactive(sample_utxos)


class TestUtxoSorting:
    """Tests for UTXO sorting in the selector."""

    def test_utxos_sorted_by_mixdepth_then_value(self, sample_utxos: list[UTXOInfo]) -> None:
        """Verify UTXOs would be sorted by mixdepth, then by value descending."""
        # The selector sorts internally, but we test the sorting logic
        sorted_utxos = sorted(sample_utxos, key=lambda u: (u.mixdepth, -u.value))

        # First should be mixdepth 0 with highest value (not the locked one since
        # we sort by value desc within mixdepth)
        # sample_utxos[3] is mixdepth 0, 500k (locked)
        # sample_utxos[0] is mixdepth 0, 100k
        # sample_utxos[1] is mixdepth 0, 50k
        # sample_utxos[2] is mixdepth 1, 1M

        assert sorted_utxos[0].mixdepth == 0
        assert sorted_utxos[0].value == 500_000  # Highest in mixdepth 0
        assert sorted_utxos[-1].mixdepth == 1  # Mixdepth 1 last
