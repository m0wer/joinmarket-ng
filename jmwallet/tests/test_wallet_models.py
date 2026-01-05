"""
Tests for wallet data models.
"""

import pytest

from jmwallet.wallet.models import AddressInfo, UTXOInfo


class TestUTXOInfo:
    """Tests for UTXOInfo model."""

    @pytest.fixture
    def p2wpkh_utxo(self):
        """Create a P2WPKH UTXO."""
        return UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            confirmations=6,
            # P2WPKH scriptpubkey: OP_0 PUSH20 <20-byte-hash> (22 bytes = 44 hex)
            scriptpubkey="0014751e76e8199196d454941c45d1b3a323f1433bd6",
            path="m/84'/0'/0'/0/0",
            mixdepth=0,
        )

    @pytest.fixture
    def p2wsh_utxo(self):
        """Create a P2WSH (fidelity bond) UTXO."""
        return UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address="bc1qxl3vzaf0cxwl9c0jsyyphwdekc6j0xh48qlfv8ja39qzqn92u7ws5arznw",
            confirmations=6,
            # P2WSH scriptpubkey: OP_0 PUSH32 <32-byte-hash> (34 bytes = 68 hex)
            scriptpubkey="00203fc582ea4fc19df170f940410577372c6a4f35ea701f4587a589408132ab9ce8",
            path="m/84'/0'/0'/2/0:1768435200",
            mixdepth=0,
            locktime=1768435200,  # 2026-01-15
        )

    @pytest.fixture
    def p2wsh_utxo_no_locktime(self):
        """Create a P2WSH UTXO without locktime (shouldn't happen in practice)."""
        return UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address="bc1qxl3vzaf0cxwl9c0jsyyphwdekc6j0xh48qlfv8ja39qzqn92u7ws5arznw",
            confirmations=6,
            # P2WSH scriptpubkey: OP_0 PUSH32 <32-byte-hash> (34 bytes = 68 hex)
            scriptpubkey="00203fc582ea4fc19df170f940410577372c6a4f35ea701f4587a589408132ab9ce8",
            path="m/84'/0'/0'/2/0",
            mixdepth=0,
            locktime=None,
        )

    def test_p2wpkh_is_p2wpkh(self, p2wpkh_utxo):
        """Test P2WPKH UTXO is detected as P2WPKH."""
        assert p2wpkh_utxo.is_p2wpkh is True
        assert p2wpkh_utxo.is_p2wsh is False

    def test_p2wpkh_not_timelocked(self, p2wpkh_utxo):
        """Test P2WPKH UTXO is not timelocked."""
        assert p2wpkh_utxo.is_timelocked is False
        assert p2wpkh_utxo.locktime is None

    def test_p2wsh_is_p2wsh(self, p2wsh_utxo):
        """Test P2WSH UTXO is detected as P2WSH."""
        assert p2wsh_utxo.is_p2wsh is True
        assert p2wsh_utxo.is_p2wpkh is False

    def test_p2wsh_is_timelocked(self, p2wsh_utxo):
        """Test P2WSH fidelity bond UTXO is timelocked."""
        assert p2wsh_utxo.is_timelocked is True
        assert p2wsh_utxo.locktime == 1768435200

    def test_p2wsh_without_locktime_not_timelocked(self, p2wsh_utxo_no_locktime):
        """Test P2WSH UTXO without locktime is not considered timelocked."""
        assert p2wsh_utxo_no_locktime.is_p2wsh is True
        assert p2wsh_utxo_no_locktime.is_timelocked is False

    def test_invalid_scriptpubkey_length(self):
        """Test UTXO with invalid scriptpubkey length."""
        utxo = UTXOInfo(
            txid="0" * 64,
            vout=0,
            value=100000,
            address="bc1q...",
            confirmations=6,
            scriptpubkey="001234",  # Invalid length
            path="m/84'/0'/0'/0/0",
            mixdepth=0,
        )
        assert utxo.is_p2wpkh is False
        assert utxo.is_p2wsh is False


class TestAddressInfo:
    """Tests for AddressInfo model."""

    def test_address_info_basic(self):
        """Test basic AddressInfo creation."""
        info = AddressInfo(
            address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            index=5,
            balance=100000,
            status="deposit",
            path="m/84'/0'/0'/0/5",
            is_external=True,
        )
        assert info.address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert info.index == 5
        assert info.balance == 100000
        assert info.status == "deposit"
        assert info.is_external is True
        assert info.is_bond is False
        assert info.locktime is None

    def test_address_info_short_path(self):
        """Test short_path property."""
        info = AddressInfo(
            address="bc1q...",
            index=5,
            balance=0,
            status="new",
            path="m/84'/0'/0'/0/5",
            is_external=True,
        )
        assert info.short_path == "0/5"

    def test_address_info_short_path_internal(self):
        """Test short_path for internal address."""
        info = AddressInfo(
            address="bc1q...",
            index=10,
            balance=50000,
            status="cj-out",
            path="m/84'/0'/0'/1/10",
            is_external=False,
        )
        assert info.short_path == "1/10"

    def test_address_info_bond(self):
        """Test AddressInfo for fidelity bond."""
        info = AddressInfo(
            address="bc1q...",
            index=0,
            balance=1000000,
            status="bond",
            path="m/84'/0'/0'/2/0:1768435200",
            is_external=False,
            is_bond=True,
            locktime=1768435200,
        )
        assert info.is_bond is True
        assert info.locktime == 1768435200
        assert info.status == "bond"

    def test_address_info_statuses(self):
        """Test different address statuses."""
        statuses = [
            "deposit",
            "cj-out",
            "non-cj-change",
            "new",
            "reused",
            "used-empty",
            "bond",
            "flagged",
        ]
        for status in statuses:
            info = AddressInfo(
                address="bc1q...",
                index=0,
                balance=0,
                status=status,
                path="m/84'/0'/0'/0/0",
                is_external=True,
            )
            assert info.status == status
