"""Tests for cold wallet fidelity bond certificate functionality."""

from __future__ import annotations

import time
from pathlib import Path

from coincurve import PrivateKey
from jmwallet.wallet.bond_registry import (
    BondRegistry,
    FidelityBondInfo,
    create_bond_info,
    load_registry,
    save_registry,
)


class TestCertificateSupport:
    """Tests for certificate fields in FidelityBondInfo."""

    def test_has_certificate_true(self) -> None:
        """Bond with all certificate fields should have certificate."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            cert_pubkey="03" + "11" * 32,
            cert_privkey="aa" * 32,
            cert_signature="bb" * 70,
            cert_expiry=52,
        )
        assert bond.has_certificate is True

    def test_has_certificate_false_missing_pubkey(self) -> None:
        """Bond missing cert_pubkey should not have certificate."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            cert_privkey="aa" * 32,
            cert_signature="bb" * 70,
            cert_expiry=52,
        )
        assert bond.has_certificate is False

    def test_has_certificate_false_missing_privkey(self) -> None:
        """Bond missing cert_privkey should not have certificate."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            cert_pubkey="03" + "11" * 32,
            cert_signature="bb" * 70,
            cert_expiry=52,
        )
        assert bond.has_certificate is False

    def test_has_certificate_false_all_none(self) -> None:
        """Bond without any certificate fields should not have certificate."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
        )
        assert bond.has_certificate is False

    def test_is_certificate_expired_true(self) -> None:
        """Certificate should be expired if current block height is past expiry."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            cert_pubkey="03" + "11" * 32,
            cert_privkey="aa" * 32,
            cert_signature="bb" * 70,
            cert_expiry=100,  # Expires at block 100 * 2016 = 201600
        )
        # Current block height is past expiry
        assert bond.is_certificate_expired(300000) is True

    def test_is_certificate_expired_false(self) -> None:
        """Certificate should not be expired if current block height is before expiry."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            cert_pubkey="03" + "11" * 32,
            cert_privkey="aa" * 32,
            cert_signature="bb" * 70,
            cert_expiry=500,  # Expires at block 500 * 2016 = 1008000
        )
        # Current block height is before expiry
        assert bond.is_certificate_expired(800000) is False

    def test_is_certificate_expired_no_certificate(self) -> None:
        """Bond without certificate should always report as expired."""
        bond = FidelityBondInfo(
            address="bc1qtest",
            locktime=int(time.time()) + 86400,
            locktime_human="2025-12-31 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="00" * 50,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
        )
        # No certificate = always expired
        assert bond.is_certificate_expired(100000) is True


class TestCertificatePersistence:
    """Tests for certificate persistence in bond registry."""

    def test_save_and_load_with_certificate(self, tmp_path: Path) -> None:
        """Test saving and loading a bond with certificate."""
        registry = BondRegistry()

        # Create bond with certificate
        bond = FidelityBondInfo(
            address="bc1qcert",
            locktime=1735689600,
            locktime_human="2025-01-01 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="abcd" * 10,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            txid="certifiedtx",
            vout=0,
            value=10000000,
            confirmations=100,
            cert_pubkey="03" + "ff" * 32,
            cert_privkey="ee" * 32,
            cert_signature="dd" * 70,
            cert_expiry=52,
        )
        registry.add_bond(bond)

        # Save and reload
        save_registry(registry, tmp_path)
        loaded = load_registry(tmp_path)

        assert len(loaded.bonds) == 1
        loaded_bond = loaded.bonds[0]
        assert loaded_bond.address == "bc1qcert"
        assert loaded_bond.has_certificate is True
        assert loaded_bond.cert_pubkey == "03" + "ff" * 32
        assert loaded_bond.cert_privkey == "ee" * 32
        assert loaded_bond.cert_signature == "dd" * 70
        assert loaded_bond.cert_expiry == 52

    def test_save_and_load_without_certificate(self, tmp_path: Path) -> None:
        """Test saving and loading a bond without certificate (backward compat)."""
        registry = BondRegistry()

        # Create bond without certificate
        bond = FidelityBondInfo(
            address="bc1qnocert",
            locktime=1735689600,
            locktime_human="2025-01-01 00:00:00",
            index=0,
            path="m/84'/0'/0'/2/0",
            pubkey="02" + "00" * 32,
            witness_script_hex="abcd" * 10,
            network="mainnet",
            created_at="2025-01-01T00:00:00",
            txid="normalftx",
            vout=0,
            value=5000000,
        )
        registry.add_bond(bond)

        # Save and reload
        save_registry(registry, tmp_path)
        loaded = load_registry(tmp_path)

        assert len(loaded.bonds) == 1
        loaded_bond = loaded.bonds[0]
        assert loaded_bond.address == "bc1qnocert"
        assert loaded_bond.has_certificate is False
        assert loaded_bond.cert_pubkey is None
        assert loaded_bond.cert_privkey is None
        assert loaded_bond.cert_signature is None
        assert loaded_bond.cert_expiry is None
