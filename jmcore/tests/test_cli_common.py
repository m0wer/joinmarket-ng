"""
Tests for the CLI common module.
"""

from __future__ import annotations

import base64
import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger

from jmcore.cli_common import load_mnemonic_from_file, setup_cli, setup_logging
from jmcore.settings import reset_settings


@pytest.fixture(autouse=True)
def reset_settings_fixture() -> Generator[None, None, None]:
    """Reset settings before and after each test."""
    reset_settings()
    yield
    reset_settings()


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_logging_sets_level(self) -> None:
        """Test that setup_logging configures the log level."""
        setup_logging("DEBUG")
        # Verify handler is configured (loguru doesn't expose level directly,
        # but we can check that the handler was added)
        handlers = logger._core.handlers
        assert len(handlers) > 0

    def test_setup_logging_case_insensitive(self) -> None:
        """Test that log level is case-insensitive."""
        # Should not raise
        setup_logging("trace")
        setup_logging("TRACE")
        setup_logging("Trace")


class TestSetupCli:
    """Tests for setup_cli function."""

    def test_setup_cli_returns_settings(self) -> None:
        """Test that setup_cli returns JoinMarketSettings."""
        from jmcore.settings import JoinMarketSettings

        settings = setup_cli()
        assert isinstance(settings, JoinMarketSettings)

    def test_setup_cli_cli_arg_overrides_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that CLI log level argument overrides settings."""
        # Set log level in env (settings)
        monkeypatch.setenv("LOGGING__LEVEL", "DEBUG")

        with patch.object(logger, "remove"), patch.object(logger, "add") as mock_add:
            setup_cli(log_level="TRACE")

            # Should use CLI value, not settings
            mock_add.assert_called_once()
            call_kwargs = mock_add.call_args[1]
            assert call_kwargs["level"] == "TRACE"

    def test_setup_cli_uses_settings_when_no_cli_arg(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that setup_cli uses settings.logging.level when no CLI arg."""
        # Set log level in env (settings)
        monkeypatch.setenv("LOGGING__LEVEL", "TRACE")

        with patch.object(logger, "remove"), patch.object(logger, "add") as mock_add:
            setup_cli(log_level=None)

            # Should use settings value
            mock_add.assert_called_once()
            call_kwargs = mock_add.call_args[1]
            assert call_kwargs["level"] == "TRACE"

    def test_setup_cli_defaults_to_info(self) -> None:
        """Test that setup_cli defaults to INFO when no CLI arg and no settings."""
        with patch.object(logger, "remove"), patch.object(logger, "add") as mock_add:
            setup_cli(log_level=None)

            mock_add.assert_called_once()
            call_kwargs = mock_add.call_args[1]
            assert call_kwargs["level"] == "INFO"


class TestLoadMnemonicFromFile:
    """Tests for load_mnemonic_from_file function."""

    def test_load_plaintext_mnemonic(self) -> None:
        """Test loading a plaintext mnemonic file."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".mnemonic") as f:
            f.write(mnemonic)
            temp_path = Path(f.name)

        try:
            result = load_mnemonic_from_file(temp_path)
            assert result == mnemonic
        finally:
            os.unlink(temp_path)

    def test_load_encrypted_mnemonic(self) -> None:
        """Test loading an encrypted mnemonic file."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = "test_password"

        # Encrypt the mnemonic
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        fernet = Fernet(key)
        encrypted_token = fernet.encrypt(mnemonic.encode("utf-8"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".mnemonic") as f:
            f.write(salt + encrypted_token)
            temp_path = Path(f.name)

        try:
            result = load_mnemonic_from_file(temp_path, password=password, auto_prompt=False)
            assert result == mnemonic
        finally:
            os.unlink(temp_path)

    def test_load_encrypted_mnemonic_wrong_password(self) -> None:
        """Test that wrong password raises ValueError."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = "correct_password"

        # Encrypt the mnemonic
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        fernet = Fernet(key)
        encrypted_token = fernet.encrypt(mnemonic.encode("utf-8"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".mnemonic") as f:
            f.write(salt + encrypted_token)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Decryption failed"):
                load_mnemonic_from_file(temp_path, password="wrong_password", auto_prompt=False)
        finally:
            os.unlink(temp_path)

    def test_load_encrypted_with_invalid_utf8_content(self) -> None:
        """Test that decrypted invalid UTF-8 raises ValueError with clear message."""
        password = "test_password"

        # Encrypt invalid UTF-8 bytes
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        fernet = Fernet(key)
        # Encrypt invalid UTF-8 bytes
        invalid_utf8 = b"\x80\x81\x82\x83"
        encrypted_token = fernet.encrypt(invalid_utf8)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".mnemonic") as f:
            f.write(salt + encrypted_token)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="not valid UTF-8"):
                load_mnemonic_from_file(temp_path, password=password, auto_prompt=False)
        finally:
            os.unlink(temp_path)

    def test_load_file_not_found(self) -> None:
        """Test that missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_mnemonic_from_file(Path("/nonexistent/path/mnemonic.txt"))

    def test_load_encrypted_no_password_no_prompt(self) -> None:
        """Test that encrypted file without password raises ValueError when auto_prompt=False."""
        # Create a file with random bytes (looks encrypted)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mnemonic") as f:
            f.write(os.urandom(100))
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError, match="appears to be encrypted"):
                load_mnemonic_from_file(temp_path, password=None, auto_prompt=False)
        finally:
            os.unlink(temp_path)


class TestResolveMnemonic:
    """Tests for resolve_mnemonic function."""

    def test_resolve_mnemonic_from_default_wallet_with_config_password(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that config password is used when loading default wallet."""
        from jmcore.cli_common import resolve_mnemonic
        from jmcore.settings import JoinMarketSettings

        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = "config_password"

        # Create encrypted mnemonic at default wallet location
        wallets_dir = tmp_path / "wallets"
        wallets_dir.mkdir(parents=True)
        default_wallet = wallets_dir / "default.mnemonic"

        # Encrypt the mnemonic
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        fernet = Fernet(key)
        encrypted_token = fernet.encrypt(mnemonic.encode("utf-8"))
        default_wallet.write_bytes(salt + encrypted_token)

        # Create settings with mnemonic_password but no mnemonic_file
        monkeypatch.setenv("JOINMARKET_DATA_DIR", str(tmp_path))
        settings = JoinMarketSettings(
            data_dir=tmp_path,
            wallet={"mnemonic_password": password},
        )

        # Resolve mnemonic - should use default wallet with config password
        result = resolve_mnemonic(settings)
        assert result is not None
        assert result.mnemonic == mnemonic
        assert "default wallet" in result.source
