"""
E2E tests for jm-wallet CLI commands.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import typer
from typer.testing import CliRunner

from jmwallet.cli import app

runner = CliRunner()


def test_bip39_import_with_passphrase_zpub_and_address():
    """
    E2E test: Import a BIP39 mnemonic with passphrase via CLI and verify zpub and address.

    Uses the actual 'jm-wallet info --extended' command with a mock backend.

    Verifies:
    - zpub for m/84'/0'/0' matches expected value
    - First address (m/84'/0'/0'/0/0) matches expected value
    - Derivation path is correct
    """
    # 24-word mnemonic
    mnemonic = (
        "actress inmate filter october eagle floor conduct issue rail nominee mixture kid "
        "tunnel thought list tower lobster route ghost cigar bundle oak fiscal pulse"
    )
    passphrase = "test"

    # Expected values
    expected_zpub = (
        "zpub6s3NLrmr3UN8Z5oWuFMozCWGHNKYPvHNB15pmjaVvHhniwa8fxoBwZmtEGro74sk8affDh"
        "hrehteRWW48DXBTZbUDsutkmTXsGru1TTuNy1"
    )
    expected_first_address = "bc1qw90s2z6etu728elvs0hxh6tda35p465phy9qz4"
    expected_first_path = "m/84'/0'/0'/0/0"

    # Create a temporary mnemonic file
    with tempfile.TemporaryDirectory() as tmpdir:
        mnemonic_file = Path(tmpdir) / "test.mnemonic"
        mnemonic_file.write_text(mnemonic)

        # Test the 'validate' command first
        result = runner.invoke(app, ["validate", "--mnemonic-file", str(mnemonic_file)])
        assert result.exit_code == 0, f"validate failed: {result.stdout}"
        assert "Mnemonic is VALID" in result.stdout
        assert "Word count: 24" in result.stdout

        # Create a mock backend that returns empty UTXOs (no balance)
        mock_backend = MagicMock()
        mock_backend.get_utxos = AsyncMock(return_value=[])
        mock_backend.close = AsyncMock()

        # Mock the BitcoinCoreBackend class (imported inside _show_wallet_info)
        with patch("jmwallet.backends.bitcoin_core.BitcoinCoreBackend", return_value=mock_backend):
            # Run 'info --extended' command to see zpub and first address
            result = runner.invoke(
                app,
                [
                    "info",
                    "--mnemonic-file",
                    str(mnemonic_file),
                    "--bip39-passphrase",
                    passphrase,
                    "--network",
                    "mainnet",
                    "--extended",
                    "--gap",
                    "1",  # Only show first address
                ],
            )

            # Debug output
            if result.exit_code != 0:
                print("STDOUT:", result.stdout)
                if result.exception:
                    print("EXCEPTION:", result.exception)
                    import traceback

                    traceback.print_exception(
                        type(result.exception), result.exception, result.exception.__traceback__
                    )

            assert result.exit_code == 0, f"info command failed: {result.stdout}"

            # Verify zpub appears in output
            assert expected_zpub in result.stdout, f"zpub not found in output:\n{result.stdout}"

            # Verify first address appears in output
            assert expected_first_address in result.stdout, (
                f"First address not found in output:\n{result.stdout}"
            )

            # Verify the derivation path appears
            assert expected_first_path in result.stdout, (
                f"Derivation path not found in output:\n{result.stdout}"
            )

            # Verify it shows mixdepth 0
            assert "mixdepth\t0" in result.stdout, "mixdepth 0 header not found"

            # Verify external addresses section
            assert "external addresses\tm/84'/0'/0'/0" in result.stdout, "external path not found"


def test_generate_and_validate_mnemonic():
    """Test generating and validating a new mnemonic via CLI."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "new.mnemonic"

        # Generate a new 24-word mnemonic and save it
        result = runner.invoke(
            app,
            [
                "generate",
                "--words",
                "24",
                "--save",
                "--output",
                str(output_file),
            ],
        )

        assert result.exit_code == 0, f"generate failed: {result.stdout}"
        assert "GENERATED MNEMONIC" in result.stdout
        assert output_file.exists(), "Mnemonic file was not created"

        # Validate the generated mnemonic
        result = runner.invoke(app, ["validate", "--mnemonic-file", str(output_file)])
        assert result.exit_code == 0, f"validate failed: {result.stdout}"
        assert "Mnemonic is VALID" in result.stdout


def test_validate_invalid_mnemonic():
    """Test validating an invalid mnemonic via CLI."""
    invalid_mnemonic = "invalid mnemonic phrase with random words that are not valid"

    result = runner.invoke(app, ["validate", invalid_mnemonic])
    assert result.exit_code == 1, "Should fail for invalid mnemonic"
    assert "Mnemonic is INVALID" in result.stdout


def test_generate_mnemonic_12_words():
    """Test generating a 12-word mnemonic."""
    result = runner.invoke(app, ["generate", "--words", "12"])

    assert result.exit_code == 0, f"generate failed: {result.stdout}"
    assert "GENERATED MNEMONIC" in result.stdout

    # Extract the mnemonic from the output
    lines = result.stdout.split("\n")
    mnemonic_line = None
    for i, line in enumerate(lines):
        if "GENERATED MNEMONIC" in line:
            # Mnemonic should be a few lines after
            mnemonic_line = lines[i + 3].strip()
            break

    assert mnemonic_line is not None, "Could not find mnemonic in output"

    # Verify it's 12 words
    words = mnemonic_line.split()
    assert len(words) == 12, f"Expected 12 words, got {len(words)}"


def test_encrypted_mnemonic_file():
    """Test saving and loading an encrypted mnemonic file via CLI."""
    password = "test_password_123"

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "encrypted.mnemonic"

        # Generate and save encrypted mnemonic using CLI
        result = runner.invoke(
            app,
            [
                "generate",
                "--words",
                "12",
                "--save",
                "--output",
                str(output_file),
                "--password",
                password,
            ],
        )

        assert result.exit_code == 0, f"generate failed: {result.stdout}"
        assert "GENERATED MNEMONIC" in result.stdout
        assert output_file.exists(), "Encrypted mnemonic file was not created"

        # Validate the encrypted file with password
        result = runner.invoke(
            app, ["validate", "--mnemonic-file", str(output_file), "--password", password]
        )
        assert result.exit_code == 0, f"validate failed: {result.stdout}"
        assert "Mnemonic is VALID" in result.stdout


def test_bip39_prompt_passphrase():
    """Test that --prompt-bip39-passphrase works correctly via CLI."""
    # 24-word mnemonic
    mnemonic = (
        "actress inmate filter october eagle floor conduct issue rail nominee mixture kid "
        "tunnel thought list tower lobster route ghost cigar bundle oak fiscal pulse"
    )
    passphrase = "test"

    # Expected values
    expected_zpub = (
        "zpub6s3NLrmr3UN8Z5oWuFMozCWGHNKYPvHNB15pmjaVvHhniwa8fxoBwZmtEGro74sk8affDh"
        "hrehteRWW48DXBTZbUDsutkmTXsGru1TTuNy1"
    )
    expected_first_address = "bc1qw90s2z6etu728elvs0hxh6tda35p465phy9qz4"

    # Create a temporary mnemonic file
    with tempfile.TemporaryDirectory() as tmpdir:
        mnemonic_file = Path(tmpdir) / "test.mnemonic"
        mnemonic_file.write_text(mnemonic)

        # Create a mock backend that returns empty UTXOs (no balance)
        mock_backend = MagicMock()
        mock_backend.get_utxos = AsyncMock(return_value=[])
        mock_backend.close = AsyncMock()

        # Mock typer.prompt to return the passphrase
        with (
            patch("jmwallet.backends.bitcoin_core.BitcoinCoreBackend", return_value=mock_backend),
            patch.object(typer, "prompt", return_value=passphrase) as mock_prompt,
        ):
            # Run 'info --extended --prompt-bip39-passphrase' command
            result = runner.invoke(
                app,
                [
                    "info",
                    "--mnemonic-file",
                    str(mnemonic_file),
                    "--prompt-bip39-passphrase",
                    "--network",
                    "mainnet",
                    "--extended",
                    "--gap",
                    "1",  # Only show first address
                ],
            )

            # Debug output
            if result.exit_code != 0:
                print("STDOUT:", result.stdout)
                if result.exception:
                    print("EXCEPTION:", result.exception)
                    import traceback

                    traceback.print_exception(
                        type(result.exception), result.exception, result.exception.__traceback__
                    )

            assert result.exit_code == 0, f"info command failed: {result.stdout}"

            # Verify typer.prompt was called with hide_input=True
            mock_prompt.assert_called_once()
            call_args = mock_prompt.call_args
            call_kwargs = call_args.kwargs

            # Check that hide_input=True was passed
            assert call_kwargs.get("hide_input") is True, "Should prompt with hide_input=True"

            # Check that the first positional argument (the prompt text) mentions BIP39
            assert len(call_args.args) > 0, "Should have at least one positional argument"
            prompt_text = call_args.args[0]
            assert "BIP39 passphrase" in prompt_text, (
                f"Prompt text should mention BIP39, got: {prompt_text}"
            )

            # Verify zpub appears in output (confirms passphrase was used)
            assert expected_zpub in result.stdout, f"zpub not found in output:\n{result.stdout}"

            # Verify first address appears in output
            assert expected_first_address in result.stdout, (
                f"First address not found in output:\n{result.stdout}"
            )
