"""
E2E tests for jm-wallet CLI commands.
"""

from __future__ import annotations

import os
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
            # Note: explicitly use scantxoutset backend since descriptor_wallet is default
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
                    "--backend",
                    "scantxoutset",  # Use scantxoutset to match the mocked backend
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

        # Generate a new 24-word mnemonic and save it (no password for test simplicity)
        result = runner.invoke(
            app,
            [
                "generate",
                "--words",
                "24",
                "--output",
                str(output_file),
                "--no-prompt-password",
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
    result = runner.invoke(app, ["generate", "--words", "12", "--no-save"])

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
                "--output",
                str(output_file),
                "--password",
                password,
                "--no-prompt-password",  # Don't prompt, use the password arg
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
            # Note: explicitly use scantxoutset backend since descriptor_wallet is default
            result = runner.invoke(
                app,
                [
                    "info",
                    "--mnemonic-file",
                    str(mnemonic_file),
                    "--prompt-bip39-passphrase",
                    "--network",
                    "mainnet",
                    "--backend",
                    "scantxoutset",  # Use scantxoutset to match the mocked backend
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


def test_send_respects_config_block_target():
    """
    Test that 'send' command uses the configured default_fee_block_target
    when no --block-target is provided via CLI.
    """
    # Mock backend
    mock_backend = MagicMock()
    mock_backend.estimate_fee = AsyncMock(return_value=1.0)  # 1 sat/vB
    mock_backend.get_balance = AsyncMock(return_value=100000)
    mock_backend.get_utxos = AsyncMock(return_value=[])  # Empty to stop execution early
    mock_backend.close = AsyncMock()

    # We expect the configured value (6) to be used, not the default (3)
    expected_target = 6

    # Set environment variable to override config
    env = os.environ.copy()
    env["WALLET__DEFAULT_FEE_BLOCK_TARGET"] = str(expected_target)

    with patch.dict(os.environ, env):
        with patch("jmwallet.backends.bitcoin_core.BitcoinCoreBackend", return_value=mock_backend):
            # Mock WalletService to avoid initialization issues
            mock_wallet = MagicMock()
            mock_wallet.get_balance = AsyncMock(return_value=100000)
            mock_wallet.get_utxos = AsyncMock(
                return_value=[]
            )  # Return empty to trigger "No UTXOs available" and exit
            mock_wallet.close = AsyncMock()
            mock_wallet.sync_all = AsyncMock()
            mock_wallet.is_descriptor_wallet_ready = AsyncMock(return_value=True)

            # Patch where it is defined, so the local import gets the mock
            with patch("jmwallet.wallet.service.WalletService", return_value=mock_wallet):
                # Run send command
                # We expect it to fail with "No UTXOs available" but that's fine,
                # we just want to check estimate_fee call
                runner.invoke(
                    app,
                    [
                        "send",
                        "bcrt1q...",
                        "--amount",
                        "1000",
                        "--mnemonic",
                        "abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon abandon abandon about",
                        "--network",
                        "regtest",
                        "--backend",
                        "scantxoutset",
                    ],
                )

                # It should have called estimate_fee
                # If the bug is present, it will be called with 3 (hardcoded default)
                # If fixed, it will be called with 6 (from env var)
                try:
                    mock_backend.estimate_fee.assert_called_with(expected_target)
                except AssertionError as e:
                    print(f"Assertion failed: {e}")
                    # Check what it was actually called with
                    if mock_backend.estimate_fee.call_args:
                        print(f"Actually called with: {mock_backend.estimate_fee.call_args}")
                    raise e


def test_history_command_status_display():
    """Test that history command displays correct status for pending, failed, and successful txs."""
    from jmwallet.history import append_history_entry, create_taker_history_entry

    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir)

        # Create a pending transaction (success=False, failure_reason="Pending confirmation")
        pending_entry = create_taker_history_entry(
            maker_nicks=["J5maker1"],
            cj_amount=100000,
            total_maker_fees=500,
            mining_fee=100,
            destination="bc1qpending...",
            source_mixdepth=0,
            selected_utxos=[("utxo1", 0)],
            txid="a" * 64,
        )
        append_history_entry(pending_entry, data_dir)

        # Create a successful transaction
        success_entry = create_taker_history_entry(
            maker_nicks=["J5maker2"],
            cj_amount=200000,
            total_maker_fees=600,
            mining_fee=150,
            destination="bc1qsuccess...",
            source_mixdepth=0,
            selected_utxos=[("utxo2", 0)],
            txid="b" * 64,
            success=True,
        )
        success_entry.confirmations = 3  # Mark as confirmed
        success_entry.failure_reason = ""  # Clear failure reason
        append_history_entry(success_entry, data_dir)

        # Create an actually failed transaction (different failure reason)
        failed_entry = create_taker_history_entry(
            maker_nicks=["J5maker3"],
            cj_amount=150000,
            total_maker_fees=550,
            mining_fee=120,
            destination="bc1qfailed...",
            source_mixdepth=0,
            selected_utxos=[("utxo3", 0)],
            txid="c" * 64,
            success=False,
            failure_reason="Maker timeout",
        )
        append_history_entry(failed_entry, data_dir)

        # Run the history command
        result = runner.invoke(app, ["history", "--data-dir", str(data_dir)])

        assert result.exit_code == 0, f"history command failed: {result.stdout}"

        # Verify status labels
        assert "[PENDING]" in result.stdout, "Pending transaction should show [PENDING]"
        assert "[FAILED]" in result.stdout, "Failed transaction should show [FAILED]"

        # Count occurrences to ensure the successful transaction doesn't have a status label
        lines = result.stdout.split("\n")
        status_lines = [line for line in lines if "aa" in line or "bb" in line or "cc" in line]

        # Verify specific txids have correct status
        pending_line = next((line for line in status_lines if "aa" in line), None)
        success_line = next((line for line in status_lines if "bb" in line), None)
        failed_line = next((line for line in status_lines if "cc" in line), None)

        assert pending_line and "[PENDING]" in pending_line, "Pending tx should have [PENDING]"
        assert (
            success_line and "[PENDING]" not in success_line and "[FAILED]" not in success_line
        ), "Success tx should have no status label"
        assert failed_line and "[FAILED]" in failed_line, "Failed tx should have [FAILED]"


def test_generate_with_output_auto_saves():
    """Test that --output automatically saves the file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "auto-save.mnemonic"

        # Generate with --output (saves by default now)
        result = runner.invoke(
            app,
            [
                "generate",
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
        )

        assert result.exit_code == 0, f"generate failed: {result.stdout}"
        assert "GENERATED MNEMONIC" in result.stdout
        assert output_file.exists(), "File should be saved when --output is specified"


def test_generate_with_save_uses_default_path():
    """Test that default behavior saves to default path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Override home directory for this test
        with patch.object(Path, "home", return_value=Path(tmpdir)):
            # Generate with defaults (should save to default path with password prompt)
            # Mock the password prompt
            with patch.object(typer, "prompt", side_effect=["testpass", "testpass"]):
                result = runner.invoke(
                    app,
                    [
                        "generate",
                    ],
                )

                assert result.exit_code == 0, f"generate failed: {result.stdout}"
                assert "GENERATED MNEMONIC" in result.stdout

                # Check default path was used
                default_path = Path(tmpdir) / ".joinmarket-ng" / "wallets" / "default.mnemonic"
                assert default_path.exists(), f"Default wallet file not found at {default_path}"


def test_generate_overwrite_protection():
    """Test that generating a wallet with an existing file prompts for confirmation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "existing.mnemonic"

        # Create an existing file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text("existing mnemonic")

        # Try to generate to existing file (decline overwrite)
        result = runner.invoke(
            app,
            [
                "generate",
                "--output",
                str(output_file),
                "--no-prompt-password",  # Skip password to simplify test
            ],
            input="n\n",  # Decline overwrite
        )

        # Should exit with code 0 (cancelled by user choice)
        assert result.exit_code == 0, (
            f"Expected exit 0, got {result.exit_code}. Output: {result.stdout}"
        )
        assert "Overwrite existing wallet file?" in result.stdout
        assert "Wallet generation cancelled" in result.stdout

        # File should still contain original content
        assert output_file.read_text() == "existing mnemonic"

        # Try again with confirmation
        result = runner.invoke(
            app,
            [
                "generate",
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
            input="y\n",  # Accept overwrite
        )

        assert result.exit_code == 0
        assert "GENERATED MNEMONIC" in result.stdout

        # File should be overwritten
        assert output_file.read_text() != "existing mnemonic"


def test_info_uses_default_wallet():
    """Test that info command can use default wallet path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create default wallet
        default_wallet = Path(tmpdir) / ".joinmarket-ng" / "wallets" / "default.mnemonic"
        default_wallet.parent.mkdir(parents=True, exist_ok=True)

        # Generate and save a valid mnemonic
        from jmwallet.cli import generate_mnemonic_secure, save_mnemonic_file

        mnemonic = generate_mnemonic_secure()
        save_mnemonic_file(mnemonic, default_wallet, None)

        # Mock backend
        mock_backend = MagicMock()
        mock_backend.get_utxos = AsyncMock(return_value=[])
        mock_backend.close = AsyncMock()

        # Override home directory for this test
        with (
            patch.object(Path, "home", return_value=Path(tmpdir)),
            patch("jmwallet.backends.bitcoin_core.BitcoinCoreBackend", return_value=mock_backend),
        ):
            # Run info without --mnemonic-file (should use default)
            result = runner.invoke(
                app,
                [
                    "info",
                    "--backend",
                    "scantxoutset",
                ],
            )

            assert result.exit_code == 0, f"info command failed: {result.stdout}"
            assert "Total Balance:" in result.stdout


# ============================================================================
# Import Command Tests
# ============================================================================


def test_import_with_mnemonic_argument():
    """Test importing a mnemonic passed via --mnemonic argument."""
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "imported.mnemonic"

        result = runner.invoke(
            app,
            [
                "import",
                "--mnemonic",
                mnemonic,
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
        )

        assert result.exit_code == 0, f"import failed: {result.stdout}"
        assert "IMPORTED MNEMONIC" in result.stdout
        assert output_file.exists(), "Mnemonic file was not created"

        # Verify the saved mnemonic matches
        saved_mnemonic = output_file.read_text().strip()
        assert saved_mnemonic == mnemonic


def test_import_with_encryption():
    """Test importing a mnemonic with password encryption."""
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    password = "test_password_123"

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "encrypted_import.mnemonic"

        result = runner.invoke(
            app,
            [
                "import",
                "--mnemonic",
                mnemonic,
                "--output",
                str(output_file),
                "--password",
                password,
                "--no-prompt-password",
            ],
        )

        assert result.exit_code == 0, f"import failed: {result.stdout}"
        assert "IMPORTED MNEMONIC" in result.stdout
        assert "File is encrypted" in result.stdout
        assert output_file.exists()

        # Verify we can decrypt and validate the saved mnemonic
        result = runner.invoke(
            app, ["validate", "--mnemonic-file", str(output_file), "--password", password]
        )
        assert result.exit_code == 0, f"validate failed: {result.stdout}"
        assert "Mnemonic is VALID" in result.stdout


def test_import_24_word_mnemonic():
    """Test importing a 24-word mnemonic."""
    mnemonic = (
        "actress inmate filter october eagle floor conduct issue rail nominee mixture kid "
        "tunnel thought list tower lobster route ghost cigar bundle oak fiscal pulse"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "imported24.mnemonic"

        result = runner.invoke(
            app,
            [
                "import",
                "--words",
                "24",
                "--mnemonic",
                mnemonic,
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
        )

        assert result.exit_code == 0, f"import failed: {result.stdout}"
        assert "Word count: 24" in result.stdout


def test_import_invalid_mnemonic_warns():
    """Test that importing an invalid mnemonic shows a warning."""
    # Valid BIP39 words but invalid checksum
    invalid_mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "invalid.mnemonic"

        # Should prompt for confirmation - say no
        result = runner.invoke(
            app,
            [
                "import",
                "--mnemonic",
                invalid_mnemonic,
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
            input="n\n",  # Say no to "Continue anyway?"
        )

        # Should exit without creating file
        assert result.exit_code == 1
        assert not output_file.exists()


def test_import_overwrite_protection():
    """Test that import command asks before overwriting existing file."""
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "existing.mnemonic"
        output_file.write_text("existing content")

        # Try to import without --force, say no to overwrite
        result = runner.invoke(
            app,
            [
                "import",
                "--mnemonic",
                mnemonic,
                "--output",
                str(output_file),
                "--no-prompt-password",
            ],
            input="n\n",  # Say no to overwrite
        )

        assert "Import cancelled" in result.stdout
        assert output_file.read_text() == "existing content"


def test_import_force_overwrite():
    """Test that --force flag skips overwrite confirmation."""
    mnemonic = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = Path(tmpdir) / "existing.mnemonic"
        output_file.write_text("old content")

        result = runner.invoke(
            app,
            [
                "import",
                "--mnemonic",
                mnemonic,
                "--output",
                str(output_file),
                "--no-prompt-password",
                "--force",
            ],
        )

        assert result.exit_code == 0
        assert output_file.read_text().strip() == mnemonic


def test_import_invalid_word_count():
    """Test that invalid word count is rejected."""
    result = runner.invoke(
        app,
        [
            "import",
            "--words",
            "13",  # Invalid word count
            "--mnemonic",
            "test",
        ],
    )

    assert result.exit_code == 1


# ============================================================================
# BIP39 Wordlist Helper Tests
# ============================================================================


def test_get_bip39_wordlist():
    """Test that BIP39 wordlist is loaded correctly."""
    from jmwallet.cli import get_bip39_wordlist

    wordlist = get_bip39_wordlist()

    assert len(wordlist) == 2048
    assert "abandon" in wordlist
    assert "zoo" in wordlist
    assert wordlist[0] == "abandon"  # First word alphabetically
    assert wordlist[-1] == "zoo"  # Last word alphabetically


def test_get_word_completions():
    """Test word completion matching."""
    from jmwallet.cli import get_word_completions

    wordlist = ["abandon", "ability", "able", "about", "above", "absent", "zoo"]

    # Single letter prefix
    assert get_word_completions("a", wordlist) == [
        "abandon",
        "ability",
        "able",
        "about",
        "above",
        "absent",
    ]

    # Two letter prefix
    assert get_word_completions("ab", wordlist) == [
        "abandon",
        "ability",
        "able",
        "about",
        "above",
        "absent",
    ]

    # More specific prefix
    assert get_word_completions("abo", wordlist) == ["about", "above"]

    # Unique match
    assert get_word_completions("aband", wordlist) == ["abandon"]

    # No match
    assert get_word_completions("xyz", wordlist) == []

    # Case insensitive
    assert get_word_completions("ABO", wordlist) == ["about", "above"]


def test_get_word_completions_real_wordlist():
    """Test word completion with the actual BIP39 wordlist."""
    from jmwallet.cli import get_bip39_wordlist, get_word_completions

    wordlist = get_bip39_wordlist()

    # Test common prefixes
    zoo_matches = get_word_completions("zoo", wordlist)
    assert zoo_matches == ["zoo"]

    # "aban" should uniquely match "abandon"
    aban_matches = get_word_completions("aban", wordlist)
    assert aban_matches == ["abandon"]

    # "ab" should match multiple words
    ab_matches = get_word_completions("ab", wordlist)
    assert len(ab_matches) > 1
    assert all(w.startswith("ab") for w in ab_matches)


def test_format_word_suggestions():
    """Test suggestion formatting."""
    from jmwallet.cli import format_word_suggestions

    # Few words - show all
    assert format_word_suggestions(["a", "b", "c"]) == "a, b, c"

    # Exactly max_display
    words = ["a", "b", "c", "d", "e", "f", "g", "h"]
    assert format_word_suggestions(words, max_display=8) == "a, b, c, d, e, f, g, h"

    # More than max_display
    words = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
    result = format_word_suggestions(words, max_display=8)
    assert result == "a, b, c, d, e, f, g, h, ... (+2 more)"
