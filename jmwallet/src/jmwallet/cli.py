"""
JoinMarket Wallet CLI - Manage wallets, generate addresses, and handle fidelity bonds.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

import typer
from jmcore.cli_common import (
    ResolvedBackendSettings,
    resolve_backend_settings,
    setup_cli,
    setup_logging,
)
from loguru import logger

if TYPE_CHECKING:
    from jmwallet.wallet.bond_registry import BondRegistry
    from jmwallet.wallet.service import WalletService

app = typer.Typer(
    name="jm-wallet",
    help="JoinMarket Wallet Management",
    add_completion=False,
)


# ============================================================================
# Mnemonic Generation and Encryption
# ============================================================================


def generate_mnemonic_secure(word_count: int = 24) -> str:
    """
    Generate a BIP39 mnemonic from secure entropy.

    Args:
        word_count: Number of words (12, 15, 18, 21, or 24)

    Returns:
        BIP39 mnemonic phrase with valid checksum
    """
    from mnemonic import Mnemonic

    if word_count not in (12, 15, 18, 21, 24):
        raise ValueError("word_count must be 12, 15, 18, 21, or 24")

    # Calculate entropy bits: 12 words = 128 bits, 24 words = 256 bits
    # Formula: word_count * 11 = entropy_bits + checksum_bits
    # checksum_bits = entropy_bits / 32
    # So: word_count * 11 = entropy_bits * (1 + 1/32) = entropy_bits * 33/32
    # entropy_bits = word_count * 11 * 32 / 33
    entropy_bits = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[word_count]

    m = Mnemonic("english")
    return m.generate(strength=entropy_bits)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP39 mnemonic phrase.

    Args:
        mnemonic: The mnemonic phrase to validate

    Returns:
        True if valid, False otherwise
    """
    from mnemonic import Mnemonic

    m = Mnemonic("english")
    return m.check(mnemonic)


def encrypt_mnemonic(mnemonic: str, password: str) -> bytes:
    """
    Encrypt a mnemonic with a password using Fernet (AES-128-CBC).

    Uses PBKDF2 to derive a key from the password.

    Args:
        mnemonic: The mnemonic phrase to encrypt
        password: The password for encryption

    Returns:
        Encrypted bytes (base64-encoded internally by Fernet)
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # High iteration count for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    # Encrypt the mnemonic
    fernet = Fernet(key)
    encrypted = fernet.encrypt(mnemonic.encode("utf-8"))

    # Prepend salt to encrypted data
    return salt + encrypted


def decrypt_mnemonic(encrypted_data: bytes, password: str) -> str:
    """
    Decrypt a mnemonic with a password.

    Args:
        encrypted_data: The encrypted bytes (salt + Fernet token)
        password: The password for decryption

    Returns:
        The decrypted mnemonic phrase

    Raises:
        ValueError: If decryption fails (wrong password or corrupted data)
    """
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data")

    # Extract salt and encrypted token
    salt = encrypted_data[:16]
    encrypted_token = encrypted_data[16:]

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    # Decrypt
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted_token)
        return decrypted.decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Decryption failed - wrong password or corrupted file") from e


def prompt_password_with_confirmation(max_attempts: int = 3) -> str:
    """
    Prompt for a password with confirmation, retrying on mismatch.

    Args:
        max_attempts: Maximum number of attempts before giving up

    Returns:
        The confirmed password

    Raises:
        typer.Exit: If passwords don't match after max_attempts
    """
    for attempt in range(max_attempts):
        password = typer.prompt("Enter encryption password", hide_input=True)
        confirm = typer.prompt("Confirm password", hide_input=True)
        if password == confirm:
            return password
        remaining = max_attempts - attempt - 1
        if remaining > 0:
            typer.echo(f"Passwords do not match. {remaining} attempt(s) remaining.")
        else:
            logger.error("Passwords do not match after maximum attempts")
            raise typer.Exit(1)
    # Should not reach here, but satisfy type checker
    raise typer.Exit(1)


def save_mnemonic_file(
    mnemonic: str,
    output_file: Path,
    password: str | None = None,
) -> None:
    """
    Save a mnemonic to a file, optionally encrypted.

    Args:
        mnemonic: The mnemonic phrase to save
        output_file: The output file path
        password: Optional password for encryption
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if password:
        encrypted = encrypt_mnemonic(mnemonic, password)
        output_file.write_bytes(encrypted)
        os.chmod(output_file, 0o600)
        logger.info(f"Encrypted mnemonic saved to {output_file}")
    else:
        output_file.write_text(mnemonic)
        os.chmod(output_file, 0o600)
        logger.warning(f"Mnemonic saved to {output_file} (PLAINTEXT - consider using --password)")


def load_mnemonic_file(
    mnemonic_file: Path,
    password: str | None = None,
) -> str:
    """
    Load a mnemonic from a file, decrypting if necessary.

    Args:
        mnemonic_file: Path to the mnemonic file
        password: Password for decryption (required if file is encrypted)

    Returns:
        The mnemonic phrase

    Raises:
        ValueError: If file is encrypted but no password provided
    """
    if not mnemonic_file.exists():
        raise FileNotFoundError(f"Mnemonic file not found: {mnemonic_file}")

    data = mnemonic_file.read_bytes()

    # Try to detect if file is encrypted
    # Encrypted files start with 16-byte salt + Fernet token
    # Plaintext files are ASCII only
    try:
        text = data.decode("utf-8")
        # Check if it looks like a valid mnemonic (words separated by spaces)
        words = text.strip().split()
        if len(words) in (12, 15, 18, 21, 24) and all(w.isalpha() for w in words):
            return text.strip()
    except UnicodeDecodeError:
        pass

    # File appears to be encrypted
    if not password:
        raise ValueError(
            "Mnemonic file appears to be encrypted. Please provide a password with --password"
        )

    return decrypt_mnemonic(data, password)


# ============================================================================
# BIP39 Wordlist and Interactive Mnemonic Input
# ============================================================================


def get_bip39_wordlist() -> list[str]:
    """
    Get the BIP39 English wordlist.

    Returns:
        List of 2048 BIP39 words in order.
    """
    from mnemonic import Mnemonic

    m = Mnemonic("english")
    return list(m.wordlist)


def get_word_completions(prefix: str, wordlist: list[str]) -> list[str]:
    """
    Get BIP39 words that start with the given prefix.

    Args:
        prefix: The prefix to match (case-insensitive)
        wordlist: The BIP39 wordlist

    Returns:
        List of matching words
    """
    prefix_lower = prefix.lower()
    return [w for w in wordlist if w.startswith(prefix_lower)]


def format_word_suggestions(matches: list[str], max_display: int = 8) -> str:
    """
    Format word suggestions for display.

    Args:
        matches: List of matching words
        max_display: Maximum number of words to display

    Returns:
        Formatted suggestion string
    """
    if len(matches) <= max_display:
        return ", ".join(matches)
    return ", ".join(matches[:max_display]) + f", ... (+{len(matches) - max_display} more)"


def interactive_mnemonic_input(word_count: int = 24) -> str:
    """
    Interactively input a BIP39 mnemonic with autocomplete support.

    Features:
    - Tab completion (if terminal supports readline)
    - Shows suggestions when prefix matches multiple words
    - Auto-completes when only one word matches
    - Validates each word against BIP39 wordlist

    Args:
        word_count: Expected number of words (12, 15, 18, 21, or 24)

    Returns:
        The complete mnemonic phrase

    Raises:
        typer.Exit: If user cancels input (Ctrl+C)
    """
    from rich.console import Console

    console = Console()
    wordlist = get_bip39_wordlist()
    words: list[str] = []

    # Try to set up readline completion if available
    try:
        import readline

        def completer(text: str, state: int) -> str | None:
            matches = get_word_completions(text, wordlist)
            if state < len(matches):
                return matches[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" ")
        has_readline = True
    except ImportError:
        has_readline = False

    console.print("\n[bold]Enter your BIP39 mnemonic phrase[/bold]")
    console.print(
        f"[dim]Expected: {word_count} words | Tab to autocomplete | Ctrl+C to cancel[/dim]"
    )
    if not has_readline:
        console.print(
            "[dim]Tip: Type prefix and press Enter - auto-completes if unique match[/dim]"
        )
    console.print()

    try:
        while len(words) < word_count:
            word_num = len(words) + 1
            prompt_text = f"Word {word_num}/{word_count}: "

            try:
                if has_readline:
                    user_input = input(prompt_text).strip().lower()
                else:
                    # For terminals without readline, use typer.prompt
                    user_input = (
                        typer.prompt(
                            f"Word {word_num}/{word_count}",
                            prompt_suffix=": ",
                            show_default=False,
                        )
                        .strip()
                        .lower()
                    )
            except EOFError:
                console.print("\n[red]Input cancelled[/red]")
                raise typer.Exit(1)

            if not user_input:
                continue

            # Check for exact match
            if user_input in wordlist:
                words.append(user_input)
                console.print(f"  [green]{user_input}[/green]", highlight=False)
                continue

            # Check for prefix matches
            matches = get_word_completions(user_input, wordlist)

            if len(matches) == 0:
                console.print(f"  [red]'{user_input}' - no matching BIP39 word[/red]")
                continue
            elif len(matches) == 1:
                # Auto-complete unique match
                word = matches[0]
                words.append(word)
                console.print(
                    f"  [green]{word}[/green] [dim](auto-completed from '{user_input}')[/dim]"
                )
            else:
                # Show suggestions
                console.print(f"  [yellow]Matches: {format_word_suggestions(matches)}[/yellow]")
                console.print("  [dim]Type more characters to narrow down[/dim]")

    except KeyboardInterrupt:
        console.print("\n[red]Input cancelled[/red]")
        raise typer.Exit(1)
    finally:
        # Restore readline settings if we modified them
        if has_readline:
            try:
                import readline

                readline.set_completer(None)
            except ImportError:
                pass

    mnemonic = " ".join(words)

    # Validate the complete mnemonic
    console.print()
    if validate_mnemonic(mnemonic):
        console.print("[bold green]Mnemonic checksum valid![/bold green]")
    else:
        console.print("[bold red]WARNING: Mnemonic checksum INVALID![/bold red]")
        console.print(
            "[yellow]The words are valid BIP39 words but the checksum doesn't match.[/yellow]"
        )
        console.print("[yellow]This could mean a word was entered incorrectly.[/yellow]")
        if not typer.confirm("Continue anyway?", default=False):
            raise typer.Exit(1)

    return mnemonic


# ============================================================================
# CLI Commands
# ============================================================================


@app.command("import")
def import_mnemonic(
    word_count: Annotated[
        int, typer.Option("--words", "-w", help="Number of words (12, 15, 18, 21, or 24)")
    ] = 24,
    mnemonic: Annotated[
        str | None, typer.Option("--mnemonic", "-m", help="Mnemonic phrase (space-separated)")
    ] = None,
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file path")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encryption")
    ] = None,
    prompt_password: Annotated[
        bool,
        typer.Option(
            "--prompt-password/--no-prompt-password",
            help="Prompt for password interactively (default: prompt)",
        ),
    ] = True,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing file without confirmation"),
    ] = False,
) -> None:
    """Import an existing BIP39 mnemonic phrase to create/recover a wallet.

    Enter your existing mnemonic interactively with autocomplete support,
    or pass it directly via --mnemonic.

    By default, saves to ~/.joinmarket-ng/wallets/default.mnemonic with password protection.

    Examples:
        jm-wallet import                          # Interactive input, 24 words
        jm-wallet import --words 12               # Interactive input, 12 words
        jm-wallet import --mnemonic "word1 word2 ..."  # Direct input
        jm-wallet import -o my-wallet.mnemonic    # Custom output file
    """
    setup_logging()

    if word_count not in (12, 15, 18, 21, 24):
        logger.error(f"Invalid word count: {word_count}. Must be 12, 15, 18, 21, or 24.")
        raise typer.Exit(1)

    # Get mnemonic from argument or interactive input
    if mnemonic:
        # Validate provided mnemonic
        words = mnemonic.strip().split()
        if len(words) != word_count:
            logger.warning(
                f"Mnemonic has {len(words)} words but --words={word_count} was specified. "
                f"Using actual word count: {len(words)}"
            )
        if not validate_mnemonic(mnemonic):
            logger.error("Provided mnemonic is INVALID (bad checksum)")
            if not typer.confirm("Continue anyway?", default=False):
                raise typer.Exit(1)
        resolved_mnemonic = mnemonic.strip()
    else:
        # Interactive input with autocomplete
        if not sys.stdin.isatty():
            logger.error("Interactive input requires a terminal. Use --mnemonic instead.")
            raise typer.Exit(1)
        resolved_mnemonic = interactive_mnemonic_input(word_count)

    # Display summary
    typer.echo("\n" + "=" * 80)
    typer.echo("IMPORTED MNEMONIC")
    typer.echo("=" * 80)
    word_list = resolved_mnemonic.split()
    typer.echo(f"Word count: {len(word_list)}")
    typer.echo(f"First word: {word_list[0]}")
    typer.echo(f"Last word: {word_list[-1]}")
    typer.echo("=" * 80 + "\n")

    # Determine output file
    if output_file is None:
        output_file = Path.home() / ".joinmarket-ng" / "wallets" / "default.mnemonic"

    # Check if file exists
    if output_file.exists() and not force:
        logger.warning(f"Wallet file already exists: {output_file}")
        if not typer.confirm("Overwrite existing wallet file?", default=False):
            typer.echo("Import cancelled")
            raise typer.Exit(0)

    # Get password
    if prompt_password and password is None:
        password = prompt_password_with_confirmation()

    # Save the mnemonic
    save_mnemonic_file(resolved_mnemonic, output_file, password)

    typer.echo(f"\nMnemonic saved to: {output_file}")
    if password:
        typer.echo("File is encrypted - you will need the password to use it.")
    else:
        typer.echo("WARNING: File is NOT encrypted")
        typer.echo("For production use, consider using a password!")
    typer.echo("\nWallet import complete. You can now use other jm-wallet commands.")


@app.command()
def generate(
    word_count: Annotated[
        int, typer.Option("--words", "-w", help="Number of words (12, 15, 18, 21, or 24)")
    ] = 24,
    save: Annotated[
        bool, typer.Option("--save/--no-save", help="Save to file (default: save)")
    ] = True,
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file path")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encryption")
    ] = None,
    prompt_password: Annotated[
        bool,
        typer.Option(
            "--prompt-password/--no-prompt-password",
            help="Prompt for password interactively (default: prompt)",
        ),
    ] = True,
) -> None:
    """Generate a new BIP39 mnemonic phrase with secure entropy.

    By default, saves to ~/.joinmarket-ng/wallets/default.mnemonic with password protection.
    Use --no-save to only display the mnemonic without saving.
    """
    setup_logging()

    try:
        mnemonic = generate_mnemonic_secure(word_count)

        # Validate the generated mnemonic
        if not validate_mnemonic(mnemonic):
            logger.error("Generated mnemonic failed validation - this should not happen")
            raise typer.Exit(1)

        # Always display the mnemonic first
        typer.echo("\n" + "=" * 80)
        typer.echo("GENERATED MNEMONIC - WRITE THIS DOWN AND KEEP IT SAFE!")
        typer.echo("=" * 80)
        typer.echo(f"\n{mnemonic}\n")
        typer.echo("=" * 80)
        typer.echo("\nThis mnemonic controls your Bitcoin funds.")
        typer.echo("Anyone with this phrase can spend your coins.")
        typer.echo("Store it securely offline - NEVER share it with anyone!")
        typer.echo("=" * 80 + "\n")

        # Auto-enable save if output_file is specified (even if --no-save was used)
        should_save = save or output_file is not None

        if should_save:
            if output_file is None:
                output_file = Path.home() / ".joinmarket-ng" / "wallets" / "default.mnemonic"

            # Check if file already exists and prompt for confirmation
            if output_file.exists():
                logger.warning(f"Wallet file already exists: {output_file}")
                overwrite = typer.confirm("Overwrite existing wallet file?", default=False)
                if not overwrite:
                    typer.echo("Wallet generation cancelled")
                    raise typer.Exit(0)

            # Prompt for password if requested and not already provided
            if prompt_password and password is None:
                password = prompt_password_with_confirmation()

            save_mnemonic_file(mnemonic, output_file, password)

            typer.echo(f"\nMnemonic saved to: {output_file}")
            if password:
                typer.echo("File is encrypted - you will need the password to use it.")
            else:
                typer.echo("WARNING: File is NOT encrypted")
                typer.echo("For production use, generate again with a password!")
            typer.echo("KEEP THIS FILE SECURE - IT CONTROLS YOUR FUNDS!")
        else:
            typer.echo("\nMnemonic NOT saved (--no-save was used)")
            typer.echo("To save it, run: jm-wallet generate")

    except ValueError as e:
        logger.error(f"Failed to generate mnemonic: {e}")
        raise typer.Exit(1)
    except typer.Exit:
        # Re-raise Exit exceptions without modification
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1)


def _resolve_mnemonic(
    mnemonic: str | None,
    mnemonic_file: Path | None,
    password: str | None = None,
    prompt_password: bool = False,
) -> str:
    """
    Resolve mnemonic from argument, file, or environment variable.

    Priority:
    1. --mnemonic argument
    2. --mnemonic-file argument
    3. MNEMONIC_FILE environment variable (path to mnemonic file)
    4. MNEMONIC environment variable
    5. Config file wallet.mnemonic_file setting
    6. Default wallet path (~/.joinmarket-ng/wallets/default.mnemonic)
    """
    if mnemonic:
        return mnemonic

    # Check for mnemonic file (from argument or environment)
    actual_mnemonic_file = mnemonic_file
    actual_password = password
    mnemonic_source = None  # Track where the mnemonic file path came from

    if not actual_mnemonic_file:
        env_mnemonic_file = os.environ.get("MNEMONIC_FILE")
        if env_mnemonic_file:
            actual_mnemonic_file = Path(env_mnemonic_file)
            mnemonic_source = "MNEMONIC_FILE environment variable"

    # If still no mnemonic file, check config file
    if not actual_mnemonic_file:
        try:
            from jmcore.settings import get_settings

            settings = get_settings()
            config_mnemonic_file = getattr(settings.wallet, "mnemonic_file", None)
            if config_mnemonic_file:
                actual_mnemonic_file = Path(config_mnemonic_file)
                mnemonic_source = "config file (wallet.mnemonic_file)"
                # Use config file password if not provided via CLI
                config_password = getattr(settings.wallet, "mnemonic_password", None)
                if actual_password is None and config_password:
                    actual_password = config_password.get_secret_value()
        except Exception as e:
            # If settings loading fails, log error but continue without config file mnemonic
            logger.error(f"Failed to load mnemonic from config: {e}")
            pass
    elif mnemonic_file:
        mnemonic_source = "--mnemonic-file argument"

    # If still no mnemonic file, try default wallet path
    if not actual_mnemonic_file:
        default_wallet = Path.home() / ".joinmarket-ng" / "wallets" / "default.mnemonic"
        if default_wallet.exists():
            actual_mnemonic_file = default_wallet
            mnemonic_source = "default wallet path"

    if actual_mnemonic_file:
        if not actual_mnemonic_file.exists():
            source_msg = f" (from {mnemonic_source})" if mnemonic_source else ""
            raise FileNotFoundError(f"Mnemonic file not found: {actual_mnemonic_file}{source_msg}")

        # Try loading without password first
        try:
            return load_mnemonic_file(actual_mnemonic_file, actual_password)
        except ValueError:
            # File is encrypted, need password
            if prompt_password or actual_password is None:
                actual_password = typer.prompt("Enter mnemonic file password", hide_input=True)
            return load_mnemonic_file(actual_mnemonic_file, actual_password)

    env_mnemonic = os.environ.get("MNEMONIC")
    if env_mnemonic:
        return env_mnemonic

    raise ValueError(
        "Mnemonic required. Use --mnemonic, --mnemonic-file, MNEMONIC_FILE, MNEMONIC env var, "
        "set wallet.mnemonic_file in config.toml, or create default wallet with: "
        "jm-wallet generate --save"
    )


def _resolve_bip39_passphrase(
    bip39_passphrase: str | None = None,
    prompt_bip39_passphrase: bool = False,
) -> str:
    """
    Resolve BIP39 passphrase from argument, environment variable, or prompt.

    Priority:
    1. --bip39-passphrase argument
    2. BIP39_PASSPHRASE environment variable
    3. Interactive prompt (if --prompt-bip39-passphrase is set)
    4. Empty string (default - no passphrase)

    Args:
        bip39_passphrase: BIP39 passphrase from command line argument
        prompt_bip39_passphrase: Whether to prompt for passphrase interactively

    Returns:
        The resolved BIP39 passphrase (empty string if none provided)
    """
    # If explicitly provided via argument, use it
    if bip39_passphrase is not None:
        return bip39_passphrase

    # Check environment variable
    env_passphrase = os.environ.get("BIP39_PASSPHRASE")
    if env_passphrase is not None:
        return env_passphrase

    # Prompt if requested
    if prompt_bip39_passphrase:
        passphrase = typer.prompt(
            "Enter BIP39 passphrase (13th/25th word) - press Enter for none",
            default="",
            hide_input=True,
            show_default=False,
        )
        return passphrase

    # Default: no passphrase
    return ""


@app.command()
def info(
    mnemonic: Annotated[str | None, typer.Option("--mnemonic", help="BIP39 mnemonic")] = None,
    mnemonic_file: Annotated[
        Path | None, typer.Option("--mnemonic-file", "-f", help="Path to mnemonic file")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encrypted file")
    ] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool,
        typer.Option(
            "--prompt-bip39-passphrase",
            help="Prompt for BIP39 passphrase interactively",
        ),
    ] = False,
    network: Annotated[str | None, typer.Option("--network", "-n", help="Bitcoin network")] = None,
    backend_type: Annotated[
        str | None,
        typer.Option(
            "--backend", "-b", help="Backend: scantxoutset | descriptor_wallet | neutrino"
        ),
    ] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")] = None,
    rpc_user: Annotated[str | None, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = None,
    rpc_password: Annotated[
        str | None, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = None,
    neutrino_url: Annotated[
        str | None, typer.Option("--neutrino-url", envvar="NEUTRINO_URL")
    ] = None,
    extended: Annotated[
        bool, typer.Option("--extended", "-e", help="Show detailed address view with derivations")
    ] = False,
    gap: Annotated[
        int, typer.Option("--gap", "-g", help="Max address gap to show in extended view")
    ] = 6,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Display wallet information and balances by mixdepth."""
    settings = setup_cli(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve backend settings with CLI overrides taking priority
    backend = resolve_backend_settings(
        settings,
        network=network,
        backend_type=backend_type,
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
        neutrino_url=neutrino_url,
        data_dir=data_dir,
    )

    asyncio.run(
        _show_wallet_info(
            resolved_mnemonic,
            backend,
            resolved_bip39_passphrase,
            extended=extended,
            gap_limit=gap,
        )
    )


async def _show_wallet_info(
    mnemonic: str,
    backend_settings: ResolvedBackendSettings,
    bip39_passphrase: str = "",
    extended: bool = False,
    gap_limit: int = 6,
) -> None:
    """Show wallet info implementation."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.history import (
        get_address_history_types,
        get_used_addresses,
        update_all_pending_transactions,
    )
    from jmwallet.wallet.service import WalletService

    network = backend_settings.network
    backend_type = backend_settings.backend_type
    data_dir = backend_settings.data_dir

    # Load fidelity bond addresses from registry
    from jmwallet.wallet.bond_registry import load_registry

    bond_registry = load_registry(data_dir)
    fidelity_bond_addresses: list[tuple[str, int, int]] = [
        (bond.address, bond.locktime, bond.index) for bond in bond_registry.bonds
    ]
    if fidelity_bond_addresses:
        logger.info(f"Found {len(fidelity_bond_addresses)} fidelity bond(s) in registry")

    # Create backend
    backend: BitcoinCoreBackend | DescriptorWalletBackend | NeutrinoBackend
    if backend_type == "neutrino":
        backend = NeutrinoBackend(neutrino_url=backend_settings.neutrino_url, network=network)
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    elif backend_type == "descriptor_wallet":
        from jmwallet.backends.descriptor_wallet import (
            generate_wallet_name,
            get_mnemonic_fingerprint,
        )

        fingerprint = get_mnemonic_fingerprint(mnemonic, bip39_passphrase or "")
        wallet_name = generate_wallet_name(fingerprint, network)
        backend = DescriptorWalletBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
            wallet_name=wallet_name,
        )
    elif backend_type == "scantxoutset":
        backend = BitcoinCoreBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
        )
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")

    # Create wallet with data_dir for history lookups
    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
        passphrase=bip39_passphrase,
        data_dir=data_dir,
    )

    try:
        # Use descriptor wallet sync if available
        if backend_type == "descriptor_wallet":
            from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

            if isinstance(backend, DescriptorWalletBackend):
                # Check if base wallet is set up (without counting bonds)
                bond_count = len(fidelity_bond_addresses)
                base_wallet_ready = await wallet.is_descriptor_wallet_ready(fidelity_bond_count=0)
                full_wallet_ready = await wallet.is_descriptor_wallet_ready(
                    fidelity_bond_count=bond_count
                )

                if not base_wallet_ready:
                    # First time setup - import everything including bonds
                    logger.info("Descriptor wallet not set up. Setting up...")
                    await wallet.setup_descriptor_wallet(
                        rescan=True,
                        fidelity_bond_addresses=fidelity_bond_addresses if bond_count else None,
                    )
                    logger.info("Descriptor wallet setup complete")
                elif not full_wallet_ready and bond_count > 0:
                    # Base wallet exists but bonds are missing - import just the bonds
                    logger.info(
                        "Descriptor wallet exists but fidelity bond addresses not imported. "
                        "Importing bond addresses..."
                    )
                    await wallet.import_fidelity_bond_addresses(
                        fidelity_bond_addresses, rescan=True
                    )

                # Use fast descriptor wallet sync (including fidelity bonds)
                await wallet.sync_with_descriptor_wallet(
                    fidelity_bond_addresses=fidelity_bond_addresses if bond_count else None
                )
        else:
            # Use standard sync (scantxoutset for scantxoutset, BIP157/158 for neutrino)
            await wallet.sync_all(fidelity_bond_addresses or None)

        # Update any pending transaction statuses
        # This safeguards against one-shot coinjoins that exited before confirmation
        await update_all_pending_transactions(backend, data_dir)

        from jmcore.bitcoin import format_amount

        total_balance = await wallet.get_total_balance()
        print(f"\nTotal Balance: {format_amount(total_balance)}")

        # Show pending transactions if any
        from jmwallet.history import get_pending_transactions

        pending = get_pending_transactions(data_dir)
        if pending:
            print(f"\nPending Transactions: {len(pending)}")
            for entry in pending:
                if entry.txid:
                    print(f"  {entry.txid[:16]}... - {entry.role} - {entry.confirmations} confs")
                else:
                    print(f"  [Broadcasting...] - {entry.role}")

        # Get history info for address status
        used_addresses = get_used_addresses(data_dir)
        history_addresses = get_address_history_types(data_dir)

        if extended:
            # Extended view with detailed address information
            print("\nJM wallet")
            _show_extended_wallet_info(wallet, used_addresses, history_addresses, gap_limit)
        else:
            # Simple view - show balance and suggested address per mixdepth
            print("\nBalance by mixdepth:")
            for md in range(5):
                balance = await wallet.get_balance(md)
                # Get next address after the last used (highest used index + 1)
                addr, _ = wallet.get_next_after_last_used_address(md, used_addresses)
                print(f"  Mixdepth {md}: {balance:>15,} sats  |  {addr}")

    finally:
        await wallet.close()


def _show_extended_wallet_info(
    wallet: WalletService,
    used_addresses: set[str],
    history_addresses: dict[str, str],
    gap_limit: int,
) -> None:
    """
    Display extended wallet information with detailed address listings.

    Mirrors the reference implementation's output format:
    - Shows zpub for each mixdepth (BIP84 native segwit format)
    - Lists external and internal addresses with derivation paths
    - Shows address status (deposit, cj-out, non-cj-change, new, etc.)
    - Shows balance per address and per branch
    """
    from jmcore.bitcoin import sats_to_btc

    from jmwallet.history import get_pending_transactions
    from jmwallet.wallet.service import FIDELITY_BOND_BRANCH

    # Get pending transactions to mark addresses
    pending_txs = get_pending_transactions(wallet.data_dir)
    pending_addresses = set()
    for entry in pending_txs:
        if entry.destination_address:
            pending_addresses.add(entry.destination_address)
        if entry.change_address:
            pending_addresses.add(entry.change_address)

    for md in range(wallet.mixdepth_count):
        # Get account zpub (BIP84 format for native segwit)
        zpub = wallet.get_account_zpub(md)

        print(f"mixdepth\t{md}\t{zpub}")

        # External addresses (receive / deposit)
        ext_addresses = wallet.get_address_info_for_mixdepth(
            md, 0, gap_limit, used_addresses, history_addresses
        )
        # Get the external branch zpub path
        ext_path = f"m/84'/{0 if wallet.network == 'mainnet' else 1}'/{md}'/0"
        print(f"external addresses\t{ext_path}\t{zpub}")

        ext_balance = 0
        for addr_info in ext_addresses:
            btc_balance = sats_to_btc(addr_info.balance)
            ext_balance += addr_info.balance
            # Format: path  address  balance  status
            # Pad path to ensure consistent alignment regardless of index digits
            status_display: str = addr_info.status
            if addr_info.address in pending_addresses:
                status_display += " (pending)"
            print(f"{addr_info.path:<24}{addr_info.address}\t{btc_balance:.8f}\t{status_display}")

        print(f"Balance:\t{sats_to_btc(ext_balance):.8f}")

        # Internal addresses (change / CJ output)
        int_addresses = wallet.get_address_info_for_mixdepth(
            md, 1, gap_limit, used_addresses, history_addresses
        )
        int_path = f"m/84'/{0 if wallet.network == 'mainnet' else 1}'/{md}'/1"
        print(f"internal addresses\t{int_path}")

        int_balance = 0
        for addr_info in int_addresses:
            btc_balance = sats_to_btc(addr_info.balance)
            int_balance += addr_info.balance
            # Pad path to ensure consistent alignment regardless of index digits
            status_str: str = addr_info.status
            if addr_info.address in pending_addresses:
                status_str += " (pending)"
            print(f"{addr_info.path:<24}{addr_info.address}\t{btc_balance:.8f}\t{status_str}")

        print(f"Balance:\t{sats_to_btc(int_balance):.8f}")

        # Fidelity bond branch (only for mixdepth 0)
        if md == 0:
            bond_addresses = wallet.get_fidelity_bond_addresses_info(gap_limit)
            if bond_addresses:
                bond_path = (
                    f"m/84'/{0 if wallet.network == 'mainnet' else 1}'/0'/{FIDELITY_BOND_BRANCH}"
                )
                print(f"fidelity bond addresses\t{bond_path}\t{zpub}")

                bond_balance = 0
                bond_locked = 0  # Locked balance (not yet expired)
                import time

                current_time = int(time.time())

                for addr_info in bond_addresses:
                    btc_balance = sats_to_btc(addr_info.balance)
                    bond_balance += addr_info.balance
                    is_locked = addr_info.locktime and addr_info.locktime > current_time
                    if is_locked:
                        bond_locked += addr_info.balance

                    # Show locktime as date for bonds
                    locktime_str = ""
                    if addr_info.locktime:
                        from datetime import datetime

                        dt = datetime.fromtimestamp(addr_info.locktime)
                        locktime_str = dt.strftime("%Y-%m-%d")
                        if is_locked:
                            locktime_str += " [LOCKED]"

                    # Pad path to ensure consistent alignment regardless of index digits
                    print(
                        f"{addr_info.path:<24}{addr_info.address}\t{btc_balance:.8f}\t{locktime_str}"
                    )

                # Show bond balance with locked amount in parentheses
                if bond_locked > 0:
                    print(
                        f"Balance:\t{sats_to_btc(bond_balance - bond_locked):.8f} "
                        f"({sats_to_btc(bond_locked):.8f})"
                    )
                else:
                    print(f"Balance:\t{sats_to_btc(bond_balance):.8f}")

        # Total balance for mixdepth
        total_md_balance = ext_balance + int_balance
        print(f"Balance for mixdepth {md}:\t{sats_to_btc(total_md_balance):.8f}")


@app.command()
def list_bonds(
    mnemonic: Annotated[str | None, typer.Option("--mnemonic")] = None,
    mnemonic_file: Annotated[Path | None, typer.Option("--mnemonic-file", "-f")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool, typer.Option("--prompt-bip39-passphrase", help="Prompt for BIP39 passphrase")
    ] = False,
    network: Annotated[str | None, typer.Option("--network", "-n", help="Bitcoin network")] = None,
    backend_type: Annotated[
        str | None,
        typer.Option(
            "--backend", "-b", help="Backend: scantxoutset | descriptor_wallet | neutrino"
        ),
    ] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")] = None,
    rpc_user: Annotated[str | None, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = None,
    rpc_password: Annotated[
        str | None, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = None,
    locktimes: Annotated[
        list[int] | None, typer.Option("--locktime", "-L", help="Locktime(s) to scan for")
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """List all fidelity bonds in the wallet."""
    settings = setup_cli(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve backend settings with CLI overrides taking priority
    backend = resolve_backend_settings(
        settings,
        network=network,
        backend_type=backend_type,
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
    )

    asyncio.run(
        _list_fidelity_bonds(
            resolved_mnemonic,
            backend,
            locktimes or [],
            resolved_bip39_passphrase,
        )
    )


async def _list_fidelity_bonds(
    mnemonic: str,
    backend_settings: ResolvedBackendSettings,
    locktimes: list[int],
    bip39_passphrase: str = "",
) -> None:
    """List fidelity bonds implementation."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.wallet.bond_registry import load_registry
    from jmwallet.wallet.service import WalletService

    # Import fidelity bond utilities from maker
    try:
        from maker.fidelity import find_fidelity_bonds
    except ImportError:
        logger.error("Failed to import fidelity bond utilities")
        raise typer.Exit(1)

    network = backend_settings.network
    data_dir = backend_settings.data_dir

    backend = BitcoinCoreBackend(
        rpc_url=backend_settings.rpc_url,
        rpc_user=backend_settings.rpc_user,
        rpc_password=backend_settings.rpc_password,
    )

    # Use large gap limit (1000) for discovery mode when scanning with --locktime
    gap_limit = 1000 if locktimes else 20
    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
        gap_limit=gap_limit,
        passphrase=bip39_passphrase,
    )

    try:
        # Load known bonds from registry for optimized scanning
        bond_registry = load_registry(data_dir)
        fidelity_bond_addresses: list[tuple[str, int, int]] = []
        if bond_registry.bonds:
            fidelity_bond_addresses = [
                (bond.address, bond.locktime, bond.index) for bond in bond_registry.bonds
            ]
            logger.info(
                f"Loading {len(fidelity_bond_addresses)} known bond(s) from registry for scanning"
            )

        # Sync wallet + known bonds in single pass
        await wallet.sync_all(fidelity_bond_addresses)

        # If user provided locktimes, also scan with large gap limit to discover new bonds
        if locktimes:
            logger.info(f"Scanning for undiscovered bonds with gap_limit={gap_limit}")
            await wallet.sync_fidelity_bonds(locktimes)

        bonds = await find_fidelity_bonds(wallet)

        if not bonds:
            print("\nNo fidelity bonds found in wallet.")
            if not locktimes:
                print("TIP: Use --locktime to specify locktime(s) to scan for undiscovered bonds")
                print(
                    "     Or use 'jm-wallet generate-bond-address' to create a new bond "
                    "and register it"
                )
            return

        print(f"\nFound {len(bonds)} fidelity bond(s):\n")
        print("=" * 120)

        # Sort by bond value (highest first)
        bonds.sort(key=lambda b: b.bond_value, reverse=True)

        for i, bond in enumerate(bonds, 1):
            locktime_dt = datetime.fromtimestamp(bond.locktime)
            expired = datetime.now().timestamp() > bond.locktime
            status = "EXPIRED" if expired else "ACTIVE"
            print(f"Bond #{i}: [{status}]")
            print(f"  UTXO:        {bond.txid}:{bond.vout}")
            from jmcore.bitcoin import format_amount

            print(f"  Value:       {format_amount(bond.value)}")
            print(f"  Locktime:    {bond.locktime} ({locktime_dt.strftime('%Y-%m-%d %H:%M:%S')})")
            print(f"  Confirms:    {bond.confirmation_time}")
            print(f"  Bond Value:  {bond.bond_value:,}")
            print("-" * 120)

    finally:
        await wallet.close()


@app.command("generate-bond-address")
def generate_bond_address(
    mnemonic: Annotated[str | None, typer.Option("--mnemonic")] = None,
    mnemonic_file: Annotated[Path | None, typer.Option("--mnemonic-file", "-f")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool, typer.Option("--prompt-bip39-passphrase", help="Prompt for BIP39 passphrase")
    ] = False,
    locktime: Annotated[
        int, typer.Option("--locktime", "-L", help="Locktime as Unix timestamp")
    ] = 0,
    locktime_date: Annotated[
        str | None,
        typer.Option("--locktime-date", "-d", help="Locktime as YYYY-MM (must be 1st of month)"),
    ] = None,
    index: Annotated[int, typer.Option("--index", "-i", help="Address index")] = 0,
    network: Annotated[str | None, typer.Option("--network", "-n")] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    no_save: Annotated[
        bool,
        typer.Option("--no-save", help="Do not save the bond to the registry"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Generate a fidelity bond (timelocked P2WSH) address."""
    settings = setup_cli(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve network from config if not provided
    resolved_network = network if network is not None else settings.network_config.network.value

    # Resolve data directory from config if not provided
    resolved_data_dir = data_dir if data_dir is not None else settings.get_data_dir()

    # Parse and validate locktime
    from jmcore.timenumber import is_valid_locktime, parse_locktime_date

    if locktime_date:
        try:
            # Use timenumber module for proper parsing and validation
            locktime = parse_locktime_date(locktime_date)
        except ValueError as e:
            logger.error(f"Invalid locktime date: {e}")
            logger.info("Use format: YYYY-MM or YYYY-MM-DD (must be 1st of month)")
            logger.info("Valid range: 2020-01 to 2099-12")
            raise typer.Exit(1)

    if locktime <= 0:
        logger.error("Locktime is required. Use --locktime or --locktime-date")
        raise typer.Exit(1)

    # Validate locktime is a valid timenumber (1st of month, midnight UTC)
    if not is_valid_locktime(locktime):
        from jmcore.timenumber import get_nearest_valid_locktime

        suggested = get_nearest_valid_locktime(locktime, round_up=True)
        suggested_dt = datetime.fromtimestamp(suggested)
        logger.warning(
            f"Locktime {locktime} is not a valid fidelity bond locktime "
            f"(must be 1st of month at midnight UTC)"
        )
        logger.info(f"Suggested locktime: {suggested} ({suggested_dt.strftime('%Y-%m-%d')})")
        logger.info("Use --locktime-date YYYY-MM for correct format")
        raise typer.Exit(1)

    # Validate locktime is in the future
    if locktime <= datetime.now().timestamp():
        logger.warning("Locktime is in the past - the bond will be immediately spendable")

    from jmcore.btc_script import disassemble_script, mk_freeze_script

    from jmwallet.wallet.address import script_to_p2wsh_address
    from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
    from jmwallet.wallet.bond_registry import (
        create_bond_info,
        load_registry,
        save_registry,
    )
    from jmwallet.wallet.service import FIDELITY_BOND_BRANCH

    seed = mnemonic_to_seed(resolved_mnemonic, resolved_bip39_passphrase)
    master_key = HDKey.from_seed(seed)

    coin_type = 0 if resolved_network == "mainnet" else 1
    path = f"m/84'/{coin_type}'/0'/{FIDELITY_BOND_BRANCH}/{index}"

    key = master_key.derive(path)
    pubkey_hex = key.get_public_key_bytes(compressed=True).hex()

    witness_script = mk_freeze_script(pubkey_hex, locktime)
    address = script_to_p2wsh_address(witness_script, resolved_network)

    locktime_dt = datetime.fromtimestamp(locktime)
    disassembled = disassemble_script(witness_script)

    # Save to registry unless --no-save
    saved = False
    existing = False
    if not no_save:
        registry = load_registry(resolved_data_dir)
        existing_bond = registry.get_bond_by_address(address)
        if existing_bond:
            existing = True
            logger.info(f"Bond already exists in registry (created: {existing_bond.created_at})")
        else:
            bond_info = create_bond_info(
                address=address,
                locktime=locktime,
                index=index,
                path=path,
                pubkey_hex=pubkey_hex,
                witness_script=witness_script,
                network=resolved_network,
            )
            registry.add_bond(bond_info)
            save_registry(registry, resolved_data_dir)
            saved = True

    print("\n" + "=" * 80)
    print("FIDELITY BOND ADDRESS")
    print("=" * 80)
    print(f"\nAddress:      {address}")
    print(f"Locktime:     {locktime} ({locktime_dt.strftime('%Y-%m-%d %H:%M:%S')})")
    print(f"Index:        {index}")
    print(f"Network:      {resolved_network}")
    print(f"Path:         {path}")
    print()
    print("-" * 80)
    print("WITNESS SCRIPT (redeemScript)")
    print("-" * 80)
    print(f"Hex:          {witness_script.hex()}")
    print(f"Disassembled: {disassembled}")
    print("-" * 80)
    if saved:
        print(f"\nSaved to registry: {resolved_data_dir / 'fidelity_bonds.json'}")
    elif existing:
        print("\nBond already in registry (not updated)")
    elif no_save:
        print("\nNot saved to registry (--no-save)")
    print("\n" + "=" * 80)
    print("IMPORTANT: Funds sent to this address are LOCKED until the locktime!")
    print("           Make sure you have backed up your mnemonic.")
    print("=" * 80 + "\n")


@app.command()
def send(
    destination: Annotated[str, typer.Argument(help="Destination address")],
    amount: Annotated[int, typer.Option("--amount", "-a", help="Amount in sats (0 for sweep)")] = 0,
    mnemonic: Annotated[str | None, typer.Option("--mnemonic")] = None,
    mnemonic_file: Annotated[Path | None, typer.Option("--mnemonic-file", "-f")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool, typer.Option("--prompt-bip39-passphrase", help="Prompt for BIP39 passphrase")
    ] = False,
    mixdepth: Annotated[int, typer.Option("--mixdepth", "-m", help="Source mixdepth")] = 0,
    fee_rate: Annotated[
        float | None,
        typer.Option(
            "--fee-rate",
            help="Manual fee rate in sat/vB (e.g. 1.5). "
            "Mutually exclusive with --block-target. "
            "Defaults to 3-block estimation.",
        ),
    ] = None,
    block_target: Annotated[
        int | None,
        typer.Option(
            "--block-target",
            help="Target blocks for fee estimation (1-1008). Defaults to 3.",
        ),
    ] = None,
    network: Annotated[str | None, typer.Option("--network", "-n", help="Bitcoin network")] = None,
    backend_type: Annotated[
        str | None,
        typer.Option(
            "--backend", "-b", help="Backend: scantxoutset | descriptor_wallet | neutrino"
        ),
    ] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")] = None,
    rpc_user: Annotated[str | None, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = None,
    rpc_password: Annotated[
        str | None, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = None,
    neutrino_url: Annotated[
        str | None, typer.Option("--neutrino-url", envvar="NEUTRINO_URL")
    ] = None,
    broadcast: Annotated[
        bool, typer.Option("--broadcast", help="Broadcast the transaction")
    ] = True,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
    select_utxos: Annotated[
        bool,
        typer.Option(
            "--select-utxos",
            "-s",
            help="Interactively select UTXOs (fzf-like TUI)",
        ),
    ] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Send a simple transaction from wallet to an address."""
    settings = setup_cli(log_level)

    # Validate mutual exclusivity

    if fee_rate is not None and block_target is not None:
        logger.error("Cannot specify both --fee-rate and --block-target")
        raise typer.Exit(1)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve backend settings
    backend_settings = resolve_backend_settings(
        settings,
        network=network,
        backend_type=backend_type,
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
        neutrino_url=neutrino_url,
        data_dir=data_dir,
    )

    # Use configured default block target if not specified
    if block_target is None and fee_rate is None:
        block_target = settings.wallet.default_fee_block_target

    asyncio.run(
        _send_transaction(
            resolved_mnemonic,
            destination,
            amount,
            mixdepth,
            fee_rate,
            block_target,
            backend_settings,
            broadcast,
            yes,
            select_utxos,
            resolved_bip39_passphrase,
        )
    )


async def _send_transaction(
    mnemonic: str,
    destination: str,
    amount: int,
    mixdepth: int,
    fee_rate: float | None,
    block_target: int | None,
    backend_settings: ResolvedBackendSettings,
    broadcast: bool,
    skip_confirmation: bool,
    interactive_utxo_selection: bool,
    bip39_passphrase: str = "",
) -> None:
    """Send transaction implementation."""
    import math

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.wallet.bond_registry import load_registry
    from jmwallet.wallet.service import WalletService
    from jmwallet.wallet.signing import (
        create_p2wpkh_script_code,
        create_p2wsh_witness_stack,
        deserialize_transaction,
        encode_varint,
        sign_p2wpkh_input,
        sign_p2wsh_input,
    )

    # Load fidelity bond addresses from registry
    bond_registry = load_registry(backend_settings.data_dir)
    fidelity_bond_addresses: list[tuple[str, int, int]] = [
        (bond.address, bond.locktime, bond.index) for bond in bond_registry.bonds
    ]

    # Create backend based on type
    backend: BitcoinCoreBackend | DescriptorWalletBackend | NeutrinoBackend
    if backend_settings.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=backend_settings.neutrino_url, network=backend_settings.network
        )
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            return
    elif backend_settings.backend_type == "descriptor_wallet":
        fingerprint = get_mnemonic_fingerprint(mnemonic, bip39_passphrase)
        wallet_name = generate_wallet_name(fingerprint, backend_settings.network)
        backend = DescriptorWalletBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
            wallet_name=wallet_name,
        )
    else:
        backend = BitcoinCoreBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
        )

    # Resolve fee rate
    # Get mempool minimum fee (if available) as a floor
    mempool_min_fee: float | None = None
    try:
        mempool_min_fee = await backend.get_mempool_min_fee()
        if mempool_min_fee is not None:
            logger.debug(f"Mempool min fee: {mempool_min_fee:.2f} sat/vB")
    except Exception:
        # Backend may not support this method
        pass

    if fee_rate is not None:
        resolved_fee_rate = fee_rate
        # Check against mempool min fee
        if mempool_min_fee is not None and resolved_fee_rate < mempool_min_fee:
            logger.warning(
                f"Manual fee rate {resolved_fee_rate:.2f} sat/vB is below node's minimum relay "
                f"fee {mempool_min_fee:.2f} sat/vB. Using mempool minimum instead. "
                f"To use lower fee rates, configure minrelaytxfee in your Bitcoin node's "
                f"bitcoin.conf (see DOCS.md for details)."
            )
            resolved_fee_rate = mempool_min_fee
        logger.info(f"Using manual fee rate: {resolved_fee_rate:.2f} sat/vB")
    else:
        # Use backend fee estimation
        target = block_target if block_target is not None else 3
        resolved_fee_rate = await backend.estimate_fee(target)
        # Check against mempool min fee
        if mempool_min_fee is not None and resolved_fee_rate < mempool_min_fee:
            logger.info(
                f"Estimated fee {resolved_fee_rate:.2f} sat/vB is below mempool min "
                f"{mempool_min_fee:.2f} sat/vB, using mempool min"
            )
            resolved_fee_rate = mempool_min_fee
        logger.info(f"Fee estimation for {target} blocks: {resolved_fee_rate:.2f} sat/vB")

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=backend_settings.network,
        mixdepth_count=5,
        passphrase=bip39_passphrase,
        data_dir=backend_settings.data_dir,
    )

    try:
        # Use descriptor wallet sync if available
        if backend_settings.backend_type == "descriptor_wallet" and isinstance(
            backend, DescriptorWalletBackend
        ):
            bond_count = len(fidelity_bond_addresses)
            base_wallet_ready = await wallet.is_descriptor_wallet_ready(fidelity_bond_count=0)
            full_wallet_ready = await wallet.is_descriptor_wallet_ready(
                fidelity_bond_count=bond_count
            )

            if not base_wallet_ready:
                logger.info("Descriptor wallet not set up. Setting up...")
                await wallet.setup_descriptor_wallet(
                    rescan=True,
                    fidelity_bond_addresses=fidelity_bond_addresses if bond_count else None,
                )
            elif not full_wallet_ready and bond_count > 0:
                logger.info("Importing fidelity bond addresses...")
                await wallet.import_fidelity_bond_addresses(fidelity_bond_addresses, rescan=True)

            await wallet.sync_with_descriptor_wallet(
                fidelity_bond_addresses=fidelity_bond_addresses if bond_count else None
            )
        else:
            await wallet.sync_all(fidelity_bond_addresses or None)

        balance = await wallet.get_balance(mixdepth)
        logger.info(f"Mixdepth {mixdepth} balance: {balance:,} sats")

        # Fetch UTXOs early for interactive selection
        utxos = await wallet.get_utxos(mixdepth)
        if not utxos:
            logger.error("No UTXOs available")
            raise typer.Exit(1)

        # Interactive UTXO selection if requested
        if interactive_utxo_selection:
            from jmwallet.history import get_utxo_label
            from jmwallet.utxo_selector import select_utxos_interactive

            # Populate labels for each UTXO based on history
            for utxo in utxos:
                utxo.label = get_utxo_label(utxo.address, backend_settings.data_dir)

            try:
                selected_utxos = select_utxos_interactive(utxos, amount)
                if not selected_utxos:
                    logger.info("UTXO selection cancelled")
                    return
                utxos = selected_utxos
                logger.info(f"Selected {len(utxos)} UTXOs")
            except RuntimeError as e:
                logger.error(f"Cannot use interactive UTXO selection: {e}")
                raise typer.Exit(1)

        # Calculate totals based on selected UTXOs
        total_input = sum(u.value for u in utxos)
        num_inputs = len(utxos)

        if amount == 0:
            # Sweep selected UTXOs
            send_amount = total_input
        else:
            send_amount = amount

        if send_amount > total_input:
            logger.error(f"Insufficient funds: need {send_amount:,}, have {total_input:,}")
            raise typer.Exit(1)

        # Estimate transaction size
        from jmcore.bitcoin import estimate_vsize, get_address_type

        try:
            dest_type = get_address_type(destination)
        except ValueError:
            logger.warning(f"Could not determine address type for {destination}, assuming P2WPKH")
            dest_type = "p2wpkh"

        input_types = ["p2wpkh"] * num_inputs
        output_types = [dest_type]

        # Initial assumption: we have change if not sweeping
        if amount > 0:
            output_types.append("p2wpkh")  # Change is always P2WPKH

        estimated_vsize = estimate_vsize(input_types, output_types)
        estimated_fee = math.ceil(estimated_vsize * resolved_fee_rate)

        if amount == 0:
            # Sweep: subtract fee from send amount
            send_amount = total_input - estimated_fee
            if send_amount <= 0:
                logger.error("Balance too low to cover fees")
                raise typer.Exit(1)
            change_amount = 0
        else:
            change_amount = total_input - send_amount - estimated_fee
            if change_amount < 0:
                logger.error(f"Insufficient funds after fee: need {send_amount + estimated_fee:,}")
                raise typer.Exit(1)
            if change_amount < 546:  # Dust threshold
                # Add to fee instead
                estimated_fee += change_amount
                change_amount = 0
                # Re-estimate without change output
                output_types.pop()  # Remove change output
                estimated_vsize = estimate_vsize(input_types, output_types)
                estimated_fee = math.ceil(estimated_vsize * resolved_fee_rate)

        num_outputs = len(output_types)

        # Use new format_amount for display
        from jmcore.bitcoin import format_amount

        logger.info(f"Sending {format_amount(send_amount)} to {destination}")
        logger.info(f"Fee: {format_amount(estimated_fee)} ({resolved_fee_rate:.2f} sat/vB)")
        if change_amount > 0:
            logger.info(f"Change: {format_amount(change_amount)}")

        # Prompt for confirmation before building transaction
        from jmcore.confirmation import confirm_transaction

        try:
            confirmed = confirm_transaction(
                operation="send",
                amount=send_amount,
                destination=destination,
                fee=estimated_fee,
                additional_info={
                    "Source Mixdepth": mixdepth,
                    "Change": format_amount(change_amount) if change_amount > 0 else "None",
                    "Fee Rate": f"{resolved_fee_rate:.2f} sat/vB",
                },
                skip_confirmation=skip_confirmation,
            )
            if not confirmed:
                logger.info("Transaction cancelled by user")
                return
        except RuntimeError as e:
            logger.error(str(e))
            raise typer.Exit(1)

        # Build unsigned transaction
        from jmwallet.wallet.address import pubkey_to_p2wpkh_script

        # Convert destination to scriptPubKey
        # For simplicity, assume bech32 (P2WPKH/P2WSH)
        if destination.startswith(("bc1", "tb1", "bcrt1")):
            # Bech32 decode
            from jmwallet.wallet.address import convertbits

            hrp = destination[: destination.index("1")]
            data_part = destination[len(hrp) + 1 :]
            charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            data_values = [charset.index(c) for c in data_part]
            # Remove checksum (last 6 characters)
            witness_data = data_values[:-6]
            witness_version = witness_data[0]
            witness_program = bytes(convertbits(bytes(witness_data[1:]), 5, 8, False))

            if witness_version == 0 and len(witness_program) == 20:
                # P2WPKH
                dest_script = bytes([0x00, 0x14]) + witness_program
            elif witness_version == 0 and len(witness_program) == 32:
                # P2WSH
                dest_script = bytes([0x00, 0x20]) + witness_program
            else:
                logger.error(f"Unsupported witness program: version={witness_version}")
                raise typer.Exit(1)
        else:
            logger.error("Only bech32 addresses are supported currently")
            raise typer.Exit(1)

        # Build raw transaction
        version = (2).to_bytes(4, "little")

        # Determine transaction locktime - must be >= max CLTV locktime if spending timelocked UTXOs
        import time

        max_locktime = 0
        has_timelocked = False
        current_time = int(time.time())
        for utxo in utxos:
            if utxo.is_timelocked and utxo.locktime is not None:
                has_timelocked = True
                if utxo.locktime > max_locktime:
                    max_locktime = utxo.locktime
                if utxo.locktime > current_time:
                    logger.error(
                        f"Cannot spend timelocked UTXO {utxo.txid}:{utxo.vout} - "
                        f"locktime {utxo.locktime} is in the future "
                        f"(current time: {current_time})"
                    )
                    raise typer.Exit(1)

        locktime = max_locktime.to_bytes(4, "little")

        # Inputs
        inputs_data = bytearray()
        for utxo in utxos:
            txid_bytes = bytes.fromhex(utxo.txid)[::-1]  # Little-endian
            inputs_data.extend(txid_bytes)
            inputs_data.extend(utxo.vout.to_bytes(4, "little"))
            inputs_data.append(0)  # Empty scriptSig for SegWit
            # For timelocked UTXOs, sequence must be < 0xFFFFFFFF to enable locktime
            if has_timelocked:
                inputs_data.extend((0xFFFFFFFE).to_bytes(4, "little"))  # Enable locktime
            else:
                inputs_data.extend((0xFFFFFFFF).to_bytes(4, "little"))  # Sequence

        # Outputs
        outputs_data = bytearray()
        # Destination
        outputs_data.extend(send_amount.to_bytes(8, "little"))
        outputs_data.extend(encode_varint(len(dest_script)))
        outputs_data.extend(dest_script)

        # Change (if any)
        if change_amount > 0:
            change_index = wallet.get_next_address_index(mixdepth, 1)
            change_addr = wallet.get_change_address(mixdepth, change_index)
            change_key = wallet.get_key_for_address(change_addr)
            if change_key:
                change_script = pubkey_to_p2wpkh_script(
                    change_key.get_public_key_bytes(compressed=True).hex()
                )
                outputs_data.extend(change_amount.to_bytes(8, "little"))
                outputs_data.extend(encode_varint(len(change_script)))
                outputs_data.extend(change_script)

        # Assemble unsigned transaction (without witness)
        unsigned_tx = (
            version
            + encode_varint(len(utxos))
            + bytes(inputs_data)
            + encode_varint(num_outputs)
            + bytes(outputs_data)
            + locktime
        )

        # Sign the transaction
        tx = deserialize_transaction(unsigned_tx)
        witnesses: list[list[bytes]] = []

        for i, utxo in enumerate(utxos):
            key = wallet.get_key_for_address(utxo.address)
            if not key:
                logger.error(f"Missing key for address {utxo.address}")
                raise typer.Exit(1)

            pubkey_bytes = key.get_public_key_bytes(compressed=True)

            # Check if this is a timelocked (fidelity bond) UTXO
            if utxo.is_timelocked and utxo.locktime is not None:
                # P2WSH signing for fidelity bonds
                from jmcore.btc_script import mk_freeze_script

                witness_script = mk_freeze_script(pubkey_bytes.hex(), utxo.locktime)
                signature = sign_p2wsh_input(
                    tx=tx,
                    input_index=i,
                    witness_script=witness_script,
                    value=utxo.value,
                    private_key=key.private_key,
                )
                witnesses.append(create_p2wsh_witness_stack(signature, witness_script))
            elif utxo.is_p2wsh:
                # P2WSH UTXO detected but locktime not known - this shouldn't happen
                # if the wallet was synced correctly with fidelity bond locktimes
                logger.error(
                    f"Cannot sign P2WSH UTXO {utxo.txid}:{utxo.vout} - "
                    f"locktime not available. This UTXO appears to be a fidelity bond "
                    f"but was not synced with its locktime information."
                )
                raise typer.Exit(1)
            else:
                # P2WPKH signing for regular UTXOs
                script_code = create_p2wpkh_script_code(pubkey_bytes)
                signature = sign_p2wpkh_input(
                    tx=tx,
                    input_index=i,
                    script_code=script_code,
                    value=utxo.value,
                    private_key=key.private_key,
                )
                witnesses.append([signature, pubkey_bytes])

        # Build signed transaction with witness
        signed_tx = bytearray()
        signed_tx.extend(version)
        signed_tx.extend(b"\x00\x01")  # Marker and flag for SegWit
        signed_tx.extend(encode_varint(len(utxos)))
        signed_tx.extend(inputs_data)
        signed_tx.extend(encode_varint(num_outputs))
        signed_tx.extend(outputs_data)

        # Witness stack
        for witness_stack in witnesses:
            signed_tx.extend(encode_varint(len(witness_stack)))
            for item in witness_stack:
                signed_tx.extend(encode_varint(len(item)))
                signed_tx.extend(item)

        signed_tx.extend(locktime)

        tx_hex = bytes(signed_tx).hex()
        print(f"\nSigned Transaction ({len(signed_tx)} bytes):")
        print(f"{tx_hex[:80]}...")

        if broadcast:
            logger.info("Broadcasting transaction...")
            txid = await backend.broadcast_transaction(tx_hex)
            print("\nTransaction broadcast successfully!")
            print(f"TXID: {txid}")
        else:
            print("\nTransaction NOT broadcast (--broadcast not set)")
            print(f"Full hex: {tx_hex}")

    finally:
        await wallet.close()


@app.command()
def history(
    limit: Annotated[int | None, typer.Option("--limit", "-n", help="Max entries to show")] = None,
    role: Annotated[
        str | None, typer.Option("--role", "-r", help="Filter by role (maker/taker)")
    ] = None,
    stats: Annotated[bool, typer.Option("--stats", "-s", help="Show statistics only")] = False,
    csv_output: Annotated[bool, typer.Option("--csv", help="Output as CSV")] = False,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
) -> None:
    """View CoinJoin transaction history."""
    from jmwallet.history import get_history_stats, read_history

    role_filter: Literal["maker", "taker"] | None = None
    if role:
        if role.lower() not in ("maker", "taker"):
            logger.error("Role must be 'maker' or 'taker'")
            raise typer.Exit(1)
        role_filter = role.lower()  # type: ignore[assignment]

    if stats:
        stats_data = get_history_stats(data_dir)

        print("\n" + "=" * 60)
        print("COINJOIN HISTORY STATISTICS")
        print("=" * 60)
        print(f"Total CoinJoins:      {stats_data['total_coinjoins']}")
        print(f"  As Maker:           {stats_data['maker_coinjoins']}")
        print(f"  As Taker:           {stats_data['taker_coinjoins']}")
        print(f"Success Rate:         {stats_data['success_rate']:.1f}%")
        print(f"Total Volume:         {stats_data['total_volume']:,} sats")
        print(f"Total Fees Earned:    {stats_data['total_fees_earned']:,} sats")
        print(f"Total Fees Paid:      {stats_data['total_fees_paid']:,} sats")
        print("=" * 60 + "\n")
        return

    entries = read_history(data_dir, limit, role_filter)

    if not entries:
        print("\nNo CoinJoin history found.")
        return

    if csv_output:
        import csv as csv_module
        import sys

        fieldnames = [
            "timestamp",
            "role",
            "txid",
            "cj_amount",
            "peer_count",
            "net_fee",
            "success",
        ]
        writer = csv_module.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "timestamp": entry.timestamp,
                    "role": entry.role,
                    "txid": entry.txid,
                    "cj_amount": entry.cj_amount,
                    "peer_count": entry.peer_count if entry.peer_count is not None else "",
                    "net_fee": entry.net_fee,
                    "success": entry.success,
                }
            )
    else:
        print(f"\nCoinJoin History ({len(entries)} entries):")
        print("=" * 140)
        header = f"{'Timestamp':<20} {'Role':<7} {'Amount':>12} {'Peers':>6}"
        header += f" {'Net Fee':>12} {'TXID':<64}"
        print(header)
        print("-" * 140)

        for entry in entries:
            # Distinguish between pending, failed, and successful transactions
            if entry.success:
                status = ""
            elif entry.confirmations == 0 and entry.failure_reason == "Pending confirmation":
                status = " [PENDING]"
            else:
                status = " [FAILED]"
            txid_full = entry.txid if entry.txid else "N/A"
            fee_str = f"{entry.net_fee:+,}" if entry.net_fee != 0 else "0"
            peer_str = str(entry.peer_count) if entry.peer_count is not None else "?"

            print(
                f"{entry.timestamp[:19]:<20} {entry.role:<7} {entry.cj_amount:>12,} "
                f"{peer_str:>6} {fee_str:>12} {txid_full:<64}{status}"
            )

        print("=" * 140)


@app.command()
def validate(
    mnemonic_arg: Annotated[str | None, typer.Argument(help="Mnemonic to validate")] = None,
    mnemonic_file: Annotated[
        Path | None, typer.Option("--mnemonic-file", "-f", help="Path to mnemonic file")
    ] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
) -> None:
    """Validate a BIP39 mnemonic phrase."""
    mnemonic: str = ""

    if mnemonic_file:
        try:
            mnemonic = load_mnemonic_file(mnemonic_file, password)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")
            raise typer.Exit(1)
    elif mnemonic_arg:
        mnemonic = mnemonic_arg
    else:
        mnemonic = typer.prompt("Enter mnemonic to validate")

    if validate_mnemonic(mnemonic):
        print("Mnemonic is VALID")
        word_count = len(mnemonic.strip().split())
        print(f"Word count: {word_count}")
    else:
        print("Mnemonic is INVALID")
        raise typer.Exit(1)


# ============================================================================
# Fidelity Bond Registry Commands
# ============================================================================


@app.command("registry-list")
def registry_list(
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    funded_only: Annotated[
        bool,
        typer.Option("--funded-only", "-f", help="Show only funded bonds"),
    ] = False,
    active_only: Annotated[
        bool,
        typer.Option("--active-only", "-a", help="Show only active (funded & not expired) bonds"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "WARNING",
) -> None:
    """List all fidelity bonds in the registry."""
    setup_logging(log_level)

    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry

    resolved_data_dir = data_dir if data_dir else get_default_data_dir()
    registry = load_registry(resolved_data_dir)

    if active_only:
        bonds = registry.get_active_bonds()
    elif funded_only:
        bonds = registry.get_funded_bonds()
    else:
        bonds = registry.bonds

    if json_output:
        import json

        output = [bond.model_dump() for bond in bonds]
        print(json.dumps(output, indent=2))
        return

    if not bonds:
        print("\nNo fidelity bonds found in registry.")
        print(f"Registry: {resolved_data_dir / 'fidelity_bonds.json'}")
        return

    print(f"\nFidelity Bonds ({len(bonds)} total)")
    print("=" * 120)
    header = f"{'Address':<64} {'Locktime':<20} {'Status':<15} {'Value':>15} {'Index':>6}"
    print(header)
    print("-" * 120)

    for bond in bonds:
        # Status
        if bond.is_funded and not bond.is_expired:
            status = "ACTIVE"
        elif bond.is_funded and bond.is_expired:
            status = "EXPIRED (funded)"
        elif bond.is_expired:
            status = "EXPIRED"
        else:
            status = "UNFUNDED"

        # Value
        value_str = f"{bond.value:,} sats" if bond.value else "-"

        print(
            f"{bond.address:<64} {bond.locktime_human:<20} {status:<15} "
            f"{value_str:>15} {bond.index:>6}"
        )

    print("=" * 120)

    # Show best bond if any active
    best = registry.get_best_bond()
    if best:
        print(f"\nBest bond for advertising: {best.address[:20]}...{best.address[-8:]}")
        print(f"  Value: {best.value:,} sats, Unlock in: {best.time_until_unlock:,}s")


@app.command("registry-show")
def registry_show(
    address: Annotated[str, typer.Argument(help="Bond address to show")],
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "WARNING",
) -> None:
    """Show detailed information about a specific fidelity bond."""
    setup_logging(log_level)

    from jmcore.btc_script import disassemble_script
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry

    resolved_data_dir = data_dir if data_dir else get_default_data_dir()
    registry = load_registry(resolved_data_dir)

    bond = registry.get_bond_by_address(address)
    if not bond:
        print(f"\nBond not found: {address}")
        print(f"Registry: {resolved_data_dir / 'fidelity_bonds.json'}")
        raise typer.Exit(1)

    if json_output:
        import json

        print(json.dumps(bond.model_dump(), indent=2))
        return

    print("\n" + "=" * 80)
    print("FIDELITY BOND DETAILS")
    print("=" * 80)
    print(f"\nAddress:          {bond.address}")
    print(f"Network:          {bond.network}")
    print(f"Index:            {bond.index}")
    print(f"Path:             {bond.path}")
    print(f"Public Key:       {bond.pubkey}")
    print()
    print(f"Locktime:         {bond.locktime} ({bond.locktime_human})")
    if bond.is_expired:
        print("Status:           EXPIRED (can be spent)")
    else:
        remaining = bond.time_until_unlock
        days = remaining // 86400
        hours = (remaining % 86400) // 3600
        print(f"Status:           LOCKED ({days}d {hours}h remaining)")
    print()
    print("-" * 80)
    print("WITNESS SCRIPT")
    print("-" * 80)
    witness_script = bytes.fromhex(bond.witness_script_hex)
    print(f"Hex:          {bond.witness_script_hex}")
    print(f"Disassembled: {disassemble_script(witness_script)}")
    print()
    print("-" * 80)
    print("FUNDING STATUS")
    print("-" * 80)
    if bond.is_funded:
        print(f"TXID:         {bond.txid}")
        print(f"Vout:         {bond.vout}")
        print(f"Value:        {bond.value:,} sats")
        print(f"Confirmations: {bond.confirmations}")
    else:
        print("Not funded (or not yet synced)")
    print()
    print(f"Created:      {bond.created_at}")
    print("=" * 80 + "\n")


@app.command("recover-bonds")
def recover_bonds(
    mnemonic: Annotated[str | None, typer.Option("--mnemonic")] = None,
    mnemonic_file: Annotated[Path | None, typer.Option("--mnemonic-file", "-f")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool, typer.Option("--prompt-bip39-passphrase", help="Prompt for BIP39 passphrase")
    ] = False,
    network: Annotated[str | None, typer.Option("--network", "-n", help="Bitcoin network")] = None,
    backend_type: Annotated[
        str | None,
        typer.Option(
            "--backend", "-b", help="Backend: scantxoutset | descriptor_wallet | neutrino"
        ),
    ] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")] = None,
    rpc_user: Annotated[str | None, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = None,
    rpc_password: Annotated[
        str | None, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = None,
    neutrino_url: Annotated[
        str | None, typer.Option("--neutrino-url", envvar="NEUTRINO_URL")
    ] = None,
    max_index: Annotated[
        int,
        typer.Option(
            "--max-index", "-i", help="Max address index per locktime to scan (default 1)"
        ),
    ] = 1,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """
    Recover fidelity bonds by scanning all 960 possible timelocks.

    This command scans the blockchain for fidelity bonds at all valid
    timenumber locktimes (Jan 2020 through Dec 2099). Use this when
    recovering a wallet from mnemonic and you don't know which locktimes
    were used for fidelity bonds.

    The scan checks address index 0 by default (most wallets only use index 0).
    Use --max-index to scan more addresses per locktime if needed.
    """
    settings = setup_cli(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve backend settings
    backend_settings = resolve_backend_settings(
        settings,
        network=network,
        backend_type=backend_type,
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
        neutrino_url=neutrino_url,
        data_dir=data_dir,
    )

    asyncio.run(
        _recover_bonds_async(
            resolved_mnemonic,
            backend_settings,
            max_index,
            resolved_bip39_passphrase,
        )
    )


async def _recover_bonds_async(
    mnemonic: str,
    backend_settings: ResolvedBackendSettings,
    max_index: int,
    bip39_passphrase: str = "",
) -> None:
    """Async implementation of fidelity bond recovery."""
    from jmcore.timenumber import TIMENUMBER_COUNT

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.wallet.bond_registry import (
        create_bond_info,
        load_registry,
        save_registry,
    )
    from jmwallet.wallet.service import FIDELITY_BOND_BRANCH, WalletService

    # Create backend based on type
    backend: BitcoinCoreBackend | DescriptorWalletBackend | NeutrinoBackend
    if backend_settings.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=backend_settings.neutrino_url, network=backend_settings.network
        )
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            return
    elif backend_settings.backend_type == "descriptor_wallet":
        fingerprint = get_mnemonic_fingerprint(mnemonic, bip39_passphrase)
        wallet_name = generate_wallet_name(fingerprint, backend_settings.network)
        backend = DescriptorWalletBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
            wallet_name=wallet_name,
        )
        # Must create/load wallet before importing descriptors
        await backend.create_wallet()
    else:
        backend = BitcoinCoreBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
        )

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=backend_settings.network,
        mixdepth_count=5,
        passphrase=bip39_passphrase,
        data_dir=backend_settings.data_dir,
    )

    print("\nScanning for fidelity bonds...")
    print(f"Timelocks to scan: {TIMENUMBER_COUNT} (Jan 2020 - Dec 2099)")
    print(f"Addresses per timelock: {max_index}")
    print(f"Total addresses: {TIMENUMBER_COUNT * max_index:,}")
    print("-" * 60)

    # Progress callback
    def progress_callback(current: int, total: int) -> None:
        percent = (current / total) * 100
        print(f"\rProgress: {current}/{total} timelocks ({percent:.1f}%)...", end="", flush=True)

    try:
        # Discover fidelity bonds
        discovered_utxos = await wallet.discover_fidelity_bonds(
            max_index=max_index,
            progress_callback=progress_callback,
        )

        print()  # Newline after progress
        print("-" * 60)

        if not discovered_utxos:
            print("\nNo fidelity bonds found.")
            print("If you expected to find bonds, try increasing --max-index")
            return

        print(f"\nDiscovered {len(discovered_utxos)} fidelity bond(s):")
        print()

        # Load registry and add discovered bonds
        registry = load_registry(backend_settings.data_dir)
        new_bonds = 0

        from jmcore.bitcoin import format_amount
        from jmcore.timenumber import format_locktime_date

        coin_type = 0 if backend_settings.network == "mainnet" else 1

        for utxo in discovered_utxos:
            # Extract index and locktime from path
            # Path format: m/84'/coin'/0'/2/index:locktime
            path_parts = utxo.path.split("/")
            index_locktime = path_parts[-1]
            if ":" in index_locktime:
                idx_str, locktime_str = index_locktime.split(":")
                idx = int(idx_str)
                locktime = int(locktime_str)
            else:
                idx = int(index_locktime)
                locktime = utxo.locktime or 0

            # Show discovered bond
            locktime_date = format_locktime_date(locktime) if locktime else "unknown"
            print(f"  Address:   {utxo.address}")
            print(f"  Value:     {format_amount(utxo.value)}")
            print(f"  Locktime:  {locktime_date}")
            print(f"  TXID:      {utxo.txid}:{utxo.vout}")
            print()

            # Check if already in registry
            existing = registry.get_bond_by_address(utxo.address)
            if existing:
                # Update UTXO info
                registry.update_utxo_info(
                    address=utxo.address,
                    txid=utxo.txid,
                    vout=utxo.vout,
                    value=utxo.value,
                    confirmations=utxo.confirmations,
                )
            else:
                # Add new bond to registry
                # Get the key and script for the bond
                key = wallet.get_fidelity_bond_key(idx, locktime)
                pubkey_hex = key.get_public_key_bytes(compressed=True).hex()

                from jmcore.btc_script import mk_freeze_script

                witness_script = mk_freeze_script(pubkey_hex, locktime)
                path = f"m/84'/{coin_type}'/0'/{FIDELITY_BOND_BRANCH}/{idx}"

                bond_info = create_bond_info(
                    address=utxo.address,
                    locktime=locktime,
                    index=idx,
                    path=path,
                    pubkey_hex=pubkey_hex,
                    witness_script=witness_script,
                    network=backend_settings.network,
                )
                # Set UTXO info
                bond_info.txid = utxo.txid
                bond_info.vout = utxo.vout
                bond_info.value = utxo.value
                bond_info.confirmations = utxo.confirmations

                registry.add_bond(bond_info)
                new_bonds += 1

        # Save registry
        save_registry(registry, backend_settings.data_dir)

        print("-" * 60)
        print(f"Added {new_bonds} new bond(s) to registry")
        print(f"Updated {len(discovered_utxos) - new_bonds} existing bond(s)")
        print(f"Registry saved to: {backend_settings.data_dir / 'fidelity_bonds.json'}")

    finally:
        await wallet.close()


@app.command("registry-sync")
def registry_sync(
    mnemonic: Annotated[str | None, typer.Option("--mnemonic")] = None,
    mnemonic_file: Annotated[Path | None, typer.Option("--mnemonic-file", "-f")] = None,
    password: Annotated[str | None, typer.Option("--password", "-p")] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    prompt_bip39_passphrase: Annotated[
        bool, typer.Option("--prompt-bip39-passphrase", help="Prompt for BIP39 passphrase")
    ] = False,
    network: Annotated[str | None, typer.Option("--network", "-n")] = None,
    backend_type: Annotated[
        str | None,
        typer.Option(
            "--backend", "-b", help="Backend: scantxoutset | descriptor_wallet | neutrino"
        ),
    ] = None,
    rpc_url: Annotated[str | None, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")] = None,
    rpc_user: Annotated[str | None, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = None,
    rpc_password: Annotated[
        str | None, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = None,
    neutrino_url: Annotated[
        str | None, typer.Option("--neutrino-url", envvar="NEUTRINO_URL")
    ] = None,
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Sync fidelity bond funding status from the blockchain."""
    settings = setup_cli(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Resolve BIP39 passphrase
    resolved_bip39_passphrase = _resolve_bip39_passphrase(bip39_passphrase, prompt_bip39_passphrase)

    # Resolve backend settings
    backend_settings = resolve_backend_settings(
        settings,
        network=network,
        backend_type=backend_type,
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
        neutrino_url=neutrino_url,
        data_dir=data_dir,
    )

    from jmwallet.wallet.bond_registry import load_registry

    registry = load_registry(backend_settings.data_dir)

    if not registry.bonds:
        print("\nNo bonds in registry to sync.")
        print("Use 'generate-bond-address' to create bonds first.")
        raise typer.Exit(0)

    asyncio.run(
        _sync_bonds_async(
            registry,
            resolved_mnemonic,
            backend_settings,
            resolved_bip39_passphrase,
        )
    )


async def _sync_bonds_async(
    registry: BondRegistry,
    mnemonic: str,
    backend_settings: ResolvedBackendSettings,
    bip39_passphrase: str = "",
) -> None:
    """Async implementation of bond syncing."""
    from jmwallet.backends import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.wallet.bond_registry import save_registry
    from jmwallet.wallet.service import WalletService

    # Create backend based on type
    backend: BitcoinCoreBackend | DescriptorWalletBackend | NeutrinoBackend
    if backend_settings.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=backend_settings.neutrino_url, network=backend_settings.network
        )
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            return
    elif backend_settings.backend_type == "descriptor_wallet":
        fingerprint = get_mnemonic_fingerprint(mnemonic, bip39_passphrase)
        wallet_name = generate_wallet_name(fingerprint, backend_settings.network)
        backend = DescriptorWalletBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
            wallet_name=wallet_name,
        )
    else:
        backend = BitcoinCoreBackend(
            rpc_url=backend_settings.rpc_url,
            rpc_user=backend_settings.rpc_user,
            rpc_password=backend_settings.rpc_password,
        )

    # For descriptor wallet, ensure bond addresses are imported
    if backend_settings.backend_type == "descriptor_wallet" and registry.bonds:
        wallet = WalletService(
            mnemonic=mnemonic,
            backend=backend,
            network=backend_settings.network,
            mixdepth_count=5,
            passphrase=bip39_passphrase,
            data_dir=backend_settings.data_dir,
        )

        # Check if wallet is set up (base wallet without bonds)
        is_ready = await wallet.is_descriptor_wallet_ready(fidelity_bond_count=0)

        if not is_ready:
            # Wallet doesn't exist at all - set it up with bonds
            fidelity_bond_addresses = [(b.address, b.locktime, b.index) for b in registry.bonds]
            logger.info("Descriptor wallet not found. Setting up with bonds...")
            await wallet.setup_descriptor_wallet(
                fidelity_bond_addresses=fidelity_bond_addresses,
                rescan=True,
                smart_scan=True,
                background_full_rescan=True,
            )
        else:
            # Wallet exists - check if bonds are imported
            full_wallet_ready = await wallet.is_descriptor_wallet_ready(
                fidelity_bond_count=len(registry.bonds)
            )

            if not full_wallet_ready:
                # Base wallet exists but bonds missing - import them
                fidelity_bond_addresses = [(b.address, b.locktime, b.index) for b in registry.bonds]
                logger.info(f"Importing {len(fidelity_bond_addresses)} bond addresses...")
                await wallet.import_fidelity_bond_addresses(
                    fidelity_bond_addresses=fidelity_bond_addresses,
                    rescan=True,
                )

    print(f"\nSyncing {len(registry.bonds)} bonds...")
    print("-" * 60)

    # Get all bond addresses
    addresses = [bond.address for bond in registry.bonds]

    # Scan all addresses at once
    try:
        utxos = await backend.get_utxos(addresses)
    except Exception as e:
        logger.error(f"Failed to scan UTXOs: {e}")
        print(f"\nError scanning blockchain: {e}")
        return

    # Build a map of address -> UTXOs
    utxo_map: dict[str, list] = {}
    for utxo in utxos:
        if utxo.address not in utxo_map:
            utxo_map[utxo.address] = []
        utxo_map[utxo.address].append(utxo)

    updated = 0
    for bond in registry.bonds:
        bond_utxos = utxo_map.get(bond.address, [])
        if bond_utxos:
            # Use the first UTXO (there should typically only be one)
            utxo = bond_utxos[0]
            registry.update_utxo_info(
                address=bond.address,
                txid=utxo.txid,
                vout=utxo.vout,
                value=utxo.value,
                confirmations=utxo.confirmations,
            )
            updated += 1
            from jmcore.bitcoin import sats_to_btc

            btc_value = sats_to_btc(utxo.value)
            print(f"  {bond.address[:20]}... FUNDED ({btc_value:.8f} BTC)")
        else:
            if bond.is_funded:
                # Was funded but now isn't - might have been spent
                logger.warning(f"Bond {bond.address[:20]}... previously funded, now empty")
                print(f"  {bond.address[:20]}... SPENT or UNFUNDED")
            else:
                print(f"  {bond.address[:20]}... not funded")

    print("-" * 60)

    if updated > 0:
        save_registry(registry, backend_settings.data_dir)
        print(f"\nUpdated {updated} bond(s). Registry saved.")
    else:
        print("\nNo updates needed.")

    # Show summary
    funded = registry.get_funded_bonds()
    active = registry.get_active_bonds()
    print(f"\nTotal bonds: {len(registry.bonds)}")
    print(f"Funded: {len(funded)}")
    print(f"Active (funded & not expired): {len(active)}")


# ============================================================================
# Cold Wallet Fidelity Bond Support
# ============================================================================


@app.command("create-bond-address")
def create_bond_address(
    pubkey: Annotated[str, typer.Argument(help="Public key (hex, 33 bytes compressed)")],
    locktime: Annotated[
        int, typer.Option("--locktime", "-L", help="Locktime as Unix timestamp")
    ] = 0,
    locktime_date: Annotated[
        str | None,
        typer.Option(
            "--locktime-date", "-d", help="Locktime as date (YYYY-MM, must be 1st of month)"
        ),
    ] = None,
    network: Annotated[str, typer.Option("--network", "-n")] = "mainnet",
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    no_save: Annotated[
        bool,
        typer.Option("--no-save", help="Do not save the bond to the registry"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """
    Create a fidelity bond address from a public key (cold wallet workflow).

    This command creates a timelocked P2WSH bond address from a public key WITHOUT
    requiring your mnemonic or private keys. Use this for true cold storage security.

    WORKFLOW:
    1. Use Sparrow Wallet (or similar) with your hardware wallet
    2. Navigate to your wallet's receive addresses
    3. Find or create an address at the fidelity bond derivation path (m/84'/0'/0'/2/0)
    4. Copy the public key from the address details
    5. Use this command with the public key to create the bond address
    6. Fund the bond address from any wallet
    7. Use 'prepare-certificate-message' and hardware wallet signing for certificates

    Your hardware wallet never needs to be connected to this online tool.
    """
    setup_logging(log_level)

    # Validate pubkey
    try:
        pubkey_bytes = bytes.fromhex(pubkey)
        if len(pubkey_bytes) != 33:
            raise ValueError("Public key must be 33 bytes (compressed)")
        # Verify it's a valid compressed pubkey (starts with 02 or 03)
        if pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")
    except ValueError as e:
        logger.error(f"Invalid public key: {e}")
        raise typer.Exit(1)

    # Parse locktime
    from jmcore.timenumber import is_valid_locktime, parse_locktime_date

    if locktime_date:
        try:
            locktime = parse_locktime_date(locktime_date)
        except ValueError as e:
            logger.error(f"Invalid locktime date: {e}")
            logger.info("Use format: YYYY-MM or YYYY-MM-DD (must be 1st of month)")
            logger.info("Valid range: 2020-01 to 2099-12")
            raise typer.Exit(1)

    if locktime <= 0:
        logger.error("Locktime is required. Use --locktime or --locktime-date")
        raise typer.Exit(1)

    # Validate locktime is a valid timenumber (1st of month, midnight UTC)
    if not is_valid_locktime(locktime):
        from jmcore.timenumber import get_nearest_valid_locktime

        suggested = get_nearest_valid_locktime(locktime, round_up=True)
        suggested_dt = datetime.fromtimestamp(suggested)
        logger.warning(
            f"Locktime {locktime} is not a valid fidelity bond locktime "
            f"(must be 1st of month at midnight UTC)"
        )
        logger.info(f"Suggested locktime: {suggested} ({suggested_dt.strftime('%Y-%m-%d')})")
        logger.info("Use --locktime-date YYYY-MM for correct format")
        raise typer.Exit(1)

    # Validate locktime is in the future
    if locktime <= datetime.now().timestamp():
        logger.warning("Locktime is in the past - the bond will be immediately spendable")

    from jmcore.btc_script import disassemble_script, mk_freeze_script
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.address import script_to_p2wsh_address
    from jmwallet.wallet.bond_registry import (
        create_bond_info,
        load_registry,
        save_registry,
    )

    # Create the witness script from the public key
    witness_script = mk_freeze_script(pubkey, locktime)
    address = script_to_p2wsh_address(witness_script, network)

    locktime_dt = datetime.fromtimestamp(locktime)
    disassembled = disassemble_script(witness_script)

    # Resolve data directory
    resolved_data_dir = data_dir if data_dir else get_default_data_dir()

    # Save to registry unless --no-save
    saved = False
    existing = False
    if not no_save:
        registry = load_registry(resolved_data_dir)
        existing_bond = registry.get_bond_by_address(address)
        if existing_bond:
            existing = True
            logger.info(f"Bond already exists in registry (created: {existing_bond.created_at})")
        else:
            # For bonds created from pubkey, we don't have the derivation path or index
            # So we use placeholder values
            bond_info = create_bond_info(
                address=address,
                locktime=locktime,
                index=-1,  # Unknown index for pubkey-based bonds
                path="external",  # Path is unknown when created from pubkey
                pubkey_hex=pubkey,
                witness_script=witness_script,
                network=network,
            )
            registry.add_bond(bond_info)
            save_registry(registry, resolved_data_dir)
            saved = True

    print("\n" + "=" * 80)
    print("FIDELITY BOND ADDRESS (created from public key)")
    print("=" * 80)
    print(f"\nAddress:      {address}")
    print(f"Locktime:     {locktime} ({locktime_dt.strftime('%Y-%m-%d %H:%M:%S')})")
    print(f"Network:      {network}")
    print(f"Public Key:   {pubkey}")
    print()
    print("-" * 80)
    print("WITNESS SCRIPT (redeemScript)")
    print("-" * 80)
    print(f"Hex:          {witness_script.hex()}")
    print(f"Disassembled: {disassembled}")
    print("-" * 80)
    if saved:
        print(f"\nSaved to registry: {resolved_data_dir / 'fidelity_bonds.json'}")
    elif existing:
        print("\nBond already in registry (not updated)")
    elif no_save:
        print("\nNot saved to registry (--no-save)")
    print("\n" + "=" * 80)
    print("HOW TO GET PUBLIC KEY FROM SPARROW WALLET:")
    print("=" * 80)
    print("  1. Open Sparrow Wallet with your hardware wallet")
    print("  2. Go to Addresses tab")
    print("  3. Navigate to the fidelity bond path: m/84'/0'/0'/2/0")
    print("     (Or use the address you want for the bond)")
    print("  4. Right-click the address and select 'Copy Public Key'")
    print("  5. Use the copied public key with this command")
    print()
    print("IMPORTANT:")
    print("  - Funds sent to this address are LOCKED until the locktime!")
    print("  - Make sure you can sign with this key in your hardware wallet")
    print("  - Your private keys never leave the hardware wallet")
    print("=" * 80 + "\n")


@app.command("generate-hot-keypair")
def generate_hot_keypair(
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Generate a hot wallet keypair for fidelity bond certificates.

    This generates a random keypair that will be used for signing nick messages
    in the fidelity bond proof. The private key stays in the hot wallet, while
    the public key is used to create a certificate signed by the cold wallet.

    The certificate chain is:
      UTXO keypair (cold) -> signs -> certificate (hot) -> signs -> nick proofs

    SECURITY:
    - The hot wallet private key should be stored securely
    - If compromised, an attacker can impersonate your bond until cert expires
    - But they CANNOT spend your bond funds (those remain in cold storage)
    """
    setup_logging(log_level)

    from coincurve import PrivateKey

    # Generate a random private key
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    print("\n" + "=" * 80)
    print("HOT WALLET KEYPAIR FOR FIDELITY BOND CERTIFICATE")
    print("=" * 80)
    print(f"\nPrivate Key (hex): {privkey.secret.hex()}")
    print(f"Public Key (hex):  {pubkey.hex()}")
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("  1. Store the private key securely (you will need it for import-certificate)")
    print("  2. Use the public key with 'prepare-certificate-message'")
    print("  3. Sign the certificate message with your hardware wallet")
    print("  4. Import the certificate with 'import-certificate'")
    print("\nSECURITY:")
    print("  - This is the HOT wallet key - it will be used to sign nick proofs")
    print("  - If this key is compromised, attacker can impersonate your bond")
    print("  - But your BOND FUNDS remain safe in cold storage!")
    print("=" * 80 + "\n")


@app.command("prepare-certificate-message")
def prepare_certificate_message(
    bond_address: Annotated[str, typer.Argument(help="Bond P2WSH address")],
    cert_pubkey: Annotated[
        str,
        typer.Option("--cert-pubkey", help="Certificate public key (hex)"),
    ],
    cert_expiry_blocks: Annotated[
        int,
        typer.Option("--cert-expiry-blocks", help="Certificate expiry in blocks"),
    ] = 104832,  # ~2 years (52 * 2016)
    data_dir_opt: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Prepare certificate message for signing with hardware wallet (cold wallet support).

    This generates the message that needs to be signed by the bond UTXO's private key.
    The message can then be signed using a hardware wallet via tools like Sparrow Wallet.

    IMPORTANT: This command does NOT require your mnemonic or private keys.
    It only prepares the message that you will sign with your hardware wallet.

    The certificate message format is:
      "fidelity-bond-cert|<cert_pubkey>|<cert_expiry>"

    Where cert_expiry is the number of 2016-block periods (difficulty adjustment periods).
    """
    setup_logging(log_level)

    if not cert_pubkey:
        logger.error("--cert-pubkey is required")
        raise typer.Exit(1)

    # Validate cert_pubkey
    try:
        cert_pubkey_bytes = bytes.fromhex(cert_pubkey)
        if len(cert_pubkey_bytes) != 33:
            raise ValueError("Certificate pubkey must be 33 bytes (compressed)")
        if cert_pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")
    except ValueError as e:
        logger.error(f"Invalid certificate pubkey: {e}")
        raise typer.Exit(1)

    # Calculate cert_expiry as 2016-block periods
    cert_expiry = cert_expiry_blocks // 2016

    # Create certificate message (binary format - matches reference implementation)
    cert_msg = b"fidelity-bond-cert|" + cert_pubkey_bytes + b"|" + str(cert_expiry).encode("ascii")

    # Also create the human-readable hex version for display
    cert_msg_hex = cert_msg.hex()

    # Save message to file for easier signing workflows
    from jmcore.paths import get_default_data_dir

    data_dir = data_dir_opt if data_dir_opt else get_default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    message_file = data_dir / "certificate_message.txt"
    message_file.write_text(cert_msg_hex)

    print("\n" + "=" * 80)
    print("FIDELITY BOND CERTIFICATE MESSAGE")
    print("=" * 80)
    print(f"\nBond Address:          {bond_address}")
    print(f"Certificate Pubkey:    {cert_pubkey}")
    weeks = cert_expiry_blocks // 2016 * 2
    print(f"Cert Expiry:           {cert_expiry} periods ({cert_expiry_blocks} blks, ~{weeks} wk)")
    print("\n" + "-" * 80)
    print("MESSAGE TO SIGN (hex format):")
    print("-" * 80)
    print(cert_msg_hex)
    print("-" * 80)
    print(f"\nMessage saved to: {message_file}")
    print("\n" + "=" * 80)
    print("HOW TO SIGN THIS MESSAGE:")
    print("=" * 80)
    print()
    print("This certificate message needs to be signed by the bond UTXO's private key")
    print("using Bitcoin message signing format.")
    print()
    print("OPTION 1: Sparrow Wallet with Hardware Wallet (Recommended)")
    print("  1. Open Sparrow Wallet and connect your hardware wallet")
    print("  2. Go to Tools -> Sign/Verify Message")
    print("  3. Select the address that corresponds to your bond's public key")
    print("     (NOT the bond P2WSH address - the underlying P2WPKH address)")
    print("  4. Paste the hex message above into the 'Message' field")
    print("  5. Click 'Sign Message' - hardware wallet will prompt for confirmation")
    print("  6. Copy the resulting signature")
    print()
    print("OPTION 2: Command-line with bitcoin-cli (if you have the private key)")
    print("  bitcoin-cli signmessagewithprivkey '<privkey_wif>' '<message_hex>'")
    print()
    print("After signing, use 'jm-wallet import-certificate' with the signature.")
    print("=" * 80 + "\n")


@app.command("import-certificate")
def import_certificate(
    address: Annotated[str, typer.Argument(help="Bond address")],
    cert_pubkey: Annotated[str, typer.Option("--cert-pubkey", help="Certificate pubkey (hex)")],
    cert_privkey: Annotated[
        str, typer.Option("--cert-privkey", help="Certificate private key (hex)")
    ],
    cert_signature: Annotated[
        str, typer.Option("--cert-signature", help="Certificate signature (base64 or hex)")
    ],
    cert_expiry: Annotated[int, typer.Option("--cert-expiry", help="Certificate expiry (periods)")],
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            help="Data directory (default: ~/.joinmarket-ng or $JOINMARKET_DATA_DIR)",
        ),
    ] = None,
    skip_verification: Annotated[
        bool,
        typer.Option("--skip-verification", help="Skip signature verification (not recommended)"),
    ] = False,
    log_level: Annotated[str, typer.Option("--log-level")] = "INFO",
) -> None:
    """
    Import a certificate signature for a fidelity bond (cold wallet support).

    This imports a certificate generated with 'prepare-certificate-message' into the
    bond registry, allowing the hot wallet to use it for making offers.

    You need to provide:
    - cert_pubkey: Hot wallet public key (from generate-hot-keypair)
    - cert_privkey: Hot wallet private key (from generate-hot-keypair)
    - cert_signature: Certificate signature from hardware wallet (base64 or hex)
    - cert_expiry: Certificate expiry in periods (from prepare-certificate-message)

    The signature must have been created by signing the certificate message with
    the bond UTXO's private key (in your hardware wallet).
    """
    setup_logging(log_level)

    from coincurve import PrivateKey
    from jmcore.crypto import bitcoin_message_hash_bytes, verify_raw_ecdsa
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry, save_registry

    # Validate inputs
    try:
        cert_pubkey_bytes = bytes.fromhex(cert_pubkey)
        if len(cert_pubkey_bytes) != 33:
            raise ValueError("Certificate pubkey must be 33 bytes")
        if cert_pubkey_bytes[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed public key format")

        cert_privkey_bytes = bytes.fromhex(cert_privkey)
        if len(cert_privkey_bytes) != 32:
            raise ValueError("Certificate privkey must be 32 bytes")

        # Try to decode signature - accept both base64 and hex
        try:
            cert_sig_bytes = base64.b64decode(cert_signature)
        except Exception:
            cert_sig_bytes = bytes.fromhex(cert_signature)

        # Verify that privkey matches pubkey
        privkey = PrivateKey(cert_privkey_bytes)
        derived_pubkey = privkey.public_key.format(compressed=True)
        if derived_pubkey != cert_pubkey_bytes:
            raise ValueError("Certificate privkey does not match cert_pubkey!")

    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        raise typer.Exit(1)

    # Load registry
    resolved_data_dir = data_dir if data_dir else get_default_data_dir()
    registry = load_registry(resolved_data_dir)

    # Find bond by address
    bond = registry.get_bond_by_address(address)
    if not bond:
        logger.error(f"Bond not found for address: {address}")
        logger.info("Make sure you have created the bond with 'create-bond-address' first")
        raise typer.Exit(1)

    # Verify certificate signature (unless skipped)
    if not skip_verification:
        try:
            # Reconstruct the certificate message
            cert_msg = (
                b"fidelity-bond-cert|" + cert_pubkey_bytes + b"|" + str(cert_expiry).encode("ascii")
            )
            msg_hash = bitcoin_message_hash_bytes(cert_msg)

            # Get the bond's utxo pubkey to verify
            utxo_pubkey = bytes.fromhex(bond.pubkey)

            # Verify signature
            if not verify_raw_ecdsa(msg_hash, cert_sig_bytes, utxo_pubkey):
                logger.error("Certificate signature verification failed!")
                logger.error("The signature does not match the bond's public key.")
                logger.info("Make sure you signed the message with the correct key.")
                raise typer.Exit(1)

            logger.info("Certificate signature verified successfully")

        except Exception as e:
            logger.error(f"Failed to verify certificate: {e}")
            raise typer.Exit(1)
    else:
        logger.warning("Skipping signature verification - use at your own risk!")

    # Update bond with certificate
    bond.cert_pubkey = cert_pubkey
    bond.cert_privkey = cert_privkey
    bond.cert_signature = cert_sig_bytes.hex()  # Store as hex for consistency
    bond.cert_expiry = cert_expiry

    save_registry(registry, resolved_data_dir)

    print("\n" + "=" * 80)
    print("CERTIFICATE IMPORTED SUCCESSFULLY")
    print("=" * 80)
    print(f"\nBond Address:          {address}")
    print(f"Certificate Pubkey:    {cert_pubkey}")
    print(f"Certificate Expiry:    {cert_expiry} periods ({cert_expiry * 2016} blocks)")
    print(f"\nRegistry updated: {resolved_data_dir / 'fidelity_bonds.json'}")
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("  The maker bot will automatically use this certificate when creating")
    print("  fidelity bond proofs. Your cold wallet private key is never needed!")
    print("=" * 80 + "\n")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
