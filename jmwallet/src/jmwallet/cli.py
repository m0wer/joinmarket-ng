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
from loguru import logger

if TYPE_CHECKING:
    from jmwallet.wallet.bond_registry import BondRegistry

app = typer.Typer(
    name="jm-wallet",
    help="JoinMarket Wallet Management",
    add_completion=False,
)


def setup_logging(level: str = "INFO") -> None:
    """Configure loguru logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
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
# CLI Commands
# ============================================================================


@app.command()
def generate(
    word_count: Annotated[
        int, typer.Option("--words", "-w", help="Number of words (12, 15, 18, 21, or 24)")
    ] = 24,
    save: Annotated[bool, typer.Option("--save", "-s", help="Save to file")] = False,
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file path")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encryption")
    ] = None,
    prompt_password: Annotated[
        bool, typer.Option("--prompt-password", help="Prompt for password interactively")
    ] = False,
) -> None:
    """Generate a new BIP39 mnemonic phrase with secure entropy."""
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

        if save:
            if output_file is None:
                output_file = Path.home() / ".joinmarket-ng" / "wallets" / "default.mnemonic"

            # Prompt for password if requested
            if prompt_password:
                password = typer.prompt("Enter encryption password", hide_input=True)
                confirm = typer.prompt("Confirm password", hide_input=True)
                if password != confirm:
                    logger.error("Passwords do not match")
                    raise typer.Exit(1)

            save_mnemonic_file(mnemonic, output_file, password)

            typer.echo(f"\nMnemonic saved to: {output_file}")
            if password:
                typer.echo("File is encrypted - you will need the password to use it.")
            else:
                typer.echo("WARNING: File is NOT encrypted - consider using --password")
            typer.echo("KEEP THIS FILE SECURE - IT CONTROLS YOUR FUNDS!")

    except ValueError as e:
        logger.error(f"Failed to generate mnemonic: {e}")
        raise typer.Exit(1)
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
    """
    if mnemonic:
        return mnemonic

    # Check for mnemonic file (from argument or environment)
    actual_mnemonic_file = mnemonic_file
    if not actual_mnemonic_file:
        env_mnemonic_file = os.environ.get("MNEMONIC_FILE")
        if env_mnemonic_file:
            actual_mnemonic_file = Path(env_mnemonic_file)

    if actual_mnemonic_file:
        if not actual_mnemonic_file.exists():
            raise FileNotFoundError(f"Mnemonic file not found: {actual_mnemonic_file}")

        # Try loading without password first
        try:
            return load_mnemonic_file(actual_mnemonic_file, password)
        except ValueError:
            # File is encrypted, need password
            if prompt_password or password is None:
                password = typer.prompt("Enter mnemonic file password", hide_input=True)
            return load_mnemonic_file(actual_mnemonic_file, password)

    env_mnemonic = os.environ.get("MNEMONIC")
    if env_mnemonic:
        return env_mnemonic

    raise ValueError(
        "Mnemonic required. Use --mnemonic, --mnemonic-file, MNEMONIC_FILE, or MNEMONIC env var"
    )


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
    network: Annotated[str, typer.Option("--network", "-n", help="Bitcoin network")] = "mainnet",
    backend_type: Annotated[
        str, typer.Option("--backend", "-b", help="Backend: full_node | neutrino")
    ] = "full_node",
    rpc_url: Annotated[
        str, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[str, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = "",
    rpc_password: Annotated[
        str, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = "",
    neutrino_url: Annotated[
        str, typer.Option("--neutrino-url", envvar="NEUTRINO_URL")
    ] = "http://127.0.0.1:8334",
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Display wallet information and balances by mixdepth."""
    setup_logging(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    asyncio.run(
        _show_wallet_info(
            resolved_mnemonic,
            network,
            backend_type,
            rpc_url,
            rpc_user,
            rpc_password,
            neutrino_url,
            bip39_passphrase or "",
        )
    )


async def _show_wallet_info(
    mnemonic: str,
    network: str,
    backend_type: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
    neutrino_url: str,
    bip39_passphrase: str = "",
) -> None:
    """Show wallet info implementation."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.wallet.service import WalletService

    # Create backend
    if backend_type == "neutrino":
        backend = NeutrinoBackend(neutrino_url=neutrino_url, network=network)
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(rpc_url=rpc_url, rpc_user=rpc_user, rpc_password=rpc_password)

    # Create wallet
    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
        passphrase=bip39_passphrase,
    )

    try:
        await wallet.sync_all()

        from jmcore.bitcoin import format_amount

        total_balance = await wallet.get_total_balance()
        print(f"\nTotal Balance: {format_amount(total_balance)}")
        print("\nBalance by mixdepth:")

        for md in range(5):
            balance = await wallet.get_balance(md)
            addr = wallet.get_receive_address(md, 0)
            print(f"  Mixdepth {md}: {balance:>15,} sats  |  {addr}")

    finally:
        await wallet.close()


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
    network: Annotated[str, typer.Option("--network", "-n")] = "mainnet",
    backend_type: Annotated[str, typer.Option("--backend", "-b")] = "full_node",
    rpc_url: Annotated[
        str, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[str, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = "",
    rpc_password: Annotated[
        str, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = "",
    locktimes: Annotated[
        list[int] | None, typer.Option("--locktime", "-L", help="Locktime(s) to scan for")
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """List all fidelity bonds in the wallet."""
    setup_logging(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    asyncio.run(
        _list_fidelity_bonds(
            resolved_mnemonic,
            network,
            backend_type,
            rpc_url,
            rpc_user,
            rpc_password,
            locktimes or [],
            bip39_passphrase or "",
        )
    )


async def _list_fidelity_bonds(
    mnemonic: str,
    network: str,
    backend_type: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
    locktimes: list[int],
    bip39_passphrase: str = "",
) -> None:
    """List fidelity bonds implementation."""
    from jmcore.paths import get_default_data_dir

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.wallet.bond_registry import load_registry
    from jmwallet.wallet.service import WalletService

    # Import fidelity bond utilities from maker
    try:
        from maker.fidelity import find_fidelity_bonds
    except ImportError:
        logger.error("Failed to import fidelity bond utilities")
        raise typer.Exit(1)

    backend = BitcoinCoreBackend(rpc_url=rpc_url, rpc_user=rpc_user, rpc_password=rpc_password)

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
        data_dir = get_default_data_dir()
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

        bonds = find_fidelity_bonds(wallet)

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
    locktime: Annotated[
        int, typer.Option("--locktime", "-L", help="Locktime as Unix timestamp")
    ] = 0,
    locktime_date: Annotated[
        str | None,
        typer.Option(
            "--locktime-date", "-d", help="Locktime as date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)"
        ),
    ] = None,
    index: Annotated[int, typer.Option("--index", "-i", help="Address index")] = 0,
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
    """Generate a fidelity bond (timelocked P2WSH) address."""
    setup_logging(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Parse locktime
    if locktime_date:
        try:
            # Try full datetime format first
            try:
                dt = datetime.strptime(locktime_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Try date-only format
                dt = datetime.strptime(locktime_date, "%Y-%m-%d")
            locktime = int(dt.timestamp())
        except ValueError:
            logger.error(f"Invalid date format: {locktime_date}")
            logger.info("Use format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
            raise typer.Exit(1)

    if locktime <= 0:
        logger.error("Locktime is required. Use --locktime or --locktime-date")
        raise typer.Exit(1)

    # Validate locktime is in the future
    if locktime <= datetime.now().timestamp():
        logger.warning("Locktime is in the past - the bond will be immediately spendable")

    from jmcore.btc_script import disassemble_script, mk_freeze_script
    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.address import script_to_p2wsh_address
    from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed
    from jmwallet.wallet.bond_registry import (
        create_bond_info,
        load_registry,
        save_registry,
    )
    from jmwallet.wallet.service import FIDELITY_BOND_BRANCH

    seed = mnemonic_to_seed(resolved_mnemonic, bip39_passphrase or "")
    master_key = HDKey.from_seed(seed)

    coin_type = 0 if network == "mainnet" else 1
    path = f"m/84'/{coin_type}'/0'/{FIDELITY_BOND_BRANCH}/{index}"

    key = master_key.derive(path)
    pubkey_hex = key.get_public_key_bytes(compressed=True).hex()

    witness_script = mk_freeze_script(pubkey_hex, locktime)
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
            bond_info = create_bond_info(
                address=address,
                locktime=locktime,
                index=index,
                path=path,
                pubkey_hex=pubkey_hex,
                witness_script=witness_script,
                network=network,
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
    print(f"Network:      {network}")
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
    mixdepth: Annotated[int, typer.Option("--mixdepth", "-m", help="Source mixdepth")] = 0,
    fee_rate: Annotated[int, typer.Option("--fee-rate", help="Fee rate in sat/vB")] = 10,
    network: Annotated[str, typer.Option("--network", "-n")] = "mainnet",
    rpc_url: Annotated[
        str, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[str, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = "",
    rpc_password: Annotated[
        str, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = "",
    broadcast: Annotated[
        bool, typer.Option("--broadcast", help="Broadcast the transaction")
    ] = True,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l")] = "INFO",
) -> None:
    """Send a simple transaction from wallet to an address."""
    setup_logging(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    asyncio.run(
        _send_transaction(
            resolved_mnemonic,
            destination,
            amount,
            mixdepth,
            fee_rate,
            network,
            rpc_url,
            rpc_user,
            rpc_password,
            broadcast,
            yes,
            bip39_passphrase or "",
        )
    )


async def _send_transaction(
    mnemonic: str,
    destination: str,
    amount: int,
    mixdepth: int,
    fee_rate: int,
    network: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
    broadcast: bool,
    skip_confirmation: bool,
    bip39_passphrase: str = "",
) -> None:
    """Send transaction implementation."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.wallet.service import WalletService
    from jmwallet.wallet.signing import (
        create_p2wpkh_script_code,
        create_p2wsh_witness_stack,
        deserialize_transaction,
        encode_varint,
        sign_p2wpkh_input,
        sign_p2wsh_input,
    )

    backend = BitcoinCoreBackend(rpc_url=rpc_url, rpc_user=rpc_user, rpc_password=rpc_password)

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
        passphrase=bip39_passphrase,
    )

    try:
        await wallet.sync_all()

        balance = await wallet.get_balance(mixdepth)
        logger.info(f"Mixdepth {mixdepth} balance: {balance:,} sats")

        if amount == 0:
            # Sweep
            send_amount = balance
        else:
            send_amount = amount

        if send_amount > balance:
            logger.error(f"Insufficient funds: need {send_amount:,}, have {balance:,}")
            raise typer.Exit(1)

        # Estimate transaction size for fee calculation
        # P2WPKH: ~68 vbytes per input, ~31 vbytes per output
        utxos = await wallet.get_utxos(mixdepth)
        if not utxos:
            logger.error("No UTXOs available")
            raise typer.Exit(1)

        # Select UTXOs (simple approach: select all, calculate change)
        total_input = sum(u.value for u in utxos)
        num_inputs = len(utxos)

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
        estimated_fee = estimated_vsize * fee_rate

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
                estimated_fee = estimated_vsize * fee_rate

        num_outputs = len(output_types)

        # Use new format_amount for display
        from jmcore.bitcoin import format_amount

        logger.info(f"Sending {format_amount(send_amount)} to {destination}")
        logger.info(f"Fee: {format_amount(estimated_fee)} ({fee_rate} sat/vB)")
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
                    "Fee Rate": f"{fee_rate} sat/vB",
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
            status = "" if entry.success else " [FAILED]"
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
    network: Annotated[str, typer.Option("--network", "-n")] = "mainnet",
    rpc_url: Annotated[
        str, typer.Option("--rpc-url", envvar="BITCOIN_RPC_URL")
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[str, typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER")] = "",
    rpc_password: Annotated[
        str, typer.Option("--rpc-password", envvar="BITCOIN_RPC_PASSWORD")
    ] = "",
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
    setup_logging(log_level)

    try:
        resolved_mnemonic = _resolve_mnemonic(mnemonic, mnemonic_file, password, True)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise typer.Exit(1)

    from jmcore.paths import get_default_data_dir

    from jmwallet.wallet.bond_registry import load_registry

    resolved_data_dir = data_dir if data_dir else get_default_data_dir()
    registry = load_registry(resolved_data_dir)

    if not registry.bonds:
        print("\nNo bonds in registry to sync.")
        print("Use 'generate-bond-address' to create bonds first.")
        raise typer.Exit(0)

    asyncio.run(
        _sync_bonds_async(
            registry,
            resolved_mnemonic,
            network,
            rpc_url,
            rpc_user,
            rpc_password,
            resolved_data_dir,
            bip39_passphrase or "",
        )
    )


async def _sync_bonds_async(
    registry: BondRegistry,
    mnemonic: str,
    network: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
    data_dir: Path,
    bip39_passphrase: str = "",
) -> None:
    """Async implementation of bond syncing."""
    from jmwallet.backends import BitcoinCoreBackend
    from jmwallet.wallet.bond_registry import save_registry

    backend = BitcoinCoreBackend(
        rpc_url=rpc_url,
        rpc_user=rpc_user,
        rpc_password=rpc_password,
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
        save_registry(registry, data_dir)
        print(f"\nUpdated {updated} bond(s). Registry saved.")
    else:
        print("\nNo updates needed.")

    # Show summary
    funded = registry.get_funded_bonds()
    active = registry.get_active_bonds()
    print(f"\nTotal bonds: {len(registry.bonds)}")
    print(f"Funded: {len(funded)}")
    print(f"Active (funded & not expired): {len(active)}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
