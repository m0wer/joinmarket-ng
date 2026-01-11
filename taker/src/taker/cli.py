"""
Command-line interface for JoinMarket Taker.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from jmcore.models import NetworkType, get_default_directory_nodes
from jmcore.notifications import get_notifier
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from loguru import logger

from taker.config import MaxCjFee, Schedule, ScheduleEntry, TakerConfig
from taker.taker import Taker

app = typer.Typer(
    name="jm-taker",
    help="JoinMarket Taker - Execute CoinJoin transactions",
    add_completion=False,
)


def setup_logging(level: str) -> None:
    """Configure loguru logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )


def load_mnemonic(
    mnemonic: str | None,
    mnemonic_file: Path | None,
    password: str | None,
) -> str:
    """
    Load mnemonic from argument, file, or environment variable.

    Priority:
    1. --mnemonic argument
    2. --mnemonic-file argument
    3. MNEMONIC_FILE environment variable (path to mnemonic file)
    4. MNEMONIC environment variable

    Args:
        mnemonic: Direct mnemonic string
        mnemonic_file: Path to mnemonic file
        password: Password for encrypted file

    Returns:
        The mnemonic phrase

    Raises:
        ValueError: If no mnemonic source is available
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
            raise ValueError(f"Mnemonic file not found: {actual_mnemonic_file}")

        # Import the mnemonic loading utilities from jmwallet
        from jmwallet.cli import load_mnemonic_file

        try:
            return load_mnemonic_file(actual_mnemonic_file, password)
        except ValueError:
            # File is encrypted, need password
            if password is None:
                password = typer.prompt("Enter mnemonic file password", hide_input=True)
            return load_mnemonic_file(actual_mnemonic_file, password)

    env_mnemonic = os.environ.get("MNEMONIC")
    if env_mnemonic:
        return env_mnemonic

    raise ValueError(
        "Mnemonic required. Use --mnemonic, --mnemonic-file, MNEMONIC_FILE, or MNEMONIC env var"
    )


@app.command()
def coinjoin(
    amount: Annotated[int, typer.Option("--amount", "-a", help="Amount in sats (0 for sweep)")],
    destination: Annotated[
        str,
        typer.Option(
            "--destination",
            "-d",
            help="Destination address (or 'INTERNAL' for next mixdepth)",
        ),
    ] = "INTERNAL",
    mixdepth: Annotated[int, typer.Option("--mixdepth", "-m", help="Source mixdepth")] = 0,
    counterparties: Annotated[
        int, typer.Option("--counterparties", "-n", help="Number of makers")
    ] = 10,
    mnemonic: Annotated[
        str | None, typer.Option("--mnemonic", envvar="MNEMONIC", help="Wallet mnemonic phrase")
    ] = None,
    mnemonic_file: Annotated[
        Path | None, typer.Option("--mnemonic-file", "-f", help="Path to mnemonic file")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encrypted mnemonic file")
    ] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    network: Annotated[
        str, typer.Option("--network", help="Protocol network for handshakes")
    ] = "mainnet",
    bitcoin_network: Annotated[
        str | None,
        typer.Option(
            "--bitcoin-network", help="Bitcoin network for addresses (defaults to --network)"
        ),
    ] = None,
    backend_type: Annotated[
        str,
        typer.Option(
            "--backend", "-b", help="Backend type: full_node | descriptor_wallet | neutrino"
        ),
    ] = "descriptor_wallet",
    rpc_url: Annotated[
        str,
        typer.Option(
            "--rpc-url",
            envvar="BITCOIN_RPC_URL",
            help="Bitcoin full node RPC URL",
        ),
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[
        str,
        typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER", help="Bitcoin full node RPC user"),
    ] = "",
    rpc_password: Annotated[
        str,
        typer.Option(
            "--rpc-password", envvar="BITCOIN_RPC_PASSWORD", help="Bitcoin full node RPC password"
        ),
    ] = "",
    neutrino_url: Annotated[
        str,
        typer.Option(
            "--neutrino-url",
            envvar="NEUTRINO_URL",
            help="Neutrino REST API URL",
        ),
    ] = "http://127.0.0.1:8334",
    directory_servers: Annotated[
        str | None,
        typer.Option(
            "--directory",
            "-D",
            envvar="DIRECTORY_SERVERS",
            help="Directory servers (comma-separated). Defaults to mainnet directory nodes.",
        ),
    ] = None,
    tor_socks_host: Annotated[
        str, typer.Option(envvar="TOR_SOCKS_HOST", help="Tor SOCKS proxy host")
    ] = "127.0.0.1",
    tor_socks_port: Annotated[
        int, typer.Option(envvar="TOR_SOCKS_PORT", help="Tor SOCKS proxy port")
    ] = 9050,
    max_abs_fee: Annotated[
        int, typer.Option("--max-abs-fee", help="Max absolute fee in sats")
    ] = 500,
    max_rel_fee: Annotated[
        str, typer.Option("--max-rel-fee", help="Max relative fee (0.001=0.1%)")
    ] = "0.001",
    fee_rate: Annotated[
        float | None,
        typer.Option(
            "--fee-rate",
            help="Manual fee rate in sat/vB (e.g. 1.5). Mutually exclusive with --block-target.",
        ),
    ] = None,
    block_target: Annotated[
        int | None,
        typer.Option(
            "--block-target",
            help="Target blocks for fee estimation (1-1008). "
            "Defaults to 3 when using full node. "
            "Cannot be used with neutrino backend.",
        ),
    ] = None,
    bondless_makers_allowance: Annotated[
        float,
        typer.Option(
            "--bondless-allowance",
            envvar="BONDLESS_MAKERS_ALLOWANCE",
            help="Fraction of time to choose makers randomly (0.0-1.0)",
        ),
    ] = 0.125,
    bond_value_exponent: Annotated[
        float,
        typer.Option(
            "--bond-exponent",
            envvar="BOND_VALUE_EXPONENT",
            help="Exponent for fidelity bond value calculation (default 1.3)",
        ),
    ] = 1.3,
    bondless_require_zero_fee: Annotated[
        bool,
        typer.Option(
            "--bondless-zero-fee/--no-bondless-zero-fee",
            envvar="BONDLESS_REQUIRE_ZERO_FEE",
            help="For bondless spots, require zero absolute fee (default: enabled)",
        ),
    ] = True,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")] = False,
    log_level: Annotated[str, typer.Option("--log-level", "-l", help="Log level")] = "INFO",
) -> None:
    """Execute a single CoinJoin transaction."""
    setup_logging(log_level)

    # Load mnemonic
    try:
        resolved_mnemonic = load_mnemonic(mnemonic, mnemonic_file, password)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Parse network
    try:
        network_type = NetworkType(network)
    except ValueError:
        logger.error(f"Invalid network: {network}")
        raise typer.Exit(1)

    # Parse bitcoin network (defaults to protocol network)
    actual_bitcoin_network = bitcoin_network or network
    try:
        bitcoin_network_type = NetworkType(actual_bitcoin_network)
    except ValueError:
        logger.error(f"Invalid bitcoin network: {actual_bitcoin_network}")
        raise typer.Exit(1)

    # Parse directory servers: use provided list or default for network
    if directory_servers:
        dir_servers = [s.strip() for s in directory_servers.split(",")]
    else:
        dir_servers = get_default_directory_nodes(network_type)

    # Build backend config based on type
    if backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url,
            "network": actual_bitcoin_network,
        }
    else:  # full_node or descriptor_wallet
        backend_config = {
            "rpc_url": rpc_url,
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
        }

    # Build config
    config = TakerConfig(
        mnemonic=resolved_mnemonic,
        passphrase=bip39_passphrase or "",
        network=network_type,
        bitcoin_network=bitcoin_network_type,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=dir_servers,
        socks_host=tor_socks_host,
        socks_port=tor_socks_port,
        destination_address=destination,
        amount=amount,
        mixdepth=mixdepth,
        counterparty_count=counterparties,
        max_cj_fee=MaxCjFee(abs_fee=max_abs_fee, rel_fee=max_rel_fee),
        fee_rate=fee_rate,
        fee_block_target=block_target,
        bondless_makers_allowance=bondless_makers_allowance,
        bond_value_exponent=bond_value_exponent,
        bondless_makers_allowance_require_zero_fee=bondless_require_zero_fee,
    )

    asyncio.run(_run_coinjoin(config, amount, destination, mixdepth, counterparties, yes))


async def _run_coinjoin(
    config: TakerConfig,
    amount: int,
    destination: str,
    mixdepth: int,
    counterparties: int,
    skip_confirmation: bool,
) -> None:
    """Run CoinJoin transaction."""
    # Use bitcoin_network for address generation
    bitcoin_network = config.bitcoin_network or config.network

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend | DescriptorWalletBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Verify connection early
        logger.info("Verifying Neutrino connection...")
        try:
            synced = await backend.wait_for_sync(timeout=30.0)
            if not synced:
                logger.error("Neutrino connection failed: not synced")
                raise typer.Exit(1)
            logger.info("Neutrino connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Neutrino backend: {e}")
            raise typer.Exit(1)
    elif config.backend_type == "descriptor_wallet":
        fingerprint = get_mnemonic_fingerprint(config.mnemonic, config.passphrase or "")
        wallet_name = generate_wallet_name(fingerprint, bitcoin_network.value)
        backend = DescriptorWalletBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
            wallet_name=wallet_name,
        )
        # Verify RPC connection early
        logger.info("Verifying Bitcoin Core RPC connection...")
        try:
            await backend.get_block_height()
            logger.info("Bitcoin Core RPC connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Bitcoin Core RPC: {e}")
            raise typer.Exit(1)
    else:  # full_node
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )
        # Verify RPC connection early
        logger.info("Verifying Bitcoin Core RPC connection...")
        try:
            await backend.get_block_height()
            logger.info("Bitcoin Core RPC connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Bitcoin Core RPC: {e}")
            raise typer.Exit(1)

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
        passphrase=config.passphrase,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
    )

    # Create confirmation callback
    def confirmation_callback(
        maker_details: list[dict],
        cj_amount: int,
        total_fee: int,
        destination: str,
        mining_fee: int | None = None,
    ) -> bool:
        """Callback for user confirmation after maker selection."""
        from jmcore.confirmation import confirm_transaction, format_maker_summary

        additional_info = format_maker_summary(maker_details)
        additional_info["CoinJoin Amount"] = cj_amount
        additional_info["Source Mixdepth"] = mixdepth

        return confirm_transaction(
            operation="coinjoin",
            amount=cj_amount,
            destination=destination,
            fee=total_fee,
            mining_fee=mining_fee,
            additional_info=additional_info,
            skip_confirmation=skip_confirmation,
        )

    # Create taker
    taker = Taker(wallet, backend, config, confirmation_callback=confirmation_callback)

    try:
        # Send startup notification immediately
        notifier = get_notifier()
        await notifier.notify_startup(
            component="Taker (CoinJoin)",
            network=config.network.value,
        )
        await taker.start()

        amount_display = "ALL (sweep)" if amount == 0 else f"{amount:,} sats"
        logger.info(f"Starting CoinJoin: {amount_display} -> {destination}")
        txid = await taker.do_coinjoin(
            amount=amount,
            destination=destination,
            mixdepth=mixdepth,
            counterparty_count=counterparties,
        )

        if txid:
            logger.info(f"CoinJoin successful! txid: {txid}")
        else:
            logger.error("CoinJoin failed")
            raise typer.Exit(1)

    finally:
        await taker.stop()


@app.command()
def tumble(
    schedule_file: Annotated[Path, typer.Argument(help="Path to schedule JSON file")],
    mnemonic: Annotated[
        str | None, typer.Option("--mnemonic", envvar="MNEMONIC", help="Wallet mnemonic phrase")
    ] = None,
    mnemonic_file: Annotated[
        Path | None, typer.Option("--mnemonic-file", "-f", help="Path to mnemonic file")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encrypted mnemonic file")
    ] = None,
    bip39_passphrase: Annotated[
        str | None,
        typer.Option(
            "--bip39-passphrase",
            envvar="BIP39_PASSPHRASE",
            help="BIP39 passphrase (13th/25th word)",
        ),
    ] = None,
    network: Annotated[str, typer.Option("--network", help="Bitcoin network")] = "mainnet",
    backend_type: Annotated[
        str,
        typer.Option(
            "--backend", "-b", help="Backend type: full_node | descriptor_wallet | neutrino"
        ),
    ] = "descriptor_wallet",
    rpc_url: Annotated[
        str,
        typer.Option(
            "--rpc-url",
            envvar="BITCOIN_RPC_URL",
            help="Bitcoin full node RPC URL",
        ),
    ] = "http://127.0.0.1:8332",
    rpc_user: Annotated[
        str,
        typer.Option("--rpc-user", envvar="BITCOIN_RPC_USER", help="Bitcoin full node RPC user"),
    ] = "",
    rpc_password: Annotated[
        str,
        typer.Option(
            "--rpc-password", envvar="BITCOIN_RPC_PASSWORD", help="Bitcoin full node RPC password"
        ),
    ] = "",
    neutrino_url: Annotated[
        str,
        typer.Option(
            "--neutrino-url",
            envvar="NEUTRINO_URL",
            help="Neutrino REST API URL",
        ),
    ] = "http://127.0.0.1:8334",
    directory_servers: Annotated[
        str | None,
        typer.Option(
            "--directory",
            "-D",
            envvar="DIRECTORY_SERVERS",
            help="Directory servers (comma-separated). Defaults to mainnet directory nodes.",
        ),
    ] = None,
    tor_socks_host: Annotated[
        str, typer.Option(envvar="TOR_SOCKS_HOST", help="Tor SOCKS proxy host")
    ] = "127.0.0.1",
    tor_socks_port: Annotated[
        int, typer.Option(envvar="TOR_SOCKS_PORT", help="Tor SOCKS proxy port")
    ] = 9050,
    log_level: Annotated[str, typer.Option("--log-level", "-l", help="Log level")] = "INFO",
) -> None:
    """Run a tumbler schedule of CoinJoins."""
    setup_logging(log_level)

    # Load mnemonic
    try:
        resolved_mnemonic = load_mnemonic(mnemonic, mnemonic_file, password)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    if not schedule_file.exists():
        logger.error(f"Schedule file not found: {schedule_file}")
        raise typer.Exit(1)

    # Load schedule
    import json

    try:
        with open(schedule_file) as f:
            schedule_data = json.load(f)

        entries = [ScheduleEntry(**entry) for entry in schedule_data["entries"]]
        schedule = Schedule(entries=entries)
    except Exception as e:
        logger.error(f"Failed to load schedule: {e}")
        raise typer.Exit(1)

    # Parse network
    try:
        network_type = NetworkType(network)
    except ValueError:
        logger.error(f"Invalid network: {network}")
        raise typer.Exit(1)

    # Parse directory servers: use provided list or default for network
    if directory_servers:
        dir_servers = [s.strip() for s in directory_servers.split(",")]
    else:
        dir_servers = get_default_directory_nodes(network_type)

    # Build backend config based on type
    if backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url,
            "network": network,
        }
    else:
        backend_config = {
            "rpc_url": rpc_url,
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
        }

    # Build config
    config = TakerConfig(
        mnemonic=resolved_mnemonic,
        passphrase=bip39_passphrase or "",
        network=network_type,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=dir_servers,
        socks_host=tor_socks_host,
        socks_port=tor_socks_port,
    )

    asyncio.run(_run_tumble(config, schedule))


async def _run_tumble(config: TakerConfig, schedule: Schedule) -> None:
    """Run tumbler schedule."""
    # Use bitcoin_network for address generation
    bitcoin_network = config.bitcoin_network or config.network

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend | DescriptorWalletBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Verify connection early
        logger.info("Verifying Neutrino connection...")
        try:
            synced = await backend.wait_for_sync(timeout=30.0)
            if not synced:
                logger.error("Neutrino connection failed: not synced")
                raise typer.Exit(1)
            logger.info("Neutrino connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Neutrino backend: {e}")
            raise typer.Exit(1)
    elif config.backend_type == "descriptor_wallet":
        fingerprint = get_mnemonic_fingerprint(config.mnemonic, config.passphrase or "")
        wallet_name = generate_wallet_name(fingerprint, bitcoin_network.value)
        backend = DescriptorWalletBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
            wallet_name=wallet_name,
        )
        # Verify RPC connection early
        logger.info("Verifying Bitcoin Core RPC connection...")
        try:
            await backend.get_block_height()
            logger.info("Bitcoin Core RPC connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Bitcoin Core RPC: {e}")
            raise typer.Exit(1)
    else:  # full_node
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )
        # Verify RPC connection early
        logger.info("Verifying Bitcoin Core RPC connection...")
        try:
            await backend.get_block_height()
            logger.info("Bitcoin Core RPC connection verified")
        except Exception as e:
            logger.error(f"Failed to connect to Bitcoin Core RPC: {e}")
            raise typer.Exit(1)

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
        passphrase=config.passphrase,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
    )

    # Create taker
    taker = Taker(wallet, backend, config)

    try:
        # Send startup notification immediately
        notifier = get_notifier()
        await notifier.notify_startup(
            component="Taker (Tumble)",
            network=config.network.value,
        )
        await taker.start()

        logger.info(f"Starting tumble with {len(schedule.entries)} entries")
        success = await taker.run_schedule(schedule)

        if success:
            logger.info("Tumble complete!")
        else:
            logger.error("Tumble failed")
            raise typer.Exit(1)

    finally:
        await taker.stop()


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
