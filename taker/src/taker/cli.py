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
    ] = 3,
    mnemonic: Annotated[
        str | None, typer.Option("--mnemonic", envvar="MNEMONIC", help="Wallet mnemonic phrase")
    ] = None,
    mnemonic_file: Annotated[
        Path | None, typer.Option("--mnemonic-file", "-f", help="Path to mnemonic file")
    ] = None,
    password: Annotated[
        str | None, typer.Option("--password", "-p", help="Password for encrypted mnemonic file")
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
        str, typer.Option("--backend", "-b", help="Backend type: full_node | neutrino")
    ] = "full_node",
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
    bondless_makers_allowance: Annotated[
        float,
        typer.Option(
            "--bondless-allowance", help="Fraction of time to choose makers randomly (0.0-1.0)"
        ),
    ] = 0.125,
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
    else:
        backend_config = {
            "rpc_url": rpc_url,
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
        }

    # Build config
    config = TakerConfig(
        mnemonic=resolved_mnemonic,
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
        bondless_makers_allowance=bondless_makers_allowance,
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

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Wait for neutrino to sync
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
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
            additional_info=additional_info,
            skip_confirmation=skip_confirmation,
        )

    # Create taker
    taker = Taker(wallet, backend, config, confirmation_callback=confirmation_callback)

    try:
        await taker.start()

        logger.info(f"Starting CoinJoin: {amount} sats -> {destination}")
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
    network: Annotated[str, typer.Option("--network", help="Bitcoin network")] = "mainnet",
    backend_type: Annotated[
        str, typer.Option("--backend", "-b", help="Backend type: full_node | neutrino")
    ] = "full_node",
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

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Wait for neutrino to sync
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
    )

    # Create taker
    taker = Taker(wallet, backend, config)

    try:
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
