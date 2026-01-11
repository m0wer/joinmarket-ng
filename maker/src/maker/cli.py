"""
Maker bot CLI using Typer.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Annotated

import typer
from jmcore.config import TorControlConfig, create_tor_control_config_from_env
from jmcore.models import NetworkType, OfferType, get_default_directory_nodes
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.bot import MakerBot
from maker.config import MakerConfig, MergeAlgorithm

app = typer.Typer(add_completion=False)


def run_async(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


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


def create_wallet_service(config: MakerConfig) -> WalletService:
    backend_type = config.backend_type.lower()
    # Use bitcoin_network for address generation (bcrt1 vs tb1 vs bc1)
    bitcoin_network = config.bitcoin_network or config.network

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.descriptor_wallet import (
        DescriptorWalletBackend,
        generate_wallet_name,
        get_mnemonic_fingerprint,
    )
    from jmwallet.backends.neutrino import NeutrinoBackend

    backend: BitcoinCoreBackend | DescriptorWalletBackend | NeutrinoBackend
    if backend_type == "descriptor_wallet":
        backend_cfg = config.backend_config
        fingerprint = get_mnemonic_fingerprint(config.mnemonic, config.passphrase or "")
        # Convert NetworkType enum to string value
        network_str = (
            bitcoin_network.value if hasattr(bitcoin_network, "value") else str(bitcoin_network)
        )
        wallet_name = generate_wallet_name(fingerprint, network_str)
        backend = DescriptorWalletBackend(
            rpc_url=backend_cfg.get("rpc_url", "http://127.0.0.1:8332"),
            rpc_user=backend_cfg.get("rpc_user", ""),
            rpc_password=backend_cfg.get("rpc_password", ""),
            wallet_name=wallet_name,
        )
    elif backend_type == "full_node":
        backend_cfg = config.backend_config
        backend = BitcoinCoreBackend(
            rpc_url=backend_cfg.get("rpc_url", "http://127.0.0.1:8332"),
            rpc_user=backend_cfg.get("rpc_user", ""),
            rpc_password=backend_cfg.get("rpc_password", ""),
        )
    elif backend_type == "neutrino":
        backend_cfg = config.backend_config
        backend = NeutrinoBackend(
            neutrino_url=backend_cfg.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
            connect_peers=backend_cfg.get("connect_peers", []),
            data_dir=backend_cfg.get("data_dir", "/data/neutrino"),
        )
    else:
        raise typer.BadParameter(f"Unsupported backend: {backend_type}")

    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
        gap_limit=config.gap_limit,
        passphrase=config.passphrase,
    )
    return wallet


@app.command()
def start(
    mnemonic: Annotated[
        str | None, typer.Option(help="BIP39 mnemonic phrase", envvar="MNEMONIC")
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
    data_dir: Annotated[
        Path | None,
        typer.Option(
            "--data-dir",
            "-d",
            envvar="JOINMARKET_DATA_DIR",
            help=(
                "Data directory for JoinMarket files (commitment blacklist, history). "
                "Defaults to ~/.joinmarket-ng or $JOINMARKET_DATA_DIR if set."
            ),
        ),
    ] = None,
    network: Annotated[NetworkType, typer.Option(case_sensitive=False)] = NetworkType.MAINNET,
    bitcoin_network: Annotated[
        NetworkType | None,
        typer.Option(
            case_sensitive=False,
            help="Bitcoin network for address generation (defaults to --network)",
        ),
    ] = None,
    backend_type: Annotated[
        str, typer.Option(help="Backend type: full_node | descriptor_wallet | neutrino")
    ] = "descriptor_wallet",
    rpc_url: Annotated[
        str | None, typer.Option(envvar="BITCOIN_RPC_URL", help="Bitcoin full node RPC URL")
    ] = None,
    rpc_user: Annotated[
        str | None, typer.Option(envvar="BITCOIN_RPC_USER", help="Bitcoin full node RPC username")
    ] = None,
    rpc_password: Annotated[
        str | None,
        typer.Option(envvar="BITCOIN_RPC_PASSWORD", help="Bitcoin full node RPC password"),
    ] = None,
    neutrino_url: Annotated[
        str | None, typer.Option(envvar="NEUTRINO_URL", help="Neutrino REST API URL")
    ] = None,
    min_size: Annotated[int, typer.Option(help="Minimum CoinJoin size in sats")] = 100_000,
    cj_fee_relative: Annotated[
        str | None,
        typer.Option(
            help=(
                "Relative coinjoin fee (e.g., 0.001 = 0.1%). "
                "Mutually exclusive with --cj-fee-absolute."
            ),
            envvar="CJ_FEE_RELATIVE",
        ),
    ] = None,
    cj_fee_absolute: Annotated[
        int | None,
        typer.Option(
            help="Absolute coinjoin fee in sats. Mutually exclusive with --cj-fee-relative.",
            envvar="CJ_FEE_ABSOLUTE",
        ),
    ] = None,
    tx_fee_contribution: Annotated[int, typer.Option(help="Tx fee contribution in sats")] = 0,
    directory_servers: Annotated[
        str | None,
        typer.Option(
            "--directory",
            "-D",
            envvar="DIRECTORY_SERVERS",
            help="Directory servers (comma-separated host:port). "
            "Defaults to mainnet directory nodes.",
        ),
    ] = None,
    tor_socks_host: Annotated[
        str, typer.Option(envvar="TOR_SOCKS_HOST", help="Tor SOCKS proxy host")
    ] = "127.0.0.1",
    tor_socks_port: Annotated[
        int, typer.Option(envvar="TOR_SOCKS_PORT", help="Tor SOCKS proxy port")
    ] = 9050,
    tor_control_host: Annotated[
        str | None,
        typer.Option(
            envvar="TOR_CONTROL_HOST",
            help="Tor control port host (default: auto-detect from TOR_SOCKS_HOST)",
        ),
    ] = None,
    tor_control_port: Annotated[
        int, typer.Option(envvar="TOR_CONTROL_PORT", help="Tor control port")
    ] = 9051,
    tor_cookie_path: Annotated[
        Path | None,
        typer.Option(
            envvar="TOR_COOKIE_PATH",
            help="Path to Tor cookie auth file (e.g., /var/lib/tor/control_auth_cookie)",
        ),
    ] = None,
    disable_tor_control: Annotated[
        bool,
        typer.Option(
            "--disable-tor-control",
            help="Disable Tor control port integration (maker won't create ephemeral onion)",
        ),
    ] = False,
    onion_serving_host: Annotated[
        str,
        typer.Option(
            envvar="ONION_SERVING_HOST",
            help="Bind address for incoming connections (0.0.0.0 for Docker)",
        ),
    ] = "127.0.0.1",
    onion_serving_port: Annotated[
        int,
        typer.Option(
            envvar="ONION_SERVING_PORT",
            help="Port for incoming .onion connections",
        ),
    ] = 5222,
    tor_target_host: Annotated[
        str,
        typer.Option(
            envvar="TOR_TARGET_HOST",
            help="Target hostname for Tor hidden service (use service name in Docker Compose)",
        ),
    ] = "127.0.0.1",
    fidelity_bond_locktimes: Annotated[
        list[int],
        typer.Option("--fidelity-bond-locktime", "-L", help="Fidelity bond locktimes to scan for"),
    ] = [],  # noqa: B006
    fidelity_bond_index: Annotated[
        int | None,
        typer.Option(
            "--fidelity-bond-index",
            "-I",
            envvar="FIDELITY_BOND_INDEX",
            help="Fidelity bond derivation index "
            "(bypasses registry, requires --fidelity-bond-locktime). "
            "Useful for Docker/automated setups without a registry file.",
        ),
    ] = None,
    fidelity_bond: Annotated[
        str | None,
        typer.Option(
            "--fidelity-bond",
            "-B",
            help="Specific fidelity bond to use (format: txid:vout). "
            "If not specified, the largest bond is selected automatically.",
        ),
    ] = None,
    merge_algorithm: Annotated[
        str,
        typer.Option(
            "--merge-algorithm",
            "-M",
            envvar="MERGE_ALGORITHM",
            help="UTXO selection strategy: default, gradual, greedy, random",
        ),
    ] = "default",
) -> None:
    """Start the maker bot."""
    # Load mnemonic
    try:
        resolved_mnemonic = load_mnemonic(mnemonic, mnemonic_file, password)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    # Use bitcoin_network for address generation, default to network if not specified
    actual_bitcoin_network = bitcoin_network or network

    # Auto-detect offer type based on which fee argument is provided
    # Priority: explicit values > env vars > defaults
    if cj_fee_relative is not None and cj_fee_absolute is not None:
        logger.error(
            "Cannot specify both --cj-fee-relative and --cj-fee-absolute. "
            "Use only one to set the fee model."
        )
        raise typer.Exit(1)

    # Determine offer type and fee values
    if cj_fee_absolute is not None:
        # User explicitly set absolute fee
        parsed_offer_type = OfferType.SW0_ABSOLUTE
        actual_cj_fee_relative = "0.001"  # Default for config, but won't be used
        actual_cj_fee_absolute = cj_fee_absolute
        logger.info(f"Using absolute fee: {cj_fee_absolute} sats")
    elif cj_fee_relative is not None:
        # User explicitly set relative fee
        parsed_offer_type = OfferType.SW0_RELATIVE
        actual_cj_fee_relative = cj_fee_relative
        actual_cj_fee_absolute = 500  # Default for config, but won't be used
        logger.info(f"Using relative fee: {cj_fee_relative}")
    else:
        # Neither specified - use relative as default
        parsed_offer_type = OfferType.SW0_RELATIVE
        actual_cj_fee_relative = "0.001"
        actual_cj_fee_absolute = 500
        logger.info("No fee specified, using default relative fee: 0.001 (0.1%)")

    # Resolve directory servers: use provided list or default for network
    if directory_servers:
        dir_servers = [s.strip() for s in directory_servers.split(",")]
    else:
        dir_servers = get_default_directory_nodes(network)

    # Parse and validate merge algorithm
    try:
        parsed_merge_algorithm = MergeAlgorithm(merge_algorithm.lower())
    except ValueError:
        logger.error(
            f"Invalid merge algorithm: {merge_algorithm}. "
            "Must be one of: default, gradual, greedy, random"
        )
        raise typer.Exit(1)

    # Validate fidelity bond index requires locktimes
    if fidelity_bond_index is not None and not fidelity_bond_locktimes:
        logger.error(
            "When using --fidelity-bond-index, you must also specify at least one "
            "--fidelity-bond-locktime"
        )
        raise typer.Exit(1)

    backend_config: dict[str, str] = {}
    if backend_type in ("full_node", "descriptor_wallet"):
        backend_config = {
            "rpc_url": rpc_url or "http://127.0.0.1:8332",
            "rpc_user": rpc_user or "",
            "rpc_password": rpc_password or "",
        }
    elif backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url or "http://127.0.0.1:8334",
            "network": actual_bitcoin_network.value,
        }

    # Configure Tor control port for ephemeral hidden service creation
    # By default, enabled with auto-detection from environment
    tor_control_cfg: TorControlConfig
    if disable_tor_control:
        # User explicitly disabled Tor control
        tor_control_cfg = TorControlConfig(enabled=False)
        logger.info("Tor control port integration disabled (will advertise NOT-SERVING-ONION)")
    else:
        # Auto-configure from environment with smart defaults
        tor_control_cfg = create_tor_control_config_from_env()

        # Override from CLI if provided
        if tor_control_host:
            object.__setattr__(tor_control_cfg, "host", tor_control_host)
        if tor_cookie_path:
            object.__setattr__(tor_control_cfg, "cookie_path", tor_cookie_path)

        logger.info(
            f"Tor control port integration enabled "
            f"({tor_control_cfg.host}:{tor_control_cfg.port}, "
            f"cookie_path={tor_control_cfg.cookie_path})"
        )

    config = MakerConfig(
        mnemonic=resolved_mnemonic,
        passphrase=bip39_passphrase or "",
        network=network,
        bitcoin_network=actual_bitcoin_network,
        data_dir=data_dir,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=dir_servers,
        socks_host=tor_socks_host,
        socks_port=tor_socks_port,
        tor_control=tor_control_cfg,
        onion_serving_host=onion_serving_host,
        onion_serving_port=onion_serving_port,
        tor_target_host=tor_target_host,
        min_size=min_size,
        offer_type=parsed_offer_type,
        cj_fee_relative=actual_cj_fee_relative,
        cj_fee_absolute=actual_cj_fee_absolute,
        tx_fee_contribution=tx_fee_contribution,
        fidelity_bond_locktimes=list(fidelity_bond_locktimes),
        fidelity_bond_index=fidelity_bond_index,
        merge_algorithm=parsed_merge_algorithm,
    )

    wallet = create_wallet_service(config)
    bot = MakerBot(wallet, wallet.backend, config)

    # Store the specific fidelity bond selection if provided
    if fidelity_bond:
        # Parse txid:vout format
        try:
            parts = fidelity_bond.split(":")
            if len(parts) != 2:
                raise ValueError("Invalid format")
            config.selected_fidelity_bond = (parts[0], int(parts[1]))
            logger.info(f"Using specified fidelity bond: {fidelity_bond}")
        except (ValueError, IndexError):
            logger.error(f"Invalid fidelity bond format: {fidelity_bond}. Use txid:vout")
            raise typer.Exit(1)

    async def run_bot() -> None:
        try:
            await bot.start()
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await bot.stop()

    try:
        run_async(run_bot())
    except KeyboardInterrupt:
        logger.info("Shutting down maker bot...")
        run_async(bot.stop())


@app.command()
def generate_address(
    mnemonic: Annotated[str | None, typer.Option(help="BIP39 mnemonic", envvar="MNEMONIC")] = None,
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
    network: Annotated[NetworkType, typer.Option(case_sensitive=False)] = NetworkType.MAINNET,
    bitcoin_network: Annotated[
        NetworkType | None,
        typer.Option(
            case_sensitive=False,
            help="Bitcoin network for address generation (defaults to --network)",
        ),
    ] = None,
    backend_type: Annotated[str, typer.Option()] = "descriptor_wallet",
) -> None:
    """Generate a new receive address."""
    # Load mnemonic
    try:
        resolved_mnemonic = load_mnemonic(mnemonic, mnemonic_file, password)
    except ValueError as e:
        logger.error(str(e))
        raise typer.Exit(1)

    actual_bitcoin_network = bitcoin_network or network
    config = MakerConfig(
        mnemonic=resolved_mnemonic,
        passphrase=bip39_passphrase or "",
        network=network,
        bitcoin_network=actual_bitcoin_network,
        backend_type=backend_type,
    )
    wallet = create_wallet_service(config)
    address = wallet.get_receive_address(0, 0)
    typer.echo(address)


def main() -> None:  # pragma: no cover
    app()
