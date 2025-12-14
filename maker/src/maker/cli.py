"""
Maker bot CLI using Typer.
"""

from __future__ import annotations

import asyncio

import typer
from jmcore.models import NetworkType
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from loguru import logger

from maker.bot import MakerBot
from maker.config import MakerConfig

app = typer.Typer(add_completion=False)


def run_async(coro):
    return asyncio.run(coro)


def create_wallet_service(config: MakerConfig) -> WalletService:
    backend_type = config.backend_type.lower()

    if backend_type == "bitcoin_core":
        backend_cfg = config.backend_config
        backend = BitcoinCoreBackend(
            rpc_url=backend_cfg.get("rpc_url", "http://127.0.0.1:18443"),
            rpc_user=backend_cfg.get("rpc_user", "test"),
            rpc_password=backend_cfg.get("rpc_password", "test"),
        )
    elif backend_type == "neutrino":
        backend_cfg = config.backend_config
        backend = NeutrinoBackend(
            neutrino_url=backend_cfg.get("neutrino_url", "http://127.0.0.1:8334"),
            network=config.network.value,
            connect_peers=backend_cfg.get("connect_peers", []),
            data_dir=backend_cfg.get("data_dir", "/data/neutrino"),
        )
    else:
        raise typer.BadParameter(f"Unsupported backend: {backend_type}")

    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network=config.network.value,
        mixdepth_count=config.mixdepth_count,
        gap_limit=config.gap_limit,
    )
    return wallet


@app.command()
def start(
    mnemonic: str = typer.Option(..., help="BIP39 mnemonic phrase"),
    network: NetworkType = typer.Option(NetworkType.REGTEST, case_sensitive=False),
    backend_type: str = typer.Option("bitcoin_core", help="Backend type: bitcoin_core | neutrino"),
    rpc_url: str | None = typer.Option(None, help="Bitcoin Core RPC URL"),
    rpc_user: str | None = typer.Option(None, help="Bitcoin Core RPC username"),
    rpc_password: str | None = typer.Option(None, help="Bitcoin Core RPC password"),
    neutrino_url: str | None = typer.Option(None, help="Neutrino REST API URL"),
    min_size: int = typer.Option(100_000, help="Minimum CoinJoin size in sats"),
    cj_fee_relative: str = typer.Option(
        "0.0002", help="Relative coinjoin fee (e.g., 0.0002 = 20bps)"
    ),
    tx_fee_contribution: int = typer.Option(10_000, help="Tx fee contribution in sats"),
    directory_servers: list[str] = typer.Option(
        ["127.0.0.1:5222"],
        help="Directory servers host:port (multiple allowed)",
    ),
):
    """Start the maker bot."""
    backend_config = {}
    if backend_type == "bitcoin_core":
        backend_config = {
            "rpc_url": rpc_url or "http://127.0.0.1:18443",
            "rpc_user": rpc_user or "test",
            "rpc_password": rpc_password or "test",
        }
    elif backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url or "http://127.0.0.1:8334",
            "network": network.value,
        }

    config = MakerConfig(
        mnemonic=mnemonic,
        network=network,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=directory_servers,
        min_size=min_size,
        cj_fee_relative=cj_fee_relative,
        tx_fee_contribution=tx_fee_contribution,
    )

    wallet = create_wallet_service(config)
    bot = MakerBot(wallet, wallet.backend, config)

    async def run_bot():
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
    mnemonic: str = typer.Option(..., help="BIP39 mnemonic"),
    network: NetworkType = typer.Option(NetworkType.REGTEST, case_sensitive=False),
    backend_type: str = typer.Option("bitcoin_core"),
):
    """Generate a new receive address."""
    config = MakerConfig(mnemonic=mnemonic, network=network, backend_type=backend_type)
    wallet = create_wallet_service(config)
    address = wallet.get_receive_address(0, 0)
    typer.echo(address)


def main():  # pragma: no cover
    app()
