"""
E2E test configuration and fixtures.

Provides parameterized blockchain backend fixtures for testing
with different backends (Bitcoin Core, Neutrino).
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    from jmwallet.backends.base import BlockchainBackend


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add custom pytest options for e2e tests."""
    parser.addoption(
        "--backend",
        action="store",
        default="bitcoin_core",
        choices=["bitcoin_core", "neutrino", "all"],
        help="Blockchain backend to test: bitcoin_core, neutrino, or all",
    )
    parser.addoption(
        "--neutrino-url",
        action="store",
        default="http://127.0.0.1:8334",
        help="Neutrino REST API URL",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "neutrino: mark test as requiring neutrino backend",
    )
    config.addinivalue_line(
        "markers",
        "bitcoin_core: mark test as requiring bitcoin_core backend",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Skip tests based on backend selection."""
    backend = config.getoption("--backend")

    if backend == "all":
        return  # Run all tests

    skip_neutrino = pytest.mark.skip(reason="neutrino backend not selected")
    skip_bitcoin_core = pytest.mark.skip(reason="bitcoin_core backend not selected")

    for item in items:
        if backend == "bitcoin_core":
            if "neutrino" in item.keywords:
                item.add_marker(skip_neutrino)
        elif backend == "neutrino":
            if "bitcoin_core" in item.keywords:
                item.add_marker(skip_bitcoin_core)


@pytest.fixture(scope="session")
def backend_type(request: pytest.FixtureRequest) -> str:
    """Get the backend type from command line."""
    return request.config.getoption("--backend")


@pytest.fixture(scope="session")
def neutrino_url(request: pytest.FixtureRequest) -> str:
    """Get the neutrino URL from command line or environment."""
    url = request.config.getoption("--neutrino-url")
    return os.environ.get("NEUTRINO_URL", url)


@pytest.fixture
def bitcoin_rpc_config() -> dict[str, str]:
    """Bitcoin Core RPC configuration from environment or defaults."""
    return {
        "rpc_url": os.environ.get("BITCOIN_RPC_URL", "http://127.0.0.1:18443"),
        "rpc_user": os.environ.get("BITCOIN_RPC_USER", "test"),
        "rpc_password": os.environ.get("BITCOIN_RPC_PASSWORD", "test"),
    }


@pytest_asyncio.fixture
async def bitcoin_core_backend(
    bitcoin_rpc_config: dict[str, str],
) -> AsyncGenerator[BlockchainBackend, None]:
    """Create Bitcoin Core backend for tests."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend

    backend = BitcoinCoreBackend(
        rpc_url=bitcoin_rpc_config["rpc_url"],
        rpc_user=bitcoin_rpc_config["rpc_user"],
        rpc_password=bitcoin_rpc_config["rpc_password"],
    )
    yield backend
    await backend.close()


@pytest_asyncio.fixture
async def neutrino_backend_fixture(
    neutrino_url: str,
) -> AsyncGenerator[BlockchainBackend, None]:
    """Create Neutrino backend for tests."""
    from jmwallet.backends.neutrino import NeutrinoBackend

    backend = NeutrinoBackend(
        neutrino_url=neutrino_url,
        network="regtest",
    )

    # Check if neutrino is available
    try:
        await backend.get_block_height()
    except Exception:
        pytest.skip("Neutrino server not available")

    yield backend
    await backend.close()


@pytest_asyncio.fixture
async def blockchain_backend(
    request: pytest.FixtureRequest,
    backend_type: str,
    bitcoin_rpc_config: dict[str, str],
    neutrino_url: str,
) -> AsyncGenerator[BlockchainBackend, None]:
    """
    Parameterized blockchain backend fixture.

    Use this fixture when you want tests to run with both backends.
    """
    backend: BlockchainBackend

    if backend_type in ("bitcoin_core", "all"):
        from jmwallet.backends.bitcoin_core import BitcoinCoreBackend

        backend = BitcoinCoreBackend(
            rpc_url=bitcoin_rpc_config["rpc_url"],
            rpc_user=bitcoin_rpc_config["rpc_user"],
            rpc_password=bitcoin_rpc_config["rpc_password"],
        )
    elif backend_type == "neutrino":
        from jmwallet.backends.neutrino import NeutrinoBackend

        backend = NeutrinoBackend(
            neutrino_url=neutrino_url,
            network="regtest",
        )

        try:
            await backend.get_block_height()
        except Exception:
            pytest.skip("Neutrino server not available")
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")

    yield backend
    await backend.close()
