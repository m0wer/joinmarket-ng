"""
E2E test configuration and fixtures.

Provides parameterized blockchain backend fixtures for testing
with different backends (Bitcoin Core, Neutrino).

Also provides fixtures for Docker service detection and wallet funding.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from loguru import logger

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
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running",
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


# =============================================================================
# Docker Service Detection
# =============================================================================


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()


def is_directory_server_running(host: str = "127.0.0.1", port: int = 5222) -> bool:
    """Check if directory server is running on the specified port."""
    return is_port_open(host, port)


def is_bitcoin_running(host: str = "127.0.0.1", port: int = 18443) -> bool:
    """Check if Bitcoin RPC is accessible."""
    return is_port_open(host, port)


@pytest.fixture(scope="session")
def docker_services_available() -> bool:
    """
    Check if Docker services are running.

    Returns True if both Bitcoin and Directory server are accessible.
    This is a session-scoped fixture so it's only checked once.
    """
    bitcoin_ok = is_bitcoin_running()
    directory_ok = is_directory_server_running()

    if not bitcoin_ok:
        logger.warning("Bitcoin Core not accessible on port 18443")
    if not directory_ok:
        logger.warning("Directory server not accessible on port 5222")

    return bitcoin_ok and directory_ok


@pytest.fixture(scope="module")
def require_docker_services(docker_services_available: bool) -> None:
    """
    Skip the test module if Docker services are not running.

    Use this fixture in tests that require the Docker Compose stack.
    """
    if not docker_services_available:
        pytest.skip(
            "Docker services not running. Start with: docker compose up -d\n"
            "Or for full e2e: docker compose --profile all up -d"
        )


@pytest_asyncio.fixture(scope="session")
async def ensure_blockchain_ready() -> None:
    """
    Ensure blockchain has sufficient height for coinbase maturity.

    Mines blocks if needed to reach height > 110.
    This is session-scoped so it only runs once per test session.
    """
    from tests.e2e.rpc_utils import mine_blocks, rpc_call

    try:
        info = await rpc_call("getblockchaininfo")
        height = info.get("blocks", 0)
        logger.info(f"Current blockchain height: {height}")

        if height < 110:
            blocks_needed = 120 - height
            # Mine to a valid P2WPKH address
            addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
            logger.info(f"Mining {blocks_needed} blocks for coinbase maturity...")
            await mine_blocks(blocks_needed, addr)
            logger.info(f"Mined {blocks_needed} blocks, new height: {120}")
    except Exception as e:
        logger.warning(f"Could not ensure blockchain ready: {e}")


@pytest_asyncio.fixture(scope="module")
async def wait_for_directory_server(
    docker_services_available: bool,
) -> AsyncGenerator[None, None]:
    """
    Wait for directory server to be ready and accepting connections.

    This fixture:
    1. Checks if the port is open
    2. Optionally performs a simple handshake check
    """
    if not docker_services_available:
        pytest.skip("Docker services not available")

    max_wait = 30  # seconds
    start = time.time()

    while time.time() - start < max_wait:
        if is_directory_server_running():
            logger.info("Directory server is ready")
            yield
            return
        await asyncio.sleep(1)

    pytest.skip("Directory server did not become ready in time")


@pytest.fixture(scope="function")
def fresh_docker_makers():
    """Restart Docker makers before test to ensure fresh UTXOs.

    This fixture restarts the Docker maker containers to prevent UTXO reuse
    between tests, which can cause transaction verification failures.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["docker", "restart", "jm-maker1", "jm-maker2"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("Restarted Docker makers, waiting for startup...")
            time.sleep(15)  # Wait for makers to start and sync with directory
        else:
            logger.warning(f"Failed to restart makers: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.warning("Docker restart timed out")
    except FileNotFoundError:
        logger.warning("Docker command not found")
    except Exception as e:
        logger.warning(f"Could not restart makers: {e}")

    yield
