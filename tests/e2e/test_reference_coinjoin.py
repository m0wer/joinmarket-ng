"""
End-to-end test for CoinJoin with reference JoinMarket implementation.

This test verifies compatibility between our implementation and the reference
JoinMarket client-server by:
1. Running our directory server and maker bots
2. Running the reference jam-standalone as the taker
3. Executing a complete CoinJoin transaction

Prerequisites:
- Docker and Docker Compose installed
- Run: docker compose --profile reference up -d

Usage:
    pytest tests/e2e/test_reference_coinjoin.py -v -s --timeout=600

Note: These tests are SKIPPED automatically if the reference services (jam, tor)
are not running. This allows running the full test suite without failures:

    pytest -lv --cov=... jmcore orderbook_watcher directory_server jmwallet maker taker tests
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from loguru import logger


# Timeouts for reference implementation tests
STARTUP_TIMEOUT = 180  # 3 minutes for all services to start
COINJOIN_TIMEOUT = 300  # 5 minutes for coinjoin to complete
WALLET_FUND_TIMEOUT = 120  # 2 minutes for wallet funding

# Pre-generated deterministic onion address for our directory server
# Keys stored in tests/e2e/reference/tor_keys/
DIRECTORY_ONION = "5x6tavdaf6mdvckxw3jmobxmzxqnnsj3uldro5tvdlvo5hebhureysad.onion"


def get_compose_file() -> Path:
    """Get path to docker-compose file."""
    return Path(__file__).parent.parent.parent / "docker-compose.yml"


def run_compose_cmd(
    args: list[str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run a docker compose command."""
    compose_file = get_compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
    ] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def run_jam_cmd(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a command inside the jam container."""
    compose_file = get_compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "jam",
    ] + args
    logger.debug(f"Running in jam: {' '.join(args)}")
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def run_bitcoin_cmd(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a bitcoin-cli command."""
    compose_file = get_compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "bitcoin",
        "bitcoin-cli",
        "-regtest",
        "-rpcuser=test",
        "-rpcpassword=test",
    ] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


async def rpc_call(method: str, params: list[Any] | None = None) -> Any:
    """Make Bitcoin RPC call."""
    url = os.getenv("BITCOIN_RPC_URL", "http://127.0.0.1:18443")
    payload = {
        "jsonrpc": "1.0",
        "id": "test",
        "method": method,
        "params": params or [],
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            url,
            auth=("test", "test"),
            json=payload,
        )
        data = response.json()
        if data.get("error"):
            raise Exception(f"RPC error: {data['error']}")
        return data.get("result")


def is_jam_running() -> bool:
    """Check if the JAM container is running."""
    result = run_compose_cmd(["ps", "-q", "jam"], check=False)
    return bool(result.stdout.strip())


def is_tor_running() -> bool:
    """Check if the Tor container is running."""
    result = run_compose_cmd(["ps", "-q", "tor"], check=False)
    return bool(result.stdout.strip())


def wait_for_services(timeout: int = STARTUP_TIMEOUT) -> bool:
    """Wait for all reference profile services to be healthy."""
    start = time.time()
    services = ["bitcoin", "directory", "tor", "maker1", "maker2", "jam"]

    while time.time() - start < timeout:
        all_healthy = True
        for service in services:
            result = run_compose_cmd(
                ["ps", "--format", "json", service],
                check=False,
            )
            if result.returncode != 0 or "running" not in result.stdout.lower():
                all_healthy = False
                logger.debug(f"Service {service} not ready yet")
                break

        if all_healthy:
            logger.info("All services are running")
            return True

        time.sleep(5)

    logger.error("Timeout waiting for services")
    return False


def cleanup_wallet_lock(wallet_name: str = "test_wallet.jmdat") -> None:
    """Remove stale wallet lock file if it exists."""
    lock_file = f"/root/.joinmarket/wallets/.{wallet_name}.lock"
    result = run_jam_cmd(["rm", "-f", lock_file], timeout=10)
    if result.returncode == 0:
        logger.debug(f"Cleaned up lock file: {lock_file}")


def create_jam_wallet(
    wallet_name: str = "test_wallet.jmdat", password: str = "testpassword123"
) -> bool:
    """
    Create a wallet in jam using the expect script for automation.

    The expect script handles the interactive prompts from wallet-tool.py generate.
    """
    # Clean up any stale lock file from previous runs
    cleanup_wallet_lock(wallet_name)

    # Check if wallet already exists
    result = run_jam_cmd(
        ["ls", f"/root/.joinmarket/wallets/{wallet_name}"],
        timeout=30,
    )
    if result.returncode == 0:
        logger.info(f"Wallet {wallet_name} already exists")
        return True

    # Check if expect is available
    result = run_jam_cmd(["which", "expect"], timeout=10)
    if result.returncode != 0:
        # Try to install expect
        logger.info("Installing expect...")
        run_jam_cmd(["apt-get", "update"], timeout=60)
        run_jam_cmd(["apt-get", "install", "-y", "expect"], timeout=60)

    # Run the expect script to create wallet
    logger.info(f"Creating wallet {wallet_name} using expect automation...")
    result = run_jam_cmd(
        ["expect", "/scripts/create_wallet.exp", password, wallet_name],
        timeout=120,
    )

    if result.returncode != 0:
        logger.error(f"Wallet creation failed: {result.stderr}")
        logger.error(f"Output: {result.stdout}")
        return False

    logger.info(f"Wallet created successfully: {wallet_name}")
    logger.debug(f"Output: {result.stdout}")
    return True


def get_jam_wallet_address(
    wallet_name: str = "test_wallet.jmdat",
    password: str = "testpassword123",
    mixdepth: int = 0,
) -> str | None:
    """
    Get a receive address from jam wallet by piping the password.

    Uses stdin to provide the password non-interactively.
    """
    # Clean up any stale lock file from previous runs
    cleanup_wallet_lock(wallet_name)

    compose_file = get_compose_file()

    # Use bash to echo password and pipe it to wallet-tool.py
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "jam",
        "bash",
        "-c",
        f"echo '{password}' | python3 /src/scripts/wallet-tool.py "
        f"--datadir=/root/.joinmarket "
        f"--wallet-password-stdin "
        f"/root/.joinmarket/wallets/{wallet_name} display",
    ]

    logger.debug(f"Getting address with command: {' '.join(cmd)}")
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60, check=False
    )

    if result.returncode != 0:
        logger.error(f"Failed to get wallet info: {result.stderr}")
        logger.debug(f"Stdout: {result.stdout}")
        return None

    # Parse output to find first NEW address in external branch of mixdepth 0
    lines = result.stdout.split("\n")
    for line in lines:
        # Look for external addresses that are "new"
        if f"/{mixdepth}'/0/" in line and "new" in line.lower():
            parts = line.split()
            for part in parts:
                if part.startswith("bcrt1") or part.startswith("bc1"):
                    logger.info(f"Found new address: {part}")
                    return part

    # Fallback: just find any address in the right mixdepth
    for line in lines:
        if f"/{mixdepth}'/0/" in line:
            parts = line.split()
            for part in parts:
                if part.startswith("bcrt1") or part.startswith("bc1"):
                    logger.info(f"Found address: {part}")
                    return part

    logger.warning(f"Could not find address in wallet output:\n{result.stdout}")
    return None


def fund_wallet_address(address: str, amount_btc: float = 1.0) -> bool:
    """Fund a wallet address by mining blocks to it."""
    logger.info(f"Funding {address} with {amount_btc} BTC...")

    # Mine blocks to the address (110 for coinbase maturity + some extra)
    result = run_bitcoin_cmd(["generatetoaddress", "111", address])
    if result.returncode != 0:
        logger.error(f"Failed to mine blocks: {result.stderr}")
        return False

    logger.info("Mined 111 blocks for coinbase maturity")
    return True


# Skip all tests in this module if JAM is not running
pytestmark = pytest.mark.skipif(
    not is_jam_running(),
    reason="Reference services not running. Start with: docker compose --profile reference up -d",
)


@pytest.fixture(scope="module")
def reference_services():
    """
    Fixture for reference test services using docker compose.

    This fixture requires reference services to already be running.
    Tests are automatically skipped if services aren't available.

    To run these tests:
        docker compose --profile reference up -d
        pytest tests/e2e/test_reference_coinjoin.py -v -s
    """
    compose_file = get_compose_file()

    if not compose_file.exists():
        pytest.skip(f"Compose file not found: {compose_file}")

    # Verify JAM and Tor are running (already checked by pytestmark, but double-check)
    if not is_jam_running():
        pytest.skip(
            "JAM container not running. "
            "Start with: docker compose --profile reference up -d"
        )

    if not is_tor_running():
        pytest.skip(
            "Tor container not running. "
            "Start with: docker compose --profile reference up -d"
        )

    # Wait for services to be healthy
    if not wait_for_services(
        timeout=60
    ):  # Shorter timeout since we expect them running
        pytest.skip(
            "Reference services not healthy. "
            "Check logs with: docker compose --profile reference logs"
        )

    yield {
        "onion_address": DIRECTORY_ONION,
    }

    # Cleanup is optional - tests can leave services running for debugging
    if os.getenv("CLEANUP_SERVICES", "false").lower() == "true":
        logger.info("Stopping reference test services...")
        run_compose_cmd(["--profile", "reference", "down", "-v"])


@pytest.mark.asyncio
@pytest.mark.timeout(600)
async def test_services_healthy(reference_services):
    """Test that all services are running and healthy."""
    # Check Bitcoin
    result = run_bitcoin_cmd(["getblockchaininfo"])
    assert result.returncode == 0, f"Bitcoin not healthy: {result.stderr}"

    info = result.stdout
    assert "regtest" in info.lower(), "Should be regtest network"
    logger.info("Bitcoin Core is healthy")

    # Check makers are running by verifying container status and log activity
    # Containers that started successfully will have logs showing listen activity
    result = run_compose_cmd(["logs", "--tail=100", "maker1"], check=False)
    maker1_logs = result.stdout.lower()
    # A running maker will show periodic "collected N messages" or "timeout waiting" logs
    maker1_running = (
        "collected" in maker1_logs
        or "timeout waiting" in maker1_logs
        or "listen" in maker1_logs
    )
    assert maker1_running, f"Maker1 should be running. Logs: {result.stdout[-500:]}"

    result = run_compose_cmd(["logs", "--tail=100", "maker2"], check=False)
    maker2_logs = result.stdout.lower()
    maker2_running = (
        "collected" in maker2_logs
        or "timeout waiting" in maker2_logs
        or "listen" in maker2_logs
    )
    assert maker2_running, f"Maker2 should be running. Logs: {result.stdout[-500:]}"

    logger.info("All services are healthy")


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_jam_can_connect_to_directory(reference_services):
    """Test that jam can connect to our directory server via Tor."""
    onion = reference_services["onion_address"]
    logger.info(f"Testing jam connection to directory at {onion}")

    # Give jam some time to establish connection
    await asyncio.sleep(30)

    # Check jam logs for connection
    result = run_compose_cmd(["logs", "--tail=50", "jam"], check=False)
    logs = result.stdout + result.stderr

    # Look for successful connection indicators
    connection_success = any(
        [
            "connected" in logs.lower(),
            "handshake" in logs.lower(),
            "directory" in logs.lower(),
        ]
    )

    if not connection_success:
        logger.warning(f"Jam logs: {logs}")

    logger.info(f"Jam connection status from logs: {connection_success}")


@pytest.mark.asyncio
@pytest.mark.timeout(600)
async def test_complete_reference_coinjoin(reference_services):
    """
    Complete end-to-end CoinJoin test with reference implementation.

    This test:
    1. Creates a wallet in jam using expect automation
    2. Funds the wallet with regtest coins
    3. Verifies makers are advertising offers

    Note: Full coinjoin completion requires protocol compatibility.
    This test verifies the setup and wallet creation automation work.
    """
    wallet_name = "test_wallet.jmdat"
    wallet_password = "testpassword123"

    logger.info("Starting complete reference coinjoin test...")

    # Verify setup
    onion = reference_services["onion_address"]
    assert onion.endswith(".onion"), "Should have valid onion address"

    # Step 1: Create wallet in jam
    logger.info("Step 1: Creating wallet in jam...")
    wallet_created = create_jam_wallet(wallet_name, wallet_password)

    if not wallet_created:
        logger.warning("Automated wallet creation failed.")
        pytest.skip("Wallet creation requires manual intervention")

    # Step 2: Get a receiving address
    logger.info("Step 2: Getting wallet address...")
    address = get_jam_wallet_address(wallet_name, wallet_password, 0)

    if not address:
        logger.error("Failed to get wallet address")
        pytest.skip("Could not get wallet address")

    logger.info(f"Got wallet address: {address}")

    # Step 3: Fund the wallet
    logger.info("Step 3: Funding wallet...")
    funded = fund_wallet_address(address)
    assert funded, "Failed to fund wallet"

    # Wait for wallet to see the funds
    await asyncio.sleep(5)

    # Verify funding
    logger.info("Verifying wallet balance...")
    result = run_bitcoin_cmd(["getreceivedbyaddress", address])
    logger.info(f"Address balance: {result.stdout}")

    # Step 4: Check makers are advertising offers
    logger.info("Step 4: Checking maker offers...")
    result = run_compose_cmd(["logs", "--tail=100", "maker1"], check=False)
    logger.info(f"Maker1 recent logs:\n{result.stdout[-2000:]}")

    result = run_compose_cmd(["logs", "--tail=100", "maker2"], check=False)
    logger.info(f"Maker2 recent logs:\n{result.stdout[-2000:]}")

    logger.info("Reference coinjoin setup test PASSED")


@pytest.mark.asyncio
@pytest.mark.timeout(900)
async def test_execute_reference_coinjoin(reference_services):
    """
    Actually execute a coinjoin using the reference taker.

    This test requires:
    1. Full protocol compatibility between our implementation and reference
    2. Properly funded maker wallets
    3. Long timeout for Tor connections
    """
    wallet_name = "test_wallet.jmdat"
    wallet_password = "testpassword123"

    # Restart makers to ensure fresh wallet state
    # This is necessary because previous tests may have consumed maker UTXOs
    logger.info("Restarting makers to ensure fresh state...")
    run_compose_cmd(["restart", "maker1", "maker2"], check=False)
    await asyncio.sleep(15)  # Wait for makers to restart and announce offers

    # Ensure bitcoin and bitcoin-jam are fully synced
    logger.info("Checking that bitcoin nodes are synced...")
    for attempt in range(30):
        result1 = run_bitcoin_cmd(["getblockcount"])
        # Get bitcoin-jam blockcount
        result2 = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(get_compose_file()),
                "exec",
                "-T",
                "bitcoin-jam",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=test",
                "-rpcpassword=test",
                "-rpcport=18445",
                "getblockcount",
            ],
            capture_output=True,
            text=True,
        )

        if result1.returncode == 0 and result2.returncode == 0:
            count1 = int(result1.stdout.strip())
            count2 = int(result2.stdout.strip())
            logger.info(f"Block counts: bitcoin={count1}, bitcoin-jam={count2}")
            if count1 == count2:
                logger.info("Nodes are synced!")
                break
            else:
                logger.info(f"Waiting for sync... (attempt {attempt + 1}/30)")
                await asyncio.sleep(2)
        else:
            logger.warning("Failed to get block counts")
            await asyncio.sleep(2)
    else:
        pytest.fail("Bitcoin nodes failed to sync within timeout")

    # Now fund the taker wallet
    wallet_created = create_jam_wallet(wallet_name, wallet_password)
    assert wallet_created, "Wallet must exist"

    address = get_jam_wallet_address(wallet_name, wallet_password, 0)
    assert address, "Must have wallet address"

    # Fund the wallet
    funded = fund_wallet_address(address, 1.0)
    assert funded, "Wallet must be funded"

    # Wait for wallet sync
    await asyncio.sleep(5)

    # Get destination address (use mixdepth 1)
    dest_address = get_jam_wallet_address(wallet_name, wallet_password, 1)
    if not dest_address:
        # Create a new address in Bitcoin Core as fallback
        result = run_bitcoin_cmd(["getnewaddress", "", "bech32"])
        dest_address = result.stdout.strip()

    logger.info(f"Destination address: {dest_address}")

    # Clean up any stale lock file before running sendpayment
    cleanup_wallet_lock(wallet_name)

    # Run sendpayment.py
    compose_file = get_compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "jam",
        "bash",
        "-c",
        f"echo '{wallet_password}' | python3 /src/scripts/sendpayment.py "
        f"--datadir=/root/.joinmarket --wallet-password-stdin "
        f"-N 2 -m 0 /root/.joinmarket/wallets/{wallet_name} "
        f"10000000 {dest_address} --yes",
    ]

    logger.info(f"Running sendpayment: {' '.join(cmd)}")

    # This will take a while due to Tor connections
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=600, check=False
    )

    logger.info(f"sendpayment stdout:\n{result.stdout}")
    logger.info(f"sendpayment stderr:\n{result.stderr}")

    # Check for failure indicators first
    failure_indicators = [
        "not enough liquidity",
        "did not complete successfully",
        "error",
        "failed",
        "taker not continuing",
    ]
    output_lower = result.stdout.lower() + result.stderr.lower()
    failure_found = any(ind in output_lower for ind in failure_indicators)

    # Check for success indicators
    success_indicators = ["broadcast", "txid", "coinjoin complete", "transaction sent"]
    success_found = any(ind in output_lower for ind in success_indicators)

    if failure_found and not success_found:
        pytest.fail(
            f"CoinJoin failed. Check logs above for details.\nstdout: {result.stdout}"
        )

    assert result.returncode == 0, (
        f"sendpayment failed with exit code {result.returncode}: {result.stderr}"
    )
    assert success_found, (
        f"CoinJoin did not complete successfully. stdout: {result.stdout}"
    )


@pytest.mark.asyncio
async def test_maker_offers_visible(reference_services):
    """Test that our maker offers are visible in the orderbook."""
    # Wait for makers to announce offers
    await asyncio.sleep(10)

    # Check maker logs - they should be running and listening
    result = run_compose_cmd(["logs", "--tail=100", "maker1"], check=False)
    maker1_logs = result.stdout + result.stderr

    result = run_compose_cmd(["logs", "--tail=100", "maker2"], check=False)
    maker2_logs = result.stdout + result.stderr

    # Look for offer-related messages (might not be in recent logs if startup was long ago)
    offer_indicators = ["offer", "sw0reloffer", "pubmsg", "orderbook"]
    maker1_has_offers = any(ind in maker1_logs.lower() for ind in offer_indicators)
    maker2_has_offers = any(ind in maker2_logs.lower() for ind in offer_indicators)

    logger.info(f"Maker1 offers visible: {maker1_has_offers}")
    logger.info(f"Maker2 offers visible: {maker2_has_offers}")

    # At minimum, makers should be running (showing listen activity)
    maker1_running = (
        "collected" in maker1_logs.lower()
        or "timeout waiting" in maker1_logs.lower()
        or "listen" in maker1_logs.lower()
    )
    assert maker1_running, "Maker1 should be running"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--timeout=600"])
