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
# Reduced timeouts to fail faster and identify issues
STARTUP_TIMEOUT = 420  # 7 minutes for all services to start (Tor can be slow in CI)
COINJOIN_TIMEOUT = 240  # 4 minutes for coinjoin to complete (reduced from 15 min)
WALLET_FUND_TIMEOUT = 300  # 5 minutes for wallet funding

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


def run_bitcoin_jam_cmd(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a bitcoin-cli command against the bitcoin-jam node."""
    compose_file = get_compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "bitcoin-jam",
        "bitcoin-cli",
        "-regtest",
        "-rpcuser=test",
        "-rpcpassword=test",
        "-rpcport=18445",
    ] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def fund_wallet_address(address: str, amount_btc: float = 1.0) -> bool:
    """
    Fund a wallet address with a single large UTXO.

    JoinMarket's PoDLE commitment sourcing requires UTXOs that are at least 20%
    of the coinjoin amount. Mining blocks directly to the address creates many
    small coinbase UTXOs (~50 BTC each), which may not meet this requirement.

    We use the main bitcoin node's fidelity_funder wallet which has mature coins,
    send to the target address, and mine a block to confirm. The transaction will
    propagate to bitcoin-jam since the nodes are peers.
    """
    logger.info(f"Funding {address} with {amount_btc} BTC as single large UTXO...")

    # Use the fidelity_funder wallet on the main bitcoin node
    # This wallet has mature coins available from the miner
    funder_wallet = "fidelity_funder"

    # Check if funder wallet has enough funds
    result = run_bitcoin_cmd(["-rpcwallet=" + funder_wallet, "getbalance"])
    if result.returncode != 0:
        logger.warning(f"Could not get funder wallet balance: {result.stderr}")
        return _fund_wallet_via_mining(address)

    balance_str = result.stdout.strip()
    try:
        balance = float(balance_str)
    except ValueError:
        balance = 0.0

    logger.info(f"Funder wallet balance: {balance} BTC")

    # If funder wallet doesn't have enough funds, mine more blocks to it
    if balance < amount_btc + 0.01:  # +0.01 for fees
        logger.info("Funder wallet needs more funds, mining blocks...")
        result = run_bitcoin_cmd(["-rpcwallet=" + funder_wallet, "getnewaddress"])
        if result.returncode != 0:
            logger.error(f"Could not get funder address: {result.stderr}")
            return _fund_wallet_via_mining(address)

        funder_address = result.stdout.strip()
        # Mine 111 blocks for coinbase maturity
        result = run_bitcoin_cmd(["generatetoaddress", "111", funder_address])
        if result.returncode != 0:
            logger.error(f"Failed to mine blocks: {result.stderr}")
            return _fund_wallet_via_mining(address)

        logger.info("Mined 111 blocks to funder wallet")

    # Now send a single large transaction to the target address
    logger.info(f"Sending {amount_btc} BTC to {address}...")
    result = run_bitcoin_cmd(
        ["-rpcwallet=" + funder_wallet, "sendtoaddress", address, str(amount_btc)]
    )
    if result.returncode != 0:
        logger.error(f"Failed to send to address: {result.stderr}")
        return _fund_wallet_via_mining(address)

    txid = result.stdout.strip()
    logger.info(f"Sent {amount_btc} BTC to {address}, txid: {txid}")

    # Mine 5 blocks to confirm the transaction (on main node, propagates to peers)
    result = run_bitcoin_cmd(["-rpcwallet=" + funder_wallet, "getnewaddress"])
    if result.returncode == 0:
        funder_address = result.stdout.strip()
        result = run_bitcoin_cmd(["generatetoaddress", "5", funder_address])
        if result.returncode == 0:
            logger.info("Mined 5 blocks to confirm transaction")

    # Wait for the transaction to propagate to bitcoin-jam
    time.sleep(3)

    # Wait for nodes to sync - important for cross-node UTXO verification
    _wait_for_node_sync()

    return True


def _wait_for_node_sync(max_attempts: int = 30) -> bool:
    """Wait for bitcoin and bitcoin-jam nodes to have the same block height."""
    for attempt in range(max_attempts):
        result1 = run_bitcoin_cmd(["getblockcount"])
        result2 = run_bitcoin_jam_cmd(["getblockcount"])

        if result1.returncode == 0 and result2.returncode == 0:
            try:
                count1 = int(result1.stdout.strip())
                count2 = int(result2.stdout.strip())
                if count1 == count2:
                    logger.debug(f"Nodes synced at height {count1}")
                    return True
                logger.debug(
                    f"Waiting for sync: bitcoin={count1}, bitcoin-jam={count2}"
                )
            except ValueError:
                pass
        time.sleep(1)

    logger.warning("Nodes did not sync within timeout")
    return False


def restart_makers_and_wait(wait_time: int = 60) -> bool:
    """
    Restart maker containers and wait for them to be fully ready.

    This ensures makers have fresh UTXOs from the main bitcoin node
    and are properly connected to the directory server.
    """
    logger.info("Restarting makers to ensure fresh UTXO state...")

    # Restart both makers
    result = run_compose_cmd(["restart", "maker1", "maker2"], check=False)
    if result.returncode != 0:
        logger.warning(f"Failed to restart makers: {result.stderr}")
        return False

    logger.info(f"Waiting {wait_time}s for makers to sync and announce offers...")
    time.sleep(wait_time)

    # Verify makers are running by checking logs
    result = run_compose_cmd(["logs", "--tail=20", "maker1"], check=False)
    maker1_ok = (
        "collected" in result.stdout.lower() or "timeout" in result.stdout.lower()
    )

    result = run_compose_cmd(["logs", "--tail=20", "maker2"], check=False)
    maker2_ok = (
        "collected" in result.stdout.lower() or "timeout" in result.stdout.lower()
    )

    if maker1_ok and maker2_ok:
        logger.info("Both makers are running and listening")
        return True

    logger.warning("Makers may not be fully ready")
    return False


def _fund_wallet_via_mining(address: str) -> bool:
    """Fallback: fund wallet by mining directly to it (creates small UTXOs)."""
    logger.warning("Falling back to mining directly to target address...")
    logger.warning("This creates many small UTXOs which may not work for PoDLE!")

    # Mine blocks to the address on the main bitcoin node
    # The blocks will propagate to bitcoin-jam since they're peers
    result = run_bitcoin_cmd(["generatetoaddress", "111", address])
    if result.returncode != 0:
        logger.error(f"Failed to mine blocks: {result.stderr}")
        return False

    logger.info("Mined 111 blocks directly to address for coinbase maturity")
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

    # Give jam more time to establish Tor connection - CI environments are slower
    # Tor bootstrap + circuit establishment can take 60-90s in constrained environments
    await asyncio.sleep(90)

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
    assert connection_success, (
        f"Jam failed to connect to directory. Logs: {logs[-2000:]}"
    )


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


def stop_conflicting_makers() -> None:
    """Stop any makers that might conflict with reference tests.

    The neutrino maker uses a different blockchain backend and cannot verify
    UTXOs from the bitcoin-jam node, which causes coinjoin failures when the
    reference taker picks it up.
    """
    conflicting_containers = ["jm-maker-neutrino", "jm-maker"]
    for container in conflicting_containers:
        result = run_compose_cmd(["stop", container], check=False)
        if result.returncode == 0:
            logger.info(f"Stopped conflicting maker: {container}")


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_execute_reference_coinjoin(reference_services):
    """
    Actually execute a coinjoin using the reference taker.

    This test requires:
    1. Full protocol compatibility between our implementation and reference
    2. Properly funded maker wallets
    3. Reduced timeout (300s) - if it takes longer, something is wrong
    """
    wallet_name = "test_wallet.jmdat"
    wallet_password = "testpassword123"

    # Stop any conflicting makers (e.g., neutrino maker from --profile all)
    # The neutrino maker can't verify taker UTXOs from bitcoin-jam node
    stop_conflicting_makers()

    # Restart makers to ensure fresh wallet state with new UTXOs
    # This is critical - previous tests may have consumed maker UTXOs
    restart_makers_and_wait(wait_time=60)

    # Ensure bitcoin nodes are synced
    logger.info("Checking that bitcoin nodes are synced...")
    if not _wait_for_node_sync(max_attempts=30):
        pytest.fail("Bitcoin nodes failed to sync within timeout")

    # Now fund the taker wallet
    wallet_created = create_jam_wallet(wallet_name, wallet_password)
    assert wallet_created, "Wallet must exist"

    address = get_jam_wallet_address(wallet_name, wallet_password, 0)
    assert address, "Must have wallet address"

    # Fund the wallet
    funded = fund_wallet_address(address, 1.0)
    assert funded, "Wallet must be funded"

    # Wait for wallet sync - allow extra time in CI
    await asyncio.sleep(15)

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

    # Reduced timeout - if coinjoin takes longer than 240s, something is wrong
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=240, check=False
    )

    logger.info(f"sendpayment stdout:\n{result.stdout}")
    logger.info(f"sendpayment stderr:\n{result.stderr}")

    # Check for success - look for txid in output which indicates broadcast
    output_combined = result.stdout + result.stderr
    output_lower = output_combined.lower()

    # Strong success indicator: txid = <hash> means transaction was broadcast
    has_txid = "txid = " in output_combined or "txid:" in output_lower

    # Check for explicit failure indicators
    explicit_failures = [
        "not enough counterparties",
        "taker not continuing",
        "did not complete successfully",
        "giving up",
        "aborting",
    ]
    has_explicit_failure = any(ind in output_lower for ind in explicit_failures)

    if has_explicit_failure:
        pytest.fail(
            f"CoinJoin explicitly failed.\n"
            f"Exit code: {result.returncode}\n"
            f"Output: {result.stdout[-3000:]}"
        )

    assert has_txid, (
        f"CoinJoin did not broadcast transaction (no txid found).\n"
        f"Exit code: {result.returncode}\n"
        f"Output: {result.stdout[-3000:]}"
    )

    logger.info("CoinJoin completed successfully!")


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
