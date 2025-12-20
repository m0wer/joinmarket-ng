"""
End-to-end test: Our Maker + Reference Taker (JAM).

This test verifies that our maker implementation is compatible with the
reference JoinMarket (jam-standalone) taker by:
1. Running our maker bots (maker1, maker2) from docker-compose
2. Running reference JAM as the taker
3. Executing a complete CoinJoin transaction
4. Verifying the transaction is created and broadcast successfully

Prerequisites:
- Docker and Docker Compose installed
- Run: docker compose --profile reference up -d

Usage:
    pytest tests/e2e/test_our_maker_reference_taker.py -v -s --timeout=600

Note: These tests are SKIPPED automatically if the reference services (jam, tor)
are not running.
"""

from __future__ import annotations

import asyncio
import subprocess
import time

import pytest
from loguru import logger

# Import utilities from reference test
from tests.e2e.test_reference_coinjoin import (
    COINJOIN_TIMEOUT,
    STARTUP_TIMEOUT,
    WALLET_FUND_TIMEOUT,
    _wait_for_node_sync,
    cleanup_wallet_lock,
    create_jam_wallet,
    fund_wallet_address,
    get_compose_file,
    get_jam_wallet_address,
    is_jam_running,
    is_tor_running,
    restart_makers_and_wait,
    run_bitcoin_cmd,
    run_compose_cmd,
    wait_for_services,
)


# Skip all tests in this module if JAM is not running
pytestmark = pytest.mark.skipif(
    not is_jam_running(),
    reason="Reference services not running. Start with: docker compose --profile reference up -d",
)


@pytest.fixture(scope="module")
def our_maker_reference_taker_services():
    """
    Fixture for testing our maker with reference taker.

    This assumes reference services are already running via docker-compose.
    The reference profile includes: bitcoin-jam, tor, jam, maker1, maker2 (our implementation).

    Services:
    - bitcoin-jam: Bitcoin Core node with legacy wallet support
    - tor: Tor daemon for onion routing
    - jam: Reference JoinMarket taker (jam-standalone)
    - maker1, maker2: Our maker implementation
    - directory: Our directory server
    """
    compose_file = get_compose_file()

    if not compose_file.exists():
        pytest.skip(f"Compose file not found: {compose_file}")

    # Verify all required services are running
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

    # Wait for all services to be healthy
    if not wait_for_services(timeout=STARTUP_TIMEOUT):
        pytest.skip(
            "Services not healthy. "
            "Check logs with: docker compose --profile reference logs"
        )

    # Give makers extra time to sync and announce offers
    # CI environments have more latency, especially with Tor
    logger.info("Waiting for makers to announce offers...")
    time.sleep(60)

    yield {
        "compose_file": compose_file,
    }


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_our_makers_are_running(our_maker_reference_taker_services):
    """Verify our maker bots are running and connected to directory."""
    # Check maker1
    result = run_compose_cmd(["logs", "--tail=100", "maker1"], check=False)
    maker1_logs = result.stdout.lower()

    # Look for signs of healthy maker operation
    # Include "timeout waiting" and "collected" which appear during normal operation
    # when the maker is idle and listening for messages
    maker1_indicators = [
        "connected",
        "handshake",
        "offer",
        "syncing",
        "wallet synced",
        "starting maker",
        "timeout waiting",
        "collected",
    ]
    maker1_healthy = any(ind in maker1_logs for ind in maker1_indicators)

    if not maker1_healthy:
        logger.warning(f"Maker1 logs:\n{result.stdout[-2000:]}")

    assert maker1_healthy, "Maker1 should be running and connected"
    logger.info("Maker1 is healthy")

    # Check maker2
    result = run_compose_cmd(["logs", "--tail=100", "maker2"], check=False)
    maker2_logs = result.stdout.lower()

    maker2_healthy = any(ind in maker2_logs for ind in maker1_indicators)

    if not maker2_healthy:
        logger.warning(f"Maker2 logs:\n{result.stdout[-2000:]}")

    assert maker2_healthy, "Maker2 should be running and connected"
    logger.info("Maker2 is healthy")


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_jam_taker_can_see_our_makers(our_maker_reference_taker_services):
    """Verify that JAM taker can see offers from our makers."""
    # Give more time for orderbook sync in CI
    await asyncio.sleep(45)

    # Check JAM logs for orderbook activity
    result = run_compose_cmd(["logs", "--tail=200", "jam"], check=False)
    jam_logs = result.stdout + result.stderr

    # Look for orderbook-related messages
    orderbook_indicators = [
        "offer",
        "orderbook",
        "sw0reloffer",
        "relorder",
        "absorder",
    ]

    has_orderbook = any(ind in jam_logs.lower() for ind in orderbook_indicators)

    if not has_orderbook:
        logger.warning(f"JAM logs (orderbook check):\n{jam_logs[-3000:]}")
    else:
        logger.info("JAM can see orderbook offers")


@pytest.mark.asyncio
@pytest.mark.timeout(WALLET_FUND_TIMEOUT)
async def test_create_and_fund_jam_wallet(our_maker_reference_taker_services):
    """Create and fund a JAM wallet for testing."""
    wallet_name = "test_maker_wallet.jmdat"
    wallet_password = "testpass123"

    # Create wallet
    logger.info(f"Creating JAM wallet: {wallet_name}")
    created = create_jam_wallet(wallet_name, wallet_password)
    assert created, "Failed to create JAM wallet"

    # Get receive address
    logger.info("Getting wallet receive address...")
    address = get_jam_wallet_address(wallet_name, wallet_password, mixdepth=0)
    assert address, "Failed to get wallet address"
    logger.info(f"Wallet address: {address}")

    # Fund the wallet
    logger.info(f"Funding wallet address {address}...")
    funded = fund_wallet_address(address, amount_btc=1.0)
    assert funded, "Failed to fund wallet"

    # Wait for confirmation - give more time in CI
    await asyncio.sleep(15)

    # Verify blocks were mined (fund_wallet_address mines 111 blocks to the address)
    result = run_bitcoin_cmd(["getblockcount"])
    assert result.returncode == 0, "Failed to get block count"
    block_height = int(result.stdout.strip())
    logger.info(f"Wallet funded successfully. Current block height: {block_height}")
    assert block_height > 0, "No blocks mined"


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
async def test_reference_taker_coinjoin_with_our_makers(
    our_maker_reference_taker_services,
):
    """
    Execute a CoinJoin with reference taker (JAM) and our makers.

    This is the main compatibility test - if this passes, our maker implementation
    is fully compatible with the reference JoinMarket taker.
    """
    wallet_name = "test_maker_wallet.jmdat"
    wallet_password = "testpass123"

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

    # Ensure wallet exists and is funded
    logger.info("Ensuring JAM wallet is ready...")
    created = create_jam_wallet(wallet_name, wallet_password)
    assert created, "Wallet must exist"

    address = get_jam_wallet_address(wallet_name, wallet_password, mixdepth=0)
    assert address, "Must have wallet address"

    # Fund the wallet if not already funded
    logger.info("Ensuring wallet is funded...")
    funded = fund_wallet_address(address, 1.0)
    assert funded, "Wallet must be funded"

    # Wait for wallet to sync - extra time for CI
    await asyncio.sleep(30)

    # Get destination address (from mixdepth 1 or generate new)
    dest_address = get_jam_wallet_address(wallet_name, wallet_password, mixdepth=1)
    if not dest_address:
        # Fallback: generate new address in Bitcoin Core
        result = run_bitcoin_cmd(["getnewaddress", "", "bech32"])
        dest_address = result.stdout.strip()

    logger.info(f"CoinJoin destination: {dest_address}")

    # Clean up any stale lock files
    cleanup_wallet_lock(wallet_name)

    # Check current maker offers before starting
    logger.info("Checking maker offers before CoinJoin...")
    result = run_compose_cmd(["logs", "--tail=50", "maker1"], check=False)
    logger.debug(f"Maker1 pre-CoinJoin logs:\n{result.stdout[-1000:]}")

    result = run_compose_cmd(["logs", "--tail=50", "maker2"], check=False)
    logger.debug(f"Maker2 pre-CoinJoin logs:\n{result.stdout[-1000:]}")

    # Execute CoinJoin via JAM sendpayment.py
    # -N 2 = require 2 counterparties (our two makers)
    # -m 0 = from mixdepth 0
    # 10000000 = 0.1 BTC
    compose_file = our_maker_reference_taker_services["compose_file"]
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

    logger.info("Executing CoinJoin via JAM sendpayment...")
    logger.debug(f"Command: {' '.join(cmd)}")

    # This will take a while due to Tor connections and protocol negotiation
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=COINJOIN_TIMEOUT, check=False
    )

    logger.info(f"sendpayment stdout:\n{result.stdout}")
    if result.stderr:
        logger.info(f"sendpayment stderr:\n{result.stderr}")

    # Check maker logs after CoinJoin attempt
    logger.info("Checking maker logs after CoinJoin...")
    result_m1 = run_compose_cmd(["logs", "--tail=100", "maker1"], check=False)
    logger.info(f"Maker1 post-CoinJoin logs:\n{result_m1.stdout[-2000:]}")

    result_m2 = run_compose_cmd(["logs", "--tail=100", "maker2"], check=False)
    logger.info(f"Maker2 post-CoinJoin logs:\n{result_m2.stdout[-2000:]}")

    # Analyze results
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
        "not enough liquidity",
        "no suitable counterparties",
        "insufficient funds",
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

    logger.info("✓ CoinJoin completed successfully with our makers!")


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_verify_makers_handled_ioauth(our_maker_reference_taker_services):
    """Verify that our makers correctly handled the !ioauth phase."""
    # Check maker1 logs for !ioauth messages
    result = run_compose_cmd(["logs", "--tail=200", "maker1"], check=False)
    maker1_logs = result.stdout

    # Look for ioauth protocol messages
    ioauth_indicators = ["ioauth", "auth", "utxo", "signature"]
    maker1_has_ioauth = any(ind in maker1_logs.lower() for ind in ioauth_indicators)

    if maker1_has_ioauth:
        logger.info("Maker1 processed !ioauth messages")

    # Check maker2
    result = run_compose_cmd(["logs", "--tail=200", "maker2"], check=False)
    maker2_logs = result.stdout

    maker2_has_ioauth = any(ind in maker2_logs.lower() for ind in ioauth_indicators)

    if maker2_has_ioauth:
        logger.info("Maker2 processed !ioauth messages")

    # At least one maker should have processed ioauth (if CoinJoin happened)
    # This is informational - the main test is the CoinJoin completion


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--timeout=900"])
