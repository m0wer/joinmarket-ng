#!/usr/bin/env python3
"""
Measure response delay distribution for !orderbook requests.

This script connects to a directory server, sends !orderbook requests,
and measures the timing of offer responses to determine an optimal timeout.
"""

from __future__ import annotations

import asyncio
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

# Add jmcore to path
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))

from jmcore.crypto import NickIdentity
from jmcore.directory_client import DirectoryClient
from jmcore.protocol import COMMAND_PREFIX, JM_VERSION, MessageType
from loguru import logger


async def measure_response_delays(
    host: str,
    port: int,
    network: str = "mainnet",
    num_trials: int = 5,
    max_listen_time: float = 60.0,
) -> dict[str, Any]:
    """
    Measure response delay distribution for orderbook requests.

    Args:
        host: Directory server host (onion address)
        port: Directory server port
        network: Bitcoin network (mainnet, testnet, signet, regtest)
        num_trials: Number of trials to run
        max_listen_time: Maximum time to listen for responses per trial

    Returns:
        Dictionary with statistics about response delays
    """
    logger.info(f"Measuring orderbook response delays from {host}:{port}")
    logger.info(f"Running {num_trials} trials, max listen time: {max_listen_time}s")

    all_delays: list[float] = []
    trial_results: list[dict] = []

    for trial in range(num_trials):
        logger.info(f"\n=== Trial {trial + 1}/{num_trials} ===")

        # Create a unique nick identity for this trial
        nick_identity = NickIdentity(JM_VERSION)
        nick = nick_identity.nick

        # Connect to directory
        client = DirectoryClient(
            host=host,
            port=port,
            network=network,
            nick_identity=nick_identity,
        )

        try:
            await client.connect()
            logger.info(f"Connected as {nick}")

            # Send !orderbook request
            if not client.connection:
                raise RuntimeError("No connection")

            pubmsg = {
                "type": MessageType.PUBMSG.value,
                "line": f"{nick}!PUBLIC!!orderbook",
            }

            start_time = time.perf_counter()
            await client.connection.send(json.dumps(pubmsg).encode("utf-8"))
            logger.info("Sent !orderbook request")

            # Collect messages with timestamps
            messages_with_timing: list[tuple[float, dict]] = []
            end_time = start_time + max_listen_time

            while time.perf_counter() < end_time:
                remaining = end_time - time.perf_counter()
                if remaining <= 0:
                    break

                try:
                    # Read one message at a time to get precise timing
                    raw = await asyncio.wait_for(
                        client.connection.receive(), timeout=remaining
                    )
                    recv_time = time.perf_counter()
                    delay = recv_time - start_time

                    try:
                        msg = json.loads(raw.decode("utf-8"))
                        messages_with_timing.append((delay, msg))
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        logger.debug(f"Failed to parse message: {e}")
                        continue

                except asyncio.TimeoutError:
                    break
                except Exception as e:
                    logger.warning(f"Error receiving message: {e}")
                    break

            # Parse offer responses and extract delays
            offer_delays: list[float] = []
            offer_count = 0

            for delay, msg in messages_with_timing:
                try:
                    msg_type = msg.get("type")
                    if msg_type not in (
                        MessageType.PUBMSG.value,
                        MessageType.PRIVMSG.value,
                    ):
                        continue

                    line = msg.get("line", "")
                    parts = line.split(COMMAND_PREFIX)
                    if len(parts) < 3:
                        continue

                    rest = COMMAND_PREFIX.join(parts[2:])
                    offer_types = [
                        "sw0absoffer",
                        "sw0reloffer",
                        "swabsoffer",
                        "swreloffer",
                    ]

                    for offer_type in offer_types:
                        if rest.startswith(offer_type):
                            offer_delays.append(delay)
                            offer_count += 1
                            all_delays.append(delay)
                            break

                except Exception as e:
                    logger.debug(f"Error parsing message: {e}")
                    continue

            # Calculate statistics for this trial
            if offer_delays:
                trial_stats = {
                    "trial": trial + 1,
                    "offer_count": offer_count,
                    "min_delay": min(offer_delays),
                    "max_delay": max(offer_delays),
                    "mean_delay": statistics.mean(offer_delays),
                    "median_delay": statistics.median(offer_delays),
                    "p95_delay": (
                        statistics.quantiles(offer_delays, n=20)[18]
                        if len(offer_delays) >= 20
                        else max(offer_delays)
                    ),
                    "p99_delay": (
                        statistics.quantiles(offer_delays, n=100)[98]
                        if len(offer_delays) >= 100
                        else max(offer_delays)
                    ),
                }
                trial_results.append(trial_stats)

                logger.info(f"Trial {trial + 1} results:")
                logger.info(f"  Offers received: {offer_count}")
                logger.info(f"  Min delay: {trial_stats['min_delay']:.3f}s")
                logger.info(f"  Max delay: {trial_stats['max_delay']:.3f}s")
                logger.info(f"  Mean delay: {trial_stats['mean_delay']:.3f}s")
                logger.info(f"  Median delay: {trial_stats['median_delay']:.3f}s")
                logger.info(f"  95th percentile: {trial_stats['p95_delay']:.3f}s")
                logger.info(f"  99th percentile: {trial_stats['p99_delay']:.3f}s")
            else:
                logger.warning(f"Trial {trial + 1}: No offers received")

        except Exception as e:
            logger.error(f"Trial {trial + 1} failed: {e}")
        finally:
            try:
                await client.close()
            except Exception:
                pass

        # Wait a bit between trials
        if trial < num_trials - 1:
            await asyncio.sleep(2)

    # Calculate overall statistics
    if all_delays:
        overall_stats = {
            "total_offers": len(all_delays),
            "num_trials": num_trials,
            "min_delay": min(all_delays),
            "max_delay": max(all_delays),
            "mean_delay": statistics.mean(all_delays),
            "median_delay": statistics.median(all_delays),
            "stddev_delay": statistics.stdev(all_delays) if len(all_delays) > 1 else 0,
            "p50_delay": statistics.median(all_delays),
            "p75_delay": (
                statistics.quantiles(all_delays, n=4)[2]
                if len(all_delays) >= 4
                else max(all_delays)
            ),
            "p90_delay": (
                statistics.quantiles(all_delays, n=10)[8]
                if len(all_delays) >= 10
                else max(all_delays)
            ),
            "p95_delay": (
                statistics.quantiles(all_delays, n=20)[18]
                if len(all_delays) >= 20
                else max(all_delays)
            ),
            "p99_delay": (
                statistics.quantiles(all_delays, n=100)[98]
                if len(all_delays) >= 100
                else max(all_delays)
            ),
            "trial_results": trial_results,
        }

        logger.info("\n=== Overall Statistics ===")
        logger.info(f"Total offers collected: {overall_stats['total_offers']}")
        logger.info(f"Min delay: {overall_stats['min_delay']:.3f}s")
        logger.info(f"Max delay: {overall_stats['max_delay']:.3f}s")
        logger.info(
            f"Mean delay: {overall_stats['mean_delay']:.3f}s ± {overall_stats['stddev_delay']:.3f}s"
        )
        logger.info(f"Median delay: {overall_stats['median_delay']:.3f}s")
        logger.info(f"75th percentile: {overall_stats['p75_delay']:.3f}s")
        logger.info(f"90th percentile: {overall_stats['p90_delay']:.3f}s")
        logger.info(f"95th percentile: {overall_stats['p95_delay']:.3f}s")
        logger.info(f"99th percentile: {overall_stats['p99_delay']:.3f}s")

        # Recommendation
        p95_delay = overall_stats["p95_delay"]
        assert isinstance(p95_delay, (int, float))
        recommended_timeout = p95_delay * 1.2  # Add 20% buffer
        logger.info("\n=== Recommendation ===")
        logger.info(
            f"Recommended timeout (95th percentile + 20%): {recommended_timeout:.1f}s"
        )
        logger.info("Current timeout: 120.0s")
        if recommended_timeout > 120.0:
            logger.warning(
                f"Current timeout is too short! Missing ~{100 - 95:.0f}% of offers"
            )
        else:
            logger.info("Current timeout is sufficient for 95th percentile")

        return overall_stats
    else:
        logger.error("No offers received in any trial")
        return {}


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Measure orderbook response delays")
    parser.add_argument(
        "--host",
        default="jmarketxf5wc4aldf3slm5u6726zsky52bqnfv6qyxe5hnafgly6yuyd.onion",
        help="Directory server host (default: JoinMarket onion)",
    )
    parser.add_argument("--port", type=int, default=5222, help="Directory server port")
    parser.add_argument(
        "--network", default="mainnet", help="Bitcoin network (default: mainnet)"
    )
    parser.add_argument(
        "--trials", type=int, default=5, help="Number of trials to run (default: 5)"
    )
    parser.add_argument(
        "--max-time",
        type=float,
        default=60.0,
        help="Max listen time per trial in seconds (default: 60)",
    )

    args = parser.parse_args()

    await measure_response_delays(
        host=args.host,
        port=args.port,
        network=args.network,
        num_trials=args.trials,
        max_listen_time=args.max_time,
    )


if __name__ == "__main__":
    asyncio.run(main())
