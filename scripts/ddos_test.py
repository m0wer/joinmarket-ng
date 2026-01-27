#!/usr/bin/env python3
"""
DDoS Test - Test Tor PoW defense by establishing many new circuits.

Unlike the DoS test (which sends many requests on the same connection),
this test establishes many NEW connections, each requiring a new Tor circuit.
This exercises Tor's PoW defense which works at the circuit level.

The key difference:
- DoS (dos_test.py): Floods requests on existing connections -> tests app rate limiting
- DDoS (this): Floods new connections -> tests Tor PoW circuit-level defense

Usage:
    python scripts/ddos_test.py --onion <address:port> --rate <conn/sec> --duration <seconds>

Example:
    # Establish 5 new connections per second for 30 seconds
    python scripts/ddos_test.py --onion 4rf2pk2bjusjcqfp7rr3bw5yuyjtbiv3tgbvwl423435dfwp2ynv56ad.onion:5222 --rate 5 --duration 30
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Add jmcore to path
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))

from jmcore.crypto import NickIdentity
from jmcore.network import connect_via_tor
from jmcore.protocol import MessageType


@dataclass
class DDoSStats:
    """Statistics for DDoS test."""

    connection_attempts: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    handshakes_completed: int = 0
    orderbook_responses: int = 0
    connection_times: list[float] = field(default_factory=list)
    start_time: float = 0.0

    def avg_connection_time(self) -> float:
        if self.connection_times:
            return sum(self.connection_times) / len(self.connection_times) * 1000
        return 0.0

    def connection_rate(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.connection_attempts / elapsed
        return 0.0


async def establish_single_connection(
    onion_address: str,
    port: int,
    stats: DDoSStats,
    socks_host: str,
    socks_port: int,
    conn_id: int,
) -> None:
    """
    Establish a single new connection to the hidden service.

    This creates a new Tor circuit, exercising Tor's PoW defense.
    """
    stats.connection_attempts += 1
    connect_start = time.time()

    try:
        # This creates a NEW Tor circuit
        conn = await asyncio.wait_for(
            connect_via_tor(
                onion_address=onion_address,
                port=port,
                socks_host=socks_host,
                socks_port=socks_port,
                max_message_size=2097152,
                timeout=60.0,  # Longer timeout for PoW solving
            ),
            timeout=90.0,  # Even longer for overall attempt
        )

        connect_time = time.time() - connect_start
        stats.connection_times.append(connect_time)
        stats.successful_connections += 1

        # Create identity
        nick_identity = NickIdentity()
        our_nick = nick_identity.nick

        # Send handshake
        handshake = {
            "type": MessageType.HANDSHAKE.value,
            "line": json.dumps(
                {
                    "app-name": "joinmarket",
                    "directory": False,
                    "location-string": "NOT-SERVING-ONION",
                    "proto-ver": 5,
                    "features": {},
                    "nick": our_nick,
                    "network": "mainnet",
                }
            ),
        }
        await conn.send(json.dumps(handshake).encode())

        # Wait for handshake response
        try:
            data = await asyncio.wait_for(conn.receive(), timeout=10.0)
            if data:
                stats.handshakes_completed += 1

                # Send orderbook request
                orderbook_msg = {
                    "type": MessageType.PUBMSG.value,
                    "line": f"{our_nick}!PUBLIC!!orderbook",
                }
                await conn.send(json.dumps(orderbook_msg).encode())

                # Wait for response
                try:
                    data = await asyncio.wait_for(conn.receive(), timeout=5.0)
                    if data:
                        msg = json.loads(data.decode())
                        if "sw0reloffer" in msg.get(
                            "line", ""
                        ) or "sw0absoffer" in msg.get("line", ""):
                            stats.orderbook_responses += 1
                except asyncio.TimeoutError:
                    pass  # Rate limited

        except asyncio.TimeoutError:
            pass

        await conn.close()

        # Log progress
        if stats.successful_connections % 10 == 0:
            print(
                f"[Conn {conn_id}] Connected in {connect_time * 1000:.0f}ms "
                f"(total: {stats.successful_connections} success, {stats.failed_connections} failed)"
            )

    except asyncio.TimeoutError:
        stats.failed_connections += 1
        elapsed = time.time() - connect_start
        if stats.failed_connections % 5 == 1:
            print(
                f"[Conn {conn_id}] TIMEOUT after {elapsed:.1f}s "
                f"(may indicate Tor PoW is increasing difficulty)"
            )
    except Exception as e:
        stats.failed_connections += 1
        error_msg = str(e)
        if "Circuit" in error_msg or "closed" in error_msg.lower():
            # Circuit failed - could be due to PoW
            if stats.failed_connections % 5 == 1:
                print(f"[Conn {conn_id}] Circuit failed: {error_msg[:50]}")
        else:
            print(f"[Conn {conn_id}] Error: {error_msg[:80]}")


async def run_ddos_test(
    onion_address: str,
    port: int,
    connection_rate: float,
    duration: float,
    socks_host: str,
    socks_port: int,
) -> DDoSStats:
    """Run DDoS test against a hidden service."""
    print(f"\n{'=' * 70}")
    print("DDoS Test (Tor PoW Defense)")
    print(f"{'=' * 70}")
    print(f"Target: {onion_address}:{port}")
    print(f"Connection rate: {connection_rate}/sec")
    print(f"Duration: {duration}s")
    print(f"Expected total connections: ~{int(connection_rate * duration)}")
    print()
    print("This test establishes NEW connections (new Tor circuits).")
    print("If Tor PoW is active, you should see:")
    print("  - Connection times increasing")
    print("  - Timeouts as PoW difficulty increases")
    print(f"{'=' * 70}\n")

    stats = DDoSStats()
    stats.start_time = time.time()

    interval = 1.0 / connection_rate if connection_rate > 0 else 0.1
    conn_id = 0
    tasks: set[asyncio.Task] = set()

    while time.time() - stats.start_time < duration:
        # Launch new connection
        task = asyncio.create_task(
            establish_single_connection(
                onion_address=onion_address,
                port=port,
                stats=stats,
                socks_host=socks_host,
                socks_port=socks_port,
                conn_id=conn_id,
            )
        )
        tasks.add(task)
        task.add_done_callback(tasks.discard)

        conn_id += 1

        # Rate limiting
        await asyncio.sleep(interval)

        # Periodic status
        elapsed = time.time() - stats.start_time
        if int(elapsed) % 10 == 0 and int(elapsed) > 0:
            print(
                f"\n[{elapsed:.0f}s] Status: "
                f"attempts={stats.connection_attempts}, "
                f"success={stats.successful_connections}, "
                f"failed={stats.failed_connections}, "
                f"avg_time={stats.avg_connection_time():.0f}ms"
            )

    # Wait for remaining tasks
    print("\nWaiting for pending connections...")
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return stats


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="DDoS Test - Tests Tor PoW defense by establishing many new circuits",
    )
    parser.add_argument(
        "--onion",
        required=True,
        help="Target onion:port (e.g., abc123.onion:5222)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=2.0,
        help="New connections per second (default: 2)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Test duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--socks-host",
        default="127.0.0.1",
        help="Tor SOCKS proxy host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=9050,
        help="Tor SOCKS proxy port (default: 9050)",
    )

    args = parser.parse_args()

    # Parse onion address
    if ":" in args.onion:
        onion_address, port_str = args.onion.rsplit(":", 1)
        port = int(port_str)
    else:
        onion_address = args.onion
        port = 5222

    if not onion_address.endswith(".onion"):
        onion_address = onion_address + ".onion"

    print("\nStarting DDoS test in 3 seconds...")
    print("Press Ctrl+C to stop early\n")
    await asyncio.sleep(3)

    try:
        stats = await run_ddos_test(
            onion_address=onion_address,
            port=port,
            connection_rate=args.rate,
            duration=args.duration,
            socks_host=args.socks_host,
            socks_port=args.socks_port,
        )

        # Final report
        elapsed = time.time() - stats.start_time
        print(f"\n{'=' * 70}")
        print("FINAL RESULTS")
        print(f"{'=' * 70}")
        print(f"Test duration:           {elapsed:.1f}s")
        print(f"Connection attempts:     {stats.connection_attempts}")
        print(f"Successful connections:  {stats.successful_connections}")
        print(f"Failed connections:      {stats.failed_connections}")
        print(f"Handshakes completed:    {stats.handshakes_completed}")
        print(f"Orderbook responses:     {stats.orderbook_responses}")
        print(f"Avg connection time:     {stats.avg_connection_time():.0f}ms")
        print(f"Actual connection rate:  {stats.connection_rate():.2f}/sec")
        print(
            f"Success rate:            {stats.successful_connections / max(1, stats.connection_attempts) * 100:.1f}%"
        )
        print(f"{'=' * 70}")

        if stats.failed_connections > stats.successful_connections:
            print("\nHigh failure rate detected!")
            print("This could indicate Tor PoW is increasing difficulty.")
            print("Check the Tor logs on the hidden service for PoW activity.")

        if stats.avg_connection_time() > 5000:
            print("\nHigh average connection time detected!")
            print("This could indicate clients are solving PoW challenges.")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")


if __name__ == "__main__":
    asyncio.run(main())
