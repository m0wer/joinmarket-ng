#!/usr/bin/env python3
"""
Test rate limiting by flooding the maker with !orderbook requests.
This runs inside the Docker container to test without Tor latency.
"""

import asyncio
import json
import time
from dataclasses import dataclass


@dataclass
class TestResult:
    requests_sent: int = 0
    responses_received: int = 0
    rate_limited: int = 0
    banned: bool = False
    errors: int = 0


async def test_rate_limiting(
    rps: float = 2.0,
    duration: float = 20.0,
) -> TestResult:
    """Send rapid !orderbook requests and track responses."""
    from jmcore.crypto import NickIdentity
    from jmcore.network import TCPConnection
    from jmcore.protocol import MessageType

    result = TestResult()
    request_interval = 1.0 / rps if rps > 0 else 0

    print("\nRate Limit Test Configuration:")
    print(f"  Target RPS: {rps}")
    print(f"  Duration: {duration}s")
    print("  Expected: Rate limiting after 1st request (30s interval)")
    print("  Expected: Ban after 10 violations")
    print("=" * 60)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 5000)
        conn = TCPConnection(reader, writer)

        # Create identity
        nick_identity = NickIdentity()
        our_nick = nick_identity.nick
        print(f"Connected as: {our_nick}")

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
                    "network": "testnet",
                }
            ),
        }
        await conn.send(json.dumps(handshake).encode())

        # Wait for handshake response
        data = await asyncio.wait_for(conn.receive(), timeout=10.0)
        msg = json.loads(data.decode())
        print(f"Handshake OK (type: {msg.get('type')})")

        start_time = time.time()
        last_report = start_time

        while time.time() - start_time < duration:
            request_start = time.time()

            # Send !orderbook
            orderbook_msg = {
                "type": MessageType.PUBMSG.value,
                "line": f"{our_nick}!PUBLIC!!orderbook",
            }

            try:
                await conn.send(json.dumps(orderbook_msg).encode())
                result.requests_sent += 1
            except Exception as e:
                if "closed" in str(e).lower():
                    print(
                        f"\n[{time.time() - start_time:.1f}s] Connection closed by maker (BANNED!)"
                    )
                    result.banned = True
                    break
                raise

            # Try to receive response
            try:
                data = await asyncio.wait_for(conn.receive(), timeout=0.5)
                if data:
                    msg = json.loads(data.decode())
                    line = msg.get("line", "")

                    if "sw0reloffer" in line or "swreloffer" in line:
                        result.responses_received += 1
                    elif "rate" in line.lower() or "limit" in line.lower():
                        result.rate_limited += 1
                        print(
                            f"\n[{time.time() - start_time:.1f}s] Rate limited: {line[:80]}"
                        )
            except asyncio.TimeoutError:
                pass  # No response (rate limited silently)
            except Exception as e:
                if "closed" in str(e).lower():
                    print(
                        f"\n[{time.time() - start_time:.1f}s] Connection closed (BANNED!)"
                    )
                    result.banned = True
                    break
                result.errors += 1

            # Progress report every 2 seconds
            if time.time() - last_report >= 2.0:
                elapsed = time.time() - start_time
                actual_rps = result.requests_sent / elapsed if elapsed > 0 else 0
                print(
                    f"[{elapsed:5.1f}s] Sent: {result.requests_sent:3d} | "
                    f"Resp: {result.responses_received:3d} | "
                    f"RPS: {actual_rps:.1f}"
                )
                last_report = time.time()

            # Rate limiting
            if request_interval > 0:
                elapsed = time.time() - request_start
                if elapsed < request_interval:
                    await asyncio.sleep(request_interval - elapsed)

        await conn.close()

    except ConnectionRefusedError:
        print("Connection refused - maker may have banned us")
        result.banned = True
    except Exception as e:
        print(f"Error: {e}")
        result.errors += 1

    return result


async def main() -> None:
    import sys

    rps = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    result = await test_rate_limiting(rps=rps, duration=duration)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Requests sent:     {result.requests_sent}")
    print(f"Responses (offer): {result.responses_received}")
    print(f"Rate limited:      {result.rate_limited}")
    print(f"Errors:            {result.errors}")
    print(f"Banned:            {result.banned}")

    # Expected behavior:
    # - First request should get a response
    # - Subsequent requests within 30s should be silently dropped (rate limited)
    # - After 10 violations, connection should be closed (banned)
    print("\n" + "=" * 60)
    print("ANALYSIS")
    print("=" * 60)

    if result.responses_received == 1:
        print("[OK] First request got response (expected)")
    elif result.responses_received == 0:
        print("[WARN] No responses received - possible issue")
    else:
        print(f"[INFO] Got {result.responses_received} responses")

    if result.banned:
        print("[OK] Connection was banned after violations (expected)")
    elif result.requests_sent > 10:
        print(
            "[WARN] Sent >10 requests but not banned - rate limiter may not be working"
        )

    expected_violations = (
        result.requests_sent - result.responses_received - result.errors
    )
    print(f"[INFO] Estimated violations: {expected_violations}")


if __name__ == "__main__":
    asyncio.run(main())
