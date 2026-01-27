#!/usr/bin/env python3
"""
Test script to verify direct !orderbook requests work.

Tests that connecting directly to a maker's onion and sending !orderbook
results in the maker responding with offers via the same connection.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Add jmcore to path
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))

from jmcore.crypto import NickIdentity
from jmcore.network import connect_via_tor
from jmcore.protocol import MessageType, parse_peerlist_entry


async def extract_onion_from_directory(
    maker_nick: str,
    directory_onion: str = "nakamotourflxwjnjpnrk7yc2nhkf6r62ed4gdfxmmn5f4saw5q5qoyd.onion",
    directory_port: int = 5222,
) -> str | None:
    """Extract maker's onion address from directory peerlist."""
    print(f"Connecting to directory {directory_onion}:{directory_port}...")

    nick_identity = NickIdentity()
    our_nick = nick_identity.nick

    conn = await connect_via_tor(
        onion_address=directory_onion,
        port=directory_port,
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
    print("Sent GETPEERLIST request...")

    # Collect peerlist entries
    maker_location = None
    timeout_count = 0

    while timeout_count < 5:
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
                timeout_count = 0

        except asyncio.TimeoutError:
            timeout_count += 1
            if maker_location:
                break

    await conn.close()
    return maker_location


async def test_direct_orderbook(onion_address: str, port: int) -> None:
    """Test sending !orderbook directly to a maker."""
    print(f"\n{'=' * 70}")
    print(f"Testing direct !orderbook to {onion_address}:{port}")
    print(f"{'=' * 70}\n")

    nick_identity = NickIdentity()
    our_nick = nick_identity.nick
    print(f"Our nick: {our_nick}")

    # Connect to maker
    print("Connecting to maker...")
    conn = await connect_via_tor(
        onion_address=onion_address,
        port=port,
        max_message_size=2097152,
        timeout=60.0,
    )
    print("Connected!")

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
    print("Sending handshake...")
    await conn.send(json.dumps(handshake).encode())

    # Wait for handshake response
    valid_handshake_types = (
        MessageType.HANDSHAKE.value,
        MessageType.DN_HANDSHAKE.value,
    )
    try:
        data = await asyncio.wait_for(conn.receive(), timeout=10.0)
        if data:
            msg = json.loads(data.decode())
            msg_type = msg.get("type")
            if msg_type in valid_handshake_types:
                print(f"Handshake successful! Response type: {msg_type}")
                line_data = json.loads(msg.get("line", "{}"))
                print(f"  Maker nick: {line_data.get('nick')}")
                print(f"  MOTD: {line_data.get('motd', 'N/A')}")
            else:
                print(f"Unexpected handshake response type: {msg_type}")
                print(f"Response: {msg}")
                return
        else:
            print("Empty handshake response")
            return
    except asyncio.TimeoutError:
        print("Handshake timeout!")
        return

    # Send !orderbook request
    orderbook_msg = {
        "type": MessageType.PUBMSG.value,
        "line": f"{our_nick}!PUBLIC!orderbook",
    }
    print("\nSending !orderbook request...")
    print(f"  Message: {orderbook_msg}")
    await conn.send(json.dumps(orderbook_msg).encode())

    # Wait for response(s)
    print("\nWaiting for response...")
    response_count = 0
    timeout_count = 0
    max_timeouts = 3

    while timeout_count < max_timeouts:
        try:
            data = await asyncio.wait_for(conn.receive(), timeout=5.0)
            if data:
                response_count += 1
                msg = json.loads(data.decode())
                msg_type = msg.get("type")
                line = msg.get("line", "")

                print(f"\n[Response {response_count}]")
                print(f"  Type: {msg_type}")
                if len(line) > 200:
                    print(f"  Line: {line[:200]}...")
                else:
                    print(f"  Line: {line}")

                # Check for offer types
                if (
                    "sw0reloffer" in line
                    or "swreloffer" in line
                    or "sw0absoffer" in line
                ):
                    print("  --> This is an OFFER response!")

                # Reset timeout counter on valid response
                timeout_count = 0

        except asyncio.TimeoutError:
            timeout_count += 1
            print(f"  (timeout {timeout_count}/{max_timeouts})")

    await conn.close()

    print(f"\n{'=' * 70}")
    print(f"RESULT: Received {response_count} response(s)")
    if response_count > 0:
        print("SUCCESS: Maker responded to direct !orderbook request!")
    else:
        print("FAILURE: No response received from maker")
    print(f"{'=' * 70}")


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Test direct !orderbook requests")
    parser.add_argument("nick", nargs="?", help="Maker nick to test")
    parser.add_argument("--onion", help="Direct onion:port to test")
    args = parser.parse_args()

    if not args.nick and not args.onion:
        parser.error("Either nick or --onion must be provided")

    if args.onion:
        if ":" in args.onion:
            onion_address, port_str = args.onion.rsplit(":", 1)
            port = int(port_str)
        else:
            onion_address = args.onion
            port = 5222
        if not onion_address.endswith(".onion"):
            onion_address = onion_address + ".onion"
    else:
        location = await extract_onion_from_directory(args.nick)
        if not location:
            print(f"Could not find {args.nick} in directory")
            sys.exit(1)
        if location == "NOT-SERVING-ONION":
            print(f"{args.nick} is not serving via onion")
            sys.exit(1)

        if ":" in location:
            onion_address, port_str = location.rsplit(":", 1)
            port = int(port_str)
        else:
            onion_address = location
            port = 5222
        if not onion_address.endswith(".onion"):
            onion_address = onion_address + ".onion"

    await test_direct_orderbook(onion_address, port)


if __name__ == "__main__":
    asyncio.run(main())
