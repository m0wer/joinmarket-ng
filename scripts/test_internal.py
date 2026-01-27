#!/usr/bin/env python3
"""Test direct !orderbook by connecting to maker via TCP."""

import asyncio
import json


async def test_direct_orderbook():
    from jmcore.network import TCPConnection
    from jmcore.protocol import MessageType
    from jmcore.crypto import NickIdentity

    print("Connecting to maker on localhost:5000...")

    reader, writer = await asyncio.open_connection("127.0.0.1", 5000)
    conn = TCPConnection(reader, writer)

    # Create identity
    nick_identity = NickIdentity()
    our_nick = nick_identity.nick
    print(f"Our nick: {our_nick}")

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
    print("Sending handshake...")
    await conn.send(json.dumps(handshake).encode())

    # Wait for handshake response
    data = await asyncio.wait_for(conn.receive(), timeout=10.0)
    msg = json.loads(data.decode())
    msg_type = msg.get("type")
    print(f"Handshake response type: {msg_type}")

    # Send !orderbook
    orderbook_msg = {
        "type": MessageType.PUBMSG.value,
        "line": f"{our_nick}!PUBLIC!orderbook",
    }
    print(f"\nSending !orderbook: {orderbook_msg}")
    await conn.send(json.dumps(orderbook_msg).encode())

    # Wait for response
    print("\nWaiting for response...")
    try:
        data = await asyncio.wait_for(conn.receive(), timeout=5.0)
        msg = json.loads(data.decode())
        print("\nResponse received!")
        resp_type = msg.get("type")
        print(f"Type: {resp_type}")
        line = msg.get("line", "")
        if len(line) > 150:
            print(f"Line: {line[:150]}...")
        else:
            print(f"Line: {line}")

        if "sw0reloffer" in line or "swreloffer" in line:
            print("\n>>> SUCCESS: Received offer response via direct connection! <<<")
        else:
            print("\nUnexpected response content")

    except asyncio.TimeoutError:
        print("\n>>> FAILURE: Timeout waiting for response <<<")

    await conn.close()
    print("\nTest completed.")


if __name__ == "__main__":
    asyncio.run(test_direct_orderbook())
