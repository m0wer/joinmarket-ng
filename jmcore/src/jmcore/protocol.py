"""
JoinMarket protocol definitions, message types, and serialization.
"""

from __future__ import annotations

import json
from enum import IntEnum
from typing import Any

from pydantic import BaseModel

JM_VERSION = 5
COMMAND_PREFIX = "!"
NICK_PEERLOCATOR_SEPARATOR = ";"
ONION_VIRTUAL_PORT = 5222
NOT_SERVING_ONION_HOSTNAME = "NOT-SERVING-ONION"


class MessageType(IntEnum):
    PRIVMSG = 685
    PUBMSG = 687
    PEERLIST = 789
    GETPEERLIST = 791
    HANDSHAKE = 793
    DN_HANDSHAKE = 795
    PING = 797
    PONG = 799
    DISCONNECT = 801

    CONNECT = 785
    CONNECT_IN = 797


class ProtocolMessage(BaseModel):
    type: MessageType
    payload: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps({"type": self.type.value, "data": self.payload})

    @classmethod
    def from_json(cls, data: str) -> ProtocolMessage:
        obj = json.loads(data)
        return cls(type=MessageType(obj["type"]), payload=obj["data"])

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> ProtocolMessage:
        return cls.from_json(data.decode("utf-8"))


def create_handshake_request(
    nick: str, location: str, network: str, directory: bool = False
) -> dict[str, Any]:
    return {
        "app-name": "joinmarket",
        "directory": directory,
        "location-string": location,
        "proto-ver": JM_VERSION,
        "features": {},
        "nick": nick,
        "network": network,
    }


def create_handshake_response(
    nick: str, network: str, accepted: bool = True, motd: str = "JoinMarket Directory Server"
) -> dict[str, Any]:
    return {
        "app-name": "joinmarket",
        "directory": True,
        "proto-ver-min": JM_VERSION,
        "proto-ver-max": JM_VERSION,
        "features": {},
        "accepted": accepted,
        "nick": nick,
        "network": network,
        "motd": motd,
    }


def parse_peer_location(location: str) -> tuple[str, int]:
    if location == NOT_SERVING_ONION_HOSTNAME:
        return (location, -1)
    try:
        host, port_str = location.split(":")
        port = int(port_str)
        if port <= 0 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
        return (host, port)
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid location string: {location}") from e


def create_peerlist_entry(nick: str, location: str, disconnected: bool = False) -> str:
    entry = f"{nick}{NICK_PEERLOCATOR_SEPARATOR}{location}"
    if disconnected:
        entry += f"{NICK_PEERLOCATOR_SEPARATOR}D"
    return entry


def parse_peerlist_entry(entry: str) -> tuple[str, str, bool]:
    parts = entry.split(NICK_PEERLOCATOR_SEPARATOR)
    if len(parts) == 2:
        return (parts[0], parts[1], False)
    elif len(parts) == 3 and parts[2] == "D":
        return (parts[0], parts[1], True)
    raise ValueError(f"Invalid peerlist entry: {entry}")


def format_jm_message(from_nick: str, to_nick: str, cmd: str, message: str) -> str:
    return f"{from_nick}{COMMAND_PREFIX}{to_nick}{COMMAND_PREFIX}{cmd} {message}"


def parse_jm_message(msg: str) -> tuple[str, str, str] | None:
    try:
        parts = msg.split(COMMAND_PREFIX)
        if len(parts) < 3:
            return None
        from_nick = parts[0]
        to_nick = parts[1]
        rest = COMMAND_PREFIX.join(parts[2:])
        return (from_nick, to_nick, rest)
    except Exception:
        return None
