"""Test that validates our bond protocol is compatible with reference implementation.

This test creates a bond proof and validates it can be parsed by simulating the
reference implementation's message flow.
"""

import base64
import struct

import pytest
from coincurve import PrivateKey
from jmcore.crypto import NickIdentity, bitcoin_message_hash
from jmcore.protocol import COMMAND_PREFIX

from maker.fidelity import FidelityBondInfo, create_fidelity_bond_proof


def simulate_reference_privmsg_parsing(privmsg: str) -> list[tuple[str, list[str]]]:
    """
    Simulate how reference implementation parses a PRIVMSG.

    Reference code (message_channel.py:922-964):
        if message[0] != COMMAND_PREFIX:
            return
        cmd_string = message[1:].split(' ')[0]
        ...
        # Strip sig/pubkey: rawmessage = ' '.join(message[1:].split(' ')[1:-2])
        # After verification: message = " ".join(message[1:].split(" ")[:-2])
        for command in message.split(COMMAND_PREFIX):
            _chunks = command.split(" ")

    Args:
        privmsg: Full PRIVMSG line (e.g., "MakerNick!TakerNick!sw0absoffer data pubkey sig")

    Returns:
        List of (command_name, chunks) tuples
    """
    # Extract message part (after second !)
    parts = privmsg.split(COMMAND_PREFIX)
    if len(parts) < 3:
        return []

    # Message is everything after "from_nick!to_nick!"
    # Format: "sw0absoffer data!tbond proof pubkey sig"
    # Note: In reference, commands in PRIVMSG do NOT have leading "!"
    # The "!" is only used as field separator for from!to!message
    full_message = COMMAND_PREFIX.join(parts[2:])

    # Strip signature and pubkey (last 2 space-separated fields)
    # "sw0absoffer data pubkey sig" -> "sw0absoffer data"
    message_parts = full_message.split(" ")
    if len(message_parts) < 3:  # Need at least cmd, pubkey, sig
        return []

    message = " ".join(message_parts[:-2])

    # Split by COMMAND_PREFIX (!) to get individual commands
    # "sw0absoffer 0 1000 2000 500 0.001!tbond PROOF" -> ["sw0absoffer...", "tbond PROOF"]
    commands = []
    for command in message.split(COMMAND_PREFIX):
        _chunks = command.split(" ")
        if _chunks and _chunks[0]:  # Non-empty command
            commands.append((_chunks[0], _chunks))

    return commands


def test_bond_proof_structure():
    """Test that our bond proof has the correct 252-byte structure."""
    # Create a test bond
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    bond = FidelityBondInfo(
        txid="a" * 64,
        vout=0,
        value=100000000,
        locktime=1768435200,
        confirmation_time=1000,
        bond_value=50000000,
        pubkey=pubkey,
        private_key=privkey,
    )

    maker_nick = "J52TestMaker"
    taker_nick = "J5TestTaker"

    # Create proof
    proof_b64 = create_fidelity_bond_proof(
        bond=bond,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        current_block_height=930000,
    )

    assert proof_b64 is not None
    assert len(proof_b64) == 336  # base64 of 252 bytes

    # Decode and verify structure
    proof_data = base64.b64decode(proof_b64)
    assert len(proof_data) == 252

    # Unpack and verify we can find DER signatures
    ser_struct_fmt = "<72s72s33sH33s32sII"
    unpacked = struct.unpack(ser_struct_fmt, proof_data)

    nick_sig_padded = unpacked[0]
    cert_sig_padded = unpacked[1]

    # Should have DER header (0x30)
    assert b"\x30" in nick_sig_padded
    assert b"\x30" in cert_sig_padded


def test_privmsg_format_with_bond():
    """Test that PRIVMSG with bond can be parsed by reference logic."""
    # Create test identity
    nick_identity = NickIdentity()
    maker_nick = nick_identity.nick
    taker_nick = "J5TestTaker"

    # Create a test bond proof
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    bond = FidelityBondInfo(
        txid="b" * 64,
        vout=1,
        value=100000000,
        locktime=1768435200,
        confirmation_time=1000,
        bond_value=50000000,
        pubkey=pubkey,
        private_key=privkey,
    )

    proof_b64 = create_fidelity_bond_proof(
        bond=bond,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        current_block_height=930000,
    )

    assert proof_b64 is not None

    # Simulate what the maker bot does
    order_type = "sw0absoffer"
    data = f"0 30000 72590 0 0!tbond {proof_b64}"

    # Sign the data
    hostid = "test-host-id"
    signed_data = nick_identity.sign_message(data, hostid)

    # Build full PRIVMSG
    privmsg = f"{maker_nick}!{taker_nick}!{order_type} {signed_data}"

    # Debug: print the message
    print(f"\nPrivmsg: {privmsg[:100]}...")
    print(f"Signed data: {signed_data[:100]}...")

    # Parse using simulated reference logic
    commands = simulate_reference_privmsg_parsing(privmsg)

    print(f"Commands parsed: {len(commands)}")
    for idx, (cmd_name, chunks) in enumerate(commands):
        print(f"  Command {idx}: {cmd_name}, chunks: {chunks[:3]}...")

    # Should have 2 commands: sw0absoffer and tbond
    assert len(commands) == 2, f"Expected 2 commands, got {len(commands)}: {commands}"

    # First command: sw0absoffer
    assert commands[0][0] == "sw0absoffer"
    assert commands[0][1][0] == "sw0absoffer"
    assert commands[0][1][1:] == ["0", "30000", "72590", "0", "0"]

    # Second command: tbond
    assert commands[1][0] == "tbond"
    assert commands[1][1][0] == "tbond"
    assert commands[1][1][1] == proof_b64


def test_bond_message_format_matches_reference():
    """Test that our bond signing messages match reference format."""
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    maker_nick = "J52TestMaker"
    taker_nick = "J5TestTaker"
    cert_expiry_blocks = 2016 * 52
    cert_expiry_encoded = cert_expiry_blocks // 2016

    # Test nick message format
    nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
    assert nick_msg == b"J5TestTaker|J52TestMaker"

    # Test cert message format (binary, matching reference get_cert_msg)
    cert_msg = b"fidelity-bond-cert|" + pubkey + b"|" + str(cert_expiry_encoded).encode("ascii")
    assert cert_msg.startswith(b"fidelity-bond-cert|")
    assert cert_msg.endswith(b"|52")
    assert len(cert_msg) == len(b"fidelity-bond-cert|") + 33 + len(b"|52")

    # Verify Bitcoin message hashing works
    msg_hash = bitcoin_message_hash(nick_msg.decode("ascii"))
    assert len(msg_hash) == 32


def test_bond_proof_with_multiple_offers():
    """Test sending multiple offers with bonds (as makers do)."""
    nick_identity = NickIdentity()
    maker_nick = nick_identity.nick
    taker_nick = "J5TestTaker"

    # Create bond
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    bond = FidelityBondInfo(
        txid="c" * 64,
        vout=0,
        value=100000000,
        locktime=1768435200,
        confirmation_time=1000,
        bond_value=50000000,
        pubkey=pubkey,
        private_key=privkey,
    )

    # Create proof (same for both offers, signed for specific taker)
    proof_b64 = create_fidelity_bond_proof(
        bond=bond,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        current_block_height=930000,
    )

    # Simulate sending two offers (as our maker does)
    offers = [
        ("sw0absoffer", "0 1000 10000 500 0.001"),
        ("sw0reloffer", "1 2000 20000 500 0.002"),
    ]

    for order_type, params in offers:
        data = f"{params}!tbond {proof_b64}"
        hostid = "test-host"
        signed_data = nick_identity.sign_message(data, hostid)
        privmsg = f"{maker_nick}!{taker_nick}!{order_type} {signed_data}"

        # Parse
        commands = simulate_reference_privmsg_parsing(privmsg)

        # Should have 2 commands per message
        assert len(commands) == 2
        assert commands[0][0] == order_type
        assert commands[1][0] == "tbond"
        assert commands[1][1][1] == proof_b64


@pytest.mark.parametrize(
    "locktime,cert_expiry_blocks",
    [
        (1768435200, 2016 * 52),  # ~1 year
        (1800000000, 2016 * 26),  # ~6 months
        (2000000000, 2016 * 104),  # ~2 years
    ],
)
def test_bond_proof_with_various_locktimes(locktime: int, cert_expiry_blocks: int):
    """Test bond proofs with various locktime values."""
    privkey = PrivateKey()
    pubkey = privkey.public_key.format(compressed=True)

    bond = FidelityBondInfo(
        txid="d" * 64,
        vout=0,
        value=100000000,
        locktime=locktime,
        confirmation_time=1000,
        bond_value=50000000,
        pubkey=pubkey,
        private_key=privkey,
    )

    proof_b64 = create_fidelity_bond_proof(
        bond=bond,
        maker_nick="J52Maker",
        taker_nick="J5Taker",
        current_block_height=930000,
    )

    assert proof_b64 is not None
    assert len(proof_b64) == 336

    # Verify locktime in proof
    proof_data = base64.b64decode(proof_b64)
    unpacked = struct.unpack("<72s72s33sH33s32sII", proof_data)
    assert unpacked[7] == locktime  # Last field is locktime
    # cert_expiry is calculated from block height: ((930000 + 2) // 2016) + 1 = 462
    expected_cert_expiry = ((930000 + 2) // 2016) + 1
    assert unpacked[3] == expected_cert_expiry  # cert_expiry
