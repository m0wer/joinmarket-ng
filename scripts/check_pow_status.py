#!/usr/bin/env python3
"""
Check Tor PoW defense status for a hidden service.

This script connects to a Tor control port and queries:
1. HS descriptor to check for pow-params (PoW configuration advertised)
2. Circuit events to see HS_POW field (PoW effort required by clients)
3. Any PoW-related configuration

Usage:
    python scripts/check_pow_status.py [--control-host HOST] [--control-port PORT]

The script assumes cookie authentication is available.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Add jmcore to path
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))

from jmcore.tor_control import TorControlClient


async def check_pow_status(
    control_host: str = "127.0.0.1",
    control_port: int = 9051,
    cookie_path: str | None = None,
) -> None:
    """Check PoW defense status on the Tor control port."""
    print(f"\n{'=' * 60}")
    print("Tor PoW Defense Status Check")
    print(f"{'=' * 60}")
    print(f"Control port: {control_host}:{control_port}")

    # Resolve cookie path if not provided
    resolved_cookie: Path | None = None
    if cookie_path:
        resolved_cookie = Path(cookie_path)
    else:
        common_paths = [
            Path("/run/tor/control.authcookie"),
            Path("/var/run/tor/control.authcookie"),
            Path("/var/lib/tor/control_auth_cookie"),
            Path.home() / ".tor" / "control_auth_cookie",
        ]
        for path in common_paths:
            if path.exists() and path.stat().st_size > 0:
                resolved_cookie = path
                break

    controller = TorControlClient(
        control_host=control_host,
        control_port=control_port,
        cookie_path=resolved_cookie,
    )

    try:
        await controller.connect()
        print("[OK] Connected to Tor control port")

        await controller.authenticate()
        print(f"[OK] Authenticated (cookie: {resolved_cookie or 'null auth'})")

        # Get Tor version and capabilities
        caps = await controller.get_capabilities()
        print(f"\nTor Version: {caps.version}")
        print(f"  - Intro DoS (torrc): {caps.has_intro_dos}")
        print(f"  - PoW module: {caps.has_pow_module}")
        print(f"  - PoW via ADD_ONION: {caps.has_add_onion_pow}")

        # List our hidden services
        print("\n--- Hidden Services ---")
        try:
            hs_list = await controller.get_info("onions/current")
            if hs_list:
                print(f"Current HS: {hs_list}")
            else:
                print("No ephemeral hidden services on this connection")
        except Exception as e:
            print(f"Could not get HS list: {e}")

        # Try to get HS descriptor for our service
        print("\n--- Checking HS Configuration ---")
        try:
            # Check config/names for PoW options
            config_names = await controller.get_info("config/names")
            pow_options = [
                line for line in config_names.split("\n") if "pow" in line.lower()
            ]
            if pow_options:
                print("PoW-related config options:")
                for opt in pow_options[:10]:
                    print(f"  {opt}")
        except Exception as e:
            print(f"Could not get config names: {e}")

        # Check specific PoW config values (only works for persistent HS in torrc)
        print("\n--- PoW Configuration Values ---")
        print("(Note: GETCONF only works for persistent HS configured in torrc,")
        print(" not for ephemeral HS created via ADD_ONION)")
        pow_configs = [
            "HiddenServicePoWDefensesEnabled",
            "HiddenServicePoWQueueRate",
            "HiddenServicePoWQueueBurst",
        ]
        for config in pow_configs:
            try:
                responses = await controller._command(f"GETCONF {config}")
                for status, _, message in responses:
                    if status == "250" and "=" in message:
                        print(f"  {message}")
            except Exception:
                pass

        # Check circuit events for PoW in action
        print("\n--- Circuit Information ---")
        try:
            circuit_status = await controller.get_info("circuit-status")
            circuits = circuit_status.strip().split("\n") if circuit_status else []
            hs_circuits = [c for c in circuits if "HS_SERVICE" in c or "HSSR" in c]
            if hs_circuits:
                print(f"Found {len(hs_circuits)} HS-related circuits:")
                for circ in hs_circuits[:5]:
                    print(f"  {circ[:100]}...")
                    # Look for HS_POW field
                    if "HS_POW=" in circ:
                        pow_part = circ.split("HS_POW=")[1].split()[0]
                        print(f"    -> PoW: {pow_part}")
            else:
                print("No HS service circuits currently")
        except Exception as e:
            print(f"Could not get circuit status: {e}")

        # Check HS descriptor for pow-params
        print("\n--- HS Descriptor pow-params ---")
        try:
            hs_list = await controller.get_info("onions/current")
            if hs_list:
                for onion in hs_list.split("\n"):
                    onion = onion.strip()
                    if not onion:
                        continue
                    try:
                        desc = await controller.get_info(f"hs/service/desc/id/{onion}")
                        pow_lines = [
                            line
                            for line in desc.split("\n")
                            if "pow-params" in line.lower()
                        ]
                        if pow_lines:
                            print(f"  {onion}: {pow_lines[0].strip()}")
                        else:
                            print(f"  {onion}: No pow-params in descriptor")
                    except Exception as e:
                        print(f"  {onion}: Could not get descriptor: {e}")
        except Exception:
            print("  No ephemeral hidden services to check")

        print("\n" + "=" * 60)
        print("Summary:")
        print("=" * 60)
        if caps.has_add_onion_pow:
            print("[OK] Tor supports PoW for ephemeral hidden services")
            print("     PoW is enabled when creating the HS via ADD_ONION")
            print("     Tor automatically adjusts difficulty under attack")
        elif caps.has_pow_module:
            print("[PARTIAL] Tor has PoW module but ADD_ONION doesn't support it")
            print("          Use persistent HS in torrc for PoW protection")
        else:
            print("[NO] Tor version does not support PoW defense")

        print("\nNote: Tor's PoW defense works at the circuit establishment level.")
        print("Under attack, Tor increases the PoW difficulty automatically.")
        print("The only observable effects are:")
        print("  - HS_POW=v1,<effort> in CIRC events (circuit-status)")
        print("  - pow-params in HS descriptors (hs/service/desc/id/<addr>)")
        print("  - Increased connection times for SOCKS clients")

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback

        traceback.print_exc()
    finally:
        await controller.close()


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check Tor PoW defense status",
    )
    parser.add_argument(
        "--control-host",
        default="127.0.0.1",
        help="Tor control port host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--control-port",
        type=int,
        default=9051,
        help="Tor control port (default: 9051)",
    )
    parser.add_argument(
        "--cookie",
        help="Path to Tor control auth cookie",
    )

    args = parser.parse_args()

    await check_pow_status(
        control_host=args.control_host,
        control_port=args.control_port,
        cookie_path=args.cookie,
    )


if __name__ == "__main__":
    asyncio.run(main())
