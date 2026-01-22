"""
Shared path utilities for JoinMarket data directories.

This module provides consistent path handling across all JoinMarket components
(maker, taker, wallet) for data directories, commitment blacklists, and history.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def get_default_data_dir() -> Path:
    """
    Get the default JoinMarket data directory.

    Returns ~/.joinmarket-ng or $JOINMARKET_DATA_DIR if set.
    Creates the directory if it doesn't exist.

    For compatibility with reference JoinMarket in Docker, users can
    set JOINMARKET_DATA_DIR=/home/jm/.joinmarket-ng to share the same volume.
    """
    env_path = os.getenv("JOINMARKET_DATA_DIR")
    data_dir = Path(env_path) if env_path else Path.home() / ".joinmarket-ng"

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_commitment_blacklist_path(data_dir: Path | None = None) -> Path:
    """
    Get the path to the commitment blacklist file.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())

    Returns:
        Path to cmtdata/commitmentlist (compatible with reference JoinMarket)
    """
    if data_dir is None:
        data_dir = get_default_data_dir()

    # Use cmtdata/ subdirectory for commitment data (matches reference implementation)
    cmtdata_dir = data_dir / "cmtdata"
    cmtdata_dir.mkdir(parents=True, exist_ok=True)

    return cmtdata_dir / "commitmentlist"


def get_used_commitments_path(data_dir: Path | None = None) -> Path:
    """
    Get the path to the used commitments file (for takers).

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())

    Returns:
        Path to cmtdata/commitments.json (compatible with reference JoinMarket)
    """
    if data_dir is None:
        data_dir = get_default_data_dir()

    # Use cmtdata/ subdirectory
    cmtdata_dir = data_dir / "cmtdata"
    cmtdata_dir.mkdir(parents=True, exist_ok=True)

    return cmtdata_dir / "commitments.json"


def get_ignored_makers_path(data_dir: Path | None = None) -> Path:
    """
    Get the path to the ignored makers file (for takers).

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())

    Returns:
        Path to ignored_makers.txt
    """
    if data_dir is None:
        data_dir = get_default_data_dir()

    return data_dir / "ignored_makers.txt"


def get_nick_state_path(data_dir: Path | str | None = None, component: str = "") -> Path:
    """
    Get the path to a component's nick state file.

    The nick state file stores the current nick of a running component,
    allowing operators to easily identify the nick and enabling cross-component
    protection (e.g., taker excluding own maker nick from peer selection).

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')

    Returns:
        Path to state/<component>.nick (e.g., ~/.joinmarket-ng/state/maker.nick)
    """
    if data_dir is None:
        data_dir = get_default_data_dir()
    elif isinstance(data_dir, str):
        data_dir = Path(data_dir)

    # Use state/ subdirectory to keep state files organized
    state_dir = data_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    return state_dir / f"{component}.nick"


def write_nick_state(data_dir: Path | str | None, component: str, nick: str) -> Path:
    """
    Write a component's nick to its state file.

    Creates the state directory if it doesn't exist.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')
        nick: The nick to write (e.g., 'J5XXXXXXXXX')

    Returns:
        Path to the written state file
    """
    path = get_nick_state_path(data_dir, component)
    path.write_text(nick + "\n")
    return path


def read_nick_state(data_dir: Path | str | None, component: str) -> str | None:
    """
    Read a component's nick from its state file.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')

    Returns:
        The nick string if file exists and is readable, None otherwise
    """
    if data_dir is None:
        data_dir = get_default_data_dir()
    elif isinstance(data_dir, str):
        data_dir = Path(data_dir)

    path = get_nick_state_path(data_dir, component)
    if path.exists():
        try:
            content = path.read_text().strip()
            # Parse format: "nick:pid" or legacy "nick"
            if ":" in content:
                return content.rsplit(":", 1)[0]
            return content
        except OSError:
            return None
    return None


def remove_nick_state(data_dir: Path | str | None, component: str) -> bool:
    """
    Remove a component's nick state file (e.g., on shutdown).

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')

    Returns:
        True if file was removed, False if it didn't exist or removal failed
    """
    if data_dir is None:
        data_dir = get_default_data_dir()
    elif isinstance(data_dir, str):
        data_dir = Path(data_dir)

    path = get_nick_state_path(data_dir, component)
    if path.exists():
        try:
            path.unlink()
            return True
        except OSError:
            return False
    return False


def get_all_nick_states(data_dir: Path | str | None = None) -> dict[str, str]:
    """
    Read all component nick state files from the data directory.

    Useful for discovering all running components and their nicks.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())

    Returns:
        Dict mapping component names to their nicks (e.g., {'maker': 'J5XXX', 'taker': 'J5YYY'})
    """
    if data_dir is None:
        data_dir = get_default_data_dir()
    elif isinstance(data_dir, str):
        data_dir = Path(data_dir)

    state_dir = data_dir / "state"
    if not state_dir.exists():
        return {}

    result: dict[str, str] = {}
    for path in state_dir.glob("*.nick"):
        component = path.stem  # e.g., 'maker' from 'maker.nick'
        try:
            content = path.read_text().strip()
            # Parse format: "nick:pid" or legacy "nick"
            nick = content.rsplit(":", 1)[0] if ":" in content else content
            if nick:
                result[component] = nick
        except OSError:
            continue

    return result


class ComponentLockError(Exception):
    """Raised when a component lock cannot be acquired."""

    def __init__(self, component: str, nick: str, pid: int):
        self.component = component
        self.nick = nick
        self.pid = pid
        super().__init__(
            f"Another {component} instance is already running (nick: {nick}, PID: {pid}). "
            f"Only one {component} can run per data directory."
        )


def _is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)  # Signal 0 doesn't kill, just checks if process exists
        return True
    except PermissionError:
        # Process exists but we don't have permission to signal it
        return True
    except OSError:
        # Process doesn't exist
        return False


def _parse_nick_state_content(content: str) -> tuple[str, int | None]:
    """
    Parse nick state file content.

    Format: "nick:pid" or legacy "nick" (without PID)

    Returns:
        (nick, pid) tuple where pid may be None for legacy format
    """
    content = content.strip()
    if ":" in content:
        parts = content.rsplit(":", 1)
        nick = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            pid = None
        return nick, pid
    return content, None


def acquire_component_lock(data_dir: Path | str | None, component: str, nick: str) -> Path:
    """
    Acquire an exclusive lock for a component by writing nick state with PID.

    This prevents running multiple instances of the same component type
    (e.g., two makers) from the same data directory, which could lead to
    wallet conflicts and UTXO double-spending attempts.

    The lock uses the nick state file with format "nick:pid". If the file
    exists but the process is dead (stale lock), it is removed and re-acquired.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')
        nick: The component's nick to write

    Returns:
        Path to the nick state file (which serves as the lock)

    Raises:
        ComponentLockError: If another instance of the component is running
    """
    state_path = get_nick_state_path(data_dir, component)
    current_pid = os.getpid()

    # Check for existing lock
    if state_path.exists():
        try:
            content = state_path.read_text()
            existing_nick, existing_pid = _parse_nick_state_content(content)

            if existing_pid is not None:
                # If it's our own PID, we can re-acquire
                if existing_pid == current_pid:
                    # Update nick in case it changed
                    state_path.write_text(f"{nick}:{current_pid}\n")
                    return state_path
                # If it's another running process, fail
                if _is_process_running(existing_pid):
                    raise ComponentLockError(component, existing_nick, existing_pid)
            # Stale lock (process dead) or legacy format - remove it
        except OSError:
            # Can't read file, try to remove it
            pass

        with contextlib.suppress(OSError):
            state_path.unlink()

    # Write nick and PID to the state file
    # Ensure state directory exists
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(f"{nick}:{current_pid}\n")
    return state_path


def release_component_lock(data_dir: Path | str | None, component: str) -> bool:
    """
    Release a component's lock by removing the nick state file.

    Only removes the lock if it belongs to the current process (safety check).

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')

    Returns:
        True if lock was released, False otherwise
    """
    state_path = get_nick_state_path(data_dir, component)
    current_pid = os.getpid()

    if state_path.exists():
        try:
            content = state_path.read_text()
            _, existing_pid = _parse_nick_state_content(content)

            # Only remove if it's our lock or legacy format (no PID)
            if existing_pid is None or existing_pid == current_pid:
                state_path.unlink()
                return True
        except OSError:
            pass

    return False


def check_component_running(data_dir: Path | str | None, component: str) -> tuple[str, int] | None:
    """
    Check if a component is running and return its nick and PID.

    Args:
        data_dir: Optional data directory (defaults to get_default_data_dir())
        component: Component name (e.g., 'maker', 'taker', 'directory', 'orderbook')

    Returns:
        (nick, pid) tuple if component is running, None otherwise
    """
    state_path = get_nick_state_path(data_dir, component)

    if state_path.exists():
        try:
            content = state_path.read_text()
            nick, pid = _parse_nick_state_content(content)

            if pid is not None and _is_process_running(pid):
                return nick, pid
        except OSError:
            pass

    return None
