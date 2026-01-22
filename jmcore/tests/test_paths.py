"""
Tests for jmcore.paths module - nick state file management and component locks.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from jmcore.paths import (
    ComponentLockError,
    acquire_component_lock,
    check_component_running,
    get_all_nick_states,
    get_nick_state_path,
    read_nick_state,
    release_component_lock,
    remove_nick_state,
    write_nick_state,
)


class TestNickStateFiles:
    """Tests for nick state file management functions."""

    def test_get_nick_state_path(self, tmp_path: Path) -> None:
        """Test that nick state path is correctly constructed."""
        path = get_nick_state_path(tmp_path, "maker")
        assert path == tmp_path / "state" / "maker.nick"

    def test_write_and_read_nick_state(self, tmp_path: Path) -> None:
        """Test writing and reading a nick state file."""
        # Write nick
        write_nick_state(tmp_path, "maker", "J5ABCDEFGHI")

        # Verify file exists
        assert (tmp_path / "state" / "maker.nick").exists()

        # Read nick back
        nick = read_nick_state(tmp_path, "maker")
        assert nick == "J5ABCDEFGHI"

    def test_read_nonexistent_nick_state(self, tmp_path: Path) -> None:
        """Test reading a non-existent nick state file returns None."""
        nick = read_nick_state(tmp_path, "nonexistent")
        assert nick is None

    def test_remove_nick_state(self, tmp_path: Path) -> None:
        """Test removing a nick state file."""
        # Write nick
        write_nick_state(tmp_path, "maker", "J5ABCDEFGHI")
        assert (tmp_path / "state" / "maker.nick").exists()

        # Remove nick
        result = remove_nick_state(tmp_path, "maker")
        assert result is True
        assert not (tmp_path / "state" / "maker.nick").exists()

    def test_remove_nonexistent_nick_state(self, tmp_path: Path) -> None:
        """Test removing a non-existent nick state file returns False."""
        result = remove_nick_state(tmp_path, "nonexistent")
        assert result is False

    def test_get_all_nick_states_empty(self, tmp_path: Path) -> None:
        """Test getting all nick states when none exist."""
        states = get_all_nick_states(tmp_path)
        assert states == {}

    def test_get_all_nick_states_multiple(self, tmp_path: Path) -> None:
        """Test getting all nick states with multiple components."""
        # Write multiple nicks
        write_nick_state(tmp_path, "maker", "J5MAKERABC")
        write_nick_state(tmp_path, "taker", "J5TAKERXYZ")
        write_nick_state(tmp_path, "directory", "directory-mainnet")
        write_nick_state(tmp_path, "orderbook", "J5ORDERBOOK")

        # Get all states
        states = get_all_nick_states(tmp_path)

        assert len(states) == 4
        assert states["maker"] == "J5MAKERABC"
        assert states["taker"] == "J5TAKERXYZ"
        assert states["directory"] == "directory-mainnet"
        assert states["orderbook"] == "J5ORDERBOOK"

    def test_write_overwrites_existing(self, tmp_path: Path) -> None:
        """Test that writing a nick overwrites existing file."""
        write_nick_state(tmp_path, "maker", "J5OLDNICK")
        write_nick_state(tmp_path, "maker", "J5NEWNICK")

        nick = read_nick_state(tmp_path, "maker")
        assert nick == "J5NEWNICK"

    def test_write_creates_state_directory(self, tmp_path: Path) -> None:
        """Test that writing creates the state directory if needed."""
        # Ensure state directory doesn't exist
        state_dir = tmp_path / "state"
        assert not state_dir.exists()

        # Write nick (should create directory)
        write_nick_state(tmp_path, "maker", "J5ABCDEFGHI")

        # Verify directory was created
        assert state_dir.exists()
        assert state_dir.is_dir()

    def test_read_strips_whitespace(self, tmp_path: Path) -> None:
        """Test that reading strips whitespace from nick."""
        # Manually create file with extra whitespace
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"
        nick_file.write_text("  J5ABCDEFGHI  \n\n")

        nick = read_nick_state(tmp_path, "maker")
        assert nick == "J5ABCDEFGHI"

    def test_get_all_nick_states_ignores_empty_files(self, tmp_path: Path) -> None:
        """Test that empty nick files are ignored."""
        # Create state directory
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)

        # Create an empty nick file
        (state_dir / "empty.nick").write_text("")

        # Create a valid nick file
        (state_dir / "maker.nick").write_text("J5ABCDEFGHI\n")

        states = get_all_nick_states(tmp_path)

        # Only the valid file should be included
        assert len(states) == 1
        assert "maker" in states
        assert "empty" not in states

    def test_get_all_nick_states_ignores_non_nick_files(self, tmp_path: Path) -> None:
        """Test that non-.nick files are ignored."""
        # Create state directory with mixed files
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)

        (state_dir / "maker.nick").write_text("J5MAKERABC\n")
        (state_dir / "other.txt").write_text("some other file")
        (state_dir / "taker.nick").write_text("J5TAKERXYZ\n")

        states = get_all_nick_states(tmp_path)

        assert len(states) == 2
        assert "maker" in states
        assert "taker" in states
        assert "other" not in states


class TestNickStateDefaultDataDir:
    """Tests for nick state functions with default data directory."""

    def test_write_with_none_data_dir(self, tmp_path: Path) -> None:
        """Test that None data_dir uses default."""
        from unittest.mock import patch

        # Mock get_default_data_dir to use tmp_path instead of ~/.joinmarket-ng
        with patch("jmcore.paths.get_default_data_dir", return_value=tmp_path):
            path = write_nick_state(None, "maker", "J5testNick")
            assert path.exists()
            assert path.read_text() == "J5testNick\n"  # write_nick_state adds newline
            assert path == tmp_path / "state" / "maker.nick"

    def test_get_nick_state_path_with_none(self, tmp_path: Path) -> None:
        """Test that None data_dir returns path under default data dir."""
        from unittest.mock import patch

        with patch("jmcore.paths.get_default_data_dir", return_value=tmp_path):
            path = get_nick_state_path(None, "maker")
            # Should be under mocked data dir/state/maker.nick
            assert path.name == "maker.nick"
            assert path.parent.name == "state"
            assert path == tmp_path / "state" / "maker.nick"


class TestComponentLocks:
    """Tests for component lock using nick state files."""

    def test_acquire_and_release_lock(self, tmp_path: Path) -> None:
        """Test acquiring and releasing a component lock."""
        lock_path = acquire_component_lock(tmp_path, "maker", "J5TESTNICK")

        # Lock file should exist with nick:pid format
        assert lock_path.exists()
        content = lock_path.read_text().strip()
        assert content == f"J5TESTNICK:{os.getpid()}"

        # Release should succeed
        result = release_component_lock(tmp_path, "maker")
        assert result is True
        assert not lock_path.exists()

    def test_acquire_lock_twice_same_process(self, tmp_path: Path) -> None:
        """Test that same process can re-acquire its own lock."""
        # First acquisition
        acquire_component_lock(tmp_path, "maker", "J5NICK1")

        # Second acquisition should succeed (same PID) and update nick
        lock_path = acquire_component_lock(tmp_path, "maker", "J5NICK2")
        assert lock_path.exists()
        content = lock_path.read_text().strip()
        assert content == f"J5NICK2:{os.getpid()}"

        release_component_lock(tmp_path, "maker")

    def test_acquire_lock_fails_when_held_by_other(self, tmp_path: Path) -> None:
        """Test that acquiring a lock fails when another process holds it."""
        # Manually create a nick state file with a different (but running) PID
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # Use PID 1 (init) which should always be running
        nick_file.write_text("J5OTHERNICK:1\n")

        with pytest.raises(ComponentLockError) as exc_info:
            acquire_component_lock(tmp_path, "maker", "J5MYNICK")

        assert exc_info.value.component == "maker"
        assert exc_info.value.nick == "J5OTHERNICK"
        assert exc_info.value.pid == 1
        assert "Another maker instance is already running" in str(exc_info.value)

    def test_acquire_lock_clears_stale_lock(self, tmp_path: Path) -> None:
        """Test that a stale lock (dead process) is cleared."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # Use a PID that definitely doesn't exist (very high number)
        nick_file.write_text("J5STALE:999999999\n")

        # Should succeed despite existing lock file
        lock_path = acquire_component_lock(tmp_path, "maker", "J5NEWNICK")
        assert lock_path.exists()
        content = lock_path.read_text().strip()
        assert content == f"J5NEWNICK:{os.getpid()}"

        release_component_lock(tmp_path, "maker")

    def test_acquire_lock_clears_legacy_format(self, tmp_path: Path) -> None:
        """Test that legacy nick state file (no PID) is cleared."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # Legacy format (nick only, no PID)
        nick_file.write_text("J5LEGACYNICK\n")

        # Should succeed - legacy format has no PID so we can't verify if running
        lock_path = acquire_component_lock(tmp_path, "maker", "J5NEWNICK")
        assert lock_path.exists()
        content = lock_path.read_text().strip()
        assert content == f"J5NEWNICK:{os.getpid()}"

        release_component_lock(tmp_path, "maker")

    def test_release_lock_only_own(self, tmp_path: Path) -> None:
        """Test that release only removes lock if owned by current process."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # Lock held by another process (PID 1)
        nick_file.write_text("J5OTHER:1\n")

        # Release should fail (not our lock)
        result = release_component_lock(tmp_path, "maker")
        assert result is False
        assert nick_file.exists()  # Lock should still exist

    def test_check_component_running(self, tmp_path: Path) -> None:
        """Test checking a component that is running."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # PID 1 (init) should be running
        nick_file.write_text("J5RUNNICK:1\n")

        result = check_component_running(tmp_path, "maker")
        assert result is not None
        nick, pid = result
        assert nick == "J5RUNNICK"
        assert pid == 1

    def test_check_component_running_dead(self, tmp_path: Path) -> None:
        """Test checking a component with dead process."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # Very high PID that doesn't exist
        nick_file.write_text("J5DEAD:999999999\n")

        result = check_component_running(tmp_path, "maker")
        assert result is None

    def test_check_component_running_none(self, tmp_path: Path) -> None:
        """Test checking a non-existent component."""
        result = check_component_running(tmp_path, "maker")
        assert result is None

    def test_multiple_components_independent_locks(self, tmp_path: Path) -> None:
        """Test that different components have independent locks."""
        maker_lock = acquire_component_lock(tmp_path, "maker", "J5MAKER")
        taker_lock = acquire_component_lock(tmp_path, "taker", "J5TAKER")

        assert maker_lock.exists()
        assert taker_lock.exists()
        assert maker_lock != taker_lock

        release_component_lock(tmp_path, "maker")
        release_component_lock(tmp_path, "taker")

    def test_component_lock_error_message(self) -> None:
        """Test ComponentLockError has informative message."""
        error = ComponentLockError("maker", "J5TESTNICK", 12345)
        assert error.component == "maker"
        assert error.nick == "J5TESTNICK"
        assert error.pid == 12345
        assert "maker" in str(error)
        assert "J5TESTNICK" in str(error)
        assert "12345" in str(error)
        assert "Only one maker can run per data directory" in str(error)

    def test_read_nick_state_with_pid_format(self, tmp_path: Path) -> None:
        """Test that read_nick_state correctly parses nick:pid format."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)
        nick_file = state_dir / "maker.nick"

        # New format with PID
        nick_file.write_text("J5TESTNICK:12345\n")

        nick = read_nick_state(tmp_path, "maker")
        assert nick == "J5TESTNICK"

    def test_get_all_nick_states_with_pid_format(self, tmp_path: Path) -> None:
        """Test that get_all_nick_states correctly parses nick:pid format."""
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)

        # Mix of new and legacy formats
        (state_dir / "maker.nick").write_text("J5MAKER:12345\n")
        (state_dir / "taker.nick").write_text("J5TAKER\n")  # Legacy format

        states = get_all_nick_states(tmp_path)
        assert states["maker"] == "J5MAKER"
        assert states["taker"] == "J5TAKER"
