"""
Tests for jmcore.paths module - nick state file management.
"""

from __future__ import annotations

from pathlib import Path

from jmcore.paths import (
    get_all_nick_states,
    get_nick_state_path,
    read_nick_state,
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
