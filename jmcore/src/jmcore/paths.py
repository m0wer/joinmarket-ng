"""
Shared path utilities for JoinMarket data directories.

This module provides consistent path handling across all JoinMarket components
(maker, taker, wallet) for data directories, commitment blacklists, and history.
"""

from __future__ import annotations

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
