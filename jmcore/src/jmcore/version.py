"""
Centralized version management for JoinMarket NG.

This is the single source of truth for the project version.
All components inherit their version from here.
"""

from __future__ import annotations

# The project version - update this when releasing
# Format: MAJOR.MINOR.PATCH (Semantic Versioning)
__version__ = "0.13.0"

# Alias for convenience
VERSION = __version__


def get_version() -> str:
    """Return the current version string."""
    return __version__


def get_version_tuple() -> tuple[int, int, int]:
    """Return the version as a tuple of (major, minor, patch)."""
    parts = __version__.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def get_version_info() -> dict[str, str | int]:
    """Return version information as a dictionary."""
    major, minor, patch = get_version_tuple()
    return {
        "version": __version__,
        "major": major,
        "minor": minor,
        "patch": patch,
    }
