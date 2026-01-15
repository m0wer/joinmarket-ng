#!/usr/bin/env python3
"""
Version bumping script for JoinMarket NG.

This script automates the release process by:
1. Bumping the version in all relevant files
2. Updating the CHANGELOG.md with version and date
3. Updating install.sh DEFAULT_VERSION
4. Creating a git commit with a standard message
5. Creating a git tag
6. Optionally pushing the changes and tag

Usage:
    python scripts/bump_version.py 0.10.0
    python scripts/bump_version.py 0.10.0 --push
    python scripts/bump_version.py --dry-run 0.10.0

The script will:
- Update jmcore/src/jmcore/version.py
- Update all pyproject.toml files
- Update install.sh DEFAULT_VERSION
- Update CHANGELOG.md (change [Unreleased] to [X.Y.Z] - YYYY-MM-DD)
- Add diff link at the bottom of CHANGELOG.md
- Commit with message "release: X.Y.Z"
- Tag with "X.Y.Z"
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent

# Files to update with version
VERSION_FILE = PROJECT_ROOT / "jmcore" / "src" / "jmcore" / "version.py"
INSTALL_SCRIPT = PROJECT_ROOT / "install.sh"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"

# All pyproject.toml files to update
PYPROJECT_FILES = [
    PROJECT_ROOT / "jmcore" / "pyproject.toml",
    PROJECT_ROOT / "jmwallet" / "pyproject.toml",
    PROJECT_ROOT / "maker" / "pyproject.toml",
    PROJECT_ROOT / "taker" / "pyproject.toml",
    PROJECT_ROOT / "directory_server" / "pyproject.toml",
    PROJECT_ROOT / "orderbook_watcher" / "pyproject.toml",
]

# Semantic version regex
SEMVER_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def validate_version(version: str) -> tuple[int, int, int]:
    """Validate and parse a semantic version string."""
    match = SEMVER_PATTERN.match(version)
    if not match:
        print(
            f"Error: Invalid version format '{version}'. Expected X.Y.Z (e.g., 0.10.0)"
        )
        sys.exit(1)
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def get_current_version() -> str:
    """Get the current version from version.py."""
    content = VERSION_FILE.read_text()
    match = re.search(r'__version__\s*=\s*"([^"]+)"', content)
    if not match:
        print(f"Error: Could not find __version__ in {VERSION_FILE}")
        sys.exit(1)
    return match.group(1)


def update_version_file(new_version: str, dry_run: bool = False) -> None:
    """Update the version.py file."""
    content = VERSION_FILE.read_text()
    new_content = re.sub(
        r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new_version}"', content
    )

    if dry_run:
        print(f"Would update {VERSION_FILE}")
        print(f'  __version__ = "{new_version}"')
    else:
        VERSION_FILE.write_text(new_content)
        print(f"Updated {VERSION_FILE}")


def update_pyproject_files(new_version: str, dry_run: bool = False) -> None:
    """Update all pyproject.toml files."""
    for pyproject in PYPROJECT_FILES:
        if not pyproject.exists():
            print(f"Warning: {pyproject} not found, skipping")
            continue

        content = pyproject.read_text()
        # Match version = "X.Y.Z" in [project] section
        new_content = re.sub(
            r'^version\s*=\s*"[^"]+"',
            f'version = "{new_version}"',
            content,
            flags=re.MULTILINE,
        )

        if dry_run:
            print(f"Would update {pyproject}")
        else:
            pyproject.write_text(new_content)
            print(f"Updated {pyproject}")


def update_install_script(new_version: str, dry_run: bool = False) -> None:
    """Update the DEFAULT_VERSION in install.sh."""
    content = INSTALL_SCRIPT.read_text()
    new_content = re.sub(
        r'DEFAULT_VERSION="[^"]+"', f'DEFAULT_VERSION="{new_version}"', content
    )

    if dry_run:
        print(f"Would update {INSTALL_SCRIPT}")
        print(f'  DEFAULT_VERSION="{new_version}"')
    else:
        INSTALL_SCRIPT.write_text(new_content)
        print(f"Updated {INSTALL_SCRIPT}")


def update_changelog(
    new_version: str, current_version: str, dry_run: bool = False
) -> None:
    """
    Update CHANGELOG.md:
    1. Change [Unreleased] to [X.Y.Z] - YYYY-MM-DD
    2. Add new [Unreleased] section
    3. Update diff links at the bottom
    """
    content = CHANGELOG.read_text()
    today = datetime.now().strftime("%Y-%m-%d")

    # Replace [Unreleased] with new version and date
    # First, add a new [Unreleased] section
    unreleased_pattern = r"## \[Unreleased\]"
    new_unreleased = f"## [Unreleased]\n\n## [{new_version}] - {today}"
    new_content = re.sub(unreleased_pattern, new_unreleased, content)

    # Update the diff links at the bottom
    # Find existing [Unreleased] link and update it
    unreleased_link_pattern = r"\[Unreleased\]: https://github\.com/m0wer/joinmarket-ng/compare/[^.]+\.\.\.HEAD"
    new_unreleased_link = f"[Unreleased]: https://github.com/m0wer/joinmarket-ng/compare/{new_version}...HEAD"
    new_content = re.sub(unreleased_link_pattern, new_unreleased_link, new_content)

    # Add new version diff link before the [Unreleased] link
    # Find where the [Unreleased] link is and add the new version link after it
    new_version_link = (
        f"[{new_version}]: https://github.com/m0wer/joinmarket-ng/compare/"
        f"{current_version}...{new_version}"
    )

    # Insert the new version link right after the [Unreleased] link
    new_content = re.sub(
        r"(\[Unreleased\]: https://github\.com/m0wer/joinmarket-ng/compare/[^\n]+)",
        f"\\1\n{new_version_link}",
        new_content,
    )

    if dry_run:
        print(f"Would update {CHANGELOG}")
        print(f"  [Unreleased] -> [{new_version}] - {today}")
        print(f"  Add diff link for {new_version}")
    else:
        CHANGELOG.write_text(new_content)
        print(f"Updated {CHANGELOG}")


def run_command(
    cmd: list[str], dry_run: bool = False, check: bool = True
) -> subprocess.CompletedProcess | None:
    """Run a command, optionally in dry-run mode."""
    if dry_run:
        print(f"Would run: {' '.join(cmd)}")
        return None

    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, cwd=PROJECT_ROOT)


def git_commit_and_tag(
    new_version: str, dry_run: bool = False, push: bool = False
) -> None:
    """Create git commit and tag."""
    # Stage all changed files
    files_to_stage = [
        str(VERSION_FILE.relative_to(PROJECT_ROOT)),
        str(INSTALL_SCRIPT.relative_to(PROJECT_ROOT)),
        str(CHANGELOG.relative_to(PROJECT_ROOT)),
    ]
    files_to_stage.extend(str(f.relative_to(PROJECT_ROOT)) for f in PYPROJECT_FILES)

    run_command(["git", "add", *files_to_stage], dry_run=dry_run)

    # Create commit
    commit_msg = f"release: {new_version}"
    run_command(["git", "commit", "-m", commit_msg], dry_run=dry_run)

    # Create tag
    run_command(["git", "tag", new_version], dry_run=dry_run)

    if push:
        # Push commit and tag
        run_command(["git", "push"], dry_run=dry_run)
        run_command(["git", "push", "--tags"], dry_run=dry_run)
    else:
        print("\nTo push changes and tag:")
        print("  git push && git push --tags")


def check_git_clean() -> bool:
    """Check if the git working directory is clean."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    return len(result.stdout.strip()) == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bump JoinMarket NG version and prepare release",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "version",
        help="New version in X.Y.Z format (e.g., 0.10.0)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Push commit and tag to remote after creating them",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip dirty working directory check",
    )

    args = parser.parse_args()

    # Validate version format
    validate_version(args.version)

    # Get current version
    current_version = get_current_version()
    print(f"Current version: {current_version}")
    print(f"New version: {args.version}")
    print()

    # Check if new version is greater than current
    current_parts = validate_version(current_version)
    new_parts = validate_version(args.version)
    if new_parts <= current_parts:
        print(
            f"Warning: New version {args.version} is not greater than current {current_version}"
        )
        if not args.force:
            response = input("Continue anyway? [y/N] ")
            if response.lower() != "y":
                print("Aborted")
                sys.exit(1)

    # Check for clean working directory
    if not args.dry_run and not args.force:
        if not check_git_clean():
            print(
                "Error: Working directory is not clean. Commit or stash changes first."
            )
            print("       Use --force to skip this check.")
            sys.exit(1)

    # Update files
    print("Updating files...")
    update_version_file(args.version, dry_run=args.dry_run)
    update_pyproject_files(args.version, dry_run=args.dry_run)
    update_install_script(args.version, dry_run=args.dry_run)
    update_changelog(args.version, current_version, dry_run=args.dry_run)
    print()

    # Git operations
    print("Git operations...")
    git_commit_and_tag(args.version, dry_run=args.dry_run, push=args.push)

    if args.dry_run:
        print("\nThis was a dry run. No changes were made.")
    else:
        print(f"\nVersion bumped to {args.version}")
        print("GitHub Actions will create the release when the tag is pushed.")


if __name__ == "__main__":
    main()
