"""
Configuration management using unified JoinMarket settings.
"""

from jmcore.settings import DirectoryServerSettings, get_settings


def get_directory_server_settings() -> DirectoryServerSettings:
    """Get directory server settings from unified config."""
    settings = get_settings()
    return settings.directory_server
