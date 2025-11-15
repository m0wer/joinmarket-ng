"""
Configuration management using pydantic-settings.
"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    network: Literal["mainnet", "testnet", "signet", "regtest"] = "mainnet"
    host: str = "127.0.0.1"
    port: int = 5222

    max_peers: int = 1000
    max_message_size: int = 40000
    message_rate_limit: int = 100

    log_level: str = "INFO"
    log_file: str = "directory_server.log"

    motd: str = "JoinMarket Directory Server https://github.com/m0wer/joinmarket-v2"


def get_settings() -> Settings:
    return Settings()
