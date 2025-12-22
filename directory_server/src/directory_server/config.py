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

    max_peers: int = 10000
    max_message_size: int = 2097152  # 2MB
    message_rate_limit: int = 100  # messages per second (sustained)
    message_burst_limit: int = 200  # maximum burst size
    rate_limit_disconnect_threshold: int = 50  # disconnect after N violations

    # Batch size for concurrent broadcasts to limit memory usage
    # Lower values = less memory, higher values = faster broadcasts
    broadcast_batch_size: int = 50

    log_level: str = "INFO"

    motd: str = "JoinMarket Directory Server https://github.com/m0wer/joinmarket-v2"

    health_check_host: str = "127.0.0.1"
    health_check_port: int = 8080


def get_settings() -> Settings:
    return Settings()
