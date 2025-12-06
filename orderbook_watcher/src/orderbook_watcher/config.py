"""
Configuration management for orderbook watcher.
"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    network: Literal["mainnet", "testnet", "signet", "regtest"] = "mainnet"

    directory_nodes: str = ""

    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = 9050

    mempool_api_url: str = (
        "http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion/api"
    )
    mempool_web_url: str | None = "https://mempool.sgn.space"
    mempool_web_onion_url: str | None = (
        "http://mempopwcaqoi7z5xj5zplfdwk5bgzyl3hemx725d4a3agado6xtk3kqd.onion"
    )

    http_host: str = "0.0.0.0"
    http_port: int = 8000

    update_interval: int = 60

    log_level: str = "INFO"

    max_message_size: int = 2097152  # 2MB
    connection_timeout: float = 30.0

    nostr_relays: str = ""

    def get_directory_nodes(self) -> list[tuple[str, int]]:
        if not self.directory_nodes:
            return []
        nodes = []
        for node in self.directory_nodes.split(","):
            node = node.strip()
            if not node:
                continue
            if ":" in node:
                host, port_str = node.rsplit(":", 1)
                nodes.append((host, int(port_str)))
            else:
                nodes.append((node, 5222))
        return nodes

    def get_nostr_relays(self) -> list[str]:
        if not self.nostr_relays:
            return []
        return [r.strip() for r in self.nostr_relays.split(",") if r.strip()]


def get_settings() -> Settings:
    return Settings()
