"""
Configuration for JoinMarket Taker.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from jmcore.models import NetworkType, OfferType
from pydantic import BaseModel, Field, model_validator


class BroadcastPolicy(str, Enum):
    """
    Policy for how to broadcast the final CoinJoin transaction.

    Privacy implications:
    - SELF: Taker broadcasts via own node. Links taker's IP to the transaction.
    - RANDOM_PEER: Random selection from makers + self. Provides plausible deniability.
    - NOT_SELF: Only makers can broadcast. Maximum privacy - taker's node never touches tx.
                WARNING: No fallback if makers fail to broadcast!
    """

    SELF = "self"
    RANDOM_PEER = "random-peer"
    NOT_SELF = "not-self"


class MaxCjFee(BaseModel):
    """Maximum CoinJoin fee limits."""

    abs_fee: int = Field(default=50_000, ge=0, description="Maximum absolute fee in sats")
    rel_fee: str = Field(default="0.001", description="Maximum relative fee (0.001 = 0.1%)")


class TakerConfig(BaseModel):
    """Configuration for taker bot."""

    # Wallet settings
    mnemonic: str
    # Protocol network - used for directory server handshakes
    # Reference JoinMarket uses "testnet" for both testnet and regtest
    network: NetworkType = NetworkType.MAINNET
    # Bitcoin network - used for address generation (bcrt1 vs tb1 vs bc1)
    # If not specified, defaults to the same as network
    bitcoin_network: NetworkType | None = None
    backend_type: str = "bitcoin_core"
    backend_config: dict[str, Any] = Field(default_factory=dict)

    # Directory server settings
    directory_servers: list[str] = Field(default_factory=list)

    # CoinJoin settings
    destination_address: str = ""  # Target address for CJ output, empty = INTERNAL
    amount: int = 0  # Amount in sats (0 = sweep)
    mixdepth: int = 0  # Source mixdepth
    counterparty_count: int = Field(default=3, ge=1, le=20)

    # Fee settings
    max_cj_fee: MaxCjFee = Field(default_factory=MaxCjFee)
    tx_fee_factor: float = Field(
        default=3.0, ge=1.0, description="Multiply estimated fee by this factor"
    )

    # PoDLE settings
    taker_utxo_retries: int = Field(default=10, ge=1, le=10)
    taker_utxo_age: int = Field(default=5, ge=1, description="Minimum UTXO confirmations")
    taker_utxo_amtpercent: int = Field(
        default=20, ge=1, le=100, description="Min UTXO value as % of CJ amount"
    )

    # Wallet structure
    mixdepth_count: int = Field(default=5, ge=1, le=10)
    gap_limit: int = Field(default=20, ge=6)

    # Timeouts
    maker_timeout_sec: int = Field(default=60, ge=10)
    order_wait_time: float = Field(
        default=10.0, ge=1.0, description="Seconds to wait for orderbook"
    )

    # Broadcast policy (privacy vs reliability tradeoff)
    tx_broadcast: BroadcastPolicy = Field(
        default=BroadcastPolicy.RANDOM_PEER,
        description="How to broadcast the final transaction: self, random-peer, or not-self",
    )
    broadcast_timeout_sec: int = Field(
        default=30,
        ge=5,
        description="Timeout waiting for maker to broadcast when delegating",
    )

    # Advanced options
    preferred_offer_type: OfferType = OfferType.SW0_RELATIVE
    minimum_makers: int = Field(default=2, ge=1)
    dust_threshold: int = Field(default=546, ge=0)

    @model_validator(mode="after")
    def set_bitcoin_network_default(self) -> TakerConfig:
        """If bitcoin_network is not set, default to the protocol network."""
        if self.bitcoin_network is None:
            object.__setattr__(self, "bitcoin_network", self.network)
        return self


class ScheduleEntry(BaseModel):
    """A single entry in a CoinJoin schedule."""

    mixdepth: int = Field(..., ge=0, le=9)
    amount: int | float = Field(..., description="Amount in sats (int) or fraction (float 0-1)")
    counterparty_count: int = Field(..., ge=1, le=20)
    destination: str = Field(..., description="Destination address or 'INTERNAL'")
    wait_time: float = Field(default=0.0, ge=0.0, description="Wait time after completion")
    rounding: int = Field(default=16, ge=1, description="Significant figures for rounding")
    completed: bool = False


class Schedule(BaseModel):
    """CoinJoin schedule for tumbler-style operations."""

    entries: list[ScheduleEntry] = Field(default_factory=list)
    current_index: int = Field(default=0, ge=0)

    def current_entry(self) -> ScheduleEntry | None:
        """Get current schedule entry."""
        if self.current_index >= len(self.entries):
            return None
        return self.entries[self.current_index]

    def advance(self) -> bool:
        """Advance to next entry. Returns True if more entries remain."""
        if self.current_index < len(self.entries):
            self.entries[self.current_index].completed = True
            self.current_index += 1
        return self.current_index < len(self.entries)

    def is_complete(self) -> bool:
        """Check if all entries are complete."""
        return self.current_index >= len(self.entries)
