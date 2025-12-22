"""
Transaction history tracking for CoinJoin operations.

Stores a simple CSV log of all CoinJoin transactions with key metadata:
- Role (maker/taker)
- Fees (paid/received)
- Peer count
- Transaction details
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Literal

from loguru import logger


@dataclass
class TransactionHistoryEntry:
    """A single CoinJoin transaction record."""

    # Timestamps
    timestamp: str  # ISO format
    completed_at: str = ""  # ISO format

    # Role and outcome
    role: Literal["maker", "taker"] = "taker"
    success: bool = True
    failure_reason: str = ""

    # Core transaction data
    txid: str = ""
    cj_amount: int = 0  # satoshis

    # Peer information
    peer_count: int = 0
    counterparty_nicks: str = ""  # comma-separated

    # Fee information (in satoshis)
    fee_received: int = 0  # Only for makers - cjfee earned
    txfee_contribution: int = 0  # Mining fee contribution
    total_maker_fees_paid: int = 0  # Only for takers
    mining_fee_paid: int = 0  # Only for takers

    # Net profit/cost
    net_fee: int = 0  # Positive = profit, negative = cost

    # UTXO/address info
    source_mixdepth: int = 0
    destination_address: str = ""
    utxos_used: str = ""  # comma-separated txid:vout

    # Broadcast method
    broadcast_method: str = ""  # "self", "maker:<nick>", etc.

    # Network
    network: str = "mainnet"


def _get_history_path(data_dir: Path | None = None) -> Path:
    """Get the path to the history CSV file."""
    if data_dir is None:
        data_dir = Path.home() / ".jm"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "coinjoin_history.csv"


def _get_fieldnames() -> list[str]:
    """Get the list of field names for the CSV."""
    return [f.name for f in fields(TransactionHistoryEntry)]


def append_history_entry(
    entry: TransactionHistoryEntry,
    data_dir: Path | None = None,
) -> None:
    """
    Append a transaction history entry to the CSV file.

    Args:
        entry: The transaction history entry to append
        data_dir: Optional data directory (defaults to ~/.jm)
    """
    history_path = _get_history_path(data_dir)
    fieldnames = _get_fieldnames()

    # Check if file exists to determine if we need to write header
    write_header = not history_path.exists()

    try:
        with open(history_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()

            # Convert entry to dict
            row = {f.name: getattr(entry, f.name) for f in fields(entry)}
            writer.writerow(row)

        logger.debug(f"Appended history entry: txid={entry.txid[:16]}... role={entry.role}")
    except Exception as e:
        logger.error(f"Failed to write history entry: {e}")


def read_history(
    data_dir: Path | None = None,
    limit: int | None = None,
    role_filter: Literal["maker", "taker"] | None = None,
) -> list[TransactionHistoryEntry]:
    """
    Read transaction history from the CSV file.

    Args:
        data_dir: Optional data directory (defaults to ~/.jm)
        limit: Maximum number of entries to return (most recent first)
        role_filter: Filter by role (maker/taker)

    Returns:
        List of TransactionHistoryEntry objects
    """
    history_path = _get_history_path(data_dir)

    if not history_path.exists():
        return []

    entries: list[TransactionHistoryEntry] = []

    try:
        with open(history_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert string values back to appropriate types
                try:
                    entry = TransactionHistoryEntry(
                        timestamp=row.get("timestamp", ""),
                        completed_at=row.get("completed_at", ""),
                        role=row.get("role", "taker"),  # type: ignore
                        success=row.get("success", "True").lower() == "true",
                        failure_reason=row.get("failure_reason", ""),
                        txid=row.get("txid", ""),
                        cj_amount=int(row.get("cj_amount", 0) or 0),
                        peer_count=int(row.get("peer_count", 0) or 0),
                        counterparty_nicks=row.get("counterparty_nicks", ""),
                        fee_received=int(row.get("fee_received", 0) or 0),
                        txfee_contribution=int(row.get("txfee_contribution", 0) or 0),
                        total_maker_fees_paid=int(row.get("total_maker_fees_paid", 0) or 0),
                        mining_fee_paid=int(row.get("mining_fee_paid", 0) or 0),
                        net_fee=int(row.get("net_fee", 0) or 0),
                        source_mixdepth=int(row.get("source_mixdepth", 0) or 0),
                        destination_address=row.get("destination_address", ""),
                        utxos_used=row.get("utxos_used", ""),
                        broadcast_method=row.get("broadcast_method", ""),
                        network=row.get("network", "mainnet"),
                    )

                    # Apply role filter
                    if role_filter and entry.role != role_filter:
                        continue

                    entries.append(entry)
                except (ValueError, KeyError) as e:
                    logger.warning(f"Skipping malformed history row: {e}")
                    continue

    except Exception as e:
        logger.error(f"Failed to read history: {e}")
        return []

    # Sort by timestamp (most recent first) and apply limit
    entries.sort(key=lambda e: e.timestamp, reverse=True)
    if limit:
        entries = entries[:limit]

    return entries


def get_history_stats(data_dir: Path | None = None) -> dict[str, int | float]:
    """
    Get aggregate statistics from transaction history.

    Returns:
        Dict with statistics:
        - total_coinjoins: Total number of CoinJoins
        - maker_coinjoins: Number as maker
        - taker_coinjoins: Number as taker
        - total_volume: Total CJ amount in sats
        - total_fees_earned: Total fees earned as maker
        - total_fees_paid: Total fees paid as taker
        - success_rate: Percentage of successful CoinJoins
    """
    entries = read_history(data_dir)

    if not entries:
        return {
            "total_coinjoins": 0,
            "maker_coinjoins": 0,
            "taker_coinjoins": 0,
            "total_volume": 0,
            "total_fees_earned": 0,
            "total_fees_paid": 0,
            "success_rate": 0.0,
        }

    maker_entries = [e for e in entries if e.role == "maker"]
    taker_entries = [e for e in entries if e.role == "taker"]
    successful = [e for e in entries if e.success]

    return {
        "total_coinjoins": len(entries),
        "maker_coinjoins": len(maker_entries),
        "taker_coinjoins": len(taker_entries),
        "total_volume": sum(e.cj_amount for e in entries),
        "total_fees_earned": sum(e.fee_received for e in maker_entries),
        "total_fees_paid": sum(e.total_maker_fees_paid + e.mining_fee_paid for e in taker_entries),
        "success_rate": len(successful) / len(entries) * 100 if entries else 0.0,
    }


def create_maker_history_entry(
    taker_nick: str,
    cj_amount: int,
    fee_received: int,
    txfee_contribution: int,
    cj_address: str,
    our_utxos: list[tuple[str, int]],
    txid: str | None = None,
    network: str = "mainnet",
) -> TransactionHistoryEntry:
    """
    Create a history entry for a completed maker CoinJoin.

    Args:
        taker_nick: The taker's nick
        cj_amount: CoinJoin amount in sats
        fee_received: CoinJoin fee received
        txfee_contribution: Mining fee contribution
        cj_address: Our CoinJoin output address
        our_utxos: List of (txid, vout) tuples for our inputs
        txid: Transaction ID (may not be known by maker)
        network: Network name

    Returns:
        TransactionHistoryEntry ready to be appended
    """
    now = datetime.now().isoformat()
    net_fee = fee_received - txfee_contribution

    return TransactionHistoryEntry(
        timestamp=now,
        completed_at=now,
        role="maker",
        success=True,
        txid=txid or "",
        cj_amount=cj_amount,
        peer_count=1,  # Maker only sees the taker
        counterparty_nicks=taker_nick,
        fee_received=fee_received,
        txfee_contribution=txfee_contribution,
        net_fee=net_fee,
        source_mixdepth=0,  # Would need to determine from UTXOs
        destination_address=cj_address,
        utxos_used=",".join(f"{txid}:{vout}" for txid, vout in our_utxos),
        network=network,
    )


def create_taker_history_entry(
    maker_nicks: list[str],
    cj_amount: int,
    total_maker_fees: int,
    mining_fee: int,
    destination: str,
    source_mixdepth: int,
    selected_utxos: list[tuple[str, int]],
    txid: str,
    broadcast_method: str = "self",
    network: str = "mainnet",
    success: bool = True,
    failure_reason: str = "",
) -> TransactionHistoryEntry:
    """
    Create a history entry for a completed taker CoinJoin.

    Args:
        maker_nicks: List of maker nicks
        cj_amount: CoinJoin amount in sats
        total_maker_fees: Total maker fees paid
        mining_fee: Mining fee paid
        destination: Destination address
        source_mixdepth: Source mixdepth
        selected_utxos: List of (txid, vout) tuples for our inputs
        txid: Transaction ID
        broadcast_method: How the tx was broadcast
        network: Network name
        success: Whether the CoinJoin succeeded
        failure_reason: Reason for failure if any

    Returns:
        TransactionHistoryEntry ready to be appended
    """
    now = datetime.now().isoformat()
    net_fee = -(total_maker_fees + mining_fee)  # Negative = cost

    return TransactionHistoryEntry(
        timestamp=now,
        completed_at=now,
        role="taker",
        success=success,
        failure_reason=failure_reason,
        txid=txid,
        cj_amount=cj_amount,
        peer_count=len(maker_nicks),
        counterparty_nicks=",".join(maker_nicks),
        total_maker_fees_paid=total_maker_fees,
        mining_fee_paid=mining_fee,
        net_fee=net_fee,
        source_mixdepth=source_mixdepth,
        destination_address=destination,
        utxos_used=",".join(f"{txid}:{vout}" for txid, vout in selected_utxos),
        broadcast_method=broadcast_method,
        network=network,
    )
