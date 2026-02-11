"""
UTXO metadata persistence using BIP-329 wallet labels export format.

Stores UTXO-level metadata (frozen state, labels) in a JSONL file where
each line is a BIP-329 record. This enables interoperability with external
wallets like Sparrow for coin control and labeling.

BIP-329 format (JSON Lines):
    {"type": "output", "ref": "txid:vout", "spendable": false}
    {"type": "output", "ref": "txid:vout", "label": "cold storage"}

The ``spendable`` field maps to frozen state:
    - ``spendable: false`` -> UTXO is frozen
    - ``spendable: true`` or absent -> UTXO is spendable (not frozen)

Reference: https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class OutputRecord:
    """A BIP-329 output record for UTXO metadata.

    Attributes:
        ref: Outpoint string in ``txid:vout`` format.
        spendable: Whether the UTXO is spendable. ``False`` means frozen.
            ``None`` means no opinion (importing wallet should not alter state).
        label: Optional human-readable label.
    """

    ref: str
    spendable: bool | None = None
    label: str | None = None

    @property
    def is_frozen(self) -> bool:
        """Whether this UTXO is frozen (not spendable)."""
        return self.spendable is False

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize to a BIP-329 JSON dict."""
        d: dict[str, str | bool] = {"type": "output", "ref": self.ref}
        if self.spendable is not None:
            d["spendable"] = self.spendable
        if self.label is not None:
            d["label"] = self.label
        return d

    @classmethod
    def from_dict(cls, d: dict[str, str | bool]) -> OutputRecord | None:
        """Deserialize from a BIP-329 JSON dict.

        Returns None if the record is not a valid output record.
        """
        if d.get("type") != "output":
            return None
        ref = d.get("ref")
        if not isinstance(ref, str):
            return None
        spendable = d.get("spendable")
        if spendable is not None and not isinstance(spendable, bool):
            return None
        label = d.get("label")
        if label is not None and not isinstance(label, str):
            label = str(label)
        return cls(ref=ref, spendable=spendable, label=label)


@dataclass
class UTXOMetadataStore:
    """In-memory store for UTXO metadata backed by a BIP-329 JSONL file.

    Thread-safety: This class is NOT thread-safe. If concurrent access is
    needed, external synchronization must be applied.

    Attributes:
        path: Path to the JSONL file on disk.
        records: Mapping from outpoint (``txid:vout``) to ``OutputRecord``.
    """

    path: Path
    records: dict[str, OutputRecord] = field(default_factory=dict)

    def load(self) -> None:
        """Load metadata from disk.

        Gracefully handles missing files, empty files, and malformed lines.
        Lines that cannot be parsed are logged and skipped.
        """
        self.records.clear()

        if not self.path.exists():
            logger.debug(f"No wallet metadata file at {self.path}")
            return

        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            logger.error(f"Failed to read wallet metadata: {e}")
            return

        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"Malformed JSON at {self.path}:{line_no}: {e}")
                continue

            record = OutputRecord.from_dict(data)
            if record is None:
                # Not an output record -- skip (BIP-329 says ignore unknown types)
                continue

            self.records[record.ref] = record

        frozen_count = sum(1 for r in self.records.values() if r.is_frozen)
        if self.records:
            logger.debug(
                f"Loaded {len(self.records)} UTXO metadata record(s) "
                f"({frozen_count} frozen) from {self.path}"
            )

    def save(self) -> None:
        """Persist all records to disk.

        Writes the entire file atomically (write to temp, then rename)
        to prevent corruption on crash.

        Raises:
            OSError: If the file cannot be written (e.g., read-only filesystem).
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Filter out records that carry no useful metadata
        records_to_write = [
            r for r in self.records.values() if r.spendable is not None or r.label is not None
        ]

        if not records_to_write:
            # No metadata to persist -- remove the file if it exists
            if self.path.exists():
                try:
                    self.path.unlink()
                    logger.debug("Removed empty wallet metadata file")
                except OSError as e:
                    logger.warning(f"Failed to remove empty metadata file: {e}")
                    raise
            return

        # Sort by ref for deterministic output
        records_to_write.sort(key=lambda r: r.ref)

        tmp_path = self.path.with_suffix(".tmp")
        try:
            lines = [json.dumps(r.to_dict(), separators=(",", ":")) for r in records_to_write]
            tmp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            tmp_path.replace(self.path)
        except OSError as e:
            logger.error(f"Failed to save wallet metadata: {e}")
            # Clean up temp file on failure
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def is_frozen(self, outpoint: str) -> bool:
        """Check if an outpoint is frozen.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Returns:
            True if the UTXO is frozen (spendable is False).
        """
        record = self.records.get(outpoint)
        return record is not None and record.is_frozen

    def get_frozen_outpoints(self) -> set[str]:
        """Get all frozen outpoints.

        Returns:
            Set of outpoint strings that are frozen.
        """
        return {ref for ref, record in self.records.items() if record.is_frozen}

    def freeze(self, outpoint: str) -> None:
        """Freeze a UTXO (set spendable to False) and persist.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.
        """
        if outpoint in self.records:
            self.records[outpoint].spendable = False
        else:
            self.records[outpoint] = OutputRecord(ref=outpoint, spendable=False)
        self.save()
        logger.info(f"Frozen UTXO: {outpoint}")

    def unfreeze(self, outpoint: str) -> None:
        """Unfreeze a UTXO (set spendable to True) and persist.

        If the record has no other metadata (no label), it is removed
        entirely since ``spendable=True`` is the default.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.
        """
        record = self.records.get(outpoint)
        if record is None:
            # Already unfrozen (no record means spendable)
            return

        if record.label is not None:
            # Keep the record for the label, just mark as spendable
            record.spendable = True
        else:
            # No other metadata -- remove entirely
            del self.records[outpoint]

        self.save()
        logger.info(f"Unfrozen UTXO: {outpoint}")

    def toggle_freeze(self, outpoint: str) -> bool:
        """Toggle the frozen state of a UTXO and persist.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Returns:
            True if the UTXO is now frozen, False if now unfrozen.
        """
        if self.is_frozen(outpoint):
            self.unfreeze(outpoint)
            return False
        else:
            self.freeze(outpoint)
            return True

    def set_label(self, outpoint: str, label: str | None) -> None:
        """Set or clear the label for a UTXO and persist.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.
            label: Label string, or None to clear.
        """
        if outpoint in self.records:
            self.records[outpoint].label = label
        elif label is not None:
            self.records[outpoint] = OutputRecord(ref=outpoint, label=label)
        else:
            return  # Nothing to do

        # Clean up record if it has no useful metadata
        record = self.records.get(outpoint)
        if record and record.spendable is None and record.label is None:
            del self.records[outpoint]

        self.save()

    def get_label(self, outpoint: str) -> str | None:
        """Get the label for an outpoint.

        Args:
            outpoint: Outpoint string in ``txid:vout`` format.

        Returns:
            Label string, or None if no label set.
        """
        record = self.records.get(outpoint)
        return record.label if record else None

    def verify_writable(self) -> None:
        """Verify that the metadata file's directory is writable.

        Attempts to create and immediately remove a temporary file in the
        same directory as the metadata file. This catches read-only mounts
        and permission issues early, before a real save attempt.

        Raises:
            OSError: If the directory is not writable.
        """
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        # Try creating a temp file in the target directory
        try:
            fd = tempfile.NamedTemporaryFile(dir=parent, prefix=".jm_write_test_", delete=True)
            fd.close()
        except OSError as e:
            raise OSError(
                f"Data directory is not writable: {parent}. "
                f"Cannot persist UTXO metadata (frozen state, labels). "
                f"Check mount permissions. Original error: {e}"
            ) from e


def load_metadata_store(data_dir: Path) -> UTXOMetadataStore:
    """Create and load a UTXOMetadataStore from the default metadata file.

    Args:
        data_dir: JoinMarket data directory (e.g., ``~/.joinmarket-ng``).

    Returns:
        Loaded UTXOMetadataStore instance.
    """
    from jmcore.paths import get_wallet_metadata_path

    path = get_wallet_metadata_path(data_dir)
    store = UTXOMetadataStore(path=path)
    store.load()
    return store
