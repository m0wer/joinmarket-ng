"""
Tests for UTXO metadata persistence (BIP-329 JSONL format).

Tests cover:
- OutputRecord serialization/deserialization
- UTXOMetadataStore load/save with atomic writes
- Freeze/unfreeze/toggle operations
- Label management
- Edge cases: missing files, malformed lines, cleanup of empty records
- BIP-329 format compliance
"""

from __future__ import annotations

import json

import pytest

from jmwallet.wallet.utxo_metadata import OutputRecord, UTXOMetadataStore

# ---------------------------------------------------------------------------
# OutputRecord tests
# ---------------------------------------------------------------------------


class TestOutputRecord:
    """Tests for BIP-329 OutputRecord dataclass."""

    def test_basic_creation(self):
        """Create a record with just a ref."""
        r = OutputRecord(ref="aabb:0")
        assert r.ref == "aabb:0"
        assert r.spendable is None
        assert r.label is None
        assert r.is_frozen is False

    def test_frozen_record(self):
        """spendable=False means frozen."""
        r = OutputRecord(ref="aabb:0", spendable=False)
        assert r.is_frozen is True

    def test_spendable_record(self):
        """spendable=True means not frozen."""
        r = OutputRecord(ref="aabb:0", spendable=True)
        assert r.is_frozen is False

    def test_to_dict_minimal(self):
        """to_dict with only ref omits optional fields."""
        r = OutputRecord(ref="aabb:0")
        d = r.to_dict()
        assert d == {"type": "output", "ref": "aabb:0"}
        assert "spendable" not in d
        assert "label" not in d

    def test_to_dict_frozen(self):
        """to_dict includes spendable when set."""
        r = OutputRecord(ref="aabb:0", spendable=False)
        d = r.to_dict()
        assert d == {"type": "output", "ref": "aabb:0", "spendable": False}

    def test_to_dict_with_label(self):
        """to_dict includes label when set."""
        r = OutputRecord(ref="aabb:0", label="cold storage")
        d = r.to_dict()
        assert d == {"type": "output", "ref": "aabb:0", "label": "cold storage"}

    def test_to_dict_full(self):
        """to_dict with all fields."""
        r = OutputRecord(ref="aabb:0", spendable=False, label="frozen funds")
        d = r.to_dict()
        assert d == {
            "type": "output",
            "ref": "aabb:0",
            "spendable": False,
            "label": "frozen funds",
        }

    def test_from_dict_valid(self):
        """from_dict with valid output record."""
        d = {"type": "output", "ref": "aabb:0", "spendable": False, "label": "test"}
        r = OutputRecord.from_dict(d)
        assert r is not None
        assert r.ref == "aabb:0"
        assert r.spendable is False
        assert r.label == "test"

    def test_from_dict_minimal(self):
        """from_dict with only required fields."""
        d = {"type": "output", "ref": "aabb:0"}
        r = OutputRecord.from_dict(d)
        assert r is not None
        assert r.ref == "aabb:0"
        assert r.spendable is None
        assert r.label is None

    def test_from_dict_wrong_type(self):
        """from_dict returns None for non-output type."""
        d = {"type": "tx", "ref": "aabb"}
        assert OutputRecord.from_dict(d) is None

    def test_from_dict_missing_type(self):
        """from_dict returns None when type is missing."""
        d = {"ref": "aabb:0"}
        assert OutputRecord.from_dict(d) is None

    def test_from_dict_missing_ref(self):
        """from_dict returns None when ref is missing."""
        d = {"type": "output"}
        assert OutputRecord.from_dict(d) is None

    def test_from_dict_invalid_ref_type(self):
        """from_dict returns None when ref is not a string."""
        d = {"type": "output", "ref": 123}
        assert OutputRecord.from_dict(d) is None

    def test_from_dict_invalid_spendable_type(self):
        """from_dict returns None when spendable is not a bool."""
        d = {"type": "output", "ref": "aabb:0", "spendable": "yes"}
        assert OutputRecord.from_dict(d) is None

    def test_from_dict_coerces_label_to_str(self):
        """from_dict coerces non-string label to string."""
        d = {"type": "output", "ref": "aabb:0", "label": 42}
        r = OutputRecord.from_dict(d)
        assert r is not None
        assert r.label == "42"

    def test_roundtrip(self):
        """to_dict -> from_dict roundtrip preserves data."""
        original = OutputRecord(ref="aa" * 32 + ":1", spendable=False, label="test label")
        d = original.to_dict()
        restored = OutputRecord.from_dict(d)
        assert restored is not None
        assert restored.ref == original.ref
        assert restored.spendable == original.spendable
        assert restored.label == original.label


# ---------------------------------------------------------------------------
# UTXOMetadataStore tests
# ---------------------------------------------------------------------------


class TestUTXOMetadataStore:
    """Tests for UTXOMetadataStore persistence and operations."""

    @pytest.fixture
    def store_path(self, tmp_path):
        """Return a path for the metadata file in a temp directory."""
        return tmp_path / "wallet_metadata.jsonl"

    @pytest.fixture
    def store(self, store_path):
        """Create a fresh UTXOMetadataStore."""
        return UTXOMetadataStore(path=store_path)

    @pytest.fixture
    def outpoint_a(self):
        return "aa" * 32 + ":0"

    @pytest.fixture
    def outpoint_b(self):
        return "bb" * 32 + ":1"

    @pytest.fixture
    def outpoint_c(self):
        return "cc" * 32 + ":2"

    # --- Load/Save ---

    def test_load_missing_file(self, store):
        """Loading with no file on disk results in empty store."""
        store.load()
        assert len(store.records) == 0

    def test_save_and_load_roundtrip(self, store, outpoint_a):
        """Save records and load them back."""
        store.freeze(outpoint_a)
        # Create a new store and load from same path
        store2 = UTXOMetadataStore(path=store.path)
        store2.load()
        assert store2.is_frozen(outpoint_a)

    def test_save_creates_parent_dirs(self, tmp_path, outpoint_a):
        """Save creates parent directories if they don't exist."""
        deep_path = tmp_path / "a" / "b" / "c" / "metadata.jsonl"
        store = UTXOMetadataStore(path=deep_path)
        store.freeze(outpoint_a)
        assert deep_path.exists()

    def test_save_removes_file_when_empty(self, store, outpoint_a):
        """Save removes the file when no meaningful records remain."""
        store.freeze(outpoint_a)
        assert store.path.exists()
        store.unfreeze(outpoint_a)
        assert not store.path.exists()

    def test_load_skips_malformed_lines(self, store_path):
        """Malformed JSON lines are skipped during load."""
        store_path.write_text(
            '{"type":"output","ref":"aa:0","spendable":false}\n'
            "not valid json\n"
            '{"type":"output","ref":"bb:1","spendable":false}\n',
            encoding="utf-8",
        )
        store = UTXOMetadataStore(path=store_path)
        store.load()
        assert len(store.records) == 2
        assert store.is_frozen("aa:0")
        assert store.is_frozen("bb:1")

    def test_load_skips_non_output_records(self, store_path):
        """Non-output BIP-329 records are ignored (per spec)."""
        store_path.write_text(
            '{"type":"tx","ref":"aabb","label":"payment"}\n'
            '{"type":"output","ref":"cc:0","spendable":false}\n',
            encoding="utf-8",
        )
        store = UTXOMetadataStore(path=store_path)
        store.load()
        assert len(store.records) == 1
        assert store.is_frozen("cc:0")

    def test_load_skips_empty_lines(self, store_path):
        """Empty lines are gracefully skipped."""
        store_path.write_text(
            '\n\n{"type":"output","ref":"aa:0","spendable":false}\n\n',
            encoding="utf-8",
        )
        store = UTXOMetadataStore(path=store_path)
        store.load()
        assert len(store.records) == 1

    def test_load_last_wins_for_duplicate_outpoints(self, store_path):
        """When the same outpoint appears twice, the last record wins."""
        store_path.write_text(
            '{"type":"output","ref":"aa:0","spendable":false}\n'
            '{"type":"output","ref":"aa:0","spendable":true}\n',
            encoding="utf-8",
        )
        store = UTXOMetadataStore(path=store_path)
        store.load()
        assert not store.is_frozen("aa:0")

    def test_save_deterministic_order(self, store, outpoint_a, outpoint_b, outpoint_c):
        """Records are saved sorted by ref for deterministic output."""
        store.freeze(outpoint_c)
        store.freeze(outpoint_a)
        store.freeze(outpoint_b)

        text = store.path.read_text(encoding="utf-8")
        lines = [line for line in text.strip().split("\n") if line]
        refs = [json.loads(line)["ref"] for line in lines]
        assert refs == sorted(refs)

    def test_save_compact_json(self, store, outpoint_a):
        """Saved JSON uses compact separators (no spaces)."""
        store.freeze(outpoint_a)
        text = store.path.read_text(encoding="utf-8").strip()
        # Should not contain ": " or ", " patterns (compact separators)
        assert ": " not in text
        assert ", " not in text

    # --- Freeze / Unfreeze ---

    def test_freeze(self, store, outpoint_a):
        """Freezing an outpoint sets spendable=False."""
        store.freeze(outpoint_a)
        assert store.is_frozen(outpoint_a)

    def test_freeze_persists_immediately(self, store, outpoint_a):
        """Each freeze call writes to disk."""
        store.freeze(outpoint_a)
        assert store.path.exists()
        # Verify by loading a new store
        store2 = UTXOMetadataStore(path=store.path)
        store2.load()
        assert store2.is_frozen(outpoint_a)

    def test_freeze_already_frozen(self, store, outpoint_a):
        """Freezing an already frozen outpoint is a no-op (still frozen)."""
        store.freeze(outpoint_a)
        store.freeze(outpoint_a)
        assert store.is_frozen(outpoint_a)

    def test_unfreeze(self, store, outpoint_a):
        """Unfreezing a frozen outpoint removes the record (when no label)."""
        store.freeze(outpoint_a)
        assert store.is_frozen(outpoint_a)
        store.unfreeze(outpoint_a)
        assert not store.is_frozen(outpoint_a)
        # Record should be removed entirely (no label)
        assert outpoint_a not in store.records

    def test_unfreeze_with_label_keeps_record(self, store, outpoint_a):
        """Unfreezing preserves the record if it has a label."""
        store.records[outpoint_a] = OutputRecord(ref=outpoint_a, spendable=False, label="important")
        store.save()
        store.unfreeze(outpoint_a)
        assert not store.is_frozen(outpoint_a)
        # Record still exists for the label
        assert outpoint_a in store.records
        assert store.records[outpoint_a].label == "important"
        assert store.records[outpoint_a].spendable is True

    def test_unfreeze_not_frozen(self, store, outpoint_a):
        """Unfreezing an outpoint that was never frozen is a no-op."""
        store.unfreeze(outpoint_a)
        assert not store.is_frozen(outpoint_a)
        assert outpoint_a not in store.records

    # --- Toggle ---

    def test_toggle_freezes_unfrozen(self, store, outpoint_a):
        """Toggle on unfrozen outpoint freezes it."""
        result = store.toggle_freeze(outpoint_a)
        assert result is True
        assert store.is_frozen(outpoint_a)

    def test_toggle_unfreezes_frozen(self, store, outpoint_a):
        """Toggle on frozen outpoint unfreezes it."""
        store.freeze(outpoint_a)
        result = store.toggle_freeze(outpoint_a)
        assert result is False
        assert not store.is_frozen(outpoint_a)

    def test_toggle_roundtrip(self, store, outpoint_a):
        """Double toggle returns to original state."""
        store.toggle_freeze(outpoint_a)  # freeze
        store.toggle_freeze(outpoint_a)  # unfreeze
        assert not store.is_frozen(outpoint_a)

    # --- get_frozen_outpoints ---

    def test_get_frozen_outpoints_empty(self, store):
        """Empty store returns empty set."""
        assert store.get_frozen_outpoints() == set()

    def test_get_frozen_outpoints(self, store, outpoint_a, outpoint_b, outpoint_c):
        """Returns only frozen outpoints."""
        store.freeze(outpoint_a)
        store.freeze(outpoint_b)
        store.set_label(outpoint_c, "just a label")  # Not frozen, just labeled

        frozen = store.get_frozen_outpoints()
        assert frozen == {outpoint_a, outpoint_b}

    # --- Labels ---

    def test_set_label(self, store, outpoint_a):
        """Setting a label creates a record."""
        store.set_label(outpoint_a, "my label")
        assert store.get_label(outpoint_a) == "my label"

    def test_clear_label_removes_record_if_no_other_metadata(self, store, outpoint_a):
        """Clearing label removes the record if no freeze state is set."""
        store.set_label(outpoint_a, "test")
        store.set_label(outpoint_a, None)
        assert outpoint_a not in store.records

    def test_clear_label_keeps_frozen_state(self, store, outpoint_a):
        """Clearing label preserves frozen state."""
        store.records[outpoint_a] = OutputRecord(ref=outpoint_a, spendable=False, label="test")
        store.save()
        store.set_label(outpoint_a, None)
        # Record should still exist for the freeze
        assert outpoint_a in store.records
        assert store.is_frozen(outpoint_a)
        assert store.get_label(outpoint_a) is None

    def test_get_label_nonexistent(self, store, outpoint_a):
        """get_label returns None for unknown outpoints."""
        assert store.get_label(outpoint_a) is None

    # --- is_frozen ---

    def test_is_frozen_unknown_outpoint(self, store):
        """is_frozen returns False for unknown outpoints."""
        assert not store.is_frozen("nonexistent:0")

    def test_is_frozen_spendable_true(self, store, outpoint_a):
        """is_frozen returns False when spendable=True."""
        store.records[outpoint_a] = OutputRecord(ref=outpoint_a, spendable=True)
        assert not store.is_frozen(outpoint_a)

    def test_is_frozen_spendable_none(self, store, outpoint_a):
        """is_frozen returns False when spendable=None."""
        store.records[outpoint_a] = OutputRecord(ref=outpoint_a, spendable=None)
        assert not store.is_frozen(outpoint_a)


# ---------------------------------------------------------------------------
# BIP-329 format compliance
# ---------------------------------------------------------------------------


class TestBIP329Compliance:
    """Tests verifying BIP-329 format compliance."""

    def test_output_type_field(self):
        """Records always have type='output'."""
        r = OutputRecord(ref="aabb:0", spendable=False)
        assert r.to_dict()["type"] == "output"

    def test_ref_is_txid_colon_vout(self, tmp_path):
        """Outpoints follow txid:vout format."""
        store = UTXOMetadataStore(path=tmp_path / "meta.jsonl")
        outpoint = "ab" * 32 + ":42"
        store.freeze(outpoint)
        text = store.path.read_text(encoding="utf-8").strip()
        record = json.loads(text)
        assert record["ref"] == outpoint
        assert ":" in record["ref"]

    def test_spendable_false_means_frozen(self):
        """BIP-329 spendable=false maps to frozen."""
        d = {"type": "output", "ref": "aa:0", "spendable": False}
        r = OutputRecord.from_dict(d)
        assert r is not None
        assert r.is_frozen is True

    def test_spendable_absent_means_no_opinion(self):
        """BIP-329 absent spendable means wallet should not alter state."""
        d = {"type": "output", "ref": "aa:0", "label": "test"}
        r = OutputRecord.from_dict(d)
        assert r is not None
        assert r.spendable is None
        assert r.is_frozen is False

    def test_jsonl_format_one_record_per_line(self, tmp_path):
        """Each record is on its own line (JSONL format)."""
        store = UTXOMetadataStore(path=tmp_path / "meta.jsonl")
        store.freeze("aa:0")
        store.freeze("bb:1")
        text = store.path.read_text(encoding="utf-8")
        lines = [line for line in text.strip().split("\n") if line]
        assert len(lines) == 2
        for line in lines:
            record = json.loads(line)
            assert record["type"] == "output"

    def test_interop_with_sparrow_format(self, tmp_path):
        """Verify format is compatible with Sparrow wallet's BIP-329 export."""
        # Sparrow exports labels like:
        # {"type":"output","ref":"txid:vout","label":"Label Text","spendable":false}
        sparrow_line = (
            '{"type":"output","ref":"' + "ab" * 32 + ':0","label":"My UTXO","spendable":false}'
        )
        path = tmp_path / "sparrow_export.jsonl"
        path.write_text(sparrow_line + "\n", encoding="utf-8")

        store = UTXOMetadataStore(path=path)
        store.load()

        outpoint = "ab" * 32 + ":0"
        assert store.is_frozen(outpoint)
        assert store.get_label(outpoint) == "My UTXO"


# ---------------------------------------------------------------------------
# Error handling and writability tests
# ---------------------------------------------------------------------------


class TestSaveErrorPropagation:
    """Tests that save() failures propagate to callers."""

    @pytest.fixture
    def readonly_store(self, tmp_path):
        """Create a store in a directory that will be made read-only."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        return store

    @pytest.fixture
    def outpoint(self):
        return "aa" * 32 + ":0"

    def test_save_raises_on_readonly_directory(self, tmp_path, outpoint):
        """save() raises OSError when directory is read-only."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        # Make directory read-only
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError):
                store.freeze(outpoint)
        finally:
            # Restore permissions for cleanup
            tmp_path.chmod(0o755)

    def test_freeze_propagates_save_error(self, tmp_path, outpoint):
        """freeze() propagates OSError from save()."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError):
                store.freeze(outpoint)
            # In-memory state may have changed, but disk is unchanged
        finally:
            tmp_path.chmod(0o755)

    def test_unfreeze_propagates_save_error(self, tmp_path, outpoint):
        """unfreeze() propagates OSError from save()."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        # First, freeze successfully
        store.freeze(outpoint)
        assert store.is_frozen(outpoint)
        # Now make read-only
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError):
                store.unfreeze(outpoint)
        finally:
            tmp_path.chmod(0o755)

    def test_toggle_freeze_propagates_save_error(self, tmp_path, outpoint):
        """toggle_freeze() propagates OSError from save()."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError):
                store.toggle_freeze(outpoint)
        finally:
            tmp_path.chmod(0o755)

    def test_set_label_propagates_save_error(self, tmp_path, outpoint):
        """set_label() propagates OSError from save()."""
        path = tmp_path / "metadata.jsonl"
        store = UTXOMetadataStore(path=path)
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError):
                store.set_label(outpoint, "test label")
        finally:
            tmp_path.chmod(0o755)


class TestVerifyWritable:
    """Tests for verify_writable() method."""

    def test_writable_directory_passes(self, tmp_path):
        """verify_writable() succeeds on a writable directory."""
        store = UTXOMetadataStore(path=tmp_path / "metadata.jsonl")
        store.verify_writable()  # Should not raise

    def test_readonly_directory_raises(self, tmp_path):
        """verify_writable() raises OSError on read-only directory."""
        store = UTXOMetadataStore(path=tmp_path / "metadata.jsonl")
        tmp_path.chmod(0o555)
        try:
            with pytest.raises(OSError, match="not writable"):
                store.verify_writable()
        finally:
            tmp_path.chmod(0o755)

    def test_creates_parent_dirs(self, tmp_path):
        """verify_writable() creates parent directories if needed."""
        deep_path = tmp_path / "a" / "b" / "metadata.jsonl"
        store = UTXOMetadataStore(path=deep_path)
        store.verify_writable()
        assert deep_path.parent.exists()

    def test_nonexistent_parent_readonly(self, tmp_path):
        """verify_writable() raises when parent can't be created."""
        # Make tmp_path read-only so mkdir fails
        tmp_path.chmod(0o555)
        deep_path = tmp_path / "newdir" / "metadata.jsonl"
        store = UTXOMetadataStore(path=deep_path)
        try:
            with pytest.raises(OSError):
                store.verify_writable()
        finally:
            tmp_path.chmod(0o755)
