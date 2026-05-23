"""Unit tests for the FR-06 two-field identity contract.

Spec: AC-08, I-06.
Tests the `declared_identity` / `authenticated_identity` FIELDS on `record()` —
NOT an `Identity` class (which is explicitly dropped in v1 per the Deviations
table in spec/SPEC_KRONO_PY_LIB.md). The contract under test is that the two
fields are preserved verbatim, never collapsed, swapped, or fallback-substituted.

UT-Names: UT-Identity-Distinct, UT-Identity-Both-None, UT-Identity-Both-Set.
"""

from __future__ import annotations

import json
from pathlib import Path

from krono.audit import AuditLog

from .conftest import make_record_kwargs, read_jsonl_lines


class TestIdentityDistinct:
    """UT-Identity-Distinct — declared set, authenticated None, both preserved."""

    def test_declared_set_authenticated_none(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(
            **make_record_kwargs(
                declared_identity="alice",
                authenticated_identity=None,
            )
        )
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["declared_identity"] == "alice"
        assert parsed["authenticated_identity"] is None

    def test_no_unknown_substitution(self, audit: AuditLog, log_path: Path) -> None:
        # The library MUST NOT substitute "unknown" for None.
        audit.record(
            **make_record_kwargs(
                declared_identity="alice",
                authenticated_identity=None,
            )
        )
        raw = log_path.read_text(encoding="utf-8")
        assert "unknown" not in raw.lower()

    def test_no_swap_on_authenticated_none(self, audit: AuditLog, log_path: Path) -> None:
        # When authenticated is None, the library MUST NOT fall back to declared.
        audit.record(
            **make_record_kwargs(
                declared_identity="alice",
                authenticated_identity=None,
            )
        )
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["authenticated_identity"] is None
        assert parsed["declared_identity"] == "alice"
        # And the two fields are NOT the same value.
        assert parsed["authenticated_identity"] != parsed["declared_identity"]


class TestIdentityBothNone:
    """UT-Identity-Both-None — both None → both serialized as JSON null."""

    def test_both_none_serialized_as_null(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(
            **make_record_kwargs(
                declared_identity=None,
                authenticated_identity=None,
            )
        )
        raw = log_path.read_text(encoding="utf-8")
        # Raw JSON must contain explicit nulls.
        assert '"declared_identity":null' in raw
        assert '"authenticated_identity":null' in raw

        parsed = json.loads(raw.strip())
        assert parsed["declared_identity"] is None
        assert parsed["authenticated_identity"] is None


class TestIdentityBothSet:
    """UT-Identity-Both-Set — both populated with distinct strings, preserved."""

    def test_both_set_distinct_values(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(
            **make_record_kwargs(
                declared_identity="claude-desktop",
                authenticated_identity="user-123",
            )
        )
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["declared_identity"] == "claude-desktop"
        assert parsed["authenticated_identity"] == "user-123"
        assert parsed["declared_identity"] != parsed["authenticated_identity"]

    def test_both_set_same_value_still_preserved(self, audit: AuditLog, log_path: Path) -> None:
        # Operator may legitimately pass the same value (e.g. CI bot identity);
        # the library must not deduplicate.
        audit.record(
            **make_record_kwargs(
                declared_identity="bot",
                authenticated_identity="bot",
            )
        )
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["declared_identity"] == "bot"
        assert parsed["authenticated_identity"] == "bot"


class TestIdentityEmptyStringVsNone:
    """Empty string and None are distinct identity values (FR-06)."""

    def test_empty_string_declared_distinct_from_none(
        self, audit: AuditLog, log_path: Path
    ) -> None:
        audit.record(
            **make_record_kwargs(
                declared_identity="",
                authenticated_identity=None,
            )
        )
        raw = log_path.read_text(encoding="utf-8")
        parsed = json.loads(raw.strip())
        assert parsed["declared_identity"] == ""
        assert parsed["authenticated_identity"] is None
        # And the raw JSON encodes the distinction.
        assert '"declared_identity":""' in raw
        assert '"authenticated_identity":null' in raw
