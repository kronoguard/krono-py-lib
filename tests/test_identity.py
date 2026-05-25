"""Unit tests for the FR-06 two-field identity contract.

Spec: AC-08, I-06; v0.2.0 adds FR-41/FR-42 — frozen ``Identity`` dataclass +
``record(identity=...)`` constructor-side convenience.

The FR-06 contract under test (top of file): the two ``declared_identity`` /
``authenticated_identity`` FIELDS on ``record()`` are preserved verbatim, never
collapsed, swapped, or fallback-substituted.

The FR-41/42 contract (bottom of file): ``Identity`` is a frozen dataclass and
``identity=`` is a constructor-side convenience — on-disk decomposition into
the same two string fields is byte-identical to the two-string path, and
``identity=`` is mutually exclusive with the per-field kwargs.

UT-Names: UT-Identity-Distinct, UT-Identity-Both-None, UT-Identity-Both-Set,
    UT-Identity-Dataclass, UT-Identity-Equivalence, UT-Identity-MutualExclusion.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from krono import Identity as PublicIdentity
from krono.audit import AuditLog
from krono.identity import Identity
from krono.verify import verify

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


# ---------------------------------------------------------------------------
# FR-41 — ``Identity`` dataclass basics
# ---------------------------------------------------------------------------


class TestIdentityDataclass:
    """UT-Identity-Dataclass — frozen, hashable, equal-by-value Identity."""

    def test_declared_only_defaults_authenticated_to_none(self) -> None:
        ident = Identity(declared="x")
        assert ident.declared == "x"
        assert ident.authenticated is None

    def test_both_fields_set(self) -> None:
        ident = Identity(declared="x", authenticated="y")
        assert ident.declared == "x"
        assert ident.authenticated == "y"

    def test_frozen_raises_on_assignment(self) -> None:
        ident = Identity(declared="x")
        with pytest.raises(dataclasses.FrozenInstanceError):
            ident.declared = "y"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            ident.authenticated = "z"  # type: ignore[misc]

    def test_equality_by_value(self) -> None:
        assert Identity("a", "b") == Identity("a", "b")
        # declared-only != declared+authenticated even when authenticated is "None-ish".
        assert Identity("a") != Identity("a", "b")
        assert Identity("a") == Identity("a", None)
        # different declared → not equal.
        assert Identity("a", "b") != Identity("c", "b")
        # different authenticated → not equal.
        assert Identity("a", "b") != Identity("a", "c")

    def test_hashable_usable_as_dict_key(self) -> None:
        a = Identity("client-1", "user-42")
        b = Identity("client-1", "user-42")  # equal but distinct instance
        bucket: dict[Identity, int] = {a: 1}
        # Equal Identities hash the same → second insert is an update, not new key.
        bucket[b] = 2
        assert bucket[a] == 2
        assert len(bucket) == 1
        # Also usable as a set member.
        s = {a, b, Identity("other", None)}
        assert len(s) == 2

    def test_repr_is_informative(self) -> None:
        # Dataclass-generated repr must include the class name and both field values.
        r = repr(Identity(declared="alice", authenticated="bob"))
        assert "Identity" in r
        assert "alice" in r
        assert "bob" in r
        assert "declared" in r
        assert "authenticated" in r

    def test_publicly_re_exported_as_krono_identity(self) -> None:
        # Re-exported symbol is the same class object (not a copy).
        assert PublicIdentity is Identity


# ---------------------------------------------------------------------------
# FR-41 — ``record(identity=...)`` is byte-identical to the two-string path
# ---------------------------------------------------------------------------


# Fields that vary by run/order regardless of identity-path choice — must be
# scrubbed before equating the two on-disk events.
_NONDETERMINISTIC_FIELDS: frozenset[str] = frozenset(
    {"event_id", "timestamp_utc", "current_hash", "previous_hash", "sequence_number"}
)


def _strip_nondeterministic(event: dict[str, object]) -> dict[str, object]:
    """Return a copy of ``event`` minus fields that vary across runs/orders."""
    return {k: v for k, v in event.items() if k not in _NONDETERMINISTIC_FIELDS}


class TestIdentityEquivalence:
    """UT-Identity-Equivalence — ``identity=`` decomposes to the same on-disk bytes."""

    def test_record_identity_kwarg_byte_identical_to_two_strings(
        self, key_env: str, tmp_path: Path
    ) -> None:
        """Entry A via ``identity=`` and entry B via the two strings differ ONLY in
        the run-varying fields (event_id, timestamp_utc, hashes, sequence)."""
        path_a = tmp_path / "a.jsonl"
        path_b = tmp_path / "b.jsonl"

        # Path A: pass an Identity.
        with AuditLog(path_a) as log_a:
            log_a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                identity=Identity(declared="client", authenticated="user-42"),
                reason="ok",
            )

        # Path B: pass the two strings.
        with AuditLog(path_b) as log_b:
            log_b.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                declared_identity="client",
                authenticated_identity="user-42",
                reason="ok",
            )

        ev_a = json.loads(path_a.read_text(encoding="utf-8").rstrip("\n"))
        ev_b = json.loads(path_b.read_text(encoding="utf-8").rstrip("\n"))

        # Both events have all 11 canonical fields.
        assert set(ev_a.keys()) == set(ev_b.keys())
        assert len(ev_a) == 11
        # Decomposition writes the same two top-level string fields.
        assert ev_a["declared_identity"] == "client" == ev_b["declared_identity"]
        assert ev_a["authenticated_identity"] == "user-42" == ev_b["authenticated_identity"]
        # All non-run-varying fields are byte-identical between the two paths.
        assert _strip_nondeterministic(ev_a) == _strip_nondeterministic(ev_b)

    def test_record_identity_authenticated_none_preserved_as_null(
        self, key_env: str, log_path: Path
    ) -> None:
        """``Identity(declared, authenticated=None)`` writes JSON ``null`` for
        ``authenticated_identity`` — never substitutes ``"unknown"``."""
        with AuditLog(log_path) as a:
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                identity=Identity(declared="client"),  # authenticated defaults to None
                reason="no-auth-boundary",
            )
        raw = log_path.read_text(encoding="utf-8")
        assert '"authenticated_identity":null' in raw
        assert "unknown" not in raw.lower()

    def test_alternating_paths_produce_valid_chain(self, key_env: str, log_path: Path) -> None:
        """Within ONE log, alternating ``identity=`` and the two-string kwargs
        produces a valid chain — proves decomposition does not perturb chain
        state."""
        with AuditLog(log_path) as a:
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"i": 0},
                identity=Identity("client", "user-1"),
            )
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"i": 1},
                declared_identity="client",
                authenticated_identity="user-1",
            )
            a.record(
                tool_name="read_note",
                decision="deny",
                arguments={"i": 2},
                identity=Identity("client", None),
            )
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"i": 3},
                declared_identity="client",
                authenticated_identity=None,
            )

        result = verify(log_path)
        assert result.ok is True
        assert result.entries_checked == 4
        assert result.failure is None


# ---------------------------------------------------------------------------
# FR-42 — mutual exclusion of ``identity=`` vs. the per-field kwargs
# ---------------------------------------------------------------------------


_FR42_MSG: str = "identity= is mutually exclusive with declared_identity=/authenticated_identity="


class TestIdentityMutualExclusion:
    """UT-Identity-MutualExclusion — FR-42 rejects mixed identity inputs, BEFORE
    any file work. The on-disk bytes must be unchanged after the TypeError."""

    def _bootstrap_with_existing_entry(self, log_path: Path) -> bytes:
        """Write one valid entry so the file is non-empty; return its bytes."""
        with AuditLog(log_path) as a:
            a.record(**make_record_kwargs(reason="seed"))
        return log_path.read_bytes()

    def test_identity_plus_declared_raises_typeerror_with_exact_message(
        self, key_env: str, log_path: Path
    ) -> None:
        before = self._bootstrap_with_existing_entry(log_path)
        before_size = log_path.stat().st_size

        with AuditLog(log_path) as a, pytest.raises(TypeError) as exc:
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                identity=Identity("a"),
                declared_identity="b",
            )

        # FR-42: exact error message.
        assert str(exc.value) == _FR42_MSG
        # File unchanged: same size, same bytes — proves the check fires BEFORE
        # any append.
        after = log_path.read_bytes()
        assert log_path.stat().st_size == before_size
        assert after == before

    def test_identity_plus_authenticated_raises_typeerror_with_exact_message(
        self, key_env: str, log_path: Path
    ) -> None:
        before = self._bootstrap_with_existing_entry(log_path)
        before_size = log_path.stat().st_size

        with AuditLog(log_path) as a, pytest.raises(TypeError) as exc:
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                identity=Identity("a"),
                authenticated_identity="b",
            )

        assert str(exc.value) == _FR42_MSG
        after = log_path.read_bytes()
        assert log_path.stat().st_size == before_size
        assert after == before

    def test_identity_plus_both_per_field_kwargs_raises_typeerror(
        self, key_env: str, log_path: Path
    ) -> None:
        before = self._bootstrap_with_existing_entry(log_path)
        before_size = log_path.stat().st_size

        with AuditLog(log_path) as a, pytest.raises(TypeError) as exc:
            a.record(
                tool_name="read_note",
                decision="allow",
                arguments={"id": "1"},
                identity=Identity("a"),
                declared_identity="b",
                authenticated_identity="c",
            )

        assert str(exc.value) == _FR42_MSG
        after = log_path.read_bytes()
        assert log_path.stat().st_size == before_size
        assert after == before

    def test_pre_mutual_exclusion_check_fires_before_other_validation(
        self, key_env: str, log_path: Path
    ) -> None:
        """Even if other args are also invalid (e.g. empty tool_name, bad
        decision), the TypeError takes precedence — the FR-42 check is the
        FIRST guard in record()."""
        before = self._bootstrap_with_existing_entry(log_path)

        with AuditLog(log_path) as a, pytest.raises(TypeError) as exc:
            a.record(
                tool_name="",  # would normally raise ValueError
                decision="bogus",  # would normally raise ValueError
                arguments={"id": "1"},
                identity=Identity("a"),
                declared_identity="b",
            )

        assert str(exc.value) == _FR42_MSG
        # File still unchanged.
        assert log_path.read_bytes() == before
