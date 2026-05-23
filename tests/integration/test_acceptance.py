"""Integration tests — the v1 release gate (source-req §17 acceptance script).

Spec: AC-17, AC-18, AC-23, AC-30.

This file is the v1 ship gate. All three IT-Acceptance-* tests must pass in
one `pytest tests/integration/test_acceptance.py` invocation.

UT-Names: IT-Acceptance-A, IT-Acceptance-B, IT-Acceptance-C.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from krono._canonical import canonical_json
from krono.audit import AuditLog
from krono.verify import FailureKind, verify

# Re-import the conftest helpers from the parent test package.
from tests.conftest import make_record_kwargs, read_jsonl_lines

# ---------------------------------------------------------------------------
# Fixtures local to integration suite — explicit so subprocess-style tests in
# sibling files don't depend on the parent's fixtures by accident.
# ---------------------------------------------------------------------------


_TEST_KEY_HEX = "00112233445566778899aabbccddeeff" * 2  # 64 chars = 32 bytes


@pytest.fixture
def acc_env(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("KRONO_AUDIT_KEY", _TEST_KEY_HEX)
    return _TEST_KEY_HEX


@pytest.fixture
def acc_log(tmp_path: Path) -> Path:
    return tmp_path / "acceptance.jsonl"


def _rewrite(path: Path, events: list[dict[str, object]]) -> None:
    body = b""
    for ev in events:
        body += canonical_json(ev) + b"\n"
    path.write_bytes(body)


# ---------------------------------------------------------------------------
# IT-Acceptance-A — last-entry content tampering (the mcp-firewall miss)
# ---------------------------------------------------------------------------


class TestAcceptanceA:
    """IT-Acceptance-A — Attack A: mutate final `"decision":"deny"` → `"allow"`."""

    def test_last_entry_decision_flipped_caught(self, acc_env: str, acc_log: Path) -> None:
        # Arrange — 2 events: one allow, one deny.
        with AuditLog(acc_log) as a:
            a.record(**make_record_kwargs(decision="allow", reason="read"))
            a.record(**make_record_kwargs(decision="deny", reason="blocked delete"))

        # Mutate the final entry's decision.
        events = [json.loads(line) for line in read_jsonl_lines(acc_log)]
        assert events[1]["decision"] == "deny"
        events[1]["decision"] = "allow"
        _rewrite(acc_log, events)

        # Act
        result = verify(acc_log)

        # Assert — the mcp-firewall miss: verify catches it.
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CONTENT_TAMPERED
        assert result.failure.sequence_number == 1


# ---------------------------------------------------------------------------
# IT-Acceptance-B — middle-entry deletion → deterministic SEQUENCE_GAP
# ---------------------------------------------------------------------------


class TestAcceptanceB:
    """IT-Acceptance-B — Attack B: delete a middle entry; FR-37 tightens to
    deterministic SEQUENCE_GAP (source-req §17 phrased it as "either kind")."""

    def test_middle_delete_yields_sequence_gap(self, acc_env: str, acc_log: Path) -> None:
        # Arrange — 3 events.
        with AuditLog(acc_log) as a:
            for i in range(3):
                a.record(**make_record_kwargs(reason=f"event {i}"))

        events = [json.loads(line) for line in read_jsonl_lines(acc_log)]
        assert len(events) == 3
        # Delete the middle entry.
        events_tampered = [events[0], events[2]]
        _rewrite(acc_log, events_tampered)

        # Act
        result = verify(acc_log)

        # Assert — deterministic per FR-37 (sequence check fires before chain check).
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.SEQUENCE_GAP, (
            f"FR-37 tightens source-req §17 to SEQUENCE_GAP exactly; got {result.failure.kind!r}"
        )


# ---------------------------------------------------------------------------
# IT-Acceptance-C — tail truncation NOT detected (the honest claim)
# ---------------------------------------------------------------------------


class TestAcceptanceC:
    """IT-Acceptance-C — Attack C: tail-truncate to keep only the first entry;
    `verify()` returns `ok=True`. This is the documented v1 limit (FR-23)."""

    def test_tail_truncation_returns_ok_true(self, acc_env: str, acc_log: Path) -> None:
        # Arrange — 3 events, then truncate to keep only the first.
        with AuditLog(acc_log) as a:
            for i in range(3):
                a.record(**make_record_kwargs(reason=f"event {i}"))

        events = [json.loads(line) for line in read_jsonl_lines(acc_log)]
        _rewrite(acc_log, [events[0]])

        # Act
        result = verify(acc_log)

        # Assert — the honest claim: this is undetected.
        assert result.ok is True, (
            "tail truncation MUST return ok=True per FR-23 / AC-23; "
            "over-claiming detection here is a v1 release-gate failure"
        )
        assert result.entries_checked == 1
        assert result.failure is None


# ---------------------------------------------------------------------------
# IT-Acceptance-Full is not a separate function — it is the umbrella label
# meaning "all three above pass in one invocation". The file's pytest exit
# code is the v1 release gate (per spec § Required Tests note).
# ---------------------------------------------------------------------------
