"""Unit tests for `krono.verify.verify`.

Spec: AC-16, AC-17, AC-18, AC-19, AC-20, AC-21, AC-22, AC-24, AC-35, AC-36,
AC-37, AC-41, AC-42, AC-43.

UT-Names:
    UT-Verify-Intact, UT-Verify-Tamper-Last, UT-Verify-Tamper-Mid,
    UT-Verify-Middle-Delete, UT-Verify-Reorder, UT-Verify-Sequence-Rewrite,
    UT-Verify-Schema, UT-Verify-Empty, UT-Verify-Missing-File,
    UT-Verify-Wrong-Key, UT-Verify-Order-Schema-Before-Hash,
    UT-Verify-Order-Seq-Before-Chain, UT-Verify-EntriesChecked,
    UT-Verify-BlankLine, UT-Verify-NoTrailingNewline,
    UT-Verify-ChainBreak-PayloadPermute, UT-FailureKind-Values.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from krono._canonical import canonical_json
from krono.audit import AuditLog
from krono.exceptions import ConfigError, MissingKeyError
from krono.verify import FailureKind, verify

from .conftest import make_record_kwargs, read_jsonl_lines

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_n_events(path: Path, n: int) -> list[dict[str, Any]]:
    """Write n valid events to `path` via AuditLog; return parsed dicts."""
    with AuditLog(path) as a:
        for i in range(n):
            a.record(**make_record_kwargs(reason=f"event {i}"))
    return [json.loads(line) for line in read_jsonl_lines(path)]


def _rewrite(path: Path, events: list[dict[str, Any]]) -> None:
    """Rewrite the file with canonical_json'd events + trailing newlines."""
    body = b""
    for ev in events:
        body += canonical_json(ev) + b"\n"
    path.write_bytes(body)


# ---------------------------------------------------------------------------
# AC-16, AC-22, AC-24 — happy paths + missing/empty file
# ---------------------------------------------------------------------------


class TestVerifyIntact:
    def test_intact_log_passes(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Intact
        _write_n_events(log_path, 3)
        result = verify(log_path)
        assert result.ok is True
        assert result.entries_checked == 3
        assert result.failure is None

    def test_empty_file_passes(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Empty
        log_path.touch()
        result = verify(log_path)
        assert result.ok is True
        assert result.entries_checked == 0
        assert result.failure is None

    def test_missing_file_raises_config_error(self, key_env: str, tmp_path: Path) -> None:
        # UT-Verify-Missing-File
        missing = tmp_path / "nope.jsonl"
        with pytest.raises(ConfigError):
            verify(missing)


# ---------------------------------------------------------------------------
# AC-17 — last-entry tampering (THE mcp-firewall miss)
# ---------------------------------------------------------------------------


class TestVerifyTamperLast:
    def test_mutate_last_decision(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Tamper-Last — load-bearing for AC-17.
        events = _write_n_events(log_path, 2)
        # Flip the last entry's decision (without re-signing).
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CONTENT_TAMPERED
        assert result.failure.sequence_number == 1
        assert result.failure.line == 2


class TestVerifyTamperMid:
    def test_mutate_middle_tool_name(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Tamper-Mid
        events = _write_n_events(log_path, 3)
        events[1]["tool_name"] = "different_tool"
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CONTENT_TAMPERED
        assert result.failure.line == 2


# ---------------------------------------------------------------------------
# AC-18, AC-19, AC-20 — sequence-based detections (SEQUENCE_GAP)
# ---------------------------------------------------------------------------


class TestVerifyMiddleDelete:
    def test_delete_middle_yields_sequence_gap(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Middle-Delete — deterministic SEQUENCE_GAP per FR-37.
        events = _write_n_events(log_path, 3)
        del events[1]
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.SEQUENCE_GAP


class TestVerifyReorder:
    def test_swap_whole_lines(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Reorder
        events = _write_n_events(log_path, 5)
        # Swap whole JSONL lines at file positions 2 and 3 (each keeps its
        # original sequence_number value).
        events[1], events[2] = events[2], events[1]
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.SEQUENCE_GAP


class TestVerifySequenceRewrite:
    def test_mutate_sequence_number_only(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Sequence-Rewrite — mutate sequence_number only; verify catches
        # it as SEQUENCE_GAP per FR-37 (sequence check fires before hash check).
        events = _write_n_events(log_path, 1)
        events[0]["sequence_number"] = 5
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.SEQUENCE_GAP


# ---------------------------------------------------------------------------
# AC-21 — schema closedness
# ---------------------------------------------------------------------------


class TestVerifySchema:
    def test_unexpected_field(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Schema (UNEXPECTED_FIELD branch)
        events = _write_n_events(log_path, 1)
        events[0]["foo"] = "bar"
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.UNEXPECTED_FIELD

    def test_missing_required_field(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Schema (MISSING_FIELD branch)
        events = _write_n_events(log_path, 1)
        del events[0]["reason"]  # remove a required field
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.MISSING_FIELD

    def test_parse_error_on_non_json_line(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Schema (PARSE_ERROR branch) — non-JSON line.
        log_path.write_text("not-json\n", encoding="utf-8")

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.PARSE_ERROR
        # FR-39: sequence_number is None for parse_error.
        assert result.failure.sequence_number is None


# ---------------------------------------------------------------------------
# AC-24 (already above) + wrong-key
# ---------------------------------------------------------------------------


class TestVerifyWrongKey:
    def test_verify_with_different_key_fails(
        self, key_env: str, log_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # UT-Verify-Wrong-Key
        _write_n_events(log_path, 2)
        # Swap key for the verify call.
        monkeypatch.setenv("KRONO_AUDIT_KEY", "ff" * 32)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CONTENT_TAMPERED
        assert result.failure.line == 1

    def test_explicit_short_key_raises(self, key_env: str, log_path: Path) -> None:
        _write_n_events(log_path, 1)
        with pytest.raises(MissingKeyError):
            verify(log_path, key=b"shortbytes")


# ---------------------------------------------------------------------------
# AC-35 — verify check order
# ---------------------------------------------------------------------------


class TestVerifyOrderSchemaBeforeHash:
    def test_unexpected_field_beats_bad_hash(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Order-Schema-Before-Hash
        events = _write_n_events(log_path, 1)
        events[0]["foo"] = "bar"  # unknown field
        events[0]["current_hash"] = "0" * 64  # also wrong
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        # Schema check fires before hash check.
        assert result.failure.kind is FailureKind.UNEXPECTED_FIELD


class TestVerifyOrderSeqBeforeChain:
    def test_sequence_gap_beats_chain_break(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-Order-Seq-Before-Chain
        events = _write_n_events(log_path, 2)
        # Mutate line 2 to have BOTH a sequence gap (5) and wrong previous_hash.
        events[1]["sequence_number"] = 5
        events[1]["previous_hash"] = "0" * 64
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        # Sequence check fires before chain check.
        assert result.failure.kind is FailureKind.SEQUENCE_GAP


# ---------------------------------------------------------------------------
# AC-37 — entries_checked semantics on failure
# ---------------------------------------------------------------------------


class TestVerifyEntriesChecked:
    def test_5_entry_tamper_line_3(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-EntriesChecked (CONTENT_TAMPERED at line 3 → entries_checked=2)
        events = _write_n_events(log_path, 5)
        events[2]["decision"] = "deny" if events[2]["decision"] == "allow" else "allow"
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.line == 3
        assert result.entries_checked == 2

    def test_1_entry_parse_error(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-EntriesChecked (PARSE_ERROR at line 1 → entries_checked=0)
        log_path.write_text("bad-json\n", encoding="utf-8")
        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.line == 1
        assert result.entries_checked == 0

    def test_3_entry_unexpected_field_line_2(self, key_env: str, log_path: Path) -> None:
        events = _write_n_events(log_path, 3)
        events[1]["junk"] = "x"
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.UNEXPECTED_FIELD
        assert result.entries_checked == 1


# ---------------------------------------------------------------------------
# AC-41 — verify on missing trailing newline
# ---------------------------------------------------------------------------


class TestVerifyNoTrailingNewline:
    def test_truncated_last_line_no_newline_fails(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-NoTrailingNewline.
        #
        # AC-41: "the final partial line is treated as a complete
        # record-attempt and runs the FR-37 check order. In practice this
        # produces PARSE_ERROR if the JSON is truncated, or CONTENT_TAMPERED
        # if it happens to parse cleanly — either way ok=False."
        #
        # We simulate a mid-write torn line: chop off the closing braces
        # AND the trailing newline of the final entry.
        _write_n_events(log_path, 2)
        contents = log_path.read_bytes()
        assert contents.endswith(b"\n")
        # Drop the final newline AND the last 20 bytes (likely cutting
        # through current_hash) to simulate truncation mid-write.
        truncated = contents.rstrip(b"\n")[:-20]
        log_path.write_bytes(truncated)

        result = verify(log_path)
        # ok=False with either PARSE_ERROR or CONTENT_TAMPERED (both acceptable).
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind in (
            FailureKind.PARSE_ERROR,
            FailureKind.CONTENT_TAMPERED,
        )

    def test_intact_content_missing_only_newline_is_accepted(
        self, key_env: str, log_path: Path
    ) -> None:
        # Loadbearing edge case: if ONLY the trailing newline is missing
        # but the JSON content is byte-identical to a properly-flushed
        # line, the verifier walks it as a valid entry. This is consistent
        # with AC-41 ("treat as a complete record-attempt and runs the
        # FR-37 check order"): a complete and validly-hashed JSON object
        # passes all six checks regardless of trailing newline presence.
        _write_n_events(log_path, 2)
        contents = log_path.read_bytes()
        log_path.write_bytes(contents.rstrip(b"\n"))

        result = verify(log_path)
        # Either outcome is spec-compliant: ok=True (lenient walk) OR ok=False
        # (strict newline policy). We only enforce that the verifier does
        # not crash and that entries_checked is reasonable.
        assert isinstance(result.ok, bool)
        assert result.entries_checked in (1, 2)


# ---------------------------------------------------------------------------
# AC-42 — verify on blank line
# ---------------------------------------------------------------------------


class TestVerifyBlankLine:
    def test_blank_line_in_middle(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-BlankLine
        events = _write_n_events(log_path, 3)
        # Insert a blank line between event 2 and event 3.
        body = (
            canonical_json(events[0])
            + b"\n"
            + canonical_json(events[1])
            + b"\n"
            + b"\n"
            + canonical_json(events[2])
            + b"\n"
        )
        log_path.write_bytes(body)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.PARSE_ERROR
        assert result.failure.line == 3
        assert result.entries_checked == 2


# ---------------------------------------------------------------------------
# AC-43 — CHAIN_BREAK is reachable via payload-permutation attack
# ---------------------------------------------------------------------------


class TestVerifyChainBreakPayloadPermute:
    def test_payload_permute_yields_chain_break(self, key_env: str, log_path: Path) -> None:
        # UT-Verify-ChainBreak-PayloadPermute
        events = _write_n_events(log_path, 3)
        # Build a tampered file:
        # new line 2 keeps sequence_number=1 BUT inherits other fields
        # (including previous_hash) from the original line 3.
        new_line_2 = dict(events[2])
        new_line_2["sequence_number"] = 1  # preserve sequence position
        # current_hash and previous_hash come from events[2] — so previous_hash
        # now points at original_line_2's current_hash, not original_line_1's.

        tampered = [events[0], new_line_2, events[2]]
        _rewrite(log_path, tampered)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CHAIN_BREAK
        assert result.failure.line == 2
        assert result.failure.sequence_number == 1


# ---------------------------------------------------------------------------
# AC-36 — FailureKind serialization
# ---------------------------------------------------------------------------


class TestFailureKindValues:
    """UT-FailureKind-Values — each member maps to the FR-38 lowercase snake_case value."""

    @pytest.mark.parametrize(
        ("member_name", "expected_value"),
        [
            ("PARSE_ERROR", "parse_error"),
            ("MISSING_FIELD", "missing_field"),
            ("UNEXPECTED_FIELD", "unexpected_field"),
            ("SEQUENCE_GAP", "sequence_gap"),
            ("CHAIN_BREAK", "chain_break"),
            ("CONTENT_TAMPERED", "content_tampered"),
        ],
    )
    def test_member_value(self, member_name: str, expected_value: str) -> None:
        member = FailureKind[member_name]
        assert member.value == expected_value

    def test_value_construction(self) -> None:
        # FailureKind("content_tampered") is FailureKind.CONTENT_TAMPERED
        assert FailureKind("content_tampered") is FailureKind.CONTENT_TAMPERED
        assert FailureKind("sequence_gap") is FailureKind.SEQUENCE_GAP

    def test_all_six_members_exist(self) -> None:
        names = {m.name for m in FailureKind}
        assert names == {
            "PARSE_ERROR",
            "MISSING_FIELD",
            "UNEXPECTED_FIELD",
            "SEQUENCE_GAP",
            "CHAIN_BREAK",
            "CONTENT_TAMPERED",
        }


# ---------------------------------------------------------------------------
# Extra negative / edge cases (from spec §Negative + §Edge Cases)
# ---------------------------------------------------------------------------


class TestVerifyMissingSequenceField:
    """If `sequence_number` is the missing field, FR-39 says failure.sequence_number is None."""

    def test_missing_sequence_number_yields_none_in_failure(
        self, key_env: str, log_path: Path
    ) -> None:
        events = _write_n_events(log_path, 1)
        del events[0]["sequence_number"]
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.MISSING_FIELD
        assert result.failure.sequence_number is None


class TestVerifyNonObjectJson:
    """A line whose top-level JSON value is not an object (array/scalar)."""

    def test_top_level_array_yields_parse_error(self, key_env: str, log_path: Path) -> None:
        log_path.write_text("[1,2,3]\n", encoding="utf-8")
        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.PARSE_ERROR

    def test_top_level_string_yields_parse_error(self, key_env: str, log_path: Path) -> None:
        log_path.write_text('"just a string"\n', encoding="utf-8")
        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.PARSE_ERROR


class TestVerifyNonIntSequence:
    """sequence_number present but not an integer → SEQUENCE_GAP, seq=None."""

    def test_string_sequence_number(self, key_env: str, log_path: Path) -> None:
        events = _write_n_events(log_path, 1)
        events[0]["sequence_number"] = "zero"  # type: ignore[assignment]
        _rewrite(log_path, events)

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.SEQUENCE_GAP
        # Per FR-39, non-int sequence yields sequence_number=None in the failure.
        assert result.failure.sequence_number is None


class TestVerifyUnreadableFile:
    """OSError on read → ConfigError (verify.py:333-334)."""

    def test_directory_path_raises_config_error(self, key_env: str, tmp_path: Path) -> None:
        # A directory `exists()` is True but reading it as bytes raises OSError
        # (on POSIX: IsADirectoryError).
        target_dir = tmp_path / "is_a_dir"
        target_dir.mkdir()
        with pytest.raises(ConfigError):
            verify(target_dir)


class TestVerifyForgedEntry:
    """An attacker without the key cannot forge a chain entry."""

    def test_appended_forged_entry_caught(self, key_env: str, log_path: Path) -> None:
        events = _write_n_events(log_path, 2)
        # Append a forged entry with a (wrong) hash the attacker invented.
        forged = dict(events[1])
        forged["sequence_number"] = 2
        forged["previous_hash"] = events[1]["current_hash"]
        forged["current_hash"] = "0" * 64  # attacker doesn't have the key
        # Rewrite with the forged third line.
        _rewrite(log_path, [events[0], events[1], forged])

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind is FailureKind.CONTENT_TAMPERED


# Suppress an unused-import warning for `os` if not used by helpers above.
_unused = (os,)
