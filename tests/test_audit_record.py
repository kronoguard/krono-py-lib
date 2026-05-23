"""Unit tests for `krono.audit.AuditLog`.

Spec: covers AC-01, AC-04, AC-05, AC-06, AC-07, AC-09, AC-11, AC-12, AC-13,
AC-14, AC-15, AC-38, AC-39, AC-40, AC-02, AC-03.

UT-Names:
    UT-AuditLog-Init, UT-Key-Missing, UT-Key-Short, UT-Record-First,
    UT-Record-Chain, UT-Decision-Coerce, UT-Args-Hash, UT-Timestamp-EventId,
    UT-Record-IOError, UT-Fsync-Toggle, UT-Close-Idempotent,
    UT-Resume-Valid, UT-Resume-Torn, UT-Resume-NoVerify,
    UT-AuditLog-Init-NotWritable, UT-Record-After-Close,
    UT-Record-Validation, UT-AuditEvent-Shape, UT-AuditEvent-RoundTrip.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from krono._canonical import canonical_json
from krono.audit import AuditLog
from krono.events import AuditEvent, Decision
from krono.exceptions import ConfigError, MissingKeyError, WriteError
from krono.verify import verify

from .conftest import make_record_kwargs, read_jsonl_lines

# ---------------------------------------------------------------------------
# AC-01, AC-02, AC-03 — construction + key validation
# ---------------------------------------------------------------------------


class TestAuditLogInit:
    """UT-AuditLog-Init, UT-Key-Missing, UT-Key-Short, UT-AuditLog-Init-NotWritable."""

    def test_fresh_construction_creates_zero_byte_file(self, key_env: str, log_path: Path) -> None:
        # Arrange: log_path does not exist.
        assert not log_path.exists()

        # Act
        a = AuditLog(log_path)
        try:
            # Assert: eager open created an empty file.
            assert log_path.exists()
            assert log_path.stat().st_size == 0
        finally:
            a.close()

    def test_missing_key_raises_and_creates_no_file(self, unset_key: None, log_path: Path) -> None:
        with pytest.raises(MissingKeyError):
            AuditLog(log_path)
        # FR-02 ordering: no file created before key validation.
        assert not log_path.exists()

    def test_short_key_raises_missing_key_error(
        self, monkeypatch: pytest.MonkeyPatch, log_path: Path
    ) -> None:
        # 31 bytes = 62 hex chars
        monkeypatch.setenv("KRONO_AUDIT_KEY", "ab" * 31)
        with pytest.raises(MissingKeyError):
            AuditLog(log_path)
        assert not log_path.exists()

    def test_non_hex_key_raises_missing_key_error(
        self, monkeypatch: pytest.MonkeyPatch, log_path: Path
    ) -> None:
        monkeypatch.setenv("KRONO_AUDIT_KEY", "ZZ" * 32)
        with pytest.raises(MissingKeyError):
            AuditLog(log_path)
        assert not log_path.exists()

    def test_exactly_32_bytes_accepted(
        self, monkeypatch: pytest.MonkeyPatch, log_path: Path
    ) -> None:
        monkeypatch.setenv("KRONO_AUDIT_KEY", "ab" * 32)  # 32 raw bytes
        a = AuditLog(log_path)
        try:
            assert log_path.exists()
        finally:
            a.close()

    def test_explicit_key_bytes(self, log_path: Path, unset_key: None) -> None:
        # Explicit `key=` argument bypasses env lookup.
        a = AuditLog(log_path, key=b"\x00" * 32)
        try:
            assert log_path.exists()
        finally:
            a.close()

    def test_explicit_short_key_rejected(self, log_path: Path, unset_key: None) -> None:
        with pytest.raises(MissingKeyError):
            AuditLog(log_path, key=b"\x00" * 31)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod-based unwritable parent dir not reliable on Windows",
    )
    def test_unwritable_parent_dir_raises_config_error(self, key_env: str, tmp_path: Path) -> None:
        # UT-AuditLog-Init-NotWritable
        unwritable = tmp_path / "ro"
        unwritable.mkdir()
        os.chmod(unwritable, 0o500)  # r-x — no write
        target = unwritable / "audit.jsonl"
        try:
            with pytest.raises(ConfigError):
                AuditLog(target)
            assert not target.exists()
        finally:
            os.chmod(unwritable, 0o700)  # restore so cleanup works

    def test_missing_parent_dir_raises_config_error(self, key_env: str, tmp_path: Path) -> None:
        target = tmp_path / "does-not-exist" / "audit.jsonl"
        with pytest.raises(ConfigError):
            AuditLog(target)
        assert not target.exists()


# ---------------------------------------------------------------------------
# AC-04, AC-05 — record sequence + chain
# ---------------------------------------------------------------------------


class TestRecordChain:
    def test_record_first_writes_one_line(self, audit: AuditLog, log_path: Path) -> None:
        # UT-Record-First
        ev = audit.record(**make_record_kwargs())

        # exactly one line
        lines = read_jsonl_lines(log_path)
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["sequence_number"] == 0
        assert parsed["previous_hash"] == "genesis"
        assert parsed["decision"] == "allow"

        # current_hash re-validates: recompute and compare.
        key = bytes.fromhex(os.environ["KRONO_AUDIT_KEY"])
        recomputed = _recompute_hash(parsed, key)
        assert recomputed == parsed["current_hash"]

        # Returned dataclass mirrors the line.
        assert isinstance(ev, AuditEvent)
        assert ev.sequence_number == 0
        assert ev.previous_hash == "genesis"

    def test_record_chain(self, audit: AuditLog, log_path: Path) -> None:
        # UT-Record-Chain
        ev0 = audit.record(**make_record_kwargs())
        ev1 = audit.record(**make_record_kwargs(decision="deny", reason="nope"))

        lines = read_jsonl_lines(log_path)
        assert len(lines) == 2
        parsed = [json.loads(line) for line in lines]

        assert parsed[1]["sequence_number"] == 1
        assert parsed[1]["previous_hash"] == parsed[0]["current_hash"]
        assert ev1.previous_hash == ev0.current_hash
        assert ev1.sequence_number == 1


# ---------------------------------------------------------------------------
# AC-06, AC-40 — decision coercion / validation
# ---------------------------------------------------------------------------


class TestDecisionCoerceAndValidation:
    def test_decision_string_allow_accepted(self, audit: AuditLog, log_path: Path) -> None:
        # UT-Decision-Coerce (positive)
        audit.record(**make_record_kwargs(decision="allow"))
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["decision"] == "allow"

    def test_decision_string_deny_accepted(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(**make_record_kwargs(decision="deny"))
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["decision"] == "deny"

    def test_decision_enum_allow_accepted(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(**make_record_kwargs(decision=Decision.ALLOW))
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        # On disk: lowercase enum VALUE, never the member name.
        assert parsed["decision"] == "allow"
        assert "ALLOW" not in read_jsonl_lines(log_path)[0]

    def test_decision_enum_deny_accepted(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(**make_record_kwargs(decision=Decision.DENY))
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["decision"] == "deny"

    def test_decision_uppercase_string_rejected(self, audit: AuditLog, log_path: Path) -> None:
        # UT-Record-Validation: case-sensitive per FR-03.
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(decision="ALLOW"))
        assert log_path.stat().st_size == 0

    def test_decision_invalid_rejected(self, audit: AuditLog, log_path: Path) -> None:
        # UT-Decision-Coerce (negative)
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(decision="invalid"))
        assert log_path.stat().st_size == 0

    def test_empty_tool_name_rejected(self, audit: AuditLog, log_path: Path) -> None:
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(tool_name=""))
        assert log_path.stat().st_size == 0

    def test_nan_argument_raises_write_error(self, audit: AuditLog, log_path: Path) -> None:
        with pytest.raises(WriteError):
            audit.record(**make_record_kwargs(arguments={"x": float("nan")}))
        # File untouched.
        assert log_path.stat().st_size == 0

    def test_empty_declared_identity_accepted_as_distinct_from_none(
        self, audit: AuditLog, log_path: Path
    ) -> None:
        # UT-Record-Validation: "" preserved verbatim, distinct from None.
        audit.record(**make_record_kwargs(declared_identity="", authenticated_identity=None))
        line = read_jsonl_lines(log_path)[0]
        # JSON contains "":"" for declared, null for authenticated.
        parsed = json.loads(line)
        assert parsed["declared_identity"] == ""
        assert parsed["authenticated_identity"] is None

    def test_non_string_declared_identity_rejected(self, audit: AuditLog, log_path: Path) -> None:
        # FR-03: declared_identity must be str or None.
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(declared_identity=123))  # type: ignore[arg-type]
        assert log_path.stat().st_size == 0

    def test_non_string_authenticated_identity_rejected(
        self, audit: AuditLog, log_path: Path
    ) -> None:
        with pytest.raises(ValueError):
            audit.record(
                **make_record_kwargs(authenticated_identity=42)  # type: ignore[arg-type]
            )
        assert log_path.stat().st_size == 0

    def test_non_string_reason_rejected(self, audit: AuditLog, log_path: Path) -> None:
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(reason=None))  # type: ignore[arg-type]
        assert log_path.stat().st_size == 0

    def test_non_mapping_arguments_rejected(self, audit: AuditLog, log_path: Path) -> None:
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(arguments=[1, 2, 3]))  # type: ignore[arg-type]
        assert log_path.stat().st_size == 0

    def test_non_string_decision_object_rejected(self, audit: AuditLog, log_path: Path) -> None:
        with pytest.raises(ValueError):
            audit.record(**make_record_kwargs(decision=42))  # type: ignore[arg-type]
        assert log_path.stat().st_size == 0


# ---------------------------------------------------------------------------
# AC-07 — arguments hash, raw args not stored
# ---------------------------------------------------------------------------


class TestArgsHash:
    def test_args_hash_matches_canonical_sha256(self, audit: AuditLog, log_path: Path) -> None:
        args = {"id": "1", "tags": ["a", "b"]}
        expected = hashlib.sha256(canonical_json(args)).hexdigest()
        audit.record(**make_record_kwargs(arguments=args))
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert parsed["arguments_hash"] == expected

    def test_raw_args_not_in_file(self, audit: AuditLog, log_path: Path) -> None:
        args = {"secret_id": "abc123xyz-VERY-secret"}
        audit.record(**make_record_kwargs(arguments=args))
        contents = log_path.read_text(encoding="utf-8")
        assert "abc123xyz-VERY-secret" not in contents
        assert "secret_id" not in contents


# ---------------------------------------------------------------------------
# AC-09 — timestamp + event_id format; both inside HMAC
# ---------------------------------------------------------------------------


_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class TestTimestampAndEventId:
    def test_timestamp_format(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(**make_record_kwargs())
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert _TIMESTAMP_RE.match(parsed["timestamp_utc"]), parsed["timestamp_utc"]

    def test_event_id_uuid4(self, audit: AuditLog, log_path: Path) -> None:
        audit.record(**make_record_kwargs())
        parsed = json.loads(read_jsonl_lines(log_path)[0])
        assert _UUID4_RE.match(parsed["event_id"]), parsed["event_id"]


# ---------------------------------------------------------------------------
# AC-13 — write/flush IOError surfaces as WriteError; no partial entry
# ---------------------------------------------------------------------------


class TestRecordIOError:
    def test_write_oserror_surfaces_as_write_error(
        self,
        audit: AuditLog,
        log_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Patch the audit log's file handle's write to raise.
        # We don't assume the internal attribute name; patch by overriding
        # the underlying buffered IO via the file object retrieved through
        # the AuditLog instance.
        # Acceptable shapes the impl may use: `_fh`, `_file`, `_fp`, `file`.
        handle: Any = None
        for attr in ("_fh", "_file", "_fp", "file"):
            if hasattr(audit, attr):
                handle = getattr(audit, attr)
                break
        if handle is None:
            pytest.skip("AuditLog does not expose its file handle; cannot inject IO failure")

        def boom(*_args: Any, **_kwargs: Any) -> int:
            raise OSError("disk full")

        monkeypatch.setattr(handle, "write", boom)

        with pytest.raises(WriteError):
            audit.record(**make_record_kwargs())

        # File contents must be empty (nothing written), and sequence not advanced.
        assert log_path.stat().st_size == 0
        # next record should still use sequence 0 (sequence not advanced).
        # Re-patch back to a working write — easiest is to drop the audit
        # instance and rely on the test fixture's teardown. We'll only
        # assert state observable here.


# ---------------------------------------------------------------------------
# AC-14 — fsync toggle
# ---------------------------------------------------------------------------


class TestFsyncToggle:
    def test_fsync_true_invokes_os_fsync(
        self,
        key_env: str,
        log_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[int] = []

        # Capture the real os.fsync before patching so wrapping is safe.
        real_fsync = os.fsync

        def counting(fd: int) -> None:
            calls.append(fd)
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", counting)
        # Some implementations may resolve the symbol via `from os import fsync`
        # into their own module's namespace; patch that too if present.
        import krono.audit as audit_mod

        if hasattr(audit_mod, "fsync"):
            monkeypatch.setattr(audit_mod, "fsync", counting)

        a = AuditLog(log_path, fsync=True)
        try:
            a.record(**make_record_kwargs())
        finally:
            a.close()
        assert len(calls) >= 1, "expected os.fsync to be called at least once"

    def test_fsync_false_does_not_invoke_os_fsync(
        self,
        key_env: str,
        log_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[int] = []

        def counting(fd: int) -> None:
            calls.append(fd)

        monkeypatch.setattr(os, "fsync", counting)
        import krono.audit as audit_mod

        if hasattr(audit_mod, "fsync"):
            monkeypatch.setattr(audit_mod, "fsync", counting)

        a = AuditLog(log_path, fsync=False)
        try:
            a.record(**make_record_kwargs())
        finally:
            a.close()
        assert calls == []


# ---------------------------------------------------------------------------
# AC-15, AC-39 — close + post-close record
# ---------------------------------------------------------------------------


class TestCloseAndPostClose:
    def test_close_idempotent(self, key_env: str, log_path: Path) -> None:
        a = AuditLog(log_path)
        a.close()
        # Second close MUST be a no-op (not raise).
        assert a.close() is None

    def test_context_manager_closes(self, key_env: str, log_path: Path) -> None:
        with AuditLog(log_path) as a:
            a.record(**make_record_kwargs())
        # After __exit__: subsequent record raises.
        with pytest.raises(WriteError):
            a.record(**make_record_kwargs())

    def test_record_after_close_raises_write_error(self, key_env: str, log_path: Path) -> None:
        # UT-Record-After-Close
        a = AuditLog(log_path)
        a.close()
        size_before = log_path.stat().st_size
        with pytest.raises(WriteError):
            a.record(**make_record_kwargs())
        # File unchanged.
        assert log_path.stat().st_size == size_before


# ---------------------------------------------------------------------------
# AC-11, AC-12 — resume on restart
# ---------------------------------------------------------------------------


class TestResume:
    def test_resume_valid(self, key_env: str, log_path: Path) -> None:
        # UT-Resume-Valid: pre-write 3 events, close, reopen.
        with AuditLog(log_path) as a:
            for _ in range(3):
                a.record(**make_record_kwargs())

        # Reopen.
        a2 = AuditLog(log_path)
        try:
            # Implementation may expose `next_sequence` and `last_current_hash`
            # via attributes; the spec mentions them by those names.
            if hasattr(a2, "next_sequence"):
                assert a2.next_sequence == 3
            # The next record should land at sequence 3 regardless of attr name.
            ev = a2.record(**make_record_kwargs())
            assert ev.sequence_number == 3
            # And previous_hash must equal the last line's current_hash before reopen.
            lines = read_jsonl_lines(log_path)
            parsed = [json.loads(line) for line in lines]
            assert parsed[3]["previous_hash"] == parsed[2]["current_hash"]
        finally:
            a2.close()

    def test_resume_torn_last_line_raises_write_error(self, key_env: str, log_path: Path) -> None:
        # UT-Resume-Torn: pre-write 2 valid lines + partial line without trailing \n
        with AuditLog(log_path) as a:
            a.record(**make_record_kwargs())
            a.record(**make_record_kwargs())

        # Append a partial (no trailing newline).
        with open(log_path, "ab") as f:
            f.write(b'{"sequence_number":2,"event_id":"deadbeef"')

        size_before = log_path.stat().st_size

        with pytest.raises(WriteError):
            AuditLog(log_path)

        # File bytes unchanged on disk.
        assert log_path.stat().st_size == size_before

    def test_resume_does_not_verify_chain(self, key_env: str, log_path: Path) -> None:
        # UT-Resume-NoVerify: write 3 valid entries, corrupt the FIRST line's
        # current_hash, then reopen — must succeed because FR-16 reads only the
        # last line.
        with AuditLog(log_path) as a:
            for _ in range(3):
                a.record(**make_record_kwargs())

        lines = read_jsonl_lines(log_path)
        # Corrupt line 0's current_hash.
        first = json.loads(lines[0])
        first["current_hash"] = "0" * 64
        # Rewrite the file with the tampered first line; canonical JSON to
        # keep schema-validity, even though hash is now wrong.
        rewritten = [
            canonical_json(first).decode("ascii"),
            lines[1],
            lines[2],
        ]
        log_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

        # Constructor SUCCEEDS — no re-verification.
        a2 = AuditLog(log_path)
        a2.close()

        # But verify() FAILS on the same file.
        result = verify(log_path)
        assert result.ok is False

    def test_resume_empty_file(self, key_env: str, log_path: Path) -> None:
        # Create empty file by hand.
        log_path.touch()
        a = AuditLog(log_path)
        try:
            ev = a.record(**make_record_kwargs())
            assert ev.sequence_number == 0
            assert ev.previous_hash == "genesis"
        finally:
            a.close()

    def test_resume_last_line_invalid_json(self, key_env: str, log_path: Path) -> None:
        # Last line is JSON-shaped garbage (e.g., truncated mid-object).
        log_path.write_bytes(b'{"bad":\n')
        with pytest.raises(WriteError):
            AuditLog(log_path)

    def test_resume_last_line_not_an_object(self, key_env: str, log_path: Path) -> None:
        # Last line is valid JSON but a scalar/array, not an object.
        log_path.write_bytes(b"[1,2,3]\n")
        with pytest.raises(WriteError):
            AuditLog(log_path)

    def test_resume_last_line_missing_required_fields(self, key_env: str, log_path: Path) -> None:
        # Last line is a JSON object missing required keys.
        log_path.write_bytes(b'{"sequence_number":0}\n')
        with pytest.raises(WriteError):
            AuditLog(log_path)

    def test_resume_last_line_bad_sequence_type(self, key_env: str, log_path: Path) -> None:
        # All required keys present but sequence_number is a string.
        body = {
            "sequence_number": "not-int",
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp_utc": "2026-05-22T13:45:01.123456Z",
            "tool_name": "x",
            "declared_identity": None,
            "authenticated_identity": None,
            "decision": "allow",
            "reason": "",
            "arguments_hash": "0" * 64,
            "previous_hash": "genesis",
            "current_hash": "0" * 64,
        }
        log_path.write_text(json.dumps(body) + "\n", encoding="utf-8")
        with pytest.raises(WriteError):
            AuditLog(log_path)

    def test_resume_last_line_bad_current_hash(self, key_env: str, log_path: Path) -> None:
        # Required keys present but current_hash is not a non-empty string.
        body = {
            "sequence_number": 0,
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp_utc": "2026-05-22T13:45:01.123456Z",
            "tool_name": "x",
            "declared_identity": None,
            "authenticated_identity": None,
            "decision": "allow",
            "reason": "",
            "arguments_hash": "0" * 64,
            "previous_hash": "genesis",
            "current_hash": "",  # empty
        }
        log_path.write_text(json.dumps(body) + "\n", encoding="utf-8")
        with pytest.raises(WriteError):
            AuditLog(log_path)

    def test_last_current_hash_property(self, key_env: str, log_path: Path) -> None:
        # Cover the last_current_hash property (and next_sequence).
        a = AuditLog(log_path)
        try:
            assert a.last_current_hash == "genesis"
            assert a.next_sequence == 0
            ev = a.record(**make_record_kwargs())
            assert a.last_current_hash == ev.current_hash
            assert a.next_sequence == 1
        finally:
            a.close()


# ---------------------------------------------------------------------------
# AC-38 — AuditEvent shape + round-trip
# ---------------------------------------------------------------------------


_EXPECTED_FIELDS = {
    "sequence_number",
    "event_id",
    "timestamp_utc",
    "tool_name",
    "declared_identity",
    "authenticated_identity",
    "decision",
    "reason",
    "arguments_hash",
    "previous_hash",
    "current_hash",
}


class TestAuditEventShape:
    def test_event_is_frozen(self, audit: AuditLog) -> None:
        # UT-AuditEvent-Shape
        ev = audit.record(**make_record_kwargs())
        with pytest.raises(FrozenInstanceError):
            ev.tool_name = "mutated"  # type: ignore[misc]

    def test_event_has_exactly_11_fields(self, audit: AuditLog) -> None:
        ev = audit.record(**make_record_kwargs())
        # Use the dataclass fields() function.
        from dataclasses import fields

        names = {f.name for f in fields(ev)}
        assert names == _EXPECTED_FIELDS

    def test_event_has_no_arguments_field(self, audit: AuditLog) -> None:
        ev = audit.record(**make_record_kwargs())
        assert not hasattr(ev, "arguments")

    def test_to_dict_round_trip_disk_bytes(self, audit: AuditLog, log_path: Path) -> None:
        # UT-AuditEvent-RoundTrip
        ev = audit.record(**make_record_kwargs())
        # Read disk bytes.
        on_disk = log_path.read_bytes()
        d = ev.to_dict()
        # Decision serializes to its lowercase string value.
        assert d["decision"] in ("allow", "deny")
        round_tripped = canonical_json(d) + b"\n"
        assert round_tripped == on_disk

    def test_to_dict_does_not_contain_arguments(self, audit: AuditLog) -> None:
        ev = audit.record(**make_record_kwargs())
        d = ev.to_dict()
        assert "arguments" not in d
        assert "arguments_hash" in d

    def test_from_dict_inverse(self, audit: AuditLog) -> None:
        ev = audit.record(**make_record_kwargs())
        ev2 = AuditEvent.from_dict(ev.to_dict())
        assert ev2 == ev

    def test_from_dict_missing_field_raises(self) -> None:
        d: dict[str, Any] = {
            "sequence_number": 0,
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp_utc": "2026-05-22T13:45:01.123456Z",
            "tool_name": "x",
            "declared_identity": None,
            "authenticated_identity": None,
            "decision": "allow",
            "reason": "",
            "arguments_hash": "0" * 64,
            "previous_hash": "genesis",
            # missing current_hash
        }
        with pytest.raises(ValueError):
            AuditEvent.from_dict(d)

    def test_from_dict_invalid_decision_raises(self) -> None:
        d: dict[str, Any] = {
            "sequence_number": 0,
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp_utc": "2026-05-22T13:45:01.123456Z",
            "tool_name": "x",
            "declared_identity": None,
            "authenticated_identity": None,
            "decision": "maybe",  # invalid value
            "reason": "",
            "arguments_hash": "0" * 64,
            "previous_hash": "genesis",
            "current_hash": "0" * 64,
        }
        with pytest.raises(ValueError):
            AuditEvent.from_dict(d)

    def test_from_dict_unexpected_field_raises(self) -> None:
        d: dict[str, Any] = {
            "sequence_number": 0,
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp_utc": "2026-05-22T13:45:01.123456Z",
            "tool_name": "x",
            "declared_identity": None,
            "authenticated_identity": None,
            "decision": "allow",
            "reason": "",
            "arguments_hash": "0" * 64,
            "previous_hash": "genesis",
            "current_hash": "0" * 64,
            "extra": "bad",
        }
        with pytest.raises(ValueError):
            AuditEvent.from_dict(d)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _recompute_hash(event: dict[str, Any], key: bytes) -> str:
    payload = {k: v for k, v in event.items() if k != "current_hash"}
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


# Suppress an unused import warning when the import is only used by helpers.
_unused = (stat,)
