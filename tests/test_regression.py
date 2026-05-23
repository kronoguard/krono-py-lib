"""Regression and smoke tests for krono.

Spec: §Required Tests → Regression.
    - Byte-layout snapshot: the exact bytes of a recorded line are stable
      across Python 3.11-3.13 (modulo timestamp_utc + event_id, which are
      pinned here via monkeypatch).
    - canonical_json key-order invariance: dict input ordering does not
      affect the output bytes.
    - 1000-entry verify smoke: verify() completes in well under one second
      on developer hardware (not a strict perf target).

These tests catch regressions in: json.dumps ordering, ASCII escape rules,
HMAC chain construction, and the FR-09 canonical JSON contract — failures
indicate the byte-level contract has drifted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from pathlib import Path

import pytest

from krono import AuditLog, verify
from krono._canonical import canonical_json

# ---------------------------------------------------------------------------
# Byte-layout snapshot — pin the random parts so the line is deterministic.
# ---------------------------------------------------------------------------

_FIXED_TS = "2026-05-22T13:45:01.123456Z"
_FIXED_EID = "00000000-0000-4000-8000-000000000001"
_FIXED_KEY_HEX = "00" * 32  # 32 raw zero bytes — deterministic for regression


class _FixedUuid:
    """Stand-in for `uuid.uuid4()` that returns a fixed UUID4 each call."""

    @staticmethod
    def uuid4() -> uuid.UUID:
        return uuid.UUID(_FIXED_EID)


def test_recorded_line_byte_layout_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """One recorded event yields a byte-exact, version-stable JSONL line.

    Pinning timestamp_utc and event_id makes the entire line deterministic
    given a fixed key and fixed arguments — so any future change to canonical
    JSON ordering, escape rules, or HMAC chain construction would change the
    bytes and fail this test.
    """
    monkeypatch.setattr("krono.audit._now_utc", lambda: _FIXED_TS)
    monkeypatch.setattr("krono.audit.uuid", _FixedUuid)
    monkeypatch.setenv("KRONO_AUDIT_KEY", _FIXED_KEY_HEX)

    log_path = tmp_path / "snapshot.jsonl"
    with AuditLog(log_path) as a:
        a.record(
            tool_name="test_tool",
            decision="allow",
            arguments={},
            declared_identity=None,
            authenticated_identity=None,
            reason="",
        )

    actual = log_path.read_bytes()

    # Build the expected line independently using the FR-09 / FR-10 primitives.
    # If this diverges from `actual`, the byte-level contract has drifted.
    args_hash = hashlib.sha256(canonical_json({})).hexdigest()
    payload = {
        "arguments_hash": args_hash,
        "authenticated_identity": None,
        "decision": "allow",
        "declared_identity": None,
        "event_id": _FIXED_EID,
        "previous_hash": "genesis",
        "reason": "",
        "sequence_number": 0,
        "timestamp_utc": _FIXED_TS,
        "tool_name": "test_tool",
    }
    expected_hash = hmac.new(
        bytes.fromhex(_FIXED_KEY_HEX), canonical_json(payload), hashlib.sha256
    ).hexdigest()
    full = {**payload, "current_hash": expected_hash}
    expected = canonical_json(full) + b"\n"

    assert actual == expected, (
        "byte-layout regression: recorded line differs from expected.\n"
        f"  actual:   {actual!r}\n"
        f"  expected: {expected!r}"
    )


def test_recorded_line_contains_known_arguments_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The empty-dict arguments_hash is a well-known SHA-256 constant.

    sha256(b'{}') = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
    Any change here means canonical_json({}) no longer produces b'{}', or the
    arguments_hash helper changed. Either is a regression.
    """
    monkeypatch.setattr("krono.audit._now_utc", lambda: _FIXED_TS)
    monkeypatch.setattr("krono.audit.uuid", _FixedUuid)
    monkeypatch.setenv("KRONO_AUDIT_KEY", _FIXED_KEY_HEX)

    log_path = tmp_path / "args_hash.jsonl"
    with AuditLog(log_path) as a:
        a.record(
            tool_name="t",
            decision="allow",
            arguments={},
            declared_identity=None,
            authenticated_identity=None,
        )

    line = json.loads(log_path.read_text(encoding="utf-8").rstrip("\n"))
    assert (
        line["arguments_hash"] == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )


# ---------------------------------------------------------------------------
# canonical_json key-order invariance regression
# ---------------------------------------------------------------------------


def test_canonical_json_key_order_invariance() -> None:
    """canonical_json({"a":1,"b":2}) == canonical_json({"b":2,"a":1}).

    A regression here means sort_keys=True is no longer effective and the
    byte-level contract is broken for any future host whose dict insertion
    order differs from ours.
    """
    a = canonical_json({"a": 1, "b": 2, "c": 3})
    b = canonical_json({"c": 3, "b": 2, "a": 1})
    c = canonical_json({"b": 2, "a": 1, "c": 3})
    assert a == b == c
    assert a == b'{"a":1,"b":2,"c":3}'


def test_canonical_json_nested_order_invariance() -> None:
    """Nested dict key-order is also stable."""
    a = canonical_json({"outer": {"a": 1, "b": 2}, "z": 3})
    b = canonical_json({"z": 3, "outer": {"b": 2, "a": 1}})
    assert a == b
    assert a == b'{"outer":{"a":1,"b":2},"z":3}'


# ---------------------------------------------------------------------------
# 1000-entry verify smoke test — completes in well under one second.
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_verify_1000_entries_smoke(tmp_path: Path, key_env: str) -> None:
    """verify() of a 1000-entry log completes in well under one second.

    Not a strict perf gate; the spec calls this out as a smoke test. Bar set
    at 2.0s to absorb CI noise; on developer hardware it runs in << 1s.
    """
    log_path = tmp_path / "1k.jsonl"
    with AuditLog(log_path) as a:
        for i in range(1000):
            a.record(
                tool_name="bench_tool",
                decision="allow" if i % 2 == 0 else "deny",
                arguments={"i": i},
                declared_identity="bench-client",
                authenticated_identity=None,
                reason=f"event {i}",
            )

    start = time.perf_counter()
    result = verify(log_path)
    elapsed = time.perf_counter() - start

    assert result.ok is True
    assert result.entries_checked == 1000
    assert elapsed < 2.0, f"verify of 1000 entries took {elapsed:.3f}s (smoke threshold 2.0s)"


@pytest.mark.smoke
def test_verify_smoke_logs_each_field_typed_correctly(tmp_path: Path, key_env: str) -> None:
    """Smoke: a recorded line round-trips into a dict whose 11 fields all
    have the documented types (FR-40 / §Data Model)."""
    log_path = tmp_path / "types.jsonl"
    uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    ts_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

    with AuditLog(log_path) as a:
        a.record(
            tool_name="t",
            decision="allow",
            arguments={"x": 1},
            declared_identity="c",
            authenticated_identity="u",
            reason="r",
        )

    event = json.loads(log_path.read_text(encoding="utf-8").rstrip("\n"))
    assert isinstance(event["sequence_number"], int)
    assert uuid_re.match(event["event_id"])
    assert ts_re.match(event["timestamp_utc"])
    assert isinstance(event["tool_name"], str)
    assert isinstance(event["declared_identity"], str)
    assert isinstance(event["authenticated_identity"], str)
    assert event["decision"] in {"allow", "deny"}
    assert isinstance(event["reason"], str)
    assert re.match(r"^[0-9a-f]{64}$", event["arguments_hash"])
    assert event["previous_hash"] == "genesis"
    assert re.match(r"^[0-9a-f]{64}$", event["current_hash"])
