"""Unit tests for `krono._hash`.

Spec: FR-07, FR-10, AC-07, AC-20.
Specifically proves UT-HMAC-Covers-AllFields: the HMAC input covers EVERY
field in the canonical 11-field schema except `current_hash` itself —
mutating any one of them changes the resulting hash. This is load-bearing
for AC-20, since FR-37's verify check order prevents `verify()` from
surfacing CONTENT_TAMPERED for a lone `sequence_number` mutation, so the
proof that sequence_number is inside the HMAC has to live here, in a
direct hash-function test.
"""

from __future__ import annotations

import hashlib

import pytest

from krono._canonical import canonical_json
from krono._hash import arguments_hash, compute_current_hash

# 32-byte hex key for HMAC tests.
KEY_A = bytes.fromhex("00" * 32)
KEY_B = bytes.fromhex("11" * 32)


def _baseline_event() -> dict[str, object]:
    """A baseline event dict with all 10 fields-except-current_hash populated."""
    return {
        "sequence_number": 0,
        "event_id": "00000000-0000-4000-8000-000000000000",
        "timestamp_utc": "2026-05-22T13:45:01.123456Z",
        "tool_name": "read_note",
        "declared_identity": "demo-client",
        "authenticated_identity": None,
        "decision": "allow",
        "reason": "default-allow read tool",
        "arguments_hash": hashlib.sha256(b'{"id":"1"}').hexdigest(),
        "previous_hash": "genesis",
    }


# The 10 fields that MUST be covered by the HMAC, per the canonical schema
# (everything except `current_hash`).
_COVERED_FIELDS = [
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
]


# Per-field "tweaked" value, distinct from the baseline.
_TWEAKS: dict[str, object] = {
    "sequence_number": 1,
    "event_id": "11111111-1111-4111-8111-111111111111",
    "timestamp_utc": "2026-05-22T13:45:01.999999Z",
    "tool_name": "delete_note",
    "declared_identity": "other-client",
    "authenticated_identity": "alice",
    "decision": "deny",
    "reason": "different reason",
    "arguments_hash": hashlib.sha256(b'{"id":"2"}').hexdigest(),
    "previous_hash": "deadbeef" * 8,  # 64 hex chars
}


class TestHmacCoversAllFields:
    """UT-HMAC-Covers-AllFields — every documented field affects the HMAC."""

    @pytest.mark.parametrize("field", _COVERED_FIELDS)
    def test_field_in_hmac(self, field: str) -> None:
        # Arrange: baseline + tweak that differs in only this one field.
        baseline = _baseline_event()
        tweaked = dict(baseline)
        tweaked[field] = _TWEAKS[field]
        assert tweaked != baseline, "tweak must actually change the field"

        # Act
        h1 = compute_current_hash(KEY_A, baseline)
        h2 = compute_current_hash(KEY_A, tweaked)

        # Assert: hashes differ → field is covered by the HMAC.
        assert h1 != h2, f"current_hash did not change when {field!r} changed"


class TestHmacKeySensitivity:
    """UT-HMAC-Key-Sensitivity."""

    def test_different_keys_produce_different_hashes(self) -> None:
        event = _baseline_event()
        h_a = compute_current_hash(KEY_A, event)
        h_b = compute_current_hash(KEY_B, event)
        assert h_a != h_b

    def test_empty_key_differs_from_nonzero_key(self) -> None:
        # hmac.new accepts empty key. Note: HMAC pads the key to the block
        # size with zeros, so an empty key produces the SAME hash as an
        # all-zero key (any length <= block size). To prove key-sensitivity
        # at the empty-key boundary we compare against a NONZERO key.
        event = _baseline_event()
        h_empty = compute_current_hash(b"", event)
        h_nonzero = compute_current_hash(KEY_B, event)
        assert h_empty != h_nonzero


class TestHmacShape:
    """Format: lowercase hex, 64 chars."""

    def test_hash_is_64_lower_hex(self) -> None:
        h = compute_current_hash(KEY_A, _baseline_event())
        assert isinstance(h, str)
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)


class TestHmacExcludesCurrentHashWhenStripped:
    """When the caller strips `current_hash` per FR-10, the resulting hash
    is stable regardless of any prior `current_hash` value in the payload.

    The contract per FR-10 is: the caller passes the event with
    `current_hash` removed. So the loadbearing property here is that two
    callers who follow FR-10 — even if one had a stale `current_hash` in
    their starting dict — compute the same value once they both strip.
    """

    def test_stripped_payload_stable(self) -> None:
        event = _baseline_event()
        # Caller A: dict without current_hash to begin with.
        h_a = compute_current_hash(KEY_A, event)
        # Caller B: starting dict had a stale current_hash; B strips it
        # before calling (per FR-10).
        starting = dict(event)
        starting["current_hash"] = "deadbeef" * 8
        stripped = {k: v for k, v in starting.items() if k != "current_hash"}
        h_b = compute_current_hash(KEY_A, stripped)
        assert h_a == h_b


class TestArgumentsHash:
    """FR-07 — `arguments_hash = sha256(canonical_json(arguments)).hexdigest()`."""

    def test_known_value(self) -> None:
        args = {"id": "1"}
        expected = hashlib.sha256(canonical_json(args)).hexdigest()
        assert arguments_hash(args) == expected

    def test_empty_args(self) -> None:
        assert arguments_hash({}) == hashlib.sha256(b"{}").hexdigest()

    def test_key_order_independent(self) -> None:
        # canonical_json sorts keys, so arguments_hash must too.
        assert arguments_hash({"a": 1, "b": 2}) == arguments_hash({"b": 2, "a": 1})

    def test_lowercase_hex_64_chars(self) -> None:
        h = arguments_hash({"id": "1"})
        assert len(h) == 64
        assert h == h.lower()
