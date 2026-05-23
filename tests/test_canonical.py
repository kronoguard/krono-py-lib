"""Unit tests for `krono._canonical.canonical_json`.

Spec: FR-09 (definition), AC-/UT-Canonical.
Covers determinism, key-order independence, ASCII-only escaping, and rejection
of NaN/Infinity/unknown types.
"""

from __future__ import annotations

import json

import pytest

from krono._canonical import canonical_json


class TestCanonicalDeterministic:
    """canonical_json output is byte-identical for equivalent inputs."""

    def test_same_dict_twice_same_bytes(self) -> None:
        d = {"a": 1, "b": "two", "c": [1, 2, 3]}
        assert canonical_json(d) == canonical_json(d)

    def test_key_order_independent(self) -> None:
        # AC: insertion order must not affect output.
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1}
        assert canonical_json(d1) == canonical_json(d2)

    def test_nested_keys_sorted(self) -> None:
        d1 = {"outer": {"b": 2, "a": 1}}
        d2 = {"outer": {"a": 1, "b": 2}}
        assert canonical_json(d1) == canonical_json(d2)


class TestCanonicalAscii:
    """Output is ASCII-only; non-ASCII characters are escaped via \\uXXXX."""

    def test_ascii_only_bytes(self) -> None:
        d = {"tool": "café"}
        out = canonical_json(d)
        # Every byte should be < 128 (ASCII).
        assert all(b < 128 for b in out)

    def test_non_ascii_escaped(self) -> None:
        d = {"k": "é"}
        out = canonical_json(d)
        # Lowercase \u escaping per json.dumps default.
        assert b"\\u00e9" in out

    def test_round_trips_via_json_loads(self) -> None:
        d = {"k": "héllo", "n": 1}
        out = canonical_json(d)
        reparsed = json.loads(out.decode("ascii"))
        assert reparsed == d


class TestCanonicalNoWhitespace:
    """Canonical JSON emits zero whitespace separators."""

    def test_no_spaces(self) -> None:
        d = {"a": 1, "b": 2}
        out = canonical_json(d)
        assert b" " not in out

    def test_compact_separators(self) -> None:
        d = {"a": 1, "b": [1, 2]}
        # Should be exactly `{"a":1,"b":[1,2]}` (sorted keys, no spaces).
        assert canonical_json(d) == b'{"a":1,"b":[1,2]}'


class TestCanonicalRejectsBadValues:
    """NaN, Infinity, and unknown types raise."""

    def test_nan_rejected(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            canonical_json({"x": float("nan")})

    def test_infinity_rejected(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            canonical_json({"x": float("inf")})

    def test_negative_infinity_rejected(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            canonical_json({"x": float("-inf")})

    def test_unknown_type_rejected(self) -> None:
        class Custom:
            pass

        with pytest.raises(TypeError):
            canonical_json({"x": Custom()})


class TestCanonicalReturnsBytes:
    """canonical_json returns `bytes` (not `str`)."""

    def test_returns_bytes(self) -> None:
        out = canonical_json({"a": 1})
        assert isinstance(out, bytes)

    def test_empty_dict(self) -> None:
        assert canonical_json({}) == b"{}"

    def test_simple_value(self) -> None:
        # Must accept any JSON value, not just dicts.
        assert canonical_json([1, 2, 3]) == b"[1,2,3]"
