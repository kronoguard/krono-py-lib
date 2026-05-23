"""Canonical JSON encoding for HMAC/SHA-256 input.

Per FR-09: the SOLE serialization used as hash input. Deterministic,
ASCII-only, key-sorted, whitespace-free, NaN/Infinity-rejecting.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Encode ``obj`` as canonical JSON bytes per FR-09.

    Sorted keys, no whitespace, ASCII-escaped non-ASCII, NaN/Infinity
    rejected. The returned bytes are the exact input fed to HMAC/SHA-256
    elsewhere in the library.

    Raises:
        ValueError: if ``obj`` contains NaN, Infinity, or another value
            that ``json.dumps`` cannot encode under ``allow_nan=False``.
        TypeError: if ``obj`` contains a type ``json.dumps`` cannot handle.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
