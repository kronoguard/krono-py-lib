"""HMAC and SHA-256 helpers built on canonical JSON.

Per FR-07 and FR-10: every byte-level hashing input goes through
``canonical_json`` first; this module is the only place HMAC keys are
applied to event payloads.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from krono._canonical import canonical_json


def arguments_hash(arguments: Mapping[str, Any]) -> str:
    """Return the SHA-256 hex digest of canonical-JSON-encoded arguments.

    Implements FR-07: 64-char lowercase hex over
    ``canonical_json(arguments)``.

    Raises:
        ValueError: if ``arguments`` contains NaN/Infinity (per FR-09).
        TypeError: if ``arguments`` contains a non-JSON-encodable value.
    """
    return hashlib.sha256(canonical_json(arguments)).hexdigest()


def compute_current_hash(key: bytes, payload: Mapping[str, Any]) -> str:
    """Return the HMAC-SHA256 hex digest of canonical(payload) under ``key``.

    Per FR-10, ``payload`` MUST be the event dict with the ``current_hash``
    key removed; the caller is responsible for omitting it. Returns 64-char
    lowercase hex.

    Raises:
        ValueError: if ``payload`` contains NaN/Infinity (per FR-09).
        TypeError: if ``payload`` contains a non-JSON-encodable value.
    """
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
