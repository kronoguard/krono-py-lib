"""Result types for :func:`krono.verify.verify`.

Houses the three verify-result data types (``FailureKind``, ``VerifyFailure``,
``VerifyResult``) in a dedicated leaf module so that :mod:`krono.exceptions`
and :mod:`krono.verify` can both reference them without creating a static
import cycle. Re-exported by :mod:`krono.verify` for backward compatibility
with v0.1.x callers that imported these names from ``krono.verify``.

Per FR-38, ``FailureKind`` is a ``str`` enum with lowercase snake_case values.
Per FR-18/FR-19/FR-20/FR-21 and FR-39, ``VerifyFailure`` carries the line
number (1-indexed), the parsed ``sequence_number`` (or ``None`` when the
failure prevented sequence extraction), the failure kind, a human-readable
message, and optional ``expected``/``actual`` fields populated only for
``CONTENT_TAMPERED``, ``SEQUENCE_GAP``, and ``CHAIN_BREAK``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FailureKind(StrEnum):
    """Per FR-38, lowercase snake_case ``str`` values.

    Members map to the six FR-37 verification checks. ``FailureKind``
    is a ``str`` enum, so ``failure.kind == "content_tampered"`` and
    ``failure.kind is FailureKind.CONTENT_TAMPERED`` both work.
    """

    PARSE_ERROR = "parse_error"
    MISSING_FIELD = "missing_field"
    UNEXPECTED_FIELD = "unexpected_field"
    SEQUENCE_GAP = "sequence_gap"
    CHAIN_BREAK = "chain_break"
    CONTENT_TAMPERED = "content_tampered"


@dataclass(frozen=True)
class VerifyFailure:
    """One verification failure, per FR-18/FR-19/FR-20/FR-21 and FR-39.

    ``line`` is 1-indexed. ``sequence_number`` is the parsed value from
    the offending event, or ``None`` when the failure prevented sequence
    extraction (``PARSE_ERROR``, or ``MISSING_FIELD`` where
    ``sequence_number`` itself was missing). ``expected``/``actual`` are
    populated only for ``CONTENT_TAMPERED``, ``SEQUENCE_GAP``, and
    ``CHAIN_BREAK``; ``None`` otherwise (the JSON serializer omits them
    in that case per the §Interfaces field-presence rules).
    """

    line: int
    sequence_number: int | None
    kind: FailureKind
    message: str
    expected: str | int | None = None
    actual: str | int | None = None


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a ``verify()`` call.

    ``ok`` is ``True`` iff the file is consistent under the FR-37 check
    order. ``entries_checked`` is the count of lines that FULLY PASSED
    all six checks (FR-39); the failing line is never counted. ``failure``
    is ``None`` on success.
    """

    ok: bool
    entries_checked: int
    failure: VerifyFailure | None = None
