"""Audit-log verification: pure function of ``(file bytes, key)``.

Walks a krono audit log line-by-line and applies the six FR-37 checks in
the normative order: parse → schema (unexpected) → schema (missing) →
sequence → chain → hash. Returns on the FIRST violated check; subsequent
checks for that line are not performed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from krono._hash import compute_current_hash
from krono._keys import resolve_key
from krono.exceptions import ConfigError

# Result types live in their own leaf module (krono.results) so that
# krono.exceptions can reference VerifyFailure under TYPE_CHECKING without
# creating a static import cycle with this module. Re-exported here for
# backward compatibility with callers that import from ``krono.verify``.
from krono.results import FailureKind, VerifyFailure, VerifyResult

__all__ = [
    "FailureKind",
    "VerifyFailure",
    "VerifyResult",
    "verify",
]

_GENESIS: str = "genesis"

# The canonical 11-field schema (FR-21). Frozenset for fast membership.
_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
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
)


# Sentinel returned by per-check helpers when the check passed.
_OK: None = None


def _check_parse(line_no: int, raw: str) -> VerifyFailure | dict[str, Any]:
    """FR-37 step 1: parse the line as a JSON object.

    Returns the parsed event ``dict`` on success, or a ``VerifyFailure``
    of kind ``PARSE_ERROR`` on any defect (blank line, invalid JSON,
    non-object top-level).
    """
    if raw.strip() == "":
        return VerifyFailure(
            line=line_no,
            sequence_number=None,
            kind=FailureKind.PARSE_ERROR,
            message=f"line {line_no}: blank line",
        )
    try:
        event: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        return VerifyFailure(
            line=line_no,
            sequence_number=None,
            kind=FailureKind.PARSE_ERROR,
            message=f"line {line_no}: invalid JSON: {exc}",
        )
    if not isinstance(event, dict):
        return VerifyFailure(
            line=line_no,
            sequence_number=None,
            kind=FailureKind.PARSE_ERROR,
            message=f"line {line_no}: top-level JSON is not an object",
        )
    return event


def _check_schema(line_no: int, event: dict[str, Any]) -> VerifyFailure | None:
    """FR-37 steps 2 and 3: unexpected-key, then missing-key.

    Returns ``None`` on success, or a ``VerifyFailure`` for the first
    schema defect found.
    """
    keys = set(event.keys())
    unexpected = keys - _REQUIRED_KEYS
    if unexpected:
        name = sorted(unexpected)[0]
        parsed_seq = event.get("sequence_number")
        is_int = isinstance(parsed_seq, int) and not isinstance(parsed_seq, bool)
        seq_for_failure: int | None = parsed_seq if is_int else None
        return VerifyFailure(
            line=line_no,
            sequence_number=seq_for_failure,
            kind=FailureKind.UNEXPECTED_FIELD,
            message=f"unexpected field: {name}",
        )
    missing = _REQUIRED_KEYS - keys
    if missing:
        name = sorted(missing)[0]
        parsed_seq = event.get("sequence_number")
        seq_for_failure = (
            parsed_seq
            if (
                "sequence_number" not in missing
                and isinstance(parsed_seq, int)
                and not isinstance(parsed_seq, bool)
            )
            else None
        )
        return VerifyFailure(
            line=line_no,
            sequence_number=seq_for_failure,
            kind=FailureKind.MISSING_FIELD,
            message=f"missing field: {name}",
        )
    return _OK


def _check_sequence(line_no: int, event: dict[str, Any], expected_seq: int) -> VerifyFailure | int:
    """FR-37 step 4: gapless sequence numbering.

    Returns the parsed ``sequence_number`` on success, or a
    ``VerifyFailure`` of kind ``SEQUENCE_GAP`` if the field is not an
    integer or does not equal ``expected_seq``.
    """
    raw_seq = event["sequence_number"]
    if not isinstance(raw_seq, int) or isinstance(raw_seq, bool):
        return VerifyFailure(
            line=line_no,
            sequence_number=None,
            kind=FailureKind.SEQUENCE_GAP,
            message=f"sequence_number is not an integer at file position {line_no}",
            expected=expected_seq,
            actual=None,
        )
    if raw_seq != expected_seq:
        return VerifyFailure(
            line=line_no,
            sequence_number=raw_seq,
            kind=FailureKind.SEQUENCE_GAP,
            message=f"sequence_number gap at file position {line_no}",
            expected=expected_seq,
            actual=raw_seq,
        )
    return raw_seq


def _check_chain(
    line_no: int, event: dict[str, Any], parsed_seq: int, prev_hash: str
) -> VerifyFailure | None:
    """FR-37 step 5: previous_hash linkage.

    Returns ``None`` on success or a ``VerifyFailure`` of kind
    ``CHAIN_BREAK`` if ``event["previous_hash"]`` does not equal the
    expected prior chain head.
    """
    parsed_prev = event["previous_hash"]
    if parsed_prev != prev_hash:
        return VerifyFailure(
            line=line_no,
            sequence_number=parsed_seq,
            kind=FailureKind.CHAIN_BREAK,
            message="previous_hash does not match prior entry's current_hash",
            expected=prev_hash,
            actual=parsed_prev if isinstance(parsed_prev, str) else None,
        )
    return _OK


def _check_hash(
    line_no: int, event: dict[str, Any], parsed_seq: int, key: bytes
) -> VerifyFailure | str:
    """FR-37 step 6: HMAC recomputation.

    Returns the validated ``current_hash`` on success or a
    ``VerifyFailure`` of kind ``CONTENT_TAMPERED`` on mismatch / failure
    to recompute (e.g., an embedded value that isn't canonicalizable).
    """
    stored_hash = event["current_hash"]
    payload = {k: v for k, v in event.items() if k != "current_hash"}
    try:
        recomputed = compute_current_hash(key, payload)
    except (ValueError, TypeError) as exc:  # pragma: no cover
        # Defensive: ``json.loads`` only emits canonicalizable types, so
        # ``compute_current_hash`` cannot raise here in practice.
        return VerifyFailure(
            line=line_no,
            sequence_number=parsed_seq,
            kind=FailureKind.CONTENT_TAMPERED,
            message=f"current_hash recomputation failed: {exc}",
        )
    if recomputed != stored_hash:
        return VerifyFailure(
            line=line_no,
            sequence_number=parsed_seq,
            kind=FailureKind.CONTENT_TAMPERED,
            message="current_hash mismatch",
            expected=recomputed,
            actual=stored_hash if isinstance(stored_hash, str) else None,
        )
    if not isinstance(stored_hash, str):  # pragma: no cover
        # Defensive: ``recomputed`` (a str) can only equal ``stored_hash``
        # when both are equal strings, so this branch is unreachable in
        # practice. Kept to satisfy mypy's return-type narrowing.
        return VerifyFailure(
            line=line_no,
            sequence_number=parsed_seq,
            kind=FailureKind.CONTENT_TAMPERED,
            message="current_hash is not a string",
        )
    return stored_hash


def _validate_line(
    line_no: int, raw: str, expected_seq: int, prev_hash: str, key: bytes
) -> VerifyFailure | tuple[int, str]:
    """Run the six FR-37 checks for one line in order.

    Returns ``(parsed_seq, current_hash)`` on success — the caller uses
    these to advance ``expected_seq`` and ``prev_hash``. Returns a
    ``VerifyFailure`` on the FIRST violated check.
    """
    parsed = _check_parse(line_no, raw)
    if isinstance(parsed, VerifyFailure):
        return parsed
    schema_failure = _check_schema(line_no, parsed)
    if schema_failure is not None:
        return schema_failure
    seq_result = _check_sequence(line_no, parsed, expected_seq)
    if isinstance(seq_result, VerifyFailure):
        return seq_result
    chain_failure = _check_chain(line_no, parsed, seq_result, prev_hash)
    if chain_failure is not None:
        return chain_failure
    hash_result = _check_hash(line_no, parsed, seq_result, key)
    if isinstance(hash_result, VerifyFailure):
        return hash_result
    return seq_result, hash_result


def _split_byte_lines(data: bytes) -> list[bytes]:
    """Split file bytes on b"\\n" into per-record byte sequences.

    Drops only the trailing empty element produced by the final ``b"\\n"``
    of a well-formed log (FR-13). A blank line in the middle of the file
    is preserved as ``b""`` so FR-37 step 1 catches it (AC-42). A final
    line lacking ``b"\\n"`` is preserved as a non-empty tail (AC-41).

    Strict UTF-8 decoding happens PER LINE in the verify loop so the
    offending line number is preserved on invalid bytes (vs. the prior
    errors="replace" leniency that silently turned invalid bytes into
    U+FFFD).
    """
    parts = data.split(b"\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def _decode_line_strict(line_no: int, raw_bytes: bytes) -> str | VerifyFailure:
    """Strict UTF-8 decode of one line; on failure return a PARSE_ERROR.

    Replaces the previous file-wide ``errors="replace"`` decoding (reviewer
    note: slightly looser than strict JSONL). Invalid bytes now surface
    deterministically as ``PARSE_ERROR`` at the offending line — never
    silently round-tripped through U+FFFD.
    """
    try:
        return raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return VerifyFailure(
            line=line_no,
            sequence_number=None,
            kind=FailureKind.PARSE_ERROR,
            message=f"line {line_no}: invalid UTF-8 at byte offset {exc.start}",
        )


def verify(
    path: str | Path,
    *,
    key: bytes | None = None,
    key_env: str = "KRONO_AUDIT_KEY",
) -> VerifyResult:
    """Verify the integrity of a krono audit log.

    Implements FR-17 through FR-23, with the check ordering of FR-37 and
    the semantics of FR-38/FR-39. Returns ``ok=False`` with a populated
    ``failure`` on any tampering; raises only on configuration/I-O
    problems (no key, no file).

    Raises:
        MissingKeyError: per FR-02 when no valid HMAC key is available.
        ConfigError: per FR-22 when ``path`` does not exist or is not a
            readable file.
    """
    resolved_path = Path(path)
    resolved_key = resolve_key(key, key_env)
    if not resolved_path.exists():
        raise ConfigError(f"audit log not found: {resolved_path}")
    try:
        with resolved_path.open("rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise ConfigError(f"audit log not readable: {resolved_path}: {exc}") from exc

    if not data:
        # FR-22: empty file is ok.
        return VerifyResult(ok=True, entries_checked=0, failure=None)

    byte_lines = _split_byte_lines(data)
    prev_hash: str = _GENESIS
    expected_seq: int = 0

    for idx, raw_bytes in enumerate(byte_lines):
        line_no = idx + 1
        decoded = _decode_line_strict(line_no, raw_bytes)
        if isinstance(decoded, VerifyFailure):
            return VerifyResult(
                ok=False,
                entries_checked=expected_seq,
                failure=decoded,
            )
        outcome = _validate_line(line_no, decoded, expected_seq, prev_hash, resolved_key)
        if isinstance(outcome, VerifyFailure):
            return VerifyResult(
                ok=False,
                entries_checked=expected_seq,
                failure=outcome,
            )
        parsed_seq, current_hash = outcome
        prev_hash = current_hash
        expected_seq = parsed_seq + 1

    return VerifyResult(ok=True, entries_checked=expected_seq, failure=None)
