"""AuditLog: tamper-evident append-only writer for MCP audit events.

Per the SPEC §Workflow: validate key (FR-02) → eager-open log (FR-01) →
on a non-empty file, resume from the last line (FR-16) → ``record()``
appends one JSONL line per call under a lock (FR-12, FR-13).
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from io import TextIOWrapper
from pathlib import Path
from types import TracebackType
from typing import Any

from krono._canonical import canonical_json
from krono._hash import arguments_hash, compute_current_hash
from krono._keys import resolve_key
from krono.events import AuditEvent, Decision
from krono.exceptions import ConfigError, WriteError

_GENESIS: str = "genesis"

# Top-level keys required on the on-disk JSON, in the canonical 11-field
# schema (FR-21). Includes ``current_hash`` because resume reads a fully
# written event.
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


def _now_utc() -> str:
    """Return current UTC time formatted per FR-05 (ISO 8601, µs, ``Z``)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _read_last_line(path: Path) -> str | None:
    """Return the last newline-terminated line of ``path`` (without ``\\n``).

    Returns ``None`` if the file is empty. Per FR-16 step 3, a final line
    without a trailing ``\\n`` is treated as torn — surfaced here by
    returning the (un-newline-terminated) tail so the caller can detect
    the mismatch and raise.

    A second sentinel value, the literal string "__torn__", is NOT used;
    instead, the caller compares the total file bytes to detect "no
    trailing newline" — see ``_load_resume_state``.
    """
    with path.open("rb") as fh:
        data = fh.read()
    if not data:
        return None
    # Strip a single trailing newline (the well-formed case).
    if data.endswith(b"\n"):
        data = data[:-1]
        ends_with_newline = True
    else:
        ends_with_newline = False
    # Find the last newline that separates the last record from the prior one.
    nl_idx = data.rfind(b"\n")
    last = data[nl_idx + 1 :] if nl_idx >= 0 else data
    text = last.decode("utf-8")
    # Encode "no trailing newline" as a torn-line signal by prefixing a
    # sentinel; the caller treats this as "raise WriteError".
    if not ends_with_newline:
        # Use a sentinel that cannot collide with valid JSON (starts with '\x00').
        return "\x00TORN\x00" + text
    return text


def _load_resume_state(path: Path) -> tuple[int, str]:
    """Read the last line of an existing log and return ``(next_seq, last_hash)``.

    Implements FR-16. Returns ``(0, "genesis")`` for an empty or missing
    file. Raises ``WriteError`` for a torn last line or schema-broken
    last entry; the caller (constructor) is responsible for releasing any
    file handle BEFORE this function raises (FR-01 + FR-16 step 3
    coupling).

    Raises:
        WriteError: if the last line lacks a trailing newline, fails to
            parse as JSON, lacks any of the 11 required keys, or
            otherwise cannot be used to derive ``(next_seq, last_hash)``.
    """
    if not path.exists():
        return 0, _GENESIS
    raw = _read_last_line(path)
    if raw is None:
        return 0, _GENESIS
    if raw.startswith("\x00TORN\x00"):
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}")
    try:
        event = json.loads(raw)
    except (ValueError, TypeError) as exc:
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}: {exc}") from exc
    if not isinstance(event, dict):
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}: not a JSON object")
    missing = _REQUIRED_KEYS - set(event.keys())
    if missing:
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}: missing {sorted(missing)}")
    seq = event["sequence_number"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}: bad sequence_number")
    last_hash = event["current_hash"]
    if not isinstance(last_hash, str) or not last_hash:
        size = path.stat().st_size
        raise WriteError(f"last line malformed at offset {size}: bad current_hash")
    return seq + 1, last_hash


class AuditLog:
    """Append-only writer for tamper-evident audit events.

    Construction order (FR-02 before FR-01, normative): resolve and
    validate the HMAC key first; only then open or create the log file.
    On a non-empty pre-existing file, the last line is read to recover
    ``next_sequence`` and ``last_current_hash`` (FR-16) — the chain is
    NOT re-verified at construction.

    Thread-safe within a single process via an internal ``threading.Lock``
    (FR-12). Not safe for use from multiple processes against the same
    file (documented limit, §Constraints).

    Raises:
        MissingKeyError: when no valid HMAC key is available (FR-02).
        ConfigError: when the parent directory is missing or not writable
            (FR-01).
        WriteError: when an existing file's last line is malformed
            (FR-16 step 3).
    """

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes | None = None,
        key_env: str = "KRONO_AUDIT_KEY",
        fsync: bool = False,
    ) -> None:
        # FR-02: validate key BEFORE any filesystem operation.
        self._key: bytes = resolve_key(key, key_env)
        self._fsync: bool = fsync
        self._lock: threading.Lock = threading.Lock()
        self._closed: bool = False
        self._path: Path = Path(path)
        # FR-01: eager open in append mode (creates if missing). open()
        # either succeeds and creates the file or raises BEFORE creating
        # anything — so there is no partial file to clean up on
        # ConfigError.
        try:
            self._fh: TextIOWrapper = self._path.open("a", encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"audit log path not writable: {self._path}") from exc
        # FR-16: resume from the last line (if any). If the resume read
        # raises, release the file handle BEFORE the exception escapes —
        # FR-16 step 3 explicitly requires the pre-existing file's bytes
        # be left unchanged on disk.
        try:
            next_seq, last_hash = _load_resume_state(self._path)
        except Exception:
            self._fh.close()
            raise
        self._next_sequence: int = next_seq
        self._last_current_hash: str = last_hash

    @property
    def next_sequence(self) -> int:
        """Return the next sequence number that will be assigned by ``record``."""
        return self._next_sequence

    @property
    def last_current_hash(self) -> str:
        """Return the in-memory chain head used as ``previous_hash`` on next record."""
        return self._last_current_hash

    def record(
        self,
        *,
        tool_name: str,
        decision: Decision | str,
        arguments: Mapping[str, Any],
        declared_identity: str | None,
        authenticated_identity: str | None,
        reason: str = "",
    ) -> AuditEvent:
        """Append one audit event and return the frozen ``AuditEvent`` written.

        Validates inputs at the public-API boundary (FR-03); on any
        validation failure NO file write occurs. The whole append is
        serialized by ``self._lock`` (FR-12) and is exactly one
        ``write()`` call carrying ``payload + "\\n"`` (FR-13).

        Raises:
            ValueError: per FR-03 when ``tool_name`` is empty, ``decision``
                is not in ``{"allow", "deny", Decision.ALLOW, Decision.DENY}``,
                or an identity field has the wrong type.
            WriteError: per FR-25 on any I/O failure; per FR-15 when the
                instance is closed; per FR-03 when ``arguments`` is not
                JSON-canonicalizable.
        """
        # --- FR-03 validation (BEFORE any file touch) ---
        if self._closed:
            raise WriteError("AuditLog is closed")
        if not isinstance(tool_name, str) or tool_name == "":
            raise ValueError("tool_name must be a non-empty str")
        if declared_identity is not None and not isinstance(declared_identity, str):
            raise ValueError("declared_identity must be str or None")
        if authenticated_identity is not None and not isinstance(authenticated_identity, str):
            raise ValueError("authenticated_identity must be str or None")
        if not isinstance(reason, str):
            raise ValueError("reason must be str")
        if not isinstance(arguments, Mapping):
            raise ValueError("arguments must be a Mapping[str, Any]")
        decision_value = self._coerce_decision(decision)
        # arguments_hash computation also acts as a JSON-canonicalizable
        # check; wrap any failure as WriteError per FR-03's "WriteError
        # BEFORE the file is touched".
        try:
            args_hash = arguments_hash(arguments)
        except (ValueError, TypeError) as exc:
            raise WriteError(f"arguments not JSON-encodable: {exc}") from exc

        # --- FR-12 critical section ---
        with self._lock:
            if self._closed:
                # Double-check inside lock (another thread may have closed).
                raise WriteError("AuditLog is closed")
            seq = self._next_sequence
            prev_hash = self._last_current_hash
            payload: dict[str, Any] = {
                "sequence_number": seq,
                "event_id": str(uuid.uuid4()),
                "timestamp_utc": _now_utc(),
                "tool_name": tool_name,
                "declared_identity": declared_identity,
                "authenticated_identity": authenticated_identity,
                "decision": decision_value.value,
                "reason": reason,
                "arguments_hash": args_hash,
                "previous_hash": prev_hash,
            }
            current_hash = compute_current_hash(self._key, payload)
            event_dict: dict[str, Any] = {**payload, "current_hash": current_hash}
            line = canonical_json(event_dict).decode("ascii") + "\n"
            try:
                self._fh.write(line)
                self._fh.flush()
                if self._fsync:
                    os.fsync(self._fh.fileno())
            except OSError as exc:
                # FR-25: fail loud. Do NOT advance chain state.
                raise WriteError(f"audit write failed: {exc}") from exc
            # Only AFTER a successful flush do we advance state.
            self._next_sequence = seq + 1
            self._last_current_hash = current_hash

        return AuditEvent(
            sequence_number=seq,
            event_id=payload["event_id"],
            timestamp_utc=payload["timestamp_utc"],
            tool_name=tool_name,
            declared_identity=declared_identity,
            authenticated_identity=authenticated_identity,
            decision=decision_value,
            reason=reason,
            arguments_hash=args_hash,
            previous_hash=prev_hash,
            current_hash=current_hash,
        )

    @staticmethod
    def _coerce_decision(decision: Decision | str) -> Decision:
        """Coerce ``decision`` to a ``Decision`` member per FR-03.

        Accepts the enum directly or the lowercase strings ``"allow"`` /
        ``"deny"``. Case-sensitive — ``"ALLOW"`` is rejected.

        Raises:
            ValueError: on any other input.
        """
        if isinstance(decision, Decision):
            return decision
        if isinstance(decision, str):
            if decision == "allow":
                return Decision.ALLOW
            if decision == "deny":
                return Decision.DENY
        raise ValueError(
            f"decision must be 'allow' or 'deny' (or Decision member); got {decision!r}"
        )

    def close(self) -> None:
        """Flush and close the underlying file handle. Idempotent (FR-15)."""
        if self._closed:
            return
        self._closed = True
        # Best-effort flush at close; the underlying error is the
        # operator's signal in their existing tracebacks.
        with contextlib.suppress(OSError):
            self._fh.flush()
        self._fh.close()

    def __enter__(self) -> AuditLog:
        """Return ``self`` for context-manager use (FR-15)."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the underlying file handle; swallow nothing."""
        self.close()
