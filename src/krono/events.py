"""Public event types: ``Decision`` enum and ``AuditEvent`` dataclass.

Per FR-08: ``Decision`` has exactly two members. Per FR-40: ``AuditEvent``
is a frozen dataclass with exactly 11 fields matching the §Data Model
schema and provides ``to_dict``/``from_dict`` for canonical-JSON
round-tripping.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """Allow/deny decision recorded for an MCP tool dispatch.

    Per FR-08, exactly two members. On-disk the value is the lowercase
    string (``"allow"`` / ``"deny"``), never the member name. The
    ``str`` mixin makes ``Decision.ALLOW == "allow"`` evaluate True.
    """

    ALLOW = "allow"
    DENY = "deny"


# Canonical, ordered list of the 11 fields that constitute an event.
# Field order here is NOT the canonical-JSON order (that is enforced by
# sort_keys=True); it is the dataclass declaration order. Kept as a
# module constant so verify() can use it for schema checks (FR-21).
_FIELD_NAMES: tuple[str, ...] = (
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
)


@dataclass(frozen=True)
class AuditEvent:
    """A single audit event, frozen after construction.

    Per FR-40: exactly 11 fields, matching the §Data Model schema.
    ``decision`` is typed as ``Decision`` (FR-08); the two identity fields
    accept ``None``. Carries ``arguments_hash`` only — raw arguments are
    never stored on the instance (FR-07, I-05).
    """

    sequence_number: int
    event_id: str
    timestamp_utc: str
    tool_name: str
    declared_identity: str | None
    authenticated_identity: str | None
    decision: Decision
    reason: str
    arguments_hash: str
    previous_hash: str
    current_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return a fresh ``dict`` whose values are JSON-serializable.

        Per FR-40 the result round-trips through ``canonical_json`` to
        bytes identical to the on-disk JSON (including ``current_hash``).
        ``decision`` is converted to its lowercase string value.
        """
        return {
            "sequence_number": self.sequence_number,
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "tool_name": self.tool_name,
            "declared_identity": self.declared_identity,
            "authenticated_identity": self.authenticated_identity,
            "decision": self.decision.value,
            "reason": self.reason,
            "arguments_hash": self.arguments_hash,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEvent:
        """Build an ``AuditEvent`` from a dict produced by ``to_dict``.

        Per FR-40: missing or unexpected keys raise ``ValueError``.

        Raises:
            ValueError: if ``d`` is missing any of the 11 required keys
                or contains an unexpected key, or if ``decision`` cannot
                be parsed as a ``Decision`` member.
        """
        expected = set(_FIELD_NAMES)
        actual = set(d.keys())
        missing = expected - actual
        unexpected = actual - expected
        if missing:
            raise ValueError(f"AuditEvent.from_dict: missing fields: {sorted(missing)}")
        if unexpected:
            raise ValueError(f"AuditEvent.from_dict: unexpected fields: {sorted(unexpected)}")
        try:
            decision = Decision(d["decision"])
        except ValueError as exc:
            raise ValueError(f"AuditEvent.from_dict: invalid decision: {d['decision']!r}") from exc
        return cls(
            sequence_number=d["sequence_number"],
            event_id=d["event_id"],
            timestamp_utc=d["timestamp_utc"],
            tool_name=d["tool_name"],
            declared_identity=d["declared_identity"],
            authenticated_identity=d["authenticated_identity"],
            decision=decision,
            reason=d["reason"],
            arguments_hash=d["arguments_hash"],
            previous_hash=d["previous_hash"],
            current_hash=d["current_hash"],
        )


# Sanity guard: keep _FIELD_NAMES in sync with the dataclass declaration.
# A drift here would silently break FR-21 schema checks.
assert tuple(f.name for f in fields(AuditEvent)) == _FIELD_NAMES
