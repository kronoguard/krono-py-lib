"""Identity dataclass — constructor-side convenience for the two identity fields.

Per FR-41/42, the v0.2.0 public API exposes a frozen ``Identity`` dataclass
that bundles the existing ``declared_identity`` and ``authenticated_identity``
fields used by :func:`krono.audit.AuditLog.record`. Identity is a
**constructor-side convenience only**: the on-disk JSONL format is byte-identical
to v0.1.1 — ``record()`` decomposes an ``Identity`` into the same two top-level
string fields before serialization.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    """Bundle of ``declared`` and ``authenticated`` identity values.

    Two-field invariant (FR-42): ``authenticated=None`` means the auth
    boundary did NOT run. The library never substitutes the literal
    string ``"unknown"``, never falls back ``declared`` → ``authenticated``,
    and never infers one from the other. Callers that want a sentinel
    must pass one explicitly.

    The dataclass is a constructor-side convenience for
    :meth:`krono.audit.AuditLog.record`; the on-disk format remains the
    canonical 11-field JSON object with separate ``declared_identity``
    and ``authenticated_identity`` string fields (FR-21). ``record()``
    decomposes ``Identity`` into those two fields and writes them
    byte-identically to v0.1.1.

    Attributes:
        declared: The identity the caller asserts (always present).
        authenticated: The identity verified by the auth boundary, or
            ``None`` when no boundary check ran.
    """

    declared: str
    authenticated: str | None = None
