"""Pattern 2 — Module-level singleton with restart resume.

Demonstrates FR-16 resume: closing one ``AuditLog`` instance and opening a
SECOND one against the same path picks up where the first left off, with
``next_sequence`` and ``previous_hash`` chained seamlessly across the
boundary.

The script simulates a process restart by:

1. Constructing ``AuditLog`` against a path, recording two events, closing.
2. Constructing a SECOND ``AuditLog`` against the SAME path (a fresh
   process would do this on import of an ``audit_instance`` module), and
   recording two more events.

After both phases run, ``verify()`` walks the file and reports
``entries_checked == 4`` with the chain intact across the restart boundary.

Run end-to-end::

    KRONO_AUDIT_KEY=<64-hex> uv run python examples/audit_singleton.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from krono import AuditLog, Decision, verify

# Per-phase and total event counts for assertions. Named so PLR2004 is happy.
_PHASE_EVENT_COUNT: int = 2
_TOTAL_EVENT_COUNT: int = _PHASE_EVENT_COUNT * 2

# ---------------------------------------------------------------------------
# Path resolution — same convention as the other example scripts.
# ---------------------------------------------------------------------------


def _resolve_log_path() -> Path:
    """Return the path to write the audit log to."""
    env_path = os.environ.get("KRONO_LOG_PATH")
    if env_path:
        return Path(env_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="krono-singleton-"))
    return tmp_dir / "demo.jsonl"


# ---------------------------------------------------------------------------
# Helpers — Pattern 2 records via a single, shared AuditLog per phase. In a
# real server, each phase would be a fresh process importing an
# ``audit_instance`` module that constructs ``AuditLog`` at import time.
# ---------------------------------------------------------------------------


def _record_pair(audit: AuditLog, phase_label: str) -> None:
    """Record two events through ``audit`` — one allow, one deny."""
    audit.record(
        tool_name="read_note",
        decision=Decision.ALLOW,
        arguments={"id": f"{phase_label}-a"},
        declared_identity="claude-desktop",
        authenticated_identity=None,
        reason=f"{phase_label}: default-allow read",
    )
    audit.record(
        tool_name="delete_note",
        decision=Decision.DENY,
        arguments={"id": f"{phase_label}-b"},
        declared_identity="claude-desktop",
        authenticated_identity=None,
        reason=f"{phase_label}: destructive",
    )


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> int:
    """Run the two-phase singleton + resume demo and verify the result."""
    log_path = _resolve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"krono-audit-singleton: log={log_path}")

    # --- Phase 1: first "process" writes two events. ---
    audit_a = AuditLog(log_path)
    try:
        _record_pair(audit_a, phase_label="phase-1")
    finally:
        audit_a.close()
    assert audit_a.next_sequence == _PHASE_EVENT_COUNT, f"phase-1 next_seq: {audit_a.next_sequence}"
    print(f"phase-1: wrote {_PHASE_EVENT_COUNT} events; next_sequence={audit_a.next_sequence}")

    # --- Phase 2: simulated restart — fresh AuditLog against the SAME path. ---
    # FR-16: the constructor reads the last line and recovers next_sequence
    # and last_current_hash without re-verifying the chain.
    audit_b = AuditLog(log_path)
    try:
        # Sanity: resume picked up where phase 1 left off.
        assert audit_b.next_sequence == _PHASE_EVENT_COUNT, (
            f"resume failed to pick up seq {_PHASE_EVENT_COUNT}: got {audit_b.next_sequence}"
        )
        _record_pair(audit_b, phase_label="phase-2")
    finally:
        audit_b.close()
    assert audit_b.next_sequence == _TOTAL_EVENT_COUNT, f"phase-2 next_seq: {audit_b.next_sequence}"
    print(f"phase-2: wrote {_PHASE_EVENT_COUNT} more events; next_sequence={audit_b.next_sequence}")

    # --- Whole-file verify across the restart boundary. ---
    result = verify(log_path)
    assert result.ok is True, f"verify failed: {result.failure!r}"
    assert result.entries_checked == _TOTAL_EVENT_COUNT, (
        f"expected {_TOTAL_EVENT_COUNT} events, got {result.entries_checked}"
    )
    print(f"OK: verified {result.entries_checked} entries (across simulated restart) at {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
