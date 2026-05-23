"""Pattern 1 — Per-tool inline audit recording.

The simplest integration shape: each MCP tool function calls
``audit.record(...)`` inline before doing its work. Decisions and
identities are populated explicitly per call.

This script mocks a tiny note-server with two tools:

* ``read_note(id)``    — allowed; records ``decision=Decision.ALLOW`` and runs.
* ``delete_note(id)``  — denied;  records ``decision=Decision.DENY`` and
                         returns a deny message without modifying state.

Run end-to-end::

    KRONO_AUDIT_KEY=<64-hex> uv run python examples/note_server.py

Honors ``$KRONO_LOG_PATH``; otherwise writes to a fresh tempdir and prints
the chosen path on stdout so test harnesses can discover it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from krono import AuditLog, Decision, verify

# Number of audit events this script appends — one allow (read), one deny
# (delete). Used in the final assertion; named so PLR2004 stays happy.
_EXPECTED_EVENT_COUNT: int = 2

# ---------------------------------------------------------------------------
# Setup: resolve log path. Prefer KRONO_LOG_PATH so tests can pre-pin it;
# fall back to a tempdir and PRINT the path so test_examples.py can
# discover the produced log via stdout scanning.
# ---------------------------------------------------------------------------


def _resolve_log_path() -> Path:
    """Return the path to write the audit log to."""
    env_path = os.environ.get("KRONO_LOG_PATH")
    if env_path:
        return Path(env_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="krono-note-server-"))
    return tmp_dir / "demo.jsonl"


# ---------------------------------------------------------------------------
# Tool implementations — Pattern 1: record() inline, then run (or deny).
# ---------------------------------------------------------------------------


def read_note(audit: AuditLog, note_id: str, client_name: str) -> str:
    """Return the (mock) content of a note after recording an allow.

    Pattern 1: record BEFORE running the tool body. ``authenticated_identity``
    is None here because this demo has no auth boundary established.
    """
    audit.record(
        tool_name="read_note",
        decision=Decision.ALLOW,
        arguments={"id": note_id},
        declared_identity=client_name,
        authenticated_identity=None,
        reason="default-allow read tool",
    )
    # Mock tool body — in a real server this is a DB read.
    return f"<note id={note_id}>"


def delete_note(audit: AuditLog, note_id: str, client_name: str) -> str:
    """Record a deny for the destructive operation; do NOT mutate state."""
    audit.record(
        tool_name="delete_note",
        decision=Decision.DENY,
        arguments={"id": note_id},
        declared_identity=client_name,
        authenticated_identity=None,
        reason="destructive",
    )
    # The audit captured the decision; the tool body returns a deny message
    # rather than running.
    return f"DENIED: cannot delete note {note_id} (destructive)"


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> int:
    """Drive the two tools end-to-end and verify the resulting log."""
    log_path = _resolve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Print the path so tests using stdout-scan can discover it.
    print(f"krono-note-server: log={log_path}")

    with AuditLog(log_path) as audit:
        allow_msg = read_note(audit, note_id="1", client_name="claude-desktop")
        deny_msg = delete_note(audit, note_id="1", client_name="claude-desktop")

    print(f"read_note  -> {allow_msg}")
    print(f"delete_note -> {deny_msg}")

    result = verify(log_path)
    assert result.ok is True, f"verify failed: {result.failure!r}"
    assert result.entries_checked == _EXPECTED_EVENT_COUNT, (
        f"expected {_EXPECTED_EVENT_COUNT} events, got {result.entries_checked}"
    )
    print(f"OK: verified {result.entries_checked} entries at {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
