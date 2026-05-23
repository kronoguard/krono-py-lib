"""Pattern 3 — Hook-style dispatch wrapper (FastMCP middleware shape).

A single ``audit_dispatch`` function records ONE event per tool call
BEFORE running the tool body. On an allow decision it then runs the
underlying tool; on a deny it records and raises ``McpDenyError`` without
running the body.

This pattern centralizes audit recording at the dispatch layer — useful
when many tools share the same policy + audit logic and you want one
place to enforce both.

Key contracts demonstrated:

1. Allow path: record runs, then the tool body runs.
2. Deny path: record runs, then a sentinel exception is raised — the tool
   body never executes. The audit captures the DECISION, not the outcome.
3. Retry path: calling the wrapper twice for the same logical operation
   results in TWO audit events (no de-dup), because each call is a
   separate decision point.

Run end-to-end::

    KRONO_AUDIT_KEY=<64-hex> uv run python examples/fastmcp_dispatch.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from krono import AuditLog, Decision, verify

# Total events this script records: 1 allow + 1 deny + 2 retries (all allow).
# Named so PLR2004 stays happy.
_EXPECTED_EVENT_COUNT: int = 4

# ---------------------------------------------------------------------------
# Path resolution — same convention as the other example scripts.
# ---------------------------------------------------------------------------


def _resolve_log_path() -> Path:
    """Return the path to write the audit log to."""
    env_path = os.environ.get("KRONO_LOG_PATH")
    if env_path:
        return Path(env_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="krono-fastmcp-"))
    return tmp_dir / "demo.jsonl"


# ---------------------------------------------------------------------------
# Mock FastMCP-shaped types.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MockContext:
    """Minimal context object imitating a FastMCP request context."""

    client_name: str
    principal: str | None  # None when the auth boundary did not run


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of the integrator's policy evaluation for one dispatch."""

    outcome: Decision
    reason: str


class McpDenyError(Exception):
    """Sentinel raised by the dispatch wrapper on a deny decision."""


# ---------------------------------------------------------------------------
# Mock tool registry and policy.
# ---------------------------------------------------------------------------


def _policy_evaluate(name: str, _args: dict[str, Any], _ctx: MockContext) -> PolicyDecision:
    """Toy policy: allow ``read_*`` tools, deny ``delete_*`` tools."""
    if name.startswith("read_"):
        return PolicyDecision(outcome=Decision.ALLOW, reason=f"default-allow {name}")
    if name.startswith("delete_"):
        return PolicyDecision(outcome=Decision.DENY, reason="destructive")
    return PolicyDecision(outcome=Decision.DENY, reason=f"unknown tool: {name}")


def _real_dispatch(name: str, args: dict[str, Any]) -> str:
    """Mock tool body — only runs on allow."""
    return f"<{name} args={args}>"


# ---------------------------------------------------------------------------
# The Pattern-3 dispatch wrapper — the central audit + policy site.
# ---------------------------------------------------------------------------


def audit_dispatch(
    audit: AuditLog,
    name: str,
    args: dict[str, Any],
    ctx: MockContext,
    real_dispatch: Callable[[str, dict[str, Any]], str] = _real_dispatch,
) -> str:
    """Record one event, then either run the tool body or raise ``McpDenyError``.

    The audit record is appended BEFORE the tool body runs. On a deny
    decision, ``McpDenyError`` propagates and the body never executes.
    """
    decision = _policy_evaluate(name, args, ctx)
    audit.record(
        tool_name=name,
        decision=decision.outcome,
        arguments=args,
        declared_identity=ctx.client_name,
        authenticated_identity=ctx.principal,
        reason=decision.reason,
    )
    if decision.outcome is Decision.DENY:
        raise McpDenyError(decision.reason)
    return real_dispatch(name, args)


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> int:
    """Drive three dispatch scenarios end-to-end and verify the log."""
    log_path = _resolve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"krono-fastmcp-dispatch: log={log_path}")

    ctx = MockContext(client_name="claude-desktop", principal=None)

    with AuditLog(log_path) as audit:
        # 1. Allow path — record runs, tool body runs.
        result_a = audit_dispatch(audit, "read_note", {"id": "1"}, ctx)
        print(f"allow path -> {result_a}")

        # 2. Deny path — record runs, McpDenyError raised, body never runs.
        try:
            audit_dispatch(audit, "delete_note", {"id": "2"}, ctx)
        except McpDenyError as exc:
            print(f"deny path raised McpDenyError: {exc}")
        else:
            raise AssertionError("deny path did not raise McpDenyError")

        # 3. Retry path — same logical call twice, both produce events.
        # The wrapper does NOT de-dup; each dispatch is a separate decision.
        retry_result_1 = audit_dispatch(audit, "read_note", {"id": "3"}, ctx)
        retry_result_2 = audit_dispatch(audit, "read_note", {"id": "3"}, ctx)
        print(f"retry path -> {retry_result_1}, {retry_result_2}")

    # Verify: 4 events total (allow + deny + 2 retries).
    result = verify(log_path)
    assert result.ok is True, f"verify failed: {result.failure!r}"
    assert result.entries_checked == _EXPECTED_EVENT_COUNT, (
        f"expected {_EXPECTED_EVENT_COUNT} events, got {result.entries_checked}"
    )
    print(f"OK: verified {result.entries_checked} entries at {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
