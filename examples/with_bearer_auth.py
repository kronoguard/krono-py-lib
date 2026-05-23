"""Pattern 4 — Auth-boundary identity wiring (the two-field model).

Demonstrates FR-06 / I-06: ``declared_identity`` (caller-asserted) and
``authenticated_identity`` (verified by an auth boundary) are kept in
distinct fields. The whole point of the two-field shape is to make
"the auth boundary did not run" observable in the audit log.

This script records THREE events in order:

1. **No Authorization header.** ``declared_identity="claude-desktop"``,
   ``authenticated_identity=None``. The auth boundary did not run.
2. **Valid bearer token.** ``declared_identity="claude-desktop"``,
   ``authenticated_identity="user:alice@example.com"`` — the verified
   subject. Critically DISTINCT from ``declared_identity``: the JWT's
   ``sub`` claim is what the auth boundary proved, not what the caller
   claimed.
3. **Invalid bearer token.** Verifier raises; the integrator MUST set
   ``authenticated_identity=None``, NEVER fall back to ``declared``.
   Recording ``declared`` as ``authenticated`` here would silently
   collapse the two-field model and is the bug FR-06 / I-06 exist to
   prevent.

Run end-to-end::

    KRONO_AUDIT_KEY=<64-hex> uv run python examples/with_bearer_auth.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from krono import AuditLog, Decision, verify

# Three request shapes → three audit events. Named so PLR2004 stays happy.
_EXPECTED_EVENT_COUNT: int = 3

# ---------------------------------------------------------------------------
# Path resolution — same convention as the other example scripts.
# ---------------------------------------------------------------------------


def _resolve_log_path() -> Path:
    """Return the path to write the audit log to."""
    env_path = os.environ.get("KRONO_LOG_PATH")
    if env_path:
        return Path(env_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="krono-bearer-auth-"))
    return tmp_dir / "demo.jsonl"


# ---------------------------------------------------------------------------
# Mock JWT verifier — DEMO ONLY. Real code uses a JWT library.
# ---------------------------------------------------------------------------


class JwtError(Exception):
    """Raised by the mock JWT verifier on an unparseable / unsigned token."""


_VALID_TOKEN: str = "demo.valid.token"
_VALID_SUBJECT: str = "user:alice@example.com"


def verify_jwt(token: str) -> dict[str, str]:
    """Toy JWT verifier — accepts exactly one token, rejects everything else.

    Real auth boundaries call into a JWT library (PyJWT, Authlib, …) here.
    """
    if token == _VALID_TOKEN:
        return {"sub": _VALID_SUBJECT}
    raise JwtError(f"invalid token: {token!r}")


# ---------------------------------------------------------------------------
# Identity derivation — the FR-06 contract in code form.
# ---------------------------------------------------------------------------


def derive_identities(
    declared: str,
    authorization_header: str | None,
) -> tuple[str, str | None]:
    """Return ``(declared, authenticated)`` per the FR-06 two-field model.

    The CRITICAL rule: on a missing OR invalid token, ``authenticated``
    stays ``None``. We NEVER fall back to ``declared``. NEVER set it to
    ``"unknown"``. NEVER set it to the raw token.
    """
    if authorization_header is None:
        return declared, None

    token = authorization_header.removeprefix("Bearer ").strip()
    if not token:
        return declared, None

    try:
        claims = verify_jwt(token)
    except JwtError:
        # Auth boundary ran and FAILED → authenticated stays None.
        return declared, None
    return declared, claims["sub"]


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> int:
    """Record three events with three different identity combinations."""
    log_path = _resolve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"krono-with-bearer-auth: log={log_path}")

    declared = "claude-desktop"

    # Three request shapes the auth boundary might see.
    request_shapes = [
        ("no-header", None),
        ("valid-token", f"Bearer {_VALID_TOKEN}"),
        ("invalid-token", "Bearer this-is-not-the-valid-token"),
    ]

    with AuditLog(log_path) as audit:
        for label, header in request_shapes:
            declared_id, authenticated_id = derive_identities(declared, header)
            audit.record(
                tool_name="read_note",
                decision=Decision.ALLOW,
                arguments={"id": label},
                declared_identity=declared_id,
                authenticated_identity=authenticated_id,
                reason=f"demo: {label}",
            )
            print(f"recorded {label}: declared={declared_id!r}, authenticated={authenticated_id!r}")

    # Verify the resulting log.
    result = verify(log_path)
    assert result.ok is True, f"verify failed: {result.failure!r}"
    assert result.entries_checked == _EXPECTED_EVENT_COUNT, (
        f"expected {_EXPECTED_EVENT_COUNT} events, got {result.entries_checked}"
    )
    print(f"OK: verified {result.entries_checked} entries at {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
