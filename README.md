# krono

[![CI](https://github.com/kronoguard/krono-py-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/kronoguard/krono-py-lib/actions/workflows/ci.yml)
[![Latest version](https://img.shields.io/badge/version-0.2.0-blue)](https://github.com/kronoguard/krono-py-lib/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-207-blue)](#)
[![Coverage](https://img.shields.io/badge/coverage-98.92%25-brightgreen)](#)
[![Open source](https://img.shields.io/badge/open%20source-yes-green)](#)

Tamper-evident audit records for MCP tool-call decisions. Python 3.11+, stdlib only, MIT.

## What `krono` is

`krono` is a Python library that appends one HMAC-chained JSONL record per allow/deny decision an MCP server makes at its tool boundary. A separate `krono verify` CLI re-walks the file with the same key and detects per-entry tampering (**including the last entry**), reordering, middle deletion, sequence rewriting, and schema violations — from `(log file, key)` alone, with no external state.

## What `krono` is NOT

- **Not a policy / allow-deny engine.** The integrator decides allow vs. deny; `krono` records the decision. There is no built-in policy DSL, no approval workflow, no rule store.
- **Not a multi-process append target.** One `AuditLog` instance per file per process. Multi-process writes against the same file are undefined behavior in v1.
- **Does NOT detect tail truncation.** If an adversary deletes the final N entries, the verifier walks the remaining prefix and returns `ok=True`. Detecting tail truncation requires an external anchor (sidecar signed-head file), which is deferred future work — see `docs/HONEST-CLAIMS.md`.
- **Not a SaaS product.** Library-only — no daemon, no exporter, no dashboard, no policy engine. Released on PyPI as [`krono-py`](https://pypi.org/project/krono-py/) (see [Install](#install)); a small portfolio-scope library, not a hosted service.

## Install

```bash
pip install krono-py
# or, with the MCP integration extra used by examples/note_server.py:
pip install "krono-py[mcp]"
```

Note the **distribution name** is `krono-py` (the bare `krono` name on PyPI
was already taken). The **import name** is still `krono`:

```python
from krono import AuditLog, Decision, verify
```

Released from <https://pypi.org/project/krono-py/>. Release/publishing process
documented in [`docs/PUBLISHING.md`](docs/PUBLISHING.md).

## Quickstart

```bash
# 1. Generate an HMAC key (32 raw bytes, hex-encoded).
export KRONO_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_bytes(32).hex())")

# 2. Record one event and verify it (~10 lines of Python).
python - <<'PY'
import os, tempfile, pathlib
from krono import AuditLog, Decision, Identity, verify

log = pathlib.Path(tempfile.mkdtemp()) / "demo.jsonl"
with AuditLog(log) as audit:
    # v0.1.x two-string form still works:
    audit.record(tool_name="read_note", decision=Decision.ALLOW,
                 arguments={"id": "1"}, declared_identity="me",
                 authenticated_identity=None, reason="demo")
    # v0.2.0 adds an Identity dataclass as a constructor-side
    # convenience — on-disk format is byte-identical to v0.1.x:
    audit.record(tool_name="read_note", decision=Decision.ALLOW,
                 arguments={"id": "2"},
                 identity=Identity(declared="me"),
                 reason="demo-with-identity")
print("log:", log)
print("verify:", verify(log))
PY

# 3. Verify from the CLI too.
krono verify <log-path-from-above>
```

Building from source (for development) instead:

```bash
git clone https://github.com/kronoguard/krono-py-lib.git && cd krono-py-lib
uv sync --all-extras
make quality && make test         # full suite incl. §17 acceptance gate
uv run python examples/note_server.py
```

## HMAC key management

`krono` uses HMAC-SHA256. The key is **required**, must be at least 32 raw bytes after hex decoding (64 hex characters), and is sourced from `$KRONO_AUDIT_KEY` by default. An explicit `key: bytes` may be passed to `AuditLog(...)` or `verify(...)` to override.

**Generation** (one-time, per deployment):

```bash
export KRONO_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_bytes(32).hex())")
```

**Fail-loud behavior (FR-02):** if `$KRONO_AUDIT_KEY` is unset, empty, non-hex, or shorter than 32 bytes, `AuditLog(...)` and `verify(...)` raise `MissingKeyError` before any filesystem operation. The library **never** generates an ephemeral key as a fallback — the ChronoGuard `secret_key or secrets.token_bytes(32)` anti-pattern is explicitly forbidden. An audit chain signed with a key only the dead process ever knew is the same as having no chain at all.

The exception message references only the env-var name, never the key material itself. The key is never written to the audit file, never logged, never echoed.

## MCP integration example

`examples/note_server.py` is the reference Pattern-1 integration — one `audit.record(...)` call inline in each tool body. The script mocks a tiny note server with two tools and produces two events end-to-end:

```python
audit = AuditLog(os.environ["KRONO_LOG_PATH"])

def read_note(audit, note_id, client_name):
    # Pattern 1: record BEFORE running the tool body.
    audit.record(
        tool_name="read_note",
        decision=Decision.ALLOW,
        arguments={"id": note_id},
        declared_identity=client_name,        # caller-asserted
        authenticated_identity=None,          # auth boundary did not run
        reason="default-allow read tool",
    )
    # Equivalent v0.2.0 form using the Identity dataclass (FR-41/42) —
    # on-disk bytes are identical to the two-string call above:
    #   audit.record(..., identity=Identity(declared=client_name),
    #                reason="default-allow read tool")
    return f"<note id={note_id}>"  # real tool body would do the DB read

def delete_note(audit, note_id, client_name):
    audit.record(
        tool_name="delete_note",
        decision=Decision.DENY,
        arguments={"id": note_id},
        declared_identity=client_name,
        authenticated_identity=None,
        reason="destructive",
    )
    return f"DENIED: cannot delete note {note_id} (destructive)"
```

Three other integration patterns are illustrated under `examples/`:

- `examples/audit_singleton.py` — module-level singleton with restart-resume (FR-16 in action).
- `examples/fastmcp_dispatch.py` — hook-style dispatch wrapper: one central place records every tool call before the body runs.
- `examples/with_bearer_auth.py` — auth-boundary identity wiring: how to keep `declared_identity` and `authenticated_identity` distinct.

See `docs/USAGE.md` for a deeper walkthrough of each pattern.

## `krono verify`

The CLI is a single subcommand:

```
krono verify [--key-env VAR] [--json] <log_path>
```

**Output (text mode, success):**

```
✓ krono audit verified: 247 entries (sequence 0..246)
  note: tail truncation not detectable from log alone (see HONEST-CLAIMS.md)
```

**Output (text mode, failure):**

```
✗ krono audit FAILED at line 132 (sequence 131): content_tampered
  current_hash mismatch
  expected: 6c2d5849d22e3c4d...
  actual:   41a733eac1fd344a...
```

**`--json` mode** emits one JSON object on stdout matching the schema in `spec/SPEC_KRONO_PY_LIB.md` §Interfaces; exit codes are unchanged.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | Verified (what is present) |
| 1 | Tampering detected |
| 2 | Usage error (bad/missing args; argparse default) |
| 3 | Configuration or I/O error (key missing, file unreadable) |

`--key-env VAR` overrides the env-var name (default `KRONO_AUDIT_KEY`) — useful in multi-tenant deployments where one machine holds several keys.

## Honest claim boundary

`krono` makes a narrow, deliberately small set of claims and documents what it does **not** detect. The summary:

- **Detected:** per-entry tampering on any byte of any entry (including the last); reordering; middle deletion; sequence-number rewriting; payload permutation; schema violations; invalid JSON.
- **NOT detected:** **tail truncation** (the last N entries deleted with no gap left behind); whole-file deletion; forgery by an attacker holding the HMAC key; integrators passing fabricated `authenticated_identity` values; argument-secret leakage via `tool_name` or `reason` (only `arguments` is hashed).
- **Investigability trade-off:** raw arguments are hashed (FR-07) and never written to the log. The hash proves a known arguments value matches a given event but does not enable browsing what was sent.

Full enumeration with `FailureKind` values and test names lives in [`docs/HONEST-CLAIMS.md`](docs/HONEST-CLAIMS.md). The single phrase **tail truncation** appears there, in the CLI success message, and in this README's "What `krono` is NOT" — by design. Audit libraries that hide their limits invite the kind of misplaced trust the mcp-firewall reviewer flagged; we make the limits load-bearing instead.

## License

MIT. See `LICENSE`.
