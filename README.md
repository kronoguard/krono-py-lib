# krono

[![CI](https://github.com/kronoguard/krono-py-lib/actions/workflows/ci.yml/badge.svg)](https://github.com/kronoguard/krono-py-lib/actions/workflows/ci.yml)
[![Latest version](https://img.shields.io/badge/version-0.1.1-blue)](https://github.com/kronoguard/krono-py-lib/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-182-blue)](#)
[![Coverage](https://img.shields.io/badge/coverage-98.86%25-brightgreen)](#)
[![Open source](https://img.shields.io/badge/open%20source-yes-green)](#)

Tamper-evident audit records for MCP tool-call decisions. Python 3.11+, stdlib only, MIT.

## What `krono` is

`krono` is a Python library that appends one HMAC-chained JSONL record per allow/deny decision an MCP server makes at its tool boundary. A separate `krono verify` CLI re-walks the file with the same key and detects per-entry tampering (**including the last entry**), reordering, middle deletion, sequence rewriting, and schema violations — from `(log file, key)` alone, with no external state.

## What `krono` is NOT

- **Not a policy / allow-deny engine.** The integrator decides allow vs. deny; `krono` records the decision. There is no built-in policy DSL, no approval workflow, no rule store.
- **Not a multi-process append target.** One `AuditLog` instance per file per process. Multi-process writes against the same file are undefined behavior in v1.
- **Does NOT detect tail truncation.** If an adversary deletes the final N entries, the verifier walks the remaining prefix and returns `ok=True`. Detecting tail truncation requires an external anchor (sidecar signed-head file), which is deferred future work — see `docs/HONEST-CLAIMS.md`.
- **Not a published product.** v1 is a portfolio piece, bounded to ~3 days of focused work. No SaaS, no daemon, no exporter, no dashboard, no CI, no PyPI release.

## Quickstart

```bash
# 1. Get the source and install dev extras.
git clone https://github.com/kronoguard/krono-py-lib.git && cd krono-py-lib
uv sync --all-extras

# 2. Generate an HMAC key (32 raw bytes, hex-encoded).
export KRONO_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_bytes(32).hex())")

# 3. Run the reference example end-to-end (Pattern 1, per-tool inline).
uv run python examples/note_server.py

# 4. Verify the log the example just produced. The example prints its
#    log path on stdout; pass that path here. Exits 0 on success.
uv run krono verify /tmp/krono-demo.jsonl

# 5. (Optional) Run the full test suite, including the §17 acceptance gate.
make quality && make test
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
