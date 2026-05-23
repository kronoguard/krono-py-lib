# krono — Integrator Usage Reference

This document is a reference, organized by the question an integrator is trying to answer. The linear "first run" experience lives in the [README](../README.md); the contract-level shapes live in [`spec/SPEC_KRONO_PY_LIB.md`](../spec/SPEC_KRONO_PY_LIB.md). This page tells you how to make decisions about identity, restart handling, durability, and failure response in a real deployment.

## Quickstart

Five lines of code to a verified log:

```bash
uv sync --all-extras
export KRONO_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_bytes(32).hex())")
```

```python
import os
from krono import AuditLog, Decision, verify

with AuditLog(os.environ["KRONO_LOG_PATH"]) as audit:
    audit.record(tool_name="read_note", decision=Decision.ALLOW,
                 arguments={"id": "1"}, declared_identity="claude-desktop",
                 authenticated_identity=None, reason="default-allow")

assert verify(os.environ["KRONO_LOG_PATH"]).ok
```

Then verify from the CLI:

```bash
uv run krono verify "$KRONO_LOG_PATH"
```

Expected: `✓ krono audit verified: 1 entries (sequence 0..0)` followed by the tail-truncation note, exit code 0.

## The four Integration Patterns

`krono`'s public API supports four integration shapes. They are not exclusive; a single deployment may use more than one. Each has a fully runnable script under `examples/`.

**Pattern 1 — Per-tool inline.** Each tool function calls `audit.record(...)` directly, before doing its work. Use when there are few tools, when each tool has tool-specific decisions, and when the integrator wants explicit per-call control. This is the simplest shape and the easiest to read in code review. Reference: `examples/note_server.py`.

**Pattern 2 — Module-level singleton with restart resume.** A single `AuditLog` is constructed at module import time against a known path, and many code sites import it. On process restart, the constructor reads the last line of the existing log to recover the chain head (FR-16) — the chain continues seamlessly across boundaries. Use when many modules record, when the chain must survive routine process restarts, and when you can guarantee one writer per file per process. The integrator is responsible for not constructing two `AuditLog` instances against the same path within one process. Reference: `examples/audit_singleton.py`.

**Pattern 3 — Hook-style dispatch wrapper.** One central function (e.g. a FastMCP middleware) records every tool call before the body runs and either invokes the real dispatch on allow or raises a sentinel on deny. Use when one place is the right level for both policy and audit. The critical contract: `record()` runs BEFORE the tool body, so a deny is recorded even though the tool never runs, and an allow is recorded even if the body subsequently raises — the audit captures the decision, not the outcome. Reference: `examples/fastmcp_dispatch.py`.

**Pattern 4 — Auth-boundary identity wiring.** Two distinct identity fields (`declared_identity` and `authenticated_identity`) are sourced from two distinct places: declared from the MCP `clientInfo.name` (caller-asserted), authenticated from a verified principal (bearer-token `sub`, API-key principal, OS user). When the auth boundary fails, `authenticated_identity` stays `None` — it is never silently filled in from `declared`. Reference: `examples/with_bearer_auth.py`. The "Identity model" section below covers this in depth; the reference example is the runnable proof.

## Identity model

The two-field identity shape is the most-misused part of `krono`'s API. This section explains the intent and the failure modes.

**Field semantics:**

- **`declared_identity: str | None`.** The MCP client's self-asserted name (`clientInfo.name` or equivalent). The caller chose this string. The library does no validation; integrators should not validate it either — it is what the client said, recorded verbatim.
- **`authenticated_identity: str | None`.** A verified principal from an auth boundary. Common sources: a JWT's `sub` claim AFTER signature verification succeeded; an API-key lookup result; the OS user under whom the process runs (when `krono` is used inside a per-user container). If no auth boundary ran, or if it ran and FAILED, this field MUST be `None`.

**How to source each field in real integrations:**

- **From MCP `clientInfo`** — for declared: `req.headers.get("X-MCP-Client-Name")` or the parsed `clientInfo.name` from the MCP handshake. The MCP transport supplies this without verification.
- **From bearer tokens** — for authenticated: parse the `Authorization: Bearer <jwt>` header, call your JWT library's `verify(token, public_key)` (NOT `decode_unverified`), extract `sub` on success. On any exception, `authenticated_identity = None`.
- **From API keys** — for authenticated: look the API key up in your store, return the associated principal on success. On lookup failure, `authenticated_identity = None`.
- **From the OS user** — for authenticated: `getpass.getuser()` when the process is single-tenant and you trust the OS user as a principal. Less common; useful for local CLI tools.

**Never do this:**

| Bad code | Why it is wrong |
|---|---|
| `authenticated_identity = declared` | Collapses the two-field model. The audit log will show "the auth boundary ran and produced this subject" when the auth boundary did not run at all. This is precisely the bug FR-06 / I-06 exist to prevent. |
| `authenticated_identity = declared or "unknown"` | Same problem in a different costume. `"unknown"` is a real-looking string; downstream consumers cannot distinguish it from a real subject named "unknown". `None` (serialized as JSON `null`) is the ONLY honest signal for "auth boundary did not run". |
| `authenticated_identity = unverified_sub_from_token` | The whole point of authentication is the signature check. A `sub` claim extracted without verifying the token's signature is a string an attacker controls. Pass it as `authenticated_identity` and your audit log becomes evidence of an attacker's claims, not of your auth boundary's findings. |

**The reason both fields exist:** so that "the auth boundary did not run on this request" is observable in the audit log months after the fact. Once you collapse the two into one, there is no way to tell from the log whether a recorded principal was verified or merely declared. That distinction is what makes the audit log forensically useful.

## Operating notes

**Key generation:**

```bash
export KRONO_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_bytes(32).hex())")
```

The library validates the key (≥32 raw bytes after hex decode) BEFORE opening any file, so a missing or short key surfaces at startup, not at first decision.

**Key rotation policy.** v1 does not support mid-log rotation. If you must rotate, start a new log file under the new key. Verification of the old file still requires the old key (keep it). Rotation as a first-class feature is deferred to v2 (see `docs/HONEST-CLAIMS.md` §"Future work").

**Restart semantics (FR-16 resume).** On `AuditLog(path)` construction against a non-empty existing file, the library reads ONLY the last line to recover `next_sequence` and `last_current_hash`. It does NOT re-verify the chain. This is a deliberate design choice: re-verifying the entire chain on every startup couples integrator boot time to log size, which is the wrong default.

**Verify-on-startup best practice (non-normative).** Because resume reads only the last line, middle-entry tampering performed BEFORE a restart is INVISIBLE to the resumed writer — it will happily append valid new entries on top of a globally invalid log, and only `verify()` catches the pre-existing tamper. If your deployment treats "the writer started cleanly" as evidence of log integrity, you are making an unsafe assumption. Operators who need full-chain validation on startup should call `verify(path)` at process boot, before constructing the first `AuditLog`. The library does not do this automatically because most deployments can tolerate the gap and would not tolerate the boot-time cost.

**Manual recovery on a torn last line.** If the last line of the existing log fails to parse on resume (missing trailing newline, malformed JSON, missing required field), the constructor raises `WriteError("last line malformed at offset N")` and the file is left unchanged on disk. The library does NOT auto-repair. Options for the operator: (a) inspect the file, decide whether the partial line was a never-confirmed event, and remove it manually if so; (b) repair the partial line manually if it is salvageable. Then re-construct `AuditLog`.

**`fsync` trade-off (FR-14).** `AuditLog(path, fsync=True)` calls `os.fsync(fd)` after every record's `flush()`. Default is `fsync=False`. With `fsync=True`, you trade throughput for durability under `SIGKILL` / power loss: each record incurs an additional syscall and a disk-level write barrier. Both choices are defensible. Recommended: `fsync=True` for audit-critical deployments where losing the last few un-flushed entries on a crash would compromise the audit trail; `fsync=False` (default) for portfolio / development / low-stakes use.

**Log rotation policy.** v1 does not rotate logs from inside the writer's lifetime. The single audit log file grows for the life of the process. Rotation strategies in v1: (a) rotate at process restart — open a new file, archive the old one; (b) accept that the file grows. The library has no `max_bytes` or `max_lines` knob; adding one is deferred future work.

## Failure-response patterns

When `AuditLog.record(...)` raises `WriteError` mid-request (disk full, I/O error, filesystem revoked), the integrator must choose how the in-flight tool call behaves. Two named patterns; both are valid; the trade-off depends on the deployment's posture.

**Pattern A — fail-closed.** Catch `WriteError` and re-raise from the tool handler. The MCP call returns an error to the client. The tool body does NOT run.

```python
try:
    audit.record(...)
except WriteError as exc:
    # Re-raise so the MCP transport returns an error to the client.
    raise McpError(f"audit recording failed: {exc}") from exc
# audit.record() succeeded; safe to run the tool body now.
run_tool_body()
```

Recommended for audit-critical deployments: if you cannot prove a decision happened, you do not run the consequence of that decision. Compliance settings, regulated industries, and any deployment where "I lost the audit but did the work" is worse than "I did neither" should use this pattern.

**Pattern B — fail-open-with-warning.** Catch `WriteError`, emit an out-of-band operational alert (Prometheus counter, syslog warning, Slack page), and allow the tool to proceed.

```python
try:
    audit.record(...)
except WriteError as exc:
    operational_alert.fire("krono_record_failed", error=str(exc))
    # Audit gap during I/O outage; explicitly accepted by the operator.
run_tool_body()
```

Acceptable ONLY if the operator has explicitly accepted that audit gaps will occur during I/O outages. Useful for low-stakes deployments where tool availability matters more than audit completeness — but the operator must understand that an attacker who can cause `WriteError` (fill the disk, revoke the mount) can now run tools without leaving an audit trail.

**Do not pick one universally.** The right pattern depends on whether the integrator's deployment treats audit gaps as a worse failure than tool unavailability, or the other way around. `krono` does not encode a preference — `WriteError` propagates and the integrator decides. The library's job is to make sure neither path is silent: a successful `record()` is durable, and a failed `record()` is loud.
