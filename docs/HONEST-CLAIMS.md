# Honest Claim Boundary

`krono` makes a narrow set of claims and documents — exactly — what it does NOT detect. This document is the load-bearing companion to README §"Honest claim boundary": every attack covered by the spec's §Security tables appears here with a detected/not-detected verdict, the FR-37 verification check that catches it (when applicable), the reported `FailureKind` value, and the test name that proves it.

Read this BEFORE relying on `krono` for compliance, forensics, or any deployment where the cost of an undetected tamper is higher than the cost of integrating an external tool.

## FR-37 verification check order (for reference)

For each line, the verifier evaluates these checks in order and returns on the FIRST violated check:

1. `PARSE_ERROR` — line is not valid JSON.
2. `UNEXPECTED_FIELD` — parsed JSON has a top-level key not in the 11-field schema.
3. `MISSING_FIELD` — parsed JSON is missing one of the 11 required keys.
4. `SEQUENCE_GAP` — `event["sequence_number"]` does not equal the expected `0..N-1` position.
5. `CHAIN_BREAK` — `event["previous_hash"]` does not equal the expected prior chain head.
6. `CONTENT_TAMPERED` — recomputed HMAC `current_hash` does not match the stored value.

This ordering is normative — it determines which `FailureKind` is reported when more than one check would fire.

## Detected attacks (verifier returns `ok=False`)

| Attack | Caught by (FR-37 step) | Reported `kind` | Test |
|---|---|---|---|
| Non-sequence field on the LAST entry mutated (e.g. `"decision":"deny"` → `"allow"`) — the mcp-firewall miss | Step 6 — HMAC recomputation | `content_tampered` | `UT-Verify-Tamper-Last`, `IT-Acceptance-A` |
| Non-sequence field on a MIDDLE entry mutated (e.g. `tool_name`) | Step 6 — HMAC recomputation | `content_tampered` | `UT-Verify-Tamper-Mid` |
| `sequence_number` rewritten on an existing entry (no other field touched) | Step 4 — gapless sequence check fires before hash check | `sequence_gap` | `UT-Verify-Sequence-Rewrite` |
| Middle entry deleted (3 → 2 entries) | Step 4 — successor's `sequence_number` skips the expected value | `sequence_gap` | `UT-Verify-Middle-Delete`, `IT-Acceptance-B` |
| Whole JSONL lines swapped (each retains its original `sequence_number`) | Step 4 — file-position-2 line carries `sequence_number=3`, expected `2` | `sequence_gap` | `UT-Verify-Reorder` |
| Payload permutation between two entries (each line keeps file-position-correct `sequence_number`; `previous_hash` mismatches) | Step 5 — chain check | `chain_break` | `UT-Verify-ChainBreak-PayloadPermute`, `AC-43` |
| New entry forged without the HMAC key | Step 6 — HMAC recomputation | `content_tampered` | `UT-Verify-Wrong-Key` (and the §17 demo's negative cases) |
| Extra top-level field added (`"foo":"bar"`) | Step 2 — schema-closedness | `unexpected_field` | `UT-Verify-Schema`, `UT-Verify-Order-Schema-Before-Hash` |
| Required field removed | Step 3 — missing-field check | `missing_field` | `UT-Verify-Schema` |
| Line is invalid JSON (truncated mid-write, garbled bytes) | Step 1 — `json.loads` raises | `parse_error` | `UT-Verify-Schema` (non-JSON sub-case) |
| Blank line in the middle of an otherwise valid log | Step 1 — blank line treated as parse error | `parse_error` | `UT-Verify-BlankLine` |
| Last line lacks trailing `\n` at verify time | Step 1 (typically) or step 6 (if it happens to parse) | `parse_error` or `content_tampered` | `UT-Verify-NoTrailingNewline` |

## NOT detected (documented v1 limits)

| Attack | Why undetected | Mitigation |
|---|---|---|
| **Tail truncation** (final N entries deleted) | The verifier sees a consistent prefix; no external anchor exists in v1. The check order is "is each line you have valid?", not "is anything missing from the end?" | Future work: sidecar signed-head file (committed to a separate trust boundary on each append). Until then, operators who need tail-truncation detection should not use `krono` alone. |
| **Whole log file deleted** | The verifier needs a file to inspect. A missing file raises `ConfigError`, not `ok=False`. | Out of scope by the same logic as tail truncation; the same sidecar approach addresses both. |
| **Forgery by an attacker holding `$KRONO_AUDIT_KEY`** | HMAC is symmetric: anyone with the key can produce valid `current_hash` values. The key MUST live on the writer; that exposure is unavoidable for symmetric MAC. | Run the writer in a smaller trust boundary than the verifier. Future work: Ed25519 signing so the writer holds only a private key and verifiers hold only the public half. |
| **Integrator passing fabricated `authenticated_identity`** | `krono` records what the integrator passes; it does not run auth. If the integrator writes the declared name into `authenticated_identity`, the audit log faithfully records that lie. | Code review at the integration boundary; the `examples/with_bearer_auth.py` and `docs/USAGE.md` §"Identity model" make the correct shape explicit. |
| **Argument-secret leakage via `tool_name` or `reason`** | Only `arguments` is hashed; `tool_name` and `reason` are written verbatim. An operator who puts a token into `reason` will see that token on disk. | Discipline — never put secrets in `tool_name` or `reason`. The two fields exist for human-readable context, not for sensitive content. |
| **Post-hoc investigation of "what arguments produced this decision"** | See "Investigability limit" below. | Operators who need full argument provenance must store arguments elsewhere (with their own access controls) and correlate via `arguments_hash`. |
| **Pre-restart middle tampering masking itself as a fresh log** | FR-16 resume reads only the LAST line to recover `next_sequence` and `last_current_hash`; it does NOT re-verify the chain. A restarted writer will happily append on top of a globally-tampered log. | Operators who need full-chain validation across restarts should call `verify()` at startup. `docs/USAGE.md` §"Operating notes" documents this as a non-normative best practice. |

## The mcp-firewall case

The motivating example for `krono` is `mcp-firewall`'s last-entry verifier. Given a 2-entry log and an attacker who flips the FINAL entry's `"decision":"deny"` to `"decision":"allow"`, `mcp-firewall`'s verifier reports `✓ integrity verified` (per `krono-status.md` §4A, Case B). The reason: its verifier loop applies the hash check to every line EXCEPT the last (the chain ends there, so the implementor reasoned "no successor means no check") — and an HMAC of the modified payload obviously doesn't match the original `current_hash`, but the loop never recomputes it.

`krono` does NOT have a "skip the last line" special case. FR-18 is normative: "This check applies uniformly to every entry, **including the last** — there is no special-case skip for the final line." `IT-Acceptance-A` is the regression test: a 2-entry log with the final decision flipped MUST surface as `failure.kind == FailureKind.CONTENT_TAMPERED, failure.sequence_number == 1, failure.line == 2`. If `IT-Acceptance-A` ever fails, `krono` has regressed into the same hole `mcp-firewall` has.

## Investigability limit

`arguments` is hashed via `arguments_hash = sha256(canonical_json(arguments)).hexdigest()` (FR-07) and the raw mapping is discarded. The raw arguments value never appears on disk, never appears in `AuditEvent`, and is never returned to the caller.

**What this enables:** an operator who still holds an arguments value can prove (or disprove) that it was the one that produced a given audit event — `sha256(canonical_json(known_arguments))` either equals the stored `arguments_hash` or it does not.

**What this does NOT enable:** browsing argument history post-hoc. "What did this client send when they got denied?" is not a question `krono` can answer alone. The arguments are gone the moment `record()` returns.

This is a deliberate privacy-and-secret-leakage trade-off. MCP tool arguments routinely contain bearer tokens, customer PII, internal IDs, and other material whose persistence on disk would convert an audit feature into a data-exfiltration vector. `krono` opts for auditability without exfiltration: the audit log proves what happened without storing what was said. Operators who need full argument provenance must store arguments elsewhere, with their own access controls, and correlate via `arguments_hash` when needed.

There is no flag to disable this. There will not be one in v1.

## Key handling

HMAC-SHA256 is a symmetric MAC. There is exactly one key, used for both signing (writer) and verifying (CLI / `verify()`). The key holder can produce any chain they like; the chain proves only that someone who knew the key wrote it.

Therefore:

- **The key MUST NOT live in the same trust boundary as the writer** if you want defense in depth against a compromised writer. In practice this means: don't store `$KRONO_AUDIT_KEY` in a CI runner's environment alongside the audit log; don't write it to the same disk image; don't echo it in container logs.
- **Exception messages reference only the env-var name** (`KRONO_AUDIT_KEY shorter than 32 bytes`). The library never logs or echoes key material; an attacker who reads a `MissingKeyError` traceback learns nothing useful.
- **No ephemeral fallback. Ever.** If `$KRONO_AUDIT_KEY` is unset, `AuditLog(...)` raises `MissingKeyError` BEFORE opening any file. The ChronoGuard `secret_key or secrets.token_bytes(32)` pattern — which silently generates a key only the dead process knows — is the precise anti-pattern FR-02 exists to prevent.
- **Rotation.** v1 does not rotate keys mid-log. If you must rotate, start a new log file under the new key. Verification of the old file still requires the old key.

## Future work

Each of these closes one row of the "NOT detected" table; none is in v1.

- **Sidecar signed-head file** — close tail-truncation detection. The writer maintains a separate, append-only file holding the rolling `(highest sequence_number, last current_hash, timestamp_utc, signature)` tuple. The verifier reads both files. If the audit log's highest sequence is less than the sidecar's most-recent claim, the verifier reports a new `TAIL_TRUNCATION` failure kind. The sidecar lives in a different trust boundary than the audit log.
- **Ed25519 signing per entry** — close the symmetric-MAC limit. The writer holds a private key; verifiers hold only the public half. A compromised verifier cannot forge entries.
- **Multi-process writer service** — close the single-process limit. A small in-process queue plus a single dedicated writer process serializes appends from many app processes against the same chain.
- **Key rotation** — close the rotation gap. Probably: chain entries record which key-id signed them; verify accepts a keyring rather than a single key; rotation events are themselves recorded entries with a special `kind`.

None of these will land in v1. Any of them is straightforward future work given the v1 contract; the v1 contract is deliberately small so the additions are additive, not breaking.
