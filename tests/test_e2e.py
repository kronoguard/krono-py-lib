"""End-to-end tests — the full integrator workflow exercised in one go.

Activates the `@pytest.mark.e2e` marker (previously a no-op selector
behind ``make test-e2e``). Each test simulates a realistic deployment
sequence: write events under a key, restart the process, write more,
verify via the CLI subprocess, then explicitly tamper and assert the
CLI catches it.

These tests are slower than unit tests (subprocess + multi-second
sequences) and live in tests/ so they're picked up by `make test-e2e`
selectively. They are NOT part of the `make test` coverage gate
critical path (they pass through the same library code as the unit
tests, just in a larger arc).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from krono import AuditLog, Decision, MissingKeyError, verify
from krono._canonical import canonical_json

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `python -m krono.cli <args>`."""
    full_env = dict(os.environ)
    full_env.pop("KRONO_AUDIT_KEY", None)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "krono.cli", *args],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# E2E-1: full integrator arc
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestE2EFullIntegratorArc:
    """Single test covering: write, restart, write more, CLI verify, CLI tamper-catch."""

    def test_full_arc(self, key_env: str, key_hex: str, tmp_path: Path) -> None:
        log_path = tmp_path / "e2e.jsonl"

        # Phase 1: record three events under the writer.
        with AuditLog(log_path) as audit:
            audit.record(
                tool_name="read_note",
                decision=Decision.ALLOW,
                arguments={"id": "1"},
                declared_identity="claude-desktop",
                authenticated_identity=None,
                reason="default-allow read tool",
            )
            audit.record(
                tool_name="delete_note",
                decision=Decision.DENY,
                arguments={"id": "1"},
                declared_identity="claude-desktop",
                authenticated_identity=None,
                reason="destructive",
            )
            audit.record(
                tool_name="read_note",
                decision=Decision.ALLOW,
                arguments={"id": "2"},
                declared_identity="claude-desktop",
                authenticated_identity="bearer:alice@example.com",
                reason="authenticated read",
            )

        # Phase 2: simulate process restart by constructing a fresh AuditLog
        # against the same path and recording two more events. FR-16 resume
        # must continue the chain seamlessly.
        with AuditLog(log_path) as audit2:
            audit2.record(
                tool_name="read_note",
                decision=Decision.ALLOW,
                arguments={"id": "3"},
                declared_identity="claude-desktop",
                authenticated_identity="bearer:alice@example.com",
                reason="post-restart read",
            )
            audit2.record(
                tool_name="delete_note",
                decision=Decision.DENY,
                arguments={"id": "3"},
                declared_identity="claude-desktop",
                authenticated_identity="bearer:alice@example.com",
                reason="destructive",
            )

        # Phase 3: in-process verify confirms the chain is intact.
        in_proc = verify(log_path)
        assert in_proc.ok is True
        assert in_proc.entries_checked == 5

        # Phase 4: CLI verify confirms the same end-to-end.
        cli = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert cli.returncode == 0, cli.stderr
        assert "✓ krono audit verified: 5 entries" in cli.stdout
        assert "tail truncation not detectable from log alone" in cli.stdout

        # Phase 5: tamper with the LAST entry (the mcp-firewall miss case)
        # and confirm the CLI catches it.
        lines = log_path.read_text(encoding="utf-8").rstrip("\n").split("\n")
        events = [json.loads(line) for line in lines]
        events[-1]["decision"] = "allow"  # flip deny to allow on the final entry
        body = b""
        for ev in events:
            body += canonical_json(ev) + b"\n"
        log_path.write_bytes(body)

        cli_after = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert cli_after.returncode == 1, cli_after.stderr
        assert "✗ krono audit FAILED" in cli_after.stdout
        assert "line 5" in cli_after.stdout
        assert "sequence 4" in cli_after.stdout
        assert "content_tampered" in cli_after.stdout

        # And the JSON output:
        cli_json = _run_cli("verify", "--json", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert cli_json.returncode == 1
        payload = json.loads(cli_json.stdout)
        assert payload["ok"] is False
        assert payload["entries_checked"] == 4
        assert payload["failure"]["kind"] == "content_tampered"
        assert payload["failure"]["sequence_number"] == 4


# ---------------------------------------------------------------------------
# E2E-2: invalid UTF-8 surfaces as PARSE_ERROR (strict-decoding regression)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestE2EInvalidUtf8:
    """Strict UTF-8 in verify: invalid bytes become PARSE_ERROR
    deterministically (replacing the prior errors="replace" leniency)."""

    def test_invalid_utf8_byte_yields_parse_error(self, key_env: str, log_path: Path) -> None:
        with AuditLog(log_path) as audit:
            audit.record(
                tool_name="t",
                decision="allow",
                arguments={},
                declared_identity=None,
                authenticated_identity=None,
            )
        # Append a line of raw invalid UTF-8 (a lone continuation byte).
        with log_path.open("ab") as fh:
            fh.write(b"\x80\x80\x80\n")

        result = verify(log_path)
        assert result.ok is False
        assert result.failure is not None
        assert result.failure.kind.value == "parse_error"
        assert result.failure.line == 2
        assert "invalid UTF-8" in result.failure.message


# ---------------------------------------------------------------------------
# E2E-3 / standalone unit: "explicit key argument" message (FR-02 polish)
# ---------------------------------------------------------------------------


class TestExplicitKeyMessage:
    """The MissingKeyError message must distinguish explicit-arg from env-var.

    Closes the reviewer note: previously, a too-short explicit `key=` argument
    produced `KRONO_AUDIT_KEY shorter than 32 bytes` — referencing the env var
    that was never consulted. After the _keys.py refactor, the explicit-arg
    case says `explicit key argument shorter than 32 bytes` instead.
    """

    def test_explicit_short_key_audit_log_message(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        with pytest.raises(MissingKeyError) as excinfo:
            AuditLog(log_path, key=b"too-short")
        assert "explicit key argument" in str(excinfo.value)
        assert "shorter than 32 bytes" in str(excinfo.value)
        # Must NOT reference the env var name (it was never consulted).
        assert "KRONO_AUDIT_KEY" not in str(excinfo.value)
        # And no file should have been created.
        assert not log_path.exists()

    def test_explicit_short_key_verify_message(self, key_env: str, log_path: Path) -> None:
        # Build a valid 1-entry log under the env-var key.
        with AuditLog(log_path) as a:
            a.record(
                tool_name="t",
                decision="allow",
                arguments={},
                declared_identity=None,
                authenticated_identity=None,
            )

        with pytest.raises(MissingKeyError) as excinfo:
            verify(log_path, key=b"short")
        assert "explicit key argument" in str(excinfo.value)
        assert "KRONO_AUDIT_KEY" not in str(excinfo.value)

    def test_env_var_short_key_still_references_env_var_name(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The env-var path keeps the prior message — only the explicit-arg
        # path changed.
        monkeypatch.setenv("KRONO_AUDIT_KEY", "00" * 10)  # 10 bytes, too short
        log_path = tmp_path / "envshort.jsonl"
        with pytest.raises(MissingKeyError) as excinfo:
            AuditLog(log_path)
        assert "KRONO_AUDIT_KEY" in str(excinfo.value)
        assert "shorter than 32 bytes" in str(excinfo.value)
        assert "explicit" not in str(excinfo.value)
