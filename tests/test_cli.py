"""Unit tests for the `krono` CLI (`krono.cli`).

Spec: AC-25, AC-26, AC-27, AC-28, FR-26..FR-29, FR-39.

UT-Names:
    UT-CLI-Success, UT-CLI-Failure, UT-CLI-MissingKey, UT-CLI-Usage,
    UT-CLI-JSON, UT-CLI-KeyEnv, UT-CLI-Kind-Lowercase, UT-CLI-NullSequence.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from krono._canonical import canonical_json
from krono.audit import AuditLog

from .conftest import make_record_kwargs, read_jsonl_lines

# ---------------------------------------------------------------------------
# Run helper — invoke the CLI as a subprocess (real exit codes, real stdio).
# ---------------------------------------------------------------------------


def _run_cli(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `python -m krono.cli <args>` and capture stdout/stderr/exit."""
    env_full = dict(os.environ)
    # Strip any inherited key so tests can opt in explicitly.
    env_full.pop("KRONO_AUDIT_KEY", None)
    if env:
        env_full.update(env)
    return subprocess.run(
        [sys.executable, "-m", "krono.cli", *args],
        env=env_full,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_valid_log(path: Path, n: int, key_hex: str) -> None:
    """Helper that writes n valid events under the given key."""
    os.environ["KRONO_AUDIT_KEY"] = key_hex  # set for AuditLog
    try:
        with AuditLog(path) as a:
            for i in range(n):
                a.record(**make_record_kwargs(reason=f"event {i}"))
    finally:
        # Tests use monkeypatch via fixtures; restore via fixture teardown.
        pass


# ---------------------------------------------------------------------------
# AC-25 — success: exit 0 + checkmark + tail-truncation honesty note
# ---------------------------------------------------------------------------


class TestCliSuccess:
    """UT-CLI-Success."""

    def test_intact_log_exit_zero_with_message(
        self, key_hex: str, key_env: str, log_path: Path
    ) -> None:
        _write_valid_log(log_path, 3, key_hex)

        proc = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})

        assert proc.returncode == 0, proc.stderr
        assert "✓ krono audit verified" in proc.stdout
        assert "3 entries" in proc.stdout
        assert "sequence 0..2" in proc.stdout
        # Honesty note literal substring (AC-25).
        assert "tail truncation not detectable from log alone" in proc.stdout


# ---------------------------------------------------------------------------
# AC-26 — failure: exit 1 + "FAILED at line ..." + lowercase kind
# ---------------------------------------------------------------------------


class TestCliFailure:
    """UT-CLI-Failure, UT-CLI-Kind-Lowercase, UT-CLI-NullSequence."""

    def test_tampered_log_exit_one(self, key_hex: str, key_env: str, log_path: Path) -> None:
        _write_valid_log(log_path, 2, key_hex)
        # Tamper with the last entry.
        lines = read_jsonl_lines(log_path)
        events = [json.loads(line) for line in lines]
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        body = b""
        for ev in events:
            body += canonical_json(ev) + b"\n"
        log_path.write_bytes(body)

        proc = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})

        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        assert "✗ krono audit FAILED" in proc.stdout
        assert "line 2" in proc.stdout
        assert "sequence 1" in proc.stdout

    def test_kind_lowercase(self, key_hex: str, key_env: str, log_path: Path) -> None:
        # UT-CLI-Kind-Lowercase
        _write_valid_log(log_path, 2, key_hex)
        events = [json.loads(line) for line in read_jsonl_lines(log_path)]
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        log_path.write_bytes(canonical_json(events[0]) + b"\n" + canonical_json(events[1]) + b"\n")

        proc = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})

        # Lowercase appears; uppercase does not.
        assert "content_tampered" in proc.stdout
        assert "CONTENT_TAMPERED" not in proc.stdout

    def test_null_sequence_renders_hyphen(self, key_hex: str, key_env: str, log_path: Path) -> None:
        # UT-CLI-NullSequence — parse_error on a non-JSON line.
        # Write 2 valid entries then a non-JSON line.
        _write_valid_log(log_path, 2, key_hex)
        with open(log_path, "ab") as f:
            f.write(b"not-json\n")

        proc = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})

        assert proc.returncode == 1, proc.stderr
        # FR-28: literal "(sequence -)" — hyphen, not None/null.
        assert "(sequence -)" in proc.stdout
        assert "(sequence None)" not in proc.stdout
        assert "(sequence null)" not in proc.stdout
        assert "parse_error" in proc.stdout


# ---------------------------------------------------------------------------
# AC-27 — missing key: exit 3, stderr mentions KRONO_AUDIT_KEY
# ---------------------------------------------------------------------------


class TestCliMissingKey:
    """UT-CLI-MissingKey."""

    def test_missing_key_exit_three(self, key_hex: str, key_env: str, log_path: Path) -> None:
        # Write a valid log (needs key) then run CLI without the key set.
        _write_valid_log(log_path, 1, key_hex)

        proc = _run_cli("verify", str(log_path), env={})  # no KRONO_AUDIT_KEY

        assert proc.returncode == 3
        assert "KRONO_AUDIT_KEY" in proc.stderr


# ---------------------------------------------------------------------------
# UT-CLI-Usage — argparse usage errors
# ---------------------------------------------------------------------------


class TestCliUsage:
    def test_no_args_exits_two(self, key_hex: str) -> None:
        proc = _run_cli(env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 2, proc.stderr

    def test_verify_without_path_exits_two(self, key_hex: str) -> None:
        proc = _run_cli("verify", env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 2, proc.stderr

    def test_help_exits_zero(self) -> None:
        proc = _run_cli("--help")
        assert proc.returncode == 0
        assert "verify" in proc.stdout.lower() or "verify" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# AC-28 — --json output schema
# ---------------------------------------------------------------------------


class TestCliJson:
    """UT-CLI-JSON."""

    def test_json_success(self, key_hex: str, key_env: str, log_path: Path) -> None:
        _write_valid_log(log_path, 3, key_hex)
        proc = _run_cli("verify", "--json", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 0, proc.stderr
        # Single JSON object on stdout.
        payload: dict[str, Any] = json.loads(proc.stdout)
        assert payload["ok"] is True
        assert payload["entries_checked"] == 3
        assert payload["failure"] is None

    def test_json_failure(self, key_hex: str, key_env: str, log_path: Path) -> None:
        _write_valid_log(log_path, 2, key_hex)
        events = [json.loads(line) for line in read_jsonl_lines(log_path)]
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        log_path.write_bytes(canonical_json(events[0]) + b"\n" + canonical_json(events[1]) + b"\n")

        proc = _run_cli("verify", "--json", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 1, proc.stderr
        payload: dict[str, Any] = json.loads(proc.stdout)
        assert payload["ok"] is False
        assert payload["failure"] is not None
        assert payload["failure"]["kind"] == "content_tampered"  # lowercase
        assert payload["failure"]["line"] == 2
        assert payload["failure"]["sequence_number"] == 1
        # CONTENT_TAMPERED carries expected + actual per §Interfaces.
        assert "expected" in payload["failure"]
        assert "actual" in payload["failure"]

    def test_json_null_sequence_for_parse_error(
        self, key_hex: str, key_env: str, log_path: Path
    ) -> None:
        # UT-CLI-NullSequence (--json branch)
        _write_valid_log(log_path, 1, key_hex)
        with open(log_path, "ab") as f:
            f.write(b"not-json\n")

        proc = _run_cli("verify", "--json", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 1
        payload: dict[str, Any] = json.loads(proc.stdout)
        # JSON null when sequence_number is None.
        assert payload["failure"]["sequence_number"] is None
        assert payload["failure"]["kind"] == "parse_error"


# ---------------------------------------------------------------------------
# UT-CLI-KeyEnv — alternate env var
# ---------------------------------------------------------------------------


class TestCliKeyEnv:
    def test_key_env_override(self, key_hex: str, key_env: str, log_path: Path) -> None:
        # UT-CLI-KeyEnv: write with default key, then verify with alternate var.
        _write_valid_log(log_path, 1, key_hex)

        proc = _run_cli(
            "verify",
            "--key-env",
            "KRONO_DEMO_KEY",
            str(log_path),
            env={
                # KRONO_AUDIT_KEY unset; the alternate var carries the key.
                "KRONO_DEMO_KEY": key_hex,
            },
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert "✓ krono audit verified" in proc.stdout


# ---------------------------------------------------------------------------
# Negative: binary file → exit 1 with PARSE_ERROR
# ---------------------------------------------------------------------------


class TestCliBinaryFile:
    def test_binary_with_null_bytes(self, key_hex: str, log_path: Path) -> None:
        # Spec §Negative: binary file containing null bytes → exit 1, PARSE_ERROR.
        log_path.write_bytes(b"\x00\x01\x02\x03\n")
        proc = _run_cli("verify", str(log_path), env={"KRONO_AUDIT_KEY": key_hex})
        assert proc.returncode == 1
        assert "parse_error" in proc.stdout.lower()


# ---------------------------------------------------------------------------
# In-process tests for `krono.cli.main(argv)` so that coverage instrumentation
# can see the CLI code. These mirror the subprocess tests but call `main()`
# directly and capture stdout/stderr via capsys.
# ---------------------------------------------------------------------------


class TestCliMainInProcess:
    """Cover `krono.cli` directly so coverage can measure it."""

    def test_main_verify_success(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        _write_valid_log(log_path, 2, key_hex)
        exit_code = main(["verify", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "✓ krono audit verified" in captured.out
        assert "tail truncation not detectable from log alone" in captured.out

    def test_main_verify_failure_text(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        _write_valid_log(log_path, 2, key_hex)
        events = [json.loads(line) for line in read_jsonl_lines(log_path)]
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        log_path.write_bytes(canonical_json(events[0]) + b"\n" + canonical_json(events[1]) + b"\n")

        exit_code = main(["verify", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "✗ krono audit FAILED" in captured.out
        assert "content_tampered" in captured.out
        # CONTENT_TAMPERED carries expected + actual lines.
        assert "expected:" in captured.out
        assert "actual:" in captured.out

    def test_main_verify_failure_json(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        _write_valid_log(log_path, 2, key_hex)
        events = [json.loads(line) for line in read_jsonl_lines(log_path)]
        events[1]["decision"] = "allow" if events[1]["decision"] == "deny" else "deny"
        log_path.write_bytes(canonical_json(events[0]) + b"\n" + canonical_json(events[1]) + b"\n")

        exit_code = main(["verify", "--json", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 1
        payload: dict[str, Any] = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["failure"]["kind"] == "content_tampered"
        # CONTENT_TAMPERED includes expected/actual in JSON too.
        assert "expected" in payload["failure"]
        assert "actual" in payload["failure"]

    def test_main_verify_success_json(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        _write_valid_log(log_path, 3, key_hex)
        exit_code = main(["verify", "--json", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["ok"] is True
        assert payload["entries_checked"] == 3
        assert payload["failure"] is None

    def test_main_verify_failure_json_parse_error_omits_expected(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Per §Interfaces: expected/actual OMITTED (not null) for parse_error.
        from krono.cli import main

        log_path.write_bytes(b"not-json\n")
        exit_code = main(["verify", "--json", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 1
        payload = json.loads(captured.out)
        assert payload["failure"]["kind"] == "parse_error"
        assert "expected" not in payload["failure"]
        assert "actual" not in payload["failure"]
        # sequence_number is JSON null.
        assert payload["failure"]["sequence_number"] is None

    def test_main_missing_key_exits_three(
        self,
        unset_key: None,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
        key_hex: str,
    ) -> None:
        from krono.cli import main

        # First, create a valid log under a key (so the file exists).
        os.environ["KRONO_AUDIT_KEY"] = key_hex
        try:
            _write_valid_log(log_path, 1, key_hex)
        finally:
            del os.environ["KRONO_AUDIT_KEY"]

        exit_code = main(["verify", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 3
        assert "KRONO_AUDIT_KEY" in captured.err

    def test_main_config_error_exits_three(
        self,
        key_hex: str,
        key_env: str,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        missing = tmp_path / "no-such-log.jsonl"
        exit_code = main(["verify", str(missing)])
        captured = capsys.readouterr()
        assert exit_code == 3
        assert "krono:" in captured.err

    def test_main_text_failure_null_sequence_hyphen(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from krono.cli import main

        _write_valid_log(log_path, 1, key_hex)
        with open(log_path, "ab") as f:
            f.write(b"not-json\n")
        exit_code = main(["verify", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 1
        assert "(sequence -)" in captured.out
        assert "parse_error" in captured.out

    def test_main_empty_log_shows_minus_one(
        self,
        key_hex: str,
        key_env: str,
        log_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Edge case in _print_text_success: empty log → 0..-1.
        from krono.cli import main

        log_path.touch()
        exit_code = main(["verify", str(log_path)])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "0 entries" in captured.out
        assert "0..-1" in captured.out

    def test_main_no_argv_uses_sys_argv(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Cover the `argv is None` default branch of main().
        from krono.cli import main

        monkeypatch.setattr(sys, "argv", ["krono", "--help"])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 0
