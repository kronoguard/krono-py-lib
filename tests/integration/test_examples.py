"""Integration tests for the four `examples/*.py` scripts.

Spec: AC-29, AC-31, AC-32, AC-33, FR-30, FR-35.

Test names:
    IT-Examples-RunAll, IT-Examples-Resume, IT-Examples-Identity.

These tests spawn each example as a subprocess (matching how an integrator
runs them on a fresh machine), assert exit code 0, log produced, and the
final `verify()` returns ok=True. note_server.py also gets the
allow/deny content assertion (AC-29).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from krono.verify import verify

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

# Deterministic key for example scripts.
_EXAMPLE_KEY_HEX = "ff" * 32  # 64 chars = 32 raw bytes


EXAMPLE_SCRIPTS = [
    "note_server.py",
    "audit_singleton.py",
    "fastmcp_dispatch.py",
    "with_bearer_auth.py",
]


def _run_example(
    script_name: str,
    log_path: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke an example script as a subprocess against `log_path`."""
    script = EXAMPLES_DIR / script_name
    if not script.exists():
        pytest.skip(f"example script not present yet: {script}")

    env = dict(os.environ)
    env["KRONO_AUDIT_KEY"] = _EXAMPLE_KEY_HEX
    # Examples take their log path via env var — a common convention; tests
    # below depend on the script writing somewhere under tmp_path. The
    # specific env-var name is the example's choice; we set the conventional
    # one and let the example pick it up or use its own tmp dir.
    env["KRONO_LOG_PATH"] = str(log_path)
    env["KRONO_EXAMPLE_LOG"] = str(log_path)  # alternate name in case the script uses it
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [sys.executable, str(script)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        cwd=str(REPO_ROOT),
    )


def _find_produced_log(declared: Path, script_name: str, stdout: str) -> Path | None:
    """Locate the log file the script produced.

    The example scripts may either (a) use the env-supplied path, or (b)
    create their own temp dir and print the path to stdout. We support both.
    """
    if declared.exists() and declared.stat().st_size > 0:
        return declared

    # Fallback: scan stdout for a path-like token ending in .jsonl that exists.
    for token in stdout.split():
        candidate = Path(token.strip().strip("\"'"))
        if candidate.suffix == ".jsonl" and candidate.exists():
            return candidate

    return None


# ---------------------------------------------------------------------------
# IT-Examples-RunAll
# ---------------------------------------------------------------------------


class TestExamplesRunAll:
    """IT-Examples-RunAll — parametrised over the four example scripts."""

    @pytest.mark.parametrize("script", EXAMPLE_SCRIPTS)
    def test_example_runs_and_verifies(self, tmp_path: Path, script: str) -> None:
        log = tmp_path / f"{script.replace('.py', '')}.jsonl"
        proc = _run_example(script, log)

        assert proc.returncode == 0, (
            f"example {script} exited {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        produced = _find_produced_log(log, script, proc.stdout)
        assert produced is not None, (
            f"could not locate log file produced by {script}\nstdout: {proc.stdout}"
        )

        # At least one line in the log.
        lines = [line for line in produced.read_text(encoding="utf-8").split("\n") if line.strip()]
        assert len(lines) >= 1, f"{script} produced an empty log at {produced}"

        # Final verify() returns ok=True (under the deterministic key).
        os.environ["KRONO_AUDIT_KEY"] = _EXAMPLE_KEY_HEX
        result = verify(produced)
        assert result.ok is True, (
            f"verify({produced}) failed for example {script}: {result.failure!r}"
        )

    def test_note_server_has_allow_and_deny(self, tmp_path: Path) -> None:
        # AC-29 specific assertion folded into IT-Examples-RunAll.
        log = tmp_path / "note_server.jsonl"
        proc = _run_example("note_server.py", log)
        assert proc.returncode == 0, proc.stderr

        produced = _find_produced_log(log, "note_server.py", proc.stdout)
        assert produced is not None
        events = [
            json.loads(line)
            for line in produced.read_text(encoding="utf-8").split("\n")
            if line.strip()
        ]
        decisions = [e["decision"] for e in events]
        assert decisions.count("allow") == 1
        assert decisions.count("deny") == 1


# ---------------------------------------------------------------------------
# IT-Examples-Resume — audit_singleton.py specifically
# ---------------------------------------------------------------------------


class TestExamplesResume:
    """IT-Examples-Resume — proves FR-16 resume preserves chain across restart."""

    def test_audit_singleton_chain_across_restart(self, tmp_path: Path) -> None:
        log = tmp_path / "singleton.jsonl"
        proc = _run_example("audit_singleton.py", log)
        assert proc.returncode == 0, proc.stderr

        produced = _find_produced_log(log, "audit_singleton.py", proc.stdout)
        assert produced is not None

        events = [
            json.loads(line)
            for line in produced.read_text(encoding="utf-8").split("\n")
            if line.strip()
        ]

        # 4 events total: 2 from first AuditLog + 2 from second (post-resume).
        assert len(events) == 4
        seq_nums = [e["sequence_number"] for e in events]
        assert seq_nums == [0, 1, 2, 3]

        # The boundary: event 2's previous_hash must equal event 1's current_hash.
        assert events[2]["previous_hash"] == events[1]["current_hash"], (
            "resume must preserve the chain across the simulated restart"
        )

        # Whole file verifies.
        os.environ["KRONO_AUDIT_KEY"] = _EXAMPLE_KEY_HEX
        result = verify(produced)
        assert result.ok is True
        assert result.entries_checked == 4


# ---------------------------------------------------------------------------
# IT-Examples-Identity — with_bearer_auth.py specifically
# ---------------------------------------------------------------------------


class TestExamplesIdentity:
    """IT-Examples-Identity — three events with the FR-06 two-field model."""

    def test_with_bearer_auth_three_events_identity_combinations(self, tmp_path: Path) -> None:
        log = tmp_path / "bearer.jsonl"
        proc = _run_example("with_bearer_auth.py", log)
        assert proc.returncode == 0, proc.stderr

        produced = _find_produced_log(log, "with_bearer_auth.py", proc.stdout)
        assert produced is not None

        events = [
            json.loads(line)
            for line in produced.read_text(encoding="utf-8").split("\n")
            if line.strip()
        ]
        assert len(events) == 3, f"expected 3 events, got {len(events)}: {events!r}"

        # Event 1: declared set, authenticated None.
        assert events[0]["declared_identity"] is not None
        assert events[0]["authenticated_identity"] is None

        # Event 2: both set, distinct.
        assert events[1]["declared_identity"] is not None
        assert events[1]["authenticated_identity"] is not None
        assert events[1]["declared_identity"] != events[1]["authenticated_identity"], (
            "the two-field model: declared and authenticated must be distinct on event 2"
        )

        # Event 3: invalid token → declared set, authenticated None.
        assert events[2]["declared_identity"] is not None
        assert events[2]["authenticated_identity"] is None, (
            "invalid bearer token must NOT fall back to declared as authenticated"
        )
