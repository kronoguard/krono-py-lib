"""Shared pytest fixtures for the krono test suite.

Provides:
- `key_hex`: a deterministic 64-char hex string (32 raw bytes) for HMAC.
- `key_env`: monkeypatches `KRONO_AUDIT_KEY` to `key_hex` for the test scope.
- `log_path`: a fresh writable path under `tmp_path` for the audit log.
- `audit`: a freshly constructed `AuditLog` against `log_path` with `key_env` set.
- `recorded`: a small helper to record N events with deterministic args.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from krono.audit import AuditLog

# 64 hex chars = 32 raw bytes — minimum valid key.
_TEST_KEY_HEX = "00112233445566778899aabbccddeeff" * 2  # 64 chars


@pytest.fixture
def key_hex() -> str:
    """Deterministic 64-char hex key (32 raw bytes)."""
    return _TEST_KEY_HEX


@pytest.fixture
def key_env(monkeypatch: pytest.MonkeyPatch, key_hex: str) -> str:
    """Set KRONO_AUDIT_KEY in the environment for this test."""
    monkeypatch.setenv("KRONO_AUDIT_KEY", key_hex)
    return key_hex


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    """A fresh path for the audit log file under tmp_path."""
    return tmp_path / "audit.jsonl"


@pytest.fixture
def audit(key_env: str, log_path: Path) -> Iterator[AuditLog]:
    """Construct an AuditLog against log_path. Closes on teardown."""
    a = AuditLog(log_path)
    try:
        yield a
    finally:
        with contextlib.suppress(Exception):
            a.close()


def make_record_kwargs(**overrides: Any) -> dict[str, Any]:
    """Construct a dict of kwargs for AuditLog.record() with sensible defaults."""
    base: dict[str, Any] = {
        "tool_name": "read_note",
        "decision": "allow",
        "arguments": {"id": "1"},
        "declared_identity": "demo-client",
        "authenticated_identity": None,
        "reason": "default-allow read tool",
    }
    base.update(overrides)
    return base


@pytest.fixture
def record_kwargs() -> dict[str, Any]:
    """Default record() kwargs that can be customized in a test."""
    return make_record_kwargs()


@pytest.fixture
def unset_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove KRONO_AUDIT_KEY from the environment for this test."""
    monkeypatch.delenv("KRONO_AUDIT_KEY", raising=False)


def read_jsonl_lines(path: Path) -> list[str]:
    """Read all non-empty lines from a JSONL file."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [line for line in text.split("\n") if line != ""]


@pytest.fixture
def env_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure no key-related env vars leak in from the host shell."""
    for var in ("KRONO_AUDIT_KEY", "KRONO_DEMO_KEY", "KRONO_OTHER_KEY"):
        monkeypatch.delenv(var, raising=False)


# Re-export helper so tests can import it.
__all__ = ["make_record_kwargs", "read_jsonl_lines"]
