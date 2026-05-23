"""krono — tamper-evident audit records for MCP tool-call decisions.

Public API surface is intentionally narrow. Each member is implemented
in its own submodule; this file only re-exports them.

Deviations from source-requirements §10 (see spec/SPEC_KRONO_PY_LIB.md
"Deviations" table): ``Identity`` is dropped in v1, ``VerifyError`` is
dropped in v1.
"""

from krono.audit import AuditLog
from krono.events import AuditEvent, Decision
from krono.exceptions import ConfigError, KronoError, MissingKeyError, WriteError
from krono.verify import FailureKind, VerifyFailure, VerifyResult, verify

__version__ = "0.1.1"

__all__ = [
    "AuditEvent",
    "AuditLog",
    "ConfigError",
    "Decision",
    "FailureKind",
    "KronoError",
    "MissingKeyError",
    "VerifyFailure",
    "VerifyResult",
    "WriteError",
    "__version__",
    "verify",
]
