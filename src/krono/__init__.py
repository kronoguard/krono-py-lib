"""krono — tamper-evident audit records for MCP tool-call decisions.

Public API surface is intentionally narrow. Each member is implemented
in its own submodule; this file only re-exports them.

v0.2.0 lifts the v1 deviations from source-requirements §10: ``Identity``
(FR-41/42) and ``VerifyError`` (FR-43) are now part of the public API.
"""

from krono.audit import AuditLog
from krono.events import AuditEvent, Decision
from krono.exceptions import ConfigError, KronoError, MissingKeyError, VerifyError, WriteError
from krono.identity import Identity
from krono.verify import FailureKind, VerifyFailure, VerifyResult, verify

__version__ = "0.2.0"

__all__ = [
    "AuditEvent",
    "AuditLog",
    "ConfigError",
    "Decision",
    "FailureKind",
    "Identity",
    "KronoError",
    "MissingKeyError",
    "VerifyError",
    "VerifyFailure",
    "VerifyResult",
    "WriteError",
    "__version__",
    "verify",
]
