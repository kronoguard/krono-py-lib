"""krono — tamper-evident audit records for MCP tool-call decisions.

Public API surface is intentionally narrow. Each member is implemented
in its own submodule; this file only re-exports them.

Deviations from source-requirements §10 (see spec/SPEC_KRONO_PY_LIB.md
"Deviations" table): `Identity` is dropped in v1, `VerifyError` is dropped
in v1.
"""

__version__ = "0.1.0"

__all__ = [
    "__version__",
]
