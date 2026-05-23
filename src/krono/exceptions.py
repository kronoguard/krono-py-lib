"""Exception hierarchy for krono.

Per FR-24: ``KronoError`` is the base; v1 subclasses are
``MissingKeyError``, ``ConfigError``, ``WriteError``. ``VerifyError`` from
source-requirements §10 is intentionally DROPPED in v1 (see SPEC
Deviations table) — ``verify()`` returns a ``VerifyResult`` and never
raises it.
"""

from __future__ import annotations


class KronoError(Exception):
    """Base class for all krono-raised exceptions."""


class MissingKeyError(KronoError):
    """The HMAC key is absent, malformed, or shorter than 32 bytes.

    Raised by ``AuditLog.__init__`` and ``verify()`` per FR-02 when the
    key cannot be sourced from the explicit ``key=`` argument or the
    named environment variable.
    """


class ConfigError(KronoError):
    """Invalid path, unreadable file, or unwritable parent directory.

    Raised by ``AuditLog.__init__`` (FR-01) and ``verify()`` (FR-22)
    on filesystem-level configuration problems.
    """


class WriteError(KronoError):
    """An I/O error or chain-state inconsistency prevented an append.

    Raised by ``AuditLog.record`` (FR-25), by ``AuditLog.__init__``
    on a torn-resume condition (FR-16 step 3), and by
    ``AuditLog.record`` calls made after ``close()`` (FR-15).
    """
